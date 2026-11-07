//! Per-flow UDP relay between one accepted `StreamKind::Udp` mux stream and
//! one dialled native-UDP FS-chain flow (the fleet's `DgramMeshLeg` (`mirage-edge-fleet`'s `dgram_leg`)).
//!
//! - [`pump_mux_udp_datagrams`] — bidirectional pump: `[2B BE len][payload]`
//!   frames off the mux stream become datagrams into the mesh, and
//!   datagrams from the mesh become framed writes back — until either side
//!   ends or [`UDP_FLOW_IDLE_TIMEOUT`] elapses with nothing in either
//!   direction.
//! - [`UdpFlowLimiter`] — per-subscriber and process-wide caps on
//!   concurrently open UDP flows, each backed by a named refusal
//!   ([`UdpFlowRefusal`]) and a guard ([`UdpFlowGuard`]) that releases both
//!   counts on drop — including on an early return or panic unwind — so a
//!   forgotten release can never ratchet a subscriber toward its cap
//!   permanently.
//!
//! See `docs/mirage/plans/2026-09-25-edge-udp.md` §3.

use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex as StdMutex, MutexGuard};
use std::time::Duration;

use mirage_control_plane::{decode_udp_datagram_frame, encode_udp_datagram_frame, EdgeSessionError};
use mirage_subscriber_gate::bandwidth_cap::ConnectionBandwidthLimiter;
use mirage_subscriber_gate::subscriber_keys::SubscriberKey;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tracing::debug;

use crate::client::pump::ByteCounters;

/// Idle timeout for one client-facing UDP flow, end to end (client mux
/// stream idle AND mesh-facing datagram tunnel idle both count) — see the
/// plan's §1 "NAT-style flow lifetime". Same value as the exit's own
/// `UDP_SESSION_TIMEOUT` (`mirage2node::core::udp_chain_splice`,
/// `family::mirage::exit::udp_fs`), so the client-facing binding and the
/// mesh-facing session expire on the same clock.
pub const UDP_FLOW_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// Cap on concurrently open `StreamKind::Udp` mux streams for ONE
/// subscriber's edge session. Each one costs the mesh a real multi-hop
/// telescopic FS-chain dial — an order of magnitude more expensive than a
/// TCP mux stream, which only ever costs a yamux stream-open frame against
/// an already-warm session — so unlike TCP (bandwidth-capped, not
/// stream-count-capped), UDP needs its own admission bound on this more
/// expensive resource.
pub const MAX_UDP_STREAMS_PER_SESSION: usize = 64;

/// Process-wide cap on concurrently live UDP flows across every subscriber
/// session this edge process serves — defense in depth ahead of the exit's
/// own shared session-table sweep, so one edge alone cannot push a shared
/// exit's table anywhere near its own eviction threshold.
pub const MAX_LIVE_UDP_FLOWS_PER_PROCESS: usize = 2048;

/// Read buffer for accumulating `[2B BE len][payload]` frames off the mux
/// stream side of the pump.
const BUF_SIZE: usize = 16 * 1024;

#[derive(Debug, Error)]
pub enum UdpFlowError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("mux datagram framing: {0}")]
    Framing(#[from] EdgeSessionError),
    #[error("mesh datagram tunnel: {0}")]
    Mesh(#[from] mirage_core::error::MirageError),
    #[error("udp flow idle for {0:?} with no traffic in either direction")]
    IdleTimeout(Duration),
}

// ── Datagram I/O seam ────────────────────────────────────────────────────
//
// A small trait per direction, implemented for the real
// `mirage_control_plane::{DatagramTunnelSender,DatagramTunnelReceiver}` in
// production and by a channel-backed double in this module's own tests —
// `DatagramTunnel` is a closed two-variant enum (`Direct`/`Onion`), not a
// trait, so there is no way to stand up a live one in a unit test without a
// real telescopic FS-chain dial. The seam mirrors `crate::client::chain_store::
// ChainSource` / the fleet's `ExcerptSource`'s own convention:
// production code depends on the trait, only tests supply a double.

/// Sends one whole datagram into the mesh-facing tunnel.
#[async_trait::async_trait]
pub trait DatagramSink: Send {
    async fn send_datagram(&mut self, data: &[u8]) -> Result<(), mirage_core::error::MirageError>;
}

/// Receives one whole datagram from the mesh-facing tunnel.
#[async_trait::async_trait]
pub trait DatagramSource: Send {
    async fn next_datagram(&mut self) -> Result<Vec<u8>, mirage_core::error::MirageError>;
}

#[async_trait::async_trait]
impl DatagramSink for mirage_control_plane::DatagramTunnelSender {
    async fn send_datagram(&mut self, data: &[u8]) -> Result<(), mirage_core::error::MirageError> {
        self.send(data).await
    }
}

#[async_trait::async_trait]
impl DatagramSource for mirage_control_plane::DatagramTunnelReceiver {
    async fn next_datagram(&mut self) -> Result<Vec<u8>, mirage_core::error::MirageError> {
        self.recv_datagram().await
    }
}

/// The boxed arms of an opened datagram flow are themselves sinks/sources —
/// the pump is generic over the traits, so a boxed opener's own output has to
/// satisfy them too.
#[async_trait::async_trait]
impl DatagramSink for Box<dyn DatagramSink + Send> {
    async fn send_datagram(&mut self, data: &[u8]) -> Result<(), mirage_core::error::MirageError> {
        (**self).send_datagram(data).await
    }
}

/// See [`DatagramSink`]'s boxed impl above — the other arm of the same flow.
#[async_trait::async_trait]
impl DatagramSource for Box<dyn DatagramSource + Send> {
    async fn next_datagram(&mut self) -> Result<Vec<u8>, mirage_core::error::MirageError> {
        (**self).next_datagram().await
    }
}

/// Pump one accepted `StreamKind::Udp` mux stream to one dialed datagram
/// flow, both directions, until either side ends or [`UDP_FLOW_IDLE_TIMEOUT`]
/// elapses with nothing in either direction. Mirrors
/// `crate::client::pump::pump_stream_to_stream_capped`'s bandwidth-cap/byte-counter
/// wiring, applied per datagram rather than per byte-stream chunk.
pub async fn pump_mux_udp_datagrams<S, Snk, Src>(
    mux_stream: S,
    sink: Snk,
    source: Src,
    cap: Option<&ConnectionBandwidthLimiter>,
    counters: Option<&ByteCounters>,
) -> Result<(), UdpFlowError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
    Snk: DatagramSink,
    Src: DatagramSource,
{
    pump_mux_udp_datagrams_with_idle_timeout(mux_stream, sink, source, cap, counters, UDP_FLOW_IDLE_TIMEOUT).await
}

/// [`pump_mux_udp_datagrams`]'s real body, with the idle timeout as a
/// parameter — this module's own tests drive it directly with a
/// millisecond-scale timeout so the idle-expiry test does not have to wait
/// out the real 60s constant.
async fn pump_mux_udp_datagrams_with_idle_timeout<S, Snk, Src>(
    mut mux_stream: S,
    mut sink: Snk,
    mut source: Src,
    cap: Option<&ConnectionBandwidthLimiter>,
    counters: Option<&ByteCounters>,
    idle_timeout: Duration,
) -> Result<(), UdpFlowError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
    Snk: DatagramSink,
    Src: DatagramSource,
{
    let mut read_buf = vec![0u8; BUF_SIZE];
    let mut pending: Vec<u8> = Vec::new();

    let idle = tokio::time::sleep(idle_timeout);
    tokio::pin!(idle);

    loop {
        tokio::select! {
            _ = &mut idle => {
                return Err(UdpFlowError::IdleTimeout(idle_timeout));
            }
            result = mux_stream.read(&mut read_buf) => {
                let n = result?;
                if n == 0 {
                    debug!("udp flow: subscriber mux stream closed");
                    return Ok(());
                }
                pending.extend_from_slice(&read_buf[..n]);
                loop {
                    match decode_udp_datagram_frame(&pending) {
                        Ok((payload, consumed)) => {
                            if let Some(cap) = cap {
                                cap.charge(payload.len() as u64).await;
                            }
                            if let Some(c) = counters {
                                c.client_to_mesh.fetch_add(payload.len() as u64, Ordering::Relaxed);
                            }
                            sink.send_datagram(payload).await?;
                            pending.drain(..consumed);
                        }
                        Err(EdgeSessionError::Truncated { .. }) => break,
                        Err(e) => return Err(UdpFlowError::Framing(e)),
                    }
                }
                idle.as_mut().reset(tokio::time::Instant::now() + idle_timeout);
            }
            result = source.next_datagram() => {
                let datagram = result?;
                if let Some(cap) = cap {
                    cap.charge(datagram.len() as u64).await;
                }
                if let Some(c) = counters {
                    c.mesh_to_client.fetch_add(datagram.len() as u64, Ordering::Relaxed);
                }
                let frame = encode_udp_datagram_frame(&datagram)?;
                mux_stream.write_all(&frame).await?;
                idle.as_mut().reset(tokio::time::Instant::now() + idle_timeout);
            }
        }
    }
}

// ── Per-subscriber / process-wide flow caps ─────────────────────────────

/// Why [`UdpFlowLimiter::try_acquire`] refused a new flow — named, not a
/// bare bool, so a caller (or a test) can tell which cap fired without
/// parsing prose.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum UdpFlowRefusal {
    #[error("per-subscriber UDP flow cap reached ({current}/{limit})")]
    PerSubscriberCap { current: usize, limit: usize },
    #[error("process-wide UDP flow cap reached ({current}/{limit})")]
    ProcessWideCap { current: usize, limit: usize },
}

struct LimiterState {
    per_subscriber: HashMap<SubscriberKey, usize>,
    live_total: usize,
}

fn lock_state(state: &StdMutex<LimiterState>) -> MutexGuard<'_, LimiterState> {
    // Recover from a poisoned lock rather than panicking — a prior panic
    // inside the (very small, infallible) critical section below would
    // otherwise wedge every subsequent UDP flow admission for the rest of
    // the process's life.
    state.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Per-subscriber and process-wide admission control for concurrently open
/// UDP flows — see the module doc.
pub struct UdpFlowLimiter {
    per_subscriber_limit: usize,
    process_limit: usize,
    state: StdMutex<LimiterState>,
}

impl UdpFlowLimiter {
    /// `per_subscriber_limit`/`process_limit` are taken as parameters,
    /// rather than baked in from [`MAX_UDP_STREAMS_PER_SESSION`]/
    /// [`MAX_LIVE_UDP_FLOWS_PER_PROCESS`], the same way
    /// `crate::client::chain_store::HeldChainStore::reconcile` takes `min_count`
    /// rather than hardcoding `MIN_CHAIN_COUNT` — production wiring passes
    /// the real constants, tests shrink them.
    pub fn new(per_subscriber_limit: usize, process_limit: usize) -> Arc<Self> {
        Arc::new(Self {
            per_subscriber_limit,
            process_limit,
            state: StdMutex::new(LimiterState { per_subscriber: HashMap::new(), live_total: 0 }),
        })
    }

    /// Acquire one flow slot for `subscriber`. Checked and incremented
    /// atomically under one lock, so a racing pair of acquires can never
    /// both observe room and together overshoot either cap. Returns a guard
    /// that releases both counts on drop — including on an early return or
    /// panic unwind — so a forgotten release can never ratchet a subscriber
    /// toward its cap permanently.
    pub fn try_acquire(self: &Arc<Self>, subscriber: SubscriberKey) -> Result<UdpFlowGuard, UdpFlowRefusal> {
        let mut state = lock_state(&self.state);
        let current_sub = *state.per_subscriber.get(&subscriber).unwrap_or(&0);
        if current_sub >= self.per_subscriber_limit {
            return Err(UdpFlowRefusal::PerSubscriberCap { current: current_sub, limit: self.per_subscriber_limit });
        }
        if state.live_total >= self.process_limit {
            return Err(UdpFlowRefusal::ProcessWideCap { current: state.live_total, limit: self.process_limit });
        }
        *state.per_subscriber.entry(subscriber).or_insert(0) += 1;
        state.live_total += 1;
        drop(state);
        Ok(UdpFlowGuard { limiter: Arc::clone(self), subscriber })
    }

    fn release(&self, subscriber: SubscriberKey) {
        let mut state = lock_state(&self.state);
        if let Some(count) = state.per_subscriber.get_mut(&subscriber) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                state.per_subscriber.remove(&subscriber);
            }
        }
        state.live_total = state.live_total.saturating_sub(1);
    }
}

/// One admitted UDP flow's admission slot — releases its per-subscriber and
/// process-wide counts on drop. See [`UdpFlowLimiter::try_acquire`]'s own
/// doc for why this is a guard and not a bare acquire/release pair.
pub struct UdpFlowGuard {
    limiter: Arc<UdpFlowLimiter>,
    subscriber: SubscriberKey,
}

impl std::fmt::Debug for UdpFlowGuard {
    /// Hand-written rather than derived: `UdpFlowLimiter` carries no `Debug`
    /// impl of its own (nothing in it is sensitive, but nothing about its
    /// internal counters is useful to print either), so this names the
    /// subscriber only — enough for `Result::expect_err` in this module's
    /// own tests.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UdpFlowGuard").field("subscriber", &hex::encode(self.subscriber)).finish_non_exhaustive()
    }
}

impl Drop for UdpFlowGuard {
    fn drop(&mut self) {
        self.limiter.release(self.subscriber);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicBool;
    use tokio::sync::mpsc;

    // ── pump_mux_udp_datagrams: in-process round trip ────────────────────

    struct ChannelSink(mpsc::UnboundedSender<Vec<u8>>);

    #[async_trait::async_trait]
    impl DatagramSink for ChannelSink {
        async fn send_datagram(&mut self, data: &[u8]) -> Result<(), mirage_core::error::MirageError> {
            self.0
                .send(data.to_vec())
                .map_err(|_| mirage_core::error::MirageError::TunnelClosed)
        }
    }

    struct ChannelSource(mpsc::UnboundedReceiver<Vec<u8>>);

    #[async_trait::async_trait]
    impl DatagramSource for ChannelSource {
        async fn next_datagram(&mut self) -> Result<Vec<u8>, mirage_core::error::MirageError> {
            self.0.recv().await.ok_or(mirage_core::error::MirageError::TunnelClosed)
        }
    }

    #[tokio::test]
    async fn round_trip_through_the_flow_mapping_both_directions() {
        // "The mesh": whatever the pump sends into `sink` is echoed straight
        // back out through `source`, standing in for a real datagram-native
        // FS tunnel's target-side echo without dialling one.
        let (sink_tx, mut sink_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let (source_tx, source_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        tokio::spawn(async move {
            while let Some(datagram) = sink_rx.recv().await {
                if source_tx.send(datagram).is_err() {
                    return;
                }
            }
        });

        let (mut app, server) = tokio::io::duplex(4096);
        let counters = ByteCounters::default();
        let pump = tokio::spawn(async move {
            pump_mux_udp_datagrams(server, ChannelSink(sink_tx), ChannelSource(source_rx), None, Some(&counters))
                .await
                .map(|_| counters)
        });

        let frame = encode_udp_datagram_frame(b"hello-mesh").expect("payload within the mux datagram ceiling");
        app.write_all(&frame).await.expect("write framed datagram");

        let mut buf = [0u8; 256];
        let n = app.read(&mut buf).await.expect("read the echoed frame");
        let (payload, consumed) = decode_udp_datagram_frame(&buf[..n]).expect("echoed bytes decode as one frame");
        assert_eq!(payload, b"hello-mesh");
        assert_eq!(consumed, n, "exactly one frame, nothing trailing");

        drop(app);
        let counters = tokio::time::timeout(Duration::from_secs(2), pump)
            .await
            .expect("pump must not hang")
            .expect("pump task must not panic")
            .expect("pump must end cleanly once the mux stream closes");
        let (client_to_mesh, mesh_to_client) = counters.snapshot();
        assert_eq!(client_to_mesh, "hello-mesh".len() as u64);
        assert_eq!(mesh_to_client, "hello-mesh".len() as u64);
    }

    #[tokio::test]
    async fn round_trip_splits_frames_arriving_in_one_read() {
        // Two datagrams written back to back before the pump ever reads —
        // proves the frame decode loop drains every complete frame out of
        // one accumulated buffer, not just the first.
        let (sink_tx, mut sink_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let (source_tx, source_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        tokio::spawn(async move {
            while let Some(datagram) = sink_rx.recv().await {
                if source_tx.send(datagram).is_err() {
                    return;
                }
            }
        });

        let (mut app, server) = tokio::io::duplex(4096);
        let pump = tokio::spawn(pump_mux_udp_datagrams(
            server,
            ChannelSink(sink_tx),
            ChannelSource(source_rx),
            None,
            None,
        ));

        let mut both = encode_udp_datagram_frame(b"first").expect("frame a");
        both.extend(encode_udp_datagram_frame(b"second").expect("frame b"));
        app.write_all(&both).await.expect("write both frames at once");

        let mut buf = [0u8; 256];
        let mut got: Vec<u8> = Vec::new();
        while got.len() < both.len() {
            let n = app.read(&mut buf).await.expect("read echoed frames");
            got.extend_from_slice(&buf[..n]);
        }
        let (first, consumed1) = decode_udp_datagram_frame(&got).expect("first echoed frame");
        assert_eq!(first, b"first");
        let (second, _consumed2) = decode_udp_datagram_frame(&got[consumed1..]).expect("second echoed frame");
        assert_eq!(second, b"second");

        drop(app);
        tokio::time::timeout(Duration::from_secs(2), pump)
            .await
            .expect("pump must not hang")
            .expect("pump task must not panic")
            .expect("pump must end cleanly");
    }

    // ── idle expiry ───────────────────────────────────────────────────────

    #[tokio::test]
    async fn idle_expiry_ends_the_flow_with_no_traffic_in_either_direction() {
        let (sink_tx, _sink_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        // `_source_tx` is kept alive (not dropped) for the whole test so the
        // channel stays open with nothing ever sent on it -- "nothing in
        // either direction", not "the mesh side closed".
        let (_source_tx, source_rx) = mpsc::unbounded_channel::<Vec<u8>>();

        // `_app` is kept alive (not dropped) for the same reason: dropping
        // the duplex peer would surface as an immediate EOF read on `server`
        // rather than genuine silence.
        let (_app, server) = tokio::io::duplex(4096);
        let idle_timeout = Duration::from_millis(30);
        let result = tokio::time::timeout(
            Duration::from_secs(2),
            pump_mux_udp_datagrams_with_idle_timeout(
                server,
                ChannelSink(sink_tx),
                ChannelSource(source_rx),
                None,
                None,
                idle_timeout,
            ),
        )
        .await
        .expect("the idle timeout itself must fire well within the outer test timeout");

        assert!(matches!(result, Err(UdpFlowError::IdleTimeout(d)) if d == idle_timeout));
    }

    #[tokio::test]
    async fn activity_on_either_side_resets_the_idle_clock() {
        // A drip of client-side writes, each inside the idle window, must
        // keep the flow alive past what a single window would allow.
        let (sink_tx, mut sink_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let (_source_tx_unused, source_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let received = Arc::new(AtomicBool::new(false));
        let received_writer = Arc::clone(&received);
        tokio::spawn(async move {
            while sink_rx.recv().await.is_some() {
                received_writer.store(true, Ordering::SeqCst);
            }
        });

        let (mut app, server) = tokio::io::duplex(4096);
        let idle_timeout = Duration::from_millis(80);
        let pump = tokio::spawn(pump_mux_udp_datagrams_with_idle_timeout(
            server,
            ChannelSink(sink_tx),
            ChannelSource(source_rx),
            None,
            None,
            idle_timeout,
        ));

        // Three writes spaced under the idle window -- total elapsed time
        // exceeds one window, but the flow must survive because each write
        // resets the clock.
        for _ in 0..3 {
            tokio::time::sleep(idle_timeout / 2).await;
            let frame = encode_udp_datagram_frame(b"keepalive").expect("small payload");
            app.write_all(&frame).await.expect("write keepalive frame");
        }
        assert!(!pump.is_finished(), "the flow must not have idled out while activity kept arriving");
        assert!(received.load(Ordering::SeqCst), "the mesh side must have actually received traffic");

        drop(app);
        tokio::time::timeout(Duration::from_secs(2), pump)
            .await
            .expect("pump must not hang")
            .expect("pump task must not panic")
            .expect("pump must end cleanly once the mux stream closes");
    }

    // ── UdpFlowLimiter: named cap refusals ───────────────────────────────

    fn key(byte: u8) -> SubscriberKey {
        [byte; 32]
    }

    #[test]
    fn per_subscriber_cap_refuses_by_name_once_reached() {
        let limiter = UdpFlowLimiter::new(2, 100);
        let a = key(1);
        let _g1 = limiter.try_acquire(a).expect("first flow admitted");
        let _g2 = limiter.try_acquire(a).expect("second flow admitted");
        let err = limiter.try_acquire(a).expect_err("third flow over the per-subscriber cap must be refused");
        assert_eq!(err, UdpFlowRefusal::PerSubscriberCap { current: 2, limit: 2 });
    }

    #[test]
    fn process_wide_cap_refuses_by_name_across_distinct_subscribers() {
        let limiter = UdpFlowLimiter::new(100, 2);
        let a = key(1);
        let b = key(2);
        let _g1 = limiter.try_acquire(a).expect("first flow admitted");
        let _g2 = limiter.try_acquire(b).expect("second flow admitted, distinct subscriber");
        let err = limiter
            .try_acquire(key(3))
            .expect_err("third flow over the process-wide cap must be refused, even for a fresh subscriber");
        assert_eq!(err, UdpFlowRefusal::ProcessWideCap { current: 2, limit: 2 });
    }

    #[test]
    fn dropping_the_guard_releases_both_counts() {
        let limiter = UdpFlowLimiter::new(1, 1);
        let a = key(9);
        {
            let _guard = limiter.try_acquire(a).expect("flow admitted");
            assert!(limiter.try_acquire(a).is_err(), "cap of 1 leaves no room for a second concurrent flow");
        }
        // `_guard` dropped at scope end -- both counts must be released, so
        // the same subscriber can open a new flow immediately.
        let _g2 = limiter.try_acquire(a).expect("cap slot released once the prior guard dropped");
    }

    #[test]
    fn distinct_subscribers_have_independent_per_subscriber_counts() {
        let limiter = UdpFlowLimiter::new(1, 100);
        let a = key(1);
        let b = key(2);
        let _ga = limiter.try_acquire(a).expect("subscriber a's own first flow");
        let _gb = limiter.try_acquire(b).expect("subscriber b is unaffected by a's cap");
    }
}

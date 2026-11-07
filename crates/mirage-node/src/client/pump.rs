//! Byte-counted pumps between an accepted client stream and a dialled
//! mesh-chain stream: [`pump_tunnel_to_chain`] (a `mirage_protocol::traits::Tunnel`
//! on one side, a plain `AsyncRead + AsyncWrite` on the other — the exact
//! shape [`mirage_mesh_client::ChainMuxPool::open_stream`] hands back, see
//! the fleet's mesh leg (`mirage-edge-fleet`'s `mesh_leg`)) mirrors `mirage2node/crates/mirage-node/src/core/entrance_dispatch.rs`'s
//! `copy_tunnel_to_stream_capped` shape, ported rather than shared since it
//! predates this crate's dependency on `mirage-subscriber-gate`.
//! [`pump_stream_to_stream_capped`] is the shape `crate::client::entrance` actually
//! needs: both ends are already plain `AsyncRead + AsyncWrite` (a
//! `mirage_mux::tokio_compat::TokioMuxStream` and a dialled mesh-chain
//! stream), and it DOES charge the subscriber's own bandwidth cap
//! (`mirage_subscriber_gate::bandwidth_cap::ConnectionBandwidthLimiter`) —
//! that crate is now a real dependency of this one.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use mirage_core::error::{MirageError, Result};
use mirage_protocol::traits::Tunnel;
use mirage_subscriber_gate::bandwidth_cap::ConnectionBandwidthLimiter;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::Mutex;
use tracing::debug;

/// Read/write buffer size for [`pump_tunnel_to_chain`] — matches
/// `entrance_dispatch::BUF_SIZE`.
const BUF_SIZE: usize = 16 * 1024;

/// Identifies one subscriber for per-subscriber byte accounting. A thin
/// newtype around the subscriber's own persistent static key hex — the
/// same identity `mirage-subscriber-gate`'s `SubscriberKeyStore` will key
/// on once that crate exists. Kept local here rather than depended on,
/// since this crate does not yet depend on that not-yet-landed crate.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SubscriberKeyId(pub String);

/// Byte counters for one subscriber's traffic, both directions.
#[derive(Debug, Default)]
pub struct ByteCounters {
    /// Bytes received from the client's tunnel and written into the mesh
    /// chain (the subscriber's own outgoing traffic).
    pub client_to_mesh: AtomicU64,
    /// Bytes received from the mesh chain and written back to the client's
    /// tunnel (the subscriber's own incoming traffic).
    pub mesh_to_client: AtomicU64,
}

impl ByteCounters {
    /// Point-in-time `(client_to_mesh, mesh_to_client)` snapshot.
    pub fn snapshot(&self) -> (u64, u64) {
        (
            self.client_to_mesh.load(Ordering::Relaxed),
            self.mesh_to_client.load(Ordering::Relaxed),
        )
    }
}

/// Lazily-populated per-subscriber [`ByteCounters`], shared across every
/// stream a subscriber opens.
#[derive(Default)]
pub struct ByteCounterRegistry {
    counters: Mutex<HashMap<SubscriberKeyId, Arc<ByteCounters>>>,
}

impl ByteCounterRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// The counters for `key`, creating them on first use.
    pub async fn counters_for(&self, key: &SubscriberKeyId) -> Arc<ByteCounters> {
        let mut guard = self.counters.lock().await;
        Arc::clone(guard.entry(key.clone()).or_insert_with(|| Arc::new(ByteCounters::default())))
    }
}

/// Bidirectional pump between `tunnel` (the client's accepted stream) and
/// `chain` (a stream opened via the fleet's `MeshLeg::open_stream`),
/// charging every chunk in both directions against `counters` when
/// supplied. `counters = None` — no subscriber key resolved for this stream
/// — skips accounting and is otherwise byte-for-byte identical.
pub async fn pump_tunnel_to_chain<S>(
    mut tunnel: Box<dyn Tunnel>,
    mut chain: S,
    counters: Option<&ByteCounters>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut tun_buf = vec![0u8; BUF_SIZE];
    let mut chain_buf = vec![0u8; BUF_SIZE];

    loop {
        tokio::select! {
            result = tunnel.recv(&mut tun_buf) => {
                let n = result?;
                if n == 0 {
                    debug!("mesh leg pump: client tunnel closed");
                    let _ = chain.shutdown().await;
                    return Ok(());
                }
                if let Some(c) = counters {
                    c.client_to_mesh.fetch_add(n as u64, Ordering::Relaxed);
                }
                chain.write_all(&tun_buf[..n]).await.map_err(MirageError::Io)?;
            }
            result = chain.read(&mut chain_buf) => {
                let n = result.map_err(MirageError::Io)?;
                if n == 0 {
                    debug!("mesh leg pump: mesh chain stream closed");
                    let _ = tunnel.close().await;
                    return Ok(());
                }
                if let Some(c) = counters {
                    c.mesh_to_client.fetch_add(n as u64, Ordering::Relaxed);
                }
                tunnel.send(&chain_buf[..n]).await?;
            }
        }
    }
}

/// Bidirectional pump between two plain `AsyncRead + AsyncWrite` streams —
/// `a` is the subscriber's own accepted mux stream
/// (`mirage_mux::tokio_compat::TokioMuxStream`), `b` is the stream
/// the fleet's `MeshLeg::open_stream` dialled for it. Charges `cap`
/// (when supplied) before each write, exactly as
/// `mirage_subscriber_gate::entrance_dispatch::copy_tunnel_to_tunnel_capped`
/// charges its own two `Tunnel`s — same backpressure reasoning, different
/// pair of concrete types since neither end here is a `Tunnel`.
pub async fn pump_stream_to_stream_capped<A, B>(
    mut a: A,
    mut b: B,
    cap: Option<&ConnectionBandwidthLimiter>,
    counters: Option<&ByteCounters>,
) -> Result<()>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let mut a_buf = vec![0u8; BUF_SIZE];
    let mut b_buf = vec![0u8; BUF_SIZE];

    loop {
        tokio::select! {
            result = a.read(&mut a_buf) => {
                let n = result.map_err(MirageError::Io)?;
                if n == 0 {
                    debug!("edge entrance pump: subscriber mux stream closed");
                    let _ = b.shutdown().await;
                    return Ok(());
                }
                if let Some(cap) = cap {
                    cap.charge(n as u64).await;
                }
                if let Some(c) = counters {
                    c.client_to_mesh.fetch_add(n as u64, Ordering::Relaxed);
                }
                b.write_all(&a_buf[..n]).await.map_err(MirageError::Io)?;
            }
            result = b.read(&mut b_buf) => {
                let n = result.map_err(MirageError::Io)?;
                if n == 0 {
                    debug!("edge entrance pump: mesh chain stream closed");
                    let _ = a.shutdown().await;
                    return Ok(());
                }
                if let Some(cap) = cap {
                    cap.charge(n as u64).await;
                }
                if let Some(c) = counters {
                    c.mesh_to_client.fetch_add(n as u64, Ordering::Relaxed);
                }
                a.write_all(&b_buf[..n]).await.map_err(MirageError::Io)?;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mirage_protocol::traits::TransportInfo;
    use std::net::SocketAddr;
    use std::sync::Mutex as StdMutex;
    use tokio::sync::mpsc;

    /// A minimal `Tunnel` backed by a pair of frame-preserving channels,
    /// mirroring `mirage2node`'s own `entrance_dispatch::tests::MockTunnel`
    /// exactly: `recv()` blocks (never busy-returns `Ok(0)`) until either a
    /// frame is sent or the peer side is dropped, which is real `Tunnel`
    /// semantics ("closed" is a distinct event, not merely "nothing queued
    /// right now") and is load-bearing here — a `recv()` that returned
    /// `Ok(0)` the instant its inbox drained would race
    /// `tokio::select!` against the real `chain.read()` below and make the
    /// pump exit before the chain's reply ever arrived.
    struct MockTunnel {
        inbound: mpsc::UnboundedReceiver<Vec<u8>>,
        outbound: Arc<StdMutex<Vec<u8>>>,
        info: TransportInfo,
    }

    #[async_trait::async_trait]
    impl Tunnel for MockTunnel {
        async fn send(&mut self, data: &[u8]) -> Result<()> {
            self.outbound.lock().expect("lock").extend_from_slice(data);
            Ok(())
        }

        async fn recv(&mut self, buf: &mut [u8]) -> Result<usize> {
            match self.inbound.recv().await {
                Some(frame) => {
                    let n = frame.len().min(buf.len());
                    buf[..n].copy_from_slice(&frame[..n]);
                    Ok(n)
                }
                None => Ok(0),
            }
        }

        async fn close(&mut self) -> Result<()> {
            Ok(())
        }

        fn transport_info(&self) -> &TransportInfo {
            &self.info
        }
    }

    fn fake_transport_info() -> TransportInfo {
        TransportInfo::tcp(
            mirage_core::mirage::wire::TcpProtocolId::Mirage,
            "127.0.0.1:1".parse::<SocketAddr>().expect("valid addr"),
        )
    }

    #[tokio::test]
    async fn pump_moves_bytes_both_ways_and_counts_them() {
        let outbox: Arc<StdMutex<Vec<u8>>> = Arc::new(StdMutex::new(Vec::new()));
        let (to_tunnel, from_test) = mpsc::unbounded_channel();
        to_tunnel.send(b"hello-mesh".to_vec()).expect("send frame");
        // Held for the rest of the test so `recv()`'s second call blocks
        // (pending, not closed) instead of reading a dropped sender as EOF
        // before the chain's own reply has had a chance to arrive.
        let _keep_open = to_tunnel;
        let tunnel = Box::new(MockTunnel {
            inbound: from_test,
            outbound: Arc::clone(&outbox),
            info: fake_transport_info(),
        });

        // `chain` is a real loopback TCP pair standing in for
        // `ChainMuxPool::open_stream`'s own `AsyncRead + AsyncWrite`.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.expect("accept");
            let mut buf = [0u8; 32];
            let n = sock.read(&mut buf).await.expect("read");
            assert_eq!(&buf[..n], b"hello-mesh");
            sock.write_all(b"hello-client").await.expect("write");
            sock.shutdown().await.expect("shutdown");
        });
        let chain = tokio::net::TcpStream::connect(addr).await.expect("connect");

        let counters = ByteCounters::default();
        pump_tunnel_to_chain(tunnel, chain, Some(&counters)).await.expect("pump completes");
        server.await.expect("server task");

        assert_eq!(outbox.lock().expect("lock").as_slice(), b"hello-client");
        let (client_to_mesh, mesh_to_client) = counters.snapshot();
        assert_eq!(client_to_mesh, "hello-mesh".len() as u64);
        assert_eq!(mesh_to_client, "hello-client".len() as u64);
    }

    #[tokio::test]
    async fn stream_to_stream_pump_moves_bytes_both_ways_and_counts_them() {
        let (mut a_app, a) = tokio::io::duplex(64);
        let (mut b_app, b) = tokio::io::duplex(64);

        let counters = ByteCounters::default();
        let pump = tokio::spawn(async move { pump_stream_to_stream_capped(a, b, None, Some(&counters)).await.map(|_| counters) });

        a_app.write_all(b"hello-mesh").await.expect("write from a-side");
        let mut buf = [0u8; 32];
        let n = b_app.read(&mut buf).await.expect("read on b-side");
        assert_eq!(&buf[..n], b"hello-mesh");

        b_app.write_all(b"hello-client").await.expect("write from b-side");
        let n = a_app.read(&mut buf).await.expect("read on a-side");
        assert_eq!(&buf[..n], b"hello-client");

        drop(a_app);
        drop(b_app);
        let counters = tokio::time::timeout(std::time::Duration::from_secs(2), pump)
            .await
            .expect("pump must not hang")
            .expect("task must not panic")
            .expect("pump must complete without error");
        let (a_to_b, b_to_a) = counters.snapshot();
        assert_eq!(a_to_b, "hello-mesh".len() as u64);
        assert_eq!(b_to_a, "hello-client".len() as u64);
    }

    #[tokio::test]
    async fn registry_hands_back_the_same_counters_for_the_same_key() {
        let registry = ByteCounterRegistry::new();
        let key = SubscriberKeyId("subscriber-a".to_string());
        let a = registry.counters_for(&key).await;
        let b = registry.counters_for(&key).await;
        a.client_to_mesh.fetch_add(5, Ordering::Relaxed);
        assert_eq!(b.client_to_mesh.load(Ordering::Relaxed), 5);
    }

    #[tokio::test]
    async fn registry_hands_back_distinct_counters_for_distinct_keys() {
        let registry = ByteCounterRegistry::new();
        let a = registry.counters_for(&SubscriberKeyId("subscriber-a".to_string())).await;
        let b = registry.counters_for(&SubscriberKeyId("subscriber-b".to_string())).await;
        a.client_to_mesh.fetch_add(5, Ordering::Relaxed);
        assert_eq!(b.client_to_mesh.load(Ordering::Relaxed), 0);
    }
}

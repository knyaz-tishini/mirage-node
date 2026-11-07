//! Factory for one UDP relay binding from `config.udp_relay[]`.
//!
//! Two flavours: plain transparent byte-pump (no inspection) and
//! crypto-verify (peels one byte-cipher layer on inbound).
//! Transparent owns its own accept loop here; crypto-verify hands its
//! already-bound socket to `relay::udp_crypto_verify::run_udp_crypto_verify_on_socket`,
//! which now returns the listener's JoinHandle so the factory keeps
//! shutdown control. Aborting the handle drops the socket via tokio's
//! Drop semantics.
//!
//! # Single-hop vs multi-hop
//!
//! `next_hop_addr` controls the forwarding target for the entry relay leg:
//!
//! - `None` (single-hop): datagrams forwarded directly to `upstream_addr`.
//! - `Some(next_hop)` (multi-hop): datagrams forwarded to `next_hop`, which
//!   is a UDP relay listener on the exit node. That exit node's own binding
//!   carries `upstream_addr` pointing at the real target service.
//!
//! The per-flow state machine is identical in both cases — the only
//! difference is which `SocketAddr` the outbound connected socket targets.
//!
//! # Hot-reconfig
//!
//! - **`upstream_addr`** (transparent only) — applied in place via
//!   ArcSwap; new sessions go to the new upstream, in-flight sessions
//!   keep talking to the old one until they idle out.
//! - **`upstream_addr`** / **`next_hop_addr`** (crypto-verify) — rebind.
//!   The per-session `ByteCipher` cannot follow a mid-stream upstream swap.
//! - **`byte_cipher_mode`** — rebind required (in both flavours).
//!   Swapping cipher mode mid-stream would split per-session
//!   `ByteCipher` state in two, silently corrupting any session that
//!   started under the old mode.
//! - **`bind_port`** — rebind, obviously.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use mirage_core::config::ByteCipherMode;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Mutex};
use tracing::{info, warn};

use crate::core::registry::handle::{ListenerHandle, ReconfigureOutcome};
use crate::core::registry::handle_impl::{
    AbortListenerHandle, AtomicListenerStats, ReconfigureFn,
};
use crate::core::registry::spec::{ListenerId, ListenerSpec};

const DEFAULT_IDLE_SECS: u64 = 60;

/// Bind one UDP relay slot.
///
/// `next_hop_addr`: when `Some`, multi-hop mode — entry forwards to that
/// address instead of `upstream_addr`. When `None`, single-hop.
pub async fn activate(
    id: ListenerId,
    bind_addr: SocketAddr,
    upstream_addr: SocketAddr,
    next_hop_addr: Option<SocketAddr>,
    idle_secs: u64,
    byte_cipher_mode: Option<ByteCipherMode>,
    spec: ListenerSpec,
) -> Result<Box<dyn ListenerHandle>, Box<dyn std::error::Error + Send + Sync>> {
    // The effective forwarding target: next_hop when present, otherwise upstream.
    let forward_addr = next_hop_addr.unwrap_or(upstream_addr);

    let sock = Arc::new(UdpSocket::bind(bind_addr).await?);
    let bound_addr = sock.local_addr()?;
    // Names the MECHANISM, not a relay mode: the two modes these labels used
    // to name were removed on 2026-09-02, and what this branch actually turns
    // on is whether a byte-cipher skin is present.
    let label = if byte_cipher_mode.is_some() { "skin" } else { "no_skin" };
    let hop_label = if next_hop_addr.is_some() { "multi_hop" } else { "single_hop" };
    info!(
        %id,
        %bound_addr,
        %forward_addr,
        mode = label,
        hop = hop_label,
        "udp_relay binding bound"
    );

    let stats = Arc::new(AtomicListenerStats::default());
    let forward_swap = Arc::new(ArcSwap::new(Arc::new(forward_addr)));
    let idle = Duration::from_secs(if idle_secs == 0 {
        DEFAULT_IDLE_SECS
    } else {
        idle_secs
    });
    let sessions: Arc<Mutex<HashMap<SocketAddr, mpsc::Sender<Vec<u8>>>>> =
        Arc::new(Mutex::new(HashMap::new()));

    // The byte_cipher peel path needs per-session `ByteCipher` state.
    // We own the socket here and hand it to `run_udp_crypto_verify_on_socket`
    // so the JoinHandle returns to us — shutdown becomes a real `abort`,
    // and the socket releases via Drop when the task ends.
    //
    // For multi-hop: forward_addr already resolved to next_hop_addr above,
    // so the crypto-verify relay forwards clean (peeled) bytes to the next
    // hop's relay listener, which performs its own byte_cipher peel.
    if let Some(mode) = byte_cipher_mode.clone() {
        let forward_now = *forward_swap.load_full();
        let crypto_task = crate::family::mirage::relay::udp_crypto_verify::run_udp_crypto_verify_on_socket(
            Arc::clone(&sock),
            forward_now,
            idle_secs,
            mode,
        );

        let reconfigure_fn: ReconfigureFn = Arc::new(move |current: &ListenerSpec,
                                                          new_spec: &ListenerSpec| {
            let current_port = current.bind_port;
            let current_cipher = byte_cipher_of(current);
            let new_port = new_spec.bind_port;
            let new_cipher = byte_cipher_of(new_spec);
            Box::pin(async move {
                if current_port != new_port || current_cipher != new_cipher {
                    Ok::<_, Box<dyn std::error::Error + Send + Sync>>(
                        ReconfigureOutcome::RebindRequired,
                    )
                } else {
                    Ok(ReconfigureOutcome::Applied)
                }
            })
        });

        return Ok(Box::new(AbortListenerHandle::new(
            id,
            bound_addr,
            stats,
            vec![crypto_task],
            spec,
            Some(reconfigure_fn),
        )));
    }

    let forward_for_loop = Arc::clone(&forward_swap);
    let sock_loop = Arc::clone(&sock);
    let stats_loop = Arc::clone(&stats);
    let sessions_loop = Arc::clone(&sessions);
    let id_loop = id.clone();
    let task = tokio::spawn(async move {
        let mut buf = vec![0u8; 65_535];
        loop {
            let (n, client_addr) = match sock_loop.recv_from(&mut buf).await {
                Ok(v) => v,
                Err(e) => {
                    warn!(%id_loop, error = %e, "udp_relay recv_from failed");
                    return;
                }
            };
            stats_loop.bytes_in.fetch_add(n as u64, std::sync::atomic::Ordering::Relaxed);

            let tx = {
                let mut s = sessions_loop.lock().await;
                if let Some(tx) = s.get(&client_addr).cloned() {
                    tx
                } else {
                    let (tx, rx) = mpsc::channel::<Vec<u8>>(64);
                    // In multi-hop mode forward_now = next_hop_addr; in single-hop
                    // mode forward_now = upstream_addr. Semantics are identical.
                    let forward_now = *forward_for_loop.load_full();
                    let outbound_sock = match UdpSocket::bind("0.0.0.0:0").await {
                        Ok(s) => Arc::new(s),
                        Err(e) => {
                            warn!(error = %e, "udp_relay outbound bind failed");
                            continue;
                        }
                    };
                    if let Err(e) = outbound_sock.connect(forward_now).await {
                        warn!(%forward_now, error = %e, "udp_relay outbound connect failed");
                        continue;
                    }
                    s.insert(client_addr, tx.clone());

                    let sessions_back = Arc::clone(&sessions_loop);
                    let outbound_send = Arc::clone(&outbound_sock);
                    let stats_send = Arc::clone(&stats_loop);
                    let id_send = id_loop.clone();
                    tokio::spawn(async move {
                        let mut rx = rx;
                        let mut last = std::time::Instant::now();
                        loop {
                            let recv = tokio::time::timeout(idle, rx.recv()).await;
                            match recv {
                                Ok(Some(pkt)) => {
                                    last = std::time::Instant::now();
                                    let _ = outbound_send.send(&pkt).await;
                                    stats_send.bytes_out.fetch_add(
                                        pkt.len() as u64,
                                        std::sync::atomic::Ordering::Relaxed,
                                    );
                                }
                                Ok(None) | Err(_) => {
                                    if last.elapsed() >= idle {
                                        sessions_back.lock().await.remove(&client_addr);
                                        tracing::debug!(%id_send, %client_addr, "udp_relay session idle out");
                                        return;
                                    }
                                }
                            }
                        }
                    });

                    let outbound_recv = Arc::clone(&outbound_sock);
                    let sock_rev = Arc::clone(&sock_loop);
                    let sessions_rev = Arc::clone(&sessions_loop);
                    let stats_rev = Arc::clone(&stats_loop);
                    let client_back = client_addr;
                    tokio::spawn(async move {
                        let mut rbuf = vec![0u8; 65_535];
                        loop {
                            match outbound_recv.recv(&mut rbuf).await {
                                Ok(m) => {
                                    stats_rev.bytes_in.fetch_add(
                                        m as u64,
                                        std::sync::atomic::Ordering::Relaxed,
                                    );
                                    if sock_rev.send_to(&rbuf[..m], client_back).await.is_err() {
                                        break;
                                    }
                                }
                                Err(_) => break,
                            }
                        }
                        sessions_rev.lock().await.remove(&client_back);
                    });

                    tx
                }
            };

            let _ = tx.send(buf[..n].to_vec()).await;
            stats_loop.accepted_total.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    });

    // Reconfigure: byte_cipher mode swap = rebind, port change = rebind,
    // upstream / next_hop change = applied in place (transparent only).
    let forward_for_reconfigure = Arc::clone(&forward_swap);
    let reconfigure_fn: ReconfigureFn = Arc::new(move |current: &ListenerSpec,
                                                       new_spec: &ListenerSpec| {
        let forward_swap_rc = Arc::clone(&forward_for_reconfigure);
        let current_port = current.bind_port;
        let current_cipher = byte_cipher_of(current);
        let new_port = new_spec.bind_port;
        let new_cipher = byte_cipher_of(new_spec);
        // Resolve effective forward target from new payload.
        let new_forward_addr = new_spec
            .payload
            .as_ref()
            .and_then(|p| serde_json::from_value::<mirage_core::config::UdpRelayBinding>(p.clone()).ok())
            .map(|b| b.next_hop_addr.unwrap_or(b.upstream_addr));
        Box::pin(async move {
            if current_port != new_port {
                return Ok::<_, Box<dyn std::error::Error + Send + Sync>>(
                    ReconfigureOutcome::RebindRequired,
                );
            }
            if current_cipher != new_cipher {
                return Ok(ReconfigureOutcome::RebindRequired);
            }
            // Apply forward-target change in place.
            if let Some(addr) = new_forward_addr {
                forward_swap_rc.store(Arc::new(addr));
            }
            Ok(ReconfigureOutcome::Applied)
        })
    });

    Ok(Box::new(AbortListenerHandle::new(
        id,
        bound_addr,
        stats,
        vec![task],
        spec,
        Some(reconfigure_fn),
    )))
}

/// Ingress byte_cipher from `ingress_layer.byte_cipher` (v2).
fn byte_cipher_of(spec: &ListenerSpec) -> Option<ByteCipherMode> {
    spec.ingress_layer
        .as_ref()
        .and_then(|l| l.byte_cipher.clone())
}

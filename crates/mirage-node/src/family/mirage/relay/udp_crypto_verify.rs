//! L1 crypto-verify UDP relay — byte_cipher peel on each inbound datagram,
//! then forward to upstream as a byte pump.
//!
//! Mirrors `relay::crypto_verify` for UDP. Used when L1 should act as a
//! probe-resistance filter without seeing inner Mirage plaintext: the client
//! prepends a thin `byte_cipher` layer (magic / junk / XOR keystream); L1
//! strips it on ingress and forwards the remainder. Outbound replies pass
//! through unchanged — byte_cipher is inbound-only at L1.
//!
//! Wire model (per binding):
//! 1. `bind_addr` UDP socket accepts datagrams from N clients.
//! 2. For each unique `client_addr`, lazily open a fresh upstream socket
//!    `connect()`-ed to `upstream_addr` and create a per-session `ByteCipher`
//!    (stateful — `ObfuscateAll` counter, `first_done` flag).
//! 3. Inbound datagrams from any client → `cipher.unwrap` → send to upstream.
//!    `MagicMismatch` / `TooShort` → drop session.
//! 4. Upstream replies → forward to client as-is.
//! 5. Idle session timeout: same eviction model as `udp_transparent`.
//!
//! Differences from `udp_transparent`:
//! - Per-session `ByteCipher` state for inbound peel.
//! - Session drop on cipher unwrap error (probe-resistance).
//! - Outbound direction unchanged.
//!
//! ## ObfuscateAll on UDP vs TCP
//!
//! UDP datagrams are self-contained — `ObfuscateAll` works per-datagram with
//! a monotonic counter. TCP requires a full-stream cipher wrapper (tracked
//! separately in `crypto_verify_io.rs`).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use mirage_core::config::ByteCipherMode;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Mutex};
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tracing::{debug, info, warn};

use crate::family::mirage::relay::byte_cipher::ByteCipher;

/// Default session idle window when none configured. Mirrors `udp_transparent`.
const DEFAULT_IDLE_SECS: u64 = 60;

/// Spawn a crypto-verify UDP relay binding.
///
/// `byte_cipher_mode` is applied per-session to inbound datagrams. A fresh
/// `ByteCipher` instance is created per `client_addr` so per-session state
/// (counters, first-packet flag) is isolated.
///
/// Returns an error only if the initial bind fails. Per-session bookkeeping
/// runs in spawned tasks; the main task owns the listening socket and never
/// returns under normal operation.
pub async fn spawn_udp_crypto_verify(
    bind_addr: SocketAddr,
    upstream_addr: SocketAddr,
    idle_secs: u64,
    byte_cipher_mode: ByteCipherMode,
) -> std::io::Result<()> {
    let listener = Arc::new(UdpSocket::bind(bind_addr).await?);
    let _ = run_udp_crypto_verify_on_socket(
        listener,
        upstream_addr,
        idle_secs,
        byte_cipher_mode,
    );
    Ok(())
}

/// Same dispatch loop as [`spawn_udp_crypto_verify`] but takes an
/// already-bound socket and returns the listener task's [`JoinHandle`].
///
/// Used by [`crate::family::mirage::listener::udp_relay`] so the factory keeps
/// shutdown control over the task — aborting the handle closes the
/// socket via Drop. The legacy fire-and-forget entry point above stays
/// for unaffected call sites; it discards the handle so its task lives
/// until process exit.
pub fn run_udp_crypto_verify_on_socket(
    listener: Arc<UdpSocket>,
    upstream_addr: SocketAddr,
    idle_secs: u64,
    byte_cipher_mode: ByteCipherMode,
) -> JoinHandle<()> {
    let bind_addr = listener
        .local_addr()
        .unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap());
    info!(
        %bind_addr,
        %upstream_addr,
        mode = ?byte_cipher_mode_variant_name(&byte_cipher_mode),
        "udp_crypto_verify: listener bound"
    );

    let sessions: Arc<Mutex<HashMap<SocketAddr, mpsc::Sender<Vec<u8>>>>> =
        Arc::new(Mutex::new(HashMap::new()));

    let idle = Duration::from_secs(if idle_secs == 0 { DEFAULT_IDLE_SECS } else { idle_secs });

    tokio::spawn({
        let listener = Arc::clone(&listener);
        let sessions = Arc::clone(&sessions);
        async move {
            let mut buf = vec![0u8; 65_535];
            loop {
                let (n, client_addr) = match listener.recv_from(&mut buf).await {
                    Ok(v) => v,
                    Err(e) => {
                        warn!(%bind_addr, error = %e, "udp_crypto_verify: recv_from failed");
                        continue;
                    }
                };

                let tx_opt = {
                    let map = sessions.lock().await;
                    map.get(&client_addr).cloned()
                };

                let tx = match tx_opt {
                    Some(tx) => tx,
                    None => {
                        let upstream = match UdpSocket::bind("0.0.0.0:0").await {
                            Ok(s) => s,
                            Err(e) => {
                                warn!(%client_addr, error = %e, "udp_crypto_verify: upstream bind failed");
                                continue;
                            }
                        };
                        if let Err(e) = upstream.connect(upstream_addr).await {
                            warn!(%client_addr, %upstream_addr, error = %e, "udp_crypto_verify: upstream connect failed");
                            continue;
                        }
                        let upstream = Arc::new(upstream);

                        let (sess_tx, mut sess_rx) = mpsc::channel::<Vec<u8>>(64);
                        let listener_for_reply = Arc::clone(&listener);
                        let upstream_for_send = Arc::clone(&upstream);
                        let sessions_for_evict = Arc::clone(&sessions);
                        let cipher_mode = byte_cipher_mode.clone();

                        // client → upstream: peel byte_cipher, forward.
                        // Cipher state is per-session; a failed unwrap drops
                        // the session (probe-resistance gate).
                        tokio::spawn(async move {
                            let mut cipher = ByteCipher::new(cipher_mode);
                            while let Some(datagram) = sess_rx.recv().await {
                                match cipher.unwrap(&datagram) {
                                    Ok(payload) => {
                                        if let Err(e) = upstream_for_send.send(&payload).await {
                                            warn!(%client_addr, %upstream_addr, error = %e, "udp_crypto_verify: upstream send failed");
                                            break;
                                        }
                                    }
                                    Err(e) => {
                                        debug!(%client_addr, error = %e, "udp_crypto_verify: byte_cipher peel failed, dropping session");
                                        break;
                                    }
                                }
                            }
                        });

                        // upstream → client: forward replies as-is.
                        tokio::spawn(async move {
                            let mut rbuf = vec![0u8; 65_535];
                            let mut last_activity = Instant::now();
                            loop {
                                match timeout(idle, upstream.recv(&mut rbuf)).await {
                                    Ok(Ok(rn)) => {
                                        last_activity = Instant::now();
                                        if let Err(e) = listener_for_reply.send_to(&rbuf[..rn], client_addr).await {
                                            warn!(%client_addr, error = %e, "udp_crypto_verify: reply to client failed");
                                            break;
                                        }
                                    }
                                    Ok(Err(e)) => {
                                        warn!(%client_addr, %upstream_addr, error = %e, "udp_crypto_verify: upstream recv failed");
                                        break;
                                    }
                                    Err(_) => {
                                        if last_activity.elapsed() >= idle {
                                            debug!(%client_addr, idle_secs = idle.as_secs(), "udp_crypto_verify: session idle, evicting");
                                            break;
                                        }
                                    }
                                }
                            }
                            sessions_for_evict.lock().await.remove(&client_addr);
                        });

                        sessions.lock().await.insert(client_addr, sess_tx.clone());
                        sess_tx
                    }
                };

                if tx.send(buf[..n].to_vec()).await.is_err() {
                    // Forwarder task exited (cipher error or idle eviction);
                    // drop entry so the next datagram from this client opens
                    // a fresh session.
                    sessions.lock().await.remove(&client_addr);
                }
            }
        }
    })
}

/// Short variant name for logging (avoids dumping key material).
fn byte_cipher_mode_variant_name(m: &ByteCipherMode) -> &'static str {
    match m {
        ByteCipherMode::Raw => "raw",
        ByteCipherMode::ValidateFirst { .. } => "validate_first",
        ByteCipherMode::StripFirst { .. } => "strip_first",
        ByteCipherMode::ObfuscateAll { .. } => "obfuscate_all",
    }
}

//! `Tunnel ↔ AsyncRead+AsyncWrite` adapter.
//!
//! The edge's entrance accepts a customer on a Mirage tunnel and then
//! upgrades that SAME tunnel to a mux session. The mux session is
//! poll-based (`AsyncRead`/`AsyncWrite`), while `Tunnel` is async
//! (`send`/`recv`) — so the tunnel is bridged into a duplex stream by a
//! background pump task.
//!
//! Why a pump task instead of implementing `AsyncRead` directly:
//! `Tunnel::recv(&mut self, ...)` is async and the future borrows `self`,
//! so holding it across `poll` calls would need a self-referential struct
//! (unsafe pinning) — the task is the safe shape, and it is the same shape
//! the mesh client uses for its own tunnel-to-io bridge.

use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

use mirage_protocol::traits::Tunnel;

/// Per-direction buffer cap inside the duplex bridge. 64 KiB matches the
/// typical mux frame window — fine for the subscriber's own session, and
/// the pump flushes synchronously, so this is back-pressure, not throughput.
const DUPLEX_BUFFER_BYTES: usize = 64 * 1024;

/// Wrap a Mirage [`Tunnel`] into a tokio-style duplex stream.
///
/// Returns the stream the caller hands to the mux session, plus a
/// `JoinHandle` to the background pump. The pump exits cleanly when either
/// side is dropped or hits EOF / IO error; the caller may ignore the handle
/// (fire-and-forget) or `.abort()` it for early cancellation.
pub fn tunnel_into_io(
    mut tunnel: Box<dyn Tunnel>,
) -> (DuplexStream, tokio::task::JoinHandle<()>) {
    let (caller_side, mut bridge_side) = tokio::io::duplex(DUPLEX_BUFFER_BYTES);

    let handle = tokio::spawn(async move {
        let mut read_buf = vec![0u8; 16 * 1024];
        let mut write_buf = vec![0u8; 16 * 1024];

        loop {
            tokio::select! {
                // tunnel → caller (read from Mirage, write to duplex)
                tunnel_recv = tunnel.recv(&mut read_buf) => match tunnel_recv {
                    Ok(0) => {
                        // EOF from the Mirage side.
                        break;
                    }
                    Ok(n) => {
                        if bridge_side.write_all(&read_buf[..n]).await.is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                },
                // caller → tunnel (read from duplex, write to Mirage)
                duplex_read = bridge_side.read(&mut write_buf) => match duplex_read {
                    Ok(0) => break,  // caller closed
                    Ok(n) => {
                        if tunnel.send(&write_buf[..n]).await.is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                },
            }
        }
        let _ = tunnel.close().await;
    });

    (caller_side, handle)
}

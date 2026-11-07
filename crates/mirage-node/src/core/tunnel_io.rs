use mirage_core::error::MirageError;
use mirage_protocol::traits::Tunnel;
use tokio::net::TcpStream;
use tokio::{io::AsyncReadExt, io::AsyncWriteExt};
use tracing::debug;

const BUF_SIZE: usize = 16 * 1024;

/// Bidirectionally copy between two [`Tunnel`] instances until one closes.
///
/// Both sides use the `Tunnel::send` / `Tunnel::recv` interface.  The loop
/// runs two concurrent futures via `tokio::select!` — whichever produces data
/// first wins the iteration.  A zero-length read on either side signals EOF.
pub async fn tunnel_copy_bidirectional(
    mut a: Box<dyn Tunnel>,
    mut b: Box<dyn Tunnel>,
) -> Result<(), MirageError> {
    let mut buf_a = vec![0u8; BUF_SIZE];
    let mut buf_b = vec![0u8; BUF_SIZE];

    debug!("tunnel_copy: starting bidirectional loop");
    loop {
        tokio::select! {
            // a → b
            result = a.recv(&mut buf_a) => {
                let n = result?;
                if n == 0 {
                    debug!("tunnel_copy: side A closed");
                    let _ = b.close().await;
                    return Ok(());
                }
                debug!(bytes = n, "tunnel_copy: A→B");
                b.send(&buf_a[..n]).await?;
            }
            // b → a
            result = b.recv(&mut buf_b) => {
                let n = result?;
                if n == 0 {
                    debug!("tunnel_copy: side B closed");
                    let _ = a.close().await;
                    return Ok(());
                }
                debug!(bytes = n, "tunnel_copy: B→A");
                a.send(&buf_b[..n]).await?;
            }
        }
    }
}

/// Bidirectionally copy between a [`Tunnel`] and a plain [`TcpStream`].
///
/// The `Tunnel` side uses `send` / `recv`; the `TcpStream` side uses
/// `AsyncReadExt` / `AsyncWriteExt`.
pub async fn copy_tunnel_to_tcp(
    mut tunnel: Box<dyn Tunnel>,
    mut tcp: TcpStream,
) -> Result<(), MirageError> {
    let mut tun_buf = vec![0u8; BUF_SIZE];
    let mut tcp_buf = vec![0u8; BUF_SIZE];

    loop {
        tokio::select! {
            // tunnel → tcp
            result = tunnel.recv(&mut tun_buf) => {
                let n = result?;
                if n == 0 {
                    debug!("copy_tunnel_to_tcp: tunnel closed");
                    let _ = tcp.shutdown().await;
                    return Ok(());
                }
                tcp.write_all(&tun_buf[..n]).await?;
            }
            // tcp → tunnel
            result = tcp.read(&mut tcp_buf) => {
                let n = result?;
                if n == 0 {
                    debug!("copy_tunnel_to_tcp: TCP target closed");
                    let _ = tunnel.close().await;
                    return Ok(());
                }
                tunnel.send(&tcp_buf[..n]).await?;
            }
        }
    }
}

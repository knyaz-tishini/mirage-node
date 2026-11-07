//! TCP relay with idle timeout — terminates connections that have no traffic
//! flowing in either direction for `idle_timeout`.
//!
//! Standard `tokio::io::copy_bidirectional` keeps a connection open forever as
//! long as both ends are readable.  Clients that vanish without sending a FIN
//! (e.g. abrupt network loss) leave the relay blocked on their reads, leaking
//! file descriptors.  This module solves that by restarting a per-iteration
//! timer on every successful read; when no bytes arrive within `idle_timeout`
//! the relay returns, allowing both sockets to be dropped.

use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Copy bytes bidirectionally between `a` and `b`, returning if no bytes flow
/// in either direction for `idle_timeout`.
///
/// The timer resets whenever *any* byte is transferred (in either direction).
/// A clean EOF or read error on one side shuts down that direction and returns
/// once both directions finish.
///
/// Returns `(a_to_b_bytes, b_to_a_bytes)` on clean close or idle abort.
pub async fn copy_bidirectional_with_idle_timeout<A, B>(
    a: &mut A,
    b: &mut B,
    idle_timeout: Duration,
) -> std::io::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let mut buf_a = vec![0u8; 16 * 1024];
    let mut buf_b = vec![0u8; 16 * 1024];
    let mut a_to_b: u64 = 0;
    let mut b_to_a: u64 = 0;
    let mut a_eof = false;
    let mut b_eof = false;

    loop {
        if a_eof && b_eof {
            break;
        }

        let timer = tokio::time::sleep(idle_timeout);
        tokio::pin!(timer);

        tokio::select! {
            biased;

            _ = &mut timer => {
                tracing::debug!(
                    a_to_b,
                    b_to_a,
                    idle_secs = idle_timeout.as_secs(),
                    "TCP idle timeout — closing relay"
                );
                return Ok((a_to_b, b_to_a));
            }

            res = a.read(&mut buf_a), if !a_eof => {
                match res? {
                    0 => {
                        a_eof = true;
                        let _ = b.shutdown().await;
                    }
                    n => {
                        b.write_all(&buf_a[..n]).await?;
                        a_to_b += n as u64;
                    }
                }
            }

            res = b.read(&mut buf_b), if !b_eof => {
                match res? {
                    0 => {
                        b_eof = true;
                        let _ = a.shutdown().await;
                    }
                    n => {
                        a.write_all(&buf_b[..n]).await?;
                        b_to_a += n as u64;
                    }
                }
            }
        }
    }

    Ok((a_to_b, b_to_a))
}

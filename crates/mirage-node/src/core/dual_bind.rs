use socket2::{Domain, Socket, Type};
use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6};
use tracing::{info, warn};

/// Bind a dual-stack TCP listener on `[::]:port`.
///
/// `IPV6_V6ONLY=false` allows the single socket to accept both IPv4-mapped
/// (`::ffff:a.b.c.d`) and native IPv6 connections.  Supported on Linux, BSD,
/// macOS, and Windows Vista+.
///
/// On platforms where `set_only_v6(false)` fails (edge case: hardened kernels
/// with `net.ipv6.bindv6only=1` set immutably) the error is logged and the
/// socket still binds as IPv6-only — callers can add a separate v4 listener if
/// required, but for production relay nodes this path should never occur.
pub async fn bind_dual_stack_tcp(port: u16) -> std::io::Result<tokio::net::TcpListener> {
    let sock = Socket::new(Domain::IPV6, Type::STREAM, None)?;

    if let Err(e) = sock.set_only_v6(false) {
        warn!(port, "set_only_v6(false) failed — binding IPv6-only: {e}");
    }

    sock.set_reuse_address(true)?;
    sock.set_nonblocking(true)?;

    let addr = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, port, 0, 0));
    sock.bind(&addr.into())?;
    sock.listen(1024)?;

    let std_listener = std::net::TcpListener::from(sock);
    let listener = tokio::net::TcpListener::from_std(std_listener)?;

    info!(port, "listener bound dual-stack on [::]:{port}");
    Ok(listener)
}


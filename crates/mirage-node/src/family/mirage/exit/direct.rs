use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use mirage_core::error::MirageError;
use mirage_mux::tokio_compat::{SessionHandle, TokioMuxStream};
use mirage_protocol::traits::Tunnel;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tracing::{debug, warn};

use crate::core::doh::DoHResolver;
use crate::core::tunnel_io::copy_tunnel_to_tcp;
use crate::family::mirage::exit::dns_handler;
use crate::family::mirage::exit::policy;

// ── MuxCompat ────────────────────────────────────────────────────────────────
//
// Bridges a `Box<dyn Tunnel>` into futures::AsyncRead+AsyncWrite for `SessionHandle`.
// A background task relays frames in both directions through a duplex channel.
//
// `prefix` is prepended before any further tunnel reads.  Used when
// auto-detection already consumed the first byte of the mux frame.

struct MuxCompat {
    stream: tokio::io::DuplexStream,
    _relay: tokio::task::JoinHandle<()>,
}

impl MuxCompat {
    fn new(tunnel: Box<dyn Tunnel>, prefix: &[u8]) -> Self {
        let (app_side, tunnel_side) = tokio::io::duplex(1048576);
        let prefix_bytes = prefix.to_vec();
        let handle = tokio::spawn(async move {
            let mut tunnel = tunnel;
            let (mut rd, mut wr) = tokio::io::split(tunnel_side);
            if !prefix_bytes.is_empty() {
                if wr.write_all(&prefix_bytes).await.is_err() {
                    return;
                }
            }
            let mut rbuf = vec![0u8; 16384];
            let mut wbuf = vec![0u8; 16384];
            loop {
                tokio::select! {
                    result = tunnel.recv(&mut rbuf) => {
                        match result {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                if wr.write_all(&rbuf[..n]).await.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                    result = rd.read(&mut wbuf) => {
                        match result {
                            Ok(0) | Err(_) => { let _ = tunnel.close().await; break; }
                            Ok(n) => {
                                if tunnel.send(&wbuf[..n]).await.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                }
            }
            warn!("mux_compat: tunnel closed");
        });
        Self { stream: app_side, _relay: handle }
    }
}

// Implement futures::io::AsyncRead by bridging from the inner tokio DuplexStream.
impl futures::io::AsyncRead for MuxCompat {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<std::io::Result<usize>> {
        let mut read_buf = ReadBuf::new(buf);
        match Pin::new(&mut self.stream).poll_read(cx, &mut read_buf) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(read_buf.filled().len())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}

// Implement futures::io::AsyncWrite by bridging from the inner tokio DuplexStream.
impl futures::io::AsyncWrite for MuxCompat {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_close(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

// ── UDP framing constants ─────────────────────────────────────────────────────

pub(super) const UDP_SESSION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);
pub(super) const MAX_UDP_DATAGRAM: usize = 65507;

// ── UDP exit target parsing ───────────────────────────────────────────────────

enum ExitTarget<'a> {
    Tcp(&'a str),
    /// `host:port` without the `udp:` prefix
    Udp(&'a str),
}

fn parse_exit_target(addr_str: &str) -> ExitTarget<'_> {
    if let Some(rest) = addr_str.strip_prefix("udp:") {
        ExitTarget::Udp(rest)
    } else {
        ExitTarget::Tcp(addr_str)
    }
}

// ── Public entry points ───────────────────────────────────────────────────────

/// Layer-2 exit — auto-detects mux vs classic from the first tunnel frame.
///
/// A mux session starts with a frame whose version byte is `0x00`.  Valid
/// classic targets begin with a printable ASCII character (`>= 0x30`), so
/// byte `0x00` is unambiguous as a mux indicator.
pub async fn handle_exit(
    mut tunnel: Box<dyn Tunnel>,
    doh: Option<Arc<DoHResolver>>,
) -> Result<(), MirageError> {
    let mut first = [0u8; 1];
    let n = tunnel.recv(&mut first).await?;
    if n == 0 {
        return Err(MirageError::TunnelClosed);
    }

    if first[0] == 0x00 {
        run_mux_session(tunnel, &first[..n], doh).await
    } else {
        handle_exit_with_prefix(tunnel, &first[..n], doh).await
    }
}

// ── Private helpers ───────────────────────────────────────────────────────────

async fn run_mux_session(
    tunnel: Box<dyn Tunnel>,
    prefix: &[u8],
    doh: Option<Arc<DoHResolver>>,
) -> Result<(), MirageError> {
    let compat = MuxCompat::new(tunnel, prefix);
    let session = SessionHandle::server(compat);

    loop {
        let stream = match session.accept_stream().await {
            Ok(s) => s,
            Err(_) => break,
        };
        let doh_clone = doh.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_mux_stream(stream, doh_clone).await {
                tracing::debug!("mux stream error: {e}");
            }
        });
    }

    Ok(())
}

/// Handle a single mux stream: read target address, connect, copy bidirectional.
async fn handle_mux_stream(
    stream: mirage_mux::MuxStream,
    doh: Option<Arc<DoHResolver>>,
) -> Result<(), MirageError> {
    let mut stream = TokioMuxStream(stream);
    let mut addr_buf = [0u8; 512];
    let n = stream.read(&mut addr_buf).await.map_err(MirageError::Io)?;
    if n == 0 {
        return Err(MirageError::TunnelClosed);
    }

    let addr_str = std::str::from_utf8(&addr_buf[..n]).map_err(|_| {
        MirageError::Protocol("mux exit: first frame is not valid UTF-8 address".into())
    })?;
    let addr_str = addr_str.trim();

    debug!(target = %addr_str, "mux exit: stream target");

    match parse_exit_target(addr_str) {
        ExitTarget::Tcp(target) => {
            // Port-53 TCP DNS interception.
            if is_port_53(target) {
                if let Some(ref resolver) = doh {
                    return handle_tcp_dns_mux(&mut stream, resolver).await;
                }
            }

            let mut tcp_target = if let Some(resolver) = doh {
                let (host, port) = split_host_port(target)?;
                let ip = resolver.resolve(host).await?;
                let sock_addr = SocketAddr::new(ip, port);
                if policy::is_blocked(sock_addr.ip()) {
                    warn!(ip = %sock_addr.ip(), target = %target, "mux exit: SSRF blocked exit target");
                    return Err(MirageError::Protocol(format!("SSRF: blocked exit target {}", sock_addr.ip())));
                }
                TcpStream::connect(sock_addr).await.map_err(|e| {
                    MirageError::NodeUnreachable(format!("mux exit: cannot connect to {sock_addr}: {e}"))
                })?
            } else {
                let sock_addr = resolve_tcp_target(target).await?;
                if policy::is_blocked(sock_addr.ip()) {
                    warn!(ip = %sock_addr.ip(), target = %target, "mux exit: SSRF blocked exit target");
                    return Err(MirageError::Protocol(format!("SSRF: blocked exit target {}", sock_addr.ip())));
                }
                TcpStream::connect(sock_addr).await.map_err(|e| {
                    MirageError::NodeUnreachable(format!("mux exit: cannot connect to {target}: {e}"))
                })?
            };

            crate::core::idle_copy::copy_bidirectional_with_idle_timeout(
                &mut stream,
                &mut tcp_target,
                std::time::Duration::from_secs(300),
            )
            .await
            .map_err(MirageError::Io)?;

            Ok(())
        }
        ExitTarget::Udp(target) => {
            handle_udp_exit_mux(&mut stream, target, doh).await
        }
    }
}

/// Classic direct exit.  `prefix` contains bytes already consumed from the
/// tunnel during auto-detection and must be prepended to the address frame.
async fn handle_exit_with_prefix(
    mut tunnel: Box<dyn Tunnel>,
    prefix: &[u8],
    doh: Option<Arc<DoHResolver>>,
) -> Result<(), MirageError> {
    let mut addr_buf = [0u8; 512];
    addr_buf[..prefix.len()].copy_from_slice(prefix);

    let n_rest = tunnel.recv(&mut addr_buf[prefix.len()..]).await?;
    let n = if n_rest == 0 { prefix.len() } else { prefix.len() + n_rest };

    if n == 0 {
        return Err(MirageError::TunnelClosed);
    }

    let addr_str = std::str::from_utf8(&addr_buf[..n]).map_err(|_| {
        MirageError::Protocol("exit: first frame is not valid UTF-8 address".into())
    })?;
    let addr_str = addr_str.trim();

    debug!(target = %addr_str, "exit: received CONNECT target");

    match parse_exit_target(addr_str) {
        ExitTarget::Tcp(target) => {
            // Port-53 TCP DNS interception.
            if is_port_53(target) {
                if let Some(ref resolver) = doh {
                    return handle_tcp_dns_tunnel(tunnel, resolver).await;
                }
            }

            let tcp_target = if let Some(resolver) = doh {
                let (host, port) = split_host_port(target)?;
                let ip = resolver.resolve(host).await?;
                let sock_addr = SocketAddr::new(ip, port);
                debug!(target = %target, resolved = %sock_addr, "exit: DoH resolved");
                if policy::is_blocked(sock_addr.ip()) {
                    warn!(ip = %sock_addr.ip(), target = %target, "exit: SSRF blocked exit target");
                    return Err(MirageError::Protocol(format!("SSRF: blocked exit target {}", sock_addr.ip())));
                }
                TcpStream::connect(sock_addr).await.map_err(|e| {
                    MirageError::NodeUnreachable(format!("exit: cannot connect to {sock_addr}: {e}"))
                })?
            } else {
                let sock_addr = resolve_tcp_target(target).await?;
                if policy::is_blocked(sock_addr.ip()) {
                    warn!(ip = %sock_addr.ip(), target = %target, "exit: SSRF blocked exit target");
                    return Err(MirageError::Protocol(format!("SSRF: blocked exit target {}", sock_addr.ip())));
                }
                TcpStream::connect(sock_addr).await.map_err(|e| {
                    MirageError::NodeUnreachable(format!("exit: cannot connect to {target}: {e}"))
                })?
            };

            debug!(target = %target, "exit: connected to target, starting bidirectional copy");
            copy_tunnel_to_tcp(tunnel, tcp_target).await
        }
        ExitTarget::Udp(target) => {
            handle_udp_exit_tunnel(tunnel, target, doh).await
        }
    }
}

/// UDP exit for mux streams (`TokioMuxStream` = `AsyncRead + AsyncWrite`).
async fn handle_udp_exit_mux(
    stream: &mut TokioMuxStream,
    target: &str,
    doh: Option<Arc<DoHResolver>>,
) -> Result<(), MirageError> {
    // Port-53 DNS interception: resolve via DoH and return synthesised response.
    if is_port_53(target) {
        if let Some(ref resolver) = doh {
            return handle_udp_dns_mux(stream, resolver).await;
        }
    }

    let dest_addr = resolve_udp_target(target, doh).await?;
    debug!(target = %target, resolved = %dest_addr, "udp exit: opening UDP socket");

    let sock = tokio::net::UdpSocket::bind("0.0.0.0:0").await.map_err(MirageError::Io)?;
    sock.connect(dest_addr).await.map_err(MirageError::Io)?;

    udp_relay_loop(stream, &sock).await
}

/// UDP exit for classic tunnel path (`Box<dyn Tunnel>`).
async fn handle_udp_exit_tunnel(
    mut tunnel: Box<dyn Tunnel>,
    target: &str,
    doh: Option<Arc<DoHResolver>>,
) -> Result<(), MirageError> {
    // Port-53 DNS interception.
    if is_port_53(target) {
        if let Some(ref resolver) = doh {
            return handle_udp_dns_tunnel(&mut tunnel, resolver).await;
        }
    }

    let dest_addr = resolve_udp_target(target, doh).await?;
    debug!(target = %target, resolved = %dest_addr, "udp exit (tunnel): opening UDP socket");

    let sock = tokio::net::UdpSocket::bind("0.0.0.0:0").await.map_err(MirageError::Io)?;
    sock.connect(dest_addr).await.map_err(MirageError::Io)?;

    let mut in_buf = Vec::with_capacity(2048);
    let mut out_buf = vec![0u8; MAX_UDP_DATAGRAM];
    let mut len_buf = [0u8; 2];

    loop {
        tokio::select! {
            // Tunnel → UDP: read [2B len][payload], send as datagram
            result = tunnel.recv(&mut len_buf) => {
                match result {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {
                        let payload_len = u16::from_be_bytes(len_buf) as usize;
                        if payload_len == 0 {
                            break;
                        }
                        if payload_len > MAX_UDP_DATAGRAM {
                            warn!("udp exit (tunnel): oversized frame {payload_len}, dropping");
                            break;
                        }
                        in_buf.resize(payload_len, 0);
                        match tunnel.recv(&mut in_buf[..payload_len]).await {
                            Ok(0) | Err(_) => break,
                            Ok(_) => {
                                if let Err(e) = sock.send(&in_buf[..payload_len]).await {
                                    warn!("udp exit (tunnel): send failed: {e}");
                                    break;
                                }
                            }
                        }
                    }
                }
            }
            // UDP → Tunnel: recv datagram, write [2B len][payload]
            result = tokio::time::timeout(UDP_SESSION_TIMEOUT, sock.recv(&mut out_buf)) => {
                match result {
                    Ok(Ok(n)) => {
                        let len_bytes = (n as u16).to_be_bytes();
                        if tunnel.send(&len_bytes).await.is_err() {
                            break;
                        }
                        if n > 0 && tunnel.send(&out_buf[..n]).await.is_err() {
                            break;
                        }
                    }
                    Ok(Err(e)) => {
                        warn!("udp exit (tunnel): recv failed: {e}");
                        break;
                    }
                    Err(_) => {
                        debug!("udp exit (tunnel): idle timeout");
                        break;
                    }
                }
            }
        }
    }
    Ok(())
}

/// Resolve a TCP target `host:port` string to a `SocketAddr` via system DNS.
///
/// Collects ALL resolved addresses and rejects the whole target if ANY address
/// is blocked by the SSRF policy.  An untrusted caller who mixes a public A-record with
/// a private one must not be able to connect — the first returned address could
/// be either, so we inspect the full set.
///
/// Returns the first NON-blocked address only after confirming none are blocked.
async fn resolve_tcp_target(target: &str) -> Result<SocketAddr, MirageError> {
    use tokio::net::lookup_host;
    let addrs: Vec<SocketAddr> = lookup_host(target)
        .await
        .map_err(MirageError::Io)?
        .collect();
    if addrs.is_empty() {
        return Err(MirageError::Protocol(format!("exit: no DNS result for {target}")));
    }
    for a in &addrs {
        if policy::is_blocked(a.ip()) {
            warn!(ip = %a.ip(), %target, "exit: SSRF guard rejected target (mixed or private DNS)");
            return Err(MirageError::Protocol(format!(
                "SSRF: blocked exit target {} (resolved from {target})",
                a.ip()
            )));
        }
    }
    // Safety: non-empty checked above; no blocked addrs confirmed.
    Ok(addrs[0])
}

/// Resolve a UDP target `host:port` string to a `SocketAddr`, optionally via DoH.
///
/// Collects ALL resolved addresses and rejects the whole target if ANY address
/// is blocked by the SSRF policy (mirrors `resolve_tcp_target` robustness).
pub(crate) async fn resolve_udp_target(
    target: &str,
    doh: Option<Arc<DoHResolver>>,
) -> Result<SocketAddr, MirageError> {
    if let Some(resolver) = doh {
        let (host, port) = split_host_port(target)?;
        let ip = resolver.resolve(host).await?;
        let addr = SocketAddr::new(ip, port);
        if policy::is_blocked(addr.ip()) {
            warn!(ip = %addr.ip(), target = %target, "udp exit: SSRF blocked exit target");
            return Err(MirageError::Protocol(format!("SSRF: blocked exit target {}", addr.ip())));
        }
        return Ok(addr);
    }

    use tokio::net::lookup_host;
    let addrs: Vec<SocketAddr> = lookup_host(target)
        .await
        .map_err(MirageError::Io)?
        .collect();
    if addrs.is_empty() {
        return Err(MirageError::Protocol(format!("udp exit: no DNS result for {target}")));
    }
    for a in &addrs {
        if policy::is_blocked(a.ip()) {
            warn!(ip = %a.ip(), %target, "udp exit: SSRF guard rejected target (mixed or private DNS)");
            return Err(MirageError::Protocol(format!(
                "SSRF: blocked exit target {} (resolved from {target})",
                a.ip()
            )));
        }
    }
    // Safety: non-empty checked above; no blocked addrs confirmed.
    Ok(addrs[0])
}

/// Bidirectional relay loop between an `AsyncRead + AsyncWrite` stream and a
/// connected `UdpSocket`, using 2-byte BE length-prefixed framing on the stream side.
pub(super) async fn udp_relay_loop<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    sock: &tokio::net::UdpSocket,
) -> Result<(), MirageError> {
    let mut in_buf = Vec::with_capacity(2048);
    let mut out_buf = vec![0u8; MAX_UDP_DATAGRAM];

    loop {
        tokio::select! {
            // Stream → UDP: read length-prefixed frame, send as datagram
            result = read_udp_frame(stream, &mut in_buf) => {
                match result {
                    Ok(0) | Err(_) => break,
                    Ok(_n) => {
                        if let Err(e) = sock.send(&in_buf).await {
                            warn!("udp exit: send failed: {e}");
                            break;
                        }
                    }
                }
            }
            // UDP → Stream: recv datagram, write as length-prefixed frame
            result = tokio::time::timeout(UDP_SESSION_TIMEOUT, sock.recv(&mut out_buf)) => {
                match result {
                    Ok(Ok(n)) => {
                        if let Err(e) = write_udp_frame(stream, &out_buf[..n]).await {
                            warn!("udp exit: write frame failed: {e}");
                            break;
                        }
                    }
                    Ok(Err(e)) => {
                        warn!("udp exit: recv failed: {e}");
                        break;
                    }
                    Err(_) => {
                        debug!("udp exit: idle timeout");
                        break;
                    }
                }
            }
        }
    }
    Ok(())
}

/// Write a length-prefixed UDP frame: `[2B BE len][payload]`.
pub(super) async fn write_udp_frame<W: AsyncWrite + Unpin>(
    w: &mut W,
    datagram: &[u8],
) -> std::io::Result<()> {
    let len = datagram.len();
    if len > MAX_UDP_DATAGRAM {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "UDP datagram too large",
        ));
    }
    w.write_all(&(len as u16).to_be_bytes()).await?;
    if len > 0 {
        w.write_all(datagram).await?;
    }
    w.flush().await?;
    Ok(())
}

/// Read a length-prefixed UDP frame: `[2B BE len][payload]` into `buf`.
///
/// Returns `Ok(0)` on a zero-length frame (signals end-of-session).
pub(super) async fn read_udp_frame<R: AsyncRead + Unpin>(
    r: &mut R,
    buf: &mut Vec<u8>,
) -> std::io::Result<usize> {
    let mut len_buf = [0u8; 2];
    r.read_exact(&mut len_buf).await?;
    let len = u16::from_be_bytes(len_buf) as usize;
    if len == 0 {
        return Ok(0);
    }
    if len > MAX_UDP_DATAGRAM {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "UDP frame too large",
        ));
    }
    buf.resize(len, 0);
    r.read_exact(&mut buf[..len]).await?;
    Ok(len)
}

/// Returns `true` when the `host:port` target has port 53.
fn is_port_53(target: &str) -> bool {
    match split_host_port(target) {
        Ok((_, port)) => port == 53,
        Err(_) => false,
    }
}

// ── DNS intercept helpers ─────────────────────────────────────────────────────

/// UDP DNS handler for mux streams.
///
/// Reads a single length-prefixed DNS query, resolves via DoH, writes
/// the synthesised response.  Falls back to raw UDP forward on parse failure.
async fn handle_udp_dns_mux(
    stream: &mut TokioMuxStream,
    resolver: &Arc<DoHResolver>,
) -> Result<(), MirageError> {
    let mut frame_buf = Vec::new();
    loop {
        let n = read_udp_frame(stream, &mut frame_buf).await.map_err(MirageError::Io)?;
        if n == 0 {
            break;
        }
        match dns_handler::handle_dns_query(&frame_buf, resolver).await {
            Ok(Some(resp)) => {
                write_udp_frame(stream, &resp).await.map_err(MirageError::Io)?;
            }
            Ok(None) => {
                // Unsupported qtype or empty result — return SERVFAIL so client
                // can retry via a different path.
                if let Some(sf) = make_servfail(&frame_buf) {
                    let _ = write_udp_frame(stream, &sf).await;
                }
                break;
            }
            Err(e) => {
                warn!(?e, "dns_handler: DoH resolve error, returning SERVFAIL");
                if let Some(sf) = make_servfail(&frame_buf) {
                    let _ = write_udp_frame(stream, &sf).await;
                }
                break;
            }
        }
    }
    Ok(())
}

/// UDP DNS handler for classic tunnel path.
async fn handle_udp_dns_tunnel(
    tunnel: &mut Box<dyn Tunnel>,
    resolver: &Arc<DoHResolver>,
) -> Result<(), MirageError> {
    let mut len_buf = [0u8; 2];
    let mut payload_buf = vec![0u8; 65507];

    loop {
        match tunnel.recv(&mut len_buf).await {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
        let payload_len = u16::from_be_bytes(len_buf) as usize;
        if payload_len == 0 {
            break;
        }
        if payload_len > payload_buf.len() {
            warn!("dns_handler (tunnel): oversized UDP DNS frame {payload_len}");
            break;
        }
        match tunnel.recv(&mut payload_buf[..payload_len]).await {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
        let query_bytes = &payload_buf[..payload_len];

        match dns_handler::handle_dns_query(query_bytes, resolver).await {
            Ok(Some(resp)) => {
                let len_bytes = (resp.len() as u16).to_be_bytes();
                if tunnel.send(&len_bytes).await.is_err() {
                    break;
                }
                if tunnel.send(&resp).await.is_err() {
                    break;
                }
            }
            Ok(None) => {
                if let Some(sf) = make_servfail(query_bytes) {
                    let lb = (sf.len() as u16).to_be_bytes();
                    let _ = tunnel.send(&lb).await;
                    let _ = tunnel.send(&sf).await;
                }
                break;
            }
            Err(e) => {
                warn!(?e, "dns_handler (tunnel): DoH resolve error");
                if let Some(sf) = make_servfail(query_bytes) {
                    let lb = (sf.len() as u16).to_be_bytes();
                    let _ = tunnel.send(&lb).await;
                    let _ = tunnel.send(&sf).await;
                }
                break;
            }
        }
    }
    Ok(())
}

/// TCP DNS handler for mux streams.
///
/// TCP DNS framing: `[2B BE length][dns message]` in both directions.
async fn handle_tcp_dns_mux(
    stream: &mut TokioMuxStream,
    resolver: &Arc<DoHResolver>,
) -> Result<(), MirageError> {
    let mut len_buf = [0u8; 2];
    loop {
        if stream.read_exact(&mut len_buf).await.is_err() {
            break;
        }
        let msg_len = u16::from_be_bytes(len_buf) as usize;
        if msg_len == 0 {
            break;
        }
        let mut msg = vec![0u8; msg_len];
        if stream.read_exact(&mut msg).await.is_err() {
            break;
        }

        match dns_handler::handle_dns_query(&msg, resolver).await {
            Ok(Some(resp)) => {
                let rlen = (resp.len() as u16).to_be_bytes();
                if stream.write_all(&rlen).await.is_err() {
                    break;
                }
                if stream.write_all(&resp).await.is_err() {
                    break;
                }
                if stream.flush().await.is_err() {
                    break;
                }
            }
            Ok(None) => {
                if let Some(sf) = make_servfail(&msg) {
                    let rlen = (sf.len() as u16).to_be_bytes();
                    let _ = stream.write_all(&rlen).await;
                    let _ = stream.write_all(&sf).await;
                    let _ = stream.flush().await;
                }
                break;
            }
            Err(e) => {
                warn!(?e, "dns_handler (tcp mux): DoH resolve error");
                if let Some(sf) = make_servfail(&msg) {
                    let rlen = (sf.len() as u16).to_be_bytes();
                    let _ = stream.write_all(&rlen).await;
                    let _ = stream.write_all(&sf).await;
                    let _ = stream.flush().await;
                }
                break;
            }
        }
    }
    Ok(())
}

/// TCP DNS handler for classic tunnel path.
async fn handle_tcp_dns_tunnel(
    mut tunnel: Box<dyn Tunnel>,
    resolver: &Arc<DoHResolver>,
) -> Result<(), MirageError> {
    let mut len_buf = [0u8; 2];
    let mut msg_buf = vec![0u8; 65535];

    loop {
        match tunnel.recv(&mut len_buf).await {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
        let msg_len = u16::from_be_bytes(len_buf) as usize;
        if msg_len == 0 {
            break;
        }
        if msg_len > msg_buf.len() {
            warn!("dns_handler (tcp tunnel): oversized TCP DNS message {msg_len}");
            break;
        }
        match tunnel.recv(&mut msg_buf[..msg_len]).await {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
        let msg = &msg_buf[..msg_len];

        match dns_handler::handle_dns_query(msg, resolver).await {
            Ok(Some(resp)) => {
                let rlen = (resp.len() as u16).to_be_bytes();
                if tunnel.send(&rlen).await.is_err() {
                    break;
                }
                if tunnel.send(&resp).await.is_err() {
                    break;
                }
            }
            Ok(None) => {
                if let Some(sf) = make_servfail(msg) {
                    let rlen = (sf.len() as u16).to_be_bytes();
                    let _ = tunnel.send(&rlen).await;
                    let _ = tunnel.send(&sf).await;
                }
                break;
            }
            Err(e) => {
                warn!(?e, "dns_handler (tcp tunnel): DoH resolve error");
                if let Some(sf) = make_servfail(msg) {
                    let rlen = (sf.len() as u16).to_be_bytes();
                    let _ = tunnel.send(&rlen).await;
                    let _ = tunnel.send(&sf).await;
                }
                break;
            }
        }
    }
    Ok(())
}

/// Build a minimal SERVFAIL response for a DNS query.
/// Returns `None` if the query is too short to extract a transaction ID.
fn make_servfail(query: &[u8]) -> Option<Vec<u8>> {
    if query.len() < 2 {
        return None;
    }
    let mut resp = vec![0u8; 12];
    resp[0] = query[0];
    resp[1] = query[1];
    // QR=1, RD=1, RA=1, RCODE=2 (SERVFAIL)
    resp[2] = 0x81;
    resp[3] = 0x82;
    Some(resp)
}

/// Split a `host:port` string into its parts.
///
/// Handles:
/// - Plain IPv4/hostname: `"example.com:443"` → `("example.com", 443)`
/// - IPv6 literals: `"[::1]:8080"` → `("[::1]", 8080)`
///
/// Public because a standalone box is its own exit: it opens the target
/// socket itself, and it must split the target the SAME way the fleet's exit
/// does — one parser, one set of rules.
pub fn split_host_port(addr: &str) -> Result<(&str, u16), MirageError> {
    if addr.starts_with('[') {
        let bracket_end = addr.find(']').ok_or_else(|| {
            MirageError::Protocol(format!("exit: malformed IPv6 address: {addr}"))
        })?;
        let rest = &addr[bracket_end + 1..];
        let port_str = rest.strip_prefix(':').ok_or_else(|| {
            MirageError::Protocol(format!("exit: missing port in address: {addr}"))
        })?;
        let port = parse_port(port_str, addr)?;
        let host = &addr[..bracket_end + 1];
        return Ok((host, port));
    }

    let colon = addr.rfind(':').ok_or_else(|| {
        MirageError::Protocol(format!("exit: no port in address: {addr}"))
    })?;
    let host = &addr[..colon];
    let port = parse_port(&addr[colon + 1..], addr)?;
    Ok((host, port))
}

fn parse_port(s: &str, full_addr: &str) -> Result<u16, MirageError> {
    s.parse::<u16>().map_err(|_| {
        MirageError::Protocol(format!("exit: invalid port in address: {full_addr}"))
    })
}

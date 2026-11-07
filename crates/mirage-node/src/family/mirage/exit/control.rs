//! TunnelControl exit: Mirage V7 AEAD handshake → bridge plaintext to control_target.
//!
//! After handshake the decrypted tunnel bytes are forwarded verbatim to the
//! monitor's over_chain_control loopback listener (default 127.0.0.1:19445).
//! The monitor's protocol (FRAME_AUTH_CHALLENGE etc) starts from the server
//! side once the bridge is up — the first bytes the client sends post-handshake
//! are auth-protocol bytes, NOT a SOCKS5-style target string.

use std::net::SocketAddr;
use std::time::Duration;

use mirage_core::config::AuthMode;
use mirage_core::crypto::KeyPair;
use mirage_core::error::MirageError;
use socket2::{SockRef, TcpKeepalive};
use tokio::net::TcpStream;
use tracing::{debug, info, warn};

use mirage_protocol::traits::Tunnel;

use crate::core::tunnel_io::copy_tunnel_to_tcp;

/// TunnelControl exit handler.
///
/// Performs the Mirage V7 AEAD handshake on the inbound stream, then bridges
/// the decrypted tunnel to the monitor's over-chain loopback listener at
/// `control_target`. Plane separation is via routing (ListenerKind::TunnelControl
/// → this handler), not via a separate auth label — reuses MIRAGE-AUTH-V5 exactly.
pub async fn handle_control_exit(
    stream: TcpStream,
    control_target: SocketAddr,
    keypair: &KeyPair,
    mesh_id: &[u8],
) -> Result<(), MirageError> {
    let peer = stream.peer_addr().map_err(MirageError::Io)?;

    let ka = {
        let base = TcpKeepalive::new()
            .with_time(Duration::from_secs(60))
            .with_interval(Duration::from_secs(15));
        #[cfg(not(target_os = "windows"))]
        let base = base.with_retries(4);
        base
    };
    if let Err(e) = SockRef::from(&stream).set_tcp_keepalive(&ka) {
        warn!(%peer, "set_tcp_keepalive(client): {e}");
    }

    // Mirage V7 AEAD handshake — same label/transcript as Exit(Direct).
    info!(%peer, %control_target, "control exit: handshaking");
    let auth = mirage_protocol::driver::convert_auth(&AuthMode::Blake3);
    let mut tunnel = match mirage_protocol::driver::handshake_server_stream(
        stream, keypair, &auth, peer, mesh_id, true,
    )
    .await?
    {
        Some(t) => t,
        None => {
            warn!(%peer, "control exit: handshake auth fail");
            return Ok(());
        }
    };

    // Swallow first post-handshake frame from client — it's a target string
    // (e.g. "127.0.0.1:19445") sent by the SOCKS5 dispatch or option-a'
    // `lease.send(target_str)`. TunnelControl ignores the target — bridge
    // always goes to the pre-configured `control_target`. Without this
    // swallow, those bytes leak into monitor's framed protocol ahead of
    // FRAME_AUTH_CHALLENGE → "frame too large" / "malformed".
    let mut discard_buf = vec![0u8; 4096];
    match tunnel.recv(&mut discard_buf).await {
        Ok(0) => {
            debug!(%peer, "control exit: client closed before first frame");
            return Ok(());
        }
        Ok(n) => {
            debug!(%peer, bytes = n, "control exit: discarded target frame");
        }
        Err(e) => {
            warn!(%peer, error = %e, "control exit: recv first frame failed");
            return Ok(());
        }
    }

    // Dial monitor's over_chain loopback listener.
    let monitor_stream = TcpStream::connect(control_target).await.map_err(|e| {
        warn!(%peer, %control_target, error = %e, "control exit: dial failed");
        MirageError::NodeUnreachable(format!("{control_target}: {e}"))
    })?;
    if let Err(e) = SockRef::from(&monitor_stream).set_tcp_keepalive(&ka) {
        warn!(%peer, %control_target, "set_tcp_keepalive(monitor): {e}");
    }

    info!(%peer, %control_target, "control exit: bridging");

    match copy_tunnel_to_tcp(tunnel, monitor_stream).await {
        Ok(_) => {
            debug!(%peer, %control_target, "control exit: bridge closed cleanly");
        }
        Err(e) => {
            debug!(%peer, %control_target, error = %e, "control exit: bridge error");
        }
    }

    Ok(())
}

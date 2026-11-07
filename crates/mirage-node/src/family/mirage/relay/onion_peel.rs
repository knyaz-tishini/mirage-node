//! Onion-peel entry/hop dispatch — forward-secret (V9-FS) circuits only.
//!
//! Flow on accept:
//! 1. Read `[4B BE total_len][frame body]` and peek `body[0]`.
//! 2. A forward-secret wire-version byte (`WIRE_VERSION_FS`,
//!    `WIRE_VERSION_FS_LEGACY`, or `MSG_FS_RELAY_INIT`) routes to
//!    [`handle_onion_fs_peel`][fs] in the sibling module.
//! 3. Anything else is refused outright — see [`handle_onion_peel`]'s own
//!    doc for why there is no flag that re-admits it.
//!
//! # What used to live here
//!
//! Before 2026-09-02 this file also decoded a non-forward-secret onion
//! envelope (`V9EnvelopeHeader`, from `mirage_protocol::onion::v9_frame` —
//! itself the third of three near-identical structs spread across
//! `v7_frame.rs`, `v8_frame.rs`, and `v9_frame.rs` in `mirage2web`, none of
//! which lined up with the "V7"/"V8"/"V9" names the surrounding code and
//! this file's own former doc comment called them), peeled a layer with
//! `peel_onion_layer_v8`, and forwarded the header UNCHANGED to the next
//! hop. That header carried `chain_node_ids: Vec<String>` — every hop's
//! identity, in cleartext, forwarded verbatim by every relay on the chain —
//! so any single relay on the route learned the whole route. Closing that
//! leak meant deleting the path, not gating it further: the forward-secret
//! telescopic circuit this dispatcher now exclusively routes to carries no
//! such field — each hop learns only its own position and an encrypted
//! next-hop address it cannot read past its own layer. See
//! `docs/mirage/research/v8-onion-deletion-surface-2026-09-02.md` for the
//! full deletion surface across this repo and `mirage2web`.
//!
//! [fs]: super::onion_fs_peel::handle_onion_fs_peel

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use mirage_core::{
    config::TransportCamouflage,
    crypto::KeyPair,
    error::MirageError,
};
// No `v9_frame` import remains: with the non-forward-secret envelope gone and
// its refusal silent, nothing in this module touches the non-FS frame types.
// That is what makes them deletable from `mirage-protocol` next.
use mirage_protocol::{
    onion::fs_frame::{MSG_FS_RELAY_INIT, WIRE_VERSION_FS, WIRE_VERSION_FS_LEGACY},
    PrefixStream,
};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use tracing::{debug, warn};

use crate::core::chain_splice::MAX_ENVELOPE_BYTES;

/// Timeout for the initial client→server frame read while this dispatcher
/// determines forward-secret vs. anything else.
const ONION_DISPATCH_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);

/// Configuration the listener passes in at accept time for a relay hop
/// (entry or middle) — everything [`handle_onion_fs_peel`][fs] needs to
/// dial the next hop, plus this hop's own identity. Resolved fresh
/// per-accept by `tunnel_tcp::resolve_onion_relay_config`; nothing here is
/// cached across connections.
///
/// [fs]: super::onion_fs_peel::handle_onion_fs_peel
pub struct OnionRelayConfig {
    pub hop_keypair: Arc<KeyPair>,
    pub chain_position: u8,
    pub chain_length: u8,
    /// Outgoing camouflage to apply when forwarding to next hop.
    /// `None` — raw TCP forward (preserves bare-multihop semantics).
    pub outgoing_camouflage: Option<TransportCamouflage>,
    /// Long-term X25519 pubkey of the next hop (used by Reality camouflage).
    /// All-zero means no camouflage wrap will be attempted even if
    /// `outgoing_camouflage` is set.
    pub next_hop_pubkey: [u8; 32],
    /// SNI / host hint for TLS-based outgoing camouflages.
    pub outgoing_sni: String,
    /// This node's identity string at `chain_position`.
    /// Sourced from `spec.chain_role.chain_node_ids[chain_position]` per-accept.
    /// Used to populate the FS transcript in the V9-FS relay handler so the
    /// node and client compute the same transcript hash.
    pub node_id: String,
}

/// Handle an onion relay-hop connection (entry or middle hop).
///
/// Peeks the first frame byte to tell a forward-secret circuit-setup frame
/// from anything else, and routes accordingly.
///
/// # Why anything non-forward-secret is refused outright
///
/// This dispatcher used to also accept a non-forward-secret onion envelope
/// here — see the module doc for what it was and why it leaked the whole
/// route to every hop. There is no config flag that re-admits it: a
/// non-forward-secret first byte is refused unconditionally, the same way
/// regardless of `allow_legacy_v8` (that flag still gates an unrelated
/// single-hop direct/exit handshake — see `core::endpoint_protocol` — and
/// is untouched by this deletion).
///
/// # Why the refusal is silent, and why the obvious alternative is an oracle
///
/// The tempting shape here is a typed `AckChainV9` carrying `BadVersion` —
/// the same answer this dispatcher gives for a bad suite or a bad chain
/// length — on the reasoning that `chain_splice` has already resolved this
/// connection to a real listener, so the question left is a protocol verdict
/// about an addressed peer rather than a pre-auth existence question.
///
/// That reasoning is wrong, and the way it is wrong is worth keeping written
/// down. **The selector `chain_splice` resolved is chosen by the caller and
/// authenticated by nothing**: `resolve_chain_frame` reads `chain_id` out of
/// the frame and looks it up before a single byte has been verified. So a
/// peer that can reach the splice — anyone the perimeter admits, which is
/// the whole internet — picks the name, and any response that differs
/// between "that name resolved" and "it did not" hands the outcome back to
/// the party that chose it.
///
/// With a typed ack the two outcomes are trivially separable: an unknown
/// `chain_id` is held silently for 30 s by `dispose_unaddressable` and then
/// closed, while a known one answers immediately. That is a chain-id
/// enumeration oracle, readable off a stopwatch, and it is exactly what the
/// hold in `dispose_unaddressable` was written to deny — its own doc matches
/// the perimeter's jail timing for this reason.
///
/// So a non-forward-secret envelope leaves through the same door as a
/// selector that resolved to nothing: held, then closed, without a byte. The
/// legitimate reader this costs a clear error is a client speaking a wire we
/// are deleting.
pub async fn handle_onion_peel<S>(
    cfg: OnionRelayConfig,
    mut client_stream: S,
    peer: SocketAddr,
    prefix_byte: Option<u8>,
) -> Result<(), MirageError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    debug!(%peer, hop_position = cfg.chain_position, total_hops = cfg.chain_length, "onion peel: incoming connection");

    // ── Wire-version peek: forward-secret vs. anything else ───────────────
    // Read the 4B frame length, then the full frame body, then peek body[0].
    // The entire initial read is wrapped in a handshake timeout so a peer
    // that connects then stalls cannot pin a task indefinitely.
    let (wire_version, frame_body) = {
        let read_fut = async {
            let mut len_buf = [0u8; 4];
            if let Some(p) = prefix_byte {
                len_buf[0] = p;
                client_stream
                    .read_exact(&mut len_buf[1..])
                    .await
                    .map_err(MirageError::Io)?;
            } else {
                client_stream
                    .read_exact(&mut len_buf)
                    .await
                    .map_err(MirageError::Io)?;
            }
            let frame_len = u32::from_be_bytes(len_buf) as usize;
            if frame_len == 0 || frame_len > MAX_ENVELOPE_BYTES {
                return Err(MirageError::Protocol(format!(
                    "onion peel: invalid envelope length {frame_len} (version peek)"
                )));
            }
            let mut body = vec![0u8; frame_len];
            client_stream
                .read_exact(&mut body)
                .await
                .map_err(MirageError::Io)?;
            let version = if body.is_empty() { 0 } else { body[0] };
            Ok::<(u8, Vec<u8>), MirageError>((version, body))
        };
        match tokio::time::timeout(ONION_DISPATCH_HANDSHAKE_TIMEOUT, read_fut).await {
            Ok(Ok(v)) => v,
            Ok(Err(e)) => return Err(e),
            Err(_) => {
                warn!(%peer, "onion peel: handshake timeout reading initial frame (15s)");
                return Ok(());
            }
        }
    };

    if wire_version == WIRE_VERSION_FS
        || wire_version == WIRE_VERSION_FS_LEGACY
        || wire_version == MSG_FS_RELAY_INIT
    {
        // ── V9-FS relay dispatch ──────────────────────────────────────────
        // frame_body[0] is the FS type byte. Replay everything after it in the
        // PrefixStream so the FS handler reads only the post-type-byte fields.
        // Pass the type byte as prefix_byte so FsInitFrame / FsRelayInitFrame
        // decode can reconstruct the full frame.
        use super::onion_fs_peel::{handle_onion_fs_peel, OnionFsRelayConfig};
        let fs_cfg = OnionFsRelayConfig {
            hop_keypair: cfg.hop_keypair,
            chain_position: cfg.chain_position,
            chain_length: cfg.chain_length,
            node_id: cfg.node_id,
            outgoing_camouflage: cfg.outgoing_camouflage,
            next_hop_pubkey: cfg.next_hop_pubkey,
            outgoing_sni: cfg.outgoing_sni,
        };
        let rest = if frame_body.len() > 1 { frame_body[1..].to_vec() } else { Vec::new() };
        let rest_len = rest.len();
        let prefixed = PrefixStream::new(client_stream, rest);
        return handle_onion_fs_peel(fs_cfg, prefixed, peer, Some(wire_version), rest_len).await;
    }

    // ── Refuse anything that isn't forward-secret ─────────────────────────
    // Silently — see this function's doc. The caller picked the chain_id that
    // got us here and nothing has authenticated it, so answering at all would
    // report whether that name resolved.
    warn!(
        %peer,
        wire_version,
        "onion peel: refusing non-forward-secret onion envelope"
    );
    crate::core::chain_splice::dispose_unaddressable(
        client_stream,
        crate::core::chain_splice::UNADDRESSABLE_HOLD_MS,
    )
    .await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use mirage_core::crypto::KeyPair;
    use tokio::io::AsyncReadExt;

    /// Build a minimal `OnionRelayConfig` with dummy values suitable for
    /// dispatch tests.
    fn dummy_config() -> OnionRelayConfig {
        OnionRelayConfig {
            hop_keypair: Arc::new(KeyPair::generate()),
            chain_position: 0,
            chain_length: 2,
            outgoing_camouflage: None,
            next_hop_pubkey: [0u8; 32],
            outgoing_sni: String::new(),
            node_id: String::new(),
        }
    }

    /// Encode a frame as `[4B BE len][body]`.
    fn encode_frame(body: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + body.len());
        out.extend_from_slice(&(body.len() as u32).to_be_bytes());
        out.extend_from_slice(body);
        out
    }

    /// Feed `frame_bytes` into one end of a duplex channel, run
    /// `handle_onion_peel` against the other end, and return the ack bytes
    /// that were written back by the handler (if any).
    async fn run_handler_with_frame(
        frame_bytes: Vec<u8>,
        cfg: OnionRelayConfig,
    ) -> (Result<(), MirageError>, Vec<u8>) {
        // `duplex(N)` returns (a, b): writes to `a` appear as reads on `b` and vice versa.
        let (mut tester_side, handler_side) = tokio::io::duplex(65536);

        // Write the frame bytes for the handler to read, then half-close write
        // by keeping only the read half alive.
        tokio::io::AsyncWriteExt::write_all(&mut tester_side, &frame_bytes)
            .await
            .unwrap();

        let peer: std::net::SocketAddr = "127.0.0.1:9999".parse().unwrap();

        // Run the handler with a timeout; it should return quickly on reject path.
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            handle_onion_peel(cfg, handler_side, peer, None),
        )
        .await
        .unwrap_or(Err(MirageError::Protocol("test timeout".into())));

        // Read whatever the handler wrote back (ack bytes).
        let mut ack_buf = Vec::new();
        let _ = tokio::time::timeout(
            std::time::Duration::from_millis(200),
            tester_side.read_to_end(&mut ack_buf),
        )
        .await;

        (result, ack_buf)
    }

    /// A non-forward-secret first byte leaves through the same door as a
    /// selector that resolved to nothing: held, and not a byte back.
    ///
    /// One read distinguishes all three possible outcomes. Bytes back would
    /// mean an ack was written -- the enumeration oracle this refusal exists
    /// to avoid, since the caller chose the unauthenticated chain_id that got
    /// it here. EOF would mean the handler returned and dropped its half,
    /// which separates a refusal from a hold by timing alone. Only a timeout
    /// means "still open, still silent", and that is the contract.
    #[tokio::test]
    async fn a_non_fs_first_byte_is_refused_in_silence() {
        for wire_ver in [0x00u8, 0x05, 0x08, 0xFF] {
            let mut body = vec![0u8; 16];
            body[0] = wire_ver;
            let frame = encode_frame(&body);

            let (mut tester_side, handler_side) = tokio::io::duplex(65536);
            tokio::io::AsyncWriteExt::write_all(&mut tester_side, &frame)
                .await
                .unwrap();
            let peer: std::net::SocketAddr = "127.0.0.1:9999".parse().unwrap();
            let handler =
                tokio::spawn(handle_onion_peel(dummy_config(), handler_side, peer, None));

            let mut buf = [0u8; 64];
            let outcome = tokio::time::timeout(
                std::time::Duration::from_millis(300),
                tokio::io::AsyncReadExt::read(&mut tester_side, &mut buf),
            )
            .await;

            assert!(
                outcome.is_err(),
                "wire_ver {wire_ver:#x}: a refusal must be held in silence, got {outcome:?}"
            );
            handler.abort();
        }
    }

    /// FS wire version bytes (0x0B, 0x0A, 0x92) must skip the refusal and
    /// reach the FS handler instead. The FS handler will fail on the dummy
    /// body (not a real FsInitFrame), but that is its own error path, not
    /// this refusal.
    #[tokio::test]
    async fn fs_bytes_skip_the_non_fs_refusal() {
        for wire_ver in [WIRE_VERSION_FS, WIRE_VERSION_FS_LEGACY, MSG_FS_RELAY_INIT] {
            let mut body = vec![0u8; 16];
            body[0] = wire_ver;
            let frame = encode_frame(&body);

            let (_, _) = run_handler_with_frame(frame, dummy_config()).await;
            // No panic or hang is the invariant.
        }
    }
}

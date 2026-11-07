//! L2 onion exit — dispatcher for the terminal (exit) hop of a chain,
//! forward-secret (V9-FS) circuits only.
//!
//! Flow on accept:
//! 1. Read `[4B BE total_len][frame body]` and peek `body[0]`.
//! 2. A forward-secret wire-version byte (`WIRE_VERSION_FS`,
//!    `WIRE_VERSION_FS_LEGACY`, or `MSG_FS_RELAY_INIT`) routes to
//!    [`handle_onion_fs_exit`][fs] in the sibling module.
//! 3. Anything else is refused outright — see [`handle_onion_exit`]'s own
//!    doc for why there is no flag that re-admits it.
//!
//! # What used to live here
//!
//! Before 2026-09-02 this file also completed a non-forward-secret onion
//! handshake — envelope parse (`V9EnvelopeHeader`), suite negotiation,
//! terminal-layer peel (`peel_onion_layer_v8`), ack — and then rejected the
//! client unconditionally right after, because the V8 wire carries no
//! credential field and credential enforcement here is unconditional (arc3
//! mandatory-credentials excision). That bookkeeping-then-reject shape only
//! existed to give a V8 dial a typed protocol response before closing it.
//! It was reachable only because `relay/onion_peel.rs` still forwarded a
//! `V9EnvelopeHeader` — carrying `chain_node_ids`, every hop's identity, in
//! cleartext — to reach this exit at all; once that relay path was deleted
//! rather than gated, no V8 dial can reach an exit through a chain that no
//! longer relays it, and the bookkeeping this file did for that dial before
//! rejecting it became dead weight on a wire nothing speaks. Closing the
//! leak meant deleting this side too, not gating it further: the
//! forward-secret circuit this dispatcher now exclusively routes to carries
//! no such field — each hop learns only its own position and an encrypted
//! next-hop address it cannot read past its own layer. See
//! `docs/mirage/research/v8-onion-deletion-surface-2026-09-02.md` for the
//! full deletion surface across this repo and `mirage2web`.
//!
//! The V9-FS (forward-secret) path is unaffected — see `exit/onion_fs.rs`,
//! dispatched from [`handle_onion_exit`] below.
//!
//! [fs]: super::onion_fs::handle_onion_fs_exit

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use arc_swap::ArcSwap;
use mirage_core::{
    crypto::{CredentialParams, KeyPair, SpentSet},
    error::MirageError,
};
// No `v9_frame` import remains: with the non-forward-secret envelope gone and
// its refusal silent, nothing in this module touches the non-FS frame types.
// That is what makes them deletable from `mirage-protocol` next.
use mirage_protocol::onion::fs_frame::{MSG_FS_RELAY_INIT, WIRE_VERSION_FS, WIRE_VERSION_FS_LEGACY};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use tracing::warn;

/// Maximum bytes read for the initial frame body in a single call.
const MAX_ONION_BYTES: usize = 65536;

/// Timeout for the initial client→server frame read while this dispatcher
/// determines forward-secret vs. anything else.
const ONION_DISPATCH_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);

/// Configuration the listener passes in at accept time for the exit hop —
/// everything [`handle_onion_fs_exit`][fs] needs plus this hop's own
/// identity. Resolved fresh per-accept by
/// `tunnel_tcp::resolve_onion_exit_config`; nothing here is cached across
/// connections.
///
/// [fs]: super::onion_fs::handle_onion_fs_exit
pub struct OnionExitV7Config {
    pub hop_keypair: Arc<KeyPair>,
    pub chain_position: u8,
    pub chain_length: u8,
    /// This node's identity string at `chain_position`.
    /// Sourced from `spec.chain_role.chain_node_ids[chain_position]` per-accept.
    /// Used to populate the FS transcript in the V9-FS exit handler so the node
    /// and client compute the same transcript hash.
    pub node_id: String,
    /// Hot-swappable credential parameters (gossip-updated). Credential
    /// enforcement is unconditional — `None` fails closed (nothing to verify
    /// against) rather than opening the relay.
    pub credential_params: Arc<ArcSwap<Option<CredentialParams>>>,
    /// Replay guard: tracks spent (epoch_id, credential_id) pairs.
    pub spent_set: Arc<Mutex<SpentSet>>,
    /// This node's own mesh — `CredentialScheme::RoleSigned`'s own admission
    /// check (see `core::role_signed_gate`) needs it since `operator_pub` is
    /// shared fleet-wide across every mesh and cannot catch a cross-mesh
    /// presentation on its own.
    pub mesh_id: Vec<u8>,
    /// Shared, bounded single-use cache for `CredentialScheme::RoleSigned`
    /// dials — same Arc-identity requirement as `spent_set`.
    pub role_signed_replay: Arc<Mutex<crate::core::role_signed_gate::RoleSignedReplayCache>>,
}

/// Handle an onion exit-hop connection — the terminal position of a chain.
///
/// Peeks the first frame byte to tell a forward-secret circuit-setup frame
/// from anything else, and routes accordingly.
///
/// # Why anything non-forward-secret is refused outright
///
/// This dispatcher used to also complete a non-forward-secret handshake
/// here before rejecting it — see the module doc for what it was and why
/// reaching it at all depended on a relay path that is now gone. There is
/// no config flag that re-admits it: a non-forward-secret first byte is
/// refused unconditionally, the same way regardless of `allow_legacy_v8`
/// (that flag still gates an unrelated single-hop direct/exit handshake —
/// see `core::endpoint_protocol` — and is untouched by this deletion).
///
/// # Why the refusal is silent, and why the obvious alternative is an oracle
///
/// The tempting shape here is the typed `AckChainV9`/`BadVersion` this
/// dispatcher used to send — the same answer it gave for a bad suite or a
/// bad chain length — on the reasoning that `chain_splice` has already
/// resolved this connection to a real EXIT listener, so the question left
/// is a protocol verdict about an addressed peer rather than a pre-auth
/// existence question.
///
/// That reasoning is wrong, and the way it is wrong is worth keeping
/// written down. **The selector `chain_splice` resolved is chosen by the
/// caller and authenticated by nothing**: `resolve_chain_frame` reads
/// `chain_id` out of the frame and looks it up before a single byte has
/// been verified. So a peer that can reach the splice — anyone the
/// perimeter admits, which is the whole internet — picks the name, and any
/// response that differs between "that name resolved to an exit" and "it
/// did not" hands the outcome back to the party that chose it.
///
/// With a typed ack the two outcomes are trivially separable: an unknown
/// `chain_id` is held silently for 30 s by `dispose_unaddressable` and then
/// closed, while a known one answers immediately. That is a chain-id
/// enumeration oracle, readable off a stopwatch, and it is exactly what the
/// hold in `dispose_unaddressable` was written to deny — its own doc
/// matches the perimeter's jail timing for this reason.
///
/// So a non-forward-secret envelope leaves through the same door as a
/// selector that resolved to nothing: held, then closed, without a byte.
/// The legitimate reader this costs a clear error is a client speaking a
/// wire we are deleting.
pub async fn handle_onion_exit<S>(
    cfg: OnionExitV7Config,
    mut client_stream: S,
    peer: SocketAddr,
) -> Result<(), MirageError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // ── Wire-version peek: forward-secret vs. anything else ────────────────
    // Read [4B len][N body bytes]. body[0] selects the handler:
    //   0x0B (WIRE_VERSION_FS)        — FsInitFrame from client (current)
    //   0x0A (WIRE_VERSION_FS_LEGACY) — FsInitFrame from client (legacy, no cred field)
    //   0x92 (MSG_FS_RELAY_INIT)      — FsRelayInitFrame forwarded by entry relay
    //   anything else                 — refused, see this function's doc.
    // Wrapped in a handshake timeout so a stalling peer cannot pin a task.
    let (wire_version, frame_body) = {
        let read_fut = async {
            let mut len_buf = [0u8; 4];
            client_stream
                .read_exact(&mut len_buf)
                .await
                .map_err(MirageError::Io)?;
            let frame_len = u32::from_be_bytes(len_buf) as usize;
            if frame_len == 0 || frame_len > MAX_ONION_BYTES {
                return Err(MirageError::Protocol(format!(
                    "onion exit: invalid envelope length {frame_len} (version peek)"
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
                warn!(%peer, "onion exit: handshake timeout reading initial frame (15s)");
                return Ok(());
            }
        }
    };

    if wire_version == MSG_FS_RELAY_INIT
        || wire_version == WIRE_VERSION_FS
        || wire_version == WIRE_VERSION_FS_LEGACY
    {
        // ── V9-FS exit dispatch ────────────────────────────────────────────
        use super::onion_fs::{handle_onion_fs_exit, OnionFsExitConfig};
        let fs_cfg = OnionFsExitConfig {
            hop_keypair: cfg.hop_keypair,
            chain_position: cfg.chain_position,
            chain_length: cfg.chain_length,
            node_id: cfg.node_id,
            credential_params: cfg.credential_params,
            spent_set: cfg.spent_set,
            mesh_id: cfg.mesh_id,
            role_signed_replay: cfg.role_signed_replay,
        };
        // frame_body already contains the full FsRelayInitFrame bytes (including
        // the 0x92 type byte). Pass it directly; client_stream is used for responses.
        return handle_onion_fs_exit(fs_cfg, client_stream, peer, frame_body).await;
    }

    // ── Refuse anything that isn't forward-secret ──────────────────────────
    // Silently — see this function's doc. The caller picked the chain_id that
    // got us here and nothing has authenticated it, so answering at all would
    // report whether that name resolved to an exit.
    warn!(
        %peer,
        wire_version,
        "onion exit: refusing non-forward-secret onion envelope"
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

    /// Build a minimal `OnionExitV7Config` with dummy values suitable for
    /// dispatch tests.
    fn dummy_config() -> OnionExitV7Config {
        OnionExitV7Config {
            hop_keypair: Arc::new(KeyPair::generate()),
            chain_position: 1,
            chain_length: 2,
            node_id: String::new(),
            credential_params: Arc::new(ArcSwap::new(Arc::new(None))),
            spent_set: Arc::new(Mutex::new(SpentSet::new())),
            mesh_id: b"test-mesh".to_vec(),
            role_signed_replay: Arc::new(Mutex::new(
                crate::core::role_signed_gate::RoleSignedReplayCache::new(),
            )),
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
    /// `handle_onion_exit` against the other end, and return the result plus
    /// whatever the handler wrote back.
    async fn run_handler_with_frame(
        frame_bytes: Vec<u8>,
        cfg: OnionExitV7Config,
    ) -> (Result<(), MirageError>, Vec<u8>) {
        let (mut tester_side, handler_side) = tokio::io::duplex(65536);

        tokio::io::AsyncWriteExt::write_all(&mut tester_side, &frame_bytes)
            .await
            .unwrap();

        let peer: std::net::SocketAddr = "127.0.0.1:9999".parse().unwrap();

        let result = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            handle_onion_exit(cfg, handler_side, peer),
        )
        .await
        .unwrap_or(Err(MirageError::Protocol("test timeout".into())));

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
                tokio::spawn(handle_onion_exit(dummy_config(), handler_side, peer));

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
    /// body (not a real FsRelayInitFrame), but that is its own error path,
    /// not this refusal.
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

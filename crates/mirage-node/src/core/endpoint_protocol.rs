//! `EndpointProtocol` — adapter that bridges `MirageEndpointConfig` to the
//! legacy `TcpProtocol` trait.
//!
//! The old per-struct protocol types (MirageProtocol, MirageRealityProtocol,
//! etc.) have been removed.  This adapter wraps a `MirageEndpointConfig` +
//! `KeyPair` pair and delegates to `mirage_protocol::driver` for both the
//! server-side accept path (`run_server_tcp` / `run_server_tcp_with_auth`) and
//! the client-side connect path (`run_client_tcp_v9`).
//!
//! This keeps the rest of the node code (listener.rs, upstream_pool.rs, etc.)
//! unchanged — they continue to work with `Arc<dyn TcpProtocol>`.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use arc_swap::ArcSwap;
use async_trait::async_trait;
use mirage_core::{
    config::{CamouflageMode, MirageEndpointConfig, TcpProtocolId},
    crypto::{CredentialParams, KeyPair, SpentSet},
    error::MirageError,
};
use mirage_protocol::{
    driver::{run_client_tcp_v9, run_server_tcp, run_server_tcp_with_auth},
    traits::{AcceptResult, TcpProtocol, Tunnel},
};
use tokio::net::TcpStream;

/// Credential-auth state threaded into `EndpointProtocol` so that the bare
/// (camouflage=None) accept path verifies anonymous credentials exactly like
/// the camouflaged path in `handle_pipelined_non_onion`.
///
/// Both fields are `Arc`-backed and shared with the long-lived
/// `NodeRuntime` — gossip frames call `runtime.credential_params.store()`
/// and every `EndpointProtocol` that holds a clone of the **same** `Arc`
/// observes the update without a protocol rebuild.
///
/// Credential enforcement is unconditional (no `require` toggle) — the
/// accept closure built from this state always rejects scheme=0x00
/// (no-credential) dials and fails closed when `params` is `None`.
#[derive(Clone)]
pub struct CredentialAuthState {
    /// Hot-swappable credential params (set by gossip `PushCredentialParams`).
    pub params: Arc<ArcSwap<Option<CredentialParams>>>,
    /// Replay guard — shared epoch→nonce set.
    pub spent:  Arc<Mutex<SpentSet>>,
    /// Shared, bounded single-use cache for `CredentialScheme::RoleSigned`
    /// dials — MUST be an `Arc`-clone of the same allocation stored on
    /// `NodeRuntime.role_signed_replay` (mirrors `spent`'s own Arc-identity
    /// requirement) so a token replayed against this bare accept path is
    /// caught the same way it would be on every other listener.
    pub role_signed_replay: Arc<Mutex<crate::core::role_signed_gate::RoleSignedReplayCache>>,
}

/// Adapter that wraps a `MirageEndpointConfig` and implements [`TcpProtocol`].
///
/// - **Server side**: `accept` calls `driver::run_server_tcp` (no credential
///   auth) or `driver::run_server_tcp_with_auth` (when `credential_auth` is
///   set, i.e. the bare-exit path).
/// - **Client side**: `connect` calls `driver::run_client_tcp_v9` (V9, forward-secret).
pub struct EndpointProtocol {
    config: MirageEndpointConfig,
    keypair: KeyPair,
    /// The logical ID reported to the rest of the node infrastructure.
    protocol_id: TcpProtocolId,
    /// Mesh identifier baked into the Blake3 confirm label (Phase 2).
    mesh_id: Vec<u8>,
    /// This node's own identity, bound into credential verification as
    /// `dial_context` (mirrors the v9-fs onion-exit path) so a credential
    /// minted for a different exit cannot be replayed here.
    node_id: Vec<u8>,
    /// When `Some`, the server accept path runs credential verification.
    /// When `None`, falls through to the original `run_server_tcp` behaviour
    /// (no credential check — byte-identical to the pre-Phase-C-gap state).
    credential_auth: Option<CredentialAuthState>,
    /// Data-plane V8 policy threaded into the driver handshake.
    ///
    /// `true`  → accept V8 + V9 frames (default; fleet-safe).
    /// `false` → reject V8 frames with `VERSION_REJECT (0xFF)`.
    ///
    /// Set via [`EndpointProtocol::with_allow_legacy_v8`] at build time.
    allow_legacy_v8: bool,
}

impl EndpointProtocol {
    /// Create a new adapter without credential auth (back-compat default).
    ///
    /// `mesh_id` — mesh identifier bytes for the BLAKE3 confirm label.
    /// `node_id` — this node's own identity, bound into credential
    /// verification as `dial_context` when `credential_auth` is attached.
    pub fn new(
        config: MirageEndpointConfig,
        keypair: KeyPair,
        protocol_id: TcpProtocolId,
        mesh_id: Vec<u8>,
        node_id: Vec<u8>,
    ) -> Self {
        Self {
            config,
            keypair,
            protocol_id,
            mesh_id,
            node_id,
            credential_auth: None,
            allow_legacy_v8: true,
        }
    }

    /// Override the data-plane V8 policy.
    ///
    /// `true`  → accept V8 + V9 (default).
    /// `false` → reject V8 with `VERSION_REJECT (0xFF)`.
    pub fn with_allow_legacy_v8(mut self, v: bool) -> Self {
        self.allow_legacy_v8 = v;
        self
    }

    /// Attach credential-auth state so the accept path verifies anonymous
    /// credentials on the bare (camouflage=None) wire.
    ///
    /// The `CredentialAuthState` fields must be `Arc`-clones of the SAME
    /// allocations stored on `NodeRuntime.credential_params` /
    /// `NodeRuntime.spent_set` — this is the Arc-identity guarantee that
    /// makes gossip updates visible to this protocol's accept closure.
    pub fn with_credential_auth(mut self, state: CredentialAuthState) -> Self {
        self.credential_auth = Some(state);
        self
    }
}

#[async_trait]
impl TcpProtocol for EndpointProtocol {
    async fn connect(
        &self,
        addr: SocketAddr,
        server_pubkey: &[u8; 32],
        sni: &str,
        _camouflage: CamouflageMode,
    ) -> Result<Box<dyn Tunnel>, MirageError> {
        // V9 forward-secret dial: ephemeral×ephemeral FS inside the handshake;
        // node static priv is used only in the proof MAC, not for secrecy.
        // Relay-outbound carries no anonymous credential (peers are in peer_table).
        let client_priv: [u8; 32] = self.keypair.secret.to_bytes();
        run_client_tcp_v9(&self.config, addr, server_pubkey, &client_priv, sni, &self.mesh_id, None).await
    }

    async fn accept(
        &self,
        stream: TcpStream,
        _peeked: &[u8],
    ) -> Result<AcceptResult, MirageError> {
        // `run_server_tcp` / `run_server_tcp_with_auth` consume the stream
        // during the handshake.  If auth fails (returns `None`), the
        // connection is dropped with a log warning — we cannot restore the
        // stream for a probe-resistance fallback at this point.
        //
        // Node receiver stays permissive (allow_legacy_v8: true) — the V8
        // gate applies only to the monitor control plane, not to data-plane
        // node listeners.
        //
        // When `credential_auth` is `Some`, we invoke `run_server_tcp_with_auth`
        // so that the bare (camouflage=None) accept path enforces the same
        // anonymous-credential policy as the camouflaged path.  When `None`,
        // we call the original `run_server_tcp` — byte-identical to pre-fix
        // behaviour (fleet back-compat for non-exit/non-credential listeners).
        let peer_addr = stream
            .peer_addr()
            .unwrap_or_else(|_| "0.0.0.0:0".parse().expect("static fallback addr parses"));

        let result = if let Some(ca) = &self.credential_auth {
            run_server_tcp_with_auth(
                &self.config,
                &self.keypair,
                stream,
                &self.mesh_id,
                crate::core::listener::make_credential_auth(
                    ca.params.clone(),
                    ca.spent.clone(),
                    peer_addr,
                    self.node_id.clone(),
                    self.mesh_id.clone(),
                    ca.role_signed_replay.clone(),
                ),
                self.allow_legacy_v8,
            )
            .await?
        } else {
            run_server_tcp(&self.config, &self.keypair, stream, &self.mesh_id, self.allow_legacy_v8).await?
        };

        match result {
            Some(tunnel) => Ok(AcceptResult::Tunnel(tunnel)),
            None => Err(MirageError::AuthFailed),
        }
    }

    fn id(&self) -> TcpProtocolId {
        self.protocol_id
    }

    fn probe_resistant(&self) -> bool {
        // All new-API endpoints are considered probe-resistant (they use BLAKE3
        // auth and return an auth error for unauthenticated connections).
        true
    }
}

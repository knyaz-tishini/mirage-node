use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use mirage_core::config::{ProtocolId, RelayMode};
use serde::{Deserialize, Serialize};
use serde_json::json;

/// Point-in-time health snapshot returned by `GET /admin/health`.
#[derive(Debug, Serialize)]
pub struct NodeAdminHealth {
    pub node_id: String,
    pub uptime_secs: u64,
    pub active_tunnels: u32,
    /// Protocol IDs currently active (in priority order).
    pub protocols: Vec<String>,
    /// Relay mode string, if the node is in relay or hybrid mode.
    pub relay_mode: Option<String>,
    /// Per-upstream connection info (empty for Exit-mode nodes).
    pub upstreams: Vec<UpstreamAdminInfo>,
    /// Increments on every successful runtime reconfiguration.
    pub config_version: u64,
    /// Count of `PushPeerTable` frames dropped because their generation was
    /// older than the currently-stored generation (stale broadcast race).
    /// Non-zero value indicates monitor mesh broadcast ordering issues.
    pub peer_table_stale_drops: u64,
}

/// Per-upstream connection statistics.
#[derive(Debug, Serialize)]
pub struct UpstreamAdminInfo {
    pub addr: String,
    pub active_connections: u32,
    pub total_connections: u64,
    pub reconnect_count: u64,
}

/// Request body for `PUT /admin/protocols`.
///
/// Replaces the entire active protocol chain with the provided list.
/// Existing in-flight connections are unaffected — they hold their own
/// `Arc<NodeRuntimeSnapshot>` from before the swap.
#[derive(Debug, Deserialize)]
pub struct SetProtocolsRequest {
    /// Ordered list of protocol IDs to activate (replaces current list).
    pub protocols: Vec<ProtocolId>,
    /// PSK for protocols that require it (ShadowTLS, Hysteria2).
    /// When provided, the `psk` field in the stored `NodeConfig` is updated
    /// before the protocol chain is rebuilt.
    pub psk: Option<String>,
}

/// Request body for `PUT /admin/relay-mode`.
#[derive(Debug, Deserialize)]
pub struct SetRelayModeRequest {
    pub mode: RelayMode,
}

/// A single upstream entry in a [`SetUpstreamsRequest`].
#[derive(Debug, Deserialize)]
pub struct UpstreamEntry {
    /// Remote address in `"IP:PORT"` format.
    pub addr: String,
    /// Hex-encoded X25519 public key (64 hex characters = 32 bytes).
    pub public_key: String,
    /// Protocol to use when connecting to this upstream.
    /// When absent, the first protocol in the active chain is used.
    pub protocol: Option<ProtocolId>,
}

/// Request body for `PUT /admin/upstreams`.
///
/// Replaces the entire upstream list atomically.  Pools whose address and
/// public key are unchanged are reused; new/changed entries get fresh pools;
/// removed entries have their pools dropped after the swap completes (the pool
/// background task exits on its next wake-up due to the `Weak` reference).
#[derive(Debug, Deserialize)]
pub struct SetUpstreamsRequest {
    pub upstreams: Vec<UpstreamEntry>,
}

/// Successful reconfiguration response.
#[derive(Debug, Serialize)]
pub struct ReconfigResponse {
    pub status: &'static str,
    pub config_version: u64,
    pub message: String,
}

/// Request body for `PUT /admin/dns-prefer-ipv6`.
#[derive(Debug, Deserialize)]
pub struct SetDnsPreferIpv6Request {
    /// `true` → prefer AAAA; `false` → prefer A.
    pub prefer_ipv6: bool,
}

/// Errors that management handlers can return.
#[derive(Debug, thiserror::Error)]
pub enum ManagementError {
    #[error("protocol '{0}' requires reality config but none present")]
    MissingReality(String),
    #[error("node is in exit mode — relay-mode changes are not applicable")]
    NotARelay,
    #[error("invalid upstream address '{addr}': {source}")]
    InvalidUpstreamAddr {
        addr: String,
        #[source]
        source: std::net::AddrParseError,
    },
    #[error("invalid upstream public key '{key}': expected 64 hex characters (32 bytes)")]
    InvalidUpstreamKey { key: String },
    #[error("node has no DoH resolver configured — set dns_resolver in exit config")]
    NoDohConfigured,
    #[error("failed to rebuild DoH resolver: {0}")]
    DohRebuildFailed(String),
}

impl IntoResponse for ManagementError {
    fn into_response(self) -> Response {
        let status = match &self {
            ManagementError::NotARelay | ManagementError::NoDohConfigured => {
                StatusCode::BAD_REQUEST
            }
            ManagementError::InvalidUpstreamAddr { .. }
            | ManagementError::InvalidUpstreamKey { .. }
            | ManagementError::DohRebuildFailed(_) => StatusCode::UNPROCESSABLE_ENTITY,
            _ => StatusCode::UNPROCESSABLE_ENTITY,
        };
        (status, Json(json!({ "error": self.to_string() }))).into_response()
    }
}

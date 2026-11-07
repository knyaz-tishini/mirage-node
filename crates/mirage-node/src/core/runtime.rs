use std::collections::HashMap;
use std::sync::{
    atomic::{AtomicU32, AtomicU64, Ordering},
    Arc, Mutex, RwLock,
};
use std::time::Instant;

use ed25519_dalek::VerifyingKey;

use arc_swap::{ArcSwap, ArcSwapOption};
use mirage_core::mirage::mesh::ChainBindings;
use mirage_core::config::NodeConfig;
use mirage_core::crypto::{CredentialParams, KeyPair, SpentSet};
use mirage_core::mirage::mesh::{PeerTable, PeerTableEntry};
use mirage_protocol::traits::TcpProtocol;

use crate::core::doh::DoHResolver;
use crate::core::health::HealthReporter;
use crate::core::metrics::MetricsRegistry;
use crate::family::mirage::relay::relay_metrics::RelayMetrics;
use crate::family::mirage::relay::upstream_pool::UpstreamPool;

/// Mutable runtime state, hot-swapped via [`ArcSwap`].
///
/// All fields inside the snapshot are immutable once published — a fresh
/// snapshot replaces the whole `ArcSwap` payload (`runtime.snapshot.store(…)`)
/// rather than any field being mutated in place.
///
/// `credential_params` and `spent_set` are intentionally NOT here — they live
/// on the long-lived [`NodeRuntime`] so gossip frames can hot-swap the params
/// without a full snapshot rebuild. Each snapshot receives an `Arc` clone of
/// those runtime fields; all snapshots share the same underlying allocation.
pub struct NodeRuntimeSnapshot {
    /// Ordered list of TCP protocol implementations in effect for new connections.
    pub protocols: Vec<Arc<dyn TcpProtocol>>,
    /// Pre-warmed upstream tunnel pools (one per upstream, CryptoRelay mode only).
    pub pools: Vec<Arc<UpstreamPool>>,
    /// Per-upstream traffic metrics (None in Exit / Transparent mode).
    pub relay_metrics: Option<Arc<RelayMetrics>>,
    /// Config snapshot used when this set of protocols/pools was built.
    pub node_config: NodeConfig,
    /// Arc-clone of [`NodeRuntime::credential_params`].
    ///
    /// The Arc is SHARED with the long-lived runtime — gossip stores a new value
    /// into `runtime.credential_params` and EVERY current snapshot (and every
    /// future one) observes the update without a snapshot rebuild.
    pub credential_params: Arc<ArcSwap<Option<CredentialParams>>>,
    /// Arc-clone of [`NodeRuntime::spent_set`].
    pub spent_set: Arc<Mutex<SpentSet>>,
    /// Arc-clone of [`NodeRuntime::role_signed_replay`] — shared the same
    /// way `spent_set` is, so an `EndpointProtocol` accept closure built
    /// before `NodeRuntime::new` runs (see `configurator_main::build_empty_runtime`)
    /// still observes the SAME replay cache every other accept path uses.
    pub role_signed_replay: Arc<Mutex<crate::core::role_signed_gate::RoleSignedReplayCache>>,
    /// Data-plane V8 (legacy wire protocol) policy.
    ///
    /// `true`  → accept both V8 and V9 frames on the data leg (default; fleet-safe).
    /// `false` → reject V8 frames with `VERSION_REJECT (0xFF)` on the data leg.
    ///
    /// Controlled at boot by `MIRAGE_DATAPLANE_ALLOW_V8` env var.
    /// A reconfigure copies this value from the long-lived [`NodeRuntime`] so
    /// the policy cannot be silently re-enabled by a snapshot rebuild.
    pub allow_legacy_v8: bool,
}

/// Central runtime object shared between the TCP listener, the QUIC listener,
/// and the management API server.
///
/// Passed as `Arc<NodeRuntime>` everywhere.  Immutable fields live directly on
/// the struct; hot-swappable state lives in [`snapshot`].
pub struct NodeRuntime {
    /// Hot-swappable runtime state.  Lock-free reads via ArcSwap::load().
    pub snapshot: ArcSwap<NodeRuntimeSnapshot>,
    /// Health reporter — owns the shared `active_tunnels` counter.
    pub health: Arc<HealthReporter>,
    /// Shared handle to the active-tunnel counter (for connection tasks).
    pub active_tunnels: Arc<AtomicU32>,
    /// Increments on every successful runtime reconfiguration.
    pub config_version: AtomicU64,
    /// Timestamp of process startup, used to compute uptime.
    pub start_time: Instant,
    /// Node keypair — immutable for the lifetime of the process.
    ///
    /// Key rotation requires a full restart.  Stored here so management
    /// handlers can rebuild protocol chains without access to `main.rs`.
    pub keypair: KeyPair,
    /// Mesh identifier baked into the BLAKE3 confirm label for every
    /// handshake on this node. Set from `NodeToml.mesh_id` at startup
    /// and never changed.
    pub mesh_id: Arc<str>,
    /// In-process metrics registry — shared across all listener tasks.
    pub metrics: Arc<MetricsRegistry>,
    /// Hot-swappable DoH resolver.  `None` when DoH is not configured.
    /// Updated at runtime via `PUT /admin/dns-prefer-ipv6` without restart.
    pub doh: ArcSwapOption<DoHResolver>,
    /// Hot-swappable peer table — `node_id → (pubkey, addr, labels)`.
    /// Updated by the monitor's `PushPeerTable` WS frame. Resolved at
    /// dial time when a listener spec carries
    /// `UpstreamRef::PeerListener { node_id, … }`. Empty until the
    /// first push frame arrives.
    pub peer_table: ArcSwap<PeerTable>,
    /// Monitor connectivity rows — operator-signed infra identity, NOT
    /// gossip state. Populated once at boot from `boot_monitor_peers`
    /// (built from the boot capsule's `peers`), refreshed only by this node's
    /// own `RegisterResponse.self_peer_entry` on every successful register/
    /// reconnect. Never touched by `PushPeerTable` (that frame becomes
    /// routing-only after this commit). Read by the two monitor-binding
    /// helpers only — never by dial-time hop-pubkey resolution.
    pub monitor_peers: ArcSwap<Vec<PeerTableEntry>>,
    /// Hot-swappable chain bindings — `chain_id → (hop_pubkeys,
    /// byte_cipher, camouflage, onion_reply_mode)`. Updated by the
    /// monitor's `PushChainBindings` frame. Resolved at listener
    /// accept time when the listener participates in a multi-chain
    /// port (peek-dispatch picks the chain_id, this map yields the
    /// matching layer config). Empty until first push.
    pub chain_bindings: ArcSwap<ChainBindings>,
    /// Per-listener dial activity timestamps (UNIX ms of the most recent
    /// accepted connection on each listener). Updated on every successful
    /// `accept()` / UDP tunnel receive. Snapshotted by the WS scheduler
    /// every 60 s and reported to the monitor as a `ListenerActivityReport`
    /// frame so the idle reaper can track genuinely unused listeners.
    ///
    /// Key: `listener_id` string. Value: UNIX epoch milliseconds.
    /// Write-lock only on first insertion; after that `insert` overwrites.
    /// Read is a snapshot clone — no contention on hot path.
    pub dial_activity: Arc<RwLock<HashMap<String, u64>>>,
    /// Canonical gossip-driven credential params (Phase C/D).
    ///
    /// The SINGLE source of truth — lives here on the long-lived runtime so
    /// a `PushCredentialParams` gossip frame can call `.store()` and every
    /// current AND future `NodeRuntimeSnapshot` observes the new value
    /// through its Arc-clone of this same allocation. Without this field the
    /// gossip→closure path would be broken: a gossip frame arriving on the
    /// control client has `Arc<NodeRuntime>` but NOT the snapshot's Arc.
    pub credential_params: Arc<ArcSwap<Option<CredentialParams>>>,
    /// Canonical per-epoch spent-nonce set (replay guard).
    ///
    /// Shared via Arc-clone into every `NodeRuntimeSnapshot.spent_set`.
    /// `std::sync::Mutex` — the auth closure is SYNC (no `.await` under lock).
    pub spent_set: Arc<Mutex<SpentSet>>,
    /// Data-plane V8 policy — boot-fixed, copied from env at startup.
    ///
    /// `true`  → accept V8 + V9 (default).
    /// `false` → reject V8 (`MIRAGE_DATAPLANE_ALLOW_V8=0`).
    ///
    /// Lives here so snapshot rebuilds can copy it without re-reading the env.
    pub allow_legacy_v8: bool,
    /// Pinned operator Ed25519 verifying key (from shared-store `operator_pinned`).
    /// Used to verify the operator signature on gossiped CredentialParams before apply.
    /// `None` = node not adopted / no pin → params accepted UNVERIFIED (logged).
    pub operator_pub: Option<Arc<VerifyingKey>>,
    /// Single-use replay guard for `CredentialScheme::RoleSigned` dials —
    /// keyed `(self_id, nonce)`, TTL-evicted by the token's own `ts_ms`. One
    /// instance shared by every accept path (pipelined listeners, the bare
    /// `EndpointProtocol` accept path, the onion/UDP FS exit hops, the
    /// datagram handshake) — a captured token presented to two different
    /// listeners on this same box is still a replay. See
    /// `core::role_signed_gate`'s own doc.
    pub role_signed_replay: Arc<std::sync::Mutex<crate::core::role_signed_gate::RoleSignedReplayCache>>,
}

impl NodeRuntime {
    /// Create a new runtime from an initial snapshot, the node keypair, and
    /// an optional DoH resolver.
    ///
    /// `credential_params` and `spent_set` are lifted out of `initial` (which
    /// carries Arc-clones of them) onto the runtime so the gossip path can
    /// call `runtime.credential_params.store(...)` and have every snapshot
    /// observe the update without a snapshot rebuild.
    pub fn new(
        initial: NodeRuntimeSnapshot,
        keypair: KeyPair,
        mesh_id: Arc<str>,
        doh: Option<Arc<DoHResolver>>,
        operator_pub: Option<Arc<VerifyingKey>>,
    ) -> Arc<Self> {
        let health = Arc::new(HealthReporter::new(initial.node_config.node_id.clone()));
        let active_tunnels = health.tunnel_counter();
        // Adopt the Arc-clones that the caller placed on the snapshot — the
        // runtime becomes the canonical owner; future snapshots clone them back.
        let credential_params = initial.credential_params.clone();
        let spent_set = initial.spent_set.clone();
        let role_signed_replay = initial.role_signed_replay.clone();
        let allow_legacy_v8 = initial.allow_legacy_v8;
        Arc::new(Self {
            snapshot: ArcSwap::new(Arc::new(initial)),
            health,
            active_tunnels,
            config_version: AtomicU64::new(0),
            start_time: Instant::now(),
            keypair,
            mesh_id,
            metrics: MetricsRegistry::new(),
            doh: ArcSwapOption::new(doh),
            peer_table: ArcSwap::new(Arc::new(PeerTable::empty())),
            monitor_peers: ArcSwap::new(Arc::new(Vec::new())),
            chain_bindings: ArcSwap::new(Arc::new(ChainBindings::empty())),
            dial_activity: Arc::new(RwLock::new(HashMap::new())),
            credential_params,
            spent_set,
            role_signed_replay,
            allow_legacy_v8,
            operator_pub,
        })
    }

    /// Read the current config version.
    pub fn config_version(&self) -> u64 {
        self.config_version.load(Ordering::SeqCst)
    }

    /// Elapsed seconds since process start.
    pub fn uptime_secs(&self) -> u64 {
        self.start_time.elapsed().as_secs()
    }
}

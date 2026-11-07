//! [`ListenerRegistry`] — the per-node table of bound listeners and the
//! single entry point for activate / deactivate / reconcile.
//!
//! Step 2 (this file) only declares the surface. `activate` returns
//! [`RegistryError::Unimplemented`] until step 3 ports the existing main.rs
//! spawn sites to factories.

use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU16, Ordering};

use tokio::sync::RwLock;

use mirage_protocol::traits::TcpProtocol;

use super::handle::{ListenerHandle, ReconfigureOutcome};
use super::selector::UdpExitSelectorError;
use super::spec::{ListenerId, ListenerKind, ListenerSpec, SpecFingerprint};
use crate::core::doh::DoHResolver;
use crate::core::runtime::NodeRuntime;

/// Outcome of a [`ListenerRegistry::reconcile`] call. Designed for the
/// monitor-side WS responder — one push frame in, one report frame out.
#[derive(Debug, Default)]
pub struct ReconcileReport {
    pub activated: Vec<(ListenerId, SocketAddr)>,
    /// Chain listeners that were REGISTERED rather than bound — a routing
    /// entry and no socket.
    ///
    /// Its own category and not an empty-address `activated` entry, because
    /// the node reports each of these upward and the monitor has to be able to
    /// tell "came up, here is its port" from "came up, has no port by design".
    /// Folding them together would make a chain listener indistinguishable
    /// from one whose bind silently produced nothing — and a listener that
    /// came up unreported is a listener the monitor believes never started.
    pub registered: Vec<ListenerId>,
    pub deactivated: Vec<ListenerId>,
    pub rebound: Vec<(ListenerId, SocketAddr)>,
    /// Hot-swapped in place via `ListenerHandle::reconfigure` — no
    /// rebind, socket still bound to the same address.
    pub reconfigured: Vec<(ListenerId, SocketAddr)>,
    pub failed: Vec<(ListenerId, RegistryError)>,
    pub unchanged: Vec<ListenerId>,
}

/// What `activate` did with a spec.
///
/// Two outcomes and not an `Option<SocketAddr>`, because the caller has to
/// report them differently upward: a bound listener has a port the monitor
/// records, and a registered one has none BY DESIGN. An `Option` would let a
/// caller treat "no port because it is a chain hop" and "no port because
/// something went wrong" as the same thing, and the second must never be
/// silent.
#[derive(Debug, Clone)]
pub enum Activation {
    /// A socket was bound at this address.
    Bound(SocketAddr),
    /// A routing entry was created. No socket exists for this listener.
    Registered(ListenerId),
}

#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    #[error("listener {0} already bound")]
    AlreadyBound(ListenerId),

    #[error("listener {0} not bound")]
    NotBound(ListenerId),

    #[error("spec rejected by node axes: {reason}")]
    UnsupportedAxis { reason: String },

    #[error("fingerprint mismatch on {id}: monitor claimed {expected:?}, node computed {actual:?}")]
    FingerprintMismatch {
        id: ListenerId,
        expected: SpecFingerprint,
        actual: SpecFingerprint,
    },

    #[error("bind failed for {id}: {source}")]
    BindFailed {
        id: ListenerId,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    #[error("factory not yet wired for listener kind (step 3 of rollout)")]
    Unimplemented,
}

/// Per-listener-spawn dependencies that the registry needs to call any
/// factory. Built once at node startup, cloned into the registry.
///
/// `runtime` carries the ArcSwap snapshot (TCP NodeListener reads it
/// per-connection); `outbound_protocol` is the L1 outbound dialer that
/// UDP relay-mode dispatch needs; `doh` is the per-node DNS resolver.
/// Both `outbound_protocol` and `doh` can be `None` on pure-relay
/// boxes / boxes without DoH configured.
#[derive(Clone)]
pub struct ActivationContext {
    pub runtime: Arc<NodeRuntime>,
    pub outbound_protocol: Option<Arc<dyn TcpProtocol>>,
    pub doh: Option<Arc<DoHResolver>>,
}

/// Local port allocator for Mirage listeners. Owns the
/// `[MIRAGE_PORT_LO, MIRAGE_PORT_HI]` range; hands out ports on
/// demand when a `MirageListenerSpec` arrives with `bind_port: None`.
///
/// Stage 1.2 (2026-05-28): node is the source of truth for which
/// ports are in use on its box. Monitor no longer dictates. Activation
/// retries on `EADDRINUSE` by advancing the counter.
pub const MIRAGE_PORT_LO: u16 = 20000;
pub const MIRAGE_PORT_HI: u16 = 65000;
const PORT_ALLOC_MAX_ATTEMPTS: u32 = 256;

#[derive(Debug, Default)]
pub struct PortAllocator {
    /// Next candidate port. Wraps from HI back to LO.
    next: AtomicU16,
}

impl PortAllocator {
    pub fn new() -> Self {
        Self {
            next: AtomicU16::new(MIRAGE_PORT_LO),
        }
    }

    /// Reserve the next candidate port. Caller binds; on success, done.
    /// On `EADDRINUSE`, caller calls `next_candidate` again.
    pub fn next_candidate(&self) -> u16 {
        loop {
            let cur = self.next.load(Ordering::Relaxed);
            let next = if cur >= MIRAGE_PORT_HI {
                MIRAGE_PORT_LO
            } else {
                cur + 1
            };
            if self
                .next
                .compare_exchange(cur, next, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
            {
                return cur;
            }
        }
    }
}

/// Per-node registry of bound listeners.
pub struct ListenerRegistry {
    bound: Arc<RwLock<HashMap<ListenerId, Box<dyn ListenerHandle>>>>,
    /// Cached fingerprints — quick reject for "spec unchanged" path
    /// without holding the write lock.
    fingerprints: Arc<RwLock<BTreeMap<ListenerId, SpecFingerprint>>>,
    /// Chain listeners: registered, never bound. See
    /// [`crate::core::registry::selector::ChainRouting`] for why the two live
    /// apart — `bound` is about sockets, and a chain hop has none.
    chain_routing: Arc<RwLock<crate::core::registry::selector::ChainRouting>>,
    /// Local port allocator. Used when `spec.bind_port == None`.
    port_alloc: Arc<PortAllocator>,
    ctx: ActivationContext,
}

impl ListenerRegistry {
    pub fn new(ctx: ActivationContext) -> Self {
        Self {
            bound: Arc::new(RwLock::new(HashMap::new())),
            fingerprints: Arc::new(RwLock::new(BTreeMap::new())),
            chain_routing: Arc::new(RwLock::new(Default::default())),
            port_alloc: Arc::new(PortAllocator::new()),
            ctx,
        }
    }

    /// Bind one listener described by `spec`.
    ///
    /// v2 dispatch (`mirage2node/docs/listener-axes-v2.md`): the
    /// primary discriminator is the triple `(family, position,
    /// wire.transport())`. Inside Mirage family the dispatch picks a
    /// tunnel factory (tcp_node_listener / udp_endpoint_listener) or
    /// a udp_relay binding when `kind = UdpRelay`.
    ///
    /// Decoy / DecoyMulti are not part of the chain family axis
    /// (probe-resistance fronting), so they keep the v1 `kind` as
    /// their selector. The v1 `kind` field is also used as a
    /// disambiguator between TunnelUdp and UdpRelay within
    /// `(Family::Mirage, *, Udp)` until the spec gains a finer
    /// "leg-kind" field.
    /// Whether this spec is a chain hop — a listener that must NOT bind.
    ///
    /// By measurement, and the first measurement was wrong.
    ///
    /// This read `TunnelTcp && chain_role.is_some()`, on the reasoning that
    /// the role is what makes a listener part of a chain. It is not:
    /// `chains_build.rs:589-599` attaches a `chain_role` only when
    /// `total_hops > 1`, so a SINGLE-HOP chain's listener carries none — and
    /// that listener would have kept its bind port, which is precisely the
    /// port outside the perimeter this cutover exists to remove. The gate
    /// would have worked for every chain anyone tested with and failed for the
    /// shortest one.
    ///
    /// The honest predicate is the kind, because `chains_build.rs:556` is the
    /// ONLY producer of `TunnelTcp` in the fleet (verified across
    /// mirage2monitor, mirage2operator and mirage2app: no other construction
    /// site exists), and everything it produces is a chain listener.
    ///
    /// UDP is in, and the plan that put it off was wrong.
    ///
    /// `TunnelUdp` and `UdpRelay` bind `spec.bind_port` from the SAME
    /// allocator (`udp_relay.rs:71`, `tunnel_udp.rs`), so they are the same
    /// violation wearing a different transport. Deferring them to a separate
    /// "UDP-face plan" would have left half the fleet's listeners on ports
    /// nothing is allowed to allocate. The rule has no transport in it:
    /// nothing binds outside a face.
    ///
    /// NOT included, and the distinction matters: an outbound
    /// `UdpSocket::bind("0.0.0.0:0")` is an ephemeral SOURCE port for
    /// datagrams this node sends. There is no way to send UDP without one and
    /// it listens for nothing. Those stay.
    ///
    /// `TunnelControl` is a different kind and keeps its socket. Nothing
    /// constructs one today — the dispatch arm it shares with `TunnelTcp` is
    /// the only reason the two ever looked alike — but its handler, exit mode
    /// and the client's dial path are all intact, so it is dormant rather
    /// than dead, and dormant is not a licence to unbind it.
    fn is_chain_hop(spec: &ListenerSpec) -> bool {
        matches!(
            spec.kind,
            ListenerKind::TunnelTcp | ListenerKind::TunnelUdp | ListenerKind::UdpRelay
        )
    }

    pub async fn activate(&self, mut spec: ListenerSpec) -> Result<Activation, RegistryError> {
        // Fingerprint integrity — monitor MUST compute and set this; any
        // spec with all-zero fingerprint or a mismatching value is rejected.
        // Phase 4 will ensure the monitor always sends correct fingerprints.
        let recomputed = spec.compute_fingerprint();
        if spec.fingerprint != recomputed {
            return Err(RegistryError::FingerprintMismatch {
                id: spec.id.clone(),
                expected: spec.fingerprint,
                actual: recomputed,
            });
        }

        // A chain hop is a routing entry and nothing else. The port it used
        // to bind is what this cutover removes: it lived outside the
        // perimeter, and the owner has ruled that nothing outside the
        // perimeter exists. Connections reach it through the shared chain
        // splice, which resolves the selector the arriving frame carries.
        if Self::is_chain_hop(&spec) {
            let id = self.register_chain_spec(&spec).await;
            self.fingerprints
                .write()
                .await
                .insert(spec.id.clone(), recomputed);
            return Ok(Activation::Registered(id));
        }

        // Stage 1.2 (2026-05-28): node is the source of truth for ports.
        //   spec.bind_port == Some(n) → bind exactly on n (fail if busy).
        //   spec.bind_port == None    → allocate from local Mirage range,
        //                               retry on EADDRINUSE.
        let (handle, bound_port) = match spec.bind_port {
            Some(pin_port) => {
                let listen_addr = std::net::SocketAddr::new(
                    std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                    pin_port,
                );
                (self.dispatch(&spec, listen_addr).await?, pin_port)
            }
            None => {
                let mut last_err: Option<RegistryError> = None;
                let mut chosen: Option<(Box<dyn ListenerHandle>, u16)> = None;
                for _ in 0..PORT_ALLOC_MAX_ATTEMPTS {
                    let candidate = self.port_alloc.next_candidate();
                    // Mutate spec so factories that read spec.bind_port
                    // downstream see the allocated value. Fingerprint
                    // is recomputed below if the caller cares — for
                    // bound state we use the actual.
                    spec.bind_port = Some(candidate);
                    let listen_addr = std::net::SocketAddr::new(
                        std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                        candidate,
                    );
                    match self.dispatch(&spec, listen_addr).await {
                        Ok(handle) => {
                            chosen = Some((handle, candidate));
                            break;
                        }
                        Err(RegistryError::BindFailed { source, .. }) => {
                            // EADDRINUSE / EACCES → try next candidate.
                            last_err = Some(RegistryError::BindFailed {
                                id: spec.id.clone(),
                                source,
                            });
                            continue;
                        }
                        Err(other) => return Err(other),
                    }
                }
                match chosen {
                    Some(c) => c,
                    None => {
                        return Err(last_err.unwrap_or(RegistryError::BindFailed {
                            id: spec.id.clone(),
                            source: "port allocator exhausted".to_string().into(),
                        }))
                    }
                }
            }
        };

        let addr = handle.bound_addr();
        let _ = bound_port; // kept for future ListenerSnapshot reporting
        {
            let mut bound = self.bound.write().await;
            if bound.contains_key(&spec.id) {
                // Race: someone else activated while we held neither
                // lock. Drop the freshly bound socket via shutdown so
                // we do not leak a half-registered handle.
                let _ = handle.shutdown().await;
                return Err(RegistryError::AlreadyBound(spec.id.clone()));
            }
            bound.insert(spec.id.clone(), handle);
        }
        self.fingerprints
            .write()
            .await
            .insert(spec.id.clone(), recomputed);
        Ok(Activation::Bound(addr))
    }

    /// Dispatch entry point. Single source of truth lives in
    /// [`crate::core::dispatch::dispatch_spec`] — keep the match there,
    /// keep the activation helpers here.
    async fn dispatch(
        &self,
        spec: &ListenerSpec,
        listen_addr: SocketAddr,
    ) -> Result<Box<dyn ListenerHandle>, RegistryError> {
        crate::core::dispatch::dispatch_spec(self, spec, listen_addr).await
    }

    pub(crate) async fn activate_mirage_tcp(
        &self,
        spec: &ListenerSpec,
        listen_addr: SocketAddr,
    ) -> Result<Box<dyn ListenerHandle>, RegistryError> {
        let runtime = Arc::clone(&self.ctx.runtime);
        crate::family::mirage::listener::tunnel_tcp::activate(
            spec.id.clone(),
            listen_addr,
            runtime,
            spec.clone(),
        )
        .await
        .map_err(|e| RegistryError::BindFailed {
            id: spec.id.clone(),
            source: e,
        })
    }

    pub(crate) async fn activate_mirage_udp(
        &self,
        spec: &ListenerSpec,
    ) -> Result<Box<dyn ListenerHandle>, RegistryError> {
        // v2: build MirageEndpointConfig from spec axes.
        //   transport    = Udp (we are in the UDP dispatch branch)
        //   auth         = Blake3 (default for Mirage UDP)
        //   camouflage   = spec.ingress_layer.camouflage
        //                  OR RawUdp { bind_addr: 0.0.0.0:bind_port }
        //   byte_cipher  = spec.ingress_layer.byte_cipher
        let endpoint = self.derive_udp_endpoint(spec)?;
        let outbound_protocol =
            self.ctx
                .outbound_protocol
                .clone()
                .ok_or_else(|| RegistryError::UnsupportedAxis {
                    reason: format!(
                        "spec {} requires outbound_protocol; activation context has none",
                        spec.id
                    ),
                })?;
        let runtime = Arc::clone(&self.ctx.runtime);
        let node_config = runtime.snapshot.load().node_config.clone();
        crate::family::mirage::listener::tunnel_udp::activate(
            spec.id.clone(),
            endpoint,
            node_config,
            runtime,
            outbound_protocol,
            self.ctx.doh.clone(),
            spec.clone(),
        )
        .await
        .map_err(|e| RegistryError::BindFailed {
            id: spec.id.clone(),
            source: e,
        })
    }

    /// Compose [`MirageEndpointConfig`] from v2 spec axes.
    ///
    /// Axes: transport=Udp, auth=Blake3, camouflage from ingress_layer,
    /// byte_cipher from ingress_layer.
    fn derive_udp_endpoint(
        &self,
        spec: &ListenerSpec,
    ) -> Result<mirage_core::config::MirageEndpointConfig, RegistryError> {
        let bind_addr = std::net::SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            spec.bind_port.unwrap_or(0),
        );
        let camouflage = spec
            .ingress_layer
            .as_ref()
            .and_then(|l| l.camouflage.clone())
            .unwrap_or(mirage_core::config::TransportCamouflage::RawUdp { bind_addr });
        let byte_cipher_mode = spec
            .ingress_layer
            .as_ref()
            .and_then(|l| l.byte_cipher.clone());
        Ok(mirage_core::config::MirageEndpointConfig {
            transport: mirage_core::config::TransportKind::Udp,
            auth: mirage_core::config::AuthMode::Blake3,
            camouflage,
            byte_cipher: None,
            byte_cipher_mode,
        })
    }

    /// Activate a decoy listener.
    ///
    /// The decoy FRONT is fleet code — the OSS node only knows the listener
    /// kind and calls the fleet-installed activator through
    /// [`crate::core::registry::decoy`]. A node with no activator installed
    /// refuses the spec instead of serving an empty front.
    pub(crate) async fn activate_decoy(
        &self,
        spec: &ListenerSpec,
    ) -> Result<Box<dyn ListenerHandle>, RegistryError> {
        crate::core::registry::decoy::activate(spec).await
    }

    /// Activate a multi-backend decoy listener.
    ///
    /// Same seam as [`Self::activate_decoy`] — the fleet's activator tells
    /// the two decoy kinds apart by the spec's own kind.
    pub(crate) async fn activate_multi_decoy(
        &self,
        spec: &ListenerSpec,
    ) -> Result<Box<dyn ListenerHandle>, RegistryError> {
        crate::core::registry::decoy::activate(spec).await
    }

    pub(crate) async fn activate_udp_relay(
        &self,
        spec: &ListenerSpec,
    ) -> Result<Box<dyn ListenerHandle>, RegistryError> {
        let payload = spec.payload.clone().ok_or_else(|| RegistryError::UnsupportedAxis {
            reason: format!("spec {} kind=UdpRelay has no payload", spec.id),
        })?;
        let binding: mirage_core::config::UdpRelayBinding = serde_json::from_value(payload)
            .map_err(|e| RegistryError::UnsupportedAxis {
                reason: format!("spec {} payload not UdpRelayBinding: {e}", spec.id),
            })?;
        crate::family::mirage::listener::udp_relay::activate(
            spec.id.clone(),
            binding.bind_addr,
            binding.upstream_addr,
            binding.next_hop_addr,
            binding.idle_secs,
            binding.byte_cipher.clone(),
            spec.clone(),
        )
        .await
        .map_err(|e| RegistryError::BindFailed {
            id: spec.id.clone(),
            source: e,
        })
    }

    /// Register a chain listener. Binds no socket — that is the whole point
    /// of the cutover. Delegates to [`ChainRouting`].
    pub async fn register_chain_spec(&self, spec: &ListenerSpec) -> ListenerId {
        self.chain_routing.write().await.register(spec)
    }

    /// Drop a chain registration and the selector that reached it.
    pub async fn unregister_chain_spec(&self, id: &ListenerId) {
        self.chain_routing.write().await.unregister(id)
    }

    /// Resolve the listener a STREAM connection is addressed to, from its
    /// init frame's fields. `selector_token` is the frame's own trailer,
    /// empty when the peer that sent it carries none. **Only after the
    /// frame has authenticated** — see [`ChainRouting::resolve`].
    ///
    /// Kind-filtered to `TunnelTcp`, fixed. Until 2026-09-09 this called
    /// `ChainRouting::resolve` with no transport filter at all — a stream
    /// connection naming a `TunnelUdp` hop's selector exactly would have
    /// resolved to that UDP spec and been served against it, the identical
    /// hole `resolve_datagram` had already closed for its own direction.
    /// This is that fix on the side that never got it, not a new
    /// capability: this function's callers were always the stream splice,
    /// so what changed is that "stream" is now checked rather than assumed.
    pub async fn resolve_for_frame(
        &self,
        chain_id: &[u8],
        chain_position: u8,
        chain_length: u8,
        selector_token: &[u8],
    ) -> Option<ListenerSpec> {
        self.chain_routing
            .read()
            .await
            .resolve(chain_id, chain_position, chain_length, selector_token, ListenerKind::TunnelTcp)
            .cloned()
    }

    /// The datagram-plane twin of [`resolve_for_frame`](Self::resolve_for_frame):
    /// same contract, same "only after the frame has authenticated" rule,
    /// kind-filtered to `TunnelUdp` instead of `TunnelTcp`. For the FS-chain
    /// datagram dispatch to resolve a listener from an `FsInitFrame` /
    /// `FsRelayInitFrame`'s own fields — distinct from
    /// [`resolve_datagram`](Self::resolve_datagram), which resolves from the
    /// throwaway classifier-token hello's chain block instead.
    ///
    /// Not wired to a caller yet. The datagram FS-chain dispatch that will
    /// call this is later, separate work (the design's Slice 4); this
    /// method is built and tested in isolation, mirroring
    /// [`single_udp_direct_exit`](Self::single_udp_direct_exit)'s own
    /// "nothing calls this today" precedent, so that piece has something
    /// correct to call into.
    pub async fn resolve_for_frame_udp(
        &self,
        chain_id: &[u8],
        chain_position: u8,
        chain_length: u8,
        selector_token: &[u8],
    ) -> Option<ListenerSpec> {
        self.chain_routing
            .read()
            .await
            .resolve(chain_id, chain_position, chain_length, selector_token, ListenerKind::TunnelUdp)
            .cloned()
    }

    /// Resolve the listener a DATAGRAM session is addressed to, from the
    /// chain block its `ClientHello` carried. Thin passthrough to
    /// [`ChainRouting::resolve_datagram`][selector], whose doc carries the
    /// reasoning — including why this one resolves BEFORE the client
    /// authenticates and what the caller owes in return (answer nothing on
    /// `None`).
    ///
    /// [selector]: crate::core::registry::selector::ChainRouting::resolve_datagram
    pub async fn resolve_datagram(
        &self,
        addr: &mirage_protocol::core::dgram_chain_addr::DatagramChainAddress,
    ) -> Option<ListenerSpec> {
        self.chain_routing.read().await.resolve_datagram(addr).cloned()
    }

    /// The one live `TunnelUdp` / `Exit{Direct}` listener registered for
    /// `mesh_id` — the path a datagram session uses when its `ClientHello`
    /// carries NO chain block: the only addressing this plane had before
    /// [`resolve_datagram`](Self::resolve_datagram), and still the right
    /// answer for a client dialling a plain direct UDP exit. See
    /// [`ChainRouting::single_udp_direct_exit`][selector] for the full
    /// reasoning; this is a thin passthrough, same shape as
    /// `resolve_for_frame` beside it.
    ///
    /// [selector]: crate::core::registry::selector::ChainRouting::single_udp_direct_exit
    pub async fn single_udp_direct_exit(
        &self,
        mesh_id: &str,
    ) -> Result<ListenerSpec, UdpExitSelectorError> {
        self.chain_routing.read().await.single_udp_direct_exit(mesh_id)
    }

    /// How many chain listeners are registered without a socket.
    pub async fn chain_spec_count(&self) -> usize {
        self.chain_routing.read().await.len()
    }

    /// How many listeners hold a bound socket. The half the step-1 gate needs
    /// to stay at zero for a pushed chain spec.
    pub async fn bound_count(&self) -> usize {
        self.bound.read().await.len()
    }

    /// The node runtime this registry activates listeners against.
    ///
    /// Exposed so a caller that holds only the registry — the chain splice
    /// (`core::chain_splice`), which resolves a selector to a [`ListenerSpec`]
    /// and then has to build the same [`OnionRelayConfig`][onion-cfg] the
    /// per-accept dispatch would have — can reach the one runtime both paths
    /// share, instead of the splice server being handed a second `Arc`
    /// alongside the registry that could quietly point at a different node.
    ///
    /// [onion-cfg]: crate::family::mirage::relay::onion_peel::OnionRelayConfig
    pub fn runtime(&self) -> Arc<NodeRuntime> {
        Arc::clone(&self.ctx.runtime)
    }

    /// This registry's DNS-over-HTTPS resolver, if configured — the same
    /// `Option<Arc<DoHResolver>>` every other exit path already reaches
    /// through `ActivationContext::doh`. Exposed for the identical reason
    /// [`Self::runtime`] is: a caller that holds only the registry
    /// (`core::udp_chain_splice`, which resolves a UDP direct-exit spec and
    /// then has to hand the SAME resolver `family::mirage::exit::direct`'s
    /// other entry points already use) reaches it without a second `Arc`
    /// threaded in beside the registry that could silently point at a
    /// different one.
    pub fn ctx_doh(&self) -> Option<Arc<DoHResolver>> {
        self.ctx.doh.clone()
    }

    /// Drain + shutdown one listener. Idempotent on the registry side —
    /// "not bound" is treated as success by reconcile, but returned as
    /// `NotBound` here for direct callers.
    pub async fn deactivate(&self, id: &ListenerId) -> Result<(), RegistryError> {
        // A chain hop has no socket to shut down — its whole existence is the
        // routing entry, so removing that IS the deactivation. Checked first
        // because `bound` will never hold it and the `NotBound` below would
        // otherwise report a withdrawal as a failure.
        if self.chain_routing.read().await.contains(id) {
            self.unregister_chain_spec(id).await;
            self.fingerprints.write().await.remove(id);
            return Ok(());
        }
        let mut bound = self.bound.write().await;
        match bound.remove(id) {
            Some(handle) => {
                if let Err(e) = handle.shutdown().await {
                    tracing::warn!(%id, error = %e, "listener shutdown reported error; treating as unbound");
                }
                self.fingerprints.write().await.remove(id);
                Ok(())
            }
            None => Err(RegistryError::NotBound(id.clone())),
        }
    }

    /// Apply a full desired set: diff against `bound`, activate new specs,
    /// deactivate removed ones, reconfigure-in-place where the listener
    /// accepts the diff, rebind otherwise. The report captures per-id
    /// outcomes so the monitor can surface partial failures (e.g. one of
    /// 23 listeners failed to bind) without rejecting the whole push.
    pub async fn reconcile(&self, desired: Vec<ListenerSpec>) -> ReconcileReport {
        let mut report = ReconcileReport::default();
        let desired_ids: HashMap<ListenerId, ListenerSpec> =
            desired.into_iter().map(|s| (s.id.clone(), s)).collect();

        let current_ids: Vec<ListenerId> =
            self.bound.read().await.keys().cloned().collect();

        for id in &current_ids {
            if !desired_ids.contains_key(id) {
                match self.deactivate(id).await {
                    Ok(()) => report.deactivated.push(id.clone()),
                    Err(e) => report.failed.push((id.clone(), e)),
                }
            }
        }

        for (id, spec) in desired_ids {
            let prior_fp = self.fingerprints.read().await.get(&id).copied();
            match prior_fp {
                Some(fp) if fp == spec.fingerprint => {
                    report.unchanged.push(id);
                }
                Some(_) => {
                    // Spec changed. Try `reconfigure` first — if the
                    // listener accepts hot-swap for this diff, we keep
                    // the socket bound and just update its runtime
                    // slots. If it returns `RebindRequired` (or errors),
                    // fall through to deactivate+activate.
                    let reconfig_outcome = {
                        let bound = self.bound.read().await;
                        match bound.get(&id) {
                            Some(handle) => Some(handle.reconfigure(&spec).await),
                            None => None,
                        }
                    };
                    match reconfig_outcome {
                        Some(Ok(ReconfigureOutcome::Applied)) => {
                            self.fingerprints
                                .write()
                                .await
                                .insert(id.clone(), spec.fingerprint);
                            let bound_addr = self
                                .bound
                                .read()
                                .await
                                .get(&id)
                                .map(|h| h.bound_addr());
                            if let Some(addr) = bound_addr {
                                report.reconfigured.push((id, addr));
                            } else {
                                report.unchanged.push(id);
                            }
                        }
                        _ => {
                            // RebindRequired, error, or handle disappeared
                            // mid-reconcile. Failure of either half lands
                            // as a `failed` entry; the listener ends up
                            // unbound, which is the safer side of the
                            // race (monitor will retry on next push).
                            let _ = self.deactivate(&id).await;
                            match self.activate(spec).await {
                                Ok(Activation::Bound(addr)) => report.rebound.push((id, addr)),
                                Ok(Activation::Registered(id)) => report.registered.push(id),
                                Err(e) => {
                                    tracing::warn!(
                                        listener_id = %id,
                                        error = %e,
                                        "registry: rebind activate failed"
                                    );
                                    report.failed.push((id, e));
                                }
                            }
                        }
                    }
                }
                None => match self.activate(spec).await {
                    Ok(Activation::Bound(addr)) => report.activated.push((id, addr)),
                    Ok(Activation::Registered(id)) => report.registered.push(id),
                    Err(e) => {
                        tracing::warn!(
                            listener_id = %id,
                            error = %e,
                            "registry: activate failed"
                        );
                        report.failed.push((id, e));
                    }
                },
            }
        }

        report
    }

    /// Snapshot of currently bound ids — for stats push to the monitor.
    pub async fn bound_ids(&self) -> Vec<ListenerId> {
        self.bound.read().await.keys().cloned().collect()
    }

    /// Snapshot of every bound listener's current spec. Used by the
    /// node-side PushChainBindings handler to find listeners affected
    /// by a chain config change and trigger their reconfigure hot-path
    /// via `reconcile`.
    pub async fn bound_specs(&self) -> Vec<ListenerSpec> {
        self.bound
            .read()
            .await
            .values()
            .map(|h| h.current_spec())
            .collect()
    }

    /// Phase 1.5 (memory wave): full snapshot of bound listeners with
    /// their current spec, the resolved bound address (host:port the
    /// kernel actually picked), and the local fingerprint. Used by
    /// node_control_client to emit `ListenerSnapshot` to the monitor
    /// right after WS (re)connect.
    pub async fn bound_snapshots(&self) -> Vec<(ListenerSpec, SocketAddr)> {
        self.bound
            .read()
            .await
            .values()
            .map(|h| (h.current_spec(), h.bound_addr()))
            .collect()
    }
}


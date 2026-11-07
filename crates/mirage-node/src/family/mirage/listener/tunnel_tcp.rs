//! Factory for the main TCP NodeListener — the dispatch socket every
//! mirage chain enters through on a non-UDP-only node.
//!
//! Functionally identical to [`crate::core::listener::NodeListener::run`]
//! but accepts a cancellation [`Notify`] so the registry can drain the
//! listener without dropping the runtime.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use mirage_core::mirage::wire::{EntryHop, Framing, ListenerRole, MirageListenerKind as ListenerKind, RelayMode};

/// Flat position discriminator used for connection dispatch within this file.
/// Derived from `ListenerRole` type-state; never stored in specs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Position {
    Entry,
    Hop,
    Exit,
}

/// Flat relay-mode hint used for connection dispatch within this file.
use socket2::{SockRef, TcpKeepalive};
use tokio::net::TcpListener;
use tokio::sync::{Notify, Semaphore};
use tracing::{debug, error, info, warn};

/// Maximum simultaneous accepted connections in the primary `tunnel_tcp` accept
/// loop.  Mirrors `MAX_CONCURRENT_CONNECTIONS_LEGACY` in `core/listener.rs`.
/// One permit is held for the ENTIRE connection lifetime.  Pre-auth slow-read
/// clients that do not progress the handshake are still bounded by the 15 s
/// handshake timeout; this cap is defense-in-depth against fd/task exhaustion
/// when the timeout is not yet applied to a given branch.
const MAX_CONCURRENT_CONNECTIONS: usize = 4096;

/// Module-level semaphore shared across ALL `tunnel_tcp` listener instances on
/// this node.  Using a global rather than per-listener cap keeps the total FD
/// count bounded regardless of how many listeners are active.
static ACCEPT_SEMAPHORE: std::sync::OnceLock<Semaphore> = std::sync::OnceLock::new();

fn accept_semaphore() -> &'static Semaphore {
    ACCEPT_SEMAPHORE.get_or_init(|| Semaphore::new(MAX_CONCURRENT_CONNECTIONS))
}

use crate::core::dual_bind::bind_dual_stack_tcp;
use crate::core::listener::handle_connection_with_protocol;
use crate::core::registry::handle::{ListenerHandle, ReconfigureOutcome};
use crate::core::registry::handle_impl::{AtomicListenerStats, TaskListenerHandle};
use crate::core::registry::spec::{ListenerSpec, ListenerId};
use crate::core::runtime::{NodeRuntime, NodeRuntimeSnapshot};

/// Peel a one-time byte_cipher wire-skin (magic / magic+junk prefix) off the
/// front of an onion-ENTRY connection before the onion handler reads the v9
/// envelope. The skin is an outer transport obfuscation the client wrote on the
/// first hop; the entry strips it so `onion + magic/junk` composes (magic is a
/// DPI skin, orthogonal to onion's per-hop AEAD). The already-read post-header
/// remainder is re-presented to the handler via `PrefixStream`. No-op (empty
/// prefix) when `byte_cipher` is None/Raw/ObfuscateAll — the latter is not a
/// one-time prefix and is unsupported as an onion skin (yet).
async fn peel_onion_ingress_skin<S>(
    mut stream: S,
    byte_cipher: Option<mirage_core::config::ByteCipherMode>,
    peer_addr: SocketAddr,
) -> Result<mirage_protocol::PrefixStream<S>, mirage_core::error::MirageError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    use mirage_core::config::ByteCipherMode;
    use mirage_core::error::MirageError;
    use tokio::io::AsyncReadExt;

    let (header_len, magic): (usize, Option<[u8; 16]>) = match &byte_cipher {
        Some(ByteCipherMode::ValidateFirst { magic }) => (16, Some(*magic)),
        Some(ByteCipherMode::StripFirst { magic, junk_size }) => {
            (16 + *junk_size as usize, Some(*magic))
        }
        // None / Raw / ObfuscateAll → no one-time prefix skin.
        _ => (0, None),
    };
    if header_len == 0 {
        return Ok(mirage_protocol::PrefixStream::new(stream, Vec::new()));
    }

    let mut buf = vec![0u8; 8192.max(header_len)];
    let mut acc = 0usize;
    while acc < header_len {
        let n = stream.read(&mut buf[acc..]).await.map_err(MirageError::Io)?;
        if n == 0 {
            return Err(MirageError::Protocol(
                "onion ingress skin: eof before byte_cipher header".into(),
            ));
        }
        acc += n;
    }
    if let Some(m) = magic {
        if buf[..16] != m {
            warn!(%peer_addr, "onion ingress skin: byte_cipher magic mismatch — rejecting");
            return Err(MirageError::Protocol(
                "onion ingress skin: byte_cipher magic mismatch".into(),
            ));
        }
    }
    // Strip the header; hand the post-header bytes (already read) back via prefix.
    let remainder = buf[header_len..acc].to_vec();
    Ok(mirage_protocol::PrefixStream::new(stream, remainder))
}

/// Build and bind the main TCP listener under registry control.
///
/// Returns once the socket is bound (so the caller can ack the activate
/// to the monitor with the real port); the accept loop runs in a spawned
/// task and stops cleanly on `cancel.notify_waiters()`.
///
/// Hot-reconfig: anything carried on [`NodeRuntimeSnapshot`] (protocols
/// list, relay mode, upstream pools, relay metrics, full NodeConfig) is
/// hot-swappable because the accept loop loads the snapshot Arc per
/// connection. Changing `bind_port` forces a rebind.
///
/// Wire V7: hop identity (static pubkeys) is resolved per-accept from the
/// live `peer_table` using `chain_role.hop_node_ids`. No pubkey is cached
/// in any closure — stale-identity drift is architecturally impossible.
/// Everything a connection's handling needs from its `ListenerSpec`.
///
/// # Why this is one function and not two derivations
///
/// Under the port model there was one derivation because there was one path:
/// `activate()` unpacked the spec, and the accept loop it spawned carried the
/// results by value for the life of the socket. One socket, one spec, no way
/// for them to disagree.
///
/// The shared chain splice removes that. A connection arriving there names its
/// listener with a selector, and the handling has to derive the same nine
/// values from the spec that selector resolved to. Two derivations of the same
/// nine values, written at different times by different people, is how one
/// socket stops behaving like the per-hop sockets it replaced — and the
/// divergence would be invisible, because both paths would still work, just
/// differently.
///
/// So both call it. `activate()` for the socket it still binds, and the
/// selector-resolve path for a connection that named a spec. The equality is
/// asserted in this module's tests rather than trusted.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct SpecBundle {
    pub ingress: Option<mirage_core::mirage::wire::LayerSpec>,
    pub framing: Option<Framing>,
    pub position: Position,
    pub kind: ListenerKind,
    pub control_target: SocketAddr,
    pub chain_position: u8,
    pub chain_length: u8,
    pub chain_node_ids: Vec<String>,
    pub next_hop_addr: Option<String>,
}

/// Derive [`SpecBundle`] from a spec. The one place it happens.
pub(crate) fn bundle_from_spec(spec: &ListenerSpec) -> SpecBundle {
    let framing: Option<Framing> = Some(spec.framing);
    let position = match &spec.role {
        ListenerRole::Relay { position, relay_mode } => {
            // The relay mode is read for its one variant only — binding it
            // keeps the match exhaustive, so a future variant is a compile
            // error here rather than a silently ignored spec.
            let RelayMode::OnionPeel = relay_mode;
            match position {
                EntryHop::Entry => Position::Entry,
                EntryHop::Hop => Position::Hop,
            }
        }
        ListenerRole::Exit { .. } => Position::Exit,
    };
    let control_target: SocketAddr = spec
        .control_target
        .unwrap_or_else(|| "127.0.0.1:19445".parse().expect("default control_target is valid"));
    let (chain_position, chain_length, chain_node_ids, next_hop_addr) =
        match spec.chain_role.as_ref() {
            Some(r) => (
                r.chain_position,
                r.chain_length,
                r.chain_node_ids.clone(),
                r.next_hop_addr.clone(),
            ),
            None => (0, 1, Vec::new(), None),
        };
    SpecBundle {
        ingress: spec.ingress_layer.clone(),
        framing,
        position,
        kind: spec.kind,
        control_target,
        chain_position,
        chain_length,
        chain_node_ids,
        next_hop_addr,
    }
}

/// Resolve peer identity and build the [`OnionRelayConfig`][cfg] one onion
/// relay hop's connection handling needs — the ONE derivation, shared
/// between the per-accept dispatch below (`run_accept_loop`'s `is_onion_peel`
/// branch) and the chain splice's selector-resolve path
/// (`core::chain_splice::handle_one`).
///
/// [cfg]: crate::family::mirage::relay::onion_peel::OnionRelayConfig
///
/// # Why this is its own function and not two call sites each doing it
///
/// This is exactly the failure [`bundle_from_spec`]'s own doc warns
/// against, one layer up: the accept loop already had one derivation of
/// `OnionRelayConfig` before the chain splice existed, and the splice needs
/// the SAME values from a spec it resolved by selector rather than bound by
/// socket. Writing that resolution a second time would mean two
/// implementations of "outgoing camouflage from the chain binding, node_id
/// from chain_role" that a future change to either could silently diverge
/// from.
///
/// Takes the already-derived scalars ([`SpecBundle`]'s onion-relevant
/// fields plus `chain_id`) rather than a whole [`ListenerSpec`] because
/// that is what both call sites actually hold: `run_accept_loop` captured
/// these as by-value closure parameters at `activate()` time and never kept
/// the spec itself, and the chain splice has a spec fresh off
/// [`crate::core::registry::registry::ListenerRegistry::resolve_for_frame`]
/// that it can run through [`bundle_from_spec`] to get the same shape.
///
/// # Why this can now refuse
///
/// Until 2026-09-02 this also resolved `static_pubs` — every hop's static
/// pubkey, from `peer_table`, on every accept — for the non-forward-secret
/// onion envelope's transcript binding, and a peer_table miss on ANY hop
/// failed the whole resolution. That envelope (and the transcript that
/// needed those pubkeys) was deleted with it; the forward-secret circuit
/// this config now exclusively serves derives its transcript from ephemeral
/// per-hop keys exchanged live, needing no pre-resolved peer table for
/// pubkeys at all.
///
/// The outgoing camouflage is a different fact, and it reintroduces a
/// failure mode on purpose: it now comes from the NEXT hop's own signed
/// chain face (`PeerTableEntry.chain_face`), not from a value the chain
/// binding used to invent from `spec.camouflage`. A dialer that guesses is
/// refused by the target's perimeter exactly like a scanner — so a missing
/// chain face is not "no camouflage, dial raw", it is "there is nothing
/// dialable here", and this function says so instead of quietly degrading.
/// See [`RelayDialResolution::Refused`] and
/// `mirage_core::mirage::mesh::ChainFace`'s own doc for why a RAW-shaped
/// published face (`chain_face: Some(ChainFace { camouflage:
/// TransportCamouflage::None, .. })`) must never be confused with that
/// refusal — port 22 is `Shape::Raw` on every box, and is a legitimate,
/// common answer.
pub(crate) fn resolve_onion_relay_config(
    chain_position: u8,
    chain_length: u8,
    chain_node_ids: &[String],
    chain_id: Option<&str>,
    own_node_id: &str,
    runtime: &NodeRuntime,
) -> RelayDialResolution {
    let chain_binding = chain_id.and_then(|cid| {
        runtime.chain_bindings.load().lookup_by_str(cid).cloned()
    });
    let Some(binding) = chain_binding else {
        return RelayDialResolution::Refused {
            reason: format!(
                "chain_id {} not found in chain_bindings",
                chain_id.unwrap_or("<none>")
            ),
        };
    };
    let Some(next_node_id) = binding.next_hop_id(own_node_id) else {
        return RelayDialResolution::Refused {
            reason: format!(
                "own node '{own_node_id}' has no next hop in chain {}",
                binding.chain_id.as_str()
            ),
        };
    };
    let pt = runtime.peer_table.load();
    let Some(peer) = pt.lookup_by_str(next_node_id.as_str()) else {
        return RelayDialResolution::Refused {
            reason: format!("next hop '{next_node_id}' not found in peer table"),
        };
    };
    let Some(face) = peer.chain_face.as_ref() else {
        return RelayDialResolution::Refused {
            reason: format!("next hop '{next_node_id}' has published no chain face"),
        };
    };

    let mut next_hop_pubkey = [0u8; 32];
    if hex::decode_to_slice(&peer.pubkey_hex, &mut next_hop_pubkey).is_err() {
        next_hop_pubkey = [0u8; 32];
    }

    let outgoing_camouflage = Some(face.camouflage.clone());
    let outgoing_sni = extract_sni_from_camouflage(outgoing_camouflage.as_ref());

    RelayDialResolution::Dial(crate::family::mirage::relay::onion_peel::OnionRelayConfig {
        hop_keypair: Arc::new(runtime.keypair.clone()),
        chain_position,
        chain_length,
        outgoing_camouflage,
        next_hop_pubkey,
        outgoing_sni,
        node_id: chain_node_ids
            .get(chain_position as usize)
            .cloned()
            .unwrap_or_default(),
    })
}

/// What [`resolve_onion_relay_config`] found for the next hop's outbound
/// dial. Two call sites match on this — the per-accept dispatch in
/// `run_accept_loop` and the chain splice's selector-resolve path — and
/// each must refuse (name the node, dispose the connection) rather than
/// falling back to a bare dial when the target published no chain face.
pub(crate) enum RelayDialResolution {
    /// The next hop published a signed chain face; dial it with that
    /// face's camouflage and pubkey.
    Dial(crate::family::mirage::relay::onion_peel::OnionRelayConfig),
    /// There is nothing dialable at the next hop — the chain/next-hop
    /// identity itself could not be resolved, or the resolved next hop has
    /// published no chain face. `reason` names it for the log line; it is
    /// never sent to the peer (see `dispose_unaddressable`'s own doc on why
    /// a pre-auth refusal here stays silent on the wire).
    Refused { reason: String },
}

/// Resolve the [`OnionExitV7Config`][cfg] a chain EXIT connection's handling
/// needs — the ONE derivation, shared between the per-accept dispatch below
/// (`run_accept_loop`'s `is_onion_exit` branch) and the chain splice's
/// selector-resolve path (`core::chain_splice::handle_one`).
///
/// [cfg]: crate::family::mirage::exit::onion::OnionExitV7Config
///
/// Mirrors [`resolve_onion_relay_config`] for the exit role, for the same
/// reason: two derivations of "this hop's identity and credential state
/// from the spec" is how the accept-loop path and the splice path would
/// silently drift from each other.
///
/// # Why this needs no peer_table lookup
///
/// Until 2026-09-02 this also resolved `static_pubs` — every hop's static
/// pubkey, from `peer_table`, on every accept — for the non-forward-secret
/// onion envelope's transcript binding, and a peer_table miss failed the
/// whole resolution with a typed `PeerTableMiss` ack back to the client.
/// That envelope was deleted with it (see `exit/onion.rs`'s module doc);
/// the forward-secret circuit this config now exclusively serves derives
/// its transcript from ephemeral per-hop keys exchanged live, needing no
/// pre-resolved peer table at all. This function therefore cannot fail.
pub(crate) fn resolve_onion_exit_config(
    chain_position: u8,
    chain_length: u8,
    chain_node_ids: &[String],
    runtime: &NodeRuntime,
) -> crate::family::mirage::exit::onion::OnionExitV7Config {
    let snap: Arc<NodeRuntimeSnapshot> = Arc::clone(&*runtime.snapshot.load());
    crate::family::mirage::exit::onion::OnionExitV7Config {
        hop_keypair: Arc::new(runtime.keypair.clone()),
        chain_position,
        chain_length,
        node_id: chain_node_ids
            .get(chain_position as usize)
            .cloned()
            .unwrap_or_default(),
        credential_params: Arc::clone(&snap.credential_params),
        spent_set: Arc::clone(&snap.spent_set),
        mesh_id: runtime.mesh_id.as_bytes().to_vec(),
        role_signed_replay: Arc::clone(&runtime.role_signed_replay),
    }
}

/// Whether `new_spec` can be applied to a RUNNING tunnel-TCP listener, or
/// whether the socket has to be rebuilt for it to take effect.
///
/// Every axis, not just `bind_port`.
///
/// This compared ONLY `bind_port` and answered `Applied` to
/// everything else, while `ListenerHandle::reconfigure`'s own
/// contract requires `RebindRequired` for any socket-affecting
/// change. The two disagreed, and the contract was right: NOTHING
/// on this listener's path is read live. `run_accept_loop` takes
/// `framing`, `kind`, `relay_mode`, `position`, `control_target`
/// and the whole `chain_role` group as by-value PARAMETERS at
/// `activate()` and copies them per connection; the only thing
/// that does change under a running loop is the chain binding,
/// looked up per connection, which is not part of this spec at
/// all. So `Applied` meant "the registry now believes the new spec
/// is in force" while the loop went on serving the old one — a
/// config change that reported success and did nothing.
///
/// Compared by fingerprint rather than field by field on purpose:
/// `compute_fingerprint` already hashes every field except itself,
/// so a field added later is covered here without anyone
/// remembering to come back. A hand-written list of axes is a list
/// that rots, and this defect is what rot looks like.
///
/// `Applied` is therefore unreachable for this listener today. The
/// closure stays instead of being dropped for the trait default so
/// that the FIRST axis to become live is granted its exception
/// here, in the open, rather than by someone rediscovering that
/// the default said no.
pub(crate) fn reconfigure_outcome_for(
    current: &ListenerSpec,
    new_spec: &ListenerSpec,
) -> ReconfigureOutcome {
    if current.compute_fingerprint() != new_spec.compute_fingerprint() {
        ReconfigureOutcome::RebindRequired
    } else {
        ReconfigureOutcome::Applied
    }
}

pub async fn activate(
    id: ListenerId,
    listen_addr: SocketAddr,
    runtime: Arc<NodeRuntime>,
    spec: ListenerSpec,
) -> Result<Box<dyn ListenerHandle>, Box<dyn std::error::Error + Send + Sync>> {
    let listener = if listen_addr.ip().is_unspecified() {
        bind_dual_stack_tcp(listen_addr.port()).await?
    } else {
        TcpListener::bind(listen_addr).await?
    };
    let bound_addr = listener.local_addr()?;
    info!(%id, addr = %bound_addr, "tcp_node_listener bound");

    let cancel = Arc::new(Notify::new());
    let stats = Arc::new(AtomicListenerStats::default());

    let ctx = crate::core::listener_ctx::ListenerCtx::new(
        spec.mesh_id.as_str(),
        runtime
            .snapshot
            .load()
            .node_config
            .node_id
            .as_str(),
        spec.id.0.as_str(),
        spec.chain_role.as_ref().map(|c| c.chain_id.as_str()),
    );

    let spec_ingress: Option<mirage_core::mirage::wire::LayerSpec> =
        spec.ingress_layer.clone();

    // One derivation, shared with the selector-resolve path — see
    // `bundle_from_spec`.
    let b = bundle_from_spec(&spec);
    let spec_framing = b.framing;
    let spec_position = b.position;
    let spec_kind = b.kind;
    let spec_control_target = b.control_target;
    let spec_chain_position = b.chain_position;
    let spec_chain_length = b.chain_length;
    let spec_chain_node_ids = b.chain_node_ids;
    let spec_next_hop_addr = b.next_hop_addr;

    let cancel_task = Arc::clone(&cancel);
    let stats_task = Arc::clone(&stats);
    let id_for_task = id.clone();
    let runtime_task = Arc::clone(&runtime);
    let ctx_task = ctx.clone();
    let spec_ingress_task = spec_ingress.clone();
    let task = tokio::spawn(async move {
        run_accept_loop(
            listener,
            runtime_task,
            cancel_task,
            stats_task,
            id_for_task,
            ctx_task,
            spec_ingress_task,
            spec_framing,
            spec_position,
            spec_kind,
            spec_control_target,
            spec_chain_position,
            spec_chain_length,
            spec_chain_node_ids,
            spec_next_hop_addr,
        )
        .await;
    });

    let reconfigure_fn: crate::core::registry::handle_impl::ReconfigureFn =
        Arc::new(|current: &ListenerSpec, new_spec: &ListenerSpec| {
            let outcome = reconfigure_outcome_for(current, new_spec);
            Box::pin(async move { Ok::<_, Box<dyn std::error::Error + Send + Sync>>(outcome) })
        });

    Ok(Box::new(TaskListenerHandle::new(
        id,
        bound_addr,
        cancel,
        stats,
        task,
        spec,
        Some(reconfigure_fn),
    )))
}

async fn run_accept_loop(
    listener: TcpListener,
    runtime: Arc<NodeRuntime>,
    cancel: Arc<Notify>,
    stats: Arc<AtomicListenerStats>,
    id: ListenerId,
    ctx: crate::core::listener_ctx::ListenerCtx,
    spec_ingress: Option<mirage_core::mirage::wire::LayerSpec>,
    spec_framing: Option<Framing>,
    spec_position: Position,
    spec_kind: ListenerKind,
    spec_control_target: SocketAddr,
    spec_chain_position: u8,
    spec_chain_length: u8,
    spec_chain_node_ids: Vec<String>,
    spec_next_hop_addr: Option<String>,
) {
    let upstream_counter = Arc::new(std::sync::atomic::AtomicUsize::new(0));

    loop {
        let accept_fut = listener.accept();
        let cancel_fut = cancel.notified();

        let (stream, peer_addr) = tokio::select! {
            _ = cancel_fut => {
                info!(%id, "tcp_node_listener: cancellation received, draining");
                return;
            }
            accept_result = accept_fut => match accept_result {
                Ok(pair) => pair,
                Err(e) => {
                    error!(%id, error = %e, "accept error");
                    stats.rejected_total.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
            }
        };

        stats.accepted_total.fetch_add(1, Ordering::Relaxed);

        // Wave 5b: stamp per-listener dial activity so the WS scheduler can
        // report last_dial_ms to the monitor. Non-blocking write; any failure
        // (poisoned lock) is silently skipped — metrics are best-effort.
        {
            let now_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0);
            if let Ok(mut map) = runtime.dial_activity.write() {
                map.insert(id.0.clone(), now_ms);
            }
        }

        // Apply TCP keepalive on the accepted stream so silent-zombie peers are
        // evicted by the kernel in ~120s (60s idle + 4×15s probes) instead of
        // holding FDs forever. Failure is non-fatal — just warn and continue.
        {
            let ka = {
                let base = TcpKeepalive::new()
                    .with_time(Duration::from_secs(60))
                    .with_interval(Duration::from_secs(15));
                #[cfg(not(target_os = "windows"))]
                let base = base.with_retries(4);
                base
            };
            if let Err(e) = SockRef::from(&stream).set_tcp_keepalive(&ka) {
                warn!(%id, %peer_addr, "set_tcp_keepalive(accepted): {e}");
            }
        }

        let snap: Arc<NodeRuntimeSnapshot> = Arc::clone(&*runtime.snapshot.load());
        let keypair = Arc::new(runtime.keypair.clone());
        let mesh_id_bytes: Arc<[u8]> = Arc::from(runtime.mesh_id.as_bytes());
        let counter = Arc::clone(&runtime.active_tunnels);
        let doh = runtime.doh.load_full();
        let metrics = Arc::clone(&runtime.metrics);
        let upstream_counter_conn = Arc::clone(&upstream_counter);
        let stats_conn = Arc::clone(&stats);
        let id_conn = id.clone();
        let ctx_conn = ctx.clone();

        let spec_kind_conn = spec_kind;
        let spec_control_target_conn = spec_control_target;

        let chain_binding: Option<Arc<mirage_core::mirage::mesh::ChainBinding>> = ctx_conn
            .chain_id
            .as_ref()
            .and_then(|cid| {
                runtime
                    .chain_bindings
                    .load()
                    .lookup_by_str(cid)
                    .cloned()
                    .map(Arc::new)
            });

        // What this listener strips on ingress is this NODE's own published
        // fact, not something the chain binding hands out — `ChainLeg`/
        // `ChainExit` no longer carry a camouflage to read here (2026-09-02).
        // `spec.ingress_layer` (pushed per-listener by the monitor to match
        // what this listener actually binds) is the sole source now.
        let ingress_layer = spec_ingress.clone();

        // The outbound dial toward the NEXT hop wraps in THAT node's own
        // published chain face, read from the peer table — never invented
        // from the chain binding. `None` here (next hop unresolved, or
        // resolved but with no published chain face) means there is
        // nothing dialable; callers of `outbound_dial` already treat
        // `None` as "no camouflage, raw forward" for this non-onion
        // dispatch path, which is this path's existing tolerant contract.
        let outbound_dial =
            chain_binding.as_ref().and_then(|b| {
                let my_node = ctx_conn.node_id.as_ref();
                let next_node_id = b.next_hop_id(my_node)?;
                let pt = runtime.peer_table.load();
                let peer = pt.lookup_by_str(next_node_id.as_str())?;
                let face = peer.chain_face.as_ref()?;
                let outgoing = Some(mirage_core::mirage::wire::LayerSpec {
                    camouflage: Some(face.camouflage.clone()),
                    byte_cipher: None,
                    auth: None,
                    relay_mode: None,
                });
                let mut pk = [0u8; 32];
                if hex::decode_to_slice(&peer.pubkey_hex, &mut pk).is_err() {
                    pk = [0u8; 32];
                }
                Some(crate::core::listener::OutboundDial {
                    outgoing_layer: outgoing,
                    next_hop_pubkey: pk,
                    sni: String::new(),
                })
            });

        // Cloned per-accept for the onion peel/exit config resolvers below
        // (`resolve_onion_relay_config` / `resolve_onion_exit_config`) — no
        // pubkey or config is cached in the closure across connections.
        let spec_framing_conn = spec_framing;
        let spec_position_conn = spec_position;
        let spec_chain_node_ids_clone = spec_chain_node_ids.clone();
        let runtime_for_spawn = Arc::clone(&runtime);

        // Concurrent-connection cap: acquire a permit without blocking the
        // accept loop.  On exhaustion, drop the connection immediately rather
        // than pinning a task — the accept loop can then service further
        // connections.  One permit is held for the ENTIRE connection lifetime
        // so task + fd counts stay bounded.
        let permit = match accept_semaphore().try_acquire() {
            Ok(p) => p,
            Err(_) => {
                warn!(%id, %peer_addr, "tunnel_tcp: connection cap reached, dropping");
                stats.rejected_total.fetch_add(1, Ordering::Relaxed);
                continue;
            }
        };

        tokio::spawn(async move {
            // `permit` is moved into the task and dropped when the task ends,
            // releasing the slot back to the semaphore.
            let _permit = permit;
            counter.fetch_add(1, Ordering::Relaxed);
            stats_conn.active_conns.fetch_add(1, Ordering::Relaxed);

            // TunnelControl: perform Mirage AEAD handshake then bridge decrypted
            // plaintext to the monitor's over-chain loopback listener.
            // A 15-second handshake timeout guards against pre-auth DoS where a
            // slow/no-send dialer pins a task+fd forever during the AEAD handshake.
            // Once the handshake completes, the bridge copy loop runs without this
            // timeout (it has TCP keepalive applied to both sockets instead).
            if matches!(spec_kind_conn, ListenerKind::TunnelControl) {
                let r = tokio::time::timeout(
                    std::time::Duration::from_secs(15),
                    crate::family::mirage::exit::control::handle_control_exit(
                        stream,
                        spec_control_target_conn,
                        &keypair,
                        &mesh_id_bytes,
                    ),
                )
                .await;
                match r {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) => warn!(%id_conn, %peer_addr, "control exit error: {e}"),
                    Err(_) => debug!(%peer_addr, "handshake timeout"),
                }
                stats_conn.active_conns.fetch_sub(1, Ordering::Relaxed);
                counter.fetch_sub(1, Ordering::Relaxed);
                return;
            }

            // V8 / Wave-5 Stage-2 dispatch:
            //
            // Transparent and crypto_verify multihop chains carry
            // `relay_mode = Some(TransparentTcp | CryptoVerify)` in the spec.
            // They must NOT enter the onion path — they have no onion envelope.
            //
            // Onion path fires when:
            //   (a) explicit framing=Onion, OR
            //   (b) total_hops > 1 AND relay_mode is absent or OnionPeel
            //       (preserves Phase-11 behaviour).
            // The transparent / crypto_verify relay branch that stood here
            // was removed on 2026-09-02 with the modes it served. Both were
            // byte pumps that never terminated the tunnel, and both were
            // addressed by their bind port; chain hops no longer bind ports
            // outside the perimeter. A multi-hop relay leg is an onion hop.

            let is_multihop_by_role = spec_chain_length > 1;
            // Onion framing: explicit Onion framing OR implicit multihop.
            // The "unless relay_mode is transparent/cv" exclusion went with
            // those modes — there is nothing left for a multihop leg to be.
            let is_onion_multihop = is_multihop_by_role;
            let onion_framing = matches!(spec_framing_conn, Some(Framing::Onion))
                || is_onion_multihop;
            let is_onion_peel = onion_framing
                && matches!(spec_position_conn, Position::Entry | Position::Hop);
            let is_onion_exit = onion_framing
                && matches!(spec_position_conn, Position::Exit);

            let result = if is_onion_peel {
                {
                    metrics.onion.active_circuits.fetch_add(1, Ordering::Relaxed);

                    // Resolve identity and build the OnionRelayConfig from
                    // this spec's already-derived values — the one
                    // derivation, shared with the chain splice's
                    // selector-resolve path. See `resolve_onion_relay_config`.
                    let r = match resolve_onion_relay_config(
                        spec_chain_position,
                        spec_chain_length,
                        &spec_chain_node_ids_clone,
                        ctx_conn.chain_id.as_deref(),
                        ctx_conn.node_id.as_ref(),
                        &runtime_for_spawn,
                    ) {
                        RelayDialResolution::Refused { reason } => {
                            warn!(
                                %peer_addr,
                                chain_id = ?ctx_conn.chain_id,
                                reason = %reason,
                                "onion peel: refusing — next hop has no dialable chain face"
                            );
                            crate::core::chain_splice::dispose_unaddressable(
                                stream,
                                crate::core::chain_splice::UNADDRESSABLE_HOLD_MS,
                            )
                            .await;
                            Ok(())
                        }
                        RelayDialResolution::Dial(cfg) => {
                            // Strip ingress camouflage before the onion peel handler.
                            // Single-hop direct exit does this via handle_connection_with_protocol;
                            // multi-hop onion must do it here so the handler sees plaintext bytes.
                            let effective_camouflage = ingress_layer
                                .as_ref()
                                .and_then(|l| l.camouflage.clone());

                            // Onion-ENTRY byte_cipher wire-skin: the client wrote a one-time
                            // magic/junk prefix as an outer transport obfuscation. Strip it
                            // here (after camo, before envelope read) so `onion + magic/junk`
                            // composes. Set ONLY on hop 0 by the monitor; middle hops see None.
                            let ingress_bc = ingress_layer
                                .as_ref()
                                .and_then(|l| l.byte_cipher.clone());

                            if let Some(cam) = effective_camouflage {
                                use mirage_protocol::camouflage::pipeline::strip_tcp_server;
                                match strip_tcp_server(stream, &cam, &*keypair).await {
                                    Ok(Some(unwrapped)) => {
                                        match peel_onion_ingress_skin(unwrapped, ingress_bc.clone(), peer_addr).await {
                                            Ok(skinned) => {
                                                crate::family::mirage::relay::onion_peel::handle_onion_peel(
                                                    cfg, skinned, peer_addr, None,
                                                ).await
                                            }
                                            Err(e) => {
                                                warn!(%peer_addr, error = %e, "onion peel: ingress byte_cipher skin failed");
                                                Err(e)
                                            }
                                        }
                                    }
                                    Ok(None) => {
                                        // Camouflage strip rejected the connection (e.g. wrong SNI).
                                        warn!(%peer_addr, "onion peel: camouflage strip rejected connection");
                                        Ok(())
                                    }
                                    Err(e) => {
                                        warn!(%peer_addr, error = %e, "onion peel: camouflage strip failed");
                                        Err(e)
                                    }
                                }
                            } else {
                                match peel_onion_ingress_skin(stream, ingress_bc, peer_addr).await {
                                    Ok(skinned) => {
                                        crate::family::mirage::relay::onion_peel::handle_onion_peel(
                                            cfg, skinned, peer_addr, None,
                                        ).await
                                    }
                                    Err(e) => {
                                        warn!(%peer_addr, error = %e, "onion peel: ingress byte_cipher skin failed");
                                        Err(e)
                                    }
                                }
                            }
                        }
                    };

                    metrics.onion.active_circuits.fetch_sub(1, Ordering::Relaxed);
                    match &r {
                        Ok(()) => {
                            metrics.onion.total_circuits.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(_) => {
                            metrics.onion.circuit_fails.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    r
                }
            } else if is_onion_exit {
                {
                    metrics.onion.active_circuits.fetch_add(1, Ordering::Relaxed);

                    // Resolve this hop's config from the spec's already-derived
                    // values — the one derivation, shared with the chain
                    // splice's selector-resolve path. See
                    // `resolve_onion_exit_config`.
                    let cfg = resolve_onion_exit_config(
                        spec_chain_position,
                        spec_chain_length,
                        &spec_chain_node_ids_clone,
                        &runtime_for_spawn,
                    );

                    // Strip ingress camouflage before the onion exit handler.
                    let effective_camouflage = ingress_layer
                        .as_ref()
                        .and_then(|l| l.camouflage.clone());

                    let r = if let Some(cam) = effective_camouflage {
                        use mirage_protocol::camouflage::pipeline::strip_tcp_server;
                        match strip_tcp_server(stream, &cam, &*keypair).await {
                            Ok(Some(unwrapped)) => {
                                crate::family::mirage::exit::onion::handle_onion_exit(
                                    cfg,
                                    unwrapped,
                                    peer_addr,
                                )
                                .await
                            }
                            Ok(None) => {
                                warn!(%peer_addr, "onion exit: camouflage strip rejected connection");
                                Ok(())
                            }
                            Err(e) => {
                                warn!(%peer_addr, error = %e, "onion exit: camouflage strip failed");
                                Err(e)
                            }
                        }
                    } else {
                        crate::family::mirage::exit::onion::handle_onion_exit(
                            cfg,
                            stream,
                            peer_addr,
                        )
                        .await
                    };

                    metrics.onion.active_circuits.fetch_sub(1, Ordering::Relaxed);
                    match &r {
                        Ok(()) => {
                            metrics.onion.total_circuits.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(_) => {
                            metrics.onion.circuit_fails.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    r
                }
            } else {
                {
                    handle_connection_with_protocol(
                        stream,
                        peer_addr,
                        snap,
                        keypair,
                        doh,
                        upstream_counter_conn,
                        metrics,
                        None,
                        ctx_conn,
                        chain_binding,
                        outbound_dial,
                        ingress_layer,
                        Arc::clone(&runtime_for_spawn.role_signed_replay),
                    )
                    .await
                }
            };

            if let Err(e) = result {
                warn!(%id_conn, %peer_addr, "connection error: {e}");
            }
            stats_conn.active_conns.fetch_sub(1, Ordering::Relaxed);
            counter.fetch_sub(1, Ordering::Relaxed);
        });
    }
}

/// Extract an SNI / host hint from an outgoing camouflage spec.
///
/// Returns `None` for camouflages that carry no SNI (raw-TCP, SSH, WS without
/// a TLS envelope, etc.).  The returned string is passed to `wrap_tcp_client`
/// as the `sni` override; an empty string tells the camouflage layer to use
/// whatever default is baked into the camouflage config itself.
fn extract_sni_from_camouflage(cam: Option<&mirage_core::config::TransportCamouflage>) -> String {
    use mirage_core::config::TransportCamouflage;
    match cam {
        Some(TransportCamouflage::TlsReal { sni, .. }) => sni.clone(),
        Some(TransportCamouflage::Reality { server_name, .. }) => server_name.clone(),
        Some(TransportCamouflage::WebSocket { host, .. }) => host.clone(),
        Some(TransportCamouflage::Xhttp { host, .. }) => host.clone(),
        _ => String::new(),
    }
}

#[cfg(test)]
mod reconfigure_tests {
    use super::{bundle_from_spec, reconfigure_outcome_for, Position};
    use crate::core::registry::handle::ReconfigureOutcome;
    use crate::core::registry::spec::{ListenerId, ListenerSpec};
    use mirage_core::mirage::wire::{
        AeadSuite, ExitMode, Framing, ListenerRole, MirageListenerKind, SpecFingerprint,
    };

    /// A real spec, built once. Every case below MUTATES ONE FIELD of a clone
    /// of this rather than hand-writing a second literal — see the plan's
    /// method note: a literal encodes the author's belief about the shape, a
    /// mutated real value encodes the shape.
    fn a_bound_spec() -> ListenerSpec {
        ListenerSpec {
            id: ListenerId("auto-fa291277-h0".into()),
            mesh_id: "MESH1".into(),
            kind: MirageListenerKind::TunnelTcp,
            role: ListenerRole::Exit {
                exit_mode: ExitMode::Direct,
            },
            framing: Framing::Plain,
            ingress_layer: None,
            outgoing_layer: None,
            aead_suite: AeadSuite::ChaCha20Poly1305,
            bind_port: Some(20000),
            chain_role: None,
            control_target: None,
            payload: None,
            fingerprint: SpecFingerprint([0u8; 32]),
        }
        .with_recomputed_fingerprint()
    }

    /// The bundle reflects the spec rather than its own defaults.
    ///
    /// The cross-path equality this test used to also claim is asserted where
    /// it can be real — through the registry, in `selector.rs` — because here
    /// it compared one function with itself.
    #[test]
    fn a_bundle_carries_the_specs_values_and_not_defaults() {
        let spec = a_bound_spec();
        // The equality half of this test used to compare two calls of
        // `bundle_from_spec` on one value, which is true by construction and
        // proved nothing. It now lives in
        // `selector::chain_routing_tests::the_resolved_spec_derives_the_same_bundle_as_activate_would`,
        // which registers a spec, resolves it the way a frame does, and
        // compares the bundle from what came back with the bundle from what
        // went in. What is left here is the half that was always real:
        let from_activate = bundle_from_spec(&spec);

        // The values are the spec's, not defaults. A bundle that silently fell
        // back to `(0, 1, empty, None)` for a spec with no chain_role would
        // compare equal to itself and prove nothing.
        assert_eq!(from_activate.kind, spec.kind);
        assert_eq!(from_activate.framing, Some(spec.framing));
        assert_eq!(from_activate.position, Position::Exit);
        assert_eq!(from_activate.chain_length, 1, "no chain_role means a single hop");
    }

    /// The chain_role values reach the bundle rather than being defaulted.
    #[test]
    fn a_chain_role_reaches_the_bundle() {
        use mirage_core::mirage::wire::ChainRole;
        let mut spec = a_bound_spec();
        spec.chain_role = Some(ChainRole {
            chain_id: "auto-fa291277".into(),
            chain_position: 1,
            chain_length: 3,
            chain_node_ids: vec!["a".into(), "b".into(), "c".into()],
            next_hop_addr: Some("10.0.0.2:443".into()),
            selector_token_hex: None,
        });
        let b = bundle_from_spec(&spec.with_recomputed_fingerprint());
        assert_eq!(b.chain_position, 1);
        assert_eq!(b.chain_length, 3);
        assert_eq!(b.chain_node_ids.len(), 3);
        assert_eq!(b.next_hop_addr.as_deref(), Some("10.0.0.2:443"));
    }

    #[test]
    fn a_changed_non_port_axis_requires_a_rebind() {
        // The regression this exists for. `framing` is not `bind_port`, it is
        // captured by value at `activate()` and never re-read, and the old
        // comparison answered `Applied` — so the registry recorded the new
        // spec as in force while the accept loop went on serving the old one.
        let current = a_bound_spec();
        let mut new_spec = current.clone();
        new_spec.framing = Framing::Onion;
        let new_spec = new_spec.with_recomputed_fingerprint();

        assert_eq!(
            new_spec.bind_port, current.bind_port,
            "the port is deliberately IDENTICAL — that is the whole point"
        );
        assert!(
            matches!(
                reconfigure_outcome_for(&current, &new_spec),
                ReconfigureOutcome::RebindRequired
            ),
            "a framing change must rebind; answering Applied is the defect"
        );
    }

    #[test]
    fn a_changed_role_requires_a_rebind() {
        // A second non-port axis, because one example proves one field and
        // the contract is about every field.
        let current = a_bound_spec();
        let mut new_spec = current.clone();
        new_spec.aead_suite = AeadSuite::Aes256Gcm;
        let new_spec = new_spec.with_recomputed_fingerprint();

        assert!(matches!(
            reconfigure_outcome_for(&current, &new_spec),
            ReconfigureOutcome::RebindRequired
        ));
    }

    #[test]
    fn a_changed_port_still_requires_a_rebind() {
        // The one case the old comparison got right. It must stay right.
        let current = a_bound_spec();
        let mut new_spec = current.clone();
        new_spec.bind_port = Some(20001);
        let new_spec = new_spec.with_recomputed_fingerprint();

        assert!(matches!(
            reconfigure_outcome_for(&current, &new_spec),
            ReconfigureOutcome::RebindRequired
        ));
    }

    #[test]
    fn an_identical_spec_is_applied_without_a_rebind() {
        // The registry only calls reconfigure when fingerprints differ, so
        // this case is unreachable in production — asserted anyway, because
        // an implementation that rebound on NO change would be a different
        // and equally silent defect.
        let current = a_bound_spec();
        let same = current.clone();
        assert!(matches!(
            reconfigure_outcome_for(&current, &same),
            ReconfigureOutcome::Applied
        ));
    }
}

/// `resolve_onion_relay_config`'s three outcomes: a real dial, a raw-shaped
/// dial that must not be confused with a refusal, and a refusal that must
/// not be confused with a raw-shaped dial. See its own doc, and
/// `mirage_core::mirage::mesh::ChainFace`'s, for why the middle case exists.
#[cfg(test)]
mod resolve_onion_relay_config_tests {
    use super::*;
    use crate::core::runtime::{NodeRuntime, NodeRuntimeSnapshot};
    use mirage_core::config::NodeConfig;
    use mirage_core::crypto::{KeyPair, SpentSet};
    use mirage_core::mirage::mesh::{
        ChainBinding, ChainBindings, ChainExit, ChainFace, ChainId, ChainLeg, MeshId, NodeId,
        PeerTable, PeerTableEntry,
    };
    use mirage_core::mirage::wire::{AeadSuite, ExitMode, RelayMode, TransportCamouflage};

    /// A runtime just complete enough to construct and call
    /// `resolve_onion_relay_config` against — mirrors
    /// `chain_splice::tests::test_runtime`.
    fn test_runtime() -> Arc<NodeRuntime> {
        let node_config: NodeConfig = serde_json::from_value(serde_json::json!({
            "node_id": "own-node",
            "listen_addr": "127.0.0.1:0",
            "mode": {"Relay": {"fallback_dest": "", "fallback_sni": "", "upstreams": []}},
            "protocols": [],
            "admin_endpoint": null,
            "health_interval_secs": 30,
            "psk": null,
        }))
        .expect("test NodeConfig must deserialize");

        let snapshot = NodeRuntimeSnapshot {
            protocols: Vec::new(),
            pools: Vec::new(),
            relay_metrics: None,
            node_config,
            credential_params: Arc::new(arc_swap::ArcSwap::new(Arc::new(None))),
            spent_set: Arc::new(std::sync::Mutex::new(SpentSet::new())),
            role_signed_replay: Arc::new(std::sync::Mutex::new(
                crate::core::role_signed_gate::RoleSignedReplayCache::new(),
            )),
            allow_legacy_v8: true,
        };

        NodeRuntime::new(snapshot, KeyPair::generate(), Arc::from("test-mesh"), None, None)
    }

    /// Two-hop chain: `own-node` is the entry leg, `next-hop` is the exit —
    /// the minimal shape that gives `own-node` a real next hop to resolve.
    fn two_hop_binding(chain_id: &str) -> ChainBinding {
        ChainBinding {
            mesh_id: MeshId::new("test-mesh"),
            chain_id: ChainId::new(chain_id),
            legs: vec![ChainLeg {
                node_id: NodeId::new("own-node"),
                relay_mode: RelayMode::OnionPeel,
                aead_suite: AeadSuite::ChaCha20Poly1305,
                byte_cipher: None,
                selector_token_hex: None,
            }],
            exit: ChainExit {
                node_id: NodeId::new("next-hop"),
                exit_mode: ExitMode::Direct,
                aead_suite: AeadSuite::ChaCha20Poly1305,
                selector_token_hex: None,
            },
            onion_reply_mode: None,
            handshake: None,
        }
    }

    fn peer_entry(node_id: &str, chain_face: Option<ChainFace>) -> PeerTableEntry {
        PeerTableEntry {
            mesh_id: MeshId::new("test-mesh"),
            responsible_monitor_id: String::new(),
            node_id: NodeId::new(node_id),
            pubkey_hex: "11".repeat(32),
            addr: "203.0.113.9:443".to_string(),
            labels: Vec::new(),
            updated_at_ms: 0,
            aead_suite_preference: Vec::new(),
            chain_face,
            chain_face_udp: None,
        }
    }

    /// A relay whose next hop publishes a chain face dials with THAT face's
    /// camouflage, not something invented from the chain binding (which no
    /// longer carries a camouflage to invent from at all).
    #[test]
    fn a_relay_dials_the_next_hops_published_face_not_the_binding() {
        let runtime = test_runtime();
        let chain_id = "chain-face-dial";
        runtime.chain_bindings.store(Arc::new(ChainBindings {
            generation: 1,
            bindings: vec![two_hop_binding(chain_id)],
        }));
        let face = ChainFace {
            port: 443,
            camouflage: TransportCamouflage::TlsReal {
                sni: "example.com".to_string(),
                alpn: Vec::new(),
            },
        };
        runtime.peer_table.store(Arc::new(PeerTable {
            generation: 1,
            peers: vec![peer_entry("next-hop", Some(face.clone()))],
        }));

        let resolution = resolve_onion_relay_config(
            0,
            2,
            &["own-node".to_string(), "next-hop".to_string()],
            Some(chain_id),
            "own-node",
            &runtime,
        );

        match resolution {
            RelayDialResolution::Dial(cfg) => {
                assert_eq!(
                    cfg.outgoing_camouflage,
                    Some(face.camouflage.clone()),
                    "must dial with the next hop's published face, not an invented one"
                );
                assert_eq!(
                    cfg.outgoing_sni, "example.com",
                    "SNI follows the face-sourced camouflage"
                );
            }
            RelayDialResolution::Refused { reason } => {
                panic!("a next hop with a published face must be dialable, got refusal: {reason}")
            }
        }
    }

    /// A next hop that has published no chain face at all refuses the
    /// dial — there is nothing dialable — and names the node in the
    /// refusal reason.
    #[test]
    fn a_next_hop_with_no_chain_face_refuses_and_names_the_node() {
        let runtime = test_runtime();
        let chain_id = "chain-no-face";
        runtime.chain_bindings.store(Arc::new(ChainBindings {
            generation: 1,
            bindings: vec![two_hop_binding(chain_id)],
        }));
        runtime.peer_table.store(Arc::new(PeerTable {
            generation: 1,
            peers: vec![peer_entry("next-hop", None)],
        }));

        let resolution = resolve_onion_relay_config(
            0,
            2,
            &["own-node".to_string(), "next-hop".to_string()],
            Some(chain_id),
            "own-node",
            &runtime,
        );

        match resolution {
            RelayDialResolution::Refused { reason } => {
                assert!(
                    reason.contains("next-hop"),
                    "the refusal must name the node that has no chain face: {reason}"
                );
            }
            RelayDialResolution::Dial(_) => {
                panic!("a next hop with no published chain face must refuse, not dial")
            }
        }
    }

    /// A next hop whose published face camouflage is `TransportCamouflage::
    /// None` (a legitimate RAW-shaped face — port 22 on every box) dials
    /// raw, and must not be confused with the refusal above. This is the
    /// whole reason `ChainFace` bundles port and camouflage in one struct
    /// rather than two `Option`s.
    #[test]
    fn a_raw_shaped_published_face_dials_raw_and_is_not_a_refusal() {
        let runtime = test_runtime();
        let chain_id = "chain-raw-face";
        runtime.chain_bindings.store(Arc::new(ChainBindings {
            generation: 1,
            bindings: vec![two_hop_binding(chain_id)],
        }));
        let face = ChainFace {
            port: 22,
            camouflage: TransportCamouflage::None,
        };
        runtime.peer_table.store(Arc::new(PeerTable {
            generation: 1,
            peers: vec![peer_entry("next-hop", Some(face))],
        }));

        let resolution = resolve_onion_relay_config(
            0,
            2,
            &["own-node".to_string(), "next-hop".to_string()],
            Some(chain_id),
            "own-node",
            &runtime,
        );

        match resolution {
            RelayDialResolution::Dial(cfg) => {
                assert_eq!(
                    cfg.outgoing_camouflage,
                    Some(TransportCamouflage::None),
                    "a RAW-shaped published face is Some(TransportCamouflage::None) — \
                     a real, dialable fact — never the refusal path"
                );
            }
            RelayDialResolution::Refused { reason } => panic!(
                "a RAW-shaped chain face must dial raw, not be confused with an \
                 absent one: {reason}"
            ),
        }
    }
}

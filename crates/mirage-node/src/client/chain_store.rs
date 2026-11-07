//! Held-chain store: this box, as owner of its own onion chains, keeps at
//! least [`MIN_CHAIN_COUNT`] distinct chains warm **per exit choice**
//! ([`ExitChoice`] — auto, or a specific country), spread across different
//! monitors, rebuilding a chain before its TTL runs out or once it has
//! failed to carry traffic too many times in a row.
//!
//! # Ported from `edge_client_supply.rs`
//!
//! The pure scheduling logic below is a direct port of
//! `mirage2operator/crates/operator-box/src/edge_client_supply.rs` (opbox's
//! now-retired cli2 supply loop — see
//! `docs/mirage/plans/2026-09-24-edge-as-entry.md`, "Chain supply: request
//! as owner, stay subscribed, hold >= 2 distinct chains"):
//! [`chain_needs_rebuild`] (`edge_client_supply.rs:254-261`),
//! [`chains_to_build`] (`edge_client_supply.rs:269-272`), and the two
//! tunables [`MIN_CHAIN_COUNT`] (`:120`) / [`CHAIN_REBUILD_LEAD_FRACTION`]
//! (`:133-139`) — same values, same intent: rebuild once less than a third
//! of a chain's TTL remains, hold at least two per demand. The pure-function
//! test names below mirror that module's own test intent one for one.
//!
//! # What is new here, not ported
//!
//! - **Keyed by [`ExitChoice`]**, not one flat pool per box. `mirage-edge`
//!   serves many customers, each picking "auto" or a specific country (plan
//!   §"The client picks the exit, the edge fulfils it"), so demand and
//!   rebuild scheduling are tracked per exit choice independently, started
//!   lazily on first demand ([`HeldChainStore::record_demand`]) and dropped
//!   after an idle period ([`HeldChainStore::drop_idle_pools`]).
//! - **Spread across monitors.** opbox's own loop built every chain through
//!   one pre-picked anchor monitor; this store instead spreads a pool's
//!   chains across whichever monitors [`HeldChainStore::reconcile`] is
//!   currently handed, picking the least-loaded one per new chain
//!   ([`choose_monitor`]) — "requested via different monitors" per the
//!   plan, so one monitor's outage does not strand every held chain for one
//!   exit choice.
//! - **`consecutive_dial_failures`.** opbox never dialled through a chain
//!   after building it, so it never needed this; `mirage-edge` does (its
//!   mesh leg dials through every held chain itself — see the fleet's mesh leg (`mirage-edge-fleet`'s `mesh_leg`)),
//!   so a chain that fails [`CONSECUTIVE_FAILURE_REBUILD_THRESHOLD`] dials in
//!   a row is treated as no longer live and rebuilt immediately, rather than
//!   waiting out its TTL — see the plan's "Liveness beyond the TTL clock".
//!
//! # `ChainSource` — the real chain build/rebuild call lands in a later brief
//!
//! Acquiring an actual chain needs the monitor's edge client-registration
//! contract (`docs/mirage/plans/2026-09-24-edge-as-entry.md`'s "Chain
//! supply" section), a separate, not-yet-merged branch
//! (`mirage2monitor`, `edge-client-reg`). This module never fakes that
//! call: every impure chain acquisition goes through [`ChainSource`], a
//! trait this store depends on but does not implement — production code has
//! no impl to construct until that contract lands. Only this module's own
//! tests supply one, as a test double.

use std::collections::HashMap;

use mirage_core::config::ChainConfig;
use tokio::sync::Mutex;

// ── tunables ─────────────────────────────────────────────────────────────

/// Minimum number of live (not due-for-rebuild, not failure-tripped) chains
/// held per exit choice in demand. Ported from `edge_client_supply.rs:120`.
pub const MIN_CHAIN_COUNT: usize = 2;

/// Rebuild a held chain once less than this fraction of its own TTL
/// remains. Ported from `edge_client_supply.rs:133-139`
/// (`CHAIN_REBUILD_LEAD_FRACTION`).
pub const CHAIN_REBUILD_LEAD_FRACTION: f64 = 1.0 / 3.0;

/// Consecutive dial failures against one held chain before it is treated as
/// no longer live and rebuilt immediately, regardless of its TTL. New in
/// this crate — see the module doc's "What is new here" section. Per the
/// plan's own proposed value ("N consecutive failures (proposed 3)").
pub const CONSECUTIVE_FAILURE_REBUILD_THRESHOLD: u32 = 3;

/// How long a per-exit-choice pool may sit with no recorded demand before
/// [`HeldChainStore::drop_idle_pools`] drops it. Proposed default, not
/// owner-confirmed — same "needs sign-off before it is final" convention
/// `edge_client_supply.rs`'s own tunables followed.
pub const POOL_IDLE_TIMEOUT_MS: u64 = 30 * 60 * 1000;

/// How often a LIVE subscriber session re-records demand for its
/// [`ExitChoice`].
///
/// Demand is otherwise recorded exactly once -- when a session is ACCEPTED
/// (`crate::client::entrance::serve_accepted_session`). A long-lived mux session
/// streams for hours and never re-accepts, so its pool's idle clock kept
/// running and the pool was dropped 30 minutes in, taking healthy chains
/// with it (the blackout of 2026-10-21:
/// `docs/mirage/audits/edge-idle-demand-drop-blackout-2026-10-21.md`).
/// Refreshing on a timer, WHILE the session is alive, makes the idle clock
/// mean "no session is asking" rather than "no session was accepted
/// recently".
pub const DEMAND_REFRESH_INTERVAL_MS: u64 = 60_000;

// ── exit choice ──────────────────────────────────────────────────────────

/// Which exit a client asked for — "auto" (any monitor/exit the picker
/// grants) or a specific country. One [`HeldChainStore`] pool per distinct
/// value in demand; see the plan's "Auto exit / country choice".
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ExitChoice {
    Auto,
    Country(String),
}

impl std::fmt::Display for ExitChoice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExitChoice::Auto => f.write_str("auto"),
            ExitChoice::Country(c) => write!(f, "country:{c}"),
        }
    }
}

// ── held chain ───────────────────────────────────────────────────────────

/// One chain this store currently holds for one [`ExitChoice`].
#[derive(Debug, Clone)]
pub struct HeldChain {
    pub chain_id: String,
    pub config: ChainConfig,
    /// Which monitor this chain was requested through — the spread
    /// [`choose_monitor`] exists to maintain across a pool's chains.
    pub monitor_id: String,
    pub built_at_ms: u64,
    pub expires_at_ms: u64,
    /// See [`CONSECUTIVE_FAILURE_REBUILD_THRESHOLD`]. Reset on
    /// [`HeldChainStore::record_dial_success`].
    pub consecutive_dial_failures: u32,
}

// ── ChainSource ──────────────────────────────────────────────────────────

/// Why a [`ChainSource`] could not produce a chain this tick. Named, not a
/// bare string wrapper's worth of nothing more — a caller (or a test) can
/// tell "the monitor refused" apart from "the dial itself failed" without
/// parsing prose.
#[derive(Debug, Clone, thiserror::Error)]
pub enum ChainSourceError {
    #[error("monitor {monitor_id} refused the request: {reason}")]
    Refused { monitor_id: String, reason: String },
    #[error("could not reach monitor {monitor_id}: {reason}")]
    Unreachable { monitor_id: String, reason: String },
}

/// Acquires (or rebuilds) a chain for one [`ExitChoice`] via one monitor.
///
/// The real implementation — the monitor edge-registration contract named
/// in this module's own doc — lands once that branch merges. Production
/// code depends on this trait and never fakes an implementation of it; only
/// tests supply a double.
#[async_trait::async_trait]
pub trait ChainSource: Send + Sync {
    /// Request a fresh chain for `exit` via `monitor_id`. Called both for
    /// first demand and for a scheduled/failure-triggered rebuild — a
    /// rebuild is always a fresh chain, never an in-place mutation of the
    /// one it replaces (mirrors `edge_client_supply.rs`'s own
    /// build-then-retire shape, see [`HeldChainStore::reconcile`]).
    async fn request_chain(
        &self,
        exit: &ExitChoice,
        monitor_id: &str,
        now_ms: u64,
    ) -> Result<HeldChain, ChainSourceError>;
}

// ── pure helpers ─────────────────────────────────────────────────────────

/// Does this held chain need to be rebuilt on TTL grounds alone — already
/// expired, or inside the [`CHAIN_REBUILD_LEAD_FRACTION`] renewal window?
/// Ported verbatim from `edge_client_supply.rs:254-261`.
pub fn chain_needs_rebuild(now_ms: u64, built_at_ms: u64, expires_at_ms: u64) -> bool {
    if expires_at_ms <= now_ms {
        return true;
    }
    let total = expires_at_ms.saturating_sub(built_at_ms).max(1) as f64;
    let remaining = expires_at_ms.saturating_sub(now_ms) as f64;
    remaining < total * CHAIN_REBUILD_LEAD_FRACTION
}

/// Is `chain` currently live — neither due for a TTL rebuild nor tripped
/// past [`CONSECUTIVE_FAILURE_REBUILD_THRESHOLD`]? The single predicate
/// both [`chains_to_build`] and [`HeldChainStore::reconcile`]'s retire step
/// use, so the two halves of "what counts as replaced" can never drift
/// apart from each other.
fn chain_is_live(now_ms: u64, chain: &HeldChain) -> bool {
    !chain_needs_rebuild(now_ms, chain.built_at_ms, chain.expires_at_ms)
        && chain.consecutive_dial_failures < CONSECUTIVE_FAILURE_REBUILD_THRESHOLD
}

/// How many NEW chains to build this tick — enough to bring the count of
/// live chains up to `min_count`. Ported from `edge_client_supply.rs:269-272`,
/// generalised to also exclude a failure-tripped chain from "live" (see
/// [`chain_is_live`]).
pub fn chains_to_build(now_ms: u64, held: &[HeldChain], min_count: usize) -> usize {
    let live = held.iter().filter(|h| chain_is_live(now_ms, h)).count();
    min_count.saturating_sub(live)
}

/// Which monitor the next new chain for this pool should be requested
/// through — whichever of `monitors` currently backs the FEWEST of
/// `held`'s chains, ties broken by `monitors`' own order. Spreads a pool's
/// chains across the roster instead of piling every one onto the same
/// monitor — see the module doc's "Spread across monitors".
pub fn choose_monitor<'m>(monitors: &'m [String], held: &[HeldChain]) -> Option<&'m str> {
    monitors
        .iter()
        .min_by_key(|m| held.iter().filter(|h| &h.monitor_id == *m).count())
        .map(|s| s.as_str())
}

// ── store (impure) ───────────────────────────────────────────────────────

struct ExitPool {
    chains: Vec<HeldChain>,
    last_demand_ms: u64,
}

/// Report of one [`HeldChainStore::reconcile`] pass.
#[derive(Debug, Default, Clone)]
pub struct ReconcileReport {
    pub built: usize,
    pub failed: Vec<ChainSourceError>,
}

/// Held chains for every [`ExitChoice`] currently in demand.
pub struct HeldChainStore {
    pools: Mutex<HashMap<ExitChoice, ExitPool>>,
}

impl Default for HeldChainStore {
    fn default() -> Self {
        Self::new()
    }
}

impl HeldChainStore {
    pub fn new() -> Self {
        Self { pools: Mutex::new(HashMap::new()) }
    }

    /// Record that a client asked for `exit` right now. Lazily starts a
    /// pool for it if this is the first ask, and always refreshes the idle
    /// clock — see [`Self::drop_idle_pools`].
    pub async fn record_demand(&self, exit: ExitChoice, now_ms: u64) {
        let mut pools = self.pools.lock().await;
        pools
            .entry(exit)
            .or_insert_with(|| ExitPool { chains: Vec::new(), last_demand_ms: now_ms })
            .last_demand_ms = now_ms;
    }

    /// Snapshot of the chains currently held for `exit` — empty both when
    /// no pool exists yet and when one exists but holds nothing (a mesh
    /// that cannot yet supply this exit choice). Callers distinguishing
    /// "never asked for" from "asked for, nothing held yet" should call
    /// [`Self::record_demand`] themselves first.
    pub async fn held_chains(&self, exit: &ExitChoice) -> Vec<HeldChain> {
        let pools = self.pools.lock().await;
        pools.get(exit).map(|p| p.chains.clone()).unwrap_or_default()
    }

    /// Every [`ExitChoice`] currently tracked (in demand or still holding
    /// chains from recent demand) — what [`Self::reconcile`] iterates.
    pub async fn demanded_exits(&self) -> Vec<ExitChoice> {
        self.pools.lock().await.keys().cloned().collect()
    }

    /// Record a dial failure against `chain_id` under `exit` — a no-op if
    /// no such pool or chain exists (the pool may have been dropped as idle
    /// between the dial and this call).
    pub async fn record_dial_failure(&self, exit: &ExitChoice, chain_id: &str) {
        let mut pools = self.pools.lock().await;
        if let Some(pool) = pools.get_mut(exit) {
            if let Some(chain) = pool.chains.iter_mut().find(|c| c.chain_id == chain_id) {
                chain.consecutive_dial_failures = chain.consecutive_dial_failures.saturating_add(1);
            }
        }
    }

    /// Reset `chain_id`'s failure counter under `exit` after a dial that
    /// actually carried traffic.
    pub async fn record_dial_success(&self, exit: &ExitChoice, chain_id: &str) {
        let mut pools = self.pools.lock().await;
        if let Some(pool) = pools.get_mut(exit) {
            if let Some(chain) = pool.chains.iter_mut().find(|c| c.chain_id == chain_id) {
                chain.consecutive_dial_failures = 0;
            }
        }
    }

    /// Drop every pool whose last recorded demand is older than
    /// `idle_timeout_ms` — see the module doc's "lazy start / idle drop".
    /// Returns the [`ExitChoice`]s dropped, so a caller (the fleet's mesh leg (`mirage-edge-fleet`'s `mesh_leg`))
    /// can tear down whatever per-chain resources (mux pools) it was
    /// keeping for them.
    ///
    /// A pool that still holds a LIVE chain is NOT dropped. Demand is
    /// recorded when a subscriber session is accepted, and a long-lived mux
    /// session never re-accepts — so the idle clock alone used to destroy
    /// healthy chains 30 minutes into a session that was still streaming
    /// (the blackout of 2026-10-21,
    /// `docs/mirage/audits/edge-idle-demand-drop-blackout-2026-10-21.md`).
    /// Such a pool is PRUNED instead: only the chains that are no longer
    /// live are dropped, the live ones stay, and the idle clock is
    /// restarted so the pool is judged by real idleness again. A pool is
    /// really dropped only once no live chain is left in it.
    pub async fn drop_idle_pools(&self, now_ms: u64, idle_timeout_ms: u64) -> Vec<ExitChoice> {
        let mut pools = self.pools.lock().await;
        let idle: Vec<ExitChoice> = pools
            .iter()
            .filter(|(_, pool)| now_ms.saturating_sub(pool.last_demand_ms) >= idle_timeout_ms)
            .map(|(exit, _)| exit.clone())
            .collect();
        let mut dropped: Vec<ExitChoice> = Vec::with_capacity(idle.len());
        for exit in idle {
            let keep_pool = {
                let Some(pool) = pools.get_mut(&exit) else { continue };
                pool.chains.retain(|chain| chain_is_live(now_ms, chain));
                if pool.chains.is_empty() {
                    false
                } else {
                    // Somebody is still being served off this pool: restart
                    // its idle clock instead of judging it idle again on the
                    // very next tick.
                    pool.last_demand_ms = now_ms;
                    true
                }
            };
            if !keep_pool {
                pools.remove(&exit);
                dropped.push(exit);
            }
        }
        dropped
    }

    /// Build whatever chains are missing, for every exit choice currently
    /// tracked, via `source` — the one place this store calls out to the
    /// mesh. `min_count` is ordinarily [`MIN_CHAIN_COUNT`]; exposed as a
    /// parameter so tests can shrink it.
    ///
    /// A chain that needed rebuilding is retired from the held set only
    /// once at least one replacement landed THIS pass (mirrors
    /// `edge_client_supply.rs::reconcile_machine`'s own "never speculatively"
    /// rule) — a mesh that grants fewer than requested still leaves the old,
    /// still-live chains in place rather than stranding the pool at zero.
    pub async fn reconcile(
        &self,
        now_ms: u64,
        monitors: &[String],
        min_count: usize,
        source: &dyn ChainSource,
    ) -> ReconcileReport {
        let exits: Vec<ExitChoice> = self.pools.lock().await.keys().cloned().collect();
        let mut report = ReconcileReport::default();

        for exit in exits {
            let due = {
                let pools = self.pools.lock().await;
                let Some(pool) = pools.get(&exit) else { continue };
                chains_to_build(now_ms, &pool.chains, min_count)
            };

            let mut built_this_exit = 0usize;
            for _ in 0..due {
                let chosen = {
                    let pools = self.pools.lock().await;
                    let held = pools.get(&exit).map(|p| p.chains.as_slice()).unwrap_or(&[]);
                    choose_monitor(monitors, held).map(|s| s.to_string())
                };
                let Some(monitor_id) = chosen else {
                    // No monitor roster to request through yet -- nothing
                    // more this pass can do for this exit choice.
                    break;
                };
                match source.request_chain(&exit, &monitor_id, now_ms).await {
                    Ok(chain) => {
                        let mut pools = self.pools.lock().await;
                        if let Some(pool) = pools.get_mut(&exit) {
                            pool.chains.push(chain);
                            built_this_exit += 1;
                            report.built += 1;
                        }
                    }
                    Err(e) => report.failed.push(e),
                }
            }

            if built_this_exit > 0 {
                let mut pools = self.pools.lock().await;
                if let Some(pool) = pools.get_mut(&exit) {
                    pool.chains.retain(|h| chain_is_live(now_ms, h));
                }
            }
        }

        report
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_chain_config(chain_id: &str) -> ChainConfig {
        ChainConfig {
            chain_id: chain_id.to_string(),
            hops: Vec::new(),
            handshake: mirage_core::config::HandshakeStrategy::Telescopic,
            reply: mirage_core::config::ReplyMode::Onion,
            protocol: mirage_core::mirage::wire::ProtocolId::Tcp(
                mirage_core::mirage::wire::TcpProtocolId::Mirage,
            ),
            priority: 0,
            shaping: Default::default(),
            camouflage: Default::default(),
            cover_traffic: Default::default(),
            socks5_bind: None,
            aead_suite: mirage_core::crypto::AeadSuite::ChaCha20Poly1305,
            kill_switch: None,
            group: None,
            nature: None,
        }
    }

    fn held(chain_id: &str, monitor_id: &str, built_at_ms: u64, expires_at_ms: u64) -> HeldChain {
        HeldChain {
            chain_id: chain_id.to_string(),
            config: sample_chain_config(chain_id),
            monitor_id: monitor_id.to_string(),
            built_at_ms,
            expires_at_ms,
            consecutive_dial_failures: 0,
        }
    }

    // ── chain_needs_rebuild ──────────────────────────────────────────────

    #[test]
    fn a_chain_well_inside_its_ttl_does_not_need_rebuild() {
        let expires = 3_600_000u64;
        assert!(!chain_needs_rebuild(1000, 0, expires));
    }

    #[test]
    fn a_chain_past_expiry_needs_rebuild() {
        assert!(chain_needs_rebuild(10_000, 0, 9_999));
        assert!(chain_needs_rebuild(10_000, 0, 10_000));
    }

    #[test]
    fn a_chain_inside_the_lead_fraction_window_needs_rebuild() {
        let built_at_ms = 0u64;
        let expires_at_ms = 3_600_000u64; // 1h TTL for round numbers
        let just_inside = expires_at_ms - (19 * 60 * 1000); // 19 min left
        let just_outside = expires_at_ms - (21 * 60 * 1000); // 21 min left
        assert!(chain_needs_rebuild(just_inside, built_at_ms, expires_at_ms));
        assert!(!chain_needs_rebuild(just_outside, built_at_ms, expires_at_ms));
    }

    // ── chains_to_build ──────────────────────────────────────────────────

    #[test]
    fn zero_held_chains_requests_the_full_minimum() {
        assert_eq!(chains_to_build(0, &[], MIN_CHAIN_COUNT), MIN_CHAIN_COUNT);
    }

    #[test]
    fn enough_live_chains_requests_none() {
        let chains = vec![
            held("a", "mon-1", 0, 3_600_000),
            held("b", "mon-2", 0, 3_600_000),
        ];
        assert_eq!(chains_to_build(1000, &chains, MIN_CHAIN_COUNT), 0);
    }

    #[test]
    fn a_due_for_rebuild_chain_is_not_counted_as_live() {
        let chains = vec![held("a", "mon-1", 0, 100)]; // already expired at now=1000
        assert_eq!(chains_to_build(1000, &chains, MIN_CHAIN_COUNT), MIN_CHAIN_COUNT);
    }

    #[test]
    fn a_failure_tripped_chain_is_not_counted_as_live() {
        let mut chain = held("a", "mon-1", 0, 3_600_000);
        chain.consecutive_dial_failures = CONSECUTIVE_FAILURE_REBUILD_THRESHOLD;
        let chains = vec![chain, held("b", "mon-2", 0, 3_600_000)];
        // Only "b" counts as live -> one more needed to reach MIN_CHAIN_COUNT=2.
        assert_eq!(chains_to_build(1000, &chains, MIN_CHAIN_COUNT), 1);
    }

    #[test]
    fn a_chain_just_under_the_failure_threshold_still_counts_as_live() {
        let mut chain = held("a", "mon-1", 0, 3_600_000);
        chain.consecutive_dial_failures = CONSECUTIVE_FAILURE_REBUILD_THRESHOLD - 1;
        let chains = vec![chain, held("b", "mon-2", 0, 3_600_000)];
        assert_eq!(chains_to_build(1000, &chains, MIN_CHAIN_COUNT), 0);
    }

    // ── choose_monitor ───────────────────────────────────────────────────

    #[test]
    fn choose_monitor_picks_the_least_loaded() {
        let monitors = vec!["mon-1".to_string(), "mon-2".to_string(), "mon-3".to_string()];
        let chains = vec![held("a", "mon-1", 0, 1), held("b", "mon-1", 0, 1)];
        assert_eq!(choose_monitor(&monitors, &chains), Some("mon-2"));
    }

    #[test]
    fn choose_monitor_spreads_across_an_empty_pool() {
        let monitors = vec!["mon-1".to_string(), "mon-2".to_string()];
        assert_eq!(choose_monitor(&monitors, &[]), Some("mon-1"));
    }

    #[test]
    fn choose_monitor_with_no_monitors_returns_none() {
        assert_eq!(choose_monitor(&[], &[]), None);
    }

    #[test]
    fn choose_monitor_falls_back_to_round_robin_once_every_monitor_is_used() {
        let monitors = vec!["mon-1".to_string(), "mon-2".to_string()];
        let chains = vec![held("a", "mon-1", 0, 1), held("b", "mon-2", 0, 1)];
        // Tied at one chain each -- ties break on `monitors`' own order.
        assert_eq!(choose_monitor(&monitors, &chains), Some("mon-1"));
    }

    // ── HeldChainStore: demand / idle lifecycle ──────────────────────────

    #[tokio::test]
    async fn a_pool_with_no_demand_yet_holds_nothing() {
        let store = HeldChainStore::new();
        assert!(store.held_chains(&ExitChoice::Auto).await.is_empty());
    }

    #[tokio::test]
    async fn record_demand_starts_an_empty_pool() {
        let store = HeldChainStore::new();
        store.record_demand(ExitChoice::Auto, 1000).await;
        assert_eq!(store.demanded_exits().await, vec![ExitChoice::Auto]);
        assert!(store.held_chains(&ExitChoice::Auto).await.is_empty());
    }

    #[tokio::test]
    async fn drop_idle_pools_drops_only_what_has_been_idle_long_enough() {
        let store = HeldChainStore::new();
        store.record_demand(ExitChoice::Auto, 0).await;
        store.record_demand(ExitChoice::Country("de".to_string()), 900_000).await;

        let dropped = store.drop_idle_pools(1_000_000, 500_000).await;
        assert_eq!(dropped, vec![ExitChoice::Auto]);
        assert_eq!(store.demanded_exits().await, vec![ExitChoice::Country("de".to_string())]);
    }

    #[tokio::test]
    async fn drop_idle_pools_keeps_a_pool_that_still_holds_a_live_chain() {
        let store = HeldChainStore::new();
        store.record_demand(ExitChoice::Auto, 0).await;
        {
            let mut pools = store.pools.lock().await;
            pools.get_mut(&ExitChoice::Auto).unwrap().chains.push(held("a", "mon-1", 0, 3_600_000));
        }

        // The demand clock says idle, but a subscriber session is still
        // streaming over this chain. Dropping the pool here is the blackout
        // of 2026-10-21 -- the chain was healthy and its TTL is 6 hours.
        let dropped = store.drop_idle_pools(1_000_000, 500_000).await;
        assert!(dropped.is_empty(), "a pool holding a live chain must not be dropped");
        assert_eq!(store.held_chains(&ExitChoice::Auto).await.len(), 1);
        assert_eq!(store.demanded_exits().await, vec![ExitChoice::Auto]);
    }

    #[tokio::test]
    async fn drop_idle_pools_prunes_dead_chains_and_keeps_the_pool() {
        let store = HeldChainStore::new();
        store.record_demand(ExitChoice::Auto, 0).await;
        {
            let mut pools = store.pools.lock().await;
            let pool = pools.get_mut(&ExitChoice::Auto).unwrap();
            pool.chains.push(held("stale", "mon-1", 0, 100));
            pool.chains.push(held("live", "mon-1", 0, 3_600_000));
        }

        let dropped = store.drop_idle_pools(1_000_000, 500_000).await;
        assert!(dropped.is_empty(), "the live chain still holds the pool open");
        let chains = store.held_chains(&ExitChoice::Auto).await;
        assert_eq!(chains.len(), 1, "the expired chain must be pruned");
        assert_eq!(chains[0].chain_id, "live");
    }

    #[tokio::test]
    async fn drop_idle_pools_drops_the_pool_once_no_live_chain_remains() {
        let store = HeldChainStore::new();
        store.record_demand(ExitChoice::Auto, 0).await;
        {
            let mut pools = store.pools.lock().await;
            pools.get_mut(&ExitChoice::Auto).unwrap().chains.push(held("stale", "mon-1", 0, 100));
        }

        // Real idleness: nothing live left, so the pool (and its chains) go.
        let dropped = store.drop_idle_pools(1_000_000, 500_000).await;
        assert_eq!(dropped, vec![ExitChoice::Auto]);
        assert!(store.held_chains(&ExitChoice::Auto).await.is_empty());
        assert!(store.demanded_exits().await.is_empty());
    }

    #[tokio::test]
    async fn record_demand_refreshes_the_idle_clock() {
        let store = HeldChainStore::new();
        store.record_demand(ExitChoice::Auto, 0).await;
        store.record_demand(ExitChoice::Auto, 900_000).await;

        let dropped = store.drop_idle_pools(1_000_000, 500_000).await;
        assert!(dropped.is_empty());
    }

    // ── HeldChainStore: dial failure/success bookkeeping ─────────────────

    #[tokio::test]
    async fn dial_failures_accumulate_and_success_resets_them() {
        let store = HeldChainStore::new();
        store.record_demand(ExitChoice::Auto, 0).await;
        {
            let mut pools = store.pools.lock().await;
            pools.get_mut(&ExitChoice::Auto).unwrap().chains.push(held("a", "mon-1", 0, 3_600_000));
        }

        store.record_dial_failure(&ExitChoice::Auto, "a").await;
        store.record_dial_failure(&ExitChoice::Auto, "a").await;
        let chains = store.held_chains(&ExitChoice::Auto).await;
        assert_eq!(chains[0].consecutive_dial_failures, 2);

        store.record_dial_success(&ExitChoice::Auto, "a").await;
        let chains = store.held_chains(&ExitChoice::Auto).await;
        assert_eq!(chains[0].consecutive_dial_failures, 0);
    }

    #[tokio::test]
    async fn recording_a_failure_for_an_unknown_chain_is_a_no_op() {
        let store = HeldChainStore::new();
        store.record_demand(ExitChoice::Auto, 0).await;
        store.record_dial_failure(&ExitChoice::Auto, "does-not-exist").await;
        assert!(store.held_chains(&ExitChoice::Auto).await.is_empty());
    }

    // ── HeldChainStore::reconcile, with a test double ChainSource ────────

    struct TestSource {
        next_expires_at_ms: u64,
        fail_after: Option<usize>,
        calls: std::sync::atomic::AtomicUsize,
    }

    impl TestSource {
        fn always_succeeds(next_expires_at_ms: u64) -> Self {
            Self { next_expires_at_ms, fail_after: None, calls: std::sync::atomic::AtomicUsize::new(0) }
        }
    }

    #[async_trait::async_trait]
    impl ChainSource for TestSource {
        async fn request_chain(
            &self,
            _exit: &ExitChoice,
            monitor_id: &str,
            now_ms: u64,
        ) -> Result<HeldChain, ChainSourceError> {
            let call = self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if let Some(fail_after) = self.fail_after {
                if call >= fail_after {
                    return Err(ChainSourceError::Refused {
                        monitor_id: monitor_id.to_string(),
                        reason: "test double: out of chains".to_string(),
                    });
                }
            }
            Ok(HeldChain {
                chain_id: format!("chain-{call}"),
                config: sample_chain_config(&format!("chain-{call}")),
                monitor_id: monitor_id.to_string(),
                built_at_ms: now_ms,
                expires_at_ms: self.next_expires_at_ms,
                consecutive_dial_failures: 0,
            })
        }
    }

    #[tokio::test]
    async fn reconcile_builds_up_to_the_minimum_spread_across_monitors() {
        let store = HeldChainStore::new();
        store.record_demand(ExitChoice::Auto, 0).await;
        let monitors = vec!["mon-1".to_string(), "mon-2".to_string()];
        let source = TestSource::always_succeeds(3_600_000);

        let report = store.reconcile(0, &monitors, MIN_CHAIN_COUNT, &source).await;
        assert_eq!(report.built, MIN_CHAIN_COUNT);
        assert!(report.failed.is_empty());

        let chains = store.held_chains(&ExitChoice::Auto).await;
        assert_eq!(chains.len(), MIN_CHAIN_COUNT);
        let monitors_used: std::collections::HashSet<&str> =
            chains.iter().map(|c| c.monitor_id.as_str()).collect();
        assert_eq!(monitors_used.len(), 2, "chains must spread across both monitors");
    }

    #[tokio::test]
    async fn reconcile_is_a_no_op_once_the_minimum_is_already_held() {
        let store = HeldChainStore::new();
        store.record_demand(ExitChoice::Auto, 0).await;
        let monitors = vec!["mon-1".to_string()];
        let source = TestSource::always_succeeds(3_600_000);
        store.reconcile(0, &monitors, MIN_CHAIN_COUNT, &source).await;

        let report = store.reconcile(1000, &monitors, MIN_CHAIN_COUNT, &source).await;
        assert_eq!(report.built, 0);
    }

    #[tokio::test]
    async fn reconcile_retires_a_rebuilt_chain_only_once_a_replacement_landed() {
        let store = HeldChainStore::new();
        store.record_demand(ExitChoice::Auto, 0).await;
        {
            let mut pools = store.pools.lock().await;
            // Already expired -- due for rebuild.
            pools.get_mut(&ExitChoice::Auto).unwrap().chains.push(held("stale", "mon-1", 0, 100));
        }
        let monitors = vec!["mon-1".to_string()];
        let source = TestSource::always_succeeds(3_600_000);

        let report = store.reconcile(1000, &monitors, MIN_CHAIN_COUNT, &source).await;
        assert_eq!(report.built, MIN_CHAIN_COUNT);

        let chains = store.held_chains(&ExitChoice::Auto).await;
        assert!(chains.iter().all(|c| c.chain_id != "stale"), "the expired chain must be retired");
        assert_eq!(chains.len(), MIN_CHAIN_COUNT);
    }

    #[tokio::test]
    async fn reconcile_keeps_a_due_chain_when_no_replacement_could_be_built() {
        let store = HeldChainStore::new();
        store.record_demand(ExitChoice::Auto, 0).await;
        {
            let mut pools = store.pools.lock().await;
            pools.get_mut(&ExitChoice::Auto).unwrap().chains.push(held("stale", "mon-1", 0, 100));
        }
        let monitors = vec!["mon-1".to_string()];
        let source = TestSource {
            next_expires_at_ms: 3_600_000,
            fail_after: Some(0),
            calls: std::sync::atomic::AtomicUsize::new(0),
        };

        let report = store.reconcile(1000, &monitors, MIN_CHAIN_COUNT, &source).await;
        assert_eq!(report.built, 0);
        assert_eq!(report.failed.len(), MIN_CHAIN_COUNT);

        let chains = store.held_chains(&ExitChoice::Auto).await;
        assert!(
            chains.iter().any(|c| c.chain_id == "stale"),
            "a due-for-rebuild chain must not be dropped speculatively when nothing replaced it"
        );
    }

    #[tokio::test]
    async fn reconcile_with_no_monitor_roster_builds_nothing() {
        let store = HeldChainStore::new();
        store.record_demand(ExitChoice::Auto, 0).await;
        let source = TestSource::always_succeeds(3_600_000);

        let report = store.reconcile(0, &[], MIN_CHAIN_COUNT, &source).await;
        assert_eq!(report.built, 0);
        assert!(report.failed.is_empty());
    }
}

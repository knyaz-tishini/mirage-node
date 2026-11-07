//! Pre-warmed upstream tunnel pool for relay-mode nodes.
//!
//! Each [`UpstreamPool`] maintains `pool_size` live tunnels to a single
//! upstream L2 node.  When a relay connection arrives the handler leases one
//! tunnel from the pool; when the connection closes the tunnel is returned
//! (or discarded if the connection errored).
//!
//! A background task replenishes the pool whenever a slot falls below the
//! target size, using exponential backoff on consecutive failures.
//!
//! The background task holds a [`Weak`] reference to the pool so that when all
//! external `Arc<UpstreamPool>` references are dropped (e.g. after a hot-swap
//! removes this upstream from the runtime snapshot) the pool is freed promptly
//! rather than kept alive by the background task.

use std::net::SocketAddr;
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};

use mirage_core::config::CamouflageMode;
use mirage_core::error::MirageError;
use mirage_protocol::traits::{TcpProtocol, Tunnel};
use tokio::sync::Mutex;
use tracing::{debug, warn};

use crate::family::mirage::relay::relay_metrics::UpstreamMetrics;

/// A single slot in the pool: a live tunnel together with the instant it was
/// placed into the pool, or `None` while the slot is being replenished.
struct Slot {
    tunnel: Box<dyn Tunnel>,
    /// When this tunnel was inserted into the pool (used for TTL checks).
    inserted_at: Instant,
}

impl Slot {
    fn new(tunnel: Box<dyn Tunnel>) -> Self {
        Self {
            tunnel,
            inserted_at: Instant::now(),
        }
    }
}

/// Pre-warmed pool of tunnels to one upstream node.
pub struct UpstreamPool {
    upstream_addr: SocketAddr,
    upstream_pubkey: [u8; 32],
    /// Slots guarded by a tokio Mutex so they can be held across `.await`.
    slots: Arc<Mutex<Vec<Option<Slot>>>>,
    target_size: usize,
    /// Maximum time a tunnel may sit idle in the pool before being discarded
    /// on lease.  Default: 90 seconds.
    max_idle: Duration,
    protocol: Arc<dyn TcpProtocol>,
    metrics: Arc<UpstreamMetrics>,
}

impl UpstreamPool {
    /// Create a new pool and spawn a background replenishment task.
    ///
    /// The pool is initially empty; the background task fills it on the first
    /// tick (within milliseconds of creation).
    ///
    /// The background task holds a [`Weak`] reference to the pool.  When the
    /// last external `Arc<UpstreamPool>` is dropped the task exits on its next
    /// wake-up, allowing clean shutdown after a hot-swap.
    ///
    /// `max_idle_secs` controls how long a tunnel may sit in the pool before
    /// being considered stale.  Use 0 for no limit (not recommended with QUIC).
    /// A sensible default is 90 seconds.
    pub fn new(
        upstream_addr: SocketAddr,
        upstream_pubkey: [u8; 32],
        target_size: usize,
        max_idle_secs: u64,
        protocol: Arc<dyn TcpProtocol>,
        metrics: Arc<UpstreamMetrics>,
    ) -> Arc<Self> {
        let max_idle = if max_idle_secs == 0 {
            Duration::MAX
        } else {
            Duration::from_secs(max_idle_secs)
        };
        let pool = Arc::new(Self {
            upstream_addr,
            upstream_pubkey,
            slots: Arc::new(Mutex::new(Vec::new())),
            target_size,
            max_idle,
            protocol,
            metrics,
        });

        // Hold only a Weak ref so the background task does not prevent the
        // pool from being dropped when it is removed from a runtime snapshot.
        let pool_weak: Weak<Self> = Arc::downgrade(&pool);
        tokio::spawn(async move {
            replenish_loop(pool_weak).await;
        });

        pool
    }

    /// The remote address this pool connects to.
    pub fn upstream_addr(&self) -> SocketAddr {
        self.upstream_addr
    }

    /// The expected public key of the upstream node (raw 32 bytes).
    pub fn upstream_pubkey(&self) -> &[u8; 32] {
        &self.upstream_pubkey
    }

    /// Lease one tunnel from the pool.
    ///
    /// If a ready tunnel is available it is removed from the pool and returned
    /// immediately (zero handshake cost).  If the pool is empty a fresh tunnel
    /// is established synchronously (fallback — rare after warm-up).
    ///
    /// Stale tunnels (idle in the pool longer than `max_idle_secs`) are
    /// discarded rather than leased — a QUIC connection silent for too long
    /// is likely dead and would fail immediately on first use.  The background
    /// replenishment task will refill the slot automatically.
    pub async fn lease(&self) -> Result<Box<dyn Tunnel>, MirageError> {
        {
            let mut slots = self.slots.lock().await;
            // Take the last non-None slot (LIFO keeps recently-used tunnels warm).
            // Skip — and discard — any slot that has been idle past the TTL.
            let mut i = slots.len();
            while i > 0 {
                i -= 1;
                if let Some(slot) = slots[i].take() {
                    if slot.inserted_at.elapsed() >= self.max_idle {
                        // Stale — drop the tunnel, leave the slot as None so
                        // the replenishment loop refills it.
                        warn!(
                            addr = %self.upstream_addr,
                            idle_secs = slot.inserted_at.elapsed().as_secs(),
                            "pool: discarding stale tunnel (TTL exceeded)"
                        );
                        // slot is dropped here, tunnel is closed.
                        continue;
                    }
                    // Fresh tunnel — take it.
                    slots.remove(i);
                    debug!(
                        addr = %self.upstream_addr,
                        remaining = slots.len(),
                        "pool: leased tunnel"
                    );
                    return Ok(slot.tunnel);
                }
            }
        }

        // Pool exhausted (all slots None or all stale) — connect on demand.
        debug!(addr = %self.upstream_addr, "pool: empty, connecting on-demand");
        self.metrics.record_reconnect();
        self.connect_fresh().await
    }

    async fn connect_fresh(&self) -> Result<Box<dyn Tunnel>, MirageError> {
        self.protocol
            .connect(
                self.upstream_addr,
                &self.upstream_pubkey,
                "",
                CamouflageMode::Raw,
            )
            .await
            .map_err(|e| MirageError::NodeUnreachable(format!("{}: {e}", self.upstream_addr)))
    }
}

/// Background loop that keeps a pool at `target_size`.
///
/// Accepts a [`Weak`] reference so the task exits automatically when the last
/// strong reference to the pool is dropped (e.g. after a runtime hot-swap
/// removes this upstream from the active snapshot).
async fn replenish_loop(pool_weak: Weak<UpstreamPool>) {
    let mut backoff_ms: u64 = 200;
    loop {
        // Upgrade to a strong ref.  If the pool has been dropped, exit.
        let Some(pool) = pool_weak.upgrade() else {
            debug!("pool: replenish_loop exiting — pool dropped");
            return;
        };

        let current_size = {
            let slots = pool.slots.lock().await;
            slots.iter().filter(|s| s.is_some()).count()
        };

        if current_size < pool.target_size {
            let needed = pool.target_size - current_size;
            debug!(
                addr = %pool.upstream_addr,
                needed,
                "pool: replenishing"
            );

            let mut added = 0usize;
            for _ in 0..needed {
                match pool.connect_fresh().await {
                    Ok(tunnel) => {
                        let mut slots = pool.slots.lock().await;
                        slots.push(Some(Slot::new(tunnel)));
                        added += 1;
                    }
                    Err(e) => {
                        warn!(
                            addr = %pool.upstream_addr,
                            error = %e,
                            "pool: replenishment connect failed"
                        );
                        pool.metrics.record_reconnect();
                        break;
                    }
                }
            }

            // Release the strong Arc ref before sleeping so the pool can be
            // dropped if it was removed from the snapshot during this iteration.
            drop(pool);

            if added < needed {
                // Back off on repeated failures.
                tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
                backoff_ms = (backoff_ms * 2).min(30_000);
            } else {
                backoff_ms = 200;
            }
        } else {
            // Pool is healthy — release Arc ref and check again after a short sleep.
            drop(pool);
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }
}

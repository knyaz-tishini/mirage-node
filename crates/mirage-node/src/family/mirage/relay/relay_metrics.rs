use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;

/// Per-upstream connection counters.
pub struct UpstreamMetrics {
    /// Address of the upstream node these metrics belong to.
    pub addr: SocketAddr,
    /// Number of connections currently active toward this upstream.
    pub active_connections: Arc<AtomicU32>,
    /// Total connections ever established toward this upstream (for logging).
    pub total_connections: Arc<AtomicU64>,
    /// Number of times connecting to this upstream failed / required a reconnect.
    pub reconnect_count: Arc<AtomicU64>,
}

impl UpstreamMetrics {
    pub fn new(addr: SocketAddr) -> Self {
        Self {
            addr,
            active_connections: Arc::new(AtomicU32::new(0)),
            total_connections: Arc::new(AtomicU64::new(0)),
            reconnect_count: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Increment active connection count and total connection count atomically.
    pub fn on_connect(&self) {
        self.active_connections.fetch_add(1, Ordering::Relaxed);
        self.total_connections.fetch_add(1, Ordering::Relaxed);
    }

    /// Decrement active connection count.
    pub fn on_disconnect(&self) {
        self.active_connections.fetch_sub(1, Ordering::Relaxed);
    }

    /// Record a reconnect event (failed connection or pool replenishment).
    pub fn record_reconnect(&self) {
        self.reconnect_count.fetch_add(1, Ordering::Relaxed);
    }
}

/// Aggregated relay metrics across all upstreams.
pub struct RelayMetrics {
    pub upstreams: Vec<Arc<UpstreamMetrics>>,
}

impl RelayMetrics {
    /// Create one metrics slot per upstream address.
    pub fn new(addrs: &[SocketAddr]) -> Self {
        Self {
            upstreams: addrs
                .iter()
                .map(|a| Arc::new(UpstreamMetrics::new(*a)))
                .collect(),
        }
    }

    /// Find metrics for a specific upstream address.
    pub fn for_addr(&self, addr: SocketAddr) -> Option<Arc<UpstreamMetrics>> {
        self.upstreams
            .iter()
            .find(|m| m.addr == addr)
            .cloned()
    }

    /// Return the upstream with the fewest active connections.
    ///
    /// Returns `None` when the upstream list is empty.
    pub fn least_loaded(&self) -> Option<Arc<UpstreamMetrics>> {
        self.upstreams
            .iter()
            .min_by_key(|m| m.active_connections.load(Ordering::Relaxed))
            .cloned()
    }
}

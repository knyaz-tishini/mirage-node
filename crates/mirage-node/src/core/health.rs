use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Instant;

/// Tracks live health metrics for this node.
pub struct HealthReporter {
    node_id: String,
    start_time: Instant,
    pub active_tunnels: Arc<AtomicU32>,
}

/// A point-in-time snapshot of node health.
#[derive(Debug)]
pub struct NodeHealth {
    pub node_id: String,
    pub uptime_secs: u64,
    pub active_tunnels: u32,
}

impl HealthReporter {
    /// Create a new reporter with zero active tunnels.
    pub fn new(node_id: String) -> Self {
        Self {
            node_id,
            start_time: Instant::now(),
            active_tunnels: Arc::new(AtomicU32::new(0)),
        }
    }

    /// Return a shared handle to the active tunnel counter so connection
    /// handlers can increment / decrement it without holding the reporter.
    pub fn tunnel_counter(&self) -> Arc<AtomicU32> {
        Arc::clone(&self.active_tunnels)
    }

    /// Capture a point-in-time snapshot of current health metrics.
    pub fn snapshot(&self) -> NodeHealth {
        NodeHealth {
            node_id: self.node_id.clone(),
            uptime_secs: self.start_time.elapsed().as_secs(),
            active_tunnels: self.active_tunnels.load(Ordering::Relaxed),
        }
    }
}

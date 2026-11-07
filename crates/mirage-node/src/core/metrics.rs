//! In-process metrics registry. Exposed via HTTP on the management port.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

/// Count of peer_table broadcast frames dropped because their generation
/// was less than or equal to the current generation already stored.
///
/// Increments when a `MonitorFrame::PushPeerTable` arrives with a stale
/// generation (incoming < current). Visible in `GET /admin/health`.
pub static PEER_TABLE_STALE_DROPS: AtomicU64 = AtomicU64::new(0);

use serde::Serialize;

/// Per-endpoint metrics.
#[derive(Debug, Default)]
pub struct EndpointMetrics {
    pub active_connections: AtomicU64,
    pub total_connections: AtomicU64,
    pub bytes_in: AtomicU64,
    pub bytes_out: AtomicU64,
    pub errors: AtomicU64,
}

/// Onion-circuit metrics.
#[derive(Debug, Default)]
pub struct OnionMetrics {
    pub active_circuits: AtomicU64,
    pub total_circuits: AtomicU64,
    pub circuit_fails: AtomicU64,
    /// For avg = cumulative / total_circuits
    pub cumulative_handshake_ms: AtomicU64,
}

/// Probe-resist metrics.
#[derive(Debug, Default)]
pub struct ProbeResistMetrics {
    pub invalid_handshakes_dropped: AtomicU64,
    pub fallback_forwarded: AtomicU64,
    pub decoy_triggered: AtomicU64,
}

/// Top-level metrics registry, shared across listeners/handlers.
#[derive(Debug, Default)]
pub struct MetricsRegistry {
    /// Keyed by "mode:listen_addr" string (e.g. "onion_peel:0.0.0.0:4500").
    endpoints: RwLock<HashMap<String, Arc<EndpointMetrics>>>,
    pub onion: OnionMetrics,
    pub probe_resist: ProbeResistMetrics,
}

impl MetricsRegistry {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Get or create endpoint metrics for a given key.
    pub fn endpoint(&self, key: &str) -> Arc<EndpointMetrics> {
        {
            let r = self.endpoints.read().unwrap();
            if let Some(em) = r.get(key) {
                return Arc::clone(em);
            }
        }
        let mut w = self.endpoints.write().unwrap();
        w.entry(key.to_owned())
            .or_insert_with(|| Arc::new(EndpointMetrics::default()))
            .clone()
    }

    /// Snapshot for HTTP export.
    pub fn snapshot(&self) -> MetricsSnapshot {
        let endpoints = self.endpoints.read().unwrap();
        let endpoint_snaps: Vec<EndpointSnapshot> = endpoints
            .iter()
            .map(|(k, em)| EndpointSnapshot {
                key: k.clone(),
                active_connections: em.active_connections.load(Ordering::Relaxed),
                total_connections: em.total_connections.load(Ordering::Relaxed),
                bytes_in: em.bytes_in.load(Ordering::Relaxed),
                bytes_out: em.bytes_out.load(Ordering::Relaxed),
                errors: em.errors.load(Ordering::Relaxed),
            })
            .collect();

        MetricsSnapshot {
            endpoints: endpoint_snaps,
            onion: OnionSnapshot {
                active_circuits: self.onion.active_circuits.load(Ordering::Relaxed),
                total_circuits: self.onion.total_circuits.load(Ordering::Relaxed),
                circuit_fails: self.onion.circuit_fails.load(Ordering::Relaxed),
                cumulative_handshake_ms: self
                    .onion
                    .cumulative_handshake_ms
                    .load(Ordering::Relaxed),
            },
            probe_resist: ProbeResistSnapshot {
                invalid_handshakes_dropped: self
                    .probe_resist
                    .invalid_handshakes_dropped
                    .load(Ordering::Relaxed),
                fallback_forwarded: self.probe_resist.fallback_forwarded.load(Ordering::Relaxed),
                decoy_triggered: self.probe_resist.decoy_triggered.load(Ordering::Relaxed),
            },
        }
    }
}

#[derive(Debug, Serialize)]
pub struct MetricsSnapshot {
    pub endpoints: Vec<EndpointSnapshot>,
    pub onion: OnionSnapshot,
    pub probe_resist: ProbeResistSnapshot,
}

#[derive(Debug, Serialize)]
pub struct EndpointSnapshot {
    pub key: String,
    pub active_connections: u64,
    pub total_connections: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub errors: u64,
}

#[derive(Debug, Serialize)]
pub struct OnionSnapshot {
    pub active_circuits: u64,
    pub total_circuits: u64,
    pub circuit_fails: u64,
    pub cumulative_handshake_ms: u64,
}

#[derive(Debug, Serialize)]
pub struct ProbeResistSnapshot {
    pub invalid_handshakes_dropped: u64,
    pub fallback_forwarded: u64,
    pub decoy_triggered: u64,
}

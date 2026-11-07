//! Upstream selection helpers — выбор одного upstream'а из списка
//! по `LoadBalanceStrategy`. Не делает никакого crypto / handshake;
//! только индексирует `&[UpstreamNode]`.
//!
//! Используется на пути transparent / crypto_verify где нода
//! форвардит trafic к выбранному upstream'у byte-pump'ом.

use mirage_core::config::{LoadBalanceStrategy, UpstreamNode};

use crate::family::mirage::relay::relay_metrics::RelayMetrics;

/// Choose one upstream from `upstreams` according to `strategy`.
///
/// `counter` is the per-node call counter for round-robin (caller owns it).
/// Returns `None` only when `upstreams` is empty.
pub fn pick_upstream<'a>(
    upstreams: &'a [UpstreamNode],
    strategy: &LoadBalanceStrategy,
    counter: &std::sync::atomic::AtomicUsize,
    metrics: &RelayMetrics,
) -> Option<&'a UpstreamNode> {
    if upstreams.is_empty() {
        return None;
    }

    match strategy {
        LoadBalanceStrategy::RoundRobin => {
            let idx = counter
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                % upstreams.len();
            Some(&upstreams[idx])
        }
        LoadBalanceStrategy::Random => {
            let tick = counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let mut x = (tick as u64).wrapping_add(0x9e3779b97f4a7c15);
            x = (x ^ (x >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
            x = (x ^ (x >> 27)).wrapping_mul(0x94d049bb133111eb);
            x ^= x >> 31;
            Some(&upstreams[(x as usize) % upstreams.len()])
        }
        LoadBalanceStrategy::LeastConnections => {
            if let Some(m) = metrics.least_loaded() {
                upstreams.iter().find(|u| u.addr == m.addr)
            } else {
                Some(&upstreams[0])
            }
        }
    }
}

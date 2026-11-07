//! Registry of currently-admitted subscriber sessions' own expiry
//! deadlines, so `crate::client::entrance` can:
//!
//! - close ITS OWN session the instant its admitted entry's `not_after_ms`
//!   passes, without waiting for the next handshake ([`wait_for_deadline`]);
//! - let a `mirage_subscriber_gate::subscriber_keys::SubscriberKeyStore`
//!   reload retroactively close or extend every LIVE session for a device
//!   whose entry changed, rather than only affecting the next NEW dial
//!   ([`LiveSessionRegistry::recheck_all`]).
//!
//! See `docs/mirage/plans/2026-09-25-subscription-bound-credentials.md`,
//! "Coordinator decision (2026-09-25)": "The edge enforces `not_after_ms`
//! per entry at handshake, and closes a live session the moment its entry
//! expires (a timer, not only at the next handshake)."
//!
//! # One mechanism for both expiry and revocation
//!
//! Each live connection is represented by one `watch::Sender<u64>` carrying
//! that connection's own currently-admitted `not_after_ms`. `0` (or any
//! value at or below `now_ms()`) always reads as "expired right now" — so a
//! natural expiry and an early revocation (the reloaded set no longer
//! admits this device at all) are literally the SAME signal to the
//! connection's own deadline watcher: there is no separate "revoked" flag
//! to keep in sync with "expired". A renewal (the reloaded set's entry
//! carries a LATER `not_after_ms`) is the same channel moving the deadline
//! forward instead.
//!
//! A device can hold more than one live connection at once (more than one
//! app, a reconnect racing the old socket's teardown) — the registry keys
//! by hex device pubkey and holds a `Vec` of entries per key, not a single
//! slot.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use mirage_core::crypto::credential::subscriber_set::EdgeScopeView;
use mirage_subscriber_gate::subscriber_keys::SubscriberKeyStore;
use tokio::sync::{watch, Mutex};

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

/// One live connection's registration — returned by
/// [`LiveSessionRegistry::register`], handed back to
/// [`LiveSessionRegistry::deregister`] when that connection ends, so the
/// registry never grows unbounded across reconnects.
pub struct LiveSessionHandle {
    id: u64,
    device_pubkey_hex: String,
}

struct RegisteredSession {
    id: u64,
    deadline_tx: watch::Sender<u64>,
}

/// See this module's own doc.
#[derive(Default)]
pub struct LiveSessionRegistry {
    next_id: AtomicU64,
    sessions: Mutex<HashMap<String, Vec<RegisteredSession>>>,
}

impl LiveSessionRegistry {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Register one freshly admitted connection. Returns the handle to
    /// [`deregister`](Self::deregister) on connection end, and the
    /// `watch::Receiver` this connection's own deadline task
    /// ([`wait_for_deadline`]) watches.
    pub async fn register(&self, device_pubkey_hex: String, not_after_ms: u64) -> (LiveSessionHandle, watch::Receiver<u64>) {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = watch::channel(not_after_ms);
        let mut sessions = self.sessions.lock().await;
        sessions.entry(device_pubkey_hex.clone()).or_default().push(RegisteredSession { id, deadline_tx: tx });
        (LiveSessionHandle { id, device_pubkey_hex }, rx)
    }

    /// Remove one connection's own registration — called once that
    /// connection's own session loop ends, on every exit path (natural
    /// close, or a deadline-triggered close).
    pub async fn deregister(&self, handle: &LiveSessionHandle) {
        let mut sessions = self.sessions.lock().await;
        if let Some(list) = sessions.get_mut(&handle.device_pubkey_hex) {
            list.retain(|e| e.id != handle.id);
            if list.is_empty() {
                sessions.remove(&handle.device_pubkey_hex);
            }
        }
    }

    /// Recheck every currently-registered device against `store`'s CURRENT
    /// good set — called once per successful `SubscriberKeyStore` hot
    /// reload (`mirage_subscriber_gate::subscriber_keys::spawn_hot_reload`'s
    /// own `on_reload` callback). Extends a renewed device's every live
    /// session's deadline; drives an unadmitted device's every live
    /// session's deadline to `now_ms()` (immediate close on its own next
    /// tick of [`wait_for_deadline`]) without waiting for its natural
    /// expiry.
    pub async fn recheck_all(&self, store: &SubscriberKeyStore, own_scope: &EdgeScopeView) {
        let now = now_ms();
        let sessions = self.sessions.lock().await;
        for (device_pubkey_hex, entries) in sessions.iter() {
            let new_deadline = match store.admit_hex(device_pubkey_hex, now, own_scope) {
                Ok(entry) => entry.not_after_ms,
                Err(_) => now,
            };
            for entry in entries {
                // A watch send only fails when every receiver has already
                // been dropped -- the connection is tearing down through
                // its own path at the same moment; nothing to do here.
                let _ = entry.deadline_tx.send(new_deadline);
            }
        }
    }
}

/// Waits until `deadline_rx`'s current value (`not_after_ms`) is at or
/// before `now_ms()`, recomputing every time
/// [`LiveSessionRegistry::recheck_all`] changes it — a revocation (moved to
/// `now_ms()`) resolves on the very next check; a renewal (moved later)
/// restarts the wait against the new, later value.
pub async fn wait_for_deadline(mut deadline_rx: watch::Receiver<u64>) {
    loop {
        let deadline_ms = *deadline_rx.borrow();
        let now = now_ms();
        if now >= deadline_ms {
            return;
        }
        let remaining = Duration::from_millis(deadline_ms - now);
        tokio::select! {
            _ = tokio::time::sleep(remaining) => {
                // The awaited duration elapsed against the deadline that
                // was current when it was computed -- the deadline has
                // passed. Return directly rather than looping back to
                // recompute against wall-clock `now_ms()` again: under a
                // real clock the two agree anyway, and under a paused
                // (test) clock only `tokio::time::sleep` respects the
                // virtual advance, so re-deriving `remaining` from
                // `now_ms()` a second time would recompute roughly the SAME
                // duration and register a fresh timer that no test
                // advancement was ever meant to satisfy.
                return;
            }
            changed = deadline_rx.changed() => {
                if changed.is_err() {
                    // The sender was dropped -- this connection's own
                    // registration is already gone (deregistered through
                    // its own exit path); nothing left to watch.
                    return;
                }
                // The deadline moved (renewal or revocation) -- loop back
                // and recompute `remaining` against the NEW value.
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use mirage_core::crypto::credential::subscriber_set::{sign, SubscriberScope, SubscriberSetEntry};
    use rand::rngs::OsRng;

    const NOW: u64 = 1_800_000_000_000;

    fn store_with_entry(hex_key: &str, not_after_ms: u64) -> (Arc<SubscriberKeyStore>, SigningKey) {
        let issuer = SigningKey::generate(&mut OsRng);
        let store = SubscriberKeyStore::empty(issuer.verifying_key());
        let entry = SubscriberSetEntry {
            device_pubkey_hex: hex_key.to_string(),
            scope: SubscriberScope::Public,
            not_after_ms,
            subscription_ref: "sub-test".to_string(),
        };
        store.install(sign(vec![entry], NOW, &issuer)).expect("valid set must install");
        (store, issuer)
    }

    // ── register / deregister bookkeeping ────────────────────────────────

    #[tokio::test]
    async fn register_then_deregister_leaves_no_trace() {
        let registry = LiveSessionRegistry::new();
        let (handle, _rx) = registry.register("aa".repeat(32), NOW + 1000).await;
        registry.deregister(&handle).await;

        let sessions = registry.sessions.lock().await;
        assert!(sessions.is_empty(), "a fully deregistered device must leave no empty entry behind");
    }

    #[tokio::test]
    async fn two_live_sessions_for_the_same_device_are_both_tracked() {
        let registry = LiveSessionRegistry::new();
        let key = "bb".repeat(32);
        let (h1, _rx1) = registry.register(key.clone(), NOW + 1000).await;
        let (h2, _rx2) = registry.register(key.clone(), NOW + 1000).await;

        {
            let sessions = registry.sessions.lock().await;
            assert_eq!(sessions.get(&key).map(|v| v.len()), Some(2));
        }

        registry.deregister(&h1).await;
        {
            let sessions = registry.sessions.lock().await;
            assert_eq!(sessions.get(&key).map(|v| v.len()), Some(1));
        }
        registry.deregister(&h2).await;
        assert!(registry.sessions.lock().await.is_empty());
    }

    // ── wait_for_deadline ─────────────────────────────────────────────────

    #[tokio::test(start_paused = true)]
    async fn wait_for_deadline_returns_once_the_deadline_passes() {
        let (_tx, rx) = watch::channel(now_ms() + 100);
        let waiter = tokio::spawn(wait_for_deadline(rx));
        // Let the freshly spawned task run once and register its own sleep
        // timer BEFORE advancing the clock -- advancing time before the
        // timer exists would move the clock past nothing.
        tokio::task::yield_now().await;
        assert!(!waiter.is_finished(), "must still be waiting before the deadline");

        tokio::time::advance(Duration::from_millis(150)).await;
        tokio::time::timeout(Duration::from_secs(1), waiter)
            .await
            .expect("must not hang")
            .expect("task must not panic");
    }

    #[tokio::test(start_paused = true)]
    async fn wait_for_deadline_resolves_immediately_for_an_already_past_deadline() {
        let (_tx, rx) = watch::channel(now_ms());
        tokio::time::timeout(Duration::from_secs(1), wait_for_deadline(rx))
            .await
            .expect("an already-past deadline must resolve immediately");
    }

    #[tokio::test(start_paused = true)]
    async fn a_renewal_extends_the_wait() {
        let (tx, rx) = watch::channel(now_ms() + 100);
        let waiter = tokio::spawn(wait_for_deadline(rx));
        tokio::task::yield_now().await;

        tokio::time::advance(Duration::from_millis(50)).await;
        tx.send(now_ms() + 500).expect("receiver still alive");
        // Let the waiter task observe the change, drop the OLD (100ms)
        // sleep, and register a fresh one against the renewed deadline.
        tokio::task::yield_now().await;

        // The OLD deadline (100ms from the start, i.e. 50ms from here) must
        // NOT end the wait -- it was extended before it ever arrived, and
        // its sleep future was dropped, not merely raced.
        tokio::time::advance(Duration::from_millis(60)).await;
        assert!(!waiter.is_finished(), "a renewal must extend the wait past the original deadline");

        tokio::time::advance(Duration::from_millis(500)).await;
        tokio::time::timeout(Duration::from_secs(1), waiter)
            .await
            .expect("must not hang")
            .expect("task must not panic");
    }

    #[tokio::test(start_paused = true)]
    async fn a_revocation_resolves_the_wait_immediately() {
        let (tx, rx) = watch::channel(now_ms() + 10_000);
        let waiter = tokio::spawn(wait_for_deadline(rx));
        tokio::task::yield_now().await;
        assert!(!waiter.is_finished());

        tx.send(0).expect("receiver still alive");
        tokio::time::timeout(Duration::from_secs(1), waiter)
            .await
            .expect("must not hang")
            .expect("task must not panic");
    }

    // ── recheck_all ───────────────────────────────────────────────────────

    #[tokio::test]
    async fn recheck_all_extends_a_renewed_devices_deadline() {
        let key = "cc".repeat(32);
        let (store, issuer) = store_with_entry(&key, NOW + 1000);
        let registry = LiveSessionRegistry::new();
        let (_handle, mut rx) = registry.register(key.clone(), NOW + 1000).await;

        // Renew: reinstall a set with the SAME device, a LATER not_after_ms.
        let renewed = SubscriberSetEntry {
            device_pubkey_hex: key.clone(),
            scope: SubscriberScope::Public,
            not_after_ms: NOW + 9999,
            subscription_ref: "sub-test".to_string(),
        };
        store.install(sign(vec![renewed], NOW + 1, &issuer)).expect("renewal must install");

        registry.recheck_all(&store, &EdgeScopeView::Public).await;
        rx.changed().await.expect("deadline must have changed");
        assert_eq!(*rx.borrow(), NOW + 9999, "the live session's deadline must extend to the renewed not_after_ms");
    }

    #[tokio::test]
    async fn recheck_all_revokes_a_no_longer_admitted_device() {
        let key = "dd".repeat(32);
        let (store, issuer) = store_with_entry(&key, NOW + 1000);
        let registry = LiveSessionRegistry::new();
        let (_handle, mut rx) = registry.register(key.clone(), NOW + 1000).await;

        // Revoke: reinstall a set that no longer names this device at all.
        let other = SubscriberSetEntry {
            device_pubkey_hex: "ee".repeat(32),
            scope: SubscriberScope::Public,
            not_after_ms: NOW + 1000,
            subscription_ref: "sub-other".to_string(),
        };
        store.install(sign(vec![other], NOW + 1, &issuer)).expect("revocation set must install");

        registry.recheck_all(&store, &EdgeScopeView::Public).await;
        rx.changed().await.expect("deadline must have changed");
        assert!(*rx.borrow() <= now_ms(), "a revoked device's deadline must move to now (or earlier)");
    }

    #[tokio::test]
    async fn recheck_all_is_a_no_op_when_nothing_changed() {
        let key = "ff".repeat(32);
        let (store, _issuer) = store_with_entry(&key, NOW + 1000);
        let registry = LiveSessionRegistry::new();
        let (_handle, rx) = registry.register(key.clone(), NOW + 1000).await;

        registry.recheck_all(&store, &EdgeScopeView::Public).await;
        assert_eq!(*rx.borrow(), NOW + 1000, "an unchanged admission must not move the deadline");
    }
}

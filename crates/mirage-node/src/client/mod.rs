//! The node's client-facing half — how a node talks to a customer directly.
//!
//! # Why this lives in the node
//!
//! The **edge** is fleet machinery: it stands in front of the fleet's nodes so
//! that the fleet itself stays hidden, and it exists to carry a customer's
//! stream INTO the mesh. That is a fleet concern.
//!
//! In OSS there is no edge. There are nodes, and a customer talks to a node
//! **directly**. Everything needed for that conversation is here:
//!
//! * the client entrance — accept, the V9 handshake, the perimeter preamble,
//!   face assignment, the session wire, the mux upgrade;
//! * the held chain store and the demand clock;
//! * the live-session registry (each admitted subscriber's own expiry);
//! * the byte pumps and the UDP-flow caps;
//! * the subscriber admission scope and the subscriber set loader;
//! * this box's own identity anchors.
//!
//! Carrying a customer's stream somewhere ELSE — into the mesh, through a
//! monitor session, with a role-signed credential minted by an operator — is
//! fleet work, and it lives in the `mirage-edge-fleet` crate, which depends on
//! this one and never the other way round.
//!
//! # The seam
//!
//! The entrance needs three things from whoever is on the other side of the
//! session, and it must not name any of them: a way to open a TCP stream to
//! the exit, a way to open a datagram flow, and the list of exit countries
//! this box can serve. Those are the three ports in [`exit_port`]. The
//! standalone box implements them against its own node; the fleet implements
//! them against the mesh.
//!
//! # The module map
//!
//! * [`entrance`] — the client accept loop: the V9 handshake, the session
//!   wire (`EdgeHello`/`EdgeWelcome`), face assignment, the mux upgrade.
//! * [`chain_store`] — the held chains and the demand clock.
//! * [`exit_port`] — the seam: how a stream reaches the exit.
//! * [`live_sessions`] — the admitted subscribers' own expiry deadlines.
//! * [`pump`], [`udp_flow`] — the byte pumps and the UDP-flow caps.
//! * [`bootstrap`], [`capsule_boot`], [`edge_scope`] — this box's own identity
//!   anchors, the identity hand-over and the admission scope.

pub mod bootstrap;
pub mod capsule_boot;
pub mod chain_store;
pub mod edge_scope;
pub mod entrance;
pub mod exit_port;
pub mod live_sessions;
pub mod pump;
pub mod tunnel_io;
pub mod udp_flow;

use std::sync::Arc;

use mirage_core::config::SubscriberEntranceConfig;
use mirage_subscriber_gate::subscriber_keys::SubscriberKeysError;
use thiserror::Error;

/// Why a node could not admit a customer.
#[derive(Debug, Error)]
pub enum ClientError {
    #[error("no usable operator key: {0}")]
    NoOperatorKey(String),
    #[error("no usable subscriber-issuer key: {0}")]
    NoSubscriberIssuerKey(String),
    #[error("could not acquire this box's identity: {0}")]
    Identity(String),
    #[error("this box's role slice: {0}")]
    OwnIdentity(String),
    #[error("capsule carries no edge_scope (public|private): opbox must set it from the box's order tier; refusing to admit anyone")]
    NoEdgeScope,
    #[error("entrance accept loop: {0}")]
    Entrance(#[from] entrance::EntranceError),
}

/// Boot-time load of the subscriber set at `path`, then hot reload for the
/// life of the process.
///
/// The hot-reload task is spawned WHATEVER the initial load returned: a fresh
/// box boots before its first `subscriber_set` push, and the file that is
/// written later must still be picked up. Until a verified set is installed the
/// store stays empty, so nobody is admitted (fail closed). A MISSING file at
/// boot is the normal fresh-box state (WARN); a present file that cannot be
/// parsed or verified is a real fault (ERROR).
pub fn start_subscriber_set(
    store: Arc<mirage_subscriber_gate::subscriber_keys::SubscriberKeyStore>,
    path: std::path::PathBuf,
    poll_interval: std::time::Duration,
    on_reload: Arc<dyn Fn() + Send + Sync>,
) -> tokio::task::JoinHandle<()> {
    use mirage_subscriber_gate::subscriber_keys::{load_subscriber_set_file, spawn_hot_reload};

    match load_subscriber_set_file(&path) {
        Ok(set) => match store.install(set) {
            Ok(()) => {
                tracing::info!(path = %path.display(), "[client] subscriber set loaded and verified");
            }
            Err(e) => {
                tracing::error!(
                    path = %path.display(),
                    error = %e,
                    "[client] subscriber set failed to verify -- every subscriber dial will be refused until a valid set is written"
                );
            }
        },
        Err(SubscriberKeysError::Read { source, .. }) if source.kind() == std::io::ErrorKind::NotFound => {
            tracing::warn!(
                path = %path.display(),
                "[client] no subscriber set yet -- waiting for the first push"
            );
        }
        Err(e) => {
            tracing::error!(
                path = %path.display(),
                error = %e,
                "[client] subscriber set could not be loaded -- every subscriber dial will be refused until a valid set is written"
            );
        }
    }
    spawn_hot_reload(store, path, poll_interval, on_reload)
}

/// The subscriber-set configuration this box falls back to when its capsule
/// names none — a box with no subscriber configuration admits nobody at the
/// bandwidth meter, but still runs.
pub fn default_subscriber_cfg() -> SubscriberEntranceConfig {
    SubscriberEntranceConfig {
        legacy_socks_addr: None,
        aggregate_rate_bytes_per_sec: None,
        aggregate_burst_bytes: None,
        per_connection_rate_bytes_per_sec: None,
        monthly_volume_bytes: None,
        degraded_floor_bytes_per_sec: None,
    }
}

#[cfg(test)]
mod subscriber_boot_tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use mirage_core::crypto::credential::subscriber_set::{sign, SubscriberScope, SubscriberSetEntry};
    use rand::rngs::OsRng;
    use std::time::Duration;

    const NOW: u64 = 1_800_000_000_000;

    fn entry(byte: u8) -> SubscriberSetEntry {
        SubscriberSetEntry {
            device_pubkey_hex: hex::encode([byte; 32]),
            scope: SubscriberScope::Public,
            not_after_ms: NOW + 3_600_000,
            subscription_ref: format!("sub-{byte:02x}"),
        }
    }

    #[tokio::test]
    async fn file_absent_at_boot_then_appears_is_loaded() {
        let signing = SigningKey::generate(&mut OsRng);
        let path = std::env::temp_dir().join(format!("mirage-client-late-set-{}.json", std::process::id()));
        let _ = std::fs::remove_file(&path);

        let store = mirage_subscriber_gate::subscriber_keys::SubscriberKeyStore::empty(signing.verifying_key());
        let handle = start_subscriber_set(Arc::clone(&store), path.clone(), Duration::from_millis(20), Arc::new(|| {}));

        // Fail closed while there is no file.
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(!store.contains(&[0x11; 32]), "no file must admit nobody");

        let set = sign(vec![entry(0x11)], NOW, &signing);
        std::fs::write(&path, set.encode().expect("encode")).expect("write set");

        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while !store.contains(&[0x11; 32]) {
            assert!(std::time::Instant::now() < deadline, "late-appearing set was never loaded");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        handle.abort();
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn invalid_file_at_boot_keeps_watching_and_recovers() {
        let signing = SigningKey::generate(&mut OsRng);
        let path = std::env::temp_dir().join(format!("mirage-client-bad-set-{}.json", std::process::id()));
        std::fs::write(&path, "not json").expect("write garbage");

        let store = mirage_subscriber_gate::subscriber_keys::SubscriberKeyStore::empty(signing.verifying_key());
        let handle = start_subscriber_set(Arc::clone(&store), path.clone(), Duration::from_millis(20), Arc::new(|| {}));
        assert!(!store.contains(&[0x22; 32]));

        tokio::time::sleep(Duration::from_millis(50)).await;
        let set = sign(vec![entry(0x22)], NOW, &signing);
        std::fs::write(&path, set.encode().expect("encode")).expect("write set");

        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while !store.contains(&[0x22; 32]) {
            assert!(std::time::Instant::now() < deadline, "repaired set was never loaded");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        handle.abort();
        let _ = std::fs::remove_file(&path);
    }
}

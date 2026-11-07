//! Node-side admission gate for `CredentialScheme::RoleSigned` — the
//! self-presented, self-vouched credential an Edge box uses to dial into
//! the mesh as the owner of its own onion chains.
//!
//! `mirage_core::crypto::credential::role_signed::verify_role_signed`
//! already does the two-signature cryptographic verification (operator_sig
//! over the identity excerpt, dial_sig over the per-dial context) — see that
//! module's own doc. What it deliberately does NOT check, because it has no
//! way to know either fact, is:
//!
//! 1. **This exit's own mesh.** `operator_pub` is the SAME fleet-wide
//!    constant across every mesh the operator runs — an excerpt honestly
//!    signed for mesh B verifies just as cleanly at a mesh-A exit. Only the
//!    caller (this module) knows which mesh IT is, so the mesh check has to
//!    live here.
//! 2. **Replay across dials.** `verify_role_signed` only bounds `ts_ms` to a
//!    freshness window (`ROLE_SIGNED_TS_WINDOW_MS`); turning "fresh" into
//!    "single-use" is this module's [`RoleSignedReplayCache`].
//!
//! Both this module's checks and `verify_role_signed`'s own checks are
//! surfaced through one named-label enum, [`RoleSignedRefusal`], so every
//! call site logs the SAME kind of thing on rejection: which check failed,
//! for which `self_id`, in which `mesh` — never a generic "credential
//! rejected".
//!
//! See `docs/mirage/plans/2026-09-24-edge-as-entry.md`, "Credentials — the
//! exit admits an edge-owned chain by the edge's own operator-signed
//! identity".

use std::collections::HashMap;
use std::sync::Mutex;

use ed25519_dalek::VerifyingKey;
use thiserror::Error;
use uuid::Uuid;

use mirage_core::crypto::credential::role_signed::{
    verify_role_signed, RoleSignedError, RoleSignedToken, ROLE_SIGNED_TS_WINDOW_MS,
};

/// Safety cap on the number of live (self_id, nonce) entries the replay
/// cache holds at once. Bounded because `check_and_record` evicts anything
/// older than the freshness window on every call — the legitimate live set
/// can never exceed "however many distinct Edge dials land inside one
/// ~120s window" — so this cap is a runaway guard, not a normal ceiling: if
/// it is ever hit, fresh (never-before-seen) tokens are rejected
/// fail-closed rather than admitted unrecorded (which would reopen the
/// replay window this cache exists to close).
pub(crate) const MAX_ROLE_SIGNED_REPLAY_ENTRIES: usize = 65_536;

/// Bounded, TTL-evicted replay cache for `RoleSignedToken`s, keyed by
/// `(self_id, nonce)` — the same edge box (or a different one that happens
/// to mint the same random 16-byte nonce, negligible) never gets to spend
/// one nonce twice.
///
/// Entries are evicted by the token's OWN `ts_ms`, not insertion time: once
/// `now_ms - ts_ms` exceeds [`ROLE_SIGNED_TS_WINDOW_MS`],
/// [`verify_role_signed`] would refuse ANY future presentation of that same
/// `ts_ms` on its own freshness check — so dropping the entry here never
/// reopens a replay window; it only stops holding memory for a token that
/// could never verify again regardless.
#[derive(Debug, Default)]
pub struct RoleSignedReplayCache {
    seen: HashMap<(Uuid, [u8; 16]), u64>,
    cap_warned: bool,
}

impl RoleSignedReplayCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Current number of live entries — test/observability hook.
    #[cfg(test)]
    fn len(&self) -> usize {
        self.seen.len()
    }

    /// Evict everything outside `[now_ms - window_ms, now_ms]`, then record
    /// `(self_id, nonce)`. Returns `true` when the presentation is fresh and
    /// has been recorded, `false` when it is a replay OR the cache is at its
    /// cap (fail-closed — see [`MAX_ROLE_SIGNED_REPLAY_ENTRIES`]).
    pub(crate) fn check_and_record(
        &mut self,
        self_id: Uuid,
        nonce: [u8; 16],
        ts_ms: u64,
        now_ms: u64,
        window_ms: u64,
    ) -> bool {
        let floor = now_ms.saturating_sub(window_ms);
        self.seen.retain(|_, seen_ts| *seen_ts >= floor);
        if self.seen.len() < MAX_ROLE_SIGNED_REPLAY_ENTRIES {
            self.cap_warned = false;
        }

        let key = (self_id, nonce);
        if self.seen.contains_key(&key) {
            return false;
        }
        if self.seen.len() >= MAX_ROLE_SIGNED_REPLAY_ENTRIES {
            if !self.cap_warned {
                self.cap_warned = true;
                tracing::warn!(
                    cap = MAX_ROLE_SIGNED_REPLAY_ENTRIES,
                    "role_signed: replay cache at capacity — rejecting further fresh tokens (fail-closed)"
                );
            }
            return false;
        }
        self.seen.insert(key, ts_ms);
        true
    }
}

/// Every way [`check_role_signed_dial`] can refuse a presented token — one
/// named label per independently reachable, independently testable cause.
/// Every variant that has decoded far enough to know it carries `self_id`
/// and `mesh` — everything past [`Malformed`](Self::Malformed).
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub(crate) enum RoleSignedRefusal {
    /// The wire bytes did not even decode as a `RoleSignedToken` — truncated,
    /// bad UTF-8, an unrecognised role byte. No `self_id` to report: decoding
    /// is what would have produced one.
    #[error("role_signed: token bytes malformed: {0}")]
    Malformed(String),
    /// This exit has no usable operator/group verifying key (un-rendered
    /// build, or a placeholder left in by mistake) — refuses unconditionally
    /// rather than skip the check.
    #[error(
        "role_signed: self_id={self_id} mesh={mesh} this exit has no usable operator key ({reason}) — refusing unconditionally"
    )]
    OperatorKeyUnavailable { self_id: Uuid, mesh: String, reason: String },
    /// The excerpt is for a real mesh, just not THIS one — `operator_pub` is
    /// shared fleet-wide, so this is the only thing that catches a
    /// cross-mesh presentation. See this module's own doc, point 1.
    #[error(
        "role_signed: self_id={self_id} mesh mismatch — token names mesh {token_mesh:?}, this node's mesh is {node_mesh:?}"
    )]
    WrongMesh { self_id: Uuid, token_mesh: String, node_mesh: String },
    /// `mirage_core::crypto::credential::role_signed::verify_role_signed`
    /// itself refused — `source` is one of its own named variants
    /// (`BadOperatorSig`, `ExpiredIdentity`, `WrongRole`,
    /// `WrongExitBinding`, `StaleTimestamp`, `BadDialSig`).
    #[error("role_signed: self_id={self_id} mesh={mesh} rejected: {source}")]
    Verify { self_id: Uuid, mesh: String, #[source] source: RoleSignedError },
    /// This exit holds a gossiped `DeclaredIdentity` for the excerpt's own
    /// `self_id`, and that identity's Edge role signing key does NOT match
    /// `signing_pubkey_hex` — the excerpt's operator signature is valid but
    /// stale relative to a key this exit already knows was rotated.
    #[error(
        "role_signed: self_id={self_id} mesh={mesh} signing_pubkey_hex does not match this node's gossiped DeclaredIdentity for this Edge"
    )]
    IdentityKeyMismatch { self_id: Uuid, mesh: String },
    /// The same `(self_id, nonce)` was already spent inside its own
    /// freshness window — see [`RoleSignedReplayCache`].
    #[error(
        "role_signed: self_id={self_id} mesh={mesh} nonce replay — token already spent inside its own freshness window"
    )]
    Replay { self_id: Uuid, mesh: String },
}

/// Verify a presented `RoleSigned` credential end to end: decode, mesh
/// binding, the two-signature crypto ([`verify_role_signed`]), the optional
/// gossiped-identity cross-check, and single-use replay.
///
/// `operator_pub` is threaded in as an already-computed `Result` (normally
/// `crate::core::bootstrap::operator_pubkey()`) rather than called inside
/// this function so the gate stays pure/testable against a real generated
/// key instead of this source tree's un-rendered placeholder.
///
/// `gossiped_signing_key_for_self_id` looks up the Edge role signing key
/// this exit's own gossiped `DeclaredIdentity` carries for the token's
/// `self_id`, if it holds one — `None` means this exit holds no live copy,
/// which is fine: `verify_role_signed`'s own `operator_sig` check already
/// proves the excerpt was really issued by the operator/group with no
/// dependency on this exit holding gossip state (see
/// `mirage_core::crypto::credential::role_signed`'s own doc). Passing
/// `|_| None` everywhere is honest today — no gossiped-identity registry
/// exists on this crate yet — and is the correct, safe default rather than a
/// crutch: the cross-check only ever turns an accept into a refusal, never
/// the reverse.
///
/// Returns the verified token's `self_id` on success — callers that want it
/// for further bookkeeping have it; callers that don't can ignore it.
pub(crate) fn check_role_signed_dial(
    credential_bytes: &[u8],
    exit_node_id: &str,
    this_mesh_id: &[u8],
    now_ms: u64,
    operator_pub: &Result<VerifyingKey, String>,
    replay: &Mutex<RoleSignedReplayCache>,
    gossiped_signing_key_for_self_id: impl Fn(Uuid) -> Option<String>,
) -> Result<Uuid, RoleSignedRefusal> {
    let token =
        RoleSignedToken::decode(credential_bytes).map_err(|e| RoleSignedRefusal::Malformed(e.to_string()))?;
    let self_id = token.self_id;
    let mesh = token.mesh_id.clone();

    let operator_pub = operator_pub.as_ref().map_err(|reason| RoleSignedRefusal::OperatorKeyUnavailable {
        self_id,
        mesh: mesh.clone(),
        reason: reason.clone(),
    })?;

    if token.mesh_id.as_bytes() != this_mesh_id {
        return Err(RoleSignedRefusal::WrongMesh {
            self_id,
            token_mesh: token.mesh_id.clone(),
            node_mesh: String::from_utf8_lossy(this_mesh_id).into_owned(),
        });
    }

    verify_role_signed(&token, operator_pub, exit_node_id, now_ms)
        .map_err(|source| RoleSignedRefusal::Verify { self_id, mesh: mesh.clone(), source })?;

    if let Some(expected) = gossiped_signing_key_for_self_id(self_id) {
        if expected != token.signing_pubkey_hex {
            return Err(RoleSignedRefusal::IdentityKeyMismatch { self_id, mesh: mesh.clone() });
        }
    }

    let fresh = replay
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .check_and_record(self_id, token.nonce, token.ts_ms, now_ms, ROLE_SIGNED_TS_WINDOW_MS);
    if !fresh {
        return Err(RoleSignedRefusal::Replay { self_id, mesh });
    }

    Ok(self_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use mirage_core::capsule::RoleSlice;
    use mirage_core::crypto::credential::role_signed::{mint_role_signed_token, sign_role_signed_excerpt};
    use mirage_core::identity::ServiceRole;
    use rand::rngs::OsRng;

    const EXIT_A: &str = "exit-node-a";
    const MESH_A: &str = "mesh-a";
    const NOW: u64 = 2_000_000_000_000;

    struct Fixture {
        operator_signing: SigningKey,
        edge_slice: RoleSlice,
        excerpt: mirage_core::crypto::credential::role_signed::RoleSignedIdentityExcerpt,
    }

    fn make_fixture(mesh_id: &str, identity_not_after_ms: u64) -> Fixture {
        let operator_signing = SigningKey::generate(&mut OsRng);
        let edge_signing = SigningKey::generate(&mut OsRng);
        let edge_signing_pub_hex = hex::encode(edge_signing.verifying_key().to_bytes());

        let edge_slice = RoleSlice {
            role: ServiceRole::Edge,
            wire_privkey: [0x11u8; 32],
            signing_privkey: Some(edge_signing.to_bytes()),
            wire_pubkey_hex: "aa".repeat(32),
            signing_pubkey_hex: Some(edge_signing_pub_hex.clone()),
        };

        let excerpt = sign_role_signed_excerpt(
            &operator_signing,
            Uuid::new_v4(),
            mesh_id,
            ServiceRole::Edge,
            &edge_signing_pub_hex,
            identity_not_after_ms,
        )
        .expect("Edge role must be encodable");

        Fixture { operator_signing, edge_slice, excerpt }
    }

    fn valid_wire(fixture: &Fixture) -> Vec<u8> {
        let token = mint_role_signed_token(&fixture.edge_slice, &fixture.excerpt, EXIT_A, NOW)
            .expect("mint must succeed for a matched slice/excerpt pair");
        token.encode().expect("encode must succeed")
    }

    fn ok_operator_pub(fixture: &Fixture) -> Result<VerifyingKey, String> {
        Ok(fixture.operator_signing.verifying_key())
    }

    fn empty_replay() -> Mutex<RoleSignedReplayCache> {
        Mutex::new(RoleSignedReplayCache::new())
    }

    // ── Happy path ───────────────────────────────────────────────────────

    #[test]
    fn a_valid_token_is_admitted() {
        let fixture = make_fixture(MESH_A, NOW + 3_600_000);
        let wire = valid_wire(&fixture);
        let op = ok_operator_pub(&fixture);
        let replay = empty_replay();

        let result =
            check_role_signed_dial(&wire, EXIT_A, MESH_A.as_bytes(), NOW, &op, &replay, |_| None);
        assert_eq!(result, Ok(fixture.excerpt.self_id));
    }

    #[test]
    fn a_valid_token_is_admitted_when_the_gossiped_key_matches() {
        let fixture = make_fixture(MESH_A, NOW + 3_600_000);
        let wire = valid_wire(&fixture);
        let op = ok_operator_pub(&fixture);
        let replay = empty_replay();
        let expected_key = fixture.excerpt.signing_pubkey_hex.clone();

        let result = check_role_signed_dial(&wire, EXIT_A, MESH_A.as_bytes(), NOW, &op, &replay, move |_| {
            Some(expected_key.clone())
        });
        assert_eq!(result, Ok(fixture.excerpt.self_id));
    }

    // ── Named refusals ───────────────────────────────────────────────────

    #[test]
    fn malformed_bytes_are_refused() {
        let op: Result<VerifyingKey, String> = Ok(SigningKey::generate(&mut OsRng).verifying_key());
        let replay = empty_replay();

        let result = check_role_signed_dial(&[0u8; 3], EXIT_A, MESH_A.as_bytes(), NOW, &op, &replay, |_| None);
        assert!(matches!(result, Err(RoleSignedRefusal::Malformed(_))));
    }

    #[test]
    fn unavailable_operator_key_is_refused() {
        let fixture = make_fixture(MESH_A, NOW + 3_600_000);
        let wire = valid_wire(&fixture);
        let op: Result<VerifyingKey, String> = Err("OPERATOR_PUBKEY_HEX is still the placeholder".to_string());
        let replay = empty_replay();

        let result =
            check_role_signed_dial(&wire, EXIT_A, MESH_A.as_bytes(), NOW, &op, &replay, |_| None);
        assert!(matches!(result, Err(RoleSignedRefusal::OperatorKeyUnavailable { .. })));
    }

    #[test]
    fn a_token_for_another_mesh_is_refused() {
        let fixture = make_fixture("mesh-b", NOW + 3_600_000);
        let wire = valid_wire(&fixture);
        let op = ok_operator_pub(&fixture);
        let replay = empty_replay();

        let result =
            check_role_signed_dial(&wire, EXIT_A, MESH_A.as_bytes(), NOW, &op, &replay, |_| None);
        assert!(matches!(result, Err(RoleSignedRefusal::WrongMesh { .. })));
    }

    #[test]
    fn a_mesh_core_rejection_surfaces_as_verify() {
        // Identity already expired relative to NOW — verify_role_signed's own
        // ExpiredIdentity check must fire and be reported as `Verify`.
        let fixture = make_fixture(MESH_A, NOW - 1);
        let wire = valid_wire(&fixture);
        let op = ok_operator_pub(&fixture);
        let replay = empty_replay();

        let result =
            check_role_signed_dial(&wire, EXIT_A, MESH_A.as_bytes(), NOW, &op, &replay, |_| None);
        assert!(matches!(result, Err(RoleSignedRefusal::Verify { .. })));
    }

    #[test]
    fn a_wrong_exit_binding_surfaces_as_verify() {
        let fixture = make_fixture(MESH_A, NOW + 3_600_000);
        let wire = valid_wire(&fixture);
        let op = ok_operator_pub(&fixture);
        let replay = empty_replay();

        // Minted for EXIT_A, verified here as if this exit were EXIT_B.
        let result =
            check_role_signed_dial(&wire, "exit-node-b", MESH_A.as_bytes(), NOW, &op, &replay, |_| None);
        assert!(matches!(result, Err(RoleSignedRefusal::Verify { .. })));
    }

    #[test]
    fn a_gossiped_identity_key_mismatch_is_refused() {
        let fixture = make_fixture(MESH_A, NOW + 3_600_000);
        let wire = valid_wire(&fixture);
        let op = ok_operator_pub(&fixture);
        let replay = empty_replay();

        let result = check_role_signed_dial(&wire, EXIT_A, MESH_A.as_bytes(), NOW, &op, &replay, |_| {
            Some("not-the-real-key".to_string())
        });
        assert!(matches!(result, Err(RoleSignedRefusal::IdentityKeyMismatch { .. })));
    }

    #[test]
    fn a_replayed_token_is_refused_on_its_second_presentation() {
        let fixture = make_fixture(MESH_A, NOW + 3_600_000);
        let wire = valid_wire(&fixture);
        let op = ok_operator_pub(&fixture);
        let replay = empty_replay();

        let first =
            check_role_signed_dial(&wire, EXIT_A, MESH_A.as_bytes(), NOW, &op, &replay, |_| None);
        assert!(first.is_ok(), "first presentation must be admitted");

        let second =
            check_role_signed_dial(&wire, EXIT_A, MESH_A.as_bytes(), NOW, &op, &replay, |_| None);
        assert!(matches!(second, Err(RoleSignedRefusal::Replay { .. })));
    }

    // ── Replay cache eviction ────────────────────────────────────────────

    #[test]
    fn cache_eviction_lets_a_stale_slot_be_reused_and_bounds_memory() {
        let mut cache = RoleSignedReplayCache::new();
        let self_id = Uuid::new_v4();
        let nonce = [0x42u8; 16];

        assert!(cache.check_and_record(self_id, nonce, NOW, NOW, ROLE_SIGNED_TS_WINDOW_MS));
        assert_eq!(cache.len(), 1);

        // Still inside the window: replay is refused, cache does not grow.
        assert!(!cache.check_and_record(self_id, nonce, NOW, NOW, ROLE_SIGNED_TS_WINDOW_MS));
        assert_eq!(cache.len(), 1);

        // Advance past the window: verify_role_signed would independently
        // refuse this ts_ms as stale by now, so evicting it here is safe —
        // the slot becomes reusable and the cache does not grow unbounded.
        let later = NOW + ROLE_SIGNED_TS_WINDOW_MS + 1;
        assert!(cache.check_and_record(self_id, nonce, later, later, ROLE_SIGNED_TS_WINDOW_MS));
        assert_eq!(cache.len(), 1, "the stale entry must have been evicted, not accumulated");
    }

    #[test]
    fn cache_fails_closed_at_capacity() {
        let mut cache = RoleSignedReplayCache::new();
        for i in 0..MAX_ROLE_SIGNED_REPLAY_ENTRIES {
            let mut nonce = [0u8; 16];
            nonce[0..8].copy_from_slice(&(i as u64).to_be_bytes());
            assert!(cache.check_and_record(Uuid::new_v4(), nonce, NOW, NOW, ROLE_SIGNED_TS_WINDOW_MS));
        }
        assert_eq!(cache.len(), MAX_ROLE_SIGNED_REPLAY_ENTRIES);

        // One more, brand new key, at the same `now_ms` (nothing to evict yet).
        let result = cache.check_and_record(Uuid::new_v4(), [0xFFu8; 16], NOW, NOW, ROLE_SIGNED_TS_WINDOW_MS);
        assert!(!result, "a fresh entry must be rejected fail-closed once the cap is reached");
        assert_eq!(cache.len(), MAX_ROLE_SIGNED_REPLAY_ENTRIES, "cap must not be exceeded");
    }
}

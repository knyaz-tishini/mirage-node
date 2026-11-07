//! Fleet-wide public identity anchor — substituted by operator-box's
//! universal build (`POST /universal/build?service=edge`) before compiling
//! the ONE binary shipped to every edge box in the fleet.
//!
//! Mirrors `mirage2sentry/crates/sentry/src/bootstrap.rs` exactly: this
//! binary carries no per-box identity of its own (that lives in the
//! operator/quorum-sealed `mirage_core::capsule::MachineCapsule` the local
//! keeper hands over — see `crate::client::capsule_boot`), only the public anchor
//! needed to verify what the keeper serves.

/// Operator Ed25519 verifying key hex (64 chars) — used to verify the
/// `MachineSlice` the local keeper hands over on boot, and to verify a
/// `RoleSignedToken`'s `operator_sig` at mint/dial time
/// (the fleet's credential module (`mirage-edge-fleet`'s `credential`)).
pub const OPERATOR_PUBKEY_HEX: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

/// Environment variable holding the operator key hex — a LOCAL source for the
/// operator key, used by a box that is not part of the fleet.
///
/// When this variable is set it wins over [`OPERATOR_PUBKEY_HEX`]. When it is
/// not set, nothing changes: the compile-time anchor stays the only key, and
/// the fleet behaves exactly as it did before this variable existed.
pub const OPERATOR_PUBKEY_ENV: &str = "MIRAGE_OPERATOR_PUBKEY_HEX";

/// Environment variable naming a FILE that holds the operator key hex — the
/// file form of [`OPERATOR_PUBKEY_ENV`], for a box that keeps its key on disk
/// rather than in its environment.
///
/// Checked only when [`OPERATOR_PUBKEY_ENV`] is unset. The file's first
/// non-empty line is the key; whitespace inside it is ignored.
pub const OPERATOR_PUBKEY_FILE_ENV: &str = "MIRAGE_OPERATOR_PUBKEY_FILE";

/// Decode [`OPERATOR_PUBKEY_HEX`] into a verifying key.
///
/// Fails loudly (`Err`, never a silent all-zero key) so a binary cut
/// without the fleet's real operator key cannot be talked into accepting a
/// slice — or a credential excerpt — signed by anyone at all.
///
/// # A LOCAL source of the same key
///
/// A box that is not part of the fleet — a standalone box, which owns its
/// identity locally — has no fleet-wide anchor to render at build time. It
/// points this binary at its own operator key through [`OPERATOR_PUBKEY_ENV`]
/// or [`OPERATOR_PUBKEY_FILE_ENV`], and this function then decodes THAT key
/// instead of the constant.
///
/// The default is unchanged: with neither variable set, this is byte-for-byte
/// the function it always was, and a live fleet box is unaffected by the
/// existence of the variables.
pub fn operator_pubkey() -> Result<ed25519_dalek::VerifyingKey, String> {
    if let Some(local_hex) = local_key_hex(OPERATOR_PUBKEY_ENV, OPERATOR_PUBKEY_FILE_ENV)? {
        return decode_local_pubkey(&local_hex, OPERATOR_PUBKEY_ENV);
    }
    decode_pinned_pubkey(OPERATOR_PUBKEY_HEX, "OPERATOR_PUBKEY_HEX")
}

/// Subscriber-issuer Ed25519 verifying key hex (64 chars) — verifies the
/// `SubscriberSet` this box's `subscriber_keys_path` file carries
/// (`mirage_core::crypto::credential::subscriber_set`), signed by opbox's
/// dedicated subscriber-issuer key (never the operator/group key — see
/// `docs/mirage/plans/2026-09-25-subscription-bound-credentials.md`,
/// "Signing key" section, on why this is a separate keypair from
/// [`OPERATOR_PUBKEY_HEX`)]). Baked the same way, by the same
/// `universal_build` step, for the same reason: this binary carries no
/// per-box secret of its own, only the public anchors it needs to verify
/// what it is handed.
pub const SUBSCRIBER_ISSUER_PUBKEY_HEX: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

/// Environment variable holding the subscriber-issuer key hex — a LOCAL
/// source, the same deal as [`OPERATOR_PUBKEY_ENV`] but for the
/// subscriber-issuer key.
pub const SUBSCRIBER_ISSUER_PUBKEY_ENV: &str = "MIRAGE_SUBSCRIBER_ISSUER_PUBKEY_HEX";

/// Environment variable naming a FILE that holds the subscriber-issuer key
/// hex — the file form of [`SUBSCRIBER_ISSUER_PUBKEY_ENV`].
pub const SUBSCRIBER_ISSUER_PUBKEY_FILE_ENV: &str = "MIRAGE_SUBSCRIBER_ISSUER_PUBKEY_FILE";

/// Decode [`SUBSCRIBER_ISSUER_PUBKEY_HEX`] into a verifying key. See
/// [`operator_pubkey`]'s own doc — same fail-loudly contract, so a binary
/// cut without the fleet's real subscriber-issuer key cannot be talked into
/// admitting a `SubscriberSet` forged by anyone at all.
///
/// A LOCAL source works here too: [`SUBSCRIBER_ISSUER_PUBKEY_ENV`] or
/// [`SUBSCRIBER_ISSUER_PUBKEY_FILE_ENV`] point this binary at the box's own
/// issuer key, and the compile-time constant stays the default.
pub fn subscriber_issuer_pubkey() -> Result<ed25519_dalek::VerifyingKey, String> {
    if let Some(local_hex) = local_key_hex(
        SUBSCRIBER_ISSUER_PUBKEY_ENV,
        SUBSCRIBER_ISSUER_PUBKEY_FILE_ENV,
    )? {
        return decode_local_pubkey(&local_hex, SUBSCRIBER_ISSUER_PUBKEY_ENV);
    }
    decode_pinned_pubkey(SUBSCRIBER_ISSUER_PUBKEY_HEX, "SUBSCRIBER_ISSUER_PUBKEY_HEX")
}

/// The key a LOCAL source names, hex — `Ok(None)` when neither source is set.
fn local_key_hex(env_name: &str, file_env_name: &str) -> Result<Option<String>, String> {
    if let Ok(raw) = std::env::var(env_name) {
        let trimmed = raw.trim();
        if !trimmed.is_empty() {
            return Ok(Some(trimmed.to_owned()));
        }
    }
    let Ok(path) = std::env::var(file_env_name) else {
        return Ok(None);
    };
    let path = path.trim();
    if path.is_empty() {
        return Ok(None);
    }
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("{file_env_name} ({path}) cannot be read: {e}"))?;
    let Some(line) = text.lines().map(str::trim).find(|line| !line.is_empty()) else {
        return Err(format!("{file_env_name} ({path}) is empty"));
    };
    Ok(Some(line.chars().filter(|c| !c.is_whitespace()).collect()))
}

/// Decode a locally-sourced key — same fail-loudly contract as
/// [`decode_pinned_pubkey`], with the local source's own name in the message.
fn decode_local_pubkey(
    hex_str: &str,
    name: &str,
) -> Result<ed25519_dalek::VerifyingKey, String> {
    let raw = hex::decode(hex_str.trim()).map_err(|e| format!("{name} hex decode: {e}"))?;
    let arr: [u8; 32] =
        raw.try_into().map_err(|v: Vec<u8>| format!("{name} must be 32 bytes, got {}", v.len()))?;
    if arr == [0u8; 32] {
        return Err(format!("{name} is the all-zero placeholder -- it is not a key to trust"));
    }
    ed25519_dalek::VerifyingKey::from_bytes(&arr).map_err(|e| format!("{name} not a valid Ed25519 point: {e}"))
}

/// Shared decode+placeholder-check for a fleet-wide baked Ed25519 public
/// key constant — see [`operator_pubkey`] and [`subscriber_issuer_pubkey`],
/// the two call sites.
fn decode_pinned_pubkey(hex_str: &str, name: &str) -> Result<ed25519_dalek::VerifyingKey, String> {
    let raw = hex::decode(hex_str).map_err(|e| format!("{name} hex decode: {e}"))?;
    let arr: [u8; 32] =
        raw.try_into().map_err(|v: Vec<u8>| format!("{name} must be 32 bytes, got {}", v.len()))?;
    if arr == [0u8; 32] {
        return Err(format!(
            "{name} is still the checked-in placeholder -- this binary was never cut with the \
             fleet's real key"
        ));
    }
    ed25519_dalek::VerifyingKey::from_bytes(&arr).map_err(|e| format!("{name} not a valid Ed25519 point: {e}"))
}

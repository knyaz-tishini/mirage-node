//! Fleet-wide public identity anchors — substituted by operator-box's
//! universal build (`POST /universal/build?service=node`) before compiling
//! the ONE binary shipped to every box in the fleet.
//!
//! BI-4 of the baked-identity conversion
//! (`docs/mirage/plans/w7-baked-identity-finish-plan-2026-07-04.md` §3.4).
//! Mirrors `mirage2sentry/crates/sentry/src/bootstrap.rs` in shape — sentry
//! is the reference baked entity this file originally copied.
//!
//! ## Capsule cutover (2026-07-26)
//!
//! Until 2026-07-25 this file also carried a per-box PRIVATE identity
//! (`NODE_ID`, `NODE_PRIVKEY`, `NODE_SIGNING_PRIVKEY`, `DECLARED_IDENTITY_JSON`,
//! `MONITOR_SNAPSHOT`, `PUBLIC_ADDR`), rendered per box by a `POST
//! /node/bake` call and gated behind an `is_baked()` check at boot
//! (`core::configurator_main::run_configurator`). Every fleet binary has
//! been a universal build since then — the per-box bake path (and the
//! `is_baked()` branch that chose between it and `core::capsule_boot`) was
//! already permanently dead in production, so it is deleted here rather
//! than kept as an unreachable branch. `core::capsule_boot::boot_from_capsule`
//! is now the ONLY identity-acquisition path for this binary.
//!
//! ## Machine-identity cutover (2026-08-17)
//!
//! `core::capsule_boot` no longer unseals a capsule of its own, and no
//! longer bakes/carries an anchor list to ask over the network — see that
//! module's doc. It dials the box's keeper (`mirage-warden`) over a local
//! socket and waits for this role's slice. What stays HERE, unchanged, is
//! the pair of public anchors below: the keeper's own admission still needs
//! to know which operator key and which mesh this binary was built for.
//!
//! ## Placeholder values
//!
//! [`OPERATOR_PUBKEY_HEX`] below is a **compile-time placeholder** in an
//! un-rendered build — sufficient for `cargo check` / `cargo build` to
//! succeed without operator-box rendering. A binary shipped to a VPS MUST
//! have `OPERATOR_PUBKEY_HEX` rendered by operator-box's universal build; it
//! stays a compile-time constant because it is not identity — it is the
//! public anchor a sealed `mirage_core::capsule::MachineCapsule` is verified
//! *against*, not per-box material a capsule could plausibly redirect.
//! `MESH_ID` was rendered beside it until 2026-08-26 and no longer is.
//!
//! ## A LOCAL source for the same key
//!
//! A box that is not part of the fleet — a standalone box, which owns its
//! identity locally — has no fleet-wide anchor to render at build time. It
//! points this binary at its own operator key through [`OPERATOR_PUBKEY_ENV`]
//! or [`OPERATOR_PUBKEY_FILE_ENV`], and [`operator_pubkey`] then decodes THAT
//! key instead of the constant.
//!
//! The default is unchanged: with neither variable set, [`operator_pubkey`] is
//! byte-for-byte the function it always was, and a live fleet box is
//! unaffected by the existence of the variables.

// Mesh this node belongs to. Monitors reject cross-mesh registers.
// `MESH_ID` was removed here on 2026-08-26. A box does not know its own
// mesh: whoever ADMITS it decides, and says so inside the capsule they
// issue — every boot, because `/run` is tmpfs and nothing is remembered.
// A constant substituted at build time made that the BUILDER's claim
// instead, and this crate then enforced it against the operator. See
// `mirage_core::self_issue::UNAFFILIATED_MESH_ID`.

/// Operator Ed25519 verifying key hex (64 chars) — used to verify a sealed
/// `MachineCapsule` on boot (indirectly: the keeper verifies it, this
/// binary verifies the slice the keeper hands back) and to verify signed
/// `CredentialParams` gossip thereafter (replaces the store's
/// `operator_pinned WHERE singleton = 1` read).
pub const OPERATOR_PUBKEY_HEX: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

/// Sentinel value [`OPERATOR_PUBKEY_HEX`] holds in an un-rendered build.
const PLACEHOLDER_OPERATOR_PUBKEY_HEX: &str =
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

/// Decode the pinned operator verifying key.
///
/// [`OPERATOR_PUBKEY_HEX`] is not identity — it is the same PUBLIC
/// fleet-wide anchor every universal build ships with, regardless of which
/// box it lands on. A capsule-booting binary carries no private identity
/// until `core::capsule_boot` acquires one, but it always ships with the
/// real operator key — that key is exactly what lets it recognise a
/// genuine capsule. This accessor exists so the capsule boot path can
/// require a real key rather than silently trusting a placeholder:
/// verifying a sealed capsule against the all-zero placeholder would
/// either fail to decode (safe) or, worse, succeed against whatever key an
/// attacker chose, so a placeholder here must be a hard error, not a soft
/// `None`.
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
    if let Some(local_hex) = local_operator_pubkey_hex()? {
        return decode_operator_pubkey(&local_hex, OPERATOR_PUBKEY_ENV);
    }
    fleet_operator_pubkey()
}

/// The key the fleet's compile-time anchor names.
///
/// This is the path every fleet box takes, and the path a standalone box
/// takes when it has not pointed the binary at a key of its own.
fn fleet_operator_pubkey() -> Result<ed25519_dalek::VerifyingKey, String> {
    if OPERATOR_PUBKEY_HEX == PLACEHOLDER_OPERATOR_PUBKEY_HEX {
        return Err(
            "OPERATOR_PUBKEY_HEX is still the placeholder — this binary was not cut \
             from a source tree with the real operator key rendered in"
                .to_string(),
        );
    }
    decode_operator_pubkey(OPERATOR_PUBKEY_HEX, "OPERATOR_PUBKEY_HEX")
}

/// The operator key this process should trust, taken from a LOCAL source.
///
/// `Ok(None)` means "no local source is configured" — the fleet case, where
/// the compile-time anchor is the only key there is.
fn local_operator_pubkey_hex() -> Result<Option<String>, String> {
    if let Some(raw) = non_empty_env(OPERATOR_PUBKEY_ENV) {
        return Ok(Some(raw));
    }
    let Some(path) = non_empty_env(OPERATOR_PUBKEY_FILE_ENV) else {
        return Ok(None);
    };
    let text = std::fs::read_to_string(&path).map_err(|e| {
        format!("{OPERATOR_PUBKEY_FILE_ENV} ({path}) cannot be read: {e}")
    })?;
    let Some(line) = text.lines().map(str::trim).find(|line| !line.is_empty()) else {
        return Err(format!("{OPERATOR_PUBKEY_FILE_ENV} ({path}) is empty"));
    };
    Ok(Some(line.chars().filter(|c| !c.is_whitespace()).collect()))
}

/// The value of `name`, when it is set to something that is not blank.
fn non_empty_env(name: &str) -> Option<String> {
    match std::env::var(name) {
        Ok(raw) => {
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_owned())
            }
        }
        Err(_) => None,
    }
}

/// Decode one hex-encoded Ed25519 verifying key.
///
/// `name` is what the message calls the key, so the fleet path says
/// `OPERATOR_PUBKEY_HEX` and a local path says which local source it came
/// from.
fn decode_operator_pubkey(
    hex_str: &str,
    name: &str,
) -> Result<ed25519_dalek::VerifyingKey, String> {
    let raw = hex::decode(hex_str.trim()).map_err(|e| format!("{name} hex decode: {e}"))?;
    let arr: [u8; 32] = raw
        .try_into()
        .map_err(|_| format!("{name} must decode to 32 bytes"))?;
    if arr == [0u8; 32] {
        return Err(format!(
            "{name} is the all-zero placeholder — it is not a key this binary can trust"
        ));
    }
    ed25519_dalek::VerifyingKey::from_bytes(&arr)
        .map_err(|e| format!("{name} is not a valid Ed25519 point: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A hex-encoded Ed25519 verifying key that is not the placeholder.
    fn a_key(seed: u8) -> String {
        hex::encode(
            ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
                .verifying_key()
                .to_bytes(),
        )
    }

    /// The fleet's own path — the compile-time anchor.
    #[test]
    fn the_fleet_anchor_is_refused_while_it_is_the_placeholder() {
        assert_eq!(
            OPERATOR_PUBKEY_HEX, PLACEHOLDER_OPERATOR_PUBKEY_HEX,
            "this build carries the placeholder — a rendered build would not"
        );
        let error = fleet_operator_pubkey().expect_err("the placeholder is not a key");
        assert!(
            error.contains("placeholder"),
            "the refusal says why: {error}"
        );
    }

    /// A box that points the binary at its own key.
    #[test]
    fn a_local_key_is_decoded_instead_of_the_fleet_anchor() {
        let hex = a_key(0x11);
        let key = decode_operator_pubkey(&hex, OPERATOR_PUBKEY_ENV).expect("the local key decodes");
        assert_eq!(hex::encode(key.to_bytes()), hex);
    }

    /// The local source is a key like any other — the placeholder is not one.
    #[test]
    fn a_local_key_that_is_the_placeholder_is_refused() {
        let error = decode_operator_pubkey(&"0".repeat(64), OPERATOR_PUBKEY_ENV)
            .expect_err("the all-zero key is not a key");
        assert!(
            error.contains("all-zero"),
            "the refusal says why: {error}"
        );
    }

    /// Garbage is refused by name.
    #[test]
    fn a_local_key_that_is_not_hex_is_refused() {
        let error =
            decode_operator_pubkey("not hex", OPERATOR_PUBKEY_ENV).expect_err("garbage is not a key");
        assert!(
            error.contains("hex decode"),
            "the refusal says why: {error}"
        );
    }

    /// The key's length is checked before its curve.
    #[test]
    fn a_local_key_of_the_wrong_length_is_refused() {
        let error = decode_operator_pubkey("aabb", OPERATOR_PUBKEY_ENV)
            .expect_err("two bytes are not a key");
        assert!(
            error.contains("32 bytes"),
            "the refusal says why: {error}"
        );
    }
}

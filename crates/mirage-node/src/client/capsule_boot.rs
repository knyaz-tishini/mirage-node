//! Machine-scoped identity acquisition — this box's `Edge` slice, taken
//! from the local keeper (`mirage-warden`), the same path
//! `mirage-sentry`/`mirage-mshd` use
//! (`docs/mirage/plans/machine-identity-consolidated-2026-08-17.md`).
//!
//! [`mirage_core::identity_boot::take_machine_slice`] is the ONLY
//! identity-acquisition path: it dials the keeper's local socket, asks for
//! this role's slice, and waits **without a deadline** — see that
//! function's own doc for why a bounded wait would reintroduce the
//! per-service announce race this migration deleted. No announce, no ask,
//! no poll loop, no renewal loop belongs in this crate.
//!
//! Unlike `mirage-sentry`'s own `capsule_boot::acquire_identity`, this one
//! reshapes nothing beyond what `take_machine_slice` already proved
//! (operator-vouched, internally coherent, right role) — sentry additionally
//! builds a monitor peer/dial table out of the slice's `peers`, which this
//! crate has no use for yet: that is the monitor session/registration half
//! of `docs/mirage/plans/2026-09-24-edge-as-entry.md` ("Chain supply"), a
//! separate not-yet-merged branch (`edge-client-reg`). `crate::client::chain_store`
//! and the fleet's mesh leg (`mirage-edge-fleet`'s `mesh_leg`) need only the raw [`MachineSlice`] this returns.

use ed25519_dalek::VerifyingKey;
use mirage_core::identity::ServiceRole;
use mirage_core::machine_identity_query::MachineSlice;

/// Acquire this box's slice for `role` from the local keeper.
///
/// `Err` is fatal by design, exactly as it is for every other service that
/// calls `take_machine_slice` — the caller should exit and let the
/// supervisor (`Restart=always`) respawn into a fresh boot that re-asks the
/// keeper, rather than loop in place on a condition `take_machine_slice`
/// itself already decided was not something retrying fixes.
pub async fn acquire_identity(
    role: ServiceRole,
    operator_pubkey: &VerifyingKey,
) -> Result<MachineSlice, String> {
    mirage_core::identity_boot::take_machine_slice(role, operator_pubkey)
        .await
        .map_err(|e| format!("keeper handed over a slice that does not check out: {e}"))
}

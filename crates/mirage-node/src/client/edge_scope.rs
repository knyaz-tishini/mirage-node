//! This box's own admission scope — `Public` (every public-scope
//! `SubscriberSetEntry` is admitted here) or `Edge { machine_id }` (only the
//! entries pinned to this box's own machine id are admitted) — see
//! `mirage_core::crypto::credential::subscriber_set::EdgeScopeView`'s own
//! doc for what each side of `VerifiedSubscriberSet::admit` checks it
//! against.
//!
//! The scope comes from the sealed capsule
//! (`mirage_core::capsule::CapsuleServiceConfig::edge_scope`), which opbox
//! writes from the order tier that created the box. It never comes from the
//! environment and has no default: an absent scope means this box admits
//! NOBODY, because a private box must never fall back to admitting
//! public-scope customers. The `machine_id` a private scope pins to is this
//! box's own quorum-signed identity, supplied by the caller.

use mirage_core::capsule::EdgeScopeKind;
use mirage_core::crypto::credential::subscriber_set::EdgeScopeView;

/// Resolve this box's own scope from its capsule field. `None` = opbox set
/// no scope, and the caller must refuse to open the entrance.
pub fn resolve(kind: Option<EdgeScopeKind>, machine_id: &str) -> Option<EdgeScopeView> {
    match kind? {
        EdgeScopeKind::Public => Some(EdgeScopeView::Public),
        EdgeScopeKind::Private => Some(EdgeScopeView::Edge { machine_id: machine_id.to_string() }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absent_scope_admits_nobody() {
        assert_eq!(resolve(None, "box-1"), None);
    }

    #[test]
    fn public_resolves_to_public() {
        assert_eq!(resolve(Some(EdgeScopeKind::Public), "box-1"), Some(EdgeScopeView::Public));
    }

    #[test]
    fn private_pins_to_this_boxs_own_machine_id() {
        assert_eq!(
            resolve(Some(EdgeScopeKind::Private), "box-2"),
            Some(EdgeScopeView::Edge { machine_id: "box-2".to_string() })
        );
    }
}

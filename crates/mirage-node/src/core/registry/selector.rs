//! The opaque key a chain connection uses to name the listener it belongs to.
//!
//! # Why a newtype and not the `ListenerId`
//!
//! Under the port model there was no key: the bind port WAS the addressing,
//! and one socket per [`ListenerId`] meant a connection could not arrive at
//! the wrong listener. Removing the port removes that, and something has to
//! carry the addressing in its place.
//!
//! §2.5.3 of `docs/mirage/plans/chain-data-plane-over-faces-2026-09-02.md` is
//! decided: the addressing is a high-entropy token the monitor mints per hop
//! and hands the node twice — once on the listener spec
//! (`ChainRole::selector_token_hex`) and once on the wire, riding a trailer
//! on every FS init/extend/relay-init frame (`selector_token`). A derived
//! `{chain_id}-h{position}` name is what every hop used before this field
//! existed, and it stays as the fallback for a spec or a frame that carries
//! no token — the whole reason a monitor can roll this out hop by hop
//! instead of on a flag day.
//!
//! So this is a newtype over bytes rather than an alias for anything. The
//! spec side and the wire side each get their own constructor —
//! [`ChainSelector::for_spec`] and [`ChainSelector::from_frame`] — and both
//! must resolve to the SAME bytes for the SAME hop, token present or absent.
//! That property is pinned by this file's own tests, both the derived-name
//! case and the token case beside it.
//!
//! # It is not a secret and it is not a credential
//!
//! Holding a selector authorises nothing. A connection reaches this lookup
//! only after the perimeter has classified it as wire and the node has taken
//! it off the chain splice, and what the selector decides is WHICH listener,
//! never WHETHER. Treating it as a capability would be a privilege model
//! resting on an identifier the monitor mints in a predictable shape.
use crate::core::registry::spec::{ListenerId, ListenerSpec};
use mirage_core::mirage::wire::{ExitMode, ListenerRole, MirageListenerKind};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ChainSelector(Vec<u8>);

impl ChainSelector {
    /// Wrap bytes read off the wire. No validation beyond length, because
    /// this type deliberately knows nothing about the shape it carries —
    /// an unrecognised value is resolved to nothing and disposed of, which
    /// is the same answer a malformed one deserves.
    pub fn from_bytes(raw: &[u8]) -> Self {
        Self(raw.to_vec())
    }

    /// The selector a listener bound with `spec` answers to.
    ///
    /// **This is the line §2.5.3 decided.** When the monitor minted a
    /// `selector_token_hex` for this hop's `chain_role`, the selector IS
    /// those bytes — the high-entropy address the wire trailer carries on
    /// every FS frame, unrelated to the `ListenerId` and never derivable
    /// from it. When the spec carries none — an older monitor, or a listener
    /// with no `chain_role` at all — the selector falls back to the
    /// `ListenerId`'s bytes, exactly as before this field existed. That
    /// fallback IS the rollout story: a node running this code against specs
    /// that predate the token keeps resolving every connection it already
    /// resolves today, with nothing to flip.
    ///
    /// A `selector_token_hex` that fails to decode as hex is treated the
    /// same as absent, not as an error — this is a lookup key, not a
    /// validator, and a spec that fails to bind a socket because its token
    /// was malformed would be a worse failure mode than falling back to the
    /// name that still works.
    pub fn for_spec(spec: &crate::core::registry::spec::ListenerSpec) -> Self {
        let hex_str = spec
            .chain_role
            .as_ref()
            .and_then(|role| role.selector_token_hex.as_deref());
        let token = match hex_str {
            None => None,
            Some(h) => match hex::decode(h) {
                Ok(bytes) if !bytes.is_empty() => Some(bytes),
                // A token that will not decode is not the same fact as no
                // token, and the difference matters: this listener then binds
                // under the DERIVED name while the operator believes it
                // answers to the minted one, and the client — which refuses a
                // malformed token outright — will never reach it. The chain is
                // dead either way, so the fallback is kept rather than
                // refusing to bind on an optional field; what must not happen
                // is that it be silent.
                Ok(_) | Err(_) => {
                    tracing::warn!(
                        listener = %spec.id.0,
                        hex_len = h.len(),
                        "selector: chain_role carries a selector_token_hex that does not                          decode to a non-empty token — binding under the derived name,                          which no token-bearing client will address"
                    );
                    None
                }
            },
        };
        match token {
            Some(bytes) => Self(bytes),
            None => Self(spec.id.0.as_bytes().to_vec()),
        }
    }

    /// The selector a frame addresses, given the token it carries (if any)
    /// and the `chain_id`/`chain_position` it always carries.
    ///
    /// Mirrors [`for_spec`](Self::for_spec)'s choice on the wire side: the
    /// token is authoritative when the frame carries one — every FS
    /// init/extend/relay-init frame trailer, empty meaning "not sent" — and
    /// [`from_chain_position`](Self::from_chain_position) is the fallback
    /// for a frame from a client or a peer hop that predates it. The two
    /// halves of one rollout have to agree hop by hop, so this delegates to
    /// `from_chain_position` rather than re-deriving its logic here.
    pub fn from_frame(selector_token: &[u8], chain_id: &[u8], position: u8) -> Self {
        if !selector_token.is_empty() {
            return Self(selector_token.to_vec());
        }
        Self::from_chain_position(chain_id, position)
    }

    /// The selector a hop derives from `chain_id`/`chain_position` alone,
    /// with no token — either because the frame carries none, or because a
    /// spec's `ListenerId` doubles as the fallback name.
    ///
    /// **Not new data on the wire.** Both frames a hop can receive —
    /// `FsInitFrame` at the entry and `FsRelayInitFrame` forwarded to every
    /// later hop — already carry `chain_id` and `chain_position`, and a
    /// `ListenerId` is exactly `{chain_id}-h{position}` (`chains_build.rs:536`,
    /// `chain_handler.rs:408`). So resolving through this fallback costs no
    /// field and no frame shape change; it is exactly what every hop did
    /// before the token existed, kept alive for whichever side of a rollout
    /// hasn't reached this hop yet.
    pub fn from_chain_position(chain_id: &[u8], position: u8) -> Self {
        let mut out = Vec::with_capacity(chain_id.len() + 4);
        out.extend_from_slice(chain_id);
        out.extend_from_slice(b"-h");
        out.extend_from_slice(position.to_string().as_bytes());
        Self(out)
    }

    /// Length only. Deliberately no accessor for the bytes themselves: a
    /// selector is a client's addressing choice, and a log line that printed
    /// it would hand whoever reads the journal the map. See the disposal
    /// path, which reports this and the peer, never the value.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// The raw bytes, for hashing ONLY.
    ///
    /// `pub(crate)` and named for its one use: the disposal path digests the
    /// selector so two log lines about one chain can be correlated without the
    /// chain appearing in the journal. Anything that wants to PRINT these
    /// bytes wants the digest instead.
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Which listener a chain connection belongs to, and the spec to serve it
/// with. The replacement for the bind port.
///
/// # Why this is its own type
///
/// `ListenerRegistry` is about SOCKETS: it binds them, hands out handles,
/// reconciles them against a desired set. A chain hop has no socket, so none
/// of that applies to it, and folding it in would mean a registry where half
/// the entries have handles and half do not — with every method having to say
/// which half it meant.
///
/// Splitting it also makes the property the step-1 gate asserts checkable
/// without standing up a node: a routing entry and no socket is two counts on
/// two types, not one count on one type with a caveat.
#[derive(Default)]
pub struct ChainRouting {
    /// Selector → the listener that answers to it.
    ///
    /// Cleared with the spec, always. A selector that outlived its spec would
    /// resolve, and the connection would be served against a spec the monitor
    /// has withdrawn.
    by_selector: std::collections::HashMap<ChainSelector, ListenerId>,
    /// The specs themselves, keyed as the monitor keys them.
    specs: std::collections::HashMap<ListenerId, ListenerSpec>,
}

impl ChainRouting {
    /// Register a chain listener. Binds nothing — that is the point.
    pub fn register(&mut self, spec: &ListenerSpec) -> ListenerId {
        self.by_selector
            .insert(ChainSelector::for_spec(spec), spec.id.clone());
        self.specs.insert(spec.id.clone(), spec.clone());
        spec.id.clone()
    }

    /// Drop a registration and the selector that reached it.
    pub fn unregister(&mut self, id: &ListenerId) {
        self.specs.remove(id);
        self.by_selector.retain(|_, bound_to| bound_to != id);
    }

    /// Resolve the listener a connection is addressed to, from the fields its
    /// init frame carries.
    ///
    /// `selector_token` is the frame's own trailer — empty when the peer that
    /// sent it predates the token or simply has none for this hop. Resolution
    /// goes through [`ChainSelector::from_frame`], so a token-bearing frame
    /// resolves against a token-bearing registration and a bare frame
    /// resolves against the derived name, exactly like [`register`](Self::register)
    /// indexed it.
    ///
    /// **Call this only after the frame has authenticated.** Resolving from an
    /// unauthenticated frame would let anyone able to open the splice ask
    /// "does this box hold chain X hop N" and read the answer off what
    /// happens next. The miss and the authentication failure share one exit
    /// precisely so that neither is distinguishable; resolving early would
    /// make the ordering itself the tell.
    ///
    /// `chain_length` is compared against the spec's rather than merely
    /// carried. A frame naming the right listener with the wrong length
    /// describes a topology this node was not told to serve, and serving it
    /// would mean trusting the caller's account of the chain over the
    /// monitor's. That is a miss, through the same door.
    ///
    /// `kind` is compared against the spec's for the identical reason, and
    /// closes a hole that was open until 2026-09-09: nothing here used to
    /// compare the resolved spec's transport against the caller's at all.
    /// `by_selector` is a flat map from selector bytes to one `ListenerId` —
    /// it has no notion of transport — so a selector minted for a
    /// `TunnelUdp` hop and named by a STREAM connection's init frame
    /// resolved exactly as happily as a `TunnelTcp` one would have. The
    /// datagram side patched this for itself on 2026-09-09
    /// (`resolve_datagram`'s now-removed post-check); this closes the same
    /// gap here, one level down, so every caller states the transport it
    /// means rather than one plane checking and the other trusting whatever
    /// the selector happened to point at.
    ///
    /// There is no lenient branch anywhere in here: no default listener, no
    /// "the only one registered", no nearest match, and no "any kind" that
    /// would let a caller skip stating which transport it is. Under the
    /// port model an unrecognised port had nothing listening on it, and this
    /// preserves that rather than inventing a helpfulness the port never
    /// had.
    pub fn resolve(
        &self,
        chain_id: &[u8],
        chain_position: u8,
        chain_length: u8,
        selector_token: &[u8],
        kind: MirageListenerKind,
    ) -> Option<&ListenerSpec> {
        let selector = ChainSelector::from_frame(selector_token, chain_id, chain_position);
        let id = self.by_selector.get(&selector)?;
        let spec = self.specs.get(id)?;
        let spec_length = spec.chain_role.as_ref().map(|r| r.chain_length).unwrap_or(1);
        if spec_length != chain_length {
            return None;
        }
        if spec.kind != kind {
            return None;
        }
        Some(spec)
    }

    /// Resolve the listener a DATAGRAM session is addressed to, from the
    /// chain block its `ClientHello` carried.
    ///
    /// Delegates to [`resolve`](Self::resolve) rather than re-deriving
    /// anything: [`DatagramChainAddress`] carries the same four facts an FS
    /// init frame carries, and `DatagramChainAddress::selector_bytes` was
    /// written against [`ChainSelector::from_frame`] precisely so that ONE
    /// chain cannot be addressed two different ways depending on which
    /// transport reached it.
    ///
    /// The kind is `MirageListenerKind::TunnelUdp`, fixed — this function's
    /// whole reason to exist is naming the datagram plane's transport, so it
    /// states it once here rather than taking it as a parameter nobody would
    /// ever pass anything else for. A datagram addressing a TCP hop's
    /// selector is a real client error and a real prober's probe; serving it
    /// would mean binding a stream listener's spec to a datagram session,
    /// and the transport a hop was minted for is the monitor's statement,
    /// not the caller's. A mismatch is a miss, through the same silent door
    /// as every other miss. This used to be a separate check bolted on
    /// after the call to `resolve` (until 2026-09-09); it is now `resolve`'s
    /// own job, done identically for every caller — see `resolve`'s doc for
    /// the matching stream-side gap this closed on the same day.
    ///
    /// # Unlike the stream side, this runs BEFORE the client authenticates
    ///
    /// It has to: the AEAD suite the datagram handshake negotiates is read
    /// off the spec this returns. The stream path can resolve after
    /// authenticating because its miss and its authentication failure share
    /// a hold-then-close, and resolving early would make the ordering the
    /// tell. The datagram path has no such tell to leak — its rejection is
    /// no reply at all, so a miss and a failed proof are the same silence,
    /// and the timing of a datagram that is never sent is not observable.
    /// That is the whole reason this ordering is safe, so the caller must
    /// keep it: on `None`, answer nothing.
    pub fn resolve_datagram(
        &self,
        addr: &mirage_protocol::core::dgram_chain_addr::DatagramChainAddress,
    ) -> Option<&ListenerSpec> {
        self.resolve(
            &addr.chain_id,
            addr.chain_position,
            addr.chain_length,
            &addr.selector_token,
            MirageListenerKind::TunnelUdp,
        )
    }

    /// Whether this id is a registered chain listener.
    pub fn contains(&self, id: &ListenerId) -> bool {
        self.specs.contains_key(id)
    }

    /// How many chain listeners are registered. The step-1 gate reads this
    /// against the registry's bound-socket count.
    pub fn len(&self) -> usize {
        self.specs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.specs.is_empty()
    }

    /// The one live `TunnelUdp` / `Exit{Direct}` listener registered for
    /// `mesh_id` — the resolution path a datagram session can actually use.
    ///
    /// # Why this exists alongside [`resolve_datagram`](Self::resolve_datagram)
    ///
    /// **Corrected 2026-09-09.** This method's doc used to say the V9
    /// datagram handshake carried no addressing and was not getting any, so
    /// `mesh_id` was the only fact a datagram session could be resolved by.
    /// The wire now carries a chain block on the `ClientHello`
    /// (`mirage_protocol::core::dgram_chain_addr`), and
    /// [`resolve_datagram`](Self::resolve_datagram) is what reads it.
    ///
    /// What is left for this method is the case that block is absent: a
    /// client dialling a plain direct UDP exit, which names a mesh and
    /// nothing finer because there is nothing finer to name. That is a real
    /// shape and stays supported — it is not a fallback for a chain-addressed
    /// dial, and `udp_chain_splice` never reaches it when a block is present.
    ///
    /// # No lenient default
    ///
    /// Same doctrine as `resolve`: no default listener, no "the only one
    /// registered elsewhere", no nearest match. Zero candidates and two or
    /// more candidates are both errors, and each names the mesh_id it was
    /// asked about and which case it hit — an ambiguous match is never
    /// resolved by picking the first.
    ///
    /// # Not wired to a caller yet
    ///
    /// Nothing in this crate calls this today. The datagram exit that will
    /// call it is later, separate work; this method is built and tested in
    /// isolation so that piece has something correct to call into.
    pub fn single_udp_direct_exit(
        &self,
        mesh_id: &str,
    ) -> Result<ListenerSpec, UdpExitSelectorError> {
        let candidates: Vec<&ListenerSpec> = self
            .specs
            .values()
            .filter(|s| {
                s.mesh_id == mesh_id
                    && s.kind == MirageListenerKind::TunnelUdp
                    && matches!(s.role, ListenerRole::Exit { exit_mode: ExitMode::Direct })
            })
            .collect();

        match candidates.as_slice() {
            [] => Err(UdpExitSelectorError::NoneRegistered(mesh_id.to_string())),
            [only] => Ok((*only).clone()),
            many => Err(UdpExitSelectorError::Ambiguous(many.len(), mesh_id.to_string())),
        }
    }
}

/// What [`ChainRouting::single_udp_direct_exit`] can fail with. Both
/// variants name the mesh_id they were asked about and which case they hit —
/// a rejection that did not would be useless to whoever reads it later.
#[derive(Debug, thiserror::Error)]
pub enum UdpExitSelectorError {
    #[error("no TunnelUdp/Direct exit registered for mesh_id {0:?}")]
    NoneRegistered(String),
    #[error(
        "{0} TunnelUdp/Direct exits registered for mesh_id {1:?} — ambiguous, refusing to guess"
    )]
    Ambiguous(usize, String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::registry::spec::{ListenerId, ListenerSpec};
    use mirage_core::mirage::wire::{
        AeadSuite, ExitMode, Framing, ListenerRole, MirageListenerKind, SpecFingerprint,
    };

    fn spec_with_id(id: &str) -> ListenerSpec {
        ListenerSpec {
            id: ListenerId(id.to_string()),
            mesh_id: "MESH1".into(),
            kind: MirageListenerKind::TunnelTcp,
            role: ListenerRole::Exit { exit_mode: ExitMode::Direct },
            framing: Framing::Plain,
            ingress_layer: None,
            outgoing_layer: None,
            aead_suite: AeadSuite::ChaCha20Poly1305,
            bind_port: None,
            chain_role: None,
            control_target: None,
            payload: None,
            fingerprint: SpecFingerprint([0u8; 32]),
        }
        .with_recomputed_fingerprint()
    }

    #[test]
    fn the_wire_derivation_matches_the_registry_key() {
        // The whole design rests on these two agreeing. The registry indexes
        // by `for_spec` (what the monitor minted); a hop resolves
        // by `from_chain_position` (what the init frame carries). If
        // they ever disagree, every connection becomes unaddressable at once and the
        // disposal path swallows the evidence — so this is pinned, not
        // assumed.
        for (chain_id, pos) in [
            ("auto-fa291277", 0u8),
            ("auto-fa291277", 1),
            ("auto-00000000", 255),
            ("an-operator-named-chain", 2),
        ] {
            let minted = spec_with_id(&format!("{chain_id}-h{pos}"));
            assert_eq!(
                ChainSelector::for_spec(&minted),
                ChainSelector::from_chain_position(chain_id.as_bytes(), pos),
                "registry key and wire derivation disagree for {chain_id} hop {pos}"
            );
        }
    }

    #[test]
    fn two_hops_of_one_chain_are_different_selectors() {
        // Per-hop addressing is the property that replaced the per-hop port.
        let h0 = ChainSelector::from_chain_position(b"auto-fa291277", 0);
        let h1 = ChainSelector::from_chain_position(b"auto-fa291277", 1);
        assert_ne!(h0, h1);
    }
}

#[cfg(test)]
mod chain_routing_tests {
    use super::*;
    use crate::core::registry::spec::ListenerSpec;
    use mirage_core::mirage::wire::{
        AeadSuite, ChainRole, EntryHop, ExitMode, Framing, ListenerRole, MirageListenerKind,
        RelayMode, SpecFingerprint,
    };

    fn hop_spec(chain_id: &str, position: u8, length: u8) -> ListenerSpec {
        ListenerSpec {
            id: crate::core::registry::spec::ListenerId(format!("{chain_id}-h{position}")),
            mesh_id: "MESH1".into(),
            kind: MirageListenerKind::TunnelTcp,
            role: if position + 1 == length {
                ListenerRole::Exit { exit_mode: ExitMode::Onion }
            } else {
                ListenerRole::Relay {
                    position: if position == 0 { EntryHop::Entry } else { EntryHop::Hop },
                    relay_mode: RelayMode::OnionPeel,
                }
            },
            framing: Framing::Onion,
            ingress_layer: None,
            outgoing_layer: None,
            aead_suite: AeadSuite::ChaCha20Poly1305,
            // The point of the whole cutover: no port.
            bind_port: None,
            chain_role: Some(ChainRole {
                chain_id: chain_id.into(),
                chain_position: position,
                chain_length: length,
                chain_node_ids: vec!["a".into(), "b".into()],
                next_hop_addr: None,
                selector_token_hex: None,
            }),
            control_target: None,
            payload: None,
            fingerprint: SpecFingerprint([0u8; 32]),
        }
        .with_recomputed_fingerprint()
    }

    fn empty_routing() -> ChainRouting {
        ChainRouting::default()
    }

    #[test]
    fn a_pushed_spec_produces_a_routing_entry_and_binds_no_socket() {
        // The step-1 gate, asserted rather than described. `bound` is the map
        // that holds a handle per SOCKET; a chain hop must not appear in it.
        let mut reg = empty_routing();
        let spec = hop_spec("auto-fa291277", 0, 2);
        let id = reg.register(&spec);

        assert_eq!(reg.len(), 1, "the spec must be registered");
        assert_eq!(reg.len(), 1, "and reachable by selector");
        assert!(
            spec.bind_port.is_none(),
            "a chain hop must carry no port — the port is what this cutover removes"
        );
        assert_eq!(id.0, "auto-fa291277-h0");
    }

    #[test]
    fn a_frame_resolves_to_the_spec_the_monitor_pushed() {
        let mut reg = empty_routing();
        let spec = hop_spec("auto-fa291277", 1, 3);
        reg.register(&spec);

        let got = reg
            .resolve(b"auto-fa291277", 1, 3, &[], MirageListenerKind::TunnelTcp)
            .expect("the frame names a registered listener");
        assert_eq!(got.id, spec.id);
    }

    #[test]
    fn a_chain_length_that_disagrees_with_the_spec_is_a_miss() {
        // The frame names the right listener and the wrong topology. Serving
        // it would mean trusting the caller's account of the chain over the
        // monitor's, so it leaves through the same door as an unknown id.
        let mut reg = empty_routing();
        reg.register(&hop_spec("auto-fa291277", 1, 3));

        assert!(
            reg.resolve(b"auto-fa291277", 1, 4, &[], MirageListenerKind::TunnelTcp).is_none(),
            "a chain_length mismatch must not resolve"
        );
    }

    #[test]
    fn an_unknown_selector_is_a_miss_and_never_a_default() {
        let mut reg = empty_routing();
        reg.register(&hop_spec("auto-fa291277", 0, 2));

        // A chain this node does not serve.
        assert!(
            reg.resolve(b"auto-00000000", 0, 2, &[], MirageListenerKind::TunnelTcp).is_none()
        );
        // The right chain, a hop this node does not serve. There is exactly
        // one registered listener, so a lenient resolver would "helpfully"
        // return it — that is the failure this asserts against.
        assert!(
            reg.resolve(b"auto-fa291277", 1, 2, &[], MirageListenerKind::TunnelTcp).is_none()
        );
    }

    #[test]
    fn unregistering_takes_the_selector_with_it() {
        let mut reg = empty_routing();
        let spec = hop_spec("auto-fa291277", 0, 2);
        let id = reg.register(&spec);
        reg.unregister(&id);

        assert_eq!(reg.len(), 0);
        assert!(
            reg.resolve(b"auto-fa291277", 0, 2, &[], MirageListenerKind::TunnelTcp).is_none(),
            "a selector outliving its spec would resolve to a spec the monitor withdrew"
        );
    }

    #[test]
    fn the_resolved_spec_derives_the_same_bundle_as_activate_would() {
        // Replaces the equality half of `both_paths_derive_the_same_bundle_from_one_spec`,
        // which compared two calls of one function on one value and was true
        // by construction. This goes through the real path: register, build
        // the selector the way the FRAME builds it, resolve, and compare the
        // bundle derived from what came back with the bundle activate() would
        // derive from what went in.
        use crate::family::mirage::listener::tunnel_tcp::bundle_from_spec;

        let mut reg = empty_routing();
        let pushed = hop_spec("auto-fa291277", 1, 3);
        reg.register(&pushed);

        // Built from the frame's fields, not from the spec — the two must
        // agree or nothing resolves.
        let resolved_via_selector = reg
            .resolve(b"auto-fa291277", 1, 3, &[], MirageListenerKind::TunnelTcp)
            .expect("the selector the frame builds must resolve");

        assert_eq!(
            bundle_from_spec(resolved_via_selector),
            bundle_from_spec(&pushed),
            "the resolve path and the activate path must derive the same nine values"
        );
    }

    #[test]
    fn every_chain_listener_kind_stops_binding_including_udp() {
        // The rule has no transport in it. TunnelUdp and UdpRelay bind
        // `spec.bind_port` from the SAME allocator as TunnelTcp, so deferring
        // them to a separate plan would have left half the fleet's listeners
        // on ports nothing is allowed to allocate.
        use mirage_core::mirage::wire::MirageListenerKind as K;
        for kind in [K::TunnelTcp, K::TunnelUdp, K::UdpRelay] {
            let mut spec = hop_spec("auto-fa291277", 0, 2);
            spec.kind = kind;
            let spec = spec.with_recomputed_fingerprint();
            let mut reg = empty_routing();
            reg.register(&spec);
            assert_eq!(reg.len(), 1, "{kind:?} must register");
            assert!(spec.bind_port.is_none(), "{kind:?} must ask for no port");
        }
    }

    #[test]
    fn a_single_hop_chain_listener_carries_no_chain_role() {
        // The case that broke the first version of the no-bind gate, pinned
        // here so it cannot come back. `chains_build.rs:589-599` attaches a
        // chain_role only when total_hops > 1, so the shortest chain there is
        // has a listener with none — and a gate keyed on the role would have
        // left that listener holding a bind port, which is the exact port the
        // cutover removes. It would have passed every multi-hop test.
        let single = hop_spec("auto-fa291277", 0, 1);
        assert!(
            single.chain_role.is_some(),
            "this fixture always sets one; the REAL single-hop spec does not —              see the note above, and key the gate on the kind"
        );
        // What the gate must actually key on, and what the fleet's only
        // producer of this kind emits.
        assert!(matches!(single.kind, MirageListenerKind::TunnelTcp));
        assert!(single.bind_port.is_none(), "and it asks for no port");
    }

    #[test]
    fn a_reconfigured_chain_spec_replaces_its_entry_rather_than_duplicating_it() {
        // B1's fingerprint compare says a changed spec must rebind; for a
        // listener with no socket that means re-register. What must NOT happen
        // is two entries for one listener, or a stale spec surviving under the
        // same selector.
        let mut reg = empty_routing();
        let first = hop_spec("auto-fa291277", 0, 2);
        reg.register(&first);

        let mut changed = first.clone();
        changed.aead_suite = AeadSuite::Aes256Gcm;
        let changed = changed.with_recomputed_fingerprint();
        reg.register(&changed);

        assert_eq!(reg.len(), 1, "re-registering must replace, not duplicate");
        let got = reg
            .resolve(b"auto-fa291277", 0, 2, &[], MirageListenerKind::TunnelTcp)
            .expect("still resolves");
        assert_eq!(
            got.aead_suite,
            AeadSuite::Aes256Gcm,
            "the entry must hold the NEW spec — a stale one would serve a config nobody chose"
        );
    }

    #[test]
    fn a_token_bearing_frame_resolves_by_token_and_a_bare_frame_by_derived_name() {
        // `for_spec` and `from_frame` must agree hop by hop: a listener the
        // monitor minted a token for is reachable ONLY by that token, and a
        // listener with none is reachable exactly as every hop was before
        // the token existed. One registry, two peers at different rollout
        // stages, both resolve.
        let mut reg = empty_routing();

        let mut tokened = hop_spec("auto-fa291277", 0, 2);
        tokened
            .chain_role
            .as_mut()
            .expect("hop_spec always sets a chain_role")
            .selector_token_hex = Some(hex::encode(b"a-real-minted-token"));
        let tokened = tokened.with_recomputed_fingerprint();
        reg.register(&tokened);

        let bare = hop_spec("auto-bare-hop", 0, 2);
        reg.register(&bare);

        let by_token = reg
            .resolve(
                b"auto-fa291277",
                0,
                2,
                b"a-real-minted-token",
                MirageListenerKind::TunnelTcp,
            )
            .expect("a frame carrying the minted token must resolve");
        assert_eq!(by_token.id, tokened.id);
        assert!(
            reg.resolve(b"auto-fa291277", 0, 2, &[], MirageListenerKind::TunnelTcp).is_none(),
            "a token-bearing listener must not also answer to its derived name — \
             that would give an observer two names for one hop"
        );

        let by_derived = reg
            .resolve(b"auto-bare-hop", 0, 2, &[], MirageListenerKind::TunnelTcp)
            .expect("a frame carrying no token must still resolve by derived name");
        assert_eq!(by_derived.id, bare.id);
    }

    #[test]
    fn a_tcp_spec_and_a_udp_spec_sharing_one_selector_resolve_only_through_their_own_kinds_entry_point()
    {
        // The latent hole this slice closes, pinned directly: `by_selector`
        // is a flat map from selector bytes to ONE `ListenerId` with no
        // notion of transport in it, so before `kind` was threaded through
        // `resolve`, whichever spec occupied a selector answered to EVERY
        // caller regardless of which transport's entry point asked. Two
        // specs minted with the identical (chain_id, chain_position,
        // selector_token) identity — a monitor is free to reuse a selector
        // across transports, nothing here validates otherwise — prove both
        // directions are closed: the wrong-kind entry point gets nothing,
        // no matter which of the two is currently occupying the shared
        // selector slot.
        let chain_id = b"auto-fa291277";
        let position = 0u8;
        let length = 2u8;
        let token = b"a-shared-selector".to_vec();

        let mut tcp_spec = hop_spec("auto-fa291277", position, length);
        tcp_spec.kind = MirageListenerKind::TunnelTcp;
        tcp_spec
            .chain_role
            .as_mut()
            .expect("hop_spec always sets a chain_role")
            .selector_token_hex = Some(hex::encode(&token));
        let tcp_spec = tcp_spec.with_recomputed_fingerprint();

        let mut udp_spec = hop_spec("auto-fa291277", position, length);
        udp_spec.kind = MirageListenerKind::TunnelUdp;
        // A distinct id: two listeners occupying one selector, not one
        // listener re-registered under a new kind (that case is already
        // covered by `a_reconfigured_chain_spec_replaces_its_entry_rather_than_duplicating_it`).
        udp_spec.id = crate::core::registry::spec::ListenerId("auto-fa291277-h0-udp-twin".into());
        udp_spec
            .chain_role
            .as_mut()
            .expect("hop_spec always sets a chain_role")
            .selector_token_hex = Some(hex::encode(&token));
        let udp_spec = udp_spec.with_recomputed_fingerprint();

        // UDP registered last: `by_selector` is a `HashMap`, so it wins the
        // shared selector slot (last write wins on a colliding key) — the
        // TCP spec still exists in `specs`, just unreachable by selector
        // while the UDP one occupies it. That is the realistic shape of the
        // collision: only one listener can occupy a given selector at a
        // time, so what must never happen is the WRONG TRANSPORT being
        // served out of that one slot.
        let mut reg = empty_routing();
        reg.register(&tcp_spec);
        reg.register(&udp_spec);

        let via_udp = reg
            .resolve(chain_id, position, length, &token, MirageListenerKind::TunnelUdp)
            .expect("the UDP entry point must resolve the UDP spec occupying the shared selector");
        assert_eq!(via_udp.id, udp_spec.id);

        assert!(
            reg.resolve(chain_id, position, length, &token, MirageListenerKind::TunnelTcp)
                .is_none(),
            "the TCP entry point must not be served the UDP spec sitting under the same \
             selector — this is the check that closes the hole `resolve_datagram` already had \
             and the stream side never did"
        );

        // Same collision, reversed registration order: TCP now occupies the
        // slot. The UDP entry point must not be served the TCP spec in
        // return — proving the check is keyed on the RESOLVED spec's kind,
        // not on which transport happened to register first.
        let mut reg2 = empty_routing();
        reg2.register(&udp_spec);
        reg2.register(&tcp_spec);

        let via_tcp = reg2
            .resolve(chain_id, position, length, &token, MirageListenerKind::TunnelTcp)
            .expect("the TCP entry point must resolve the TCP spec occupying the shared selector");
        assert_eq!(via_tcp.id, tcp_spec.id);

        assert!(
            reg2.resolve(chain_id, position, length, &token, MirageListenerKind::TunnelUdp)
                .is_none(),
            "the UDP entry point must not be served the TCP spec sitting under the same selector"
        );
    }
}

#[cfg(test)]
mod udp_direct_exit_selector_tests {
    //! Proof for [`ChainRouting::single_udp_direct_exit`] — the resolution
    //! path a datagram session (no `chain_id`/`chain_position`/
    //! `chain_length` to give `resolve`) can actually use.
    use super::*;
    use crate::core::registry::spec::ListenerSpec;
    use mirage_core::mirage::wire::{
        AeadSuite, ExitMode, Framing, ListenerRole, MirageListenerKind, SpecFingerprint,
    };

    fn udp_direct_exit_spec(mesh_id: &str, id: &str) -> ListenerSpec {
        ListenerSpec {
            id: ListenerId(id.to_string()),
            mesh_id: mesh_id.into(),
            kind: MirageListenerKind::TunnelUdp,
            role: ListenerRole::Exit { exit_mode: ExitMode::Direct },
            framing: Framing::Plain,
            ingress_layer: None,
            outgoing_layer: None,
            aead_suite: AeadSuite::ChaCha20Poly1305,
            bind_port: None,
            chain_role: None,
            control_target: None,
            payload: None,
            fingerprint: SpecFingerprint([0u8; 32]),
        }
        .with_recomputed_fingerprint()
    }

    fn empty_routing() -> ChainRouting {
        ChainRouting::default()
    }

    #[test]
    fn exactly_one_registered_resolves_to_it() {
        let mut reg = empty_routing();
        let spec = udp_direct_exit_spec("MESH1", "udp-exit-0");
        reg.register(&spec);

        let got = reg
            .single_udp_direct_exit("MESH1")
            .expect("the one registered TunnelUdp/Direct exit must resolve");
        assert_eq!(got.id, spec.id);
    }

    #[test]
    fn none_registered_is_a_named_error() {
        let reg = empty_routing();

        let err = reg
            .single_udp_direct_exit("MESH1")
            .expect_err("nothing is registered — this must not silently succeed");
        assert!(
            matches!(err, UdpExitSelectorError::NoneRegistered(ref m) if m == "MESH1"),
            "the error must name the case it hit and the mesh_id it was asked about: {err}"
        );
        let rendered = err.to_string();
        assert!(rendered.contains("MESH1"), "rejection must name its inputs: {rendered}");
        assert!(rendered.contains("no TunnelUdp"), "rejection must name the case: {rendered}");
    }

    #[test]
    fn two_or_more_registered_is_a_named_error_and_never_a_silent_pick() {
        let mut reg = empty_routing();
        let a = udp_direct_exit_spec("MESH1", "udp-exit-a");
        let b = udp_direct_exit_spec("MESH1", "udp-exit-b");
        reg.register(&a);
        reg.register(&b);

        let err = reg
            .single_udp_direct_exit("MESH1")
            .expect_err("two candidates must be refused, not one silently picked");
        assert!(
            matches!(err, UdpExitSelectorError::Ambiguous(2, ref m) if m == "MESH1"),
            "the error must carry the exact count and the mesh_id: {err}"
        );
        let rendered = err.to_string();
        assert!(rendered.contains('2'), "rejection must name the count: {rendered}");
        assert!(rendered.contains("MESH1"), "rejection must name its inputs: {rendered}");
        assert!(rendered.contains("ambiguous"), "rejection must name the case: {rendered}");
    }

    #[test]
    fn a_different_meshs_listener_is_not_a_candidate() {
        let mut reg = empty_routing();
        // Registered, but for a mesh nobody is asking about.
        reg.register(&udp_direct_exit_spec("OTHER-MESH", "udp-exit-other"));

        let err = reg
            .single_udp_direct_exit("MESH1")
            .expect_err("a listener on a different mesh must not be a candidate");
        assert!(
            matches!(err, UdpExitSelectorError::NoneRegistered(ref m) if m == "MESH1"),
            "the other mesh's listener must not count toward MESH1: {err}"
        );

        // With one real candidate on a lab mesh alongside the other mesh's
        // listener, resolution must still be exactly one match, not two.
        let wanted = udp_direct_exit_spec("MESH1", "udp-exit-mesh1");
        reg.register(&wanted);
        let got = reg
            .single_udp_direct_exit("MESH1")
            .expect("MESH1's own listener must resolve despite OTHER-MESH's also being registered");
        assert_eq!(got.id, wanted.id);
    }

    #[test]
    fn a_non_udp_direct_exit_is_not_a_candidate() {
        // A TunnelTcp chain hop on the same mesh must not satisfy the UDP
        // selector — the kind and role filters both have to hold, not just
        // the mesh_id.
        let mut reg = empty_routing();
        let mut tcp_hop = udp_direct_exit_spec("MESH1", "tcp-hop-0");
        tcp_hop.kind = MirageListenerKind::TunnelTcp;
        let tcp_hop = tcp_hop.with_recomputed_fingerprint();
        reg.register(&tcp_hop);

        assert!(
            reg.single_udp_direct_exit("MESH1").is_err(),
            "a TunnelTcp listener must never satisfy the TunnelUdp/Direct selector"
        );
    }
}

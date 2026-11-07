//! `mirage-node` — the Mirage data plane, as a library.
//!
//! This crate is the **OSS** half of the node: the runtime, the listener
//! registry, the chain splice, the exit handlers. It has NO fleet
//! dependency — no mesh client, no monitor control channel, no capsule
//! boot — so a standalone server built on it physically cannot reach a
//! fleet crate.
//!
//! The binary that ships to the fleet is the `mirage-node-fleet` crate's
//! `main.rs`: a thin shell that parses the command line, hardens the
//! process and calls the fleet configurator. Everything else — the
//! runtime, the listener registry, the chain splice, the exit handlers —
//! lives here, so that a node can also be embedded into another binary.
//!
//! # What is inside
//!
//! * [`core`] — the node's own machinery: the runtime ([`core::runtime`]), the
//!   listener registry ([`core::registry`]), the chain splice
//!   ([`core::chain_splice`]), the credential gate
//!   ([`core::role_signed_gate`]) and the fleet's compile-time identity
//!   anchors ([`core::bootstrap`]).
//! * [`family`] — the Mirage-native handlers: what binds on the socket
//!   (`family::mirage::listener`), the relay legs (`family::mirage::relay`)
//!   and the exit legs (`family::mirage::exit`).
//! * [`client`] — the customer-facing half: the client entrance, the session
//!   wire, the held chain store, the live-session registry, the byte pumps
//!   and the UDP-flow caps. A customer talks to a NODE directly — there is no
//!   edge in between. See [`client`]'s own doc for why the edge is fleet
//!   machinery and not a part of this crate.
//!
//! # The two ways to run a node
//!
//! 1. **Fleet node** — the `mirage-node-fleet` crate's
//!    `core::configurator_main::run_configurator`. The binary acquires its
//!    identity from the box's keeper and receives its listener specs, peer
//!    table and chain bindings over the monitor's control channel.
//! 2. **Standalone node** — a box that owns its identity locally and builds
//!    the same control-plane objects itself from local configuration. That
//!    path lives in the `mirage-standalone` crate, which depends on this one;
//!    the pieces it needs are public here for exactly that reason.
//!
//! The behaviour of the shipped binary is unchanged by this split: the
//! library is the same code the binary used to own, and the binary is still
//! called `mirage-node`.

pub mod client;
pub mod core;
pub mod family;

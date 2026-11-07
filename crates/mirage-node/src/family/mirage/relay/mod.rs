//! Mirage Entry/Hop dispatch.
//!
//! - [`onion_peel`] — `RelayMode::OnionPeel`. Per-connection ECDH + AEAD
//!   layer peel, and the only relay mode there is.
//!
//! # UDP onion (removed 2026-09-02)
//!
//! A UDP analogue (`udp_onion_peel`) existed alongside this one, but it was
//! non-forward-secret with no FS counterpart anywhere in this codebase, and
//! its only reachable path (`ListenerKind::UdpRelay` +
//! `Framing::Onion`) is one the monitor never produces. Deleted along with
//! `exit::udp_onion` and `registry::activate_udp_onion` rather than ported
//! to forward-secret — see
//! `docs/mirage/research/v8-onion-deletion-surface-2026-09-02.md`. UDP's
//! remaining onion-unrelated mode, [`udp_listener`], is untouched.
//!
//! # What was here until 2026-09-02
//!
//! `transparent` (blind byte pump), `crypto_verify` (peel one static-keyed
//! byte-cipher skin, then pipe), `udp_transparent` and `byte_cipher_io` were
//! deleted with the relay modes they implemented: neither terminated the
//! tunnel, and both were addressed by a bind port chain hops no longer have.
//!
//! Two modules named after those modes SURVIVED, and the distinction is the
//! whole point of keeping this note. [`udp_crypto_verify`] is called by
//! `udp_relay` on the presence of a BYTE_CIPHER (`udp_relay.rs:102`), not on a
//! relay mode, and [`byte_cipher`] is what it peels with. The byte-cipher
//! skin is an axis of its own and it outlived `RelayMode::CryptoVerify` —
//! deleting these two because of their names would have taken a live UDP path
//! with them.
//!
//! On TCP the same axis is served elsewhere: the onion ENTRY hop peels its
//! skin in `tunnel_tcp::peel_onion_ingress_skin`, which reads
//! `mirage_core::config::ByteCipherMode` directly and never used these
//! helpers.
//!
//! Decoy front and upstream/metrics helpers live alongside.

pub mod byte_cipher;
pub mod onion_fs_peel;
pub mod onion_peel;
pub mod relay_metrics;
pub mod udp_crypto_verify;
pub mod udp_fs_peel;
pub mod udp_listener;
pub mod upstream_pool;
pub mod upstream_select;

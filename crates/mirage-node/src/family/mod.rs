//! Mirage native family — runtime handlers for the Mirage stack.
//!
//! `mirage-node` is a **Mirage-only** binary.
//!
//! Sub-trees:
//! - [`mirage::listener`] — what binds on the socket.
//! - [`mirage::relay`] — Entry/Hop dispatch (Transparent / CryptoVerify /
//!   OnionPeel).
//! - [`mirage::exit`] — Exit dispatch (Direct / Onion / Control).

pub mod mirage;

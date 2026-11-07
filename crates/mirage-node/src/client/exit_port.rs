//! The fleet port — the seam between the OSS edge box and the fleet's mesh
//! machinery.
//!
//! # Why this exists
//!
//! The edge's entrance — accept the customer, assign a face, read the
//! perimeter preamble, decide the outcome — is OSS: it is the product's own
//! wire protocol and it must not change because the fleet reorganised.
//!
//! Carrying a customer's stream INTO the mesh is not: that needs a mesh
//! client, a credential minter and a monitor session. Those are fleet
//! concerns, they live in the `mirage-edge-fleet` crate, and this module
//! is how the OSS entrance asks for them without ever naming them.
//!
//! # The direction of the dependency
//!
//! `mirage-edge-fleet` depends on `mirage-edge`, never the other way round:
//! the OSS crate defines the three ports below, and the fleet crate
//! implements them (its `MeshLeg`, its `DgramMeshLeg`, its
//! `MonitorSessionSet`) and hands the implementations to
//! [`crate::client::entrance::EntranceDeps`] at boot.
//!
//! The error types are deliberately OSS-local and message-shaped: the fleet's
//! own error enums carry mesh-client types (`ChainMuxPoolError`), and the
//! entrance only ever logs them.

use async_trait::async_trait;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::client::chain_store::ExitChoice;
use crate::client::udp_flow::{DatagramSink, DatagramSource};

/// A readable-and-writable trait object.
///
/// `Unpin` is not an auto trait, so a bare
/// `Box<dyn AsyncRead + AsyncWrite + Unpin + Send>` is not a legal trait
/// object; this helper trait carries the two real bounds and the `Unpin`
/// bound stays on the boxed type itself.
pub trait AsyncReadWrite: AsyncRead + AsyncWrite {}

impl<T: AsyncRead + AsyncWrite> AsyncReadWrite for T {}

/// A TCP stream opened into the mesh, ready to be pumped.
pub type MeshStream = Box<dyn AsyncReadWrite + Send + Unpin>;

/// Why a TCP stream into the mesh could not be opened.
#[derive(Debug, Error)]
pub enum StreamOpenError {
    #[error("no chain currently held for exit choice {0}")]
    NoChainHeld(ExitChoice),
    #[error("chain {chain_id}: {message}")]
    Pool { chain_id: String, message: String },
    #[error("chain {0}: no exit hop carries a node id to bind a RoleSigned credential to")]
    NoExitNodeId(String),
    /// The target could not be resolved to an address.
    ///
    /// A local exit (a standalone box that IS the exit) has no chain to walk —
    /// it resolves the target itself, and this is what it says when the name
    /// does not resolve.
    #[error("target {target}: resolution failed: {message}")]
    Resolve { target: String, message: String },
    /// The target was refused by the box's own address policy.
    #[error("target {target}: refused by the box's address policy: {reason}")]
    Refused { target: String, reason: String },
    /// The connection to the target could not be established.
    #[error("target {target}: dialling failed: {message}")]
    Dial { target: String, message: String },
}

/// Why a datagram flow into the mesh could not be opened.
#[derive(Debug, Error)]
pub enum DatagramFlowError {
    #[error("no UDP-chain currently held for exit choice {0}")]
    NoChainHeld(ExitChoice),
    #[error("chain {chain_id}: no exit hop carries a node id to bind a RoleSigned credential to")]
    NoExitNodeId { chain_id: String },
    #[error("chain {chain_id}: dialling the datagram-native FS tunnel failed: {message}")]
    Dial { chain_id: String, message: String },
    #[error("chain {chain_id}: writing the destination datagram failed: {message}")]
    Destination { chain_id: String, message: String },
    /// The target could not be resolved to an address.
    #[error("target {target}: resolution failed: {message}")]
    Resolve { target: String, message: String },
    /// The target was refused by the box's own address policy.
    #[error("target {target}: refused by the box's address policy: {reason}")]
    Refused { target: String, reason: String },
    /// The local datagram socket could not be opened.
    #[error("target {target}: opening the local UDP socket failed: {message}")]
    Local { target: String, message: String },
}

/// Open a TCP stream into the mesh for `exit`, aimed at `target`
/// (`host:port`).
///
/// The fleet's implementation is its `MeshLeg`: it picks a held chain for
/// that exit choice, dials it and reports the attempt on the chain store.
#[async_trait]
pub trait StreamOpener: Send + Sync {
    /// Open a stream, or say why it could not be opened.
    async fn open_stream(&self, exit: &ExitChoice, target: &str) -> Result<MeshStream, StreamOpenError>;
}

/// Open a datagram flow into the mesh for `exit`, aimed at `target`.
///
/// The fleet's implementation is its `DgramMeshLeg`: a UDP-native FS chain
/// of its own, never the TCP onion-mux plane.
///
/// The flow is handed back as the two trait objects the pump already speaks —
/// [`DatagramSink`] and [`DatagramSource`] — not as the mesh's own closed
/// two-variant `DatagramTunnel` enum. The enum is a WIRE shape: both of its
/// arms are the FS-chain's own datagram tunnel, and there is no third arm a
/// standalone box could use for a plain local socket. The traits are the
/// seam the pump was written against, so a local exit can join the same pump
/// without the wire shape leaking into it.
#[async_trait]
pub trait DatagramFlowOpener: Send + Sync {
    /// Open the flow, or say why it could not be opened.
    async fn open_datagram_flow(
        &self,
        exit: &ExitChoice,
        target: &str,
    ) -> Result<(DatagramSinkBox, DatagramSourceBox), DatagramFlowError>;
}

/// A datagram sink, boxed — one end of an opened datagram flow.
pub type DatagramSinkBox = Box<dyn DatagramSink + Send>;

/// A datagram source, boxed — the other end of an opened datagram flow.
pub type DatagramSourceBox = Box<dyn DatagramSource + Send>;

/// The exit countries this box can actually serve right now.
///
/// The fleet's implementation is its `MonitorSessionSet`: the union of the
/// countries its live monitor sessions report.
#[async_trait]
pub trait ExitCountryOracle: Send + Sync {
    /// The servable exit countries, sorted and deduplicated.
    async fn servable_exit_countries(&self) -> Vec<String>;
}

//! Byte cipher layer — server-side (mirage-node).
//!
//! The L1 server applies [`ByteCipher::unwrap`] on every inbound chunk before
//! dispatching to the L2 protocol chain.
//!
//! ByteCipher never decrypts the L2 content — it works on opaque byte slices.
//!
//! ## Design
//!
//! [`ByteCipher`] is **stateful** and **per-session**:
//! - `ObfuscateAll` tracks an inbound packet counter.
//! - `ValidateFirst` / `StripFirst` track whether the first packet has already
//!   been processed.

use mirage_core::{
    config::{ByteCipherMode, ObfuscationAlgorithm},
    error::MirageError,
};

use chacha20::ChaCha8;
use chacha20::cipher::{KeyIvInit, StreamCipher};

// ── Error type ────────────────────────────────────────────────────────────────

/// Errors produced by the byte cipher unwrap path.
#[derive(Debug, thiserror::Error)]
pub enum ByteCipherError {
    /// The first packet did not begin with the expected 16-byte magic.
    #[error("byte cipher magic mismatch: session rejected")]
    MagicMismatch,
    /// The packet was too short to contain the required header.
    #[error("byte cipher packet too short: need {needed} bytes, got {got}")]
    TooShort { needed: usize, got: usize },
}

impl From<ByteCipherError> for MirageError {
    fn from(e: ByteCipherError) -> Self {
        MirageError::Protocol(e.to_string())
    }
}

// ── ByteCipher ────────────────────────────────────────────────────────────────

/// Stateful byte cipher server-side — one instance per session.
///
/// For `ValidateFirst` / `StripFirst`, the first-packet flag is set after
/// the first packet is processed; remaining bytes flow through unchanged.
pub struct ByteCipher {
    mode: ByteCipherMode,
    /// Packet counter for the inbound (unwrap) direction.
    in_counter: u64,
    /// Whether the first packet has been processed (ValidateFirst / StripFirst).
    first_done: bool,
}

impl ByteCipher {
    /// Create a new cipher for the given mode.  Counter starts at 0.
    pub fn new(mode: ByteCipherMode) -> Self {
        Self {
            mode,
            in_counter: 0,
            first_done: false,
        }
    }

    /// Server side: unwrap an inbound byte slice received from the client.
    ///
    /// Returns `Ok(payload)` with any header stripped and/or XOR removed.
    /// Returns `Err(ByteCipherError::MagicMismatch)` to signal the session should be
    /// dropped.
    pub fn unwrap(&mut self, wire_bytes: &[u8]) -> Result<Vec<u8>, ByteCipherError> {
        match &self.mode {
            ByteCipherMode::Raw => Ok(wire_bytes.to_vec()),

            ByteCipherMode::ValidateFirst { magic } => {
                if self.first_done {
                    return Ok(wire_bytes.to_vec());
                }
                self.first_done = true;
                if wire_bytes.len() < 16 {
                    return Err(ByteCipherError::TooShort { needed: 16, got: wire_bytes.len() });
                }
                if wire_bytes[..16] != *magic {
                    return Err(ByteCipherError::MagicMismatch);
                }
                // Keep everything including magic — server may still want to
                // see the payload that followed the magic in the first packet.
                Ok(wire_bytes.to_vec())
            }

            ByteCipherMode::StripFirst { magic, junk_size } => {
                if self.first_done {
                    return Ok(wire_bytes.to_vec());
                }
                self.first_done = true;
                let header_len = 16 + *junk_size as usize;
                if wire_bytes.len() < header_len {
                    return Err(ByteCipherError::TooShort {
                        needed: header_len,
                        got: wire_bytes.len(),
                    });
                }
                if wire_bytes[..16] != *magic {
                    return Err(ByteCipherError::MagicMismatch);
                }
                // Strip magic + junk, return the payload portion.
                Ok(wire_bytes[header_len..].to_vec())
            }

            ByteCipherMode::ObfuscateAll { algorithm, obf_key } => {
                let counter = self.in_counter;
                self.in_counter += 1;
                deobfuscate(wire_bytes, counter, algorithm, obf_key)
            }
        }
    }
}

// ── Obfuscation helpers ───────────────────────────────────────────────────────

/// Strip the header from `wire_bytes` and XOR/decrypt back to plaintext.
fn deobfuscate(
    wire_bytes: &[u8],
    _counter: u64,
    algorithm: &ObfuscationAlgorithm,
    key: &[u8; 32],
) -> Result<Vec<u8>, ByteCipherError> {
    match algorithm {
        ObfuscationAlgorithm::XorBlake3 => {
            if wire_bytes.len() < 4 {
                return Err(ByteCipherError::TooShort { needed: 4, got: wire_bytes.len() });
            }
            let salt: [u8; 4] = wire_bytes[..4].try_into().expect("slice is 4 bytes");
            let ciphertext = &wire_bytes[4..];
            let keystream = blake3_keystream(&salt, key, ciphertext.len());
            let plaintext = ciphertext.iter().zip(keystream.iter()).map(|(b, k)| b ^ k).collect();
            Ok(plaintext)
        }
        ObfuscationAlgorithm::ChaCha8 => {
            if wire_bytes.len() < 8 {
                return Err(ByteCipherError::TooShort { needed: 8, got: wire_bytes.len() });
            }
            let nonce_bytes: [u8; 8] = wire_bytes[..8].try_into().expect("slice is 8 bytes");
            let mut plaintext = wire_bytes[8..].to_vec();
            chacha8_apply(key, &nonce_bytes, &mut plaintext);
            Ok(plaintext)
        }
    }
}

/// Produce `len` bytes of keystream via `BLAKE3(salt || key)`.
fn blake3_keystream(salt: &[u8; 4], key: &[u8; 32], len: usize) -> Vec<u8> {
    // BLAKE3 keyed hash: key = obf_key, data = salt bytes.
    // Produces 32 bytes; for payloads > 32 bytes we chain with an incremented
    // block counter appended to the salt.
    let mut out = Vec::with_capacity(len);
    let mut block: u32 = 0;
    while out.len() < len {
        let mut data = Vec::with_capacity(4 + 4);
        data.extend_from_slice(salt);
        data.extend_from_slice(&block.to_le_bytes());
        let hash = blake3::keyed_hash(key, &data);
        out.extend_from_slice(hash.as_bytes());
        block += 1;
    }
    out.truncate(len);
    out
}

/// Apply ChaCha8 in-place (encrypt = decrypt for stream cipher).
///
/// Key: 32 bytes.  Nonce: 8-byte little-endian counter, zero-padded to 12 bytes
/// as required by the `chacha20` crate's `ChaCha8` (96-bit nonce variant).
fn chacha8_apply(key: &[u8; 32], nonce_le_8: &[u8; 8], buf: &mut [u8]) {
    // ChaCha8 uses a 96-bit (12-byte) nonce.  We left-pad the 8-byte counter.
    let mut nonce = [0u8; 12];
    nonce[4..].copy_from_slice(nonce_le_8);
    let mut cipher = ChaCha8::new(key.into(), &nonce.into());
    cipher.apply_keystream(buf);
}

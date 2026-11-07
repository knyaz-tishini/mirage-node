use mirage_core::error::MirageError;

/// Decode a 64-character lowercase hex string into a 32-byte array.
///
/// Returns `MirageError::Config` if the string is the wrong length or
/// contains non-hex characters.
pub fn decode_hex_key(hex: &str) -> Result<[u8; 32], MirageError> {
    if hex.len() != 64 {
        return Err(MirageError::Config(format!(
            "expected 64 hex chars for a 32-byte key, got {}",
            hex.len()
        )));
    }
    let mut out = [0u8; 32];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        let hi = hex_nibble(chunk[0]).map_err(|e| MirageError::Config(e))?;
        let lo = hex_nibble(chunk[1]).map_err(|e| MirageError::Config(e))?;
        out[i] = (hi << 4) | lo;
    }
    Ok(out)
}

fn hex_nibble(b: u8) -> Result<u8, String> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(format!("invalid hex character: '{}'", b as char)),
    }
}

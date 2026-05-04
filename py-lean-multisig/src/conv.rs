use backend::{KoalaBear, PrimeField32};
use pyo3::prelude::*;
use xmss::MESSAGE_LEN_FE;

use crate::error::SerializationError;

/// 32 bytes = 8 little-endian u32s, one per [KoalaBear; 8] field element.
/// Each u32's high bit must be clear (value < 2^31), since KoalaBear is a
/// 31-bit prime.
pub const MESSAGE_BYTES: usize = MESSAGE_LEN_FE * 4;
const _: () = assert!(MESSAGE_BYTES == 32);

/// Convert 32 bytes -> `[KoalaBear; 8]`.
///
/// Returns `SerializationError` on:
///   - wrong length (not exactly 32 bytes)
///   - any u32 with high bit set (value not representable in KoalaBear)
pub fn message_from_bytes(bytes: &[u8]) -> PyResult<[KoalaBear; MESSAGE_LEN_FE]> {
    if bytes.len() != MESSAGE_BYTES {
        return Err(SerializationError::new_err(format!(
            "message must be exactly {} bytes, got {}",
            MESSAGE_BYTES,
            bytes.len()
        )));
    }
    let mut out = [KoalaBear::default(); MESSAGE_LEN_FE];
    for (i, chunk) in bytes.chunks_exact(4).enumerate() {
        let v = u32::from_le_bytes(chunk.try_into().unwrap());
        if v & 0x8000_0000 != 0 {
            return Err(SerializationError::new_err(format!(
                "message u32 at index {} has high bit set (0x{:08x}); each value must be < 2^31",
                i, v
            )));
        }
        out[i] = KoalaBear::new(v);
    }
    Ok(out)
}

/// Convert `[KoalaBear; 8]` -> 32 bytes (LE u32s).
pub fn message_to_bytes(msg: &[KoalaBear; MESSAGE_LEN_FE]) -> [u8; MESSAGE_BYTES] {
    let mut out = [0u8; MESSAGE_BYTES];
    for (i, fe) in msg.iter().enumerate() {
        let v: u32 = fe.as_canonical_u32();
        out[i * 4..(i + 1) * 4].copy_from_slice(&v.to_le_bytes());
    }
    out
}

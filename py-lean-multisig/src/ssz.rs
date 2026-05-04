use backend::{KoalaBear, PrimeField32};
use pyo3::prelude::*;
use xmss::{XmssPublicKey, XMSS_DIGEST_LEN, PUBLIC_PARAM_LEN_FE};

use crate::error::SerializationError;

/// SSZ-encoded `XmssPublicKey`: flat concatenation of merkle_root (4 F)
/// then public_param (4 F), each field element as 4 LE bytes with
/// high bit clear. Fixed length = 32 bytes.
pub const XMSS_PUBKEY_BYTES: usize = (XMSS_DIGEST_LEN + PUBLIC_PARAM_LEN_FE) * 4;
const _: () = assert!(XMSS_PUBKEY_BYTES == 32);

/// Encode one `KoalaBear` to 4 LE bytes via its canonical u32 representation.
fn fe_to_bytes(fe: KoalaBear) -> [u8; 4] {
    fe.as_canonical_u32().to_le_bytes()
}

/// Decode 4 LE bytes to a `KoalaBear`. The high bit must be clear (KoalaBear
/// is a 31-bit prime); a value with the high bit set is malformed input.
fn fe_from_bytes(bytes: [u8; 4]) -> PyResult<KoalaBear> {
    let v = u32::from_le_bytes(bytes);
    if v & 0x8000_0000 != 0 {
        return Err(SerializationError::new_err(format!(
            "field element u32 has high bit set: 0x{:08x}", v
        )));
    }
    Ok(KoalaBear::new(v))
}

pub fn pubkey_to_ssz(pk: &XmssPublicKey) -> [u8; XMSS_PUBKEY_BYTES] {
    let mut out = [0u8; XMSS_PUBKEY_BYTES];
    for (i, fe) in pk.merkle_root.iter().enumerate() {
        out[i * 4..(i + 1) * 4].copy_from_slice(&fe_to_bytes(*fe));
    }
    let off = XMSS_DIGEST_LEN * 4;
    for (i, fe) in pk.public_param.iter().enumerate() {
        out[off + i * 4..off + (i + 1) * 4].copy_from_slice(&fe_to_bytes(*fe));
    }
    out
}

pub fn pubkey_from_ssz(bytes: &[u8]) -> PyResult<XmssPublicKey> {
    if bytes.len() != XMSS_PUBKEY_BYTES {
        return Err(SerializationError::new_err(format!(
            "XmssPublicKey SSZ must be {} bytes, got {}",
            XMSS_PUBKEY_BYTES,
            bytes.len()
        )));
    }
    let mut merkle_root = [KoalaBear::default(); XMSS_DIGEST_LEN];
    for i in 0..XMSS_DIGEST_LEN {
        merkle_root[i] = fe_from_bytes(bytes[i * 4..(i + 1) * 4].try_into().unwrap())?;
    }
    let mut public_param = [KoalaBear::default(); PUBLIC_PARAM_LEN_FE];
    let off = XMSS_DIGEST_LEN * 4;
    for i in 0..PUBLIC_PARAM_LEN_FE {
        public_param[i] = fe_from_bytes(bytes[off + i * 4..off + (i + 1) * 4].try_into().unwrap())?;
    }
    Ok(XmssPublicKey { merkle_root, public_param })
}

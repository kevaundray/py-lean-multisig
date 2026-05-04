use backend::{KoalaBear, PrimeField32};
use pyo3::prelude::*;
use xmss::{
    XmssPublicKey, XmssSignature, WotsSignature, LOG_LIFETIME,
    PUBLIC_PARAM_LEN_FE, RANDOMNESS_LEN_FE, V, XMSS_DIGEST_LEN,
};

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

/// SSZ-encoded `XmssSignature`: flat concatenation of the WOTS signature
/// (randomness then chain_tips) followed by the Merkle authentication path.
///
/// Layout:
///   [0 .. RANDOMNESS_LEN_FE * 4]                     WOTS randomness  (6 F = 24 B)
///   [.. + V * XMSS_DIGEST_LEN * 4]                   WOTS chain_tips  (42 * 4 F = 672 B)
///   [.. + LOG_LIFETIME * XMSS_DIGEST_LEN * 4]        merkle_proof     (32 * 4 F = 512 B)
///
/// Total = 24 + 672 + 512 = 1208 bytes.
const WOTS_SIGNATURE_BYTES: usize = (RANDOMNESS_LEN_FE + V * XMSS_DIGEST_LEN) * 4;
pub const XMSS_SIGNATURE_BYTES: usize = WOTS_SIGNATURE_BYTES + LOG_LIFETIME * XMSS_DIGEST_LEN * 4;
const _: () = assert!(WOTS_SIGNATURE_BYTES == 696);
const _: () = assert!(XMSS_SIGNATURE_BYTES == 1208);

/// Encode one `Digest = [KoalaBear; XMSS_DIGEST_LEN]` into `out` (must be 16 B).
fn digest_to_bytes(d: &[KoalaBear; XMSS_DIGEST_LEN], out: &mut [u8]) {
    debug_assert_eq!(out.len(), XMSS_DIGEST_LEN * 4);
    for (i, fe) in d.iter().enumerate() {
        out[i * 4..(i + 1) * 4].copy_from_slice(&fe_to_bytes(*fe));
    }
}

/// Decode 16 bytes into one `Digest`. Each 4-byte group must be a canonical
/// KoalaBear (high bit clear).
fn digest_from_bytes(bytes: &[u8]) -> PyResult<[KoalaBear; XMSS_DIGEST_LEN]> {
    debug_assert_eq!(bytes.len(), XMSS_DIGEST_LEN * 4);
    let mut out = [KoalaBear::default(); XMSS_DIGEST_LEN];
    for i in 0..XMSS_DIGEST_LEN {
        out[i] = fe_from_bytes(bytes[i * 4..(i + 1) * 4].try_into().unwrap())?;
    }
    Ok(out)
}

pub fn signature_to_ssz(sig: &XmssSignature) -> Vec<u8> {
    let mut out = vec![0u8; XMSS_SIGNATURE_BYTES];

    // [0 .. RANDOMNESS_LEN_FE * 4]: WOTS randomness
    let randomness_end = RANDOMNESS_LEN_FE * 4;
    for (i, fe) in sig.wots_signature.randomness.iter().enumerate() {
        out[i * 4..(i + 1) * 4].copy_from_slice(&fe_to_bytes(*fe));
    }
    // [.. .. .. + V * XMSS_DIGEST_LEN * 4]: WOTS chain_tips (V digests)
    let tips_start = randomness_end;
    for (i, d) in sig.wots_signature.chain_tips.iter().enumerate() {
        let off = tips_start + i * XMSS_DIGEST_LEN * 4;
        digest_to_bytes(d, &mut out[off..off + XMSS_DIGEST_LEN * 4]);
    }
    // [WOTS_SIGNATURE_BYTES .. END]: Merkle proof (LOG_LIFETIME digests)
    let proof_start = WOTS_SIGNATURE_BYTES;
    debug_assert_eq!(sig.merkle_proof.len(), LOG_LIFETIME);
    for (i, d) in sig.merkle_proof.iter().enumerate() {
        let off = proof_start + i * XMSS_DIGEST_LEN * 4;
        digest_to_bytes(d, &mut out[off..off + XMSS_DIGEST_LEN * 4]);
    }
    out
}

pub fn signature_from_ssz(bytes: &[u8]) -> PyResult<XmssSignature> {
    if bytes.len() != XMSS_SIGNATURE_BYTES {
        return Err(SerializationError::new_err(format!(
            "XmssSignature SSZ must be {} bytes, got {}",
            XMSS_SIGNATURE_BYTES,
            bytes.len()
        )));
    }

    // randomness: [F; RANDOMNESS_LEN_FE]
    let mut randomness = [KoalaBear::default(); RANDOMNESS_LEN_FE];
    for i in 0..RANDOMNESS_LEN_FE {
        randomness[i] = fe_from_bytes(bytes[i * 4..(i + 1) * 4].try_into().unwrap())?;
    }
    // chain_tips: [Digest; V] — fixed-length array, build directly
    let tips_start = RANDOMNESS_LEN_FE * 4;
    let mut chain_tips = [[KoalaBear::default(); XMSS_DIGEST_LEN]; V];
    for i in 0..V {
        let off = tips_start + i * XMSS_DIGEST_LEN * 4;
        chain_tips[i] = digest_from_bytes(&bytes[off..off + XMSS_DIGEST_LEN * 4])?;
    }
    // merkle_proof: Vec<Digest> of length LOG_LIFETIME
    let proof_start = WOTS_SIGNATURE_BYTES;
    let mut merkle_proof: Vec<[KoalaBear; XMSS_DIGEST_LEN]> = Vec::with_capacity(LOG_LIFETIME);
    for i in 0..LOG_LIFETIME {
        let off = proof_start + i * XMSS_DIGEST_LEN * 4;
        merkle_proof.push(digest_from_bytes(&bytes[off..off + XMSS_DIGEST_LEN * 4])?);
    }

    let wots_signature = WotsSignature { chain_tips, randomness };
    Ok(XmssSignature { wots_signature, merkle_proof })
}

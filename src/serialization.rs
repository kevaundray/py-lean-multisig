//! Each [`KoalaBear`] field element fits in 31 bits (the prime is
//! `2^31 - 2^24 + 1`), so we encode it as a 4-byte little-endian `u32`
//! whose high bit is always clear. Decoding rejects any 4 bytes whose
//! interpreted `u32` has the high bit set.

use backend::{KoalaBear, PrimeField32};
use pyo3::prelude::*;
use rec_aggregation::AggregatedXMSS;
use xmss::{
    WotsSignature, XmssPublicKey, XmssSignature, PUBLIC_PARAM_LEN_FE, RANDOMNESS_LEN_FE, V,
    XMSS_DIGEST_LEN,
};

use crate::error::SerializationError;

/// 4 bytes per field element × 4 (merkle_root) + 4 (public_param) = 32 bytes.
pub const PUBLIC_KEY_BYTES: usize = (XMSS_DIGEST_LEN + PUBLIC_PARAM_LEN_FE) * 4;
const _: () = assert!(PUBLIC_KEY_BYTES == 32);

/// Fixed portion of a signature on the wire:
///   chain_tips: V × XMSS_DIGEST_LEN field elements = 42 × 4 × 4 = 672 bytes
///   randomness: RANDOMNESS_LEN_FE field elements      = 6 × 4     = 24  bytes
///   merkle_proof_len: u32 LE                                       = 4   bytes
/// Then: merkle_proof_len × XMSS_DIGEST_LEN field elements (16 bytes each).
const SIG_CHAIN_TIPS_BYTES: usize = V * XMSS_DIGEST_LEN * 4;
const SIG_RANDOMNESS_BYTES: usize = RANDOMNESS_LEN_FE * 4;
const SIG_FIXED_BYTES: usize = SIG_CHAIN_TIPS_BYTES + SIG_RANDOMNESS_BYTES + 4;
const DIGEST_BYTES: usize = XMSS_DIGEST_LEN * 4;

fn fe_to_bytes(fe: KoalaBear) -> [u8; 4] {
    fe.as_canonical_u32().to_le_bytes()
}

fn fe_from_bytes(bytes: [u8; 4]) -> PyResult<KoalaBear> {
    let v = u32::from_le_bytes(bytes);
    if v & 0x8000_0000 != 0 {
        return Err(SerializationError::new_err(format!(
            "field element u32 has high bit set: 0x{:08x}",
            v
        )));
    }
    Ok(KoalaBear::new(v))
}

pub fn encode_public_key(pk: &XmssPublicKey) -> [u8; PUBLIC_KEY_BYTES] {
    let mut out = [0u8; PUBLIC_KEY_BYTES];
    for (i, fe) in pk.merkle_root.iter().enumerate() {
        out[i * 4..(i + 1) * 4].copy_from_slice(&fe_to_bytes(*fe));
    }
    let off = XMSS_DIGEST_LEN * 4;
    for (i, fe) in pk.public_param.iter().enumerate() {
        out[off + i * 4..off + (i + 1) * 4].copy_from_slice(&fe_to_bytes(*fe));
    }
    out
}

pub fn decode_public_key(bytes: &[u8]) -> PyResult<XmssPublicKey> {
    if bytes.len() != PUBLIC_KEY_BYTES {
        return Err(SerializationError::new_err(format!(
            "PublicKey must be exactly {} bytes, got {}",
            PUBLIC_KEY_BYTES,
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
    Ok(XmssPublicKey {
        merkle_root,
        public_param,
    })
}

pub fn encode_signature(sig: &XmssSignature) -> Vec<u8> {
    let proof_len: u32 = sig
        .merkle_proof
        .len()
        .try_into()
        .expect("merkle_proof length fits in u32 (bounded by LOG_LIFETIME = 32)");
    let mut out = Vec::with_capacity(SIG_FIXED_BYTES + sig.merkle_proof.len() * DIGEST_BYTES);
    for digest in &sig.wots_signature.chain_tips {
        for fe in digest {
            out.extend_from_slice(&fe_to_bytes(*fe));
        }
    }
    for fe in &sig.wots_signature.randomness {
        out.extend_from_slice(&fe_to_bytes(*fe));
    }
    out.extend_from_slice(&proof_len.to_le_bytes());
    for digest in &sig.merkle_proof {
        for fe in digest {
            out.extend_from_slice(&fe_to_bytes(*fe));
        }
    }
    out
}

pub fn decode_signature(bytes: &[u8]) -> PyResult<XmssSignature> {
    if bytes.len() < SIG_FIXED_BYTES {
        return Err(SerializationError::new_err(format!(
            "Signature must be at least {} bytes, got {}",
            SIG_FIXED_BYTES,
            bytes.len()
        )));
    }
    let mut pos = 0;
    let mut chain_tips = [[KoalaBear::default(); XMSS_DIGEST_LEN]; V];
    for digest in &mut chain_tips {
        for fe in digest.iter_mut() {
            *fe = fe_from_bytes(bytes[pos..pos + 4].try_into().unwrap())?;
            pos += 4;
        }
    }
    let mut randomness = [KoalaBear::default(); RANDOMNESS_LEN_FE];
    for fe in &mut randomness {
        *fe = fe_from_bytes(bytes[pos..pos + 4].try_into().unwrap())?;
        pos += 4;
    }
    let proof_len = u32::from_le_bytes(bytes[pos..pos + 4].try_into().unwrap()) as usize;
    pos += 4;
    let expected_total = SIG_FIXED_BYTES + proof_len * DIGEST_BYTES;
    if bytes.len() != expected_total {
        return Err(SerializationError::new_err(format!(
            "Signature length mismatch: header claims {} merkle nodes ({} bytes total), got {}",
            proof_len,
            expected_total,
            bytes.len()
        )));
    }
    let mut merkle_proof = Vec::with_capacity(proof_len);
    for _ in 0..proof_len {
        let mut digest = [KoalaBear::default(); XMSS_DIGEST_LEN];
        for fe in &mut digest {
            *fe = fe_from_bytes(bytes[pos..pos + 4].try_into().unwrap())?;
            pos += 4;
        }
        merkle_proof.push(digest);
    }
    Ok(XmssSignature {
        wots_signature: WotsSignature {
            chain_tips,
            randomness,
        },
        merkle_proof,
    })
}

/// Thin wrapper over upstream's `AggregatedXMSS::serialize`.
/// Lives here for symmetry with the other `encode_*`/`decode_*` pairs.
pub fn encode_aggregated_signature(agg: &AggregatedXMSS) -> Vec<u8> {
    agg.serialize()
}

pub fn decode_aggregated_signature(bytes: &[u8]) -> PyResult<AggregatedXMSS> {
    AggregatedXMSS::deserialize(bytes).ok_or_else(|| {
        SerializationError::new_err(
            "failed to decode AggregatedSignature",
        )
    })
}

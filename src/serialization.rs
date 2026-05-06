//! Each [`KoalaBear`] field element fits in 31 bits (the prime is
//! `2^31 - 2^24 + 1`), so we encode it as a 4-byte little-endian `u32`
//! whose high bit is always clear. Decoding rejects any 4 bytes whose
//! interpreted `u32` has the high bit set.

use backend::{KoalaBear, PrimeField32};
use pyo3::prelude::*;
use rec_aggregation::AggregatedXMSS;
use xmss::{
    WotsSignature, XmssPublicKey, XmssSignature, LOG_LIFETIME, PUBLIC_PARAM_LEN_FE,
    RANDOMNESS_LEN_FE, V, XMSS_DIGEST_LEN,
};

use crate::error::SerializationError;

pub const PUBLIC_KEY_BYTES: usize = (XMSS_DIGEST_LEN + PUBLIC_PARAM_LEN_FE) * 4;
const _: () = assert!(PUBLIC_KEY_BYTES == 32);

/// Wire layout for a signature: [chain_tips | randomness | proof_len: u32 LE | merkle_proof].
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

fn write_fes(out: &mut Vec<u8>, fes: &[KoalaBear]) {
    for fe in fes {
        out.extend_from_slice(&fe_to_bytes(*fe));
    }
}

/// Read N field elements (4N bytes) from `bytes` starting at `*pos`, advancing
/// `*pos` past them. Caller must have length-checked the slice already.
pub(crate) fn read_fes<const N: usize>(
    bytes: &[u8],
    pos: &mut usize,
) -> PyResult<[KoalaBear; N]> {
    let mut out = [KoalaBear::default(); N];
    for fe in &mut out {
        *fe = fe_from_bytes(bytes[*pos..*pos + 4].try_into().unwrap())?;
        *pos += 4;
    }
    Ok(out)
}

pub fn encode_public_key(pk: &XmssPublicKey) -> [u8; PUBLIC_KEY_BYTES] {
    let mut out = [0u8; PUBLIC_KEY_BYTES];
    for (i, fe) in pk.flaten().iter().enumerate() {
        out[i * 4..(i + 1) * 4].copy_from_slice(&fe_to_bytes(*fe));
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
    let mut pos = 0;
    let merkle_root = read_fes::<XMSS_DIGEST_LEN>(bytes, &mut pos)?;
    let public_param = read_fes::<PUBLIC_PARAM_LEN_FE>(bytes, &mut pos)?;
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
        write_fes(&mut out, digest);
    }
    write_fes(&mut out, &sig.wots_signature.randomness);
    out.extend_from_slice(&proof_len.to_le_bytes());
    for digest in &sig.merkle_proof {
        write_fes(&mut out, digest);
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
        *digest = read_fes::<XMSS_DIGEST_LEN>(bytes, &mut pos)?;
    }
    let randomness = read_fes::<RANDOMNESS_LEN_FE>(bytes, &mut pos)?;
    let proof_len = u32::from_le_bytes(bytes[pos..pos + 4].try_into().unwrap()) as usize;
    pos += 4;
    // Reject before allocating: an attacker-controlled u32 here could otherwise
    // request a multi-GB Vec before the length-mismatch check.
    if proof_len > LOG_LIFETIME {
        return Err(SerializationError::new_err(format!(
            "Signature merkle proof too long: {} entries (max {})",
            proof_len, LOG_LIFETIME
        )));
    }
    let expected_total = SIG_FIXED_BYTES + proof_len * DIGEST_BYTES;
    if bytes.len() != expected_total {
        return Err(SerializationError::new_err(format!(
            "Signature length mismatch: proof length prefix declares {} merkle nodes ({} bytes expected), got {}",
            proof_len,
            expected_total,
            bytes.len()
        )));
    }
    let mut merkle_proof = Vec::with_capacity(proof_len);
    for _ in 0..proof_len {
        merkle_proof.push(read_fes::<XMSS_DIGEST_LEN>(bytes, &mut pos)?);
    }
    Ok(XmssSignature {
        wots_signature: WotsSignature {
            chain_tips,
            randomness,
        },
        merkle_proof,
    })
}

pub fn encode_aggregated_signature(agg: &AggregatedXMSS) -> Vec<u8> {
    agg.serialize()
}

pub fn decode_aggregated_signature(bytes: &[u8]) -> PyResult<AggregatedXMSS> {
    AggregatedXMSS::deserialize(bytes)
        .ok_or_else(|| SerializationError::new_err("failed to decode AggregatedSignature"))
}

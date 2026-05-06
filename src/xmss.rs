use std::sync::Arc;

use pyo3::prelude::*;
use rand::rngs::StdRng;
use rand::SeedableRng;
use xmss::{xmss_key_gen, xmss_sign, xmss_verify, XmssKeyGenError, XmssSignatureError, XmssVerifyError};

use crate::error::{KeygenError, SerializationError, SignError, VerifyError};
use crate::types::{message_from_bytes, PyPublicKey, PySecretKey, PySignature};

#[pyfunction]
pub fn keygen(seed: &[u8], slot_start: u32, slot_end: u32) -> PyResult<(PySecretKey, PyPublicKey)> {
    let seed_arr: [u8; 32] = seed.try_into().map_err(|_| {
        SerializationError::new_err(format!("seed must be 32 bytes, got {}", seed.len()))
    })?;
    let (sk, pk) = xmss_key_gen(seed_arr, slot_start, slot_end).map_err(|e| match e {
        XmssKeyGenError::InvalidRange => KeygenError::new_err(format!(
            "invalid slot range: start={}, end={}",
            slot_start, slot_end
        )),
    })?;
    let py_pk = PyPublicKey { inner: Arc::new(pk) };
    let py_sk = PySecretKey {
        inner: Arc::new(sk),
        slot_start,
        slot_end,
    };
    Ok((py_sk, py_pk))
}

#[pyfunction]
#[pyo3(signature = (sk, message, slot, *, rng_seed=None))]
pub fn sign(
    sk: &PySecretKey,
    message: &[u8],
    slot: u32,
    rng_seed: Option<&[u8]>,
) -> PyResult<PySignature> {
    let msg_fe = message_from_bytes(message)?;
    let mut rng = match rng_seed {
        Some(s) => {
            let arr: [u8; 32] = s.try_into().map_err(|_| {
                SerializationError::new_err(format!("rng_seed must be 32 bytes, got {}", s.len()))
            })?;
            StdRng::from_seed(arr)
        }
        None => rand::make_rng::<StdRng>(),
    };
    let sig = xmss_sign(&mut rng, &sk.inner, &msg_fe, slot).map_err(|e| match e {
        XmssSignatureError::SlotOutOfRange => SignError::new_err(format!(
            "slot {} not in key range [{}, {}]",
            slot, sk.slot_start, sk.slot_end
        )),
    })?;
    Ok(PySignature { inner: Arc::new(sig) })
}

#[pyfunction]
pub fn verify(pk: &PyPublicKey, message: &[u8], sig: &PySignature, slot: u32) -> PyResult<()> {
    let msg_fe = message_from_bytes(message)?;
    xmss_verify(&pk.inner, &msg_fe, &sig.inner, slot).map_err(|e| match e {
        XmssVerifyError::InvalidWots => VerifyError::new_err("WOTS recovery failed"),
        XmssVerifyError::InvalidMerklePath => {
            VerifyError::new_err("Merkle path does not match public key root")
        }
    })?;
    Ok(())
}

use std::sync::Arc;

use pyo3::prelude::*;
use rand::rngs::StdRng;
use rand::SeedableRng;
use xmss::{xmss_key_gen, xmss_sign, xmss_verify, XmssKeyGenError, XmssSignatureError, XmssVerifyError};

use crate::conv::message_from_bytes;
use crate::error::{KeygenError, SerializationError, SignError, VerifyError};
use crate::panic::catch;
use crate::types::{PyPublicKey, PySecretKey, PySignature};

#[pyfunction]
pub fn keygen(seed: &[u8], slot_start: u32, slot_end: u32) -> PyResult<(PySecretKey, PyPublicKey)> {
    let seed_arr: [u8; 32] = seed.try_into().map_err(|_| {
        SerializationError::new_err(format!("seed must be 32 bytes, got {}", seed.len()))
    })?;
    catch(
        || {
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
                pk: py_pk.clone(),
            };
            Ok((py_sk, py_pk))
        },
        |m| KeygenError::new_err(format!("keygen panicked: {}", m)),
    )
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
    let seed_arr: Option<[u8; 32]> = match rng_seed {
        Some(s) => Some(s.try_into().map_err(|_| {
            SerializationError::new_err(format!("rng_seed must be 32 bytes, got {}", s.len()))
        })?),
        None => None,
    };
    let slot_start = sk.slot_start;
    let slot_end = sk.slot_end;
    let inner = sk.inner.clone();
    catch(
        || {
            let mut rng = match seed_arr {
                Some(arr) => StdRng::from_seed(arr),
                None => rand::make_rng::<StdRng>(),
            };
            let result = xmss_sign(&mut rng, &inner, &msg_fe, slot);
            let sig = result.map_err(|e| match e {
                XmssSignatureError::SlotOutOfRange => SignError::new_err(format!(
                    "slot {} not in key range [{}, {}]",
                    slot, slot_start, slot_end
                )),
            })?;
            Ok(PySignature { inner: Arc::new(sig) })
        },
        |m| SignError::new_err(format!("sign panicked: {}", m)),
    )
}

#[pyfunction]
pub fn verify(pk: &PyPublicKey, message: &[u8], sig: &PySignature, slot: u32) -> PyResult<()> {
    let msg_fe = message_from_bytes(message)?;
    let pk_inner = pk.inner.clone();
    let sig_inner = sig.inner.clone();
    catch(
        || {
            xmss_verify(&pk_inner, &msg_fe, &sig_inner, slot).map_err(|e| match e {
                XmssVerifyError::InvalidWots => VerifyError::new_err("WOTS recovery failed"),
                XmssVerifyError::InvalidMerklePath => {
                    VerifyError::new_err("Merkle path does not match public key root")
                }
            })?;
            Ok(())
        },
        |m| VerifyError::new_err(format!("verify panicked: {}", m)),
    )
}

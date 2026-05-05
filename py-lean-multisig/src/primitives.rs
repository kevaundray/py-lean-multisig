use std::sync::Arc;

use pyo3::prelude::*;
use xmss::{xmss_key_gen, XmssKeyGenError};

use crate::error::{KeygenError, SerializationError};
use crate::panic::catch;
use crate::types::{PyPublicKey, PySecretKey};

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

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::Arc;

use pyo3::prelude::*;
use pyo3::pyclass::CompareOp;
use pyo3::types::PyBytes;
use xmss::{XmssPublicKey, XmssSecretKey, XmssSignature};

use crate::ssz::{pubkey_from_ssz, pubkey_to_ssz, signature_from_ssz, signature_to_ssz};

fn short_hex(bytes: &[u8]) -> String {
    if bytes.len() <= 8 {
        format!("0x{}", hex::encode(bytes))
    } else {
        format!(
            "0x{}…{}",
            hex::encode(&bytes[..4]),
            hex::encode(&bytes[bytes.len() - 4..])
        )
    }
}

#[pyclass(name = "PublicKey", frozen, module = "py_lean_multisig")]
#[derive(Clone)]
pub struct PyPublicKey {
    pub inner: Arc<XmssPublicKey>,
}

#[pymethods]
impl PyPublicKey {
    #[classmethod]
    fn from_ssz(_cls: &Bound<'_, pyo3::types::PyType>, data: &[u8]) -> PyResult<Self> {
        Ok(Self {
            inner: Arc::new(pubkey_from_ssz(data)?),
        })
    }

    fn to_ssz<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &pubkey_to_ssz(&self.inner))
    }

    fn __repr__(&self) -> String {
        format!("PublicKey({})", short_hex(&pubkey_to_ssz(&self.inner)))
    }

    fn __richcmp__(&self, other: &Self, op: CompareOp) -> PyResult<bool> {
        let eq = self.inner.merkle_root == other.inner.merkle_root
            && self.inner.public_param == other.inner.public_param;
        match op {
            CompareOp::Eq => Ok(eq),
            CompareOp::Ne => Ok(!eq),
            _ => Err(pyo3::exceptions::PyTypeError::new_err(
                "PublicKey only supports == and !=",
            )),
        }
    }

    fn __hash__(&self) -> u64 {
        let mut h = DefaultHasher::new();
        pubkey_to_ssz(&self.inner).hash(&mut h);
        h.finish()
    }
}

#[pyclass(name = "Signature", frozen, module = "py_lean_multisig")]
#[derive(Clone)]
pub struct PySignature {
    pub inner: Arc<XmssSignature>,
}

#[pymethods]
impl PySignature {
    #[classmethod]
    fn from_ssz(_cls: &Bound<'_, pyo3::types::PyType>, data: &[u8]) -> PyResult<Self> {
        Ok(Self {
            inner: Arc::new(signature_from_ssz(data)?),
        })
    }

    fn to_ssz<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &signature_to_ssz(&self.inner))
    }

    fn __repr__(&self) -> String {
        format!("Signature({})", short_hex(&signature_to_ssz(&self.inner)))
    }

    fn __richcmp__(&self, other: &Self, op: CompareOp) -> PyResult<bool> {
        let lhs = signature_to_ssz(&self.inner);
        let rhs = signature_to_ssz(&other.inner);
        match op {
            CompareOp::Eq => Ok(lhs == rhs),
            CompareOp::Ne => Ok(lhs != rhs),
            _ => Err(pyo3::exceptions::PyTypeError::new_err(
                "Signature only supports == and !=",
            )),
        }
    }

    fn __hash__(&self) -> u64 {
        let mut h = DefaultHasher::new();
        signature_to_ssz(&self.inner).hash(&mut h);
        h.finish()
    }
}

// SecretKey is intentionally NOT serializable: persisting one-time-use signing
// material is a footgun. We capture slot_start/slot_end on the wrapper at
// keygen time since upstream's fields are pub(crate).
#[pyclass(name = "SecretKey", frozen, module = "py_lean_multisig")]
pub struct PySecretKey {
    pub inner: Arc<XmssSecretKey>,
    pub slot_start: u32,
    pub slot_end: u32,
    pub pk: PyPublicKey,
}

#[pymethods]
impl PySecretKey {
    #[getter]
    fn public_key(&self) -> PyPublicKey {
        self.pk.clone()
    }

    #[getter]
    fn slot_start(&self) -> u32 {
        self.slot_start
    }

    #[getter]
    fn slot_end(&self) -> u32 {
        self.slot_end
    }

    fn __repr__(&self) -> String {
        format!(
            "SecretKey(slots={}..={}, pk={})",
            self.slot_start,
            self.slot_end,
            short_hex(&pubkey_to_ssz(&self.pk.inner))
        )
    }
}


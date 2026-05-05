use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::Arc;

use pyo3::prelude::*;
use pyo3::pyclass::CompareOp;
use pyo3::types::PyBytes;
use rec_aggregation::AggregatedXMSS;
use xmss::{XmssPublicKey, XmssSecretKey, XmssSignature};

use crate::error::SerializationError;

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

/// Serialize any upstream serde-derived type via postcard. We piggyback
/// on upstream's `Serialize`/`Deserialize` derives instead of carrying a
/// hand-written byte-layout codec; the wire format is whatever postcard
/// produces, not consensus-layer SSZ. AggregatedSignature uses upstream's
/// own postcard+lz4 helpers (it has compression baked in) — these helpers
/// are for the smaller, uncompressed PublicKey/Signature.
fn encode<T: serde::Serialize>(value: &T) -> Vec<u8> {
    postcard::to_allocvec(value).expect("postcard serialization is infallible for these types")
}

fn decode<'a, T: serde::Deserialize<'a>>(bytes: &'a [u8], type_name: &str) -> PyResult<T> {
    postcard::from_bytes(bytes).map_err(|e| {
        SerializationError::new_err(format!("failed to decode {}: {}", type_name, e))
    })
}

#[pyclass(name = "PublicKey", frozen, module = "py_lean_multisig")]
#[derive(Clone)]
pub struct PyPublicKey {
    pub inner: Arc<XmssPublicKey>,
}

#[pymethods]
impl PyPublicKey {
    /// Decode from postcard-encoded bytes (matches `to_bytes`).
    #[classmethod]
    fn from_bytes(_cls: &Bound<'_, pyo3::types::PyType>, data: &[u8]) -> PyResult<Self> {
        let pk: XmssPublicKey = decode(data, "PublicKey")?;
        Ok(Self { inner: Arc::new(pk) })
    }

    /// Encode to postcard-format bytes (round-trips with `from_bytes`).
    fn to_bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &encode(&*self.inner))
    }

    fn __repr__(&self) -> String {
        format!("PublicKey({})", short_hex(&encode(&*self.inner)))
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
        encode(&*self.inner).hash(&mut h);
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
    /// Decode from postcard-encoded bytes (matches `to_bytes`).
    #[classmethod]
    fn from_bytes(_cls: &Bound<'_, pyo3::types::PyType>, data: &[u8]) -> PyResult<Self> {
        let sig: XmssSignature = decode(data, "Signature")?;
        Ok(Self { inner: Arc::new(sig) })
    }

    /// Encode to postcard-format bytes (round-trips with `from_bytes`).
    fn to_bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &encode(&*self.inner))
    }

    fn __repr__(&self) -> String {
        format!("Signature({})", short_hex(&encode(&*self.inner)))
    }

    fn __richcmp__(&self, other: &Self, op: CompareOp) -> PyResult<bool> {
        match op {
            CompareOp::Eq => Ok(self.inner == other.inner),
            CompareOp::Ne => Ok(self.inner != other.inner),
            _ => Err(pyo3::exceptions::PyTypeError::new_err(
                "Signature only supports == and !=",
            )),
        }
    }

    fn __hash__(&self) -> u64 {
        let mut h = DefaultHasher::new();
        encode(&*self.inner).hash(&mut h);
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
            short_hex(&encode(&*self.pk.inner))
        )
    }
}

/// Aggregated XMSS signature — wraps `rec_aggregation::AggregatedXMSS`.
/// Wire format is upstream's native postcard+lz4. The consensus-layer SSZ
/// container is currently the same byte payload (no extra framing); if
/// upstream ever introduces real framing, a separate accessor will be
/// added rather than overloading `to_bytes`.
#[pyclass(name = "AggregatedSignature", frozen, module = "py_lean_multisig")]
#[derive(Clone)]
pub struct PyAggregatedSignature {
    pub inner: Arc<AggregatedXMSS>,
}

#[pymethods]
impl PyAggregatedSignature {
    #[classmethod]
    fn from_bytes(_cls: &Bound<'_, pyo3::types::PyType>, data: &[u8]) -> PyResult<Self> {
        let agg = AggregatedXMSS::deserialize(data).ok_or_else(|| {
            SerializationError::new_err(
                "failed to decode AggregatedSignature (postcard+lz4 deserialization failed)",
            )
        })?;
        Ok(Self { inner: Arc::new(agg) })
    }

    fn to_bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.serialize())
    }

    fn __repr__(&self) -> String {
        let bytes = self.inner.serialize();
        format!(
            "AggregatedSignature({} bytes, {})",
            bytes.len(),
            short_hex(&bytes)
        )
    }
}


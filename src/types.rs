use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::Arc;

use backend::KoalaBear;
use pyo3::prelude::*;
use pyo3::pyclass::CompareOp;
use pyo3::types::PyBytes;
use rec_aggregation::{TypeOneMultiSignature, TypeTwoMultiSignature};
use xmss::{XmssPublicKey, XmssSecretKey, XmssSignature, MESSAGE_LEN_FE};

use crate::error::SerializationError;
use crate::serialization::{
    decode_multi_message_signature, decode_public_key, decode_signature,
    decode_single_message_signature, encode_message, encode_multi_message_signature,
    encode_public_key, encode_signature, encode_single_message_signature, read_fes,
};

const MESSAGE_BYTES: usize = MESSAGE_LEN_FE * 4;
const _: () = assert!(MESSAGE_BYTES == 32);

/// Convert 32 bytes (8 little-endian u32s, each high bit clear) into the
/// `[KoalaBear; 8]` upstream wants for messages.
pub(crate) fn message_from_bytes(bytes: &[u8]) -> PyResult<[KoalaBear; MESSAGE_LEN_FE]> {
    if bytes.len() != MESSAGE_BYTES {
        return Err(SerializationError::new_err(format!(
            "message must be exactly {} bytes, got {}",
            MESSAGE_BYTES,
            bytes.len()
        )));
    }
    let mut pos = 0;
    read_fes::<MESSAGE_LEN_FE>(bytes, &mut pos)
}

pub(crate) fn wrap_pubkeys(pks: &[XmssPublicKey]) -> Vec<PyPublicKey> {
    pks.iter()
        .cloned()
        .map(|pk| PyPublicKey { inner: Arc::new(pk) })
        .collect()
}

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

#[pyclass(name = "PublicKey", frozen, module = "py_lean_multisig", skip_from_py_object)]
#[derive(Clone)]
pub struct PyPublicKey {
    pub(crate) inner: Arc<XmssPublicKey>,
}

#[pymethods]
impl PyPublicKey {
    #[classmethod]
    fn from_bytes(_cls: &Bound<'_, pyo3::types::PyType>, data: &[u8]) -> PyResult<Self> {
        let pk = decode_public_key(data)?;
        Ok(Self { inner: Arc::new(pk) })
    }

    fn to_bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &encode_public_key(&self.inner))
    }

    fn __repr__(&self) -> String {
        format!("PublicKey({})", short_hex(&encode_public_key(&self.inner)))
    }

    fn __richcmp__(&self, other: &Self, op: CompareOp) -> PyResult<bool> {
        match op {
            CompareOp::Eq => Ok(self.inner == other.inner),
            CompareOp::Ne => Ok(self.inner != other.inner),
            _ => Err(pyo3::exceptions::PyTypeError::new_err(
                "PublicKey only supports == and !=",
            )),
        }
    }

    fn __hash__(&self) -> u64 {
        let mut h = DefaultHasher::new();
        self.inner.hash(&mut h);
        h.finish()
    }
}

#[pyclass(name = "Signature", frozen, module = "py_lean_multisig", skip_from_py_object)]
#[derive(Clone)]
pub struct PySignature {
    pub(crate) inner: Arc<XmssSignature>,
}

#[pymethods]
impl PySignature {
    #[classmethod]
    fn from_bytes(_cls: &Bound<'_, pyo3::types::PyType>, data: &[u8]) -> PyResult<Self> {
        let sig = decode_signature(data)?;
        Ok(Self { inner: Arc::new(sig) })
    }

    fn to_bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &encode_signature(&self.inner))
    }

    fn __repr__(&self) -> String {
        // Avoid encoding the full ~1.2KB signature for a short identifier.
        format!("Signature(h=0x{:016x})", self.__hash__())
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
        self.inner.hash(&mut h);
        h.finish()
    }
}

// SecretKey isn't serializable: upstream's XmssSecretKey derives only Debug
// and its fields are pub(crate), so we can't build an encoder. Re-derive
// across processes by persisting (seed, slot_start, slot_end) and calling
// keygen() — it's deterministic. slot_start/slot_end are cached here
// because upstream doesn't expose them.
#[pyclass(name = "SecretKey", frozen, module = "py_lean_multisig")]
pub struct PySecretKey {
    pub(crate) inner: Arc<XmssSecretKey>,
    pub(crate) slot_start: u32,
    pub(crate) slot_end: u32,
}

#[pymethods]
impl PySecretKey {
    #[getter]
    fn public_key(&self) -> PyPublicKey {
        PyPublicKey { inner: Arc::new(self.inner.public_key()) }
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
        let pk_bytes = encode_public_key(&self.inner.public_key());
        format!(
            "SecretKey(slots={}..={}, pk={})",
            self.slot_start,
            self.slot_end,
            short_hex(&pk_bytes)
        )
    }
}

/// Many XMSS sigs over one `(message, slot)` aggregated into a single zkVM proof.
/// Wraps upstream's `TypeOneMultiSignature`.
#[pyclass(
    name = "SingleMessageSignature",
    frozen,
    module = "py_lean_multisig",
    skip_from_py_object
)]
#[derive(Clone)]
pub struct PySingleMessageSignature {
    pub(crate) inner: Arc<TypeOneMultiSignature>,
}

#[pymethods]
impl PySingleMessageSignature {
    #[classmethod]
    fn from_bytes(_cls: &Bound<'_, pyo3::types::PyType>, data: &[u8]) -> PyResult<Self> {
        let sig = decode_single_message_signature(data)?;
        Ok(Self { inner: Arc::new(sig) })
    }

    fn to_bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &encode_single_message_signature(&self.inner))
    }

    #[getter]
    fn message<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &encode_message(&self.inner.info.message))
    }

    #[getter]
    fn slot(&self) -> u32 {
        self.inner.info.slot
    }

    #[getter]
    fn pubkeys(&self) -> Vec<PyPublicKey> {
        wrap_pubkeys(&self.inner.info.pubkeys)
    }

    fn __repr__(&self) -> String {
        format!(
            "SingleMessageSignature(slot={}, n_signers={})",
            self.inner.info.slot,
            self.inner.info.pubkeys.len()
        )
    }
}

/// Bundles n single-message proofs, each potentially over a different
/// `(message, slot)`. Wraps upstream's `TypeTwoMultiSignature`.
#[pyclass(
    name = "MultiMessageSignature",
    frozen,
    module = "py_lean_multisig",
    skip_from_py_object
)]
#[derive(Clone)]
pub struct PyMultiMessageSignature {
    pub(crate) inner: Arc<TypeTwoMultiSignature>,
}

#[pymethods]
impl PyMultiMessageSignature {
    #[classmethod]
    fn from_bytes(_cls: &Bound<'_, pyo3::types::PyType>, data: &[u8]) -> PyResult<Self> {
        let sig = decode_multi_message_signature(data)?;
        Ok(Self { inner: Arc::new(sig) })
    }

    fn to_bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &encode_multi_message_signature(&self.inner))
    }

    #[getter]
    fn components(&self) -> Vec<PyComponentInfo> {
        self.inner
            .info
            .iter()
            .cloned()
            .map(|info| PyComponentInfo { inner: Arc::new(info) })
            .collect()
    }

    fn __len__(&self) -> usize {
        self.inner.info.len()
    }

    fn __repr__(&self) -> String {
        format!("MultiMessageSignature(n_components={})", self.inner.info.len())
    }
}

/// Read-only view of one MultiMessageSignature component's bound info.
#[pyclass(
    name = "ComponentInfo",
    frozen,
    module = "py_lean_multisig",
    skip_from_py_object
)]
#[derive(Clone)]
pub struct PyComponentInfo {
    inner: Arc<rec_aggregation::TypeOneInfo>,
}

#[pymethods]
impl PyComponentInfo {
    #[getter]
    fn message<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &encode_message(&self.inner.message))
    }

    #[getter]
    fn slot(&self) -> u32 {
        self.inner.slot
    }

    #[getter]
    fn pubkeys(&self) -> Vec<PyPublicKey> {
        wrap_pubkeys(&self.inner.pubkeys)
    }

    fn __repr__(&self) -> String {
        format!(
            "ComponentInfo(slot={}, n_signers={})",
            self.inner.slot,
            self.inner.pubkeys.len()
        )
    }
}

use std::sync::Arc;

use lean_vm::{MAX_WHIR_LOG_INV_RATE, MIN_WHIR_LOG_INV_RATE};
use pyo3::prelude::*;
use pyo3::wrap_pyfunction;

mod aggregation;
mod error;
mod serialization;
mod types;
mod xmss;

use crate::error::SerializationError;
use crate::serialization::{
    decode_multi_message_signature, decode_single_message_signature, peek_kind,
    KIND_MULTI_MESSAGE, KIND_SINGLE_MESSAGE,
};
use crate::types::{PyMultiMessageSignature, PySingleMessageSignature};

/// Decode a SingleMessageSignature or MultiMessageSignature from bytes,
/// returning whichever the kind tag identifies. Useful when receiving an
/// aggregated signature from an untrusted source where the kind isn't
/// known ahead of time.
#[pyfunction]
fn parse_aggregated<'py>(py: Python<'py>, data: &[u8]) -> PyResult<Bound<'py, PyAny>> {
    match peek_kind(data, "aggregated signature")? {
        KIND_SINGLE_MESSAGE => {
            let inner = decode_single_message_signature(data)?;
            Ok(Py::new(py, PySingleMessageSignature { inner: Arc::new(inner) })?
                .into_bound(py)
                .into_any())
        }
        KIND_MULTI_MESSAGE => {
            let inner = decode_multi_message_signature(data)?;
            Ok(Py::new(py, PyMultiMessageSignature { inner: Arc::new(inner) })?
                .into_bound(py)
                .into_any())
        }
        other => Err(SerializationError::new_err(format!(
            "aggregated signature has unknown kind tag: 0x{:02x} (expected 0x01 or 0x02)",
            other
        ))),
    }
}

#[pymodule]
fn py_lean_multisig(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    m.add("MIN_LOG_INV_RATE", MIN_WHIR_LOG_INV_RATE)?;
    m.add("MAX_LOG_INV_RATE", MAX_WHIR_LOG_INV_RATE)?;
    error::register(py, m)?;
    m.add_class::<types::PyPublicKey>()?;
    m.add_class::<types::PySignature>()?;
    m.add_class::<types::PySecretKey>()?;
    m.add_class::<types::PySingleMessageSignature>()?;
    m.add_class::<types::PyMultiMessageSignature>()?;
    m.add_class::<types::PyComponentInfo>()?;
    m.add_class::<aggregation::PyProver>()?;
    m.add_class::<aggregation::PyVerifier>()?;
    m.add_function(wrap_pyfunction!(xmss::keygen, m)?)?;
    m.add_function(wrap_pyfunction!(xmss::sign, m)?)?;
    m.add_function(wrap_pyfunction!(xmss::verify, m)?)?;
    m.add_function(wrap_pyfunction!(parse_aggregated, m)?)?;
    Ok(())
}

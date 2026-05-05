use lean_vm::{MAX_WHIR_LOG_INV_RATE, MIN_WHIR_LOG_INV_RATE};
use pyo3::prelude::*;
use pyo3::wrap_pyfunction;

mod aggregation;
mod error;
mod primitives;
mod types;

#[pymodule]
fn py_lean_multisig(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    m.add("MIN_LOG_INV_RATE", MIN_WHIR_LOG_INV_RATE)?;
    m.add("MAX_LOG_INV_RATE", MAX_WHIR_LOG_INV_RATE)?;
    error::register(py, m)?;
    m.add_class::<types::PyPublicKey>()?;
    m.add_class::<types::PySignature>()?;
    m.add_class::<types::PySecretKey>()?;
    m.add_class::<types::PyAggregatedSignature>()?;
    m.add_class::<aggregation::PyProver>()?;
    m.add_class::<aggregation::PyVerifier>()?;
    m.add_function(wrap_pyfunction!(primitives::keygen, m)?)?;
    m.add_function(wrap_pyfunction!(primitives::sign, m)?)?;
    m.add_function(wrap_pyfunction!(primitives::verify, m)?)?;
    Ok(())
}

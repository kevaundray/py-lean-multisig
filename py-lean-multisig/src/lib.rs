use pyo3::prelude::*;
use pyo3::wrap_pyfunction;

mod conv;
mod error;
mod panic;
mod primitives;
mod ssz;
mod types;

#[pymodule]
fn py_lean_multisig(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    error::register(py, m)?;
    m.add_class::<types::PyPublicKey>()?;
    m.add_class::<types::PySignature>()?;
    m.add_class::<types::PySecretKey>()?;
    m.add_class::<types::PyAggregatedSignature>()?;
    m.add_function(wrap_pyfunction!(primitives::keygen, m)?)?;
    m.add_function(wrap_pyfunction!(primitives::sign, m)?)?;
    m.add_function(wrap_pyfunction!(primitives::verify, m)?)?;
    Ok(())
}

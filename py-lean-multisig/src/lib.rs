use pyo3::prelude::*;
use xmss as _;
use rec_aggregation as _;

mod conv;
mod error;
mod panic;
mod ssz;
mod types;

#[pymodule]
fn py_lean_multisig(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    error::register(py, m)?;
    m.add_class::<types::PyPublicKey>()?;
    m.add_class::<types::PySignature>()?;
    m.add_class::<types::PySecretKey>()?;
    Ok(())
}

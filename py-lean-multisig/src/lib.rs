use pyo3::prelude::*;
use xmss as _;
use rec_aggregation as _;

#[pymodule]
fn _lean_multisig(_py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    Ok(())
}

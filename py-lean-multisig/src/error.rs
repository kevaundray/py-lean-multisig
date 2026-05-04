use pyo3::create_exception;
use pyo3::exceptions::PyException;
use pyo3::prelude::*;

create_exception!(py_lean_multisig, LeanMultisigError, PyException);
create_exception!(py_lean_multisig, KeygenError, LeanMultisigError);
create_exception!(py_lean_multisig, SignError, LeanMultisigError);
create_exception!(py_lean_multisig, VerifyError, LeanMultisigError);
create_exception!(py_lean_multisig, AggregationError, LeanMultisigError);
create_exception!(py_lean_multisig, SerializationError, LeanMultisigError);

pub fn register(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("LeanMultisigError", py.get_type::<LeanMultisigError>())?;
    m.add("KeygenError", py.get_type::<KeygenError>())?;
    m.add("SignError", py.get_type::<SignError>())?;
    m.add("VerifyError", py.get_type::<VerifyError>())?;
    m.add("AggregationError", py.get_type::<AggregationError>())?;
    m.add("SerializationError", py.get_type::<SerializationError>())?;
    Ok(())
}

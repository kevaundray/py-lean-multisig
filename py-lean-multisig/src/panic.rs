use pyo3::prelude::*;
use std::any::Any;
use std::panic::{catch_unwind, AssertUnwindSafe};

/// Convert a panic payload from `catch_unwind` into a printable string.
/// Handles the two payload shapes Rust panics commonly carry (`&'static str`
/// and `String`); anything else falls back to a fixed message rather than
/// silently dropping the payload.
pub fn panic_msg(payload: Box<dyn Any + Send>) -> String {
    if let Some(s) = payload.downcast_ref::<&'static str>() {
        (*s).to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "unknown panic payload".to_string()
    }
}

/// Run `f`; on panic, build a `PyErr` from the payload via `to_err`.
/// Use this at every PyO3 boundary that calls into upstream code that
/// might panic on assertion failure.
pub fn catch<T, F, E>(f: F, to_err: E) -> PyResult<T>
where
    F: FnOnce() -> PyResult<T>,
    E: FnOnce(String) -> PyErr,
{
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(res) => res,
        Err(payload) => Err(to_err(panic_msg(payload))),
    }
}
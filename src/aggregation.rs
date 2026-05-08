use std::sync::Arc;

use backend::{precompute_dft_twiddles, KoalaBear};
use lean_vm::{MAX_WHIR_LOG_INV_RATE, MIN_WHIR_LOG_INV_RATE};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use rec_aggregation::{
    aggregate_type_1, init_aggregation_bytecode, merge_many_type_1, split_type_2, verify_type_1,
    verify_type_2, TypeOneMultiSignature, MAX_RECURSIONS,
};
use xmss::{XmssPublicKey, XmssSignature};

use crate::error::{AggregationError, VerifyError};
use crate::types::{
    message_from_bytes, wrap_pubkeys, PyMultiMessageSignature, PyPublicKey, PySignature,
    PySingleMessageSignature,
};

/// True iff `passed`, sorted by `XmssPublicKey::cmp`, equals `expected`.
/// `expected` is assumed already sorted (upstream invariant on
/// `TypeOneInfo::pubkeys`).
fn pubkeys_match_sorted(passed: &[PyRef<'_, PyPublicKey>], expected: &[XmssPublicKey]) -> bool {
    if passed.len() != expected.len() {
        return false;
    }
    let mut sorted: Vec<&XmssPublicKey> = passed.iter().map(|p| &*p.inner).collect();
    sorted.sort();
    sorted.iter().zip(expected.iter()).all(|(a, b)| **a == *b)
}

/// Validate that the caller-passed `(message, slot, pubkeys)` triple matches
/// what's bound inside a `TypeOneInfo`. `label` prefixes error messages
/// (`""` for SingleMessage, `"component {i} "` for MultiMessage).
fn check_bound_info(
    label: &str,
    bound: &rec_aggregation::TypeOneInfo,
    pub_keys: &[PyRef<'_, PyPublicKey>],
    message: &[u8],
    slot: u32,
) -> PyResult<()> {
    let msg_fe = message_from_bytes(message)?;
    if bound.message != msg_fe {
        return Err(VerifyError::new_err(format!(
            "{}message does not match the message bound in the signature",
            label
        )));
    }
    if bound.slot != slot {
        return Err(VerifyError::new_err(format!(
            "{}slot ({}) does not match the slot bound in the signature ({})",
            label, slot, bound.slot
        )));
    }
    if !pubkeys_match_sorted(pub_keys, &bound.pubkeys) {
        return Err(VerifyError::new_err(format!(
            "{}pub_keys do not match the keys bound in the signature",
            label
        )));
    }
    Ok(())
}

#[pyclass(name = "Prover", module = "py_lean_multisig")]
pub struct PyProver {
    log_inv_rate: usize,
}

#[pymethods]
impl PyProver {
    #[new]
    #[pyo3(signature = (*, log_inv_rate=2))]
    fn new(log_inv_rate: usize) -> PyResult<Self> {
        if !(MIN_WHIR_LOG_INV_RATE..=MAX_WHIR_LOG_INV_RATE).contains(&log_inv_rate) {
            return Err(PyValueError::new_err(format!(
                "log_inv_rate must be in {}..={}, got {}",
                MIN_WHIR_LOG_INV_RATE, MAX_WHIR_LOG_INV_RATE, log_inv_rate
            )));
        }
        precompute_dft_twiddles::<KoalaBear>(1 << 24);
        init_aggregation_bytecode();
        Ok(Self { log_inv_rate })
    }

    #[pyo3(signature = (pub_keys, signatures, message, slot, *, children=None))]
    fn aggregate(
        &self,
        py: Python<'_>,
        pub_keys: Vec<PyRef<'_, PyPublicKey>>,
        signatures: Vec<PyRef<'_, PySignature>>,
        message: &[u8],
        slot: u32,
        children: Option<Vec<PyRef<'_, PySingleMessageSignature>>>,
    ) -> PyResult<(Vec<PyPublicKey>, PySingleMessageSignature)> {
        if pub_keys.len() != signatures.len() {
            return Err(PyValueError::new_err(format!(
                "pub_keys length {} != signatures length {}",
                pub_keys.len(),
                signatures.len()
            )));
        }
        let msg_fe = message_from_bytes(message)?;

        let raw_xmss: Vec<(XmssPublicKey, XmssSignature)> = pub_keys
            .iter()
            .zip(signatures.iter())
            .map(|(p, s)| ((*p.inner).clone(), (*s.inner).clone()))
            .collect();

        let children_owned: Vec<TypeOneMultiSignature> = children
            .unwrap_or_default()
            .iter()
            .map(|c| (*c.inner).clone())
            .collect();

        let log_inv_rate = self.log_inv_rate;
        let result = py
            .detach(|| aggregate_type_1(&children_owned, raw_xmss, msg_fe, slot, log_inv_rate))
            .map_err(|e| AggregationError::new_err(format!("aggregation failed: {:?}", e)))?;

        let py_pks = wrap_pubkeys(&result.info.pubkeys);
        Ok((
            py_pks,
            PySingleMessageSignature {
                inner: Arc::new(result),
            },
        ))
    }

    /// 1 zkVM proving op regardless of input count.
    fn merge(
        &self,
        py: Python<'_>,
        signatures: Vec<PyRef<'_, PySingleMessageSignature>>,
    ) -> PyResult<PyMultiMessageSignature> {
        if signatures.is_empty() {
            return Err(PyValueError::new_err(
                "merge() requires at least one signature",
            ));
        }
        if signatures.len() > MAX_RECURSIONS {
            return Err(PyValueError::new_err(format!(
                "merge() supports at most {} signatures, got {}",
                MAX_RECURSIONS,
                signatures.len()
            )));
        }
        let owned: Vec<TypeOneMultiSignature> =
            signatures.iter().map(|s| (*s.inner).clone()).collect();
        let log_inv_rate = self.log_inv_rate;
        let result = py
            .detach(move || merge_many_type_1(owned, log_inv_rate))
            .map_err(|e| AggregationError::new_err(format!("merge failed: {:?}", e)))?;
        Ok(PyMultiMessageSignature { inner: Arc::new(result) })
    }

    /// 1 zkVM proving op per call — not free.
    fn split(
        &self,
        py: Python<'_>,
        agg: &PyMultiMessageSignature,
        index: usize,
    ) -> PyResult<PySingleMessageSignature> {
        let n = agg.inner.info.len();
        if index >= n {
            return Err(PyValueError::new_err(format!(
                "split index {} out of bounds (signature has {} component{})",
                index,
                n,
                if n == 1 { "" } else { "s" }
            )));
        }
        // Deep clone (multi-MB): split_type_2 takes ownership and we share
        // the Arc with Python — contrast with verify_multi's Arc::clone.
        let owned = (*agg.inner).clone();
        let log_inv_rate = self.log_inv_rate;
        let result = py
            .detach(move || split_type_2(owned, index, log_inv_rate))
            .map_err(|e| AggregationError::new_err(format!("split failed: {:?}", e)))?;
        Ok(PySingleMessageSignature { inner: Arc::new(result) })
    }
}

#[pyclass(name = "Verifier", module = "py_lean_multisig")]
pub struct PyVerifier;

#[pymethods]
impl PyVerifier {
    #[new]
    fn new() -> PyResult<Self> {
        init_aggregation_bytecode();
        Ok(Self)
    }

    fn verify(
        &self,
        py: Python<'_>,
        pub_keys: Vec<PyRef<'_, PyPublicKey>>,
        message: &[u8],
        agg: &PySingleMessageSignature,
        slot: u32,
    ) -> PyResult<()> {
        check_bound_info("", &agg.inner.info, &pub_keys, message, slot)?;

        // Bump the Arc refcount instead of deep-cloning the multi-MB WHIR
        // proof to satisfy `py.detach`'s `'static` requirement.
        let inner = Arc::clone(&agg.inner);
        py.detach(move || verify_type_1(&inner))
            .map_err(|e| VerifyError::new_err(format!("aggregated signature verification failed: {:?}", e)))?;
        Ok(())
    }

    /// Boundary-checked per component before zkVM work.
    fn verify_multi(
        &self,
        py: Python<'_>,
        components: Vec<(Vec<PyRef<'_, PyPublicKey>>, Vec<u8>, u32)>,
        agg: &PyMultiMessageSignature,
    ) -> PyResult<()> {
        if components.len() != agg.inner.info.len() {
            return Err(VerifyError::new_err(format!(
                "components length {} does not match the {} bound in the signature",
                components.len(),
                agg.inner.info.len(),
            )));
        }
        for (i, ((pub_keys, message, slot), bound)) in
            components.iter().zip(agg.inner.info.iter()).enumerate()
        {
            check_bound_info(&format!("component {} ", i), bound, pub_keys, message, *slot)?;
        }

        let inner = Arc::clone(&agg.inner);
        py.detach(move || verify_type_2(&inner))
            .map_err(|e| {
                VerifyError::new_err(format!("multi-message verification failed: {:?}", e))
            })?;
        Ok(())
    }
}

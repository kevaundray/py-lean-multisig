use std::sync::Arc;

use backend::{precompute_dft_twiddles, KoalaBear};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use rec_aggregation::{
    init_aggregation_bytecode, xmss_aggregate, xmss_verify_aggregation, AggregatedXMSS,
};
use xmss::{XmssPublicKey, XmssSignature};

use crate::error::{AggregationError, VerifyError};
use crate::types::{message_from_bytes, PyAggregatedSignature, PyPublicKey, PySignature};

#[pyclass(name = "Prover", module = "py_lean_multisig")]
pub struct PyProver {
    log_inv_rate: usize,
}

#[pymethods]
impl PyProver {
    #[new]
    #[pyo3(signature = (*, log_inv_rate=2))]
    fn new(log_inv_rate: usize) -> PyResult<Self> {
        if !(1..=4).contains(&log_inv_rate) {
            return Err(PyValueError::new_err(format!(
                "log_inv_rate must be in 1..=4, got {}",
                log_inv_rate
            )));
        }
        // Match upstream's run_aggregation_benchmark order: twiddles first, then bytecode.
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
        children: Option<Vec<(Vec<PyRef<'_, PyPublicKey>>, PyRef<'_, PyAggregatedSignature>)>>,
    ) -> PyResult<(Vec<PyPublicKey>, PyAggregatedSignature)> {
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

        // Single materialization: collect each child's owned (Vec<XmssPublicKey>,
        // AggregatedXMSS), then build the borrow-shaped tuple upstream wants
        // from the same allocation. The inner AggregatedXMSS still has to be
        // cloned per call — upstream takes it by value.
        let children_owned: Vec<(Vec<XmssPublicKey>, AggregatedXMSS)> = children
            .unwrap_or_default()
            .into_iter()
            .map(|(child_pks, child_agg)| {
                let pks: Vec<XmssPublicKey> =
                    child_pks.iter().map(|p| (*p.inner).clone()).collect();
                (pks, (*child_agg.inner).clone())
            })
            .collect();
        let children_refs: Vec<(&[XmssPublicKey], AggregatedXMSS)> = children_owned
            .iter()
            .map(|(p, a)| (p.as_slice(), a.clone()))
            .collect();

        let log_inv_rate = self.log_inv_rate;
        let (pks_out, agg) = py
            .allow_threads(|| {
                xmss_aggregate(&children_refs, raw_xmss, &msg_fe, slot, log_inv_rate)
            })
            .map_err(|e| AggregationError::new_err(format!("aggregation failed: {:?}", e)))?;
        let py_pks: Vec<PyPublicKey> = pks_out
            .into_iter()
            .map(|pk| PyPublicKey { inner: Arc::new(pk) })
            .collect();
        Ok((
            py_pks,
            PyAggregatedSignature {
                inner: Arc::new(agg),
            },
        ))
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
        agg: &PyAggregatedSignature,
        slot: u32,
    ) -> PyResult<()> {
        let msg_fe = message_from_bytes(message)?;
        let pks: Vec<XmssPublicKey> = pub_keys.iter().map(|p| (*p.inner).clone()).collect();
        let agg_inner = agg.inner.clone();
        py.allow_threads(|| xmss_verify_aggregation(&pks, &agg_inner, &msg_fe, slot)).map_err(
            |e| VerifyError::new_err(format!("aggregated signature verification failed: {:?}", e)),
        )?;
        Ok(())
    }
}

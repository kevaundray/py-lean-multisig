import pytest

import py_lean_multisig as lm


@pytest.fixture(scope="module")
def prover():
    return lm.Prover(log_inv_rate=lm.MAX_LOG_INV_RATE)  # smallest proof, fastest aggregate


@pytest.fixture(scope="module")
def verifier():
    return lm.Verifier()

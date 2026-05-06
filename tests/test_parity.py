import hashlib

import py_lean_multisig as lm

SEED = b"\x00" * 32
SLOT_RANGE = (0, 7)
MESSAGE = b"\x42" * 32
SIGN_SLOT = 5
RNG_SEED = b"\x99" * 32

EXPECTED_PUBKEY_HEX = (
    "8300a12d1f51bd13e0293a2a2dd955540e31c354335c863509c8f564a0d40f2a"
)
EXPECTED_PUBKEY_SHA256 = (
    "eefaf998184c7ee5140ea9177479080faf9b5a2af2e07da29e4970ea47ba1974"
)
EXPECTED_SIGNATURE_SHA256 = (
    "5479d7d2d45b1c4b14cfef3d155affd3a51cb1916538690489dfa62875d41d97"
)


def test_pubkey_bytes_are_stable():
    _, pk = lm.keygen(SEED, *SLOT_RANGE)
    assert pk.to_bytes().hex() == EXPECTED_PUBKEY_HEX
    assert hashlib.sha256(pk.to_bytes()).hexdigest() == EXPECTED_PUBKEY_SHA256


def test_signature_bytes_are_stable():
    sk, _ = lm.keygen(SEED, *SLOT_RANGE)
    sig = lm.sign(sk, MESSAGE, SIGN_SLOT, rng_seed=RNG_SEED)
    assert hashlib.sha256(sig.to_bytes()).hexdigest() == EXPECTED_SIGNATURE_SHA256


def test_full_cycle_with_stable_fixtures():
    """A signature produced from the fixed inputs must verify with the
    fixed pubkey. Catches any layered drift across keygen/sign/verify."""
    sk, pk = lm.keygen(SEED, *SLOT_RANGE)
    sig = lm.sign(sk, MESSAGE, SIGN_SLOT, rng_seed=RNG_SEED)
    assert lm.verify(pk, MESSAGE, sig, SIGN_SLOT) is None

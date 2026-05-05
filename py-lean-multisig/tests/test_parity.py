"""Regression-guard the wire format (postcard via upstream serde) against
silent drift.

These fixed bytes are generated at the upstream pin in Cargo.toml. If
they change, either:
  - we changed encoders (intentional — regenerate the fixtures), or
  - upstream's KoalaBear / WotsSignature / XmssPublicKey representation
    drifted under us (bump the upstream pin deliberately, then regenerate).

Re-generate from Python with:

    sk, pk = py_lean_multisig.keygen(b"\\x00"*32, 0, 7)
    sig = py_lean_multisig.sign(sk, b"\\x42"*32, 5, rng_seed=b"\\x99"*32)
    pk.to_bytes().hex()
    hashlib.sha256(sig.to_bytes()).hexdigest()
"""

import hashlib

import py_lean_multisig as lm

SEED = b"\x00" * 32
SLOT_RANGE = (0, 7)
MESSAGE = b"\x42" * 32
SIGN_SLOT = 5
RNG_SEED = b"\x99" * 32

EXPECTED_PUBKEY_HEX = (
    "9196989801d592d7199fde855fc49c819001b1cb8fa10299fdedd807c6d5f5f306ca88db8906"
)
EXPECTED_PUBKEY_SHA256 = (
    "cc8134c0fa5bda60d272c20163c1b9e6fad6b4c309602906ec5922f8ebfefeb7"
)
EXPECTED_SIGNATURE_SHA256 = (
    "b4958eda2d09be001b3da590666e2889c8703a42ebebe532558db44f36f8b9a7"
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

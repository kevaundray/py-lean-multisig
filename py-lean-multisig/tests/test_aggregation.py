"""End-to-end tests for Prover.aggregate / Verifier.verify.

Tests are slow (Prover() init compiles the lean-DSL aggregation circuit,
~5-10s; aggregating 4 sigs ~1-2s in release mode). All test_aggregation.*
tests share a session-scoped Prover/Verifier so the bytecode + DFT
twiddle precompute cost is paid once per pytest run.
"""

import struct

import pytest

import py_lean_multisig as lm

# Use the same field-element-friendly message format upstream uses for
# benchmarks: 8 LE u32s with the high bit clear. The exact values don't
# matter — only that each value is < 2^31.
MSG = b"".join(struct.pack("<I", i) for i in range(8))
SLOT = 111


def _signers(n: int):
    """Generate n distinct signers + sigs for MSG at SLOT."""
    pairs = [lm.keygen(bytes([(i + 1) % 256]) * 32, 111, 112) for i in range(n)]
    sks = [sk for sk, _ in pairs]
    pks = [pk for _, pk in pairs]
    sigs = [
        lm.sign(sk, MSG, SLOT, rng_seed=bytes([(i + 100) % 256]) * 32)
        for i, sk in enumerate(sks)
    ]
    return pks, sigs


@pytest.fixture(scope="module")
def prover():
    return lm.Prover(log_inv_rate=4)  # smallest proof, fastest aggregate


@pytest.fixture(scope="module")
def verifier():
    return lm.Verifier()


def test_aggregate_then_verify_4_sigs(prover, verifier):
    pks, sigs = _signers(4)
    sorted_pks, agg = prover.aggregate(pks, sigs, MSG, SLOT)
    assert isinstance(agg, lm.AggregatedSignature)
    assert isinstance(sorted_pks, list)
    assert all(isinstance(p, lm.PublicKey) for p in sorted_pks)
    assert len(sorted_pks) == 4
    # Returns None on success
    assert verifier.verify(sorted_pks, MSG, agg, SLOT) is None


def test_aggregate_returns_sorted_pks(prover):
    pks, sigs = _signers(4)
    sorted_pks, _ = prover.aggregate(pks, sigs, MSG, SLOT)
    # The order must match what verifier expects — i.e. sorted by upstream's
    # XmssPublicKey Ord, which we don't replicate in Python. Just check we
    # got back the same set.
    assert set(p.to_bytes() for p in sorted_pks) == set(p.to_bytes() for p in pks)


def test_aggregate_mismatched_lengths_raises_value_error(prover):
    pks, sigs = _signers(3)
    with pytest.raises(ValueError):
        prover.aggregate(pks, sigs[:2], MSG, SLOT)
    with pytest.raises(ValueError):
        prover.aggregate(pks[:2], sigs, MSG, SLOT)


def test_prover_log_inv_rate_validation():
    with pytest.raises(ValueError):
        lm.Prover(log_inv_rate=0)
    with pytest.raises(ValueError):
        lm.Prover(log_inv_rate=5)


def test_aggregate_short_message_raises_serialization_error(prover):
    pks, sigs = _signers(4)
    with pytest.raises(lm.SerializationError):
        prover.aggregate(pks, sigs, b"\x00" * 31, SLOT)


def test_aggregated_signature_round_trip(prover):
    pks, sigs = _signers(2)
    _, agg = prover.aggregate(pks, sigs, MSG, SLOT)
    raw = agg.to_bytes()
    assert isinstance(raw, bytes)
    assert len(raw) > 0
    agg2 = lm.AggregatedSignature.from_bytes(raw)
    assert agg.to_bytes() == agg2.to_bytes()


def test_aggregated_signature_from_bytes_garbage_raises():
    with pytest.raises(lm.SerializationError):
        lm.AggregatedSignature.from_bytes(b"not a valid postcard+lz4 payload")


def test_verify_tampered_aggregated_signature_raises(prover, verifier):
    pks, sigs = _signers(4)
    sorted_pks, agg = prover.aggregate(pks, sigs, MSG, SLOT)
    # Round-trip through bytes, flip a bit, decode, verify
    raw = bytearray(agg.to_bytes())
    raw[len(raw) // 2] ^= 0x01
    try:
        tampered = lm.AggregatedSignature.from_bytes(bytes(raw))
    except lm.SerializationError:
        # If the flipped bit landed in the lz4 prefix, decompression will
        # fail before we get to the verifier. That's still a rejection of
        # a tampered signature — pass.
        return
    with pytest.raises(lm.VerifyError):
        verifier.verify(sorted_pks, MSG, tampered, SLOT)


def test_verify_wrong_slot_raises(prover, verifier):
    pks, sigs = _signers(4)
    sorted_pks, agg = prover.aggregate(pks, sigs, MSG, SLOT)
    with pytest.raises(lm.VerifyError):
        verifier.verify(sorted_pks, MSG, agg, SLOT + 1)


def test_verify_wrong_message_raises(prover, verifier):
    pks, sigs = _signers(4)
    sorted_pks, agg = prover.aggregate(pks, sigs, MSG, SLOT)
    other_msg = b"".join(struct.pack("<I", 100 + i) for i in range(8))
    with pytest.raises(lm.VerifyError):
        verifier.verify(sorted_pks, other_msg, agg, SLOT)

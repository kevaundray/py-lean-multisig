import struct

import pytest

import py_lean_multisig as lm

# Use the same field-element-friendly message format upstream uses for
# benchmarks: 8 LE u32s with the high bit clear. The exact values don't
# matter, only that each value is < 2^31.
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
    return lm.Prover(log_inv_rate=lm.MAX_LOG_INV_RATE)  # smallest proof, fastest aggregate


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
        lm.Prover(log_inv_rate=lm.MIN_LOG_INV_RATE - 1)
    with pytest.raises(ValueError):
        lm.Prover(log_inv_rate=lm.MAX_LOG_INV_RATE + 1)


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


def test_hierarchical_aggregation(prover, verifier):
    """Aggregate two leaves (2 sigs each) into child proofs, then
    aggregate the children at the top level via the `children=` kwarg.
    Verifier sees the union of all leaf pubkeys."""
    # Two disjoint sets of signers (different seed ranges so the leaf
    # pubkey sets don't overlap)
    pks_a, sigs_a = _signers(2)
    pairs_b = [lm.keygen(bytes([(i + 50) % 256]) * 32, 111, 112) for i in range(2)]
    sks_b = [sk for sk, _ in pairs_b]
    pks_b = [pk for _, pk in pairs_b]
    sigs_b = [
        lm.sign(sk, MSG, SLOT, rng_seed=bytes([(i + 200) % 256]) * 32)
        for i, sk in enumerate(sks_b)
    ]

    # Layer 1: aggregate each leaf separately
    sorted_pks_a, agg_a = prover.aggregate(pks_a, sigs_a, MSG, SLOT)
    sorted_pks_b, agg_b = prover.aggregate(pks_b, sigs_b, MSG, SLOT)

    # Layer 2: aggregate the two children with no fresh raw signatures
    sorted_pks_top, agg_top = prover.aggregate(
        [], [], MSG, SLOT,
        children=[(sorted_pks_a, agg_a), (sorted_pks_b, agg_b)],
    )

    # Verifier sees the deduplicated union of all leaf pubkeys
    verifier.verify(sorted_pks_top, MSG, agg_top, SLOT)


def test_hierarchical_aggregation_with_fresh_raw_sigs(prover, verifier):
    """Mixing raw signatures with children at the same level: fold two
    existing child aggregates plus a fresh batch of raw signatures into
    one combined proof in a single aggregate() call. Verifier sees the
    union of all signers (children's leaves + the fresh raw ones)."""
    # Two disjoint child batches (use distinct seed ranges so pubkeys
    # across all three sets don't overlap)
    pks_a, sigs_a = _signers(2)
    pairs_b = [lm.keygen(bytes([(i + 50) % 256]) * 32, 111, 112) for i in range(2)]
    sks_b = [sk for sk, _ in pairs_b]
    pks_b = [pk for _, pk in pairs_b]
    sigs_b = [
        lm.sign(sk, MSG, SLOT, rng_seed=bytes([(i + 200) % 256]) * 32)
        for i, sk in enumerate(sks_b)
    ]
    sorted_pks_a, agg_a = prover.aggregate(pks_a, sigs_a, MSG, SLOT)
    sorted_pks_b, agg_b = prover.aggregate(pks_b, sigs_b, MSG, SLOT)

    # A fresh batch of raw signers — NOT in either child
    pairs_c = [lm.keygen(bytes([(i + 150) % 256]) * 32, 111, 112) for i in range(2)]
    sks_c = [sk for sk, _ in pairs_c]
    pks_c = [pk for _, pk in pairs_c]
    sigs_c = [
        lm.sign(sk, MSG, SLOT, rng_seed=bytes([(i + 250) % 256]) * 32)
        for i, sk in enumerate(sks_c)
    ]

    # One aggregate() call: 2 fresh raw sigs + 2 children = 6 signers folded
    sorted_pks_top, agg_top = prover.aggregate(
        pks_c, sigs_c, MSG, SLOT,
        children=[(sorted_pks_a, agg_a), (sorted_pks_b, agg_b)],
    )

    assert len(sorted_pks_top) == 6
    verifier.verify(sorted_pks_top, MSG, agg_top, SLOT)

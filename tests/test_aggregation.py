import struct

import pytest

import py_lean_multisig as lm

# Use the same field-element-friendly message format upstream uses for
# benchmarks: 8 LE u32s with the high bit clear. The exact values don't
# matter, only that each value is < 2^31.
MSG = b"".join(struct.pack("<I", i) for i in range(8))
SLOT = 111


def _signers(n: int, seed_offset: int = 0):
    """Generate n distinct signers + sigs for MSG at SLOT.

    `seed_offset` shifts both the keygen seed and the rng seed by the
    same amount, so multiple calls with disjoint offsets produce
    disjoint signer sets — useful for hierarchical aggregation tests
    where each child batch must have unique pubkeys.
    """
    pairs = [
        lm.keygen(bytes([(i + 1 + seed_offset) % 256]) * 32, 111, 112)
        for i in range(n)
    ]
    sks = [sk for sk, _ in pairs]
    pks = [pk for _, pk in pairs]
    sigs = [
        lm.sign(sk, MSG, SLOT, rng_seed=bytes([(i + 100 + seed_offset) % 256]) * 32)
        for i, sk in enumerate(sks)
    ]
    return pks, sigs


@pytest.fixture(scope="module")
def prover():
    return lm.Prover(log_inv_rate=lm.MAX_LOG_INV_RATE)  # smallest proof, fastest aggregate


@pytest.fixture(scope="module")
def verifier():
    return lm.Verifier()


@pytest.fixture(scope="module")
def child_proofs(prover):
    """Two pre-aggregated child proofs over disjoint 2-signer batches,
    shared across the hierarchical-aggregation tests so we don't pay
    ~1.5s × 2 of redundant proving per test."""
    pks_a, sigs_a = _signers(2)
    pks_b, sigs_b = _signers(2, seed_offset=49)
    sorted_pks_a, agg_a = prover.aggregate(pks_a, sigs_a, MSG, SLOT)
    sorted_pks_b, agg_b = prover.aggregate(pks_b, sigs_b, MSG, SLOT)
    return (sorted_pks_a, agg_a), (sorted_pks_b, agg_b)


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


def test_hierarchical_aggregation(prover, verifier, child_proofs):
    """Aggregate two leaves (2 sigs each) into child proofs, then
    aggregate the children at the top level via the `children=` kwarg.
    Verifier sees the union of all leaf pubkeys."""
    (sorted_pks_a, agg_a), (sorted_pks_b, agg_b) = child_proofs

    sorted_pks_top, agg_top = prover.aggregate(
        [], [], MSG, SLOT,
        children=[(sorted_pks_a, agg_a), (sorted_pks_b, agg_b)],
    )

    verifier.verify(sorted_pks_top, MSG, agg_top, SLOT)


def test_hierarchical_aggregation_with_fresh_raw_sigs(prover, verifier, child_proofs):
    """Mixing raw signatures with children at the same level: fold two
    existing child aggregates plus a fresh batch of raw signatures into
    one combined proof in a single aggregate() call. Verifier sees the
    union of all signers (children's leaves + the fresh raw ones)."""
    (sorted_pks_a, agg_a), (sorted_pks_b, agg_b) = child_proofs
    # A fresh batch of raw signers — disjoint seed range so pubkeys
    # don't collide with either child.
    pks_c, sigs_c = _signers(2, seed_offset=149)

    sorted_pks_top, agg_top = prover.aggregate(
        pks_c, sigs_c, MSG, SLOT,
        children=[(sorted_pks_a, agg_a), (sorted_pks_b, agg_b)],
    )

    assert len(sorted_pks_top) == 6
    verifier.verify(sorted_pks_top, MSG, agg_top, SLOT)

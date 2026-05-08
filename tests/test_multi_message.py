"""Tests for the MultiMessage API: Prover.merge / split, Verifier.verify_multi,
and the polymorphic lm.parse_aggregated() deserializer."""
import struct

import pytest

import py_lean_multisig as lm

# Three distinct (message, slot) pairs — each gets its own SingleMessage.
SLOT_A, SLOT_B, SLOT_C = 50, 60, 70
MSG_A = b"".join(struct.pack("<I", i) for i in range(8))
MSG_B = b"".join(struct.pack("<I", 100 + i) for i in range(8))
MSG_C = b"".join(struct.pack("<I", 200 + i) for i in range(8))


def _signers(n: int, msg: bytes, slot: int, seed_offset: int = 0):
    pairs = [
        lm.keygen(bytes([(i + 1 + seed_offset) % 256]) * 32, slot, slot + 1)
        for i in range(n)
    ]
    pks = [pk for _, pk in pairs]
    sigs = [
        lm.sign(sk, msg, slot, rng_seed=bytes([(i + 100 + seed_offset) % 256]) * 32)
        for i, (sk, _) in enumerate(pairs)
    ]
    return pks, sigs


@pytest.fixture(scope="module")
def three_singles(prover):
    """Three SingleMessage proofs over disjoint (message, slot) pairs.
    Shared so the merge/split tests don't pay aggregate cost three times."""
    a_pks, a_sigs = _signers(2, MSG_A, SLOT_A, seed_offset=0)
    b_pks, b_sigs = _signers(2, MSG_B, SLOT_B, seed_offset=10)
    c_pks, c_sigs = _signers(2, MSG_C, SLOT_C, seed_offset=20)
    _, a = prover.aggregate(a_pks, a_sigs, MSG_A, SLOT_A)
    _, b = prover.aggregate(b_pks, b_sigs, MSG_B, SLOT_B)
    _, c = prover.aggregate(c_pks, c_sigs, MSG_C, SLOT_C)
    return a, b, c


@pytest.fixture(scope="module")
def merged(prover, three_singles):
    a, b, c = three_singles
    return prover.merge([a, b, c])


def test_merge_returns_multi_message(merged):
    assert isinstance(merged, lm.MultiMessageSignature)
    assert len(merged) == 3


def test_merge_components_carry_per_component_info(merged):
    components = merged.components
    assert len(components) == 3
    assert isinstance(components[0], lm.ComponentInfo)
    assert components[0].message == MSG_A
    assert components[0].slot == SLOT_A
    assert components[1].message == MSG_B
    assert components[1].slot == SLOT_B
    assert components[2].message == MSG_C
    assert components[2].slot == SLOT_C


def test_merge_empty_raises_value_error(prover):
    with pytest.raises(ValueError):
        prover.merge([])


def test_verify_multi_succeeds(verifier, merged):
    components = [(c.pubkeys, c.message, c.slot) for c in merged.components]
    assert verifier.verify_multi(components, merged) is None


def test_verify_multi_wrong_length_raises(verifier, merged):
    components = [(c.pubkeys, c.message, c.slot) for c in merged.components]
    with pytest.raises(lm.VerifyError):
        verifier.verify_multi(components[:2], merged)


def test_verify_multi_wrong_message_raises(verifier, merged):
    components = [(c.pubkeys, c.message, c.slot) for c in merged.components]
    components[1] = (components[1][0], MSG_C, components[1][2])  # B's slot, C's msg
    with pytest.raises(lm.VerifyError):
        verifier.verify_multi(components, merged)


def test_verify_multi_wrong_slot_raises(verifier, merged):
    components = [(c.pubkeys, c.message, c.slot) for c in merged.components]
    components[0] = (components[0][0], components[0][1], components[0][2] + 1)
    with pytest.raises(lm.VerifyError):
        verifier.verify_multi(components, merged)


def test_verify_multi_wrong_pubkeys_raises(verifier, merged):
    components = [(c.pubkeys, c.message, c.slot) for c in merged.components]
    # Swap pubkeys between components 0 and 1.
    swapped = (components[1][0], components[0][1], components[0][2])
    components[0] = swapped
    with pytest.raises(lm.VerifyError):
        verifier.verify_multi(components, merged)


def test_split_recovers_a_single_message(prover, verifier, merged):
    recovered = prover.split(merged, 1)
    assert isinstance(recovered, lm.SingleMessageSignature)
    assert recovered.message == MSG_B
    assert recovered.slot == SLOT_B
    # Verifies as a standalone single-message signature
    verifier.verify(recovered.pubkeys, MSG_B, recovered, SLOT_B)


def test_split_out_of_bounds_raises(prover, merged):
    with pytest.raises(ValueError):
        prover.split(merged, 99)


def test_promote_single_to_multi_with_one_component(prover, verifier, three_singles):
    """Single-component MultiMessage is legal (n_components == 1)."""
    a, _, _ = three_singles
    promoted = prover.merge([a])
    assert len(promoted) == 1
    assert promoted.components[0].message == MSG_A
    assert promoted.components[0].slot == SLOT_A
    components = [(promoted.components[0].pubkeys, MSG_A, SLOT_A)]
    verifier.verify_multi(components, promoted)


def test_multi_message_round_trip(merged):
    raw = merged.to_bytes()
    assert raw[0] == 0x02  # kind tag = multi-message
    decoded = lm.MultiMessageSignature.from_bytes(raw)
    assert decoded.to_bytes() == raw
    assert len(decoded) == len(merged)


def test_multi_message_from_bytes_wrong_kind_tag_raises(prover, three_singles):
    """A SingleMessage payload (tag 0x01) must be rejected by
    MultiMessageSignature.from_bytes."""
    a, _, _ = three_singles
    with pytest.raises(lm.SerializationError):
        lm.MultiMessageSignature.from_bytes(a.to_bytes())


def test_parse_aggregated_dispatches_to_single_message(prover, three_singles):
    a, _, _ = three_singles
    parsed = lm.parse_aggregated(a.to_bytes())
    assert isinstance(parsed, lm.SingleMessageSignature)
    assert parsed.to_bytes() == a.to_bytes()


def test_parse_aggregated_dispatches_to_multi_message(merged):
    parsed = lm.parse_aggregated(merged.to_bytes())
    assert isinstance(parsed, lm.MultiMessageSignature)
    assert parsed.to_bytes() == merged.to_bytes()


def test_parse_aggregated_unknown_kind_tag_raises():
    with pytest.raises(lm.SerializationError):
        lm.parse_aggregated(b"\xff" + b"\x00" * 100)


def test_parse_aggregated_empty_raises():
    with pytest.raises(lm.SerializationError):
        lm.parse_aggregated(b"")

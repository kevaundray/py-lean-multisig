import pytest

import py_lean_multisig as lm


def test_keygen_returns_typed_pair():
    sk, pk = lm.keygen(b"\x00" * 32, 0, 7)
    assert isinstance(sk, lm.SecretKey)
    assert isinstance(pk, lm.PublicKey)
    assert sk.slot_start == 0
    assert sk.slot_end == 7
    assert sk.public_key == pk


def test_keygen_deterministic_for_same_seed():
    seed = b"\x42" * 32
    _, pk1 = lm.keygen(seed, 0, 0)
    _, pk2 = lm.keygen(seed, 0, 0)
    assert pk1 == pk2
    assert pk1.to_bytes() == pk2.to_bytes()


def test_keygen_different_seed_yields_different_pubkey():
    _, pk_a = lm.keygen(b"\x00" * 32, 0, 0)
    _, pk_b = lm.keygen(b"\x01" * 32, 0, 0)
    assert pk_a != pk_b


def test_keygen_short_seed_raises_serialization_error():
    with pytest.raises(lm.SerializationError):
        lm.keygen(b"short", 0, 7)


def test_keygen_long_seed_raises_serialization_error():
    with pytest.raises(lm.SerializationError):
        lm.keygen(b"\x00" * 33, 0, 7)


def test_keygen_invalid_range_raises_keygen_error():
    with pytest.raises(lm.KeygenError):
        lm.keygen(b"\x00" * 32, 8, 0)


def test_pubkey_bytes_round_trip():
    _, pk = lm.keygen(b"\x07" * 32, 0, 7)
    raw = pk.to_bytes()
    assert isinstance(raw, bytes)
    pk2 = lm.PublicKey.from_bytes(raw)
    assert pk == pk2
    assert hash(pk) == hash(pk2)
    assert "PublicKey" in repr(pk)


def test_sign_returns_typed_signature():
    sk, _ = lm.keygen(b"\x00" * 32, 0, 7)
    sig = lm.sign(sk, b"\x11" * 32, 3, rng_seed=b"\x99" * 32)
    assert isinstance(sig, lm.Signature)


def test_sign_deterministic_with_rng_seed():
    sk, _ = lm.keygen(b"\x00" * 32, 0, 7)
    msg = b"\x11" * 32
    sig_a = lm.sign(sk, msg, 3, rng_seed=b"\x99" * 32)
    sig_b = lm.sign(sk, msg, 3, rng_seed=b"\x99" * 32)
    assert sig_a == sig_b
    assert sig_a.to_bytes() == sig_b.to_bytes()


def test_sign_slot_out_of_range_raises():
    sk, _ = lm.keygen(b"\x00" * 32, 5, 9)
    with pytest.raises(lm.SignError):
        lm.sign(sk, b"\x00" * 32, 0, rng_seed=b"\x01" * 32)
    with pytest.raises(lm.SignError):
        lm.sign(sk, b"\x00" * 32, 10, rng_seed=b"\x01" * 32)


def test_sign_short_message_raises_serialization_error():
    sk, _ = lm.keygen(b"\x00" * 32, 0, 7)
    with pytest.raises(lm.SerializationError):
        lm.sign(sk, b"\x00" * 31, 0, rng_seed=b"\x01" * 32)


def test_sign_high_bit_set_message_raises():
    sk, _ = lm.keygen(b"\x00" * 32, 0, 7)
    bad = b"\xff" * 4 + b"\x00" * 28
    with pytest.raises(lm.SerializationError):
        lm.sign(sk, bad, 0, rng_seed=b"\x01" * 32)


def test_sign_short_rng_seed_raises():
    sk, _ = lm.keygen(b"\x00" * 32, 0, 7)
    with pytest.raises(lm.SerializationError):
        lm.sign(sk, b"\x00" * 32, 0, rng_seed=b"short")


def test_signature_bytes_round_trip():
    sk, _ = lm.keygen(b"\x07" * 32, 0, 7)
    sig = lm.sign(sk, b"\x22" * 32, 5, rng_seed=b"\xaa" * 32)
    raw = sig.to_bytes()
    assert isinstance(raw, bytes)
    sig2 = lm.Signature.from_bytes(raw)
    assert sig == sig2


def test_verify_round_trip():
    sk, pk = lm.keygen(b"\x00" * 32, 0, 7)
    msg = b"\x22" * 32
    sig = lm.sign(sk, msg, 5, rng_seed=b"\x01" * 32)
    # Returns None on success
    assert lm.verify(pk, msg, sig, 5) is None


def test_verify_tampered_message_raises():
    sk, pk = lm.keygen(b"\x00" * 32, 0, 7)
    sig = lm.sign(sk, b"\x22" * 32, 5, rng_seed=b"\x01" * 32)
    with pytest.raises(lm.VerifyError):
        lm.verify(pk, b"\x33" * 32, sig, 5)


def test_verify_tampered_slot_raises():
    sk, pk = lm.keygen(b"\x00" * 32, 0, 7)
    sig = lm.sign(sk, b"\x22" * 32, 5, rng_seed=b"\x01" * 32)
    with pytest.raises(lm.VerifyError):
        lm.verify(pk, b"\x22" * 32, sig, 4)


def test_verify_wrong_pubkey_raises():
    sk_a, _ = lm.keygen(b"\x00" * 32, 0, 7)
    _, pk_b = lm.keygen(b"\x01" * 32, 0, 7)
    sig = lm.sign(sk_a, b"\x22" * 32, 5, rng_seed=b"\x01" * 32)
    with pytest.raises(lm.VerifyError):
        lm.verify(pk_b, b"\x22" * 32, sig, 5)


def test_verify_short_message_raises_serialization_error():
    sk, pk = lm.keygen(b"\x00" * 32, 0, 7)
    sig = lm.sign(sk, b"\x22" * 32, 5, rng_seed=b"\x01" * 32)
    with pytest.raises(lm.SerializationError):
        lm.verify(pk, b"\x22" * 31, sig, 5)


def test_verify_after_bytes_roundtrip():
    """Signature/PublicKey round-tripped through bytes should still verify."""
    sk, pk = lm.keygen(b"\x00" * 32, 0, 7)
    msg = b"\x22" * 32
    sig = lm.sign(sk, msg, 5, rng_seed=b"\x01" * 32)
    pk2 = lm.PublicKey.from_bytes(pk.to_bytes())
    sig2 = lm.Signature.from_bytes(sig.to_bytes())
    assert lm.verify(pk2, msg, sig2, 5) is None

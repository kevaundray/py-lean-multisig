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
    assert pk1.to_ssz() == pk2.to_ssz()


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


def test_pubkey_ssz_round_trip():
    _, pk = lm.keygen(b"\x07" * 32, 0, 7)
    raw = pk.to_ssz()
    assert isinstance(raw, bytes)
    assert len(raw) == 32  # 8 KoalaBear field elements × 4 bytes
    pk2 = lm.PublicKey.from_ssz(raw)
    assert pk == pk2
    assert hash(pk) == hash(pk2)
    assert "PublicKey" in repr(pk)


def test_pubkey_from_ssz_wrong_length_raises():
    with pytest.raises(lm.SerializationError):
        lm.PublicKey.from_ssz(b"\x00" * 31)


def test_pubkey_from_ssz_high_bit_set_raises():
    bad = b"\xff" * 4 + b"\x00" * 28  # first u32 has high bit set
    with pytest.raises(lm.SerializationError):
        lm.PublicKey.from_ssz(bad)

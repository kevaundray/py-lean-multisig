# py-lean-multisig

Python bindings for [leanMultisig](https://github.com/leanEthereum/leanMultisig)'s
hash-based XMSS signature primitives — the post-quantum signature scheme
targeted by the Lean Ethereum project.

> **Scope (v0.0.x):** XMSS keygen, sign, verify only. Signature aggregation
> via the leanMultisig zkVM is **not** included — it requires runtime
> compilation of a lean-DSL aggregation circuit through ~700 LOC of upstream
> machinery that's currently `pub(crate)`. Will land when upstream exposes
> a usable `init_aggregation_bytecode_from_source` API or we accept a fork.

## Install

```bash
pip install py-lean-multisig
```

Wheels are published for Linux (x86_64, aarch64) and macOS (x86_64, arm64).
Python ≥ 3.11.

## Quickstart

```python
import py_lean_multisig as lm

# Keygen — seed is 32 bytes, slot range is inclusive on both ends.
sk, pk = lm.keygen(seed=b"\x00" * 32, slot_start=0, slot_end=1023)

# Sign — message is 32 bytes (interpreted as 8 LE u32s, each high bit
# clear, since each value must fit in KoalaBear's 31-bit prime field).
# rng_seed is optional; provide it for deterministic signing in tests.
message = b"\x42" * 32
signature = lm.sign(sk, message, slot=5, rng_seed=b"\x99" * 32)

# Verify — raises lm.VerifyError on failure, returns None on success.
lm.verify(pk, message, signature, slot=5)

# SSZ wire format — pubkey is 32 bytes, signature is 1208 bytes (fixed).
pk_bytes = pk.to_ssz()
sig_bytes = signature.to_ssz()
pk2 = lm.PublicKey.from_ssz(pk_bytes)
sig2 = lm.Signature.from_ssz(sig_bytes)
assert pk == pk2 and signature == sig2
```

## API

### Functions

- `keygen(seed: bytes, slot_start: int, slot_end: int) -> tuple[SecretKey, PublicKey]`
  — `seed` must be exactly 32 bytes. `slot_start <= slot_end < 2^32` (the
  XMSS lifetime is 2³² slots; you typically pick a smaller range).
- `sign(sk: SecretKey, message: bytes, slot: int, *, rng_seed: bytes | None = None) -> Signature`
  — `message` must be 32 bytes. `slot` must be within the secret key's
  range. With `rng_seed=None`, OS randomness is used; provide a 32-byte
  `rng_seed` for deterministic signing.
- `verify(pk: PublicKey, message: bytes, sig: Signature, slot: int) -> None`
  — returns `None` on success, raises `VerifyError` on any failure.

### Types

- `PublicKey` — 32 bytes SSZ. Hashable, equatable, has `to_ssz()` /
  `from_ssz()` classmethod. Carries the Merkle root and the public param.
- `Signature` — 1208 bytes SSZ (696 bytes WOTS + 512 bytes Merkle proof).
  Hashable, equatable, same SSZ surface.
- `SecretKey` — **deliberately not serializable** (persisting one-time-use
  signing material is a footgun). Exposes `public_key`, `slot_start`,
  `slot_end` as properties.

### Exceptions

All wrapper exceptions inherit from `LeanMultisigError`:

- `KeygenError` — invalid slot range.
- `SignError` — slot out of the secret key's range.
- `VerifyError` — signature failed WOTS recovery or Merkle path check.
- `SerializationError` — wrong-length input bytes, malformed SSZ, or a
  KoalaBear field element with the high bit set.
- `AggregationError` — reserved for future aggregation work.
- (`SerializationError` does **not** inherit from `ValueError` — by design.
  Catch `LeanMultisigError` or the specific subclass.)

## Design notes

- **Build:** maturin + PyO3 0.27. `pyo3/extension-module` is enabled by
  maturin at build time, not as a static cargo feature, so `cargo build`
  and `cargo check` work normally.
- **Upstream pin:** `xmss` and `backend` from `leanEthereum/leanMultisig`
  are pinned by git SHA in `Cargo.toml`. Bumping the pin requires
  re-running `tests/test_parity.py` to confirm the SSZ wire format hasn't
  drifted (the test asserts fixed bytes for fixed inputs).
- **Logging:** the wrapper does not initialize `tracing_subscriber` — that's
  the embedding application's job.
- **Threading:** PyO3 calls hold the GIL. Releasing it inside `sign` /
  `verify` is deferred to a future version pending benchmarks against
  Python-thread contention.

## Development

```bash
cd py-lean-multisig
python -m venv .venv
.venv/bin/pip install maturin pytest mypy
.venv/bin/maturin develop
.venv/bin/python -m pytest tests/ -v
```

## License

MIT OR Apache-2.0.

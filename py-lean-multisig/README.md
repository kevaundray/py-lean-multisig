# py-lean-multisig

Python bindings for [leanMultisig](https://github.com/leanEthereum/leanMultisig):
hash-based XMSS signatures (the post-quantum signature scheme targeted by the
Lean Ethereum project) plus zkVM-backed signature aggregation.

> **Note:** Aggregation requires an upstream fix (a rust-embed-based replacement
> for the build-time `env!("CARGO_MANIFEST_DIR")` lookup in `rec_aggregation`).
> Currently consumed via a local path dep against the `kw/rust-embed-src-code`
> branch; will switch to a git pin once merged.

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

# Wire format — postcard via upstream's serde derives. Round-trips
# through to_bytes() / from_bytes().
pk_bytes = pk.to_bytes()
sig_bytes = signature.to_bytes()
pk2 = lm.PublicKey.from_bytes(pk_bytes)
sig2 = lm.Signature.from_bytes(sig_bytes)
assert pk == pk2 and signature == sig2
```

## Aggregating signatures

`Prover` aggregates N XMSS signatures (all over the same `(message, slot)`)
into a single zkVM-backed SNARK proof; `Verifier` checks it. Both pay a
~5–10s startup cost on first instantiation while the lean-DSL aggregation
circuit is compiled to bytecode and DFT twiddles are precomputed.

```python
import py_lean_multisig as lm

# Generate 4 distinct keys + signatures over the same message+slot
message = b"\x42" * 32
slot = 5
signers = [lm.keygen(bytes([i + 1]) * 32, 0, 1023) for i in range(4)]
pks  = [pk for _, pk in signers]
sigs = [lm.sign(sk, message, slot, rng_seed=bytes([i + 100]) * 32)
        for i, (sk, _) in enumerate(signers)]

prover = lm.Prover(log_inv_rate=4)   # 1..=4: smaller = faster + bigger proof
verifier = lm.Verifier()

# Aggregate returns the keys in the order the verifier needs them
sorted_pks, agg = prover.aggregate(pks, sigs, message, slot)

verifier.verify(sorted_pks, message, agg, slot)   # raises VerifyError on failure

# AggregatedSignature serializes via to_bytes/from_bytes
# (upstream's native postcard+lz4 form, which the consensus-layer SSZ
# container currently wraps verbatim).
wire = agg.to_bytes()
agg2 = lm.AggregatedSignature.from_bytes(wire)
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

- `PublicKey` — Merkle root + public param. Hashable, equatable,
  `to_bytes()` / `from_bytes()` classmethod (postcard via upstream serde).
- `Signature` — WOTS signature + Merkle authentication path. Same
  hashable / equatable / bytes surface.
- `SecretKey` — **not serializable**: upstream's `XmssSecretKey` derives
  only `Debug` and exposes no `to_bytes`/`from_bytes` API, so we can't
  either. To carry a key across processes, persist the
  `(seed, slot_start, slot_end)` triple yourself and call `keygen()`
  again — it's deterministic. (For long slot ranges this can be slow,
  since keygen builds the full Merkle tree. For real stateful XMSS use
  you'd also need to track which slots have been signed; that's your
  responsibility regardless of how the key is stored.) Exposes
  `public_key`, `slot_start`, `slot_end` as properties.
- `AggregatedSignature` — variable-length zkVM SNARK proof. Round-trips
  through `to_bytes()` / `from_bytes()` (upstream's native postcard+lz4
  form).

### Aggregation classes

- `Prover(*, log_inv_rate: int = 2)` — `log_inv_rate` in `1..=4` selects
  the WHIR rate; smaller is faster to prove + verify but produces a
  bigger proof. Constructor pays a ~5–10s init cost (compiles the
  lean-DSL aggregation circuit to zkVM bytecode + precomputes DFT
  twiddles); subsequent `Prover()` instantiations in the same process
  are no-ops.
- `Prover.aggregate(pub_keys, signatures, message, slot, *, children=None)`
  — returns `(sorted_pub_keys, AggregatedSignature)`. The first element
  is the `pub_keys` list re-ordered to match what `Verifier.verify`
  requires; pass it through unchanged.
- `Verifier()` — same init cost as `Prover` but skips DFT twiddles.
- `Verifier.verify(pub_keys, message, agg, slot)` — `pub_keys` must be
  the sorted list returned by `aggregate`. Raises `VerifyError` on
  failure; returns `None` on success.

### Exceptions

All wrapper exceptions inherit from `LeanMultisigError`:

- `KeygenError` — invalid slot range.
- `SignError` — slot out of the secret key's range.
- `VerifyError` — signature failed WOTS recovery, Merkle path check, or
  aggregated-signature verification.
- `AggregationError` — prover failure or panic during `Prover.aggregate`.
- `SerializationError` — wrong-length input bytes, malformed SSZ, or a
  KoalaBear field element with the high bit set.
- (`SerializationError` does **not** inherit from `ValueError` — by design.
  Catch `LeanMultisigError` or the specific subclass.)

## Design notes

- **Build:** maturin + PyO3 0.27. `pyo3/extension-module` is enabled by
  maturin at build time, not as a static cargo feature, so `cargo build`
  and `cargo check` work normally.
- **Upstream pin:** `xmss`, `backend`, and `rec_aggregation` come from
  `leanEthereum/leanMultisig`. Bumping the pin requires re-running
  `tests/test_parity.py` to confirm the SSZ wire format hasn't drifted
  (the test asserts fixed bytes for fixed inputs).
- **AVX2 required on x86_64.** `.cargo/config.toml` enables
  `target-feature=+avx2` for x86_64 targets so the upstream backend uses
  its tested packed-field path instead of the `no_packing` fallback —
  the fallback produces wrong proof witnesses under aggregation. NEON is
  on by default for aarch64.
- **Logging:** the wrapper does not initialize `tracing_subscriber` — that's
  the embedding application's job.
- **Threading:** PyO3 calls hold the GIL. Releasing it inside `sign` /
  `verify` / `Prover.aggregate` / `Verifier.verify` is deferred to a
  future version pending benchmarks against Python-thread contention.

## Development

Uses [`uv`](https://github.com/astral-sh/uv) for venv + dependency
management (matches the pattern py-arkworks-bls12381 uses).

```bash
cd py-lean-multisig

# One-time setup: create the venv, install maturin + dev deps, build
# and editable-install the extension.
uv venv
uv pip install maturin pytest mypy
uv run maturin develop --release --extras dev

# Run the test suite.
uv run pytest tests/ -v

# Verify the .pyi stubs match the runtime extension.
uv run python -m mypy.stubtest py_lean_multisig --allowlist stubtest_allowlist.txt
```

After Rust source changes, re-run `uv run maturin develop --release` to
rebuild the extension.

## License

MIT OR Apache-2.0.

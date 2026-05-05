# py-lean-multisig

Python bindings for leanMultisig: XMSS signatures and zkVM-backed signature aggregation.

Requires Python >= 3.11. Wheels are built for Linux (x86_64, aarch64) and macOS (x86_64, arm64).

## Install

```
pip install py-lean-multisig
```

## Quickstart

```python
import py_lean_multisig as lm

# Key generation (seed is 32 bytes; slot range is inclusive)
sk, pk = lm.keygen(b"\x00" * 32, 0, 1023)

# Sign and verify (message is 32 bytes)
msg = b"\x42" * 32
sig = lm.sign(sk, msg, 5, rng_seed=b"\x99" * 32)  # rng_seed optional
lm.verify(pk, msg, sig, 5)

# Serialize/deserialize
pk2 = lm.PublicKey.from_bytes(pk.to_bytes())
sig2 = lm.Signature.from_bytes(sig.to_bytes())
assert pk == pk2 and sig == sig2
```

## Aggregation

Aggregate N signatures over the same `(message, slot)` into a single proof, then verify.

```python
import py_lean_multisig as lm

msg, slot = b"\x42" * 32, 5
pairs = [lm.keygen(bytes([i+1])*32, 0, 1023) for i in range(4)]
pks  = [pk for _, pk in pairs]
sigs = [lm.sign(sk, msg, slot, rng_seed=bytes([i+100])*32) for i, (sk, _) in enumerate(pairs)]

prover = lm.Prover(log_inv_rate=4)
verifier = lm.Verifier()

sorted_pks, agg = prover.aggregate(pks, sigs, msg, slot)
verifier.verify(sorted_pks, msg, agg, slot)

# AggregatedSignature bytes round-trip
agg2 = lm.AggregatedSignature.from_bytes(agg.to_bytes())
```

## API (summary)

- Functions: `keygen(seed, slot_start, slot_end)`, `sign(sk, message, slot, *, rng_seed=None)`, `verify(pk, message, sig, slot)`
- Types: `PublicKey`, `Signature`, `SecretKey` (not serializable), `AggregatedSignature`
- Classes: `Prover(log_inv_rate=2)` (range `MIN_LOG_INV_RATE..=MAX_LOG_INV_RATE`), `Verifier()`
- Errors: all raise subclasses of `LeanMultisigError` (`KeygenError`, `SignError`, `VerifyError`, `AggregationError`, `SerializationError`)

## Development

Uses [`uv`](https://github.com/astral-sh/uv) for venv + dependency
management

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

MIT OR Apache-2.0
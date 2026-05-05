"""Verify the .pyi stubs cover every export by type-checking a sample
script with `mypy --strict`. Fails CI if a new symbol is added to the
Rust module without a corresponding stub entry.
"""

import pathlib
import shutil
import subprocess
import sys
import textwrap

import pytest


SAMPLE = textwrap.dedent(
    """
    import py_lean_multisig as lm

    sk: lm.SecretKey
    pk: lm.PublicKey
    sk, pk = lm.keygen(b"\\x00" * 32, 0, 7)
    sig: lm.Signature = lm.sign(sk, b"\\x00" * 32, 3)
    sig2: lm.Signature = lm.sign(sk, b"\\x00" * 32, 3, rng_seed=b"\\x01" * 32)
    lm.verify(pk, b"\\x00" * 32, sig, 3)

    pk_bytes: bytes = pk.to_ssz()
    pk2: lm.PublicKey = lm.PublicKey.from_ssz(pk_bytes)
    assert pk == pk2
    sig_bytes: bytes = sig.to_ssz()
    sig3: lm.Signature = lm.Signature.from_ssz(sig_bytes)

    start: int = sk.slot_start
    end: int = sk.slot_end
    sk_pk: lm.PublicKey = sk.public_key

    version: str = lm.__version__

    err_classes: tuple[type[lm.LeanMultisigError], ...] = (
        lm.KeygenError,
        lm.SignError,
        lm.VerifyError,
        lm.AggregationError,
        lm.SerializationError,
    )
    """
)


def test_mypy_strict_covers_every_export(tmp_path: pathlib.Path) -> None:
    if shutil.which("mypy") is None:
        pytest.skip("mypy not installed")
    script = tmp_path / "_lm_stub_check.py"
    script.write_text(SAMPLE)
    result = subprocess.run(
        [sys.executable, "-m", "mypy", "--strict", str(script)],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, (
        f"mypy --strict failed:\n--- stdout ---\n{result.stdout}\n--- stderr ---\n{result.stderr}"
    )

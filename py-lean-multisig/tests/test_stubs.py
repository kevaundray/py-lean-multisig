"""Verify the .pyi stubs match the runtime extension via mypy.stubtest.

stubtest introspects the actual installed module and compares against
the stub — catches missing symbols, wrong signatures, parameter
positionality issues, and __init__-vs-__new__ mistakes that a sample-
script + mypy --strict approach silently misses.
"""

import pathlib
import shutil
import subprocess
import sys

import pytest


def test_stubs_match_runtime():
    if shutil.which("mypy") is None:
        pytest.skip("mypy not installed")
    project_root = pathlib.Path(__file__).resolve().parent.parent
    allowlist = project_root / "stubtest_allowlist.txt"
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "mypy.stubtest",
            "py_lean_multisig",
            "--allowlist",
            str(allowlist),
        ],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, (
        f"mypy.stubtest failed:\n--- stdout ---\n{result.stdout}\n"
        f"--- stderr ---\n{result.stderr}"
    )

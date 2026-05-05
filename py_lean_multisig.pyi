"""Type stubs for py_lean_multisig.
"""

from typing import final

__all__ = [
    "__version__",
    "MIN_LOG_INV_RATE",
    "MAX_LOG_INV_RATE",
    "PublicKey",
    "SecretKey",
    "Signature",
    "AggregatedSignature",
    "Prover",
    "Verifier",
    "keygen",
    "sign",
    "verify",
    "LeanMultisigError",
    "KeygenError",
    "SignError",
    "VerifyError",
    "AggregationError",
    "SerializationError",
]

__version__: str

# Bounds on Prover(log_inv_rate=...). Re-exported from upstream's
# lean_vm::{MIN,MAX}_WHIR_LOG_INV_RATE — values outside this range will
# raise ValueError.
MIN_LOG_INV_RATE: int
MAX_LOG_INV_RATE: int

@final
class PublicKey:
    @classmethod
    def from_bytes(cls, data: bytes) -> "PublicKey": ...
    def to_bytes(self) -> bytes: ...
    def __eq__(self, value: object, /) -> bool: ...
    def __ne__(self, value: object, /) -> bool: ...
    def __hash__(self) -> int: ...
    def __repr__(self) -> str: ...

@final
class SecretKey:
    @property
    def public_key(self) -> PublicKey: ...
    @property
    def slot_start(self) -> int: ...
    @property
    def slot_end(self) -> int: ...
    def __repr__(self) -> str: ...

@final
class Signature:
    @classmethod
    def from_bytes(cls, data: bytes) -> "Signature": ...
    def to_bytes(self) -> bytes: ...
    def __eq__(self, value: object, /) -> bool: ...
    def __ne__(self, value: object, /) -> bool: ...
    def __hash__(self) -> int: ...
    def __repr__(self) -> str: ...

@final
class AggregatedSignature:
    @classmethod
    def from_bytes(cls, data: bytes) -> "AggregatedSignature": ...
    def to_bytes(self) -> bytes: ...
    def __repr__(self) -> str: ...

@final
class Prover:
    # PyO3 #[new] surfaces as Python __new__, not __init__.
    def __new__(cls, *, log_inv_rate: int = ...) -> "Prover": ...
    def aggregate(
        self,
        pub_keys: list[PublicKey],
        signatures: list[Signature],
        message: bytes,
        slot: int,
        *,
        children: list[tuple[list[PublicKey], AggregatedSignature]] | None = ...,
    ) -> tuple[list[PublicKey], AggregatedSignature]: ...

@final
class Verifier:
    def __new__(cls) -> "Verifier": ...
    def verify(
        self,
        pub_keys: list[PublicKey],
        message: bytes,
        agg: AggregatedSignature,
        slot: int,
    ) -> None: ...

def keygen(seed: bytes, slot_start: int, slot_end: int) -> tuple[SecretKey, PublicKey]: ...
def sign(
    sk: SecretKey,
    message: bytes,
    slot: int,
    *,
    rng_seed: bytes | None = ...,
) -> Signature: ...
def verify(pk: PublicKey, message: bytes, sig: Signature, slot: int) -> None: ...

class LeanMultisigError(Exception): ...
class KeygenError(LeanMultisigError): ...
class SignError(LeanMultisigError): ...
class VerifyError(LeanMultisigError): ...
class AggregationError(LeanMultisigError): ...
class SerializationError(LeanMultisigError): ...

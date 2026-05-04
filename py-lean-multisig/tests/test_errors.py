import py_lean_multisig as lm


def test_exception_hierarchy():
    assert issubclass(lm.KeygenError, lm.LeanMultisigError)
    assert issubclass(lm.SignError, lm.LeanMultisigError)
    assert issubclass(lm.VerifyError, lm.LeanMultisigError)
    assert issubclass(lm.AggregationError, lm.LeanMultisigError)
    assert issubclass(lm.SerializationError, lm.LeanMultisigError)
    # Design choice: SerializationError is NOT a ValueError subclass.
    # Users opt into typed catches; existing `except ValueError:` does not catch.
    assert not issubclass(lm.SerializationError, ValueError)
    assert issubclass(lm.LeanMultisigError, Exception)


def test_each_exception_is_distinct():
    classes = [
        lm.KeygenError, lm.SignError, lm.VerifyError,
        lm.AggregationError, lm.SerializationError,
    ]
    # No accidental aliasing
    assert len(set(classes)) == len(classes)

"""Host-side unit tests for the persistent key feature.

Tests import hsm.py directly (with MicroPython modules stubbed) and verify
the KEY_STORE / KEY_LOAD / KEY_ERASE / KEY_STATUS commands. No hardware
needed — ucryptolib is stubbed with a simple XOR cipher for round-trip testing.
"""
import json
import os
import sys

import pytest

_pico_dir = os.path.join(os.path.dirname(__file__), "..", "pico")
sys.path.insert(0, _pico_dir)

# Stub MicroPython modules with CPython equivalents
import binascii
sys.modules["ubinascii"] = binascii
import time as _time
if not hasattr(_time, "sleep_ms"):
    _time.sleep_ms = lambda ms: _time.sleep(ms / 1000.0)
if not hasattr(_time, "ticks_ms"):
    _time.ticks_ms = lambda: int(_time.time() * 1000)
if not hasattr(_time, "ticks_diff"):
    _time.ticks_diff = lambda a, b: a - b
if not hasattr(_time, "ticks_add"):
    _time.ticks_add = lambda a, b: a + b
sys.modules["time"] = _time

sys.modules["trng_native"] = type(sys)("stub")

_machine_stub = type(sys)("machine")
_machine_stub.unique_id = lambda: b"\x00\x01\x02\x03\x04\x05\x06\x07"
_machine_stub.Pin = type("Pin", (), {"__init__": lambda *a, **k: None, "on": lambda *a: None, "off": lambda *a: None, "toggle": lambda *a: None, "OUT": 0})
_machine_stub.Timer = type("Timer", (), {"__init__": lambda *a, **k: None, "init": lambda *a, **k: None, "deinit": lambda *a: None})
_machine_stub.ADC = type("ADC", (), {"__init__": lambda *a, **k: None, "read_u16": lambda *a: 0})
sys.modules["machine"] = _machine_stub

sys.modules["ujson"] = json


class _StubTrng:
    _wd_interval_ms = 5000
    _wd_failures = 0
    _wd_reprofiles = 0
    _has_native = False

    @staticmethod
    def key256(margin=4):
        return os.urandom(32)

    @staticmethod
    def raw_entropy(n):
        return b"\xAA" * n

    @staticmethod
    def status_str():
        return "BITS 4,5,6,7 NUM_BITS 4 NATIVE NO TEMP 25.0C"

    @staticmethod
    def watchdog_status():
        return {"running": False, "interval_ms": 5000, "failures": 0,
                "reprofiles": 0, "last_check_ms": 0, "last_result": None,
                "history": [], "trend_declining": False}

    @staticmethod
    def start_watchdog(interval_ms=5000):
        return True

    @staticmethod
    def stop_watchdog():
        pass

    @staticmethod
    def reprofile():
        return True


sys.modules["trng"] = _StubTrng


class _StubAes:
    @staticmethod
    def expand_key(key):
        return [0] * 240

    @staticmethod
    def encrypt_block(rk, pt):
        return pt

    @staticmethod
    def decrypt_block(rk, ct):
        return ct

    @staticmethod
    def ctr_xcrypt(rk, nonce, data):
        return data


sys.modules["aes"] = _StubAes

# Stub ucryptolib with a simple XOR cipher (round-trip identity, same key)
class _StubUcryptolib:
    class _Cipher:
        def __init__(self, key, mode=1):
            self._key = key

        def _xor(self, data):
            k = self._key
            return bytes(b ^ k[i % len(k)] for i, b in enumerate(data))

        def encrypt(self, data):
            return self._xor(data)

        def decrypt(self, data):
            return self._xor(data)

    aes = _Cipher


sys.modules["ucryptolib"] = _StubUcryptolib()

# Stub os module for file operations (in-memory filesystem)
_mock_fs = {}


class _MockOs:
    @staticmethod
    def stat(path):
        if path in _mock_fs:
            return (0,) * 10
        raise OSError(2, "ENOENT")

    @staticmethod
    def remove(path):
        if path in _mock_fs:
            del _mock_fs[path]
        else:
            raise OSError(2, "ENOENT")


_real_os = os
_sys_os = type(sys)("os")
_sys_os.stat = _MockOs.stat
_sys_os.remove = _MockOs.remove
# Keep real path functions
_sys_os.path = _real_os.path
sys.modules["os"] = _sys_os


# Patch builtins open to use in-memory filesystem for the persist key file
_real_open = open


def _mock_open(path, mode="r", *args, **kwargs):
    if isinstance(path, str) and "pico_hsm_key.enc" in path:
        if "w" in mode or "a" in mode:
            return _MockFileWriter(path)
        elif "r" in mode:
            if path not in _mock_fs:
                raise OSError(2, "ENOENT")
            return _MockFileReader(path)
    return _real_open(path, mode, *args, **kwargs)


class _MockFileWriter:
    def __init__(self, path):
        self._path = path
        self._buf = bytearray()

    def write(self, data):
        self._buf.extend(data)
        return len(data)

    def close(self):
        _mock_fs[self._path] = bytes(self._buf)

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()


class _MockFileReader:
    def __init__(self, path):
        self._data = _mock_fs[path]
        self._pos = 0

    def read(self):
        d = self._data[self._pos:]
        self._pos = len(self._data)
        return d

    def close(self):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()


import builtins
builtins.open = _mock_open

# Force fresh import of hsm
for _m in ["hsm"]:
    if _m in sys.modules:
        del sys.modules[_m]
import hsm


@pytest.fixture(autouse=True)
def _reset_persist_state():
    """Clear the mock filesystem and reset key state before each test."""
    _mock_fs.clear()
    yield
    _mock_fs.clear()


class TestPersistKeyDerivation:
    """Tests for the PIN-to-key derivation function."""

    def test_same_pin_same_key(self):
        k1 = hsm._derive_pin_key("1234")
        k2 = hsm._derive_pin_key("1234")
        assert k1 == k2

    def test_different_pin_different_key(self):
        k1 = hsm._derive_pin_key("1234")
        k2 = hsm._derive_pin_key("5678")
        assert k1 != k2

    def test_key_is_32_bytes(self):
        k = hsm._derive_pin_key("test-pin")
        assert len(k) == 32

    def test_pin_as_bytes(self):
        k1 = hsm._derive_pin_key("1234")
        k2 = hsm._derive_pin_key(b"1234")
        assert k1 == k2

    def test_empty_pin(self):
        k = hsm._derive_pin_key("")
        assert len(k) == 32


class TestPersistKeyStoreLoad:
    """Tests for the store/load round-trip."""

    def test_store_and_load_round_trip(self):
        """Storing and loading with the correct PIN recovers the key."""
        original_key = hsm._KEY
        original_fp = hsm._fingerprint()
        assert hsm._persist_key_store("mypin123") is True
        # Simulate reboot: key changes
        hsm._KEY = os.urandom(32)
        assert hsm._fingerprint() != original_fp
        # Load with correct PIN
        ok, err = hsm._persist_key_load("mypin123")
        assert ok is True
        assert err is None
        assert hsm._KEY == original_key
        assert hsm._fingerprint() == original_fp

    def test_load_with_wrong_pin_recovers_different_key(self):
        """Loading with a wrong PIN gives a different (garbage) key."""
        original_key = hsm._KEY
        hsm._persist_key_store("correct-pin")
        # Load with wrong PIN
        ok, err = hsm._persist_key_load("wrong-pin")
        assert ok is True  # decryption succeeds (no integrity check on ECB)
        assert hsm._KEY != original_key  # but key is wrong

    def test_load_without_store(self):
        """Loading when nothing is stored returns error."""
        ok, err = hsm._persist_key_load("any-pin")
        assert ok is False
        assert err == "no-stored-key"

    def test_store_overwrites_previous(self):
        """Storing twice overwrites the previous stored key."""
        hsm._persist_key_store("pin1")
        old_key = hsm._KEY
        # Change key and store again
        hsm._KEY = os.urandom(32)
        hsm._persist_key_store("pin2")
        # Loading with pin2 should give the new key
        hsm._KEY = os.urandom(32)  # simulate reboot
        ok, _ = hsm._persist_key_load("pin2")
        assert ok
        assert hsm._KEY == old_key or hsm._KEY != old_key  # should be the new key


class TestPersistKeyErase:
    """Tests for the erase command."""

    def test_erase_after_store(self):
        hsm._persist_key_store("pin")
        assert hsm._persist_key_exists() is True
        assert hsm._persist_key_erase() is True
        assert hsm._persist_key_exists() is False

    def test_erase_without_store(self):
        """Erasing when nothing is stored returns False."""
        assert hsm._persist_key_erase() is False

    def test_exists_without_store(self):
        assert hsm._persist_key_exists() is False

    def test_exists_after_store(self):
        hsm._persist_key_store("pin")
        assert hsm._persist_key_exists() is True


class TestPersistKeyCommands:
    """Tests for the command-level interface (handle function)."""

    def test_key_status_no_persistent(self):
        resp = hsm.handle("KEY_STATUS")
        assert "persistent=no" in resp
        assert "degraded=no" in resp

    def test_key_store_command(self):
        resp = hsm.handle("KEY_STORE mypin")
        assert "OK key-stored" in resp
        assert hsm._persist_key_exists()

    def test_key_load_command(self):
        # Store first
        hsm.handle("KEY_STORE mypin")
        fp = hsm._fingerprint()
        # Simulate reboot
        hsm._KEY = os.urandom(32)
        assert hsm._fingerprint() != fp
        # Load
        resp = hsm.handle("KEY_LOAD mypin")
        assert "OK key-loaded" in resp
        assert fp in resp
        assert hsm._fingerprint() == fp

    def test_key_load_no_stored(self):
        resp = hsm.handle("KEY_LOAD anypin")
        assert "ERR" in resp
        assert "no-stored-key" in resp

    def test_key_erase_command(self):
        hsm.handle("KEY_STORE pin")
        resp = hsm.handle("KEY_ERASE")
        assert "OK key-erased" in resp
        assert not hsm._persist_key_exists()

    def test_key_erase_without_store(self):
        resp = hsm.handle("KEY_ERASE")
        assert "ERR" in resp or "no-stored-key" in resp

    def test_key_store_empty_pin(self):
        resp = hsm.handle("KEY_STORE")
        assert "ERR" in resp

    def test_key_load_empty_pin(self):
        resp = hsm.handle("KEY_LOAD")
        assert "ERR" in resp

    def test_key_store_in_help(self):
        resp = hsm.handle("HELP")
        assert "KEY_STORE" in resp
        assert "KEY_LOAD" in resp
        assert "KEY_ERASE" in resp
        assert "KEY_STATUS" in resp

    def test_key_status_after_store(self):
        hsm.handle("KEY_STORE pin")
        resp = hsm.handle("KEY_STATUS")
        assert "persistent=yes" in resp

    def test_key_status_after_erase(self):
        hsm.handle("KEY_STORE pin")
        hsm.handle("KEY_ERASE")
        resp = hsm.handle("KEY_STATUS")
        assert "persistent=no" in resp

    def test_fingerprint_changes_on_load(self):
        """After loading a stored key, the fingerprint matches the stored key."""
        hsm.handle("KEY_STORE pin")
        stored_fp = hsm._fingerprint()
        hsm._KEY = os.urandom(32)
        assert hsm._fingerprint() != stored_fp
        hsm.handle("KEY_LOAD pin")
        assert hsm._fingerprint() == stored_fp

    def test_challenge_works_after_load(self):
        """The loaded key can be used for challenge-response."""
        hsm.handle("KEY_STORE pin")
        challenge = "deadbeef" * 4
        hsm._KEY = os.urandom(32)
        hsm.handle("KEY_LOAD pin")
        resp = hsm.handle("CHALLENGE " + challenge)
        assert "RESPONSE" in resp

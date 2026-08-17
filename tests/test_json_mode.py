"""Host-side unit tests for the JSON output mode.

These tests import hsm.py directly (with MicroPython modules stubbed) and
verify that JSON mode toggles correctly and produces valid JSON responses.
No hardware needed.
"""
import json
import os
import sys

import pytest

# Stub MicroPython-only modules so hsm.py can be imported on CPython
_pico_dir = os.path.join(os.path.dirname(__file__), "..", "pico")
sys.path.insert(0, _pico_dir)

# Stub MicroPython modules with CPython equivalents
import binascii
sys.modules["ubinascii"] = binascii  # hexlify/unhexlify are the same
import time as _time
if not hasattr(_time, "sleep_ms"):
    _time.sleep_ms = lambda ms: _time.sleep(ms / 1000.0)
if not hasattr(_time, "ticks_ms"):
    _time.ticks_ms = lambda: int(_time.time() * 1000)
if not hasattr(_time, "ticks_diff"):
    _time.ticks_diff = lambda a, b: a - b

sys.modules["trng_native"] = type(sys)("stub")

# Stub machine module with needed attributes
_machine_stub = type(sys)("machine")
_machine_stub.unique_id = lambda: b"\x00\x01\x02\x03\x04\x05\x06\x07"
_machine_stub.Pin = type("Pin", (), {"__init__": lambda *a, **k: None, "on": lambda *a: None, "off": lambda *a: None, "toggle": lambda *a: None, "OUT": 0})
_machine_stub.Timer = type("Timer", (), {"__init__": lambda *a, **k: None, "init": lambda *a, **k: None, "deinit": lambda *a: None})
_machine_stub.ADC = type("ADC", (), {"__init__": lambda *a, **k: None, "read_u16": lambda *a: 0})
sys.modules["machine"] = _machine_stub

# Stub ujson (MicroPython's json — CPython has stdlib json)
sys.modules["ujson"] = json

# Stub trng module — hsm.py calls trng functions at import time and runtime
class _StubTrng:
    _wd_interval_ms = 5000
    _wd_failures = 0
    _wd_reprofiles = 0
    _has_native = False

    @staticmethod
    def key256(margin=4):
        return b"\x00" * 32

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

    @staticmethod
    def start_watchdog(interval_ms=5000):
        _StubTrng._wd_interval_ms = interval_ms
        return True


sys.modules["trng"] = _StubTrng

# Stub aes module
class _StubAes:
    @staticmethod
    def expand_key(key):
        return [0] * 240

    @staticmethod
    def encrypt_block(rk, pt):
        return pt  # identity

    @staticmethod
    def decrypt_block(rk, ct):
        return ct

    @staticmethod
    def ctr_xcrypt(rk, nonce, data):
        return data


sys.modules["aes"] = _StubAes

import hsm


class TestJSONMode:
    def test_default_is_text_mode(self):
        hsm._JSON_MODE = False
        resp = hsm.handle("PING")
        assert resp.startswith("PONG ")

    def test_json_on(self):
        hsm._JSON_MODE = False
        resp = hsm.handle("JSON ON")
        assert hsm._JSON_MODE is True
        data = json.loads(resp)
        assert data["ok"] is True
        assert data["cmd"] == "JSON"
        assert data["enabled"] is True

    def test_json_off(self):
        hsm._JSON_MODE = True
        resp = hsm.handle("JSON OFF")
        assert hsm._JSON_MODE is False
        # Response is in text mode (since we just turned it off)
        assert resp == "OK json off"

    def test_json_toggle_off_text_response(self):
        hsm._JSON_MODE = True
        resp = hsm.handle("JSON")
        assert hsm._JSON_MODE is False
        assert resp == "OK json off"

    def test_ping_json(self):
        hsm._JSON_MODE = True
        resp = hsm.handle("PING")
        data = json.loads(resp)
        assert data["ok"] is True
        assert data["cmd"] == "PING"
        assert isinstance(data["ts"], int)

    def test_who_json(self):
        hsm._JSON_MODE = True
        resp = hsm.handle("WHO")
        data = json.loads(resp)
        assert data["ok"] is True
        assert data["cmd"] == "WHO"
        assert "device" in data
        assert "fingerprint" in data
        assert "degraded" in data

    def test_challenge_json(self):
        hsm._JSON_MODE = True
        resp = hsm.handle("CHALLENGE deadbeef")
        data = json.loads(resp)
        assert data["ok"] is True
        assert data["cmd"] == "CHALLENGE"
        assert len(data["response"]) == 64  # 32-byte HMAC = 64 hex chars

    def test_seed_json(self):
        hsm._JSON_MODE = True
        resp = hsm.handle("SEED 32")
        data = json.loads(resp)
        assert data["ok"] is True
        assert data["cmd"] == "SEED"
        assert len(data["seed"]) == 64  # 32 bytes = 64 hex chars

    def test_version_json(self):
        hsm._JSON_MODE = True
        resp = hsm.handle("VERSION")
        data = json.loads(resp)
        assert data["ok"] is True
        assert data["cmd"] == "VERSION"
        assert "1.6" in data["version"]

    def test_help_json(self):
        hsm._JSON_MODE = True
        resp = hsm.handle("HELP")
        data = json.loads(resp)
        assert data["ok"] is True
        assert data["cmd"] == "HELP"
        assert isinstance(data["commands"], list)
        assert "JSON [ON|OFF]" in data["commands"]

    def test_error_json(self):
        hsm._JSON_MODE = True
        resp = hsm.handle("SEED abc")
        data = json.loads(resp)
        assert data["ok"] is False
        assert data["error"] == "bad-count"

    def test_unknown_cmd_json(self):
        hsm._JSON_MODE = True
        resp = hsm.handle("FOOBAR")
        data = json.loads(resp)
        assert data["ok"] is False
        assert data["error"] == "unknown-cmd"

    def test_aes_key_json(self):
        hsm._JSON_MODE = True
        resp = hsm.handle("AES_KEY")
        data = json.loads(resp)
        assert data["ok"] is True
        assert data["cmd"] == "AES_KEY"
        assert "fingerprint" in data

    def test_trng_json(self):
        hsm._JSON_MODE = True
        resp = hsm.handle("TRNG")
        data = json.loads(resp)
        assert data["ok"] is True
        assert data["cmd"] == "TRNG"
        assert "status" in data

    def test_text_mode_still_works(self):
        hsm._JSON_MODE = False
        resp = hsm.handle("WHO")
        assert resp.startswith("ID openhands-pico-hsm DEVICE ")
        assert "FINGERPRINT" in resp

    def test_json_appears_in_help(self):
        hsm._JSON_MODE = False
        resp = hsm.handle("HELP")
        assert "JSON" in resp

    def test_aes_enc_dec_roundtrip_json(self):
        hsm._JSON_MODE = True
        block = "00112233445566778899aabbccddeeff"
        enc = json.loads(hsm.handle("AES_ENC " + block))
        assert enc["ok"] is True
        dec = json.loads(hsm.handle("AES_DEC " + enc["ct"]))
        assert dec["ok"] is True
        assert dec["pt"] == block  # stub is identity

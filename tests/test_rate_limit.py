"""Host-side unit tests for the rate limiting / lockout feature.

Tests import hsm.py directly (with MicroPython modules stubbed) and verify
the sliding-window rate limiter with exponential backoff. No hardware needed.
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
        _StubTrng._wd_interval_ms = interval_ms
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

# Force fresh import of hsm (other tests may have stubbed trng)
for _m in ["hsm"]:
    if _m in sys.modules:
        del sys.modules[_m]
import hsm


@pytest.fixture(autouse=True)
def _reset_rate_limiter():
    """Reset rate limiter and JSON mode state before each test."""
    hsm._rate_reset()
    hsm._JSON_MODE = False
    yield
    hsm._rate_reset()
    hsm._JSON_MODE = False


class TestRateLimiter:
    def test_challenge_allowed_under_limit(self):
        """Normal challenges should succeed up to the rate limit."""
        for i in range(hsm._RATE_MAX_IN_WINDOW):
            resp = hsm.handle("CHALLENGE deadbeef")
            assert "RESPONSE" in resp or '"response"' in resp

    def test_challenge_rate_limited_after_max(self):
        """After max requests in the window, the next should be rate-limited."""
        for i in range(hsm._RATE_MAX_IN_WINDOW):
            hsm.handle("CHALLENGE deadbeef")
        resp = hsm.handle("CHALLENGE deadbeef")
        assert "rate-limited" in resp or "rate-limited" in resp.lower()

    def test_rate_limit_json_error(self):
        """Rate-limited response in JSON mode should be valid JSON with error."""
        hsm._JSON_MODE = True
        for i in range(hsm._RATE_MAX_IN_WINDOW):
            hsm.handle("CHALLENGE deadbeef")
        resp = hsm.handle("CHALLENGE deadbeef")
        data = json.loads(resp)
        assert data["ok"] is False
        assert data["error"] == "rate-limited"
        assert "retry_after_ms" in data

    def test_seed_also_rate_limited(self):
        """SEED should be rate-limited too after exceeding the window."""
        for i in range(hsm._RATE_MAX_IN_WINDOW):
            hsm.handle("SEED 16")
        resp = hsm.handle("SEED 16")
        assert "rate-limited" in resp.lower()

    def test_rate_limit_status_command(self):
        """RATE_LIMIT STATUS should show current state."""
        resp = hsm.handle("RATE_LIMIT STATUS")
        assert "RATE_LIMIT" in resp
        assert "OK" in resp

    def test_rate_limit_status_after_lockout(self):
        """RATE_LIMIT STATUS should show LOCKED after lockout."""
        for i in range(hsm._RATE_MAX_IN_WINDOW):
            hsm.handle("CHALLENGE deadbeef")
        hsm.handle("CHALLENGE deadbeef")  # triggers lockout
        resp = hsm.handle("RATE_LIMIT STATUS")
        assert "LOCKED" in resp

    def test_rate_limit_status_json(self):
        """RATE_LIMIT STATUS in JSON mode should return structured status."""
        hsm._JSON_MODE = True
        resp = hsm.handle("RATE_LIMIT STATUS")
        data = json.loads(resp)
        assert data["ok"] is True
        assert data["cmd"] == "RATE_LIMIT"
        assert "status" in data
        s = data["status"]
        assert "lockout_active" in s
        assert "requests_in_window" in s
        assert "max_per_window" in s

    def test_rate_limit_reset(self):
        """RATE_LIMIT RESET should clear the lockout."""
        for i in range(hsm._RATE_MAX_IN_WINDOW):
            hsm.handle("CHALLENGE deadbeef")
        hsm.handle("CHALLENGE deadbeef")  # triggers lockout
        resp = hsm.handle("RATE_LIMIT RESET")
        assert "OK" in resp
        # After reset, challenges should work again
        resp = hsm.handle("CHALLENGE deadbeef")
        assert "RESPONSE" in resp

    def test_rate_limit_reset_json(self):
        """RATE_LIMIT RESET in JSON mode should return structured status."""
        hsm._JSON_MODE = True
        resp = hsm.handle("RATE_LIMIT RESET")
        data = json.loads(resp)
        assert data["ok"] is True
        assert data["status"]["lockout_active"] is False

    def test_exponential_backoff(self):
        """Each lockout should double the lockout duration."""
        # First lockout
        for i in range(hsm._RATE_MAX_IN_WINDOW):
            hsm.handle("CHALLENGE deadbeef")
        hsm.handle("CHALLENGE deadbeef")  # triggers 1st lockout
        assert hsm._rate_lockout_ms == hsm._RATE_LOCKOUT_BASE_MS

        # Reset lockout state (simulating time passing)
        hsm._rate_lockout_until = 0
        hsm._rate_timestamps[:] = []
        # Re-fill the window
        for i in range(hsm._RATE_MAX_IN_WINDOW):
            hsm.handle("CHALLENGE deadbeef")
        hsm.handle("CHALLENGE deadbeef")  # triggers 2nd lockout
        assert hsm._rate_lockout_ms == hsm._RATE_LOCKOUT_BASE_MS * 2

    def test_backoff_capped(self):
        """Lockout duration should be capped at _RATE_LOCKOUT_MAX_MS."""
        hsm._rate_lockout_ms = hsm._RATE_LOCKOUT_MAX_MS  # already at cap
        hsm._rate_lockout_until = 0
        hsm._rate_timestamps[:] = []
        for i in range(hsm._RATE_MAX_IN_WINDOW):
            hsm.handle("CHALLENGE deadbeef")
        hsm.handle("CHALLENGE deadbeef")
        assert hsm._rate_lockout_ms == hsm._RATE_LOCKOUT_MAX_MS

    def test_non_tracked_commands_not_rate_limited(self):
        """WHO, PING, VERSION should not be rate-limited even after lockout."""
        for i in range(hsm._RATE_MAX_IN_WINDOW):
            hsm.handle("CHALLENGE deadbeef")
        hsm.handle("CHALLENGE deadbeef")  # triggers lockout
        # WHO should still work
        resp = hsm.handle("WHO")
        assert "ID" in resp or '"device"' in resp
        # PING should still work
        resp = hsm.handle("PING")
        assert "PONG" in resp or '"ts"' in resp

    def test_rate_limit_in_help(self):
        """RATE_LIMIT should appear in HELP output."""
        hsm._JSON_MODE = False
        resp = hsm.handle("HELP")
        assert "RATE_LIMIT" in resp

    def test_rate_limit_in_commands_json(self):
        """RATE_LIMIT should appear in JSON HELP commands list."""
        hsm._JSON_MODE = True
        resp = hsm.handle("HELP")
        data = json.loads(resp)
        assert "RATE_LIMIT" in " ".join(data["commands"])

    def test_bad_hex_not_counted_after_lockout(self):
        """After lockout, even bad hex should return rate-limited, not bad-hex."""
        for i in range(hsm._RATE_MAX_IN_WINDOW):
            hsm.handle("CHALLENGE deadbeef")
        resp = hsm.handle("CHALLENGE xyz")
        assert "rate-limited" in resp.lower()

    def test_lockout_clears_after_timeout(self):
        """After the lockout expires, challenges should work again."""
        for i in range(hsm._RATE_MAX_IN_WINDOW):
            hsm.handle("CHALLENGE deadbeef")
        hsm.handle("CHALLENGE deadbeef")  # triggers lockout
        # Simulate lockout expiry by setting lockout_until to past
        hsm._rate_lockout_until = 0
        hsm._rate_lockout_ms = 0
        hsm._rate_timestamps[:] = []
        resp = hsm.handle("CHALLENGE deadbeef")
        assert "RESPONSE" in resp

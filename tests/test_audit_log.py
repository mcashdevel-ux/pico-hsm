"""Host-side unit tests for the audit log (ring buffer).

Tests import hsm.py directly (with MicroPython modules stubbed) and verify
the in-RAM audit ring buffer records CHALLENGE events correctly. No hardware.
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

# Force fresh import of hsm
for _m in ["hsm"]:
    if _m in sys.modules:
        del sys.modules[_m]
import hsm


@pytest.fixture(autouse=True)
def _reset_state():
    """Reset audit log, rate limiter, and JSON mode before each test."""
    hsm._audit_clear()
    hsm._rate_reset()
    hsm._JSON_MODE = False
    yield
    hsm._audit_clear()
    hsm._rate_reset()
    hsm._JSON_MODE = False


class TestAuditLog:
    def test_empty_audit_log(self):
        """AUDIT on a fresh boot should show empty."""
        resp = hsm.handle("AUDIT")
        assert "empty" in resp

    def test_challenge_recorded(self):
        """A successful CHALLENGE should appear in the audit log."""
        hsm.handle("CHALLENGE deadbeef")
        resp = hsm.handle("AUDIT")
        assert "AUDIT entries=1" in resp
        assert "CHALLENGE" in resp
        assert "ok" in resp

    def test_challenge_hash_stored(self):
        """Audit entry should contain a challenge hash, not the raw challenge."""
        hsm.handle("CHALLENGE deadbeef")
        resp = hsm.handle("AUDIT")
        assert "ch=" in resp
        # The raw challenge "deadbeef" should NOT appear (only its hash)
        assert "deadbeef" not in resp

    def test_bad_hex_recorded(self):
        """A bad-hex challenge should be recorded as 'bad-hex'."""
        resp = hsm.handle("CHALLENGE xyz")
        assert "bad-hex" in resp
        audit = hsm.handle("AUDIT")
        assert "bad-hex" in audit

    def test_rate_limited_recorded(self):
        """A rate-limited challenge should be recorded as 'rate-limited'."""
        for i in range(hsm._RATE_MAX_IN_WINDOW):
            hsm.handle("CHALLENGE deadbeef")
        hsm.handle("CHALLENGE deadbeef")  # this one is rate-limited
        audit = hsm.handle("AUDIT")
        assert "rate-limited" in audit

    def test_multiple_challenges(self):
        """Multiple challenges should all appear in order (newest first)."""
        for i in range(5):
            hsm.handle("CHALLENGE %08x" % i)
        resp = hsm.handle("AUDIT")
        assert "entries=5" in resp

    def test_audit_n_parameter(self):
        """AUDIT <n> should return at most n entries."""
        for i in range(10):
            hsm.handle("CHALLENGE %08x" % i)
        resp = hsm.handle("AUDIT 3")
        # Should show 3 entries
        lines = resp.strip().split("\n")
        # First line is header, rest are entries
        assert len(lines) == 4  # 1 header + 3 entries

    def test_audit_clear(self):
        """AUDIT CLEAR should wipe the log."""
        hsm.handle("CHALLENGE deadbeef")
        hsm.handle("CHALLENGE cafebabe")
        hsm.handle("AUDIT CLEAR")
        resp = hsm.handle("AUDIT")
        assert "empty" in resp

    def test_ring_buffer_wraps(self):
        """When full, the ring buffer should overwrite oldest entries."""
        # Fill past capacity
        total = hsm._AUDIT_MAX + 10
        for i in range(total):
            hsm.handle("CHALLENGE %08x" % i)
        resp = hsm.handle("AUDIT")
        # Should show capacity, not total
        assert "entries=%d" % hsm._AUDIT_MAX in resp
        # The newest entry should be the last challenge
        # The oldest (challenge 0) should have been overwritten
        entries = hsm._audit_get(1)
        assert len(entries) == 1

    def test_ring_buffer_capacity_exact(self):
        """Filling exactly to capacity should work."""
        for i in range(hsm._AUDIT_MAX):
            hsm.handle("CHALLENGE %08x" % i)
        resp = hsm.handle("AUDIT")
        assert "entries=%d" % hsm._AUDIT_MAX in resp

    def test_audit_json_mode(self):
        """AUDIT in JSON mode should return structured entries."""
        hsm._JSON_MODE = True
        hsm.handle("CHALLENGE deadbeef")
        resp = hsm.handle("AUDIT")
        data = json.loads(resp)
        assert data["ok"] is True
        assert data["cmd"] == "AUDIT"
        assert "entries" in data
        assert len(data["entries"]) == 1
        e = data["entries"][0]
        assert "ts" in e
        assert "cmd" in e
        assert "ch_hash" in e
        assert "result" in e

    def test_audit_clear_json(self):
        """AUDIT CLEAR in JSON mode should return empty entries."""
        hsm._JSON_MODE = True
        hsm.handle("CHALLENGE deadbeef")
        resp = hsm.handle("AUDIT CLEAR")
        data = json.loads(resp)
        assert data["ok"] is True
        assert data["count"] == 0
        assert data["entries"] == []

    def test_audit_n_json(self):
        """AUDIT <n> in JSON mode should return n entries."""
        hsm._JSON_MODE = True
        for i in range(5):
            hsm.handle("CHALLENGE %08x" % i)
        resp = hsm.handle("AUDIT 3")
        data = json.loads(resp)
        assert len(data["entries"]) == 3

    def test_audit_in_help(self):
        """AUDIT should appear in HELP output."""
        resp = hsm.handle("HELP")
        assert "AUDIT" in resp

    def test_audit_status_alias(self):
        """AUDIT STATUS should be an alias for AUDIT."""
        hsm.handle("CHALLENGE deadbeef")
        resp1 = hsm.handle("AUDIT")
        resp2 = hsm.handle("AUDIT STATUS")
        assert resp1 == resp2

    def test_challenge_hash_is_sha256_prefix(self):
        """The ch_hash should be the first 8 bytes of SHA-256(challenge)."""
        import hashlib as _hl
        ch = b"\xde\xad\xbe\xef"
        hsm.handle("CHALLENGE deadbeef")
        entries = hsm._audit_get(1)
        expected = _hl.sha256(ch).digest()[:8].hex()
        assert entries[0]["ch_hash"] == expected

    def test_different_challenges_different_hashes(self):
        """Different challenges should produce different audit hashes."""
        hsm.handle("CHALLENGE deadbeef")
        hsm.handle("CHALLENGE cafebabe")
        entries = hsm._audit_get(2)
        assert entries[0]["ch_hash"] != entries[1]["ch_hash"]

    def test_non_challenge_commands_not_audited(self):
        """PING, WHO, SEED should not appear in the audit log."""
        hsm.handle("PING")
        hsm.handle("WHO")
        hsm.handle("SEED 16")
        resp = hsm.handle("AUDIT")
        assert "empty" in resp

    def test_audit_get_returns_newest_first(self):
        """_audit_get should return entries newest-first."""
        hsm.handle("CHALLENGE 00000001")
        hsm.handle("CHALLENGE 00000002")
        hsm.handle("CHALLENGE 00000003")
        entries = hsm._audit_get(3)
        import hashlib as _hl
        # Newest (00000003) should be first
        h3 = _hl.sha256(b"\x00\x00\x00\x03").digest()[:8].hex()
        assert entries[0]["ch_hash"] == h3

    def test_audit_n_zero_or_negative_clamped(self):
        """AUDIT 0 should be clamped to 1."""
        hsm.handle("CHALLENGE deadbeef")
        resp = hsm.handle("AUDIT 0")
        assert "entries=1" in resp

    def test_audit_n_over_capacity_clamped(self):
        """AUDIT with n > capacity should be clamped to capacity."""
        hsm.handle("CHALLENGE deadbeef")
        resp = hsm.handle("AUDIT 9999")
        # Only 1 entry exists, so should show 1
        assert "entries=1" in resp

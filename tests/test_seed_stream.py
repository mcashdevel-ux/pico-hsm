"""Host-side unit tests for the bulk SEED streaming mode.

Tests import hsm.py directly (with MicroPython modules stubbed) and verify
the SEED_STREAM command returns entropy in chunks. No hardware needed.
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
        return bytes(range(n % 256))[:n] if n <= 256 else bytes(range(256)) * (n // 256 + 1)

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
    """Reset state before each test."""
    hsm._rate_reset()
    hsm._audit_clear()
    hsm._enc_reset()
    hsm._JSON_MODE = False
    yield
    hsm._rate_reset()
    hsm._audit_clear()
    hsm._enc_reset()
    hsm._JSON_MODE = False


class TestSeedStream:
    def test_basic_stream(self):
        """SEED_STREAM should return entropy in chunks."""
        resp = hsm.handle("SEED_STREAM 128")
        assert "SEED_STREAM" in resp
        assert "total=128" in resp
        # Default chunk=64, so 128/64 = 2 chunks
        assert "chunks=2" in resp

    def test_custom_chunk_size(self):
        """SEED_STREAM with custom chunk size should produce correct chunks."""
        resp = hsm.handle("SEED_STREAM 256 32")
        assert "chunk=32" in resp
        assert "chunks=8" in resp  # 256/32 = 8

    def test_total_not_multiple_of_chunk(self):
        """When total is not a multiple of chunk, last chunk is smaller."""
        resp = hsm.handle("SEED_STREAM 100 32")
        # 100 / 32 = 3 full chunks + 1 partial (4 bytes)
        assert "chunks=4" in resp
        # Verify the chunks are on separate lines
        lines = resp.strip().split("\n")
        assert len(lines) == 5  # 1 header + 4 chunks

    def test_single_byte(self):
        """SEED_STREAM 1 should return one chunk of 1 byte."""
        resp = hsm.handle("SEED_STREAM 1")
        assert "total=1" in resp
        assert "chunks=1" in resp
        lines = resp.strip().split("\n")
        assert len(lines) == 2  # 1 header + 1 chunk

    def test_max_total(self):
        """SEED_STREAM 8192 should work (max allowed)."""
        resp = hsm.handle("SEED_STREAM 8192 256")
        assert "total=8192" in resp
        assert "chunks=32" in resp  # 8192/256 = 32

    def test_total_above_max_rejected(self):
        """SEED_STREAM above 8192 should be rejected."""
        resp = hsm.handle("SEED_STREAM 8193")
        assert "total-range" in resp.lower()

    def test_zero_total_rejected(self):
        """SEED_STREAM 0 should be rejected."""
        resp = hsm.handle("SEED_STREAM 0")
        assert "total-range" in resp.lower()

    def test_negative_total_rejected(self):
        """SEED_STREAM with negative total should be rejected."""
        resp = hsm.handle("SEED_STREAM -1")
        assert "total-range" in resp.lower() or "bad" in resp.lower()

    def test_chunk_above_max_rejected(self):
        """Chunk size above 256 should be rejected."""
        resp = hsm.handle("SEED_STREAM 128 257")
        assert "chunk-range" in resp.lower()

    def test_chunk_zero_rejected(self):
        """Chunk size 0 should be rejected."""
        resp = hsm.handle("SEED_STREAM 128 0")
        assert "chunk-range" in resp.lower()

    def test_bad_total(self):
        """Non-integer total should be rejected."""
        resp = hsm.handle("SEED_STREAM abc")
        assert "bad-total" in resp.lower()

    def test_bad_chunk(self):
        """Non-integer chunk size should be rejected."""
        resp = hsm.handle("SEED_STREAM 128 xyz")
        assert "bad-chunk" in resp.lower()

    def test_no_args(self):
        """SEED_STREAM with no args should show usage."""
        resp = hsm.handle("SEED_STREAM")
        assert "usage" in resp.lower()

    def test_too_many_args(self):
        """SEED_STREAM with 3+ args should show usage."""
        resp = hsm.handle("SEED_STREAM 128 64 32")
        assert "usage" in resp.lower()

    def test_json_mode(self):
        """SEED_STREAM in JSON mode should return structured response."""
        hsm._JSON_MODE = True
        resp = hsm.handle("SEED_STREAM 128 64")
        data = json.loads(resp)
        assert data["ok"] is True
        assert data["cmd"] == "SEED_STREAM"
        assert data["total_bytes"] == 128
        assert data["chunk_size"] == 64
        assert data["chunk_count"] == 2
        assert len(data["chunks"]) == 2
        # Each chunk should be hex
        for c in data["chunks"]:
            assert all(ch in "0123456789abcdef" for ch in c)

    def test_json_mode_single_chunk(self):
        """SEED_STREAM with total < chunk should produce one chunk in JSON."""
        hsm._JSON_MODE = True
        resp = hsm.handle("SEED_STREAM 16 64")
        data = json.loads(resp)
        assert data["chunk_count"] == 1
        assert len(data["chunks"]) == 1

    def test_chunk_hex_decodes_to_correct_bytes(self):
        """Each chunk should hex-decode to chunk_size bytes."""
        hsm._JSON_MODE = True
        resp = hsm.handle("SEED_STREAM 128 64")
        data = json.loads(resp)
        for c in data["chunks"]:
            raw = binascii.unhexlify(c)
            assert len(raw) == 64

    def test_total_bytes_match(self):
        """Sum of chunk byte lengths should equal total."""
        hsm._JSON_MODE = True
        resp = hsm.handle("SEED_STREAM 200 32")
        data = json.loads(resp)
        total = sum(len(binascii.unhexlify(c)) for c in data["chunks"])
        assert total == 200

    def test_rate_limited(self):
        """SEED_STREAM should be rate-limited like SEED."""
        for i in range(hsm._RATE_MAX_IN_WINDOW):
            hsm.handle("SEED 16")
        resp = hsm.handle("SEED_STREAM 128")
        assert "rate-limited" in resp.lower()

    def test_in_help(self):
        """SEED_STREAM should appear in HELP output."""
        resp = hsm.handle("HELP")
        assert "SEED_STREAM" in resp

    def test_in_commands_json(self):
        """SEED_STREAM should appear in JSON HELP commands list."""
        hsm._JSON_MODE = True
        resp = hsm.handle("HELP")
        data = json.loads(resp)
        assert "SEED_STREAM" in " ".join(data["commands"])

    def test_large_stream_performance(self):
        """Large stream (8192 bytes) should complete quickly."""
        resp = hsm.handle("SEED_STREAM 8192 256")
        assert "chunks=32" in resp

    def test_chunk_size_1(self):
        """Chunk size 1 should produce one chunk per byte."""
        resp = hsm.handle("SEED_STREAM 5 1")
        assert "chunks=5" in resp
        lines = resp.strip().split("\n")
        assert len(lines) == 6  # 1 header + 5 chunks

    def test_seed_stream_counts_as_one_rate_request(self):
        """A single SEED_STREAM should count as one request against rate limit."""
        # Use most of the rate limit with SEED_STREAM calls
        for i in range(hsm._RATE_MAX_IN_WINDOW - 1):
            r = hsm.handle("SEED_STREAM 32")
            assert "rate-limited" not in r.lower()
        # One more should still work
        r = hsm.handle("SEED_STREAM 32")
        assert "rate-limited" not in r.lower()
        # But the next one should be rate-limited
        r = hsm.handle("SEED_STREAM 32")
        assert "rate-limited" in r.lower()

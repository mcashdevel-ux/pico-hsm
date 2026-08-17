"""Host-side unit tests for the NIST SP 800-90B continuous health tests.

These tests do NOT need a Pico — they import trng.py's NIST functions
directly and test them with synthetic byte sequences (uniform random,
stuck source, biased source).
"""
import os
import random
import sys

import pytest

# trng.py imports MicroPython modules (machine, _thread, etc.) at module
# level, so we stub them before importing.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "pico"))

# Stub MicroPython-only modules so trng.py can be imported on CPython
for mod in ["machine", "_thread", "trng_native"]:
    sys.modules.setdefault(mod, type(sys)("stub"))

# MicroPython's time.sleep_ms is not in CPython's time module
import time as _time
if not hasattr(_time, "sleep_ms"):
    _time.sleep_ms = lambda ms: _time.sleep(ms / 1000.0)
if not hasattr(_time, "ticks_ms"):
    _time.ticks_ms = lambda: int(_time.time() * 1000)
if not hasattr(_time, "ticks_diff"):
    _time.ticks_diff = lambda a, b: a - b

import trng


class TestRepetitionCount:
    def test_uniform_random_passes(self):
        random.seed(42)
        raw = bytes(random.randint(0, 255) for _ in range(1024))
        ok, max_run, details = trng._nist_repetition_count(raw)
        assert ok is True
        assert max_run < details["threshold"]

    def test_stuck_source_fails(self):
        # 1024 identical bytes — a completely stuck source
        raw = b"\x42" * 1024
        ok, max_run, details = trng._nist_repetition_count(raw)
        assert ok is False
        assert max_run > details["threshold"]

    def test_long_run_fails(self):
        # Mostly random but with a run of 30 identical bytes
        random.seed(99)
        raw = bytearray(random.randint(0, 255) for _ in range(500))
        raw[100:130] = b"\xAA" * 30
        ok, max_run, details = trng._nist_repetition_count(bytes(raw))
        assert ok is False

    def test_short_sequence_passes(self):
        ok, max_run, details = trng._nist_repetition_count(b"\x01\x02\x03")
        assert ok is True
        assert details["n"] == 3

    def test_threshold_scales_with_n(self):
        # Larger sample → higher threshold
        random.seed(1)
        raw_small = bytes(random.randint(0, 255) for _ in range(64))
        raw_large = bytes(random.randint(0, 255) for _ in range(1024))
        _, _, d_small = trng._nist_repetition_count(raw_small)
        _, _, d_large = trng._nist_repetition_count(raw_large)
        assert d_large["threshold"] > d_small["threshold"]


class TestAdaptiveProportion:
    def test_uniform_random_passes(self):
        random.seed(42)
        raw = bytes(random.randint(0, 255) for _ in range(512))
        ok, max_count, details = trng._nist_adaptive_proportion(raw)
        assert ok is True
        assert max_count <= details["cutoff"]

    def test_biased_source_fails(self):
        # First sample is the biased value (0x42), which appears 100+ times
        raw = bytearray(b"\x42")  # first sample = tracked value
        raw.extend(random.randint(0, 255) for _ in range(411))
        raw.extend(b"\x42" * 100)  # pad with more of the biased value
        random.shuffle(raw[1:])  # shuffle everything except the first byte
        ok, max_count, details = trng._nist_adaptive_proportion(bytes(raw))
        assert ok is False
        assert details["tracked_count"] > details["cutoff"]

    def test_all_same_value_fails(self):
        raw = b"\x00" * 512
        ok, max_count, details = trng._nist_adaptive_proportion(raw)
        assert ok is False
        assert max_count == 512

    def test_short_sequence_passes(self):
        ok, max_count, details = trng._nist_adaptive_proportion(b"\x01\x02")
        assert ok is True
        assert details["n"] == 2


class TestNISTHealth:
    def test_healthy_data_passes(self):
        random.seed(7)
        raw = bytes(random.randint(0, 255) for _ in range(512))
        ok, details = trng._nist_health(raw)
        assert ok is True
        assert "repetition_count" in details
        assert "adaptive_proportion" in details

    def test_stuck_source_fails(self):
        raw = b"\xFF" * 512
        ok, details = trng._nist_health(raw)
        assert ok is False

    def test_biased_source_fails(self):
        raw = b"\x00" * 512
        ok, details = trng._nist_health(raw)
        assert ok is False

    def test_returns_details_dict(self):
        random.seed(3)
        raw = bytes(random.randint(0, 255) for _ in range(256))
        ok, details = trng._nist_health(raw)
        rc = details["repetition_count"]
        ap = details["adaptive_proportion"]
        assert "max_run" in rc
        assert "threshold" in rc
        assert "max_count" in ap
        assert "cutoff" in ap
        assert details["healthy"] == ok

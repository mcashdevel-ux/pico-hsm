#!/usr/bin/env python3
"""Basic statistical tests for the pico-hsm TRNG.

Pulls N bytes of raw entropy from the board via SEED commands, then runs
three lightweight suites from NIST SP800-22 (reduced):

- **Monobit** — proportion of 1-bits should be ~0.5 (±2/sqrt(N*8)).
- **Runs test** — number of bit transitions should be consistent with
  a fair coin (chi-square on the observed run lengths).
- **Chi-square on byte values** — byte distribution should be uniform
  (expected count = N/256 per byte).

These are NOT a substitute for NIST SP800-22/90B certification. They are
a quick sanity check that the entropy source hasn't degraded.

Usage::

    python3 host/trng_stats.py [--port /dev/ttyACM0] [--bytes 4096]
"""
import argparse
import binascii
import math
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from hsm_client import PicoHSM, DEFAULT_PORT

MAX_SEED = 256  # Pico protocol limit per SEED command


def collect_entropy(hsm, nbytes):
    """Collect *nbytes* of raw entropy via multiple SEED calls."""
    chunks = []
    remaining = nbytes
    while remaining > 0:
        n = min(remaining, MAX_SEED)
        chunks.append(hsm.seed(n))
        remaining -= n
    return b"".join(chunks)


def monobit_test(data):
    """NIST monobit test: count 1-bits, check proportion ~0.5."""
    nbits = len(data) * 8
    ones = sum(bin(b).count("1") for b in data)
    proportion = ones / nbits
    # Pass if within ±2/sqrt(nbits) of 0.5 (NIST threshold)
    threshold = 2.0 / math.sqrt(nbits)
    passed = abs(proportion - 0.5) <= threshold
    return {
        "name": "Monobit",
        "ones": ones,
        "zeros": nbits - ones,
        "proportion": round(proportion, 6),
        "threshold": round(threshold, 6),
        "passed": passed,
    }


def runs_test(data):
    """Runs test: count bit transitions, compare to expected for fair coin."""
    bits = []
    for b in data:
        for i in range(7, -1, -1):
            bits.append((b >> i) & 1)
    n = len(bits)
    # Count runs (transitions)
    transitions = sum(1 for i in range(1, n) if bits[i] != bits[i - 1])
    # Expected transitions for fair coin: (n-1)/2
    expected = (n - 1) / 2.0
    # Std dev: sqrt((n-1)/4) for binomial
    stddev = math.sqrt((n - 1) / 4.0)
    z = (transitions - expected) / stddev if stddev > 0 else 0
    # Pass if |z| <= 3 (3-sigma)
    passed = abs(z) <= 3.0
    return {
        "name": "Runs",
        "transitions": transitions,
        "expected": round(expected, 1),
        "z_score": round(z, 4),
        "passed": passed,
    }


def chi_square_test(data):
    """Chi-square test on byte value distribution (expected uniform)."""
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    expected = n / 256.0
    chi2 = sum((c - expected) ** 2 / expected for c in counts)
    # 255 degrees of freedom; critical value at p=0.01 is ~310
    passed = chi2 < 310.0
    return {
        "name": "Chi-square (bytes)",
        "chi2": round(chi2, 2),
        "df": 255,
        "critical_p01": 310,
        "min_count": min(counts),
        "max_count": max(counts),
        "expected_per_byte": round(expected, 1),
        "passed": passed,
    }


def main():
    parser = argparse.ArgumentParser(description="pico-hsm TRNG statistical test")
    parser.add_argument("--port", default=DEFAULT_PORT,
                        help="serial port (default: $PICO_HSM_PORT or /dev/ttyACM0)")
    parser.add_argument("--bytes", type=int, default=4096,
                        help="total bytes to test (default: 4096)")
    args = parser.parse_args()

    print("Collecting %d bytes from Pico TRNG via SEED..." % args.bytes)
    with PicoHSM(args.port) as hsm:
        data = collect_entropy(hsm, args.bytes)
    print("Got %d bytes.\n" % len(data))

    results = [
        monobit_test(data),
        runs_test(data),
        chi_square_test(data),
    ]

    all_pass = True
    for r in results:
        status = "PASS" if r["passed"] else "FAIL"
        if not r["passed"]:
            all_pass = False
        detail = "  ".join("%s=%s" % (k, v) for k, v in r.items()
                           if k not in ("name", "passed"))
        print("[%-4s] %s: %s" % (status, r["name"], detail))

    print()
    if all_pass:
        print("All tests PASSED — TRNG output looks random.")
        sys.exit(0)
    else:
        print("Some tests FAILED — TRNG output may be biased.")
        sys.exit(1)


if __name__ == "__main__":
    main()

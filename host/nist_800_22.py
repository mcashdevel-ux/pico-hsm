#!/usr/bin/env python3
"""Standalone NIST SP 800-22 statistical tests on a binary file."""
import math
import sys


def monobit_test(data):
    nbits = len(data) * 8
    ones = sum(bin(b).count("1") for b in data)
    proportion = ones / nbits
    threshold = 2.0 / math.sqrt(nbits)
    passed = abs(proportion - 0.5) <= threshold
    return passed, f"proportion={proportion:.6f} threshold=±{threshold:.6f} ones={ones}"


def runs_test(data):
    nbits = len(data) * 8
    bits = []
    for b in data:
        for i in range(7, -1, -1):
            bits.append((b >> i) & 1)
    transitions = sum(1 for i in range(1, len(bits)) if bits[i] != bits[i - 1])
    expected = (nbits - 1) * 0.5
    chi_sq = (transitions - expected) ** 2 / expected
    passed = chi_sq < 3.841  # 95% confidence, 1 dof
    return passed, f"transitions={transitions} expected={expected:.1f} chi_sq={chi_sq:.4f}"


def chi_square_test(data):
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    expected = len(data) / 256
    chi_sq = sum((c - expected) ** 2 / expected for c in counts)
    passed = chi_sq < 311.41  # 95% confidence, 255 dof
    return passed, f"chi_sq={chi_sq:.4f} threshold=311.41 expected={expected:.1f}/byte"


def poker_test(data):
    """4-bit poker test: divide into 4-bit nibbles, check distribution."""
    nibbles = []
    for b in data:
        nibbles.append(b >> 4)
        nibbles.append(b & 0xF)
    counts = [0] * 16
    for n in nibbles:
        counts[n] += 1
    expected = len(nibbles) / 16
    chi_sq = sum((c - expected) ** 2 / expected for c in counts)
    passed = chi_sq < 25.0  # 95% confidence, 15 dof
    return passed, f"chi_sq={chi_sq:.4f} threshold=25.0"


def serial_test(data):
    """2-bit serial test: check pairs of bits."""
    bits = []
    for b in data:
        for i in range(7, -1, -1):
            bits.append((b >> i) & 1)
    pairs = [(bits[i], bits[i + 1]) for i in range(0, len(bits) - 1, 2)]
    counts = [0, 0, 0, 0]
    for a, b in pairs:
        counts[a * 2 + b] += 1
    expected = len(pairs) / 4
    chi_sq = sum((c - expected) ** 2 / expected for c in counts)
    passed = chi_sq < 7.815  # 95% confidence, 3 dof
    return passed, f"chi_sq={chi_sq:.4f} threshold=7.815 counts={counts}"


def autocorr_test(data, lag=1):
    """Autocorrelation test: check for periodicity."""
    bits = []
    for b in data:
        for i in range(7, -1, -1):
            bits.append((b >> i) & 1)
    n = len(bits)
    matches = sum(1 for i in range(n - lag) if bits[i] == bits[i + lag])
    proportion = matches / (n - lag)
    threshold = 2.0 / math.sqrt(n - lag)
    passed = abs(proportion - 0.5) <= threshold
    return passed, f"lag={lag} proportion={proportion:.6f} threshold=±{threshold:.6f}"


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <file.bin> [lag]")
        sys.exit(1)
    fname = sys.argv[1]
    lag = int(sys.argv[2]) if len(sys.argv) > 2 else 1
    with open(fname, "rb") as f:
        data = f.read()
    print(f"Loaded {len(data)} bytes from {fname}")
    print()

    tests = [
        ("Monobit", monobit_test(data)),
        ("Runs", runs_test(data)),
        ("Chi-square (byte)", chi_square_test(data)),
        ("Poker (4-bit)", poker_test(data)),
        ("Serial (2-bit)", serial_test(data)),
        (f"Autocorr (lag={lag})", autocorr_test(data, lag)),
    ]

    all_pass = True
    for name, (passed, detail) in tests:
        status = "✅ PASS" if passed else "❌ FAIL"
        print(f"{status}  {name}: {detail}")
        if not passed:
            all_pass = False

    print()
    if all_pass:
        print("All tests PASSED — output looks random.")
    else:
        print("Some tests FAILED — investigate the entropy source.")
        sys.exit(1)


if __name__ == "__main__":
    main()

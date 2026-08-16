"""Integration tests for the pico-hsm board.

These tests connect to a real Pico via the serial port. They are skipped
if no board is detected (see conftest.py).
"""
import binascii
import os

from conftest import skip_no_hardware


@skip_no_hardware
class TestPing:
    def test_ping_returns_int(self, hsm):
        """PING should return a positive integer (ticks_ms)."""
        result = hsm.ping()
        assert isinstance(result, int)
        assert result > 0

    def test_ping_increases(self, hsm):
        """Successive PINGs should show increasing tick counts."""
        t1 = hsm.ping()
        t2 = hsm.ping()
        assert t2 > t1


@skip_no_hardware
class TestWho:
    def test_who_format(self, hsm):
        """WHO should return 'ID openhands-pico-hsm DEVICE <16hex> FINGERPRINT <64hex>'."""
        resp = hsm.who()
        assert resp.startswith("ID openhands-pico-hsm DEVICE ")
        assert " FINGERPRINT " in resp
        parts = resp.split()
        device = parts[parts.index("DEVICE") + 1]
        fp = parts[parts.index("FINGERPRINT") + 1]
        assert len(device) == 16
        int(device, 16)  # valid hex
        assert len(fp) == 64
        int(fp, 16)

    def test_device_id_stable(self, hsm):
        """Device ID (chip ID) should be stable across calls within a session."""
        did = hsm.device_id()
        assert len(did) == 16
        int(did, 16)
        assert hsm.device_id() == did

    def test_fingerprint_stable_within_session(self, hsm):
        """Same fingerprint within one session (key is volatile per-boot)."""
        fp1 = hsm.fingerprint()
        fp2 = hsm.fingerprint()
        assert fp1 == fp2
        assert len(fp1) == 64


@skip_no_hardware
class TestChallenge:
    def test_challenge_returns_32_bytes(self, hsm):
        """CHALLENGE should return a 32-byte HMAC-SHA256."""
        mac = hsm.challenge(os.urandom(32))
        assert isinstance(mac, bytes)
        assert len(mac) == 32

    def test_challenge_deterministic(self, hsm):
        """Same challenge within a session -> same HMAC."""
        challenge = b"deadbeef" + b"\x00" * 24
        mac1 = hsm.challenge(challenge)
        mac2 = hsm.challenge(challenge)
        assert mac1 == mac2

    def test_challenge_different_inputs(self, hsm):
        """Different challenges -> different HMACs."""
        mac1 = hsm.challenge(b"\x01" * 32)
        mac2 = hsm.challenge(b"\x02" * 32)
        assert mac1 != mac2

    def test_challenge_accepts_hex_string(self, hsm):
        """CHALLENGE should accept a hex string as well as bytes."""
        mac_from_hex = hsm.challenge("deadbeef")
        mac_from_bytes = hsm.challenge(binascii.unhexlify("deadbeef"))
        assert mac_from_hex == mac_from_bytes


@skip_no_hardware
class TestSeed:
    def test_seed_returns_correct_length(self, hsm):
        """SEED n should return exactly n bytes."""
        for n in (1, 16, 32, 64, 128, 256):
            raw = hsm.seed(n)
            assert isinstance(raw, bytes)
            assert len(raw) == n, f"SEED {n} returned {len(raw)} bytes"

    def test_seed_non_deterministic(self, hsm):
        """Two SEED calls should return different values (true RNG)."""
        s1 = hsm.seed(32)
        s2 = hsm.seed(32)
        assert s1 != s2

    def test_seed_max_256(self, hsm):
        """SEED > 256 should return an error."""
        resp = hsm.seed(999)
        assert isinstance(resp, str)
        assert "ERR" in resp

    def test_seed_zero_invalid(self, hsm):
        """SEED 0 should return an error."""
        resp = hsm.seed(0)
        assert isinstance(resp, str)
        assert "ERR" in resp


@skip_no_hardware
class TestVersion:
    def test_version_format(self, hsm):
        """VERSION should return a string with 'pico-hsm/' and 'micropython-'."""
        resp = hsm.version()
        assert "pico-hsm/" in resp
        assert "micropython-" in resp


@skip_no_hardware
class TestHelp:
    def test_help_lists_commands(self, hsm):
        """HELP should list all available commands."""
        resp = hsm.help()
        assert resp.startswith("COMMANDS ")
        for cmd in ("WHO", "PING", "CHALLENGE", "SEED", "HELP", "VERSION"):
            assert cmd in resp


@skip_no_hardware
class TestErrorHandling:
    def test_unknown_command(self, hsm):
        """Unknown commands should return ERR unknown-cmd."""
        resp = hsm._send("FOOBAR")
        assert "ERR" in resp

    def test_bad_seed_count(self, hsm):
        """Non-integer SEED count should return ERR."""
        resp = hsm._send("SEED abc")
        assert "ERR" in resp

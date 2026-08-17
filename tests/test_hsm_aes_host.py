"""Pytest integration tests for AES and TRNG commands via the serial protocol.

Unlike test_hsm_aes.py (which runs *on* the Pico via mpremote), these tests
run on the host and talk to the board through hsm_client.py — exercising the
full serial round-trip including framing, hex parsing, and timeout handling.

These tests connect to a real Pico via the serial port. They are skipped
if no board is detected (see conftest.py).
"""
import os

from conftest import skip_no_hardware


@skip_no_hardware
class TestAESKey:
    def test_aes_key_returns_fingerprint(self, hsm):
        fp = hsm.aes_key()
        assert isinstance(fp, str)
        assert len(fp) == 64
        int(fp, 16)

    def test_aes_key_stable_within_session(self, hsm):
        fp1 = hsm.aes_key()
        fp2 = hsm.aes_key()
        assert fp1 == fp2


@skip_no_hardware
class TestAESEncDec:
    def test_enc_returns_16_bytes(self, hsm):
        pt = bytes(range(16))
        ct = hsm.aes_enc(pt)
        assert isinstance(ct, bytes)
        assert len(ct) == 16

    def test_dec_round_trip(self, hsm):
        pt = bytes(range(16))
        ct = hsm.aes_enc(pt)
        pt2 = hsm.aes_dec(ct)
        assert pt2 == pt

    def test_dec_round_trip_random_block(self, hsm):
        pt = os.urandom(16)
        ct = hsm.aes_enc(pt)
        assert ct != pt
        pt2 = hsm.aes_dec(ct)
        assert pt2 == pt

    def test_enc_bad_block_size(self, hsm):
        resp = hsm.aes_enc(b"\x00\x01")
        assert resp == "ERR block-size-16"

    def test_enc_bad_hex(self, hsm):
        resp = hsm.aes_enc("zz")
        assert resp == "ERR bad-hex"

    def test_dec_bad_hex(self, hsm):
        resp = hsm.aes_dec("zz")
        assert resp == "ERR bad-hex"


@skip_no_hardware
class TestAESCTR:
    def test_ctr_round_trip(self, hsm):
        nonce = b"\x00" * 16
        data = b"Hello World!"
        enc = hsm.aes_ctr(nonce, data)
        assert enc != data
        dec = hsm.aes_ctr(nonce, enc)
        assert dec == data

    def test_ctr_multi_block(self, hsm):
        nonce = b"\x00" * 16
        data = bytes(range(64))
        enc = hsm.aes_ctr(nonce, data)
        assert len(enc) == 64
        dec = hsm.aes_ctr(nonce, enc)
        assert dec == data

    def test_ctr_empty_data(self, hsm):
        nonce = b"\x00" * 16
        out = hsm.aes_ctr(nonce, b"")
        assert out == b""

    def test_ctr_bad_nonce_size(self, hsm):
        resp = hsm.aes_ctr(b"\x00", b"test")
        assert resp == "ERR nonce-size-16"


@skip_no_hardware
class TestTRNGCommands:
    def test_trng_status(self, hsm):
        resp = hsm._send("TRNG")
        assert "BITS " in resp
        assert "NUM_BITS " in resp

    def test_trng_reprofile(self, hsm):
        resp = hsm._send("TRNG_REPROFILE")
        assert resp.startswith("OK reprofile ")

    def test_trng_watchdog_toggle(self, hsm):
        hsm._send("TRNG_WATCHDOG OFF")
        resp = hsm._send("TRNG_WATCHDOG")
        assert "STOPPED" in resp
        hsm._send("TRNG_WATCHDOG ON")
        resp = hsm._send("TRNG_WATCHDOG")
        assert "RUNNING" in resp

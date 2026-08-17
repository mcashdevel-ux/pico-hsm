"""Host-side unit tests for the encrypted serial protocol (AES-CTR transport).

Tests import hsm.py directly (with MicroPython modules stubbed) and verify
the AES-CTR encrypted transport layer. No hardware needed.
"""
import hashlib
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
    """AES stub using a simple XOR-based CTR mode for testing.

    This is NOT real AES — it's a deterministic CTR-mode cipher using SHA-256
    as a block function, which is sufficient for testing the protocol logic.
    """
    @staticmethod
    def expand_key(key):
        return key  # return the key directly as the "round key"

    @staticmethod
    def encrypt_block(rk, pt):
        return bytes(d ^ k for d, k in zip(pt, hashlib.sha256(rk).digest()))

    @staticmethod
    def decrypt_block(rk, ct):
        return bytes(d ^ k for d, k in zip(ct, hashlib.sha256(rk).digest()))

    @staticmethod
    def ctr_xcrypt(rk, nonce, data):
        """XOR data with a keystream derived from rk and nonce."""
        keystream = b""
        block_num = 0
        while len(keystream) < len(data):
            block = hashlib.sha256(rk + nonce + block_num.to_bytes(4, 'big')).digest()
            keystream += block
            block_num += 1
        return bytes(d ^ k for d, k in zip(data, keystream))


sys.modules["aes"] = _StubAes

# Force fresh import of hsm
for _m in ["hsm"]:
    if _m in sys.modules:
        del sys.modules[_m]
import hsm


def _derive_session_key(nonce_bytes):
    """Helper: compute the same session key the host would compute."""
    hmac_resp = hsm._hmac_sha256(hsm._KEY, nonce_bytes)
    return hashlib.sha256(b'enc-session:' + nonce_bytes + hmac_resp).digest()


def _encrypt(plaintext_str, session_key, counter):
    """Helper: encrypt a command the way the host would."""
    rk = hsm._aes.expand_key(session_key)
    nonce = counter.to_bytes(16, 'big')
    ct = hsm._aes.ctr_xcrypt(rk, nonce, plaintext_str.encode())
    return ct


def _decrypt(ciphertext_bytes, session_key, counter):
    """Helper: decrypt a response the way the host would."""
    rk = hsm._aes.expand_key(session_key)
    nonce = counter.to_bytes(16, 'big')
    return hsm._aes.ctr_xcrypt(rk, nonce, ciphertext_bytes)


@pytest.fixture(autouse=True)
def _reset_state():
    """Reset all state before each test."""
    hsm._enc_reset()
    hsm._audit_clear()
    hsm._rate_reset()
    hsm._JSON_MODE = False
    yield
    hsm._enc_reset()
    hsm._audit_clear()
    hsm._rate_reset()
    hsm._JSON_MODE = False


class TestEncryptedProtocol:
    def test_enc_status_off_by_default(self):
        """ENC STATUS should show inactive by default."""
        resp = hsm.handle("ENC STATUS")
        assert "ENC OFF" in resp

    def test_enc_on_activates_session(self):
        """ENC ON should activate the encrypted session."""
        nonce = b"\x00" * 16
        nonce_hex = binascii.hexlify(nonce).decode()
        resp = hsm.handle("ENC ON " + nonce_hex)
        assert "ENC ACTIVE" in resp or "active" in resp.lower()

    def test_enc_off_deactivates(self):
        """ENC OFF should deactivate the session."""
        nonce = b"\x00" * 16
        hsm.handle("ENC ON " + binascii.hexlify(nonce).decode())
        resp = hsm.handle("ENC OFF")
        assert "ENC OFF" in resp

    def test_enc_msg_not_active(self):
        """ENC_MSG before ENC ON should fail."""
        ct = b"\x00" * 16
        resp = hsm.handle("ENC_MSG 0 " + binascii.hexlify(ct).decode())
        assert "not-active" in resp.lower()

    def test_enc_msg_decrypts_and_executes(self):
        """ENC_MSG should decrypt, execute, and return encrypted response."""
        nonce = b"\x00" * 16
        nonce_hex = binascii.hexlify(nonce).decode()
        hsm.handle("ENC ON " + nonce_hex)
        session_key = _derive_session_key(nonce)

        # Encrypt a PING command
        plaintext = "PING"
        ct = _encrypt(plaintext, session_key, 0)
        ct_hex = binascii.hexlify(ct).decode()

        resp = hsm.handle("ENC_MSG 0 " + ct_hex)
        # Should be ENC_MSG <counter> <response_hex> (text mode)
        assert resp.startswith("ENC_MSG 0 ")

    def test_enc_msg_ping_roundtrip(self):
        """Full round-trip: encrypt PING, send, decrypt response → PONG."""
        nonce = b"\x01\x02\x03\x04\x05\x06\x07\x08" + b"\x00" * 8
        nonce_hex = binascii.hexlify(nonce).decode()
        hsm.handle("ENC ON " + nonce_hex)
        session_key = _derive_session_key(nonce)

        # Encrypt PING
        ct = _encrypt("PING", session_key, 0)
        resp = hsm.handle("ENC_MSG 0 " + binascii.hexlify(ct).decode())

        # Text mode: ENC_MSG 0 <hex>
        assert resp.startswith("ENC_MSG 0 ")
        enc_resp_hex = resp.split(" ", 2)[2]
        enc_resp = binascii.unhexlify(enc_resp_hex)
        decrypted = _decrypt(enc_resp, session_key, 0)
        assert b"PONG" in decrypted

    def test_enc_msg_challenge_roundtrip(self):
        """Full round-trip: encrypt CHALLENGE, decrypt response."""
        nonce = b"\xAA" * 16
        nonce_hex = binascii.hexlify(nonce).decode()
        hsm.handle("ENC ON " + nonce_hex)
        session_key = _derive_session_key(nonce)

        ct = _encrypt("CHALLENGE deadbeef", session_key, 0)
        resp = hsm.handle("ENC_MSG 0 " + binascii.hexlify(ct).decode())
        assert resp.startswith("ENC_MSG 0 ")
        enc_resp_hex = resp.split(" ", 2)[2]
        enc_resp = binascii.unhexlify(enc_resp_hex)
        decrypted = _decrypt(enc_resp, session_key, 0)
        assert b"RESPONSE" in decrypted

    def test_replay_protection(self):
        """Replaying the same counter should be rejected."""
        nonce = b"\x00" * 16
        hsm.handle("ENC ON " + binascii.hexlify(nonce).decode())
        session_key = _derive_session_key(nonce)

        ct = _encrypt("PING", session_key, 5)
        ct_hex = binascii.hexlify(ct).decode()

        # First message with rx counter 5 should work (tx counter starts at 0)
        resp1 = hsm.handle("ENC_MSG 5 " + ct_hex)
        assert resp1.startswith("ENC_MSG 0 ")  # tx counter is 0

        # Replay with same rx counter 5 should fail
        resp2 = hsm.handle("ENC_MSG 5 " + ct_hex)
        assert "replay" in resp2.lower()

    def test_counter_must_increase(self):
        """A lower counter than the last received should be rejected."""
        nonce = b"\x00" * 16
        hsm.handle("ENC ON " + binascii.hexlify(nonce).decode())
        session_key = _derive_session_key(nonce)

        # Send with counter 10
        ct10 = _encrypt("PING", session_key, 10)
        resp1 = hsm.handle("ENC_MSG 10 " + binascii.hexlify(ct10).decode())
        assert "replay" not in resp1.lower()

        # Send with counter 5 (lower) — should be rejected
        ct5 = _encrypt("PING", session_key, 5)
        resp2 = hsm.handle("ENC_MSG 5 " + binascii.hexlify(ct5).decode())
        assert "replay" in resp2.lower()

    def test_enc_on_bad_hex(self):
        """ENC ON with bad hex should fail."""
        resp = hsm.handle("ENC ON xyz")
        assert "bad-hex" in resp.lower()

    def test_enc_on_short_nonce(self):
        """ENC ON with a nonce < 8 bytes should fail."""
        resp = hsm.handle("ENC ON 00112233")  # 4 bytes
        assert "nonce-too-short" in resp.lower() or "too-short" in resp.lower()

    def test_enc_on_no_nonce(self):
        """ENC ON without a nonce should show usage error."""
        resp = hsm.handle("ENC ON")
        assert "usage" in resp.lower()

    def test_enc_status_json(self):
        """ENC STATUS in JSON mode should return structured status."""
        hsm._JSON_MODE = True
        resp = hsm.handle("ENC STATUS")
        data = json.loads(resp)
        assert data["ok"] is True
        assert data["cmd"] == "ENC"
        assert data["status"]["active"] is False

    def test_enc_on_json(self):
        """ENC ON in JSON mode should return structured status."""
        hsm._JSON_MODE = True
        nonce = b"\x00" * 16
        resp = hsm.handle("ENC ON " + binascii.hexlify(nonce).decode())
        data = json.loads(resp)
        assert data["ok"] is True
        assert data["status"]["active"] is True

    def test_enc_off_json(self):
        """ENC OFF in JSON mode should return structured status."""
        hsm._JSON_MODE = True
        resp = hsm.handle("ENC OFF")
        data = json.loads(resp)
        assert data["ok"] is True
        assert data["status"]["active"] is False

    def test_enc_in_help(self):
        """ENC should appear in HELP output."""
        resp = hsm.handle("HELP")
        assert "ENC" in resp

    def test_enc_msg_bad_counter(self):
        """ENC_MSG with a non-integer counter should fail."""
        nonce = b"\x00" * 16
        hsm.handle("ENC ON " + binascii.hexlify(nonce).decode())
        resp = hsm.handle("ENC_MSG abc deadbeef")
        assert "bad-counter" in resp.lower()

    def test_enc_msg_missing_data(self):
        """ENC_MSG without ciphertext should fail."""
        nonce = b"\x00" * 16
        hsm.handle("ENC ON " + binascii.hexlify(nonce).decode())
        resp = hsm.handle("ENC_MSG 0")
        assert "usage" in resp.lower()

    def test_enc_msg_bad_hex(self):
        """ENC_MSG with bad hex ciphertext should fail."""
        nonce = b"\x00" * 16
        hsm.handle("ENC ON " + binascii.hexlify(nonce).decode())
        resp = hsm.handle("ENC_MSG 0 xyz")
        assert "bad-hex" in resp.lower()

    def test_enc_multiple_messages(self):
        """Multiple encrypted messages should work with increasing counters."""
        nonce = b"\x00" * 16
        hsm.handle("ENC ON " + binascii.hexlify(nonce).decode())
        session_key = _derive_session_key(nonce)

        for i in range(5):
            ct = _encrypt("PING", session_key, i)
            resp = hsm.handle("ENC_MSG %d %s" % (i, binascii.hexlify(ct).decode()))
            # Text mode: ENC_MSG <tx_counter> <hex>
            assert resp.startswith("ENC_MSG %d " % i)
            enc_resp_hex = resp.split(" ", 2)[2]
            enc_resp = binascii.unhexlify(enc_resp_hex)
            decrypted = _decrypt(enc_resp, session_key, i)
            assert b"PONG" in decrypted

    def test_enc_off_then_msg_fails(self):
        """After ENC OFF, ENC_MSG should fail."""
        nonce = b"\x00" * 16
        hsm.handle("ENC ON " + binascii.hexlify(nonce).decode())
        hsm.handle("ENC OFF")
        resp = hsm.handle("ENC_MSG 0 " + binascii.hexlify(b"\x00" * 4).decode())
        assert "not-active" in resp.lower()

    def test_enc_msg_who_roundtrip(self):
        """WHO command through encrypted transport."""
        nonce = b"\x00" * 16
        hsm.handle("ENC ON " + binascii.hexlify(nonce).decode())
        session_key = _derive_session_key(nonce)

        ct = _encrypt("WHO", session_key, 0)
        resp = hsm.handle("ENC_MSG 0 " + binascii.hexlify(ct).decode())
        assert resp.startswith("ENC_MSG 0 ")
        enc_resp_hex = resp.split(" ", 2)[2]
        enc_resp = binascii.unhexlify(enc_resp_hex)
        decrypted = _decrypt(enc_resp, session_key, 0)
        assert b"ID" in decrypted or b"device" in decrypted

    def test_session_key_derivation(self):
        """The session key should be deterministic from nonce + key."""
        nonce = b"\x42" * 16
        sk = hsm._enc_derive_session_key(nonce)
        expected = _derive_session_key(nonce)
        assert sk == expected

    def test_different_nonces_different_sessions(self):
        """Different nonces should produce different session keys."""
        sk1 = hsm._enc_derive_session_key(b"\x00" * 16)
        sk2 = hsm._enc_derive_session_key(b"\x01" * 16)
        assert sk1 != sk2

    def test_enc_reactivate_after_off(self):
        """Should be able to re-activate ENC after ENC OFF."""
        nonce = b"\x00" * 16
        hsm.handle("ENC ON " + binascii.hexlify(nonce).decode())
        hsm.handle("ENC OFF")
        resp = hsm.handle("ENC ON " + binascii.hexlify(nonce).decode())
        assert "ACTIVE" in resp or "active" in resp.lower()

    def test_enc_counter_resets_on_reactivate(self):
        """Re-activating ENC should reset the tx counter to 0."""
        nonce = b"\x00" * 16
        hsm.handle("ENC ON " + binascii.hexlify(nonce).decode())
        session_key = _derive_session_key(nonce)

        # Send one message
        ct = _encrypt("PING", session_key, 0)
        hsm.handle("ENC_MSG 0 " + binascii.hexlify(ct).decode())

        # Re-activate
        hsm.handle("ENC OFF")
        hsm.handle("ENC ON " + binascii.hexlify(nonce).decode())

        # tx counter should be back to 0
        ct = _encrypt("PING", session_key, 0)
        resp = hsm.handle("ENC_MSG 0 " + binascii.hexlify(ct).decode())
        assert resp.startswith("ENC_MSG 0 ")

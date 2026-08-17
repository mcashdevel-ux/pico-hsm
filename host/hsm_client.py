#!/usr/bin/env python3
"""Host-side client for the pico-hsm.

Can be used as a library::

    from hsm_client import PicoHSM
    hsm = PicoHSM("/dev/ttyACM0")
    print(hsm.who())          # fingerprint
    mac = hsm.challenge(b"deadbeef")  # -> 32-byte HMAC
    raw = hsm.seed(32)        # -> 32 bytes of raw TRNG entropy

Or run directly as a demo CLI::

    python3 host/hsm_client.py [--port /dev/ttyACM0]
"""
import argparse
import binascii
import glob
import os
import serial
import sys
import time


def _detect_port():
    """Auto-detect the Pico serial port on Linux, macOS, or Windows.

    Priority: $PICO_HSM_PORT env var > first matching device found.
    Linux:   /dev/ttyACM*
    macOS:   /dev/cu.usbmodem*
    Windows: COM* (via pyserial comports if available, else glob)
    """
    env = os.environ.get("PICO_HSM_PORT")
    if env:
        return env

    patterns = {
        "linux": "/dev/ttyACM*",
        "darwin": "/dev/cu.usbmodem*",
        "win32": "COM*",
    }
    plat = sys.platform
    pattern = patterns.get(plat)
    if pattern is None:
        return "/dev/ttyACM0"

    # On Windows, use pyserial's comports() for reliable enumeration
    if plat == "win32":
        try:
            from serial.tools import list_ports
            for port, desc, hwid in list_ports.comports():
                if "2e8a" in hwid.lower() or "picopico" in desc.lower() \
                        or "micropython" in desc.lower():
                    return port
            # Fall back to first available COM port
            for port, desc, hwid in list_ports.comports():
                return port
        except ImportError:
            pass
        return "COM3"

    # Linux / macOS: glob for the device files
    ports = sorted(glob.glob(pattern))
    return ports[0] if ports else pattern.replace("*", "0")

DEFAULT_PORT = _detect_port()
BAUD = 115200


class PicoHSM:
    """Serial client for the pico-hsm board."""

    def __init__(self, port=DEFAULT_PORT, baud=BAUD):
        self.port = port
        # Short inter-byte timeout so _send doesn't block 5s per command
        # after the response is fully received.
        self.ser = serial.Serial(port, baud, timeout=1, dsrdtr=False, rtscts=False)
        time.sleep(0.3)
        # Send Ctrl-C twice to interrupt any running code and exit raw REPL
        # mode (left by prior mpremote sessions). Then Ctrl-D to soft-reset,
        # which re-runs main.py.
        self.ser.write(b"\x03\x03")
        time.sleep(0.2)
        self.ser.read(256)  # drain any interrupt output
        self.ser.write(b"\x04")
        self._drain_banner()
        # The first command after a soft-reset often catches leftover serial
        # framing; send a throwaway PING to absorb it.
        self._send("PING")

    def _drain_banner(self):
        """Read and discard the boot banner.

        A soft-reset (Ctrl-D) reboots the Pico; trng.key256() takes several
        seconds. Read until we see the FINGERPRINT line, then keep draining
        any remaining banner lines (AES ready, etc.) with a short timeout.
        """
        buf = b""
        end = time.time() + 15
        while time.time() < end:
            b = self.ser.read(256)
            if b:
                buf += b
                if b"FINGERPRINT" in buf:
                    break
            else:
                time.sleep(0.2)
        # Drain any remaining banner lines (e.g. "AES ready. FINGERPRINT ...")
        end = time.time() + 1
        while time.time() < end:
            b = self.ser.read(256)
            if not b:
                break

    def _send(self, cmd):
        """Send a command line, return the first non-echo response line."""
        self.ser.write((cmd + "\n").encode())
        r = b""
        end = time.time() + 10
        while time.time() < end:
            # Non-blocking: read whatever is already in the buffer
            n = self.ser.in_waiting
            if n:
                r += self.ser.read(n)
                # Small grace period for the rest of the response to arrive
                time.sleep(0.05)
                continue
            if r:
                # We have data and the buffer is empty — check once more
                # after a brief pause, then return.
                time.sleep(0.1)
                if self.ser.in_waiting:
                    continue
                break
            # No data yet — brief poll
            time.sleep(0.05)
        text = r.decode(errors="replace").strip()
        lines = [l.strip() for l in text.split("\n") if l.strip()]
        resp_lines = [l for l in lines if l != cmd and not l.startswith(">>>")]
        if resp_lines:
            return "\n".join(resp_lines)
        return text

    # -- protocol commands ------------------------------------------------

    def ping(self):
        """Return the PONG tick count (int)."""
        resp = self._send("PING")
        if resp.startswith("PONG "):
            return int(resp[5:].strip())
        return resp

    def who(self):
        """Return the WHO response line (ID ... DEVICE <hex> FINGERPRINT <hex>)."""
        return self._send("WHO")

    def device_id(self):
        """Return the 16-hex-char chip ID (persistent per-board identity)."""
        resp = self.who()
        if "DEVICE " in resp:
            return resp.split("DEVICE ", 1)[1].split()[0]
        return resp

    def fingerprint(self):
        """Return just the 64-hex-char fingerprint string."""
        resp = self.who()
        if "FINGERPRINT " in resp:
            # WHO format: ... FINGERPRINT <hex64> STATUS [DEGRADED]
            return resp.split("FINGERPRINT ", 1)[1].split()[0]
        return resp

    def challenge(self, msg):
        """Send a CHALLENGE, return the 32-byte HMAC-SHA256.

        *msg* can be bytes or a hex string.  Returns raw bytes.
        """
        if isinstance(msg, bytes):
            hx = binascii.hexlify(msg).decode()
        else:
            hx = msg
        resp = self._send("CHALLENGE " + hx)
        if resp.startswith("RESPONSE "):
            return binascii.unhexlify(resp[9:].strip())
        return resp

    def seed(self, nbytes):
        """Return *nbytes* of raw TRNG entropy (bytes, 1-256)."""
        resp = self._send("SEED " + str(nbytes))
        line = resp.split("\n", 1)[0] if "\n" in resp else resp
        if line.startswith("SEED "):
            return binascii.unhexlify(line[5:].strip())
        return resp

    def version(self):
        """Return the VERSION response line."""
        return self._send("VERSION")

    def help(self):
        """Return the HELP response line (available commands)."""
        return self._send("HELP")

    def aes_key(self):
        """Return the AES key fingerprint (hex string)."""
        resp = self._send("AES_KEY")
        if resp.startswith("AES_KEY_FP "):
            return resp[11:].strip()
        return resp

    # -- persistent key management -------------------------------------------

    def key_store(self, pin):
        """Store the current HMAC key encrypted with *pin* in flash.

        Opt-in feature: persists the otherwise-volatile HMAC key so it
        survives reboots. Returns True on success, False otherwise.
        """
        resp = self._send("KEY_STORE " + str(pin))
        return resp.startswith("OK key-stored")

    def key_load(self, pin):
        """Load and decrypt the persistent key from flash.

        Returns the new fingerprint (hex) on success, or None on failure.
        """
        resp = self._send("KEY_LOAD " + str(pin))
        if resp.startswith("OK key-loaded fingerprint="):
            return resp.split("fingerprint=", 1)[1].strip()
        return None

    def key_erase(self):
        """Erase the persistent key from flash. Returns True on success."""
        resp = self._send("KEY_ERASE")
        return resp.startswith("OK key-erased")

    def key_status(self):
        """Return dict with 'persistent' and 'degraded' booleans."""
        resp = self._send("KEY_STATUS")
        out = {"persistent": False, "degraded": False}
        if "persistent=yes" in resp:
            out["persistent"] = True
        if "degraded=yes" in resp:
            out["degraded"] = True
        return out

    def aes_enc(self, block):
        """Encrypt a 16-byte block. Returns 16 bytes of ciphertext."""
        if isinstance(block, (bytes, bytearray)):
            hx = binascii.hexlify(block).decode()
        else:
            hx = block
        resp = self._send("AES_ENC " + hx)
        if resp.startswith("AES_CT "):
            return binascii.unhexlify(resp[7:].strip())
        return resp

    def aes_dec(self, block):
        """Decrypt a 16-byte block. Returns 16 bytes of plaintext."""
        if isinstance(block, (bytes, bytearray)):
            hx = binascii.hexlify(block).decode()
        else:
            hx = block
        resp = self._send("AES_DEC " + hx)
        if resp.startswith("AES_PT "):
            return binascii.unhexlify(resp[7:].strip())
        return resp

    def aes_ctr(self, nonce, data):
        """AES-CTR encrypt/decrypt. Returns output bytes."""
        if isinstance(nonce, (bytes, bytearray)):
            nonce = binascii.hexlify(nonce).decode()
        if isinstance(data, (bytes, bytearray)):
            data = binascii.hexlify(data).decode() if data else ""
        cmd = "AES_CTR " + nonce
        if data:
            cmd += " " + data
        resp = self._send(cmd)
        if resp.startswith("AES_OUT"):
            return binascii.unhexlify(resp[8:].strip() or "")
        return resp

    def close(self):
        self.ser.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


# -- demo CLI -------------------------------------------------------------

def _demo(hsm):
    print("=== PING ===")
    print(hsm.ping())

    print("\n=== WHO ===")
    print(hsm.who())
    print("device ID:", hsm.device_id())

    challenge = os.urandom(32)
    ch_hex = binascii.hexlify(challenge).decode()
    print("\n=== CHALLENGE (host-side random) ===")
    print("challenge hex:", ch_hex)
    mac = hsm.challenge(challenge)
    print("response:", binascii.hexlify(mac).decode())
    print("Got HMAC (%d bytes)" % len(mac))
    print("NOTE: host cannot verify without the key (good - key stays on Pico).")

    print("\n=== SEED 32 ===")
    raw = hsm.seed(32)
    if isinstance(raw, (bytes, bytearray)):
        print("raw entropy (%d bytes): %s" % (len(raw), binascii.hexlify(raw).decode()))
    else:
        print("SEED error:", raw)

    print("\n=== consistency: same challenge again ===")
    mac2 = hsm.challenge(challenge)
    print("deterministic (same challenge -> same HMAC)?", mac == mac2)

    print("\n=== VERSION ===")
    print(hsm.version())


def main():
    parser = argparse.ArgumentParser(description="pico-hsm demo client")
    parser.add_argument("--port", default=DEFAULT_PORT,
                        help="serial port (default: $PICO_HSM_PORT or /dev/ttyACM0)")
    args = parser.parse_args()
    with PicoHSM(args.port) as hsm:
        _demo(hsm)


if __name__ == "__main__":
    main()

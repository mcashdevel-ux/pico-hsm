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
import os
import serial
import time

DEFAULT_PORT = os.environ.get("PICO_HSM_PORT", "/dev/ttyACM0")
BAUD = 115200


class PicoHSM:
    """Serial client for the pico-hsm board."""

    def __init__(self, port=DEFAULT_PORT, baud=BAUD):
        self.port = port
        self.ser = serial.Serial(port, baud, timeout=5, dsrdtr=False, rtscts=False)
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
        time.sleep(0.15)
        r = b""
        end = time.time() + 5
        while time.time() < end:
            b = self.ser.read(256)
            if b:
                r += b
                time.sleep(0.05)
            elif r:
                time.sleep(0.1)
                # One more read to catch a late response
                more = self.ser.read(256)
                if more:
                    r += more
                    continue
                break
        text = r.decode(errors="replace").strip()
        lines = [l.strip() for l in text.split("\n") if l.strip()]
        for line in lines:
            if line != cmd and not line.startswith(">>>"):
                return line
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
        """Return just the hex fingerprint string."""
        resp = self.who()
        if "FINGERPRINT " in resp:
            return resp.split("FINGERPRINT ", 1)[1].strip()
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
        if resp.startswith("SEED "):
            return binascii.unhexlify(resp[5:].strip())
        return resp

    def version(self):
        """Return the VERSION response line."""
        return self._send("VERSION")

    def help(self):
        """Return the HELP response line (available commands)."""
        return self._send("HELP")

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

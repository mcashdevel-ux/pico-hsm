# Integration test: AES + TRNG commands via the HSM command interface
# Tests the full path: serial command -> hsm.handle() -> native aes module
# Run on the Pico: mpremote connect /dev/ttyACM0 run tests/test_hsm_aes.py
import hsm, ubinascii, os

passed = 0
failed = 0

def check(name, got, expected):
    global passed, failed
    if got == expected:
        passed += 1
        print("  [PASS] %s" % name)
    else:
        failed += 1
        print("  [FAIL] %s" % name)
        print("    got:      %s" % got)
        print("    expected: %s" % expected)

def check_true(name, cond):
    global passed, failed
    if cond:
        passed += 1
        print("  [PASS] %s" % name)
    else:
        failed += 1
        print("  [FAIL] %s" % name)

print("=== HSM AES + TRNG integration test ===")
print("  firmware:", os.uname().version if hasattr(os, 'uname') else '?')

# Start the watchdog for testing (normally started by main.py at boot)
import trng
trng.start_watchdog(interval_ms=5000)

# WHO should work and include fingerprint + STATUS
resp = hsm.handle("WHO")
check_true("WHO returns ID", resp.startswith("ID openhands-pico-hsm DEVICE"))
check_true("WHO includes STATUS", "STATUS" in resp)

# HELP should list all commands including TRNG
resp = hsm.handle("HELP")
for cmd in ("AES_ENC", "AES_DEC", "AES_CTR", "AES_KEY", "TRNG", "TRNG_REPROFILE", "TRNG_WATCHDOG"):
    check_true("HELP includes " + cmd, cmd in resp)

# VERSION should be 1.6.x
resp = hsm.handle("VERSION")
check_true("VERSION is 1.6.x", "pico-hsm/1.6" in resp)

# ── TRNG adaptive status ────────────────────────────────────────────── #
print("\n--- TRNG adaptive status ---")
resp = hsm.handle("TRNG")
check_true("TRNG returns BITS", "BITS " in resp)
check_true("TRNG returns NUM_BITS", "NUM_BITS " in resp)
check_true("TRNG returns TEMP", "TEMP " in resp)
check_true("TRNG returns WATCHDOG", "WATCHDOG" in resp)
check_true("TRNG returns PROFILE", "PROFILE" in resp)

# Parse selected bits
for line in resp.split("\n"):
    if line.startswith("NUM_BITS "):
        nbits = int(line.split()[1])
        check_true("TRNG has >= 4 selected bits", nbits >= 4)
        break

# TRNG_REPROFILE should work
resp = hsm.handle("TRNG_REPROFILE")
check_true("TRNG_REPROFILE returns OK", resp.startswith("OK reprofile "))

# TRNG_WATCHDOG should show running
resp = hsm.handle("TRNG_WATCHDOG")
check_true("TRNG_WATCHDOG shows RUNNING", "RUNNING" in resp)

# Watchdog off/on
resp = hsm.handle("TRNG_WATCHDOG OFF")
check_true("Watchdog OFF", "stopped" in resp)
resp = hsm.handle("TRNG_WATCHDOG")
check_true("Watchdog STOPPED", "STOPPED" in resp)
resp = hsm.handle("TRNG_WATCHDOG ON")
check_true("Watchdog ON", "started" in resp)
resp = hsm.handle("TRNG_WATCHDOG")
check_true("Watchdog RUNNING again", "RUNNING" in resp)

# ── AES tests ────────────────────────────────────────────────────────── #
print("\n--- AES-256 tests ---")
resp = hsm.handle("AES_KEY")
check_true("AES_KEY returns fingerprint", resp.startswith("AES_KEY_FP "))

pt_hex = "00112233445566778899aabbccddeeff"
resp = hsm.handle("AES_ENC " + pt_hex)
check_true("AES_ENC returns ciphertext", resp.startswith("AES_CT "))
ct_hex = resp[7:] if resp.startswith("AES_CT ") else ""

resp = hsm.handle("AES_DEC " + ct_hex)
check("AES_DEC round-trip matches plaintext", resp, "AES_PT " + pt_hex)

# Error cases
check("AES_ENC bad block size rejected", hsm.handle("AES_ENC 0011"), "ERR block-size-16")
check("AES_ENC bad hex rejected", hsm.handle("AES_ENC zz"), "ERR bad-hex")
check("AES_DEC bad hex rejected", hsm.handle("AES_DEC zz"), "ERR bad-hex")

# CTR mode
nonce_hex = "00000000000000000000000000000000"
data_hex = "48656c6c6f20576f726c6421"  # "Hello World!" (12 bytes)
resp = hsm.handle("AES_CTR " + nonce_hex + " " + data_hex)
check_true("AES_CTR returns output", resp.startswith("AES_OUT "))
enc_hex = resp[8:] if resp.startswith("AES_OUT ") else ""

resp2 = hsm.handle("AES_CTR " + nonce_hex + " " + enc_hex)
check("AES_CTR round-trip matches original data", resp2, "AES_OUT " + data_hex)

# CTR multi-block
big_hex = "".join("%02x" % i for i in range(64))
resp = hsm.handle("AES_CTR " + nonce_hex + " " + big_hex)
check_true("AES_CTR 64-byte encrypt works", resp.startswith("AES_OUT "))
enc_big = resp[8:] if resp.startswith("AES_OUT ") else ""
resp2 = hsm.handle("AES_CTR " + nonce_hex + " " + enc_big)
check("AES_CTR 64-byte round-trip matches", resp2, "AES_OUT " + big_hex)

# CTR empty data
resp = hsm.handle("AES_CTR " + nonce_hex)
check("AES_CTR empty data returns empty output", resp, "AES_OUT ")

# CTR bad nonce
check("AES_CTR bad nonce size rejected",
      hsm.handle("AES_CTR 00 " + data_hex), "ERR nonce-size-16")

# ── Core HSM tests ───────────────────────────────────────────────────── #
print("\n--- Core HSM tests ---")
check("Unknown command rejected", hsm.handle("BOGUS"), "ERR unknown-cmd")
check_true("PING returns PONG", hsm.handle("PING").startswith("PONG "))
check_true("CHALLENGE returns RESPONSE", hsm.handle("CHALLENGE " + "00" * 16).startswith("RESPONSE "))

# SEED — may work (adaptive TRNG found good bits) or report unhealthy
resp = hsm.handle("SEED 32")
if resp.startswith("SEED "):
    check_true("SEED returns entropy (adaptive TRNG working!)", len(resp) > 10)
else:
    check("SEED reports unhealthy gracefully", resp, "ERR trng-unhealthy")

print()
print("=== Results: %d passed, %d failed ===" % (passed, failed))
if failed == 0:
    print("ALL TESTS PASSED")
# Stop the watchdog thread so the script can exit cleanly
trng.shutdown()
import time as _t
_t.sleep_ms(300)  # let the thread exit

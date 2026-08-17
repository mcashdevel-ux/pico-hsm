"""Shared fixtures for pico-hsm tests.

Tests that need a physical board are marked with ``@pytest.mark.hardware``
and skipped if no serial port is available (no ``PICO_HSM_PORT`` env var
and no ``/dev/ttyACM0`` device).
"""
import os
import sys

import pytest

# test_hsm_aes.py runs on the Pico via mpremote, not under pytest — exclude
# it from collection so importing MicroPython-only modules doesn't error.
collect_ignore = ["test_hsm_aes.py"]

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "host"))

from hsm_client import _detect_port

DEFAULT_PORT = _detect_port()


def _port_available():
    return os.path.exists(DEFAULT_PORT)


skip_no_hardware = pytest.mark.skipif(
    not _port_available(),
    reason=f"No Pico HSM at {DEFAULT_PORT} (set PICO_HSM_PORT to override)",
)


@pytest.fixture(scope="session")
def hsm():
    """Yield a single PicoHSM instance for the whole test session.

    Session-scoped so the board is only soft-reset (and trng.key256() run)
    once, not once per test.
    """
    from hsm_client import PicoHSM
    dev = PicoHSM(DEFAULT_PORT)
    # Disable rate limiting for the test suite — tests send many rapid
    # commands and the rate limiter (10 req/10s) would cause spurious
    # ERR rate-limited failures. Re-enabled on next board reset.
    dev._send("RATE_LIMIT RESET")
    yield dev
    dev.close()


@pytest.fixture(autouse=True)
def _reset_rate_limit(request):
    """Reset the rate limiter before each hardware test to avoid cross-test
    interference.

    Only activates when the board is present. Uses the session-scoped ``hsm``
    instance so no extra serial connection is opened.
    """
    if not _port_available():
        return
    try:
        hsm = request.getfixturevalue("hsm")
        hsm._send("RATE_LIMIT RESET")
    except Exception:
        pass  # not all firmware versions support RATE_LIMIT

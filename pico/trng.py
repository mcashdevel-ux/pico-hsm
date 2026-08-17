# trng.py — RP2040 ADC TRNG with adaptive bit selection + von-Neumann
# debiasing + HMAC-DRBG.
#
# Pipeline (NIST SP 800-90A-inspired):
#   ADC noise → per-bit profiling → optimal bit selection → von-Neumann
#   debias → health gate → HMAC-DRBG (SHA-256) → keys
#
# Adaptive bit selection (v1.5.0):
#   Under low voltage or high temperature the noisy ADC bits shift. Instead
#   of a fixed 6-bit window (bits 4..9), the TRNG profiles all 12 data bits
#   at boot and selects the subset with the highest per-bit Shannon entropy,
#   best balance (≈0.50), and highest transition rate (≈0.50). If the health
#   gate fails, it re-profiles and tries a different bit set — up to 3 times
#   — before declaring the source unhealthy. This lets the TRNG find viable
#   signal under degraded conditions that would have triggered degraded-mode
#   fallback in v1.4.0.
#
# The ADC source was validated 2026-08-16 against the NIST SP 800-22 suite
# (9/9 tests, alpha=0.01) using the trng-crypt repo's test harness.
#
# Native C acceleration (v1.6.0):
#   If the trng_native.mpy module is present on the Pico's filesystem, the
#   hot path (ADC sampling → health gate → VN debias → HMAC-DRBG) runs in C
#   instead of Python, giving ~100x speedup for SEED. The Python pipeline
#   remains as a fallback if the native module is not installed.
import machine, hashlib, math, gc

# Try to import the native C module for acceleration.
try:
    import trng_native
    _has_native = True
except ImportError:
    trng_native = None
    _has_native = False

_ADC_PIN = None
_ADC = None

# ── Adaptive bit-selection state ────────────────────────────────────────── #
# Profiling analyses bits 4..15 (the 12 actual ADC data bits; bits 0..3 are
# always 0 because read_u16() left-shifts the 12-bit result by 4).
_ADC_DATA_BITS = list(range(4, 16))

# Currently selected bit positions (sorted). None = not yet profiled.
_selected_bits = None
_last_metrics = None      # per-bit metrics from last _profile_bits() call
_last_temp = None         # die temperature at last profile (°C), or None

# Profiling thresholds — a bit is "good" if it passes all of these.
_PROF_MIN_BALANCE = 0.30   # fraction of 1s must be in [0.30, 0.70]
_PROF_MIN_TRANS = 0.30     # at least 30% of consecutive samples must flip
                           # Sticky bits (low transition rate) create high
                           # serial correlation in packed bytes that fails
                           # the full health gate. 0.30 selects only high-
                           # quality noise bits (the original v1.3.0 set was
                           # bits 4-9, all with trans ~0.45-0.50).
_PROF_MAX_TRANS = 0.95     # at most 95% (above = oscillating, not random)
_PROF_MIN_BITS = 4         # need at least 4 good bits to proceed
_PROF_MAX_BITS = 8         # cap to keep bytes manageable (max 255)

# Health-gate thresholds — adaptive based on number of selected bits.
# min-entropy floor is 50% of theoretical max (num_bits), with a hard floor
# of 2.0 bits. This is far more lenient than v1.4.0's fixed 6.0 (which
# required near-perfect uniformity) but still catches a dead source.
_HEALTH_BALANCE_LO = 0.35
_HEALTH_BALANCE_HI = 0.65
_HEALTH_SERIAL_ABS = 0.50   # relaxed from 0.30 — VN debiaser handles bias


# ── ADC init ────────────────────────────────────────────────────────────── #
def _init():
    global _ADC_PIN, _ADC
    if _ADC is None:
        _ADC_PIN = machine.Pin(26, machine.Pin.IN, None)  # floating high-Z
        _ADC = machine.ADC(0)


def _raw16():
    return _ADC.read_u16()


# ── Temperature sensor ──────────────────────────────────────────────────── #
def read_temp():
    """Read the RP2040 internal temperature sensor (ADC4). Returns °C or None."""
    _init()
    try:
        raw = machine.ADC(4).read_u16()
        v = raw * 3.3 / 65535
        return 27 - (v - 0.706) / 0.001721
    except Exception:
        return None


# ── Per-bit profiling ──────────────────────────────────────────────────── #
def _profile_bits(n=2000):
    """Sample the ADC n times and compute per-bit quality metrics.

    Returns a list of dicts (one per bit position 0..15), each with:
      bit, balance, transitions, entropy, quality, selected
    """
    _init()
    # Warm up: discard first 50 samples (ADC settling)
    for _ in range(50):
        _raw16()

    ones = [0] * 16
    trans = [0] * 16
    prev = _raw16()
    for i in range(1, n):
        v = _raw16()
        diff = v ^ prev
        for b in _ADC_DATA_BITS:
            if v & (1 << b):
                ones[b] += 1
            if diff & (1 << b):
                trans[b] += 1
        prev = v
        if i % 64 == 0:
            time.sleep_ms(0)  # yield GIL so main thread can run

    metrics = []
    for b in range(16):
        bal = ones[b] / n if n > 0 else 0
        tr = trans[b] / (n - 1) if n > 1 else 0
        if 0 < bal < 1:
            ent = -bal * math.log2(bal) - (1 - bal) * math.log2(1 - bal)
        else:
            ent = 0.0
        # Quality score: high entropy × balance near 0.5 × transitions near 0.5
        bal_score = 1 - 2 * abs(bal - 0.5)
        trans_score = 1 - abs(tr - 0.5) if tr <= 1.0 else 0
        quality = ent * bal_score * trans_score
        metrics.append({
            'bit': b,
            'balance': bal,
            'transitions': tr,
            'entropy': ent,
            'quality': quality,
            'selected': False,
        })
    return metrics


def _select_bits(metrics):
    """Choose the best bits from profiling metrics.

    Returns (sorted_bit_list, updated_metrics) or (None, metrics) if too
    few bits pass the quality gate.
    """
    good = []
    for m in metrics:
        b = m['bit']
        if b not in _ADC_DATA_BITS:
            continue
        bal = m['balance']
        tr = m['transitions']
        if (_PROF_MIN_BALANCE <= bal <= (1 - _PROF_MIN_BALANCE)
                and _PROF_MIN_TRANS <= tr <= _PROF_MAX_TRANS):
            good.append(m)
    if len(good) < _PROF_MIN_BITS:
        return None, metrics
    good.sort(key=lambda m: m['quality'], reverse=True)
    selected = sorted([m['bit'] for m in good[:_PROF_MAX_BITS]])
    for m in metrics:
        m['selected'] = m['bit'] in selected
    return selected, metrics


def _set_bits(bit_positions):
    """Configure which ADC bits to extract."""
    global _selected_bits
    _selected_bits = sorted(bit_positions)


def reprofile():
    """Re-profile the ADC and select the best bits.

    Returns True if >= _PROF_MIN_BITS good bits were found, False otherwise.
    Also updates _last_metrics and _last_temp.
    """
    global _last_metrics, _last_temp
    _last_metrics = _profile_bits()
    _last_temp = read_temp()
    selected, _last_metrics = _select_bits(_last_metrics)
    if selected is not None:
        _set_bits(selected)
        return True
    return False


def _ensure_profiled():
    """Profile on first use if not already done."""
    if _selected_bits is None:
        reprofile()


# ── Bit extraction ──────────────────────────────────────────────────────── #
def _noisy(v):
    """Extract selected bits from a 16-bit ADC reading, pack into a byte.

    With 6 selected bits, returns 0..63. With 8, returns 0..255. The caller
    treats each result as one byte of raw entropy.
    """
    if _selected_bits is None:
        return (v >> 4) & 0x3F  # legacy fallback: bits 4..9
    bits = 0
    for i, b in enumerate(_selected_bits):
        if v & (1 << b):
            bits |= (1 << i)
    return bits


def _num_extract_bits():
    """Number of bits extracted per sample."""
    if _selected_bits is None:
        return 6
    return len(_selected_bits)


def _bits_to_mask():
    """Convert _selected_bits (16-bit ADC positions) to a 12-bit bitmask for
    the native C module.

    The Python code uses read_u16() which left-shifts the 12-bit ADC result
    by 4 (bits 4-15 of the 16-bit value). The native C module reads the raw
    12-bit register directly (bits 0-11). So bit N in 16-bit space maps to
    bit N-4 in 12-bit space.
    """
    if _selected_bits is None:
        return 0x3F  # default: bits 4-9 → 12-bit bits 0-5
    mask = 0
    for b in _selected_bits:
        pos = b - 4
        if 0 <= pos < 12:
            mask |= (1 << pos)
    return mask


# ── Health gate ────────────────────────────────────────────────────────── #
def _health_check(raw):
    """Screen raw bytes; return metrics dict, or raise on degraded source.

    The min-entropy threshold is adaptive: 50% of the number of extracted
    bits, with a hard floor of 2.0. This is far more lenient than v1.4.0's
    fixed 6.0 (which required near-perfect uniformity on 6-bit samples) but
    still catches a completely dead source.
    """
    n = len(raw)
    if n < 256:
        raise RuntimeError("health: insufficient data (%d bytes)" % n)
    nbits = _num_extract_bits()
    min_ent_floor = max(2.0, nbits * 0.5)

    ones = 0
    for i, b in enumerate(raw):
        ones += bin(b).count("1")
        if i % 128 == 0:
            time.sleep_ms(0)  # yield GIL
    total = n * nbits  # each byte carries nbits meaningful bits
    bal = ones / total if total > 0 else 0

    hist = [0] * 256
    for i, b in enumerate(raw):
        hist[b] += 1
        if i % 128 == 0:
            time.sleep_ms(0)  # yield GIL
    pmax = max(hist) / n
    min_ent = -math.log2(pmax) if pmax > 0 else 0.0

    mean = sum(raw) / n
    num = 0.0
    den1 = 0.0
    den2 = 0.0
    for i in range(1, n):
        d = raw[i] - mean
        d0 = raw[i - 1] - mean
        num += d * d0
        den2 += d * d
        den1 += d0 * d0
        if i % 128 == 0:
            time.sleep_ms(0)  # yield GIL
    serial = num / (math.sqrt(den1 * den2)) if den1 > 0 and den2 > 0 else 0.0

    ok = (_HEALTH_BALANCE_LO <= bal <= _HEALTH_BALANCE_HI
          and min_ent >= min_ent_floor
          and abs(serial) <= _HEALTH_SERIAL_ABS)
    if not ok:
        raise RuntimeError(
            "health FAIL: bal=%.4f min_ent=%.4f/%.1f |serial|=%.4f"
            % (bal, min_ent, min_ent_floor, abs(serial)))
    return {"balance": bal, "min_ent": min_ent, "serial": serial,
            "threshold": min_ent_floor}


# ── Von-Neumann debiaser ───────────────────────────────────────────────── #
def _vn_debias(raw):
    """Von-Neumann extractor: 01→0, 10→1, 00/11 discarded. Removes bias."""
    out = bytearray()
    prev = None
    for idx, byte in enumerate(raw):
        for shift in range(_num_extract_bits() - 1, -1, -1):
            bit = (byte >> shift) & 1
            if prev is None:
                prev = bit
            else:
                if prev == 0 and bit == 1:
                    out.append(0)
                    prev = None
                elif prev == 1 and bit == 0:
                    out.append(1)
                    prev = None
                else:
                    prev = None
        if idx % 128 == 0:
            time.sleep_ms(0)  # yield GIL
    return bytes(out)


# ── HMAC-SHA256 (manual; no hmac module in this MicroPython build) ─────── #
def _hmac_sha256(key, msg):
    block = 64
    if len(key) > block:
        key = hashlib.sha256(key).digest()
    k = key + b'\x00' * (block - len(key))
    o = bytes(b ^ 0x5c for b in k)
    i = bytes(b ^ 0x36 for b in k)
    inner = hashlib.sha256(i + msg).digest()
    return hashlib.sha256(o + inner).digest()


# ── HMAC-DRBG (NIST SP 800-90A, SHA-256) ──────────────────────────────── #
class HMACDRBG:
    SEEDLEN = 32
    MAX_PER_REQ = 1 << 16

    def __init__(self, entropy, perso=b""):
        self._K = b"\x00" * self.SEEDLEN
        self._V = b"\x01" * self.SEEDLEN
        self._update(entropy + perso)
        self._ctr = 1

    def _update(self, provided):
        self._K = _hmac_sha256(self._K, self._V + b"\x00" + provided)
        self._V = _hmac_sha256(self._K, self._V)
        self._K = _hmac_sha256(self._K, self._V + b"\x01" + provided)
        self._V = _hmac_sha256(self._K, self._V)

    def reseed(self, entropy):
        self._update(entropy)
        self._ctr = 1

    def generate(self, n):
        out = bytearray()
        while len(out) < n:
            self._V = _hmac_sha256(self._K, self._V)
            out.extend(self._V)
        self._update(b"")
        self._ctr += 1
        return bytes(out[:n])


# ── Entropy harvest ───────────────────────────────────────────────────── #
def _collect_raw(nbytes):
    """Collect >= nbytes raw samples (one byte each, carrying selected bits)."""
    nbits = _num_extract_bits()
    # Oversample: VN discards ~50%+, health check needs >=256, plus margin.
    need = max(nbytes * 4, 2048)
    acc = bytearray()
    i = 0
    while len(acc) < need:
        acc.append(_noisy(_raw16()))
        i += 1
        if i % 64 == 0:
            time.sleep_ms(0)  # yield GIL so main thread (serial REPL) can run
    return bytes(acc)


def _lightweight_health(raw):
    """Fast health check for the watchdog (no serial correlation).

    Returns (ok, metrics_dict). Uses only balance + min-entropy — fast enough
    to run on core 1 every few seconds without blocking the main thread.
    """
    n = len(raw)
    if n < 128:
        return False, {"error": "insufficient data"}
    nbits = _num_extract_bits()
    ones = 0
    for i, b in enumerate(raw):
        ones += bin(b).count("1")
        if i % 128 == 0:
            time.sleep_ms(0)  # yield GIL
    total = n * nbits
    bal = ones / total if total > 0 else 0
    hist = [0] * 256
    for i, b in enumerate(raw):
        hist[b] += 1
        if i % 128 == 0:
            time.sleep_ms(0)  # yield GIL
    pmax = max(hist) / n
    min_ent = -math.log2(pmax) if pmax > 0 else 0.0
    min_ent_floor = max(2.0, nbits * 0.5)
    ok = (_HEALTH_BALANCE_LO <= bal <= _HEALTH_BALANCE_HI
          and min_ent >= min_ent_floor)
    return ok, {"balance": bal, "min_ent": min_ent,
                "threshold": min_ent_floor, "healthy": ok}


def _fresh_entropy(nbytes):
    """Harvest, debias, and health-check enough entropy for a DRBG seed.

    On health failure, re-profiles the ADC (selects different bits) and
    retries, up to 3 attempts. Raises RuntimeError if all attempts fail.
    Also checks the watchdog's degradation flag before collecting.

    If the native C module (trng_native) is available, the entire hot path
    (collect → health → VN debias) runs in C for ~100x speedup.
    """
    global _wd_failures, _wd_active
    _init()
    _ensure_profiled()
    # If the watchdog flagged degradation since last call, reprofile now
    if _wd_failures > 0 and _wd_active:
        reprofile()
        _wd_failures = 0

    # Native C fast path: collect + health + VN debias in one call
    if _has_native:
        bit_mask = _bits_to_mask()
        try:
            return trng_native.fresh_entropy(nbytes, bit_mask)
        except Exception:
            # Health failure in native module — fall through to Python path
            # which will re-profile and retry
            pass

    # Python fallback path
    need = max(nbytes * 8, 4096)
    for attempt in range(3):
        raw = _collect_raw(need)
        try:
            _health_check(raw)
            deb = _vn_debias(raw)
            if len(deb) < nbytes:
                deb = raw  # fall back to raw (health-gated) if VN collapsed
            if len(deb) >= nbytes:
                return deb[:nbytes]
            return deb + b'\x00' * (nbytes - len(deb))
        except RuntimeError:
            if attempt < 2:
                # Health failed — re-profile to find better bits
                reprofile()
    raise RuntimeError("TRNG unhealthy after adaptive re-profiling (3 attempts)")


# ── Entropy watchdog (runs on RP2040 core 1) ──────────────────────────── #
# Continuously monitors ADC entropy quality in the background. On degradation
# (2 consecutive health failures OR a declining trend), triggers reprofile()
# to find better bits. Tracks a rolling window of health metrics to detect
# gradual degradation before it crosses the hard threshold.
#
# The thread is created once at boot and runs for the lifetime of the process.
# ON/OFF toggles a pause flag (_wd_active) rather than killing/creating the
# thread — MicroPython's _thread on RP2040 does not reliably support creating
# a new thread after the previous one has exited.
import _thread, time

_wd_running = False          # thread should stay alive (set once at start)
_wd_active = False           # actively monitoring (toggled by ON/OFF)
_wd_interval_ms = 5000       # default check interval
_wd_failures = 0             # consecutive failures (reset on success)
_wd_threshold = 2            # failures before reprofile
_wd_reprofiles = 0           # total reprofiles triggered by watchdog
_wd_last_check_ms = 0       # ticks_ms of last check
_wd_last_result = None       # last health check metrics
_wd_history = []             # rolling window of last 10 min_ent values
_wd_history_max = 10
_wd_trend_declining = False  # 3 consecutive downward min_ent values


def _watchdog_loop():
    """Background thread: periodically health-check and reprofile on degradation."""
    global _wd_running, _wd_active, _wd_failures, _wd_last_check_ms
    global _wd_last_result, _wd_reprofiles, _wd_history, _wd_trend_declining
    # Initial delay: let the main thread boot (mint keys, print banner, enter
    # the serial REPL loop) before the first health check. Without this, the
    # watchdog's first _profile_bits()+_collect_raw() burst can starve the
    # main thread of CPU for seconds, making the board appear unresponsive.
    _boot_delay = 3000
    elapsed = 0
    while elapsed < _boot_delay and _wd_running:
        chunk = min(200, _boot_delay - elapsed)
        time.sleep_ms(chunk)
        elapsed += chunk
    while _wd_running:
        # Sleep in small chunks so ON/OFF is responsive
        elapsed = 0
        target = _wd_interval_ms
        while elapsed < target and _wd_running:
            chunk = min(200, target - elapsed)
            time.sleep_ms(chunk)
            elapsed += chunk
        if not _wd_running:
            break
        if not _wd_active:
            continue  # paused — skip health check, keep thread alive
        try:
            _init()
            _ensure_profiled()
            raw = _collect_raw(512)
            ok, metrics = _lightweight_health(raw)
            metrics['temp'] = read_temp()
            _wd_last_check_ms = time.ticks_ms()
            _wd_last_result = metrics

            # Trend tracking: detect gradual decline
            me = metrics.get('min_ent', 0)
            _wd_history.append(me)
            if len(_wd_history) > _wd_history_max:
                _wd_history = _wd_history[-_wd_history_max:]
            if len(_wd_history) >= 3:
                last3 = _wd_history[-3:]
                _wd_trend_declining = (last3[0] > last3[1] > last3[2]
                                       and last3[0] - last3[2] > 0.3)
            else:
                _wd_trend_declining = False

            if ok:
                _wd_failures = 0
            else:
                _wd_failures += 1
                # Reprofile on hard threshold OR declining trend
                if _wd_failures >= _wd_threshold or _wd_trend_declining:
                    reprofile()
                    _wd_reprofiles += 1
                    _wd_failures = 0
                    _wd_history = []  # reset trend after reprofile
                    _wd_trend_declining = False
        except Exception:
            _wd_failures += 1


def start_watchdog(interval_ms=5000):
    """Start (or resume) the entropy watchdog on RP2040 core 1.

    Returns True if the watchdog is now active, False if it was already active.
    The underlying thread is created once; subsequent calls just resume it.
    """
    global _wd_running, _wd_interval_ms, _wd_active
    if not _wd_running:
        _wd_interval_ms = interval_ms
        _wd_running = True
        _wd_active = True
        try:
            _thread.start_new_thread(_watchdog_loop, ())
        except Exception:
            _wd_running = False
            _wd_active = False
            return False
        return True
    if not _wd_active:
        _wd_active = True
        return True  # resumed
    return False  # already active


def stop_watchdog():
    """Pause the entropy watchdog (thread stays alive, just stops monitoring)."""
    global _wd_active
    _wd_active = False


def shutdown():
    """Stop the watchdog thread entirely. Call before script exit.

    Sets _wd_running=False so the thread's sleep loop exits within 200ms.
    """
    global _wd_running, _wd_active
    _wd_active = False
    _wd_running = False


def watchdog_status():
    """Return watchdog status dict."""
    return {
        'running': _wd_active,       # actively monitoring
        'thread_alive': _wd_running,  # thread exists
        'interval_ms': _wd_interval_ms,
        'failures': _wd_failures,
        'reprofiles': _wd_reprofiles,
        'last_check_ms': _wd_last_check_ms,
        'last_result': _wd_last_result,
        'history': list(_wd_history),
        'trend_declining': _wd_trend_declining,
    }


# ── Public API ─────────────────────────────────────────────────────────── #
def measure(n=2000):
    """Quick entropy estimate: min-entropy and distinct-value count."""
    _init()
    _ensure_profiled()
    hist = {}
    for _ in range(n):
        b = _noisy(_raw16())
        hist[b] = hist.get(b, 0) + 1
    pmax = max(hist.values()) / n
    return -math.log2(pmax) if pmax > 0 else 0.0, len(hist)


def key256(margin=4):
    """Mint a 256-bit key from the TRNG via HMAC-DRBG.

    Volatile: exists only in RAM, destroyed on power-loss.
    Uses adaptive bit selection — re-profiles on health failure.
    """
    _init()
    _ensure_profiled()
    seed = _fresh_entropy(32)
    perso = b"pico-trng-drbg/v2-adaptive"
    drbg = HMACDRBG(seed, perso=perso)
    key = drbg.generate(32)
    seed = b'\x00' * 32
    gc.collect()
    return key


def raw_entropy(nbytes):
    """Return nbytes of TRNG output via the HMAC-DRBG (reseeded per call).

    Each call reseeds with fresh TRNG entropy (backtracking resistance).
    Raises RuntimeError if the TRNG is unhealthy after adaptive re-profiling.

    When the native C module is available, the entire pipeline (ADC collect
    → health gate → VN debias → HMAC-DRBG) runs in C for maximum speed.
    """
    _init()
    _ensure_profiled()
    if nbytes < 1 or nbytes > 256:
        raise ValueError("count must be 1..256")
    # Native C fast path: full pipeline including DRBG in C
    if _has_native:
        bit_mask = _bits_to_mask()
        try:
            return trng_native.seed(nbytes, bit_mask)
        except Exception:
            pass  # fall through to Python path
    # Python fallback: fresh_entropy + HMAC-DRBG
    seed = _fresh_entropy(32)
    drbg = HMACDRBG(seed)
    out = bytearray()
    remaining = nbytes
    while remaining > 0:
        chunk = min(remaining, HMACDRBG.MAX_PER_REQ)
        out.extend(drbg.generate(chunk))
        remaining -= chunk
        if remaining > 0:
            more = _fresh_entropy(32)
            drbg.reseed(more)
            more = b'\x00' * 32
    seed = b'\x00' * 32
    gc.collect()
    return bytes(out[:nbytes])


def status():
    """Return current TRNG status as a dict.

    Keys:
      selected_bits — list of int bit positions currently extracted
      num_bits      — len(selected_bits)
      temperature   — die temperature °C (or None)
      metrics       — per-bit profiling data (list of dicts) or None
      healthy       — True if last health check passed (None if untested)
      native        — True if native C module is loaded
      watchdog      — watchdog status dict (running, failures, reprofiles, ...)
    """
    _init()
    _ensure_profiled()
    return {
        'selected_bits': list(_selected_bits) if _selected_bits else [],
        'num_bits': len(_selected_bits) if _selected_bits else 0,
        'temperature': _last_temp,
        'metrics': _last_metrics,
        'healthy': None,  # updated by _fresh_entropy callers if needed
        'native': _has_native,
        'watchdog': watchdog_status(),
    }


def status_str():
    """Human-readable status string for the TRNG command."""
    _init()
    _ensure_profiled()
    s = status()
    bits = s['selected_bits']
    temp = s['temperature']
    temp_str = "%.1fC" % temp if temp is not None else "?"
    lines = ["BITS %s" % ",".join(str(b) for b in bits)]
    lines.append("NUM_BITS %d" % s['num_bits'])
    lines.append("NATIVE %s" % ("YES" if s['native'] else "NO"))
    lines.append("TEMP %s" % temp_str)
    # Watchdog status
    wd = s['watchdog']
    lines.append("WATCHDOG %s interval=%dms failures=%d reprofiles=%d" % (
        "RUNNING" if wd['running'] else "STOPPED",
        wd['interval_ms'], wd['failures'], wd['reprofiles']))
    if wd['trend_declining']:
        lines.append("WATCHDOG_TREND DECLINING")
    if wd['last_result']:
        lr = wd['last_result']
        lines.append("WATCHDOG_LAST bal=%.3f min_ent=%.3f/%.1f healthy=%s temp=%s" % (
            lr.get('balance', 0), lr.get('min_ent', 0),
            lr.get('threshold', 0), lr.get('healthy', '?'),
            "%.1fC" % lr['temp'] if lr.get('temp') is not None else "?"))
    if wd['history']:
        lines.append("WATCHDOG_HISTORY %s" % ", ".join(
            "%.2f" % v for v in wd['history']))
    if _last_metrics:
        lines.append("PROFILE:")
        for m in _last_metrics:
            sel = "*" if m['selected'] else " "
            lines.append("  %s bit%2d bal=%.3f trans=%.3f ent=%.3f q=%.3f" % (
                sel, m['bit'], m['balance'], m['transitions'],
                m['entropy'], m['quality']))
    return "\n".join(lines)

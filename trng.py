import machine, hashlib, math

_ADC_PIN = None
_ADC = None

def _init():
    global _ADC_PIN, _ADC
    if _ADC is None:
        _ADC_PIN = machine.Pin(26, machine.Pin.IN, None)  # floating high-Z
        _ADC = machine.ADC(0)

def _raw16():
    return _ADC.read_u16()

def _noisy(v):
    return (v >> 4) & 0x3F   # bits 4..9 (the 6 varying bits)

def measure(n=2000):
    _init()
    hist = {}
    for _ in range(n):
        b = _noisy(_raw16())
        hist[b] = hist.get(b, 0) + 1
    pmax = max(hist.values()) / n
    return -math.log2(pmax) if pmax > 0 else 0.0, len(hist)

def key256(margin=4):
    _init()
    hmin, _ = measure()
    if hmin < 0.5:
        hmin = 0.5
    need = math.ceil(256 / hmin) * margin
    acc = bytearray()
    for _ in range(need):
        acc.append(_noisy(_raw16()))
    return hashlib.sha256(acc).digest()

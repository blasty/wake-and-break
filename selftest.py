"""Offline checks for wakebreak.py and identify.py. Touches no device.

Everything here is derived from the shipped blobs, so it catches a bad or
mismatched blob, a drifted profile table, and a broken request builder
before any of it reaches a card.

    python3 selftest.py
"""

import importlib.util
import io
import random
import struct
import sys
from contextlib import redirect_stdout
from pathlib import Path

HERE = Path(__file__).resolve().parent
H = 0x1234ABCD


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


wb = load("wakebreak", HERE / "wakebreak.py")
idf = load("identify", HERE / "identify.py")

# --- manifests --------------------------------------------------------------
# Profile() itself asserts the stock preimage sha, the blob sizes, the helper's
# copy length and the tail literal pool. What is left to check is the shape of
# the manifest those blobs produce.
for name in sorted(wb.PROFILES):
    prof = wb.Profile(name)
    targets, actions = prof.targets(), prof.actions()
    assert len(targets) == 67, f"{name}: {len(targets)} targets"
    assert len(actions) == 135, f"{name}: {len(actions)} actions"

    # 68 preimage probes first, then 67 writes: no write may be attempted
    # before the whole card has been proven to be the expected build.
    assert [w for _, _, w, _ in actions[:68]] == [0] * 68, f"{name}: probe block"
    assert [w for _, _, w, _ in actions[68:]] == [4] * 67, f"{name}: write block"
    assert actions[0][0] == wb.ENTRY[0], f"{name}: entry probe missing"

    # Probes expect the stock word, writes expect the planted word.
    by_address = {a: (stock, planted) for a, stock, planted in targets}
    by_address[wb.ENTRY[0]] = wb.ENTRY[1:]
    for address, value, width, after in actions:
        stock, planted = by_address[address]
        assert value == planted, f"{name}: {address:#x} plants the wrong word"
        assert after == (stock if width == 0 else planted), f"{name}: {address:#x}"

    # The redirects into the installer tail are written last, after the hook
    # body and the installer are already in place.
    sites = [wb.fabric(s) for s in wb.PROFILES[name]["site"]]
    assert [a for a, _, _, _ in actions[-2:]] == sites, f"{name}: redirects not last"

    # Addresses are unique and word-aligned, and the planted words are exactly
    # the blobs: 46 hook dwords, 8 helper, 11 tail, 2 redirects.
    addresses = [a for a, _, _ in targets]
    assert len(set(addresses)) == 67 and not any(a & 3 for a in addresses)
    planted = [p for _, _, p in targets]
    assert planted[:46] == list(struct.unpack("<46I", prof.source)), f"{name}: payload"
    assert planted[46:54] == list(struct.unpack("<8I", prof.helper)), f"{name}: helper"
    assert planted[54:65] == list(struct.unpack("<11I", prof.tail)), f"{name}: tail"
    assert tuple(planted[65:]) == wb.PROFILES[name]["patch_site"], f"{name}: sites"
    stocks = [s for _, s, _ in targets]
    assert stocks[:46] == list(struct.unpack("<46I", prof.stock)), f"{name}: preimage"
    assert stocks[46:65] == [0] * 19, f"{name}: caves must read as zero"

print(f"manifests: {len(wb.PROFILES)} profiles x 135 actions, probes before writes")

# --- request builders -------------------------------------------------------
prof = wb.Profile("a")
for address, value, width, _ in prof.actions():
    request = wb.five_call(H, address, value, width == 4)
    assert len(request) == wb.BUFFER_SIZE, "wrong command-buffer size"
    assert struct.unpack_from("<I", request, 0)[0] == 0xFE0A
    assert struct.unpack_from("<I", request, 0x10)[0] == H
    # The fourth RPC is the 0x403 write, carrying our address, value and width.
    write = request[wb.SOURCE_OFF + wb.MESSAGE_OFFSETS[3] :][: wb.RPC_SIZE]
    opcode, a1, a2, a3, _, a5 = struct.unpack_from("<6I", write)
    assert (opcode, a1, a2, a3) == (0x403, 82 | 4 << 8, address, value)
    assert a5 == (4 if width == 4 else 0), "probe must be a width-0 no-write"
    # The ASD .163 allowlist entry has to name the same address.
    entry = struct.unpack_from("<I", request, wb.SOURCE_OFF + 0xA88)[0]
    assert entry == address, "allowlist entry does not match the write target"

for builder in (wb.fe07_open(), wb.fe08_auth(H, bytes(256)), wb.fe0c_migration(),
                wb.fe09_authenticated_seed(H, 1, bytes(16), 16),
                wb.fe0a_codeword_probe(H, 0x404A78)):
    assert len(builder) == wb.BUFFER_SIZE, "signed-gate request is the wrong size"

print("builders: 135 ROP requests plus 5 signed gates well formed")

# --- identify.py ------------------------------------------------------------
# Synthetic dumps: the bootloader side is the real shipped preimage, the sOS
# side places the documented anchors at each profile's own offsets.
random.seed(11)

for name, p in idf.PROFILES.items():
    assert p["site"] == wb.PROFILES[name]["sos_site"], f"{name}: site drift"
    assert p["cave"] == wb.PROFILES[name]["sos_cave"], f"{name}: cave drift"
    assert p["stock"] == wb.PROFILES[name]["stock"], f"{name}: stock blob drift"


def synth_sos(name, size=0x20000):
    p = idf.PROFILES[name]
    b = bytearray(random.getrandbits(8) for _ in range(size))

    def put(va, data):
        b[va - idf.HEADER : va - idf.HEADER + len(data)] = data

    put(p["helper"], idf.CACHE_PROLOGUE)
    put(p["site"], struct.pack("<I", idf.SOS_SITE_WORD))
    put(p["cave"], bytes(idf.SPAN))
    return bytes(b)


def synth_flash(name):
    pad = lambda n: bytes(random.getrandbits(8) for _ in range(n))
    bl = (HERE / "hook" / idf.PROFILES[name]["stock"]).read_bytes()
    return pad(0x2000) + bl + pad(0x1000) + synth_sos(name) + pad(0x800)


def quietly(blob):
    with redirect_stdout(io.StringIO()):
        return idf.identify(blob)


for name in sorted(idf.PROFILES):
    assert quietly(synth_flash(name)) == name, f"identify: full flash {name}"
    assert quietly(synth_sos(name)) == name, f"identify: sOS payload {name}"

# The shared a/b bootloader span alone cannot decide, and must not guess.
assert quietly((HERE / "hook" / "source_stock.bin").read_bytes()) is None
# Noise, and an sOS truncated before its cave, resolve to nothing.
assert quietly(bytes(random.getrandbits(8) for _ in range(0x10000))) is None
assert quietly(synth_sos("a")[: idf.PROFILES["a"]["cave"] - idf.HEADER]) is None

print("identify: resolves a/b/c/d from flash or sOS payload, no false positives")
print("selftest ok")

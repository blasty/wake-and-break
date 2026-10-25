#!/usr/bin/env python3
"""Extract the exact LOAD_IP_FW payloads the AM driver sends, and write a
signature-only tampered copy of one of them, for `hax.py --hook ipfw`.

Every payload is a signed `$PS1` container whose trailing 0x100 bytes are the
RSA-2048 signature over everything before it. Flipping a bit there invalidates
the signature while leaving the ucode body bit-identical, so an acceptance
re-loads the genuine firmware and proves only that the verdict was skipped.

Reads firmware files and opens no device:

    python3 ipfw_images.py            # list the payloads this card loads
    python3 ipfw_images.py 89         # write /tmp/fw_89_{ok,bad}.bin
"""
import hashlib
import sys
import types
from pathlib import Path

from tinygrad.runtime.autogen.am import am
from tinygrad.runtime.support.am.amdev import AMFirmware

# IP versions of the tested card (gfx11 / RX 7900 XTX); AMFirmware only uses
# these to build firmware file names, so no device is needed.
STUB = types.SimpleNamespace(
    ip_ver={
        am.MP0_HWIP: (13, 0, 0),
        am.MP1_HWIP: (13, 0, 0),
        am.GC_HWIP: (11, 0, 0),
        am.SDMA0_HWIP: (6, 0, 0),
    },
    devfmt="ipfw_images",
)


def payloads():
    fw = AMFirmware(STUB)
    descs = list(fw.descs)
    if hasattr(fw, "smu_psp_desc"):
        descs.insert(0, fw.smu_psp_desc)  # SMU is loaded before the TMR
    return descs


def main():
    names = {v: k for k, v in vars(am).items() if k.startswith("GFX_FW_TYPE_")}
    want = int(sys.argv[1], 0) if len(sys.argv) > 1 else None
    for types_, blob in payloads():
        data = bytes(blob)
        label = ",".join(names.get(t, hex(t)) for t in types_)
        print(
            f"{label:<34} {len(data):>8} bytes  magic={data[0x10:0x14]!r}"
            f"  sha256={hashlib.sha256(data).hexdigest()[:12]}"
        )
        if want is None or want not in types_:
            continue
        if data[0x10:0x14] != b"$PS1":
            raise SystemExit("not a signed $PS1 container; refusing to tamper")
        Path(f"/tmp/fw_{want}_ok.bin").write_bytes(data)
        bad = bytearray(data)
        bad[-0x100] ^= 1
        Path(f"/tmp/fw_{want}_bad.bin").write_bytes(bad)
        print(f"\nwrote /tmp/fw_{want}_ok.bin and /tmp/fw_{want}_bad.bin")
        return
    if want is not None:
        raise SystemExit(f"type {want:#x} is not loaded by this driver")


if __name__ == "__main__":
    main()

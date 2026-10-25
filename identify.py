"""Which --sos-build does this card need? Answer it from an SPI flash dump.

    python3 identify.py FLASH.bin
    python3 identify.py PSP_SOS.bin --verbose

Feed it anything that contains the PSP images in plaintext: a full SPI dump, a
single extracted payload, or a directory entry's body. Nothing is parsed --
the images are found by content, so the container layout does not matter.

Two independent pieces of evidence, each on its own:

  bootloader  the 184-byte span the plant overwrites is shipped as
              hook/source_stock*.bin, so it is searched for verbatim.
              Profiles a and b share one bootloader and cannot be separated
              by it.
  sOS         located by the stock cache clean+invalidate helper's prologue,
              then confirmed at that profile's own offsets: the hooked call
              site holds 0xF0074620 and the 184-byte cave is zero. Those
              offsets differ per build, so this does separate a from b.

The intersection is the answer. An EncOption=1 body is AES-CBC encrypted in
flash and reads as noise; if nothing is found, extract and decrypt the
payloads first with an AMD SPI parser and run this on the result.
"""

import argparse
import hashlib
from pathlib import Path
from struct import unpack_from

HERE = Path(__file__).resolve().parent
HOOK = HERE / "hook"

# Mirrors PROFILES in wakebreak.py; keep the two in step.
# sOS file offset = VA - 0x100 (the signed image carries a 0x100-byte header).
PROFILES = {
    "a": dict(stock="source_stock.bin", bl="26565174", sos="8168d633",
              site=0x9B28, cave=0x12CB8, helper=0x5600, roms=12),
    "b": dict(stock="source_stock.bin", bl="26565174", sos="b8cb2d7d",
              site=0x9B48, cave=0x12CD8, helper=0x5600, roms=3),
    "c": dict(stock="source_stock_sosc.bin", bl="294ec7b1", sos="f796ac5e",
              site=0x99AC, cave=0x12AB8, helper=0x54F4, roms=21),
    "d": dict(stock="source_stock_sosd.bin", bl="46f0c343", sos="7b395f4d",
              site=0x9C80, cave=0x132A4, helper=0x5688, roms=3),
}

SOS_SITE_WORD = 0xF0074620  # MOV R0,R4 + first BL halfword, all four builds
CACHE_PROLOGUE = bytes.fromhex("70b522f01f04")  # cache clean+invalidate helper
HEADER = 0x100  # signed image header, so file offset = VA - HEADER
SPAN = 184


def find_all(blob, needle, limit=64):
    out, at = [], blob.find(needle)
    while at >= 0 and len(out) < limit:
        out.append(at)
        at = blob.find(needle, at + 1)
    return out


def bootloader_evidence(blob):
    """Profiles whose stock bootloader span appears verbatim in the dump."""
    hits = {}
    for name, p in PROFILES.items():
        path = HOOK / p["stock"]
        if not path.is_file():
            continue
        span = path.read_bytes()
        if len(span) != SPAN:
            raise SystemExit(f"{path} is {len(span)} bytes, expected {SPAN}")
        for at in find_all(blob, span):
            hits.setdefault(name, []).append(at)
    return hits


def sos_evidence(blob):
    """Profiles whose sOS anchors all hold at a consistent image base.

    The cache helper's prologue gives a candidate base; the hooked call site
    and the zero cave then have to agree at that profile's own offsets.
    """
    hits = {}
    for at in find_all(blob, CACHE_PROLOGUE, limit=256):
        for name, p in PROFILES.items():
            base = at - (p["helper"] - HEADER)
            if base < 0:
                continue
            site = base + p["site"] - HEADER
            cave = base + p["cave"] - HEADER
            if site + 4 > len(blob) or cave + SPAN > len(blob):
                continue
            if unpack_from("<I", blob, site)[0] != SOS_SITE_WORD:
                continue
            if blob[cave : cave + SPAN] != bytes(SPAN):
                continue
            hits.setdefault(name, []).append(base)
    return hits


def identify(blob, verbose=False):
    bl, sos = bootloader_evidence(blob), sos_evidence(blob)

    def show(label, hits, extra):
        if not hits:
            print(f"  {label:<11} not found")
            return
        for name in sorted(hits):
            at = hits[name] if verbose else hits[name][:4]
            where = ", ".join(f"{o:#x}" for o in at)
            more = "" if len(at) == len(hits[name]) else f" (+{len(hits[name]) - len(at)})"
            print(f"  {label:<11} {name} ({extra(name)}) at {where}{more}")

    print(f"{len(blob)} bytes, sha256 {hashlib.sha256(blob).hexdigest()[:16]}")
    show("bootloader", bl, lambda n: PROFILES[n]["bl"])
    show("sOS", sos, lambda n: PROFILES[n]["sos"])

    both = sorted(set(bl) & set(sos))
    if len(both) == 1:
        name = both[0]
        print(f"\nsos-build {name}: wakebreak.py --sos-build {name}")
        return name
    # The sOS alone is decisive when present: it is what the installer
    # compares, and its offsets differ across all four profiles.
    if len(sos) == 1:
        name = next(iter(sos))
        print(f"\nsos-build {name} (sOS only; bootloader not in this dump)")
        print(f"wakebreak.py --sos-build {name}")
        return name
    if both:
        print(f"\nambiguous: {', '.join(both)}. Dump contains more than one build?")
        return None
    if bl and not sos:
        names = sorted(bl)
        print(f"\nbootloader matches {', '.join(names)} but no plaintext sOS was")
        print("found. If the sOS body is EncOption=1 it is AES-CBC encrypted in")
        print("flash: extract and decrypt the payloads first, then retry.")
        return None
    print("\nno shipped profile matches this dump.")
    print("Either the images are encrypted or compressed, or this is a build")
    print("nobody has retargeted yet. Trying each --sos-build is harmless.")
    return None


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("dump", type=Path, help="SPI flash dump or extracted payload")
    ap.add_argument("-v", "--verbose", action="store_true",
                    help="list every anchor offset found")
    args = ap.parse_args()
    if not args.dump.is_file():
        raise SystemExit(f"{args.dump} is not a file")
    raise SystemExit(0 if identify(args.dump.read_bytes(), args.verbose) else 1)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Generates tweaks/model-cycles_OS1.13/50-control-all-config.json (personal tweak, English).

Port of durchgemacht/cycles-control-all-config (MIT, see tools/machines/control_all/LICENSE-control-all-config):
[TRACK] + TRIG 1-6 leaves single tracks out of Control All. The assembly source is the author's, unchanged.
Difference from the original build: its second code block sat in the 34x34 sprite mask 0x4016f8c8, which
lfo-plus uses. Here it sits in the free 34x34 mask 0x40185f48 (constant 0x400ad9c4), so both mods can be ticked.

Needs the m68k binutils (as, ld, nm, objcopy) and the official .syx:
    python3 tools/gen_control_all.py --cycles model-cycles_OS1.13.syx [--cross m68k-linux-gnu-] [--check]
"""
import argparse, json, pathlib, shutil, struct, subprocess, sys, tempfile

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import build, sprites                                   # noqa: E402
from mtlib import aplib, container                      # noqa: E402
from mtlib.syx import unwrap                            # noqa: E402

OUT = HERE.parent / "tweaks" / "model-cycles_OS1.13" / "50-control-all-config.json"
SRC = HERE / "machines" / "control_all" / "control_all_config.s"
BASE = build.BASE
MASK_A, SIZE_A = 0x4018D918, 328      # 41x41, section .cac_a (as upstream)
MASK_B, SIZE_B = 0x40185F48, 272      # 34x34, section .cac_b (upstream used 0x4016f8c8)
LOOPS = [(0x4001D6F8, "2052 2668 007c", "cac_loop1"), (0x4001D5A2, "2052 2f03 2f02", "cac_loop2"),
         (0x4001EBD2, "2052 4878 0020", "cac_loop3"), (0x4001AC7A, "2f02 2f03 4e92", "cac_loop4"),
         (0x400A2798, "2f02 2f05 4e94", "cac_loop5")]
VTABLE = [(0x40100EE8, 0x40024078, "cac_keys"), (0x40100F98, 0x40023D8C, "cac_leds")]


def main_os(path):
    stream, _ = unwrap(pathlib.Path(path).read_bytes())
    c = container.parse(stream)
    s3 = next(s for s in c["sections"] if s["id"] == 3)
    return aplib.depack(c["blob"][s3["off"]:s3["off"] + s3["size"]])[0]


def run(*cmd):
    r = subprocess.run(list(map(str, cmd)), capture_output=True, text=True)
    if r.returncode:
        sys.exit("!! %s failed:\n%s%s" % (cmd[0], r.stdout, r.stderr))
    return r.stdout


def assemble(cross):
    tools = {n: shutil.which(cross + n) for n in ("as", "ld", "nm", "objcopy")}
    if not all(tools.values()):
        sys.exit("!! m68k binutils not found (prefix %r). sudo apt install binutils-m68k-linux-gnu, "
                 "then pass --cross m68k-linux-gnu-" % cross)
    with tempfile.TemporaryDirectory() as t:
        t = pathlib.Path(t)
        (t / "l.ld").write_text("SECTIONS {\n .cac_a 0x%x : { *(.cac_a) }\n .cac_b 0x%x : { *(.cac_b) }\n"
                                " /DISCARD/ : { *(*) }\n}\n" % (MASK_A, MASK_B))
        run(tools["as"], "-mcpu=54418", "-o", t / "o.o", SRC)
        run(tools["ld"], "-T", t / "l.ld", "-o", t / "o.elf", t / "o.o")
        syms = {}
        for line in run(tools["nm"], t / "o.elf").splitlines():
            a, k, n = line.split()
            if k in "Tt":
                syms[n] = int(a, 16)
        code = {}
        for sec, addr, size in ((".cac_a", MASK_A, SIZE_A), (".cac_b", MASK_B, SIZE_B)):
            run(tools["objcopy"], "-O", "binary", "-j", sec, t / "o.elf", t / (sec[1:] + ".bin"))
            b = (t / (sec[1:] + ".bin")).read_bytes()
            if len(b) > size:
                sys.exit("!! %s is %d bytes, mask holds %d" % (sec, len(b), size))
            code[addr] = b
        return code, syms


def build_tweak(stock, cross):
    code, syms = assemble(cross)
    at = lambda va, n: stock[va - BASE:va - BASE + n]
    writes = []
    for addr, size in ((MASK_A, SIZE_A), (MASK_B, SIZE_B)):
        _, const, _, kept = sprites.MASKS[addr]
        if at(addr, size) != at(kept, size):
            sys.exit("!! mask %#x is not identical to its kept copy %#x" % (addr, kept))
        if at(const, 4) != struct.pack(">I", addr) or stock.count(struct.pack(">I", addr)) != 1:
            sys.exit("!! unexpected references to mask %#x" % addr)
        c = code[addr]
        writes.append({"off": addr - BASE, "old": at(addr, len(c)).hex(), "new": c.hex()})
        writes.append(sprites.redirect_write(addr))
    for va, old_hex, sym in LOOPS:
        old = bytes.fromhex(old_hex)
        if at(va, len(old)) != old:
            sys.exit("!! unexpected stock bytes at %#x" % va)
        # The moved instructions follow "move.l d2,d0 / jsr cac_skip / tst.l d0 / bne.s 2f". Depending on the
        # assembler, jsr cac_skip is 4 bytes (pc-relative) or 6 (absolute), so look for the stock bytes + the
        # jump back instead of using a fixed offset. Exactly one place in the first 40 bytes must match.
        tr = code_bytes(code, syms[sym])
        pat = old + b"\x4e\xf9" + struct.pack(">I", va + 6)
        hits = [i for i in range(4, 40) if tr[i:i + len(pat)] == pat]
        if len(hits) != 1:
            sys.exit("!! %s does not repeat the stock bytes of %#x and jump back (first 30 bytes: %s)"
                     % (sym, va, tr[:30].hex()))
        writes.append({"off": va - BASE, "old": old_hex.replace(" ", ""),
                       "new": (b"\x4e\xf9" + struct.pack(">I", syms[sym])).hex()})
    for va, old, sym in VTABLE:
        if at(va, 4) != struct.pack(">I", old):
            sys.exit("!! unexpected vtable slot at %#x" % va)
        writes.append({"off": va - BASE, "old": struct.pack(">I", old).hex(), "new": struct.pack(">I", syms[sym]).hex()})
    return {"id": "control-all-config", "order": 50, "name": "Control All: leave tracks out",
            "description": ["[TRACK] + TRIG 1-6 toggles whether a track follows Control All (TRACK held + knob). "
                            "Port of durchgemacht/cycles-control-all-config (MIT), second code block moved to the "
                            "free 34x34 mask 0x40185f48 so it works with lfo-plus. Personal tweak, untested."],
            "device": "Model:Cycles", "os": "1.13", "section": 3, "writes": writes}


def code_bytes(code, va):
    for addr, b in code.items():
        if addr <= va < addr + len(b):
            return b[va - addr:]
    sys.exit("!! symbol %#x outside the code" % va)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--cycles", required=True)
    ap.add_argument("--cross", default="m68k-linux-gnu-")
    ap.add_argument("--check", action="store_true")
    a = ap.parse_args()
    stock = main_os(a.cycles)
    dev = json.loads((OUT.parent / "device.json").read_text(encoding="utf-8"))
    if build.sha(stock) != dev["section_sha256"]:
        sys.exit("!! not the official Model:Cycles OS 1.13 main program")
    tw = build_tweak(stock, a.cross)
    build.apply_writes(stock, [tw])
    text = json.dumps(tw, indent=1, ensure_ascii=False) + "\n"
    if a.check:
        ok = OUT.exists() and OUT.read_text(encoding="utf-8") == text
        print("  %s %s" % (OUT.name, "is up to date" if ok else "DOES NOT MATCH"))
        sys.exit(0 if ok else 1)
    OUT.write_text(text, encoding="utf-8")
    print("  wrote %s (%d writes)" % (OUT.name, len(tw["writes"])))


if __name__ == "__main__":
    main()

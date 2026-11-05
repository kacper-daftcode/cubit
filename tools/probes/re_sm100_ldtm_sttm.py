#!/usr/bin/env python3
"""Measure the tcgen05 `LDTM Rd, tmem[URb+off]` (opcode 0x9ee, key `LDTM_R_II`) and
`STTM tmem[URb+off], Ra` (0x9ed, `STTM_II_R`) field layout on sm_100a / sm_103a and rebuild the
two keys' harvest rows.

Why: the SM103a/SM100a strict round trip of 2026-11-03 (B300 host, cubit `docs/KNOWN_ISSUES.md` V5,
session T NEEDS_OWNER 19) left 5 tcgen05 words that re-encoded to a different word:
`STTM.16dp32bit_t16_t31.x{2,8,32} tmem[0x..], R` and `LDTM.16dp32bit_t16_t31.x{2,8}`. Their
harvest rows had no uniform-register field (the sample's URZ = 0xff was half-baked as 0xc0 in
`and_base`), a 2-3-bit register field and a 32-bit offset field that overlapped the UR slot, so
cubit printed `tmem[URZ+0x20]` and re-encoded it as `tmem[UR192+0x20]`.

Measured with nvdisasm 13.1 (`-b SM100`, one word per call; `-b SM103` agrees):
  * shape enum = bits {87, 82, 81} (value = bit81 | bit82<<1 | bit87<<2): 0 `16dp128bit`,
    1 `16dp256bit`, 2 `32dp32bit` (printed as no modifier), 3 `16dp64bit`, 4 `16dp32bit_t0_t15`,
    5 `16dp32bit_t16_t31`, 6 / 7 INVALID6 / INVALID7 (unclaimed);
  * count enum `.x2^n` at [85:83] (x2 .. x128; 0 = no modifier, printed as the bare op);
  * bit 80 = `.EXPAND16BIT` (STTM) / `.PACK16BIT` (LDTM);
  * register: LDTM Rd at [23:16], STTM Ra at [39:32] — 8 bits, 255 = RZ;
  * tmem base UR: LDTM [39:32], STTM [71:64] — 8 bits, 255 = URZ (printed `tmem[URZ]` with offset 0,
    elided with an offset: `tmem[0x20]`; a register base prints `tmem[UR4]` / `tmem[UR4+0x20]`);
    nvdisasm names any value (UR192 ...), the parser bounds it to UR0..UR63 / URZ;
  * tmem offset: bits [63:40] (24 bits) plus [79:72] as bits [31:24] of a signed 32-bit offset —
    the rows carry the 24-bit field only (every shipped word fits), the high byte stays outside
    the mask (fail-closed, lattice);
  * bit 91 is the frame (clear = illegal); bits 86, 88-90 and (LDTM) [71:64] are text-inert and
    stay outside the rows.
`probe` writes `tests/fixtures/sm100a_ldtm_sttm_nvdisasm.jsonl`; `apply <table.json>` rebuilds
`LDTM_R_II` and `STTM_II_R` (one measured group per legal shape x count x pack) in a canonical
sm100a.json / sm103a.json.
"""
import argparse
import pathlib
import re
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import nvprobe  # noqa: E402

PROVENANCE = "ldtm-sttm-sm100-2026-11-05"
OPC = {"LDTM": 0x9ee, "STTM": 0x9ed}
NATIVE_CTRL = 0x000fe400 << 96
SHAPES = {0: "16dp128bit", 1: "16dp256bit", 2: "", 3: "16dp64bit", 4: "16dp32bit_t0_t15", 5: "16dp32bit_t16_t31"}
PACK = {"LDTM": "PACK16BIT", "STTM": "EXPAND16BIT"}
FIXTURE = nvprobe.FIXTURES / "sm100a_ldtm_sttm_nvdisasm.jsonl"
TMEM = r"tmem\[(UR(Z|\d+)|UR\d+\+-?0x[0-9a-f]+|-?0x[0-9a-f]+)\]"
TEXT = re.compile(r"(@!?UP[0-6T] )?(LDTM|STTM)(\.[A-Za-z0-9_]+)* (R(Z|\d+), " + TMEM + "|" + TMEM + r", R(Z|\d+))")


def word(op, shape=5, count=5, pack=0, guard=7, reg=4, ur=255, off=0x20, extra=0, bit91=1):
    w = OPC[op] | (guard << 12) | (off << 40) | (pack << 80) | (count << 83) | (bit91 << 91) | extra
    w |= ((shape & 1) << 81) | (((shape >> 1) & 1) << 82) | (((shape >> 2) & 1) << 87)
    if op == "LDTM":
        w |= (reg << 16) | (ur << 32)
    else:
        w |= (reg << 32) | (ur << 64)
    return w


def sweep_words():
    form, lattice = set(), set()
    for op in OPC:
        for shape in range(8):
            for count in range(8):
                for pack in (0, 1):
                    base = word(op, shape, count, pack)
                    if shape not in SHAPES:
                        lattice.add(base)
                        continue
                    form.add(base)
                    if count in (0, 5) and pack == 0:
                        for guard in (0, 3, 15):
                            form.add(word(op, shape, count, pack, guard=guard))
                        for reg in (0, 1, 128, 254, 255):
                            form.add(word(op, shape, count, pack, reg=reg))
                        for ur in (0, 4, 63, 255):
                            form.add(word(op, shape, count, pack, ur=ur))
                        for off in (0, 1, 0x8, 0x1000, 0xffffff):
                            form.add(word(op, shape, count, pack, off=off))
        base = word(op)
        lattice.add(word(op, bit91=0))
        for bit in (72, 79, 86, 88, 89, 90):
            lattice.add(base | (1 << bit))
        if op == "LDTM":
            for bit in (64, 71):
                lattice.add(base | (1 << bit))
    lattice -= form
    return [(w, False) for w in sorted(form)] + [(w, True) for w in sorted(lattice)]


def probe(nvdisasm, out=FIXTURE, arch="SM100"):
    rows = nvprobe.probe_words(
        nvdisasm, "ldtm_sttm", sweep_words(), NATIVE_CTRL,
        check_form=lambda w, t: TEXT.fullmatch(t) is not None,
        check_lattice=lambda w, t: t is None or t.startswith(("LDTM", "STTM")),
        arch=arch)
    nvprobe.write_fixture(out, rows)
    n_form = sum(1 for r in rows if not r.get("lattice"))
    print(f"{out}: {n_form} form words, {len(rows) - n_form} lattice words ({arch})")


def mods_of(text):
    op = text.split()[0]
    return op.split(".")[1:]


def measured_group(op, shape, count, pack):
    base = word(op, shape, count, pack, guard=0, reg=0, ur=0, off=0)
    src = PROVENANCE
    if op == "LDTM":
        fields = [nvprobe.field(12, 4, "guard", 0, src), nvprobe.field(16, 8, "reg", 1, src),
                  nvprobe.field(32, 8, "tmem_ur", 2, src), nvprobe.field(40, 24, "tmem_off", 2, src)]
    else:
        fields = [nvprobe.field(12, 4, "guard", 0, src), nvprobe.field(64, 8, "tmem_ur", 1, src),
                  nvprobe.field(40, 24, "tmem_off", 1, src), nvprobe.field(32, 8, "reg", 2, src)]
    note = f"{op} shape {SHAPES[shape] or '32dp32bit'} count 2^{count} pack {pack}: measured with nvdisasm 13.1 -b SM100 (session T-5, 2026-11-05)"
    return nvprobe.row(base, fields, src, note)


def apply(table_path):
    path = pathlib.Path(table_path)
    table = nvprobe.load_table(path)
    ins = table["instructions"]
    for op, key in (("LDTM", "LDTM_R_II"), ("STTM", "STTM_II_R")):
        entry = ins[key]
        if all(g.get("_src") == PROVENANCE for g in entry["mod_groups"].values()):
            print(f"{key}: already measured in {path}")
            continue
        groups = {}
        for shape, sname in SHAPES.items():
            for count in range(8):
                for pack in (0, 1):
                    mods = [m for m in (sname, PACK[op] if pack else "", f"x{1 << count}" if count else "") if m]
                    groups[",".join(sorted(mods))] = measured_group(op, shape, count, pack)
        entry["mod_groups"] = groups
        entry["_src"] = PROVENANCE
        print(f"{key}: rebuilt with {len(groups)} groups in {path}")
    nvprobe.save_table(path, table)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("probe")
    p.add_argument("--nvdisasm", required=True)
    p.add_argument("--out", type=pathlib.Path, default=FIXTURE)
    p.add_argument("--arch", default="SM100")
    a = sub.add_parser("apply")
    a.add_argument("table")
    args = parser.parse_args()
    if args.command == "probe":
        probe(args.nvdisasm, args.out, args.arch)
    else:
        apply(args.table)


if __name__ == "__main__":
    main()

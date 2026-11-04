#!/usr/bin/env python3
"""Measure SM120 `MUFU.<fn>[.F16|.BF16] Rd, [-|]URb[|]` (the uniform-source transcendental, opcode
0xd08) and rebuild its canonical key `MUFU_R_UR`.

Found by the GB10-host census of 2026-11-04 (cuBLASLt sm_120 cubins, `lib_120.jsonl`): `MUFU.EX2
R4, UR7` decoded as `MUFU.LG2`, `MUFU.RSQ R2, UR6` as `MUFU.RCP` / `MUFU.RCP64H`. The four harvest
rows of `MUFU_R_UR` (LG2 / RCP / RCP64H / RSQ64H) baked their sample's UR number and function code
into `and_base` with masks of a few stray bits, so the decoder's tiebreak picked them for any
function.

`probe` sweeps with nvdisasm 13.1 (one word per call): the function enum [77:74] (0 COS, 1 SIN,
2 EX2, 3 LG2, 4 RCP, 5 RSQ, 6 RCP64H, 7 RSQ64H, 8 SQRT, 9 TANH; 10-15 print INVALIDn and stay
unclaimed), the guard [15:12], Rd [23:16] (255 = RZ), URb [39:32] (255 = URZ), abs (bit 62,
`|URb|`), neg (bit 63, `-URb`), the half types bit 72 (`.F16`) / bit 73 (`.BF16`; both set is
rejected; on RCP64H / RSQ64H they print INVALID6 / INVALID7 and stay unclaimed), bit 91 (required
frame; clear is rejected). Bits 24-31, 40-61, 78-90 are text-inert and stay outside the rows
(fail-closed). `apply` replaces the four harvest groups with the ten measured function groups, each
with fields guard / reg / ureg / abs / neg, plus the `F16` and `BF16` twins of the eight functions
that take them (26 groups), cloning the entry metadata of the existing key.
"""
import argparse
import pathlib
import re
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import nvprobe  # noqa: E402

PROVENANCE = "mufu-ur-sm120-2026-11-04"
OPCODE = 0xd08
NATIVE_CTRL = 0x000e2400 << 96  # control code of the census word
KEY = "MUFU_R_UR"
FUNCS = {0: "COS", 1: "SIN", 2: "EX2", 3: "LG2", 4: "RCP", 5: "RSQ", 6: "RCP64H", 7: "RSQ64H", 8: "SQRT", 9: "TANH"}
HALF = {0: "", 1: "F16", 2: "BF16"}
NO_HALF = {6, 7}  # RCP64H / RSQ64H: the half types print INVALID6 / INVALID7


def legal(fn, half):
    return half == 0 or fn not in NO_HALF
FIXTURE = nvprobe.FIXTURES / "sm120_mufu_ur_nvdisasm.jsonl"
TEXT = re.compile(r"(@!?P[0-6T] )?MUFU\.(COS|SIN|EX2|LG2|RCP|RSQ|RCP64H|RSQ64H|SQRT|TANH)(\.(F16|BF16))? R(Z|\d+), -?\|?UR(Z|\d+)\|?")


def word(guard=7, rd=4, ur=7, fn=2, half=0, neg=0, abs_=0, hi_extra=0, bit91=1):
    return (OPCODE | (guard << 12) | (rd << 16) | (ur << 32) | (abs_ << 62) | (neg << 63) | (half << 72)
            | (fn << 74) | (bit91 << 91) | hi_extra)


def sweep_words():
    form = set()
    lattice_half = set()
    for fn in FUNCS:
        for half in HALF:
            if not legal(fn, half):
                lattice_half.add(word(fn=fn, half=half))
                continue
            form.add(word(fn=fn, half=half))
            for guard in (0, 3, 7, 8, 15):
                form.add(word(fn=fn, half=half, guard=guard))
            for r in (0, 1, 100, 254, 255):
                form.add(word(fn=fn, half=half, rd=r))
            for ur in (0, 1, 31, 62, 63, 255):
                form.add(word(fn=fn, half=half, ur=ur))
            form.add(word(fn=fn, half=half, neg=1))
            form.add(word(fn=fn, half=half, abs_=1))
            form.add(word(fn=fn, half=half, neg=1, abs_=1))
    lattice = {word(bit91=0), word(half=3)} | lattice_half
    for fn in range(10, 16):
        lattice.add(word(fn=fn))
    for bit in [*range(24, 32), 40, 48, 56, 61, *range(78, 91)]:
        lattice.add(word(hi_extra=1 << bit))
    lattice -= form
    return [(w, False) for w in sorted(form)] + [(w, True) for w in sorted(lattice)]


def probe(nvdisasm, out=FIXTURE):
    rows = nvprobe.probe_words(
        nvdisasm, "mufu_ur", sweep_words(), NATIVE_CTRL,
        check_form=lambda w, t: TEXT.fullmatch(t) is not None,
        check_lattice=lambda w, t: t is None or t.startswith("MUFU"),
    )
    nvprobe.write_fixture(out, rows)
    n_form = sum(not r.get("lattice") for r in rows)
    print(f"{n_form} MUFU Rd, UR words + {len(rows) - n_form} lattice words -> {out}")


def measured_group(fn, half):
    fields = [nvprobe.field(12, 4, "guard", 0, PROVENANCE), nvprobe.field(16, 8, "reg", 1, PROVENANCE),
              nvprobe.field(32, 8, "ureg", 2, PROVENANCE), nvprobe.field(62, 1, "abs", 2, PROVENANCE),
              nvprobe.field(63, 1, "neg", 2, PROVENANCE)]
    return nvprobe.row(
        word(guard=0, rd=0, ur=0, fn=fn, half=half), fields, PROVENANCE,
        "nvdisasm 13.1 sweeps (2026-11-04, found by the GB10-host census of cuBLASLt sm_120 code): guard[15:12], "
        f"Rd[23:16] (255 = RZ), UR[39:32] (255 = URZ), abs bit 62, neg bit 63; function [77:74] = {fn} ({FUNCS[fn]}; "
        f"10-15 = INVALIDn, unclaimed), half type bits 72/73 = {HALF[half] or 'none'} (both set is rejected; INVALIDn on "
        "RCP64H / RSQ64H, unclaimed), bit 91 "
        "= the uniform frame (required). Bits 24-31, 40-61, 78-90 are text-inert - outside the row. Replaces four "
        "harvest rows that baked a sample's UR and function into and_base with a few-bit mask (EX2 decoded as LG2, RSQ "
        "as RCP / RCP64H).",
    )


def apply(table_path):
    path = pathlib.Path(table_path)
    table = nvprobe.load_table(path)
    ins = table["instructions"]
    if KEY in ins and all(g.get("_src") == PROVENANCE for g in ins[KEY]["mod_groups"].values()):
        print(f"{KEY}: already measured in {path}")
        return
    entry = ins[KEY]
    groups = {}
    for fn, name in FUNCS.items():
        for half, hname in HALF.items():
            if not legal(fn, half):
                continue
            gname = ",".join(sorted(x for x in (name, hname) if x))
            groups[gname] = measured_group(fn, half)
    entry["mod_groups"] = groups
    entry["_src"] = PROVENANCE
    nvprobe.save_table(path, table)
    print(f"{KEY}: rebuilt with {len(groups)} groups in {path}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("probe")
    p.add_argument("--nvdisasm", required=True)
    p.add_argument("--out", type=pathlib.Path, default=FIXTURE)
    a = sub.add_parser("apply")
    a.add_argument("table")
    args = parser.parse_args()
    if args.command == "probe":
        probe(args.nvdisasm, args.out)
    else:
        apply(args.table)


if __name__ == "__main__":
    main()

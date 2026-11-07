#!/usr/bin/env python3
"""Measure the sm103a MUFU packed-half lanes `MUFU.EX2.BF16x2` / `MUFU.EX2.F16x2 Rd, [-|]Ra[|] | [-|]URa[|] | imm_hi, imm_lo`
(opcodes 0x308 register / 0xd08 + bit 91 uniform / 0x908 immediate) and add their rows to `sm103a.json`.

Found by session G's conversion batch (2026-11-07, `G/NEEDS_OWNER.md` 5, T `NEEDS_OWNER.md` 48): on `-b SM103` nvdisasm renders
bit 80 as `.BF16x2` and the half code 3 ([73:72]) as `.F16x2` on MUFU; on `-b SM120` / `SM100` bit 80 is text-inert and half 3
is illegal. Session T-14 measured the lanes on the B300 host (`cold-face-bounces-fin-02`, CPU guest) with **nvdisasm 13.3.73**
(`/usr/local/cuda-13.3/bin/nvdisasm`), and nvdisasm 13.0.85 and 13.1 (this host) print the same text for every word
(`T/t14/needs46/mufu_lattice_multi.jsonl`, `mufu_x2_probe_multi.jsonl`: 384 lattice + 674 sweep words, 0 disagreements).

Law (SM103): the function [77:74] admits **EX2 (2) only** in the packed lanes — every other value prints `INVALIDn.BF16x2` /
`INVALIDn.F16x2` (unclaimed, fail-closed); the `.BF16x2` lane is bit 80 with the half code 0 (bit 80 with half 1 / 2 / 3 is
illegal); the `.F16x2` lane is the half code 3 (with bit 80 illegal); guard [15:12]; Rd [23:16] (255 = RZ); Ra / URa [39:32]
(255 = RZ / URZ) with `|x|` bit 62 and `-x` bit 63; the immediate form carries two halves, hi [63:48] printed first and lo
[47:32] second, as bf16 (`.BF16x2`) or f16 (`.F16x2`) literals (`MUFU.EX2.F16x2 R4, 1, 1` for 0x3c00:0x3c00; `+INF , -INF`
for 0x7c00:0xfc00); the uniform form needs bit 91 (clear = illegal; set on the register / immediate forms = illegal). Bit 60
(the `.H1` selector of the scalar half lanes) is text-inert in the packed lanes, as are bits 24-31, 40-61 (R / UR forms),
64-71, 78-79, 81-90, 92-104 — all outside the rows (fail-closed). `probe` records the sweep (form words + lattice) into
`tests/fixtures/sm103a_mufu_x2_nvdisasm.jsonl` (`"arch": "SM103"`); `apply` adds the groups `BF16x2,EX2` and `EX2,F16x2`
to `MUFU_R_R` and `MUFU_R_UR` and the new key `MUFU_R_FI_FI` (entry metadata cloned from `MUFU_R_FI`) with provenance
`mufu-x2-sm103a-2026-11-07`. The sm103a scalar MUFU rows (harvest) are not touched here — the family measurement proper
is a later batch (the SM103 scalar texts equal SM120's, so `re_sm120_conv.py --arch SM103` is the tool for it).

Not measured: silicon. The B300 was busy with a foreign process throughout T-14; the rows are text evidence (nvdisasm 13.0 /
13.1 / 13.3 agree). No compiler word of the B300 corpora (2 145 cubins, 149 934 MUFU words on sm_100 / sm_103) uses either lane.
"""
import argparse
import pathlib
import re
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import nvprobe  # noqa: E402

PROVENANCE = "mufu-x2-sm103a-2026-11-07"
ARCH = "SM103"
CTRL = 0x000fe200 << 96  # the probe's control code (stall 1, yield)
FIXTURE = nvprobe.FIXTURES / "sm103a_mufu_x2_nvdisasm.jsonl"
FORMS = {"R": (0x308, 0), "UR": (0xd08, 1 << 91), "FI": (0x908, 0)}
LANES = {"BF16x2": (0, 1), "F16x2": (3, 0)}  # (half code [73:72], bit 80)
EX2 = 2
NUM = r"[-+]?(\d+(\.\d+)?(e[-+]?\d+)?|INF|QNAN|NAN)\s?"
TEXT = re.compile(r"(@!?P[0-6T] )?MUFU\.EX2\.(BF16x2|F16x2) R(Z|\d+), (-?\|?(R|UR)(Z|\d+)\|?|" + NUM + ", " + NUM + ")")


def word(form, lane, guard=7, rd=4, src=2, fn=EX2, neg=0, abs_=0, hi=0x3c00, lo=0x3c00, extra=0):
    opcode, frame = FORMS[form]
    half, b80 = LANES[lane]
    w = opcode | frame | (guard << 12) | (rd << 16) | (half << 72) | (fn << 74) | (b80 << 80) | extra
    if form == "FI":
        return w | (hi << 48) | (lo << 32)
    return w | (src << 32) | (abs_ << 62) | (neg << 63)


def sweep_words():
    form, lattice = set(), set()
    for f in FORMS:
        for lane in LANES:
            form.add(word(f, lane))
            for guard in (0, 3, 7, 8, 15):
                form.add(word(f, lane, guard=guard))
            for rd in (0, 1, 100, 254, 255):
                form.add(word(f, lane, rd=rd))
            if f == "FI":
                for hi, lo in ((0, 0), (0x3f80, 0x3f80), (0xbc00, 0), (0x7c00, 0xfc00), (0x0001, 0x8000), (0xffff, 0x7fff)):
                    form.add(word(f, lane, hi=hi, lo=lo))
            else:
                for src in (0, 1, 31, 63, 254, 255):
                    form.add(word(f, lane, src=src))
                form.add(word(f, lane, neg=1))
                form.add(word(f, lane, abs_=1))
                form.add(word(f, lane, neg=1, abs_=1))
            # lattice: the other functions (INVALIDn), the lane bits crossed, the frame, the inert bits
            for fn in range(16):
                if fn != EX2:
                    lattice.add(word(f, lane, fn=fn))
            half, b80 = LANES[lane]
            if lane == "BF16x2":
                for h in (1, 2, 3):
                    lattice.add(word(f, lane, extra=h << 72))  # bit 80 with a half code: illegal
            else:
                lattice.add(word(f, lane, extra=1 << 80))  # half 3 with bit 80: illegal
            lattice.add(word(f, lane) ^ (1 << 91))
            for bit in (24, 31, 60, 61, 64, 71, 78, 79, 81, 90, 92, 95):
                if f == "FI" and 32 <= bit <= 63:
                    continue
                lattice.add(word(f, lane, extra=1 << bit))
    lattice -= form
    return [(w, False) for w in sorted(form)] + [(w, True) for w in sorted(lattice)]


def probe(nvdisasm, out=FIXTURE, arch=ARCH, jobs=1):
    rows = nvprobe.probe_words(
        nvdisasm, "mufu_x2", sweep_words(), CTRL, arch=arch, jobs=jobs,
        check_form=lambda w, t: TEXT.fullmatch(t) is not None,
        check_lattice=lambda w, t: t is None or t.startswith("MUFU"),
    )
    nvprobe.write_fixture(out, rows)
    n_form = sum(not r.get("lattice") for r in rows)
    print(f"{n_form} MUFU x2 form words + {len(rows) - n_form} lattice words ({arch}) -> {out}")


def measured_group(form, lane):
    f = [nvprobe.field(12, 4, "guard", 0, PROVENANCE), nvprobe.field(16, 8, "reg", 1, PROVENANCE)]
    if form == "R":
        f += [nvprobe.field(32, 8, "reg", 2, PROVENANCE), nvprobe.field(62, 1, "abs", 2, PROVENANCE),
              nvprobe.field(63, 1, "neg", 2, PROVENANCE)]
    elif form == "UR":
        f += [nvprobe.field(32, 8, "ureg", 2, PROVENANCE), nvprobe.field(62, 1, "abs", 2, PROVENANCE),
              nvprobe.field(63, 1, "neg", 2, PROVENANCE)]
    else:
        kind = "bf16" if lane == "BF16x2" else "f16"
        f += [nvprobe.field(48, 16, kind, 2, PROVENANCE), nvprobe.field(32, 16, kind, 3, PROVENANCE)]
    base = word(form, lane, guard=0, rd=0, src=0, hi=0, lo=0)
    return nvprobe.row(
        base, f, PROVENANCE,
        f"MUFU.EX2.{lane} {form} form measured with nvdisasm 13.3.73 on -b SM103 (B300 host, 2026-11-07, session T-14; "
        "13.0 / 13.1 print the same text): guard [15:12], Rd [23:16] (255 = RZ), "
        + ("Ra [39:32] (255 = RZ), |Ra| 62, -Ra 63; " if form == "R" else
           "URa [39:32] (255 = URZ), |URa| 62, -URa 63, bit 91 = the uniform frame (required); " if form == "UR" else
           "imm_hi [63:48] (printed first) and imm_lo [47:32] as " + ("bf16" if lane == "BF16x2" else "f16") + " literals; ")
        + ("the lane = bit 80 with the half code [73:72] = 0 (bit 80 with a half code is illegal)" if lane == "BF16x2" else
           "the lane = the half code [73:72] = 3 (bit 80 on it is illegal)")
        + "; the function [77:74] admits EX2 only (the other values print INVALIDn, unclaimed). Bit 60 (.H1 of the scalar "
          "half lanes), 24-31, 40-61 (R / UR), 64-71, 78-79, 81-90, 92-104 are text-inert and outside the row (fail-closed). "
          "On -b SM120 / SM100 bit 80 is text-inert and the half code 3 illegal: these lanes exist on sm103a only.",
    )


def apply(table_path):
    path = pathlib.Path(table_path)
    table = nvprobe.load_table(path)
    ins = table["instructions"]
    groups = {"BF16x2": "BF16x2,EX2", "F16x2": "EX2,F16x2"}
    changed = 0
    for form, key in (("R", "MUFU_R_R"), ("UR", "MUFU_R_UR"), ("FI", "MUFU_R_FI_FI")):
        if key not in ins:
            donor = ins["MUFU_R_FI"]
            ins[key] = {k: v for k, v in donor.items() if k != "mod_groups"}
            ins[key]["operand_sig"] = "R_FI_FI"
            ins[key]["mod_groups"] = {}
        for lane, gname in groups.items():
            row = ins[key]["mod_groups"].get(gname)
            if row is not None and row.get("_src") == PROVENANCE:
                continue
            ins[key]["mod_groups"][gname] = measured_group(form, lane)
            changed += 1
    src = table["_meta"].setdefault("provenance", {}).setdefault("sources", {})
    src[PROVENANCE] = {"rows": 6, "kind": "nvdisasm 13.3.73 field probe (-b SM103; 13.0 / 13.1 text-identical)",
                       "date": "2026-11-07", "tool": "tools/probes/re_sm103_mufu_x2.py", "test": "tests/sm103a_mufu_x2.rs"}
    if changed:
        nvprobe.save_table(path, table)
    print(f"{changed} MUFU x2 groups written to {path}")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("probe")
    p.add_argument("--nvdisasm", required=True)
    p.add_argument("--arch", default=ARCH)
    p.add_argument("--jobs", type=int, default=1)
    p.add_argument("--out", type=pathlib.Path, default=FIXTURE)
    a = sub.add_parser("apply")
    a.add_argument("table")
    args = parser.parse_args()
    if args.command == "probe":
        probe(args.nvdisasm, args.out, args.arch, args.jobs)
    else:
        apply(args.table)


if __name__ == "__main__":
    main()

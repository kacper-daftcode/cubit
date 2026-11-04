#!/usr/bin/env python3
"""Measure SM120 `LDL[.size][.LU] Rd, [Ra+URb+imm]` (local load with a register base, a uniform
offset register and an immediate) and add its canonical key `LDL_R_ARURI`.

Found by the GB10-host census of 2026-11-04 (cuBLASLt sm_120 cubins, `lib_120.jsonl`): 95 words
`LDL.64 R14, [R18+UR12+0x20]` had no row - `sm120.json` carried the register form `LDL_R_ARI`
(`[Ra+imm]`) and the uniform form `LDL_R_AURI` (`[URb+imm]`, base RZ baked) but not the three-term
address. The twin for shared memory (`LDS_R_ARURI`) exists.

`probe` sweeps with nvdisasm 13.1 (one word per call) around the census word: guard [15:12], Rd
[23:16], Ra [31:24] (255 = RZ prints the `[URb+imm]` twin and stays with LDL_R_AURI), URb [39:32]
(255 = URZ prints `+URZ`), imm [63:40] (24-bit two's complement: 0x800000 = -0x800000, 0xffffff =
-0x1), the size enum [75:73] (0 U8, 1 S8, 2 U16, 3 S16, 4 plain, 5 .64, 6 .128, 7 INVALID7 -
unclaimed), bit 84 (clear = `.EF`; the rows keep it set like every LDL row), bit 85 (`.LU`), bit 86
(`.NA`, unclaimed), bit 91 (the uniform-operand frame; clear = the `[Ra+imm]` form), bit 76 (the
descriptor form `desc[UR][R+imm]`, unclaimed). Bits 72, 77-83, 87-90, 92-95 are text-inert and stay
outside the rows (fail-closed). `apply` adds `LDL_R_ARURI` with the groups '', '64', '128', 'U8',
'S8', 'U16', 'S16' and their `LU` twins (14 groups), fields guard / reg / sub_r0 / sub_ur1 / sub_imm1
(signed 24-bit), cloning the entry metadata of `LDL_R_AURI`.
"""
import argparse
import pathlib
import re
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import nvprobe  # noqa: E402

PROVENANCE = "ldl-aruri-sm120-2026-11-04"
OPCODE = 0x983
NATIVE_CTRL = 0x0000a200 << 96  # the census word's control code (stall 1, wait mask bits)
KEY = "LDL_R_ARURI"
SIZES = {0: "U8", 1: "S8", 2: "U16", 3: "S16", 4: "", 5: "64", 6: "128"}
FIXTURE = nvprobe.FIXTURES / "sm120_ldl_aruri_nvdisasm.jsonl"
TEXT = re.compile(r"(@!?P[0-6T] )?LDL(\.LU)?(\.(U8|S8|U16|S16|64|128))? R(Z|\d+), \[R\d+\+UR(Z|\d+)(\+-?0x[0-9a-f]+)?\]")


def word(guard=7, rd=14, ra=18, ur=12, imm=0x20, size=5, lu=0, ef=0, hi_extra=0, bit91=1):
    return (OPCODE | (guard << 12) | (rd << 16) | (ra << 24) | (ur << 32) | ((imm & 0xffffff) << 40)
            | (size << 73) | ((0 if ef else 1) << 84) | (lu << 85) | (bit91 << 91) | hi_extra)


def sweep_words():
    form = set()
    for size in SIZES:
        for lu in (0, 1):
            form.add(word(size=size, lu=lu))
            for guard in (0, 3, 7, 8, 15):
                form.add(word(size=size, lu=lu, guard=guard))
            for r in (0, 1, 100, 254, 255):
                form.add(word(size=size, lu=lu, rd=r))
            for r in (0, 1, 100, 254):
                form.add(word(size=size, lu=lu, ra=r))
            for ur in (0, 1, 31, 62, 63, 255):
                form.add(word(size=size, lu=lu, ur=ur))
            for imm in (0, 1, 0x20, 0x7fffff, 0x800000, 0xffffff):
                form.add(word(size=size, lu=lu, imm=imm))
    form.add(word(guard=10, rd=255, ra=0, ur=63, imm=0xfffff0, size=6, lu=1))
    lattice = {word(size=7), word(bit91=0), word(ra=255), word(ef=1), word(hi_extra=1 << 86), word(hi_extra=1 << 76)}
    for bit in [72, *range(77, 84), 87, 88, 89, 90, 92, 93, 94, 95]:
        lattice.add(word(hi_extra=1 << bit))
    lattice -= form
    return [(w, False) for w in sorted(form)] + [(w, True) for w in sorted(lattice)]


def probe(nvdisasm, out=FIXTURE):
    rows = nvprobe.probe_words(
        nvdisasm, "ldl_aruri", sweep_words(), NATIVE_CTRL,
        check_form=lambda w, t: TEXT.fullmatch(t) is not None,
        check_lattice=lambda w, t: t is None or t.startswith("LDL"),
    )
    nvprobe.write_fixture(out, rows)
    n_form = sum(not r.get("lattice") for r in rows)
    print(f"{n_form} LDL Rd, [Ra+UR+imm] words + {len(rows) - n_form} lattice words -> {out}")


def measured_group(size, lu):
    fields = [nvprobe.field(12, 4, "guard", 0, PROVENANCE), nvprobe.field(16, 8, "reg", 1, PROVENANCE),
              nvprobe.field(24, 8, "sub_r0", 2, PROVENANCE), nvprobe.field(32, 8, "sub_ur1", 2, PROVENANCE),
              nvprobe.field(40, 24, "sub_imm1", 2, PROVENANCE)]
    name = SIZES[size]
    return nvprobe.row(
        word(guard=0, rd=0, ra=0, ur=0, imm=0, size=size, lu=lu), fields, PROVENANCE,
        "nvdisasm 13.1 sweeps (2026-11-04, found by the GB10-host census of cuBLASLt sm_120 code): guard[15:12], "
        "Rd[23:16], Ra[31:24] (255 = RZ is the [UR+imm] twin LDL_R_AURI), UR[39:32] (255 = URZ), imm[63:40] "
        f"signed 24-bit; size enum [75:73] = {size} ({name or 'plain'}; 7 = INVALID7, unclaimed), bit 84 set (clear "
        f"= .EF, unclaimed), bit 85 = LU ({'set' if lu else 'clear'}), bit 86 = NA (unclaimed), bit 91 = the uniform "
        "frame, bit 76 = the desc form (unclaimed). Bits 72, 77-83, 87-90, 92-95 are text-inert - outside the row.",
    )


def apply(table_path):
    path = pathlib.Path(table_path)
    table = nvprobe.load_table(path)
    ins = table["instructions"]
    if KEY in ins and all(g.get("_src") == PROVENANCE for g in ins[KEY]["mod_groups"].values()):
        print(f"{KEY}: already measured in {path}")
        return
    donor = ins["LDL_R_AURI"]
    entry = {k: v for k, v in donor.items() if k not in ("mod_groups", "operand_sig", "_o2")}
    entry["operand_sig"] = "R_ARURI"
    groups = {}
    for size, name in SIZES.items():
        for lu in (0, 1):
            gname = ",".join(sorted(x for x in (name, "LU" if lu else "") if x))
            groups[gname] = measured_group(size, lu)
    entry["mod_groups"] = groups
    entry["_src"] = PROVENANCE
    ins[KEY] = entry
    nvprobe.save_table(path, table)
    print(f"{KEY}: added with groups {list(groups)} in {path}")


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

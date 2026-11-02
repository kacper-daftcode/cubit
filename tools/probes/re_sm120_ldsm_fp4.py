#!/usr/bin/env python3
"""Measure SM120 LDSM.U4x16P64TO8 / LDSM.U6x16P32TO8 (FP4 / FP6 shared-memory matrix loads with unpack
to 8-bit lanes, PTX ldmatrix ... .b8x16.b4x16_p64 / .b8x16.b6x16_p32) in the [R+imm] address form
and add the canonical groups.

The table carried the two datatypes only as harvest-era `[UR]` keys (`LDSM.U4x16P64TO8.M816_R_AUR`,
`LDSM.U6x16P32TO8.M816_R_AUR`, no count field). DeepGEMM's grouped FP8 x FP4 MoE GEMMs
(`sm120_m_grouped_fp8_fp4_gemm_contiguous_1d1d`, 576 words over 20 census cubins) load their FP4
B fragments with `LDSM.U4x16P64TO8.M816.2 R66, [R72+0xa000]`.

`probe` sweeps, with nvdisasm 13.1 one word per call: the guard [15:12], Rd [23:16] and base Ra
[31:24] (255 = RZ), the signed 24-bit offset [63:40], the count [73:72] (0 plain, 1 `.2`, 2 `.4`;
3 = INVALID3) and the shape [80:78] (0 M88, 1 MT88, 2 M816, 3 M832, 4 MT1616; 5-7 INVALIDn) for the
datatype codes [77:75] = 5 (U4x16P64TO8) and 6 (U6x16P32TO8); codes 0 (`16`) and 7 (`8`) are the
existing rows, codes 1-4 are unnamed by nvdisasm. Bits 32-39, 64-71, 74, 81-90, 92-95 are text-inert;
bit 91 switches to the `[R+UR]` address (ARURI, not claimed here) - all outside the rows (fail-closed).
`apply` adds to `LDSM_R_ARI` the 30 groups `{,2,,4,} x {U4x16P64TO8,U6x16P32TO8} x {M88,MT88,M816,
M832,MT1616}` with the measured geometry (guard, reg, sub_r0, sub_imm1 - the fields of the
`16,*` rows) and a mask of exactly those fields. Modifier spelling follows the shipped text:
datatype, shape, count (`LDSM.U4x16P64TO8.M816.2`).
"""
import argparse
import pathlib
import re
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import nvprobe  # noqa: E402

PROVENANCE = "ldsm-fp4-fp6-sm120-2026-11-02"
OPCODE = 0x83b
NATIVE_CTRL = 0x0002a200 << 96
KEY = "LDSM_R_ARI"
DTYPES = {5: "U4x16P64TO8", 6: "U6x16P32TO8"}
SHAPES = {0: "M88", 1: "MT88", 2: "M816", 3: "M832", 4: "MT1616"}
COUNTS = {0: "", 1: "2", 2: "4"}
FIXTURE = nvprobe.FIXTURES / "sm120_ldsm_fp4_nvdisasm.jsonl"
TEXT = re.compile(r"(@!?P[0-6T] )?LDSM\.(U4x16P64TO8|U6x16P32TO8)\.(M88|MT88|M816|M832|MT1616)(\.[24])? R(Z|\d+), \[(R(Z|\d+))?(\+?-?0x[0-9a-f]+)?\]")


def word(guard=7, rd=6, ra=4, imm=0, count=1, dtype=5, shape=2, hi_extra=0, bit91=0):
    hi = (count << 72) | (dtype << 75) | (shape << 78) | (bit91 << 91) | hi_extra
    return OPCODE | (guard << 12) | (rd << 16) | (ra << 24) | ((imm & 0xffffff) << 40) | hi


def group_name(count, dtype, shape):
    """mod-group spelling of the canonical table: the modifiers sorted (digits before letters)"""
    return ",".join(sorted(m for m in (COUNTS[count], DTYPES[dtype], SHAPES[shape]) if m))


def sweep_words():
    form = set()
    for dtype in DTYPES:
        for shape in SHAPES:
            for count in COUNTS:
                form.add(word(dtype=dtype, shape=shape, count=count))
        for guard in range(16):
            form.add(word(dtype=dtype, guard=guard))
        for r in (0, 1, 100, 254, 255):
            form.add(word(dtype=dtype, rd=r))
            form.add(word(dtype=dtype, ra=r))
        for imm in (1, 0x10, 0xa000, 0x7fffff, 0x800000, 0xffffff):
            form.add(word(dtype=dtype, imm=imm))
        for bit in range(24):
            form.add(word(dtype=dtype, imm=1 << bit))
        form.add(word(dtype=dtype, guard=9, rd=255, ra=255, imm=0x11c00, count=2, shape=4))
    lattice = set()
    for dtype in DTYPES:
        lattice.add(word(dtype=dtype, count=3))
        for shape in (5, 6, 7):
            lattice.add(word(dtype=dtype, shape=shape))
        lattice.add(word(dtype=dtype, bit91=1))
    for dtype in (1, 2, 3, 4):
        lattice.add(word(dtype=dtype))
    for bit in [*range(32, 40), *range(64, 72), 74, *range(81, 91), 92, 93, 94, 95]:
        lattice.add(word(hi_extra=1 << bit))
    lattice -= form
    return [(w, False) for w in sorted(form)] + [(w, True) for w in sorted(lattice)]


def probe(nvdisasm, out=FIXTURE):
    rows = nvprobe.probe_words(
        nvdisasm, "ldsm_fp4", sweep_words(), NATIVE_CTRL,
        check_form=lambda w, t: TEXT.fullmatch(t) is not None,
        check_lattice=lambda w, t: t is None or t.startswith("LDSM"),
    )
    nvprobe.write_fixture(out, rows)
    n_form = sum(not r.get("lattice") for r in rows)
    print(f"{n_form} LDSM.U4x16P64TO8/U6x16P32TO8 [R+imm] words + {len(rows) - n_form} lattice words -> {out}")


def measured_group(count, dtype, shape):
    fields = [nvprobe.field(12, 4, "guard", 0, PROVENANCE), nvprobe.field(16, 8, "reg", 1, PROVENANCE),
              nvprobe.field(24, 8, "sub_r0", 2, PROVENANCE), nvprobe.field(40, 24, "sub_imm1", 2, PROVENANCE)]
    return nvprobe.row(
        word(guard=0, rd=0, ra=0, imm=0, count=count, dtype=dtype, shape=shape), fields, PROVENANCE,
        "nvdisasm 13.1 sweeps: guard[15:12], Rd[23:16], base register[31:24] (255 = RZ), signed 24-bit "
        f"offset[63:40]; datatype [77:75] = {dtype} ({DTYPES[dtype]}), shape [80:78] = {shape} ({SHAPES[shape]}), "
        f"count [73:72] = {count} ({COUNTS[count] or 'x1'}; 3 = INVALID3). Shapes 5-7 (INVALIDn), datatype codes "
        "1-4 (unnamed), bit 91 ([R+UR] address) and the text-inert bits 32-39, 64-71, 74, 81-90, 92-95 are "
        "outside the row (fail-closed). PTX ldmatrix .b8x16." + ("b4x16_p64" if dtype == 5 else "b6x16_p32") + ".",
    )


def apply(table_path):
    path = pathlib.Path(table_path)
    table = nvprobe.load_table(path)
    entry = table["instructions"][KEY]
    assert entry["base_op"] == "LDSM" and entry["operand_sig"] == "R_ARI"
    added = []
    for dtype in DTYPES:
        for shape in SHAPES:
            for count in COUNTS:
                name = group_name(count, dtype, shape)
                if entry["mod_groups"].get(name, {}).get("_src") == PROVENANCE:
                    continue
                assert name not in entry["mod_groups"], f"unexpected existing group {name}"
                entry["mod_groups"][name] = measured_group(count, dtype, shape)
                added.append(name)
    if not added:
        print(f"{KEY}: already measured in {path}")
        return
    nvprobe.save_table(path, table)
    print(f"{KEY}: added {len(added)} groups ({added[0]} .. {added[-1]}) in {path}")


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

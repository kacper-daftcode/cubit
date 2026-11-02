#!/usr/bin/env python3
"""Measure SM120 UTMASTG.<n>D [UR], [UR] (bulk tensor store, PTX cp.async.bulk.tensor.<n>d.global.shared)
and add the missing dimension groups to the canonical row.

The table carried `UTMASTG_AURI_AURI` / `3D` only (harvest era). DeepGEMM's grouped FP8 x FP4 MoE
GEMMs (`sm120_m_grouped_fp8_fp4_gemm_contiguous_1d1d`, 36 words over 20 cubins of the census)
store their 2-D tiles with `UTMASTG.2D [UR8], [UR14]`, which no row matched.

`probe` sweeps, with nvdisasm 13.1 one word per call: the dimension code [81:79] (0 = 1D,
1 = 2D, 2 = 3D, 3 = 4D, 4 = 5D, 5..7 = INVALIDn), the uniform guard [15:12] (@UP0..@UP6, 7 =
none, @!UP0..@!UP6, 15 = @!UPT), the tensor-map UR [39:32] (first operand, 255 = URZ) and the
shared-memory UR [31:24] (second operand, 255 = URZ). The lattice stays outside the rows: bit 76
adds a `desc[UR]` operand, bit 82 prints `.IM2COL`, bit 83 `.SCATTER4`, bit 91 is required
(clearing it is illegal) and bits 16-23, 40-63, 72-75, 77, 78, 84-90, 92-95 are text-inert.
`apply` adds the `1D`, `2D`, `4D` and `5D` groups with the measured 3D geometry (guard, two
`sub_ur0` fields) and a fail-closed mask of exactly those fields.
"""
import argparse
import pathlib
import re
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import nvprobe  # noqa: E402

PROVENANCE = "utmastg-dims-sm120-2026-11-02"
OPCODE = 0x3b5
NATIVE_CTRL = 0x0003e400 << 96
KEY = "UTMASTG_AURI_AURI"
DIMS = {0: "1D", 1: "2D", 2: "3D", 3: "4D", 4: "5D"}
FIXTURE = nvprobe.FIXTURES / "sm120_utmastg_dims_nvdisasm.jsonl"
TEXT = re.compile(r"(@!?UP[0-6T] )?UTMASTG\.[1-5]D \[UR(Z|\d+)\], \[UR(Z|\d+)\]")


def word(guard=7, tmap=4, smem=14, dim=1, hi_extra=0, bit91=1):
    return OPCODE | (guard << 12) | (smem << 24) | (tmap << 32) | (dim << 79) | (bit91 << 91) | hi_extra


def sweep_words():
    form = set()
    for dim in DIMS:
        form.add(word(dim=dim))
        for guard in range(16):
            form.add(word(dim=dim, guard=guard))
        for ur in (0, 1, 31, 62, 63, 255):
            form.add(word(dim=dim, tmap=ur))
            form.add(word(dim=dim, smem=ur))
    form.add(word(guard=8, tmap=255, smem=0, dim=4))
    lattice = set()
    for dim in (5, 6, 7):
        lattice.add(word(dim=dim))
    lattice.add(word(bit91=0))
    for bit in [*range(16, 24), 40, 48, 56, 63, 72, 73, 74, 75, 76, 77, 78, 82, 83, 84, 85, 86, 87, 88, 89, 90, 92, 93, 94, 95]:
        lattice.add(word(hi_extra=1 << bit))
    lattice -= form
    return [(w, False) for w in sorted(form)] + [(w, True) for w in sorted(lattice)]


def probe(nvdisasm, out=FIXTURE):
    rows = nvprobe.probe_words(
        nvdisasm, "utmastg_dims", sweep_words(), NATIVE_CTRL,
        check_form=lambda w, t: TEXT.fullmatch(t) is not None,
        check_lattice=lambda w, t: t is None or t.startswith("UTMASTG"),
    )
    nvprobe.write_fixture(out, rows)
    n_form = sum(not r.get("lattice") for r in rows)
    print(f"{n_form} UTMASTG.nD [UR], [UR] words + {len(rows) - n_form} lattice words -> {out}")


def measured_group(dim):
    fields = [nvprobe.field(12, 4, "guard", 0, PROVENANCE), nvprobe.field(32, 8, "sub_ur0", 1, PROVENANCE),
              nvprobe.field(24, 8, "sub_ur0", 2, PROVENANCE)]
    return nvprobe.row(
        word(guard=0, tmap=0, smem=0, dim=dim), fields, PROVENANCE,
        f"nvdisasm 13.1 sweeps: uniform guard[15:12], tensor-map UR[39:32] (255 = URZ), shared UR[31:24] "
        f"(255 = URZ); dimension code [81:79] = {dim} ({DIMS[dim]}; 0 = 1D .. 4 = 5D, 5-7 INVALIDn); bit 91 "
        f"required. Bit 76 (desc[UR] operand), 82 (.IM2COL), 83 (.SCATTER4) and the text-inert bits 16-23, "
        f"40-63, 72-75, 77, 78, 84-90, 92-95 are outside the row (fail-closed). Same geometry as the "
        f"harvest-era 3D group. PTX cp.async.bulk.tensor.{DIMS[dim].lower()}.global.shared::cta.",
    )


def apply(table_path):
    path = pathlib.Path(table_path)
    table = nvprobe.load_table(path)
    entry = table["instructions"][KEY]
    assert entry["base_op"] == "UTMASTG" and entry["operand_sig"] == "AURI_AURI"
    added = []
    for dim, name in DIMS.items():
        if name in entry["mod_groups"] and entry["mod_groups"][name].get("_src") != PROVENANCE:
            # the harvest 3D row: same fields; keep it, only record what was measured
            if name == "3D":
                old = entry["mod_groups"][name]
                assert int(old["and_base"], 16) == word(guard=0, tmap=0, smem=0, dim=2)
                continue
        if entry["mod_groups"].get(name, {}).get("_src") == PROVENANCE:
            continue
        entry["mod_groups"][name] = measured_group(dim)
        added.append(name)
    if not added:
        print(f"{KEY}: already measured in {path}")
        return
    nvprobe.save_table(path, table)
    print(f"{KEY}: added groups {added} in {path}")


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

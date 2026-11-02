#!/usr/bin/env python3
"""Measure SM120 HMUL2[.BF16_V2][.FMZ][.SAT][.FTZ] Rd, Ra, imm_hi, imm_lo (packed half-precision multiply
by two 16-bit immediates, opcode 0x832) and add its canonical key.

The table had HMUL2 with a register (0x232) or uniform-register (0xc32) second source but not the
packed-immediate form. FlashInfer's `cake_sparse_mla_dsv41_mixed` kernels (12 664 words over 41 census
cubins, the single largest gap) scale their BF16 fragments with `HMUL2.BF16_V2 R112, R44, 1, 1` and
`HMUL2.BF16_V2 R105, R150, 5.19229685853482762853e+33, 5.19229685853482762853e+33` (0x3f80 / 0x7780 in
both halves).

`probe` sweeps, with nvdisasm 13.1 one word per call: the guard [15:12], Rd [23:16] and Ra [31:24]
(255 = RZ), Ra's sign (bit 72 `-Ra`), absolute value (bit 73 `|Ra|`) and half selector ([75:74]:
2 = `.H0_H0`, 3 = `.H1_H1`; 1 prints INVALID1), the high immediate [63:48] (printed first) and the low
immediate [47:32] (printed second; f16 without bit 85, bf16 with `.BF16_V2` = bit 85, incl. -0.0, +INF,
+QNAN and denormals), and the modifier bits 76 `.FMZ`, 77 `.SAT`, 80 `.FTZ`. The lattice stays outside
the rows: bit 78 (prints `.INVALID3` and drops the datatype), bit 91 (illegal), the text-inert bits
64-71, 79, 81-84, 86-90, 92-95, and the reuse window [124:122] (printed by nothing). `apply` adds the key
`HMUL2_R_R_FI_FI` with twelve groups ({'', BF16_V2} x {'', FMZ, SAT, FMZ,SAT, FTZ, FTZ,SAT} - the set of
`HMUL2_R_R_R`), fields guard / reg / reg+neg+abs+hsel / f16|bf16 hi / f16|bf16 lo (+ reuse@122 for Ra)
and a mask of exactly those fields, cloning the entry metadata of `HMUL2_R_R_R`.
"""
import argparse
import pathlib
import re
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import nvprobe  # noqa: E402

PROVENANCE = "hmul2-imm-sm120-2026-11-02"
OPCODE = 0x832
NATIVE_CTRL = 0x000fc400 << 96
KEY = "HMUL2_R_R_FI_FI"
MODS = {0: "", 1 << 76: "FMZ", 1 << 77: "SAT", (1 << 76) | (1 << 77): "FMZ,SAT", 1 << 80: "FTZ", (1 << 80) | (1 << 77): "FTZ,SAT"}
FIXTURE = nvprobe.FIXTURES / "sm120_hmul2_imm_nvdisasm.jsonl"
NUM = r"[-+]?(\d+(\.\d+)?(e[-+]\d+)?|INF|QNAN) ?"
TEXT = re.compile(r"(@!?P[0-6T] )?HMUL2(\.(BF16_V2|FMZ|SAT|FTZ))* R(Z|\d+), -?\|?R(Z|\d+)\|?(\.H[01]_H[01])?, " + NUM + ", " + NUM)


def word(guard=7, rd=11, ra=11, hi=0x3f80, lo=0x3f80, bf16=1, mods=0, neg=0, abs_=0, hsel=0, hi_extra=0):
    top = (bf16 << 85) | mods | (neg << 72) | (abs_ << 73) | (hsel << 74) | hi_extra
    return OPCODE | (guard << 12) | (rd << 16) | (ra << 24) | (lo << 32) | (hi << 48) | top


def sweep_words():
    form = set()
    for bf16 in (0, 1):
        for mods in MODS:
            form.add(word(bf16=bf16, mods=mods))
            form.add(word(bf16=bf16, mods=mods, hi=0x4000, lo=0xc000))
        for guard in range(16):
            form.add(word(bf16=bf16, guard=guard))
        for r in (0, 1, 100, 254, 255):
            form.add(word(bf16=bf16, rd=r))
            form.add(word(bf16=bf16, ra=r))
        for hi, lo in [(0x3f80, 0x0000), (0x0000, 0x3f80), (0xbf80, 0x3f80), (0x7f80, 0x7fc0), (0x0001, 0x8000),
                       (0x7780, 0x7780), (0x3c00, 0x3c00), (0xffff, 0x0001), (0x5640, 0x3e80)]:
            form.add(word(bf16=bf16, hi=hi, lo=lo))
        for bit in range(32):
            form.add(word(bf16=bf16, hi=(1 << bit) >> 16, lo=(1 << bit) & 0xffff))
        form.add(word(bf16=bf16, neg=1))
        form.add(word(bf16=bf16, abs_=1))
        form.add(word(bf16=bf16, neg=1, abs_=1))
        form.add(word(bf16=bf16, hsel=2))
        form.add(word(bf16=bf16, hsel=3))
        form.add(word(bf16=bf16, neg=1, hsel=3))
    form.add(word(guard=12, rd=255, ra=0, hi=0x7780, lo=0x3f80, mods=(1 << 76) | (1 << 77), abs_=1, hsel=2))
    lattice = {word(hsel=1), word(hi_extra=1 << 78), word(bf16=0, hi_extra=1 << 78), word(hi_extra=1 << 91)}
    for bit in [*range(64, 72), 79, 81, 82, 83, 84, 86, 87, 88, 89, 90, 92, 93, 94, 95, 122, 123, 124]:
        lattice.add(word(hi_extra=1 << bit))
    lattice -= form
    return [(w, False) for w in sorted(form)] + [(w, True) for w in sorted(lattice)]


def probe(nvdisasm, out=FIXTURE):
    rows = nvprobe.probe_words(
        nvdisasm, "hmul2_imm", sweep_words(), NATIVE_CTRL,
        check_form=lambda w, t: TEXT.fullmatch(t) is not None,
        check_lattice=lambda w, t: t is None or t.startswith("HMUL2"),
    )
    nvprobe.write_fixture(out, rows)
    n_form = sum(not r.get("lattice") for r in rows)
    print(f"{n_form} HMUL2 Rd, Ra, imm, imm words + {len(rows) - n_form} lattice words -> {out}")


def measured_group(bf16, mods):
    ext = "bf16" if bf16 else "f16"
    fields = [nvprobe.field(12, 4, "guard", 0, PROVENANCE), nvprobe.field(16, 8, "reg", 1, PROVENANCE),
              nvprobe.field(24, 8, "reg", 2, PROVENANCE), nvprobe.field(122, 1, "reuse", 2, PROVENANCE),
              nvprobe.field(72, 1, "neg", 2, PROVENANCE), nvprobe.field(73, 1, "abs", 2, PROVENANCE),
              nvprobe.field(74, 2, "hsel", 2, PROVENANCE), nvprobe.field(48, 16, ext, 3, PROVENANCE),
              nvprobe.field(32, 16, ext, 4, PROVENANCE)]
    name = ",".join(x for x in (["BF16_V2"] if bf16 else []) + ([MODS[mods]] if MODS[mods] else []))
    return name, nvprobe.row(
        word(guard=0, rd=0, ra=0, hi=0, lo=0, bf16=bf16, mods=mods), fields, PROVENANCE,
        "nvdisasm 13.1 sweeps: guard[15:12], Rd[23:16], Ra[31:24] (255 = RZ) with -Ra (bit 72), |Ra| (bit 73) "
        "and the half selector [75:74] (2 = .H0_H0, 3 = .H1_H1; 1 = INVALID1, unclaimed), high immediate "
        f"[63:48] (printed first) and low immediate [47:32] as {ext}; opcode 0x832, bit 85 = {bf16} "
        f"({'.BF16_V2' if bf16 else 'f16'}), modifiers {MODS[mods] or 'none'} (76 FMZ, 77 SAT, 80 FTZ). Bit 78 "
        "(.INVALID3), bit 91 (illegal) and the text-inert bits 64-71, 79, 81-84, 86-90, 92-95 are outside the "
        "row (fail-closed). The packed-immediate twin of HMUL2_R_R_R (0x232) / HMUL2_R_R_UR (0xc32).",
    )


def apply(table_path):
    path = pathlib.Path(table_path)
    table = nvprobe.load_table(path)
    ins = table["instructions"]
    if KEY in ins and all(g.get("_src") == PROVENANCE for g in ins[KEY]["mod_groups"].values()):
        print(f"{KEY}: already measured in {path}")
        return
    donor = ins["HMUL2_R_R_R"]
    entry = {k: v for k, v in donor.items() if k not in ("mod_groups", "operand_sig", "_bug226d")}
    entry["operand_sig"] = "R_R_FI_FI"
    groups = {}
    for bf16 in (0, 1):
        for mods in MODS:
            name, g = measured_group(bf16, mods)
            groups[name] = g
    entry["mod_groups"] = groups
    entry["_src"] = PROVENANCE
    ins[KEY] = entry
    nvprobe.save_table(path, table)
    print(f"{KEY}: added with {len(groups)} groups in {path}")


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

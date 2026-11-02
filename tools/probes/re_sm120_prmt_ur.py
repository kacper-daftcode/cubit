#!/usr/bin/env python3
"""Measure SM120 PRMT[.mode] Rd, Ra, URsel, Rc (byte permute with the selector in a uniform register)
and add its canonical key.

The table had PRMT with a register (0x216), an immediate (0x816) and a uniform *fourth* operand
(`PRMT_R_R_R_UR`, 0xe16) but not the uniform *selector* form, opcode 0xc16. FlashInfer's
`cake_sparse_mla_dsv41_mixed` kernels (544 words over 41 census cubins) permute with
`PRMT R53, R65, UR7, R64`.

`probe` sweeps, with nvdisasm 13.1 one word per call: the guard [15:12] (@P0..@P6, 7 = none,
@!P0..@!P6, 15 = @!PT), Rd [23:16], Ra [31:24], Rc [71:64] (255 = RZ each), the selector UR [39:32]
(255 = URZ) and the mode [74:72] (0 = plain, 1 F4E, 2 B4E, 3 RC8, 4 ECL, 5 ECR, 6 RC16; 7 prints
INVALID7 and stays unclaimed). Bit 91 is required (the uniform-operand frame; clearing it is
illegal); bits 40-63, 75-90, 92-95 are text-inert and stay outside the rows (fail-closed). `apply`
adds the key `PRMT_R_R_UR_R` with the seven mode groups, fields guard / reg / reg / ureg / reg and a
mask of exactly those fields, cloning the entry metadata of `PRMT_R_R_R_R`.
"""
import argparse
import pathlib
import re
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import nvprobe  # noqa: E402

PROVENANCE = "prmt-ur-sm120-2026-11-02"
OPCODE = 0xc16
NATIVE_CTRL = 0x000fc400 << 96
KEY = "PRMT_R_R_UR_R"
MODES = {0: "", 1: "F4E", 2: "B4E", 3: "RC8", 4: "ECL", 5: "ECR", 6: "RC16"}
FIXTURE = nvprobe.FIXTURES / "sm120_prmt_ur_nvdisasm.jsonl"
TEXT = re.compile(r"(@!?P[0-6T] )?PRMT(\.(F4E|B4E|RC8|ECL|ECR|RC16))? R(Z|\d+), R(Z|\d+), UR(Z|\d+), R(Z|\d+)")


def word(guard=7, rd=53, ra=65, ur=7, rc=64, mode=0, hi_extra=0, bit91=1):
    return OPCODE | (guard << 12) | (rd << 16) | (ra << 24) | (ur << 32) | (rc << 64) | (mode << 72) | (bit91 << 91) | hi_extra


def sweep_words():
    form = set()
    for mode in MODES:
        form.add(word(mode=mode))
        for guard in range(16):
            form.add(word(mode=mode, guard=guard))
        for r in (0, 1, 100, 254, 255):
            form.add(word(mode=mode, rd=r))
            form.add(word(mode=mode, ra=r))
            form.add(word(mode=mode, rc=r))
        for ur in (0, 1, 31, 62, 63, 255):
            form.add(word(mode=mode, ur=ur))
    form.add(word(guard=10, rd=255, ra=0, ur=63, rc=255, mode=6))
    lattice = {word(mode=7), word(bit91=0)}
    for bit in [40, 48, 56, 63, *range(75, 91), 92, 93, 94, 95]:
        lattice.add(word(hi_extra=1 << bit))
    lattice -= form
    return [(w, False) for w in sorted(form)] + [(w, True) for w in sorted(lattice)]


def probe(nvdisasm, out=FIXTURE):
    rows = nvprobe.probe_words(
        nvdisasm, "prmt_ur", sweep_words(), NATIVE_CTRL,
        check_form=lambda w, t: TEXT.fullmatch(t) is not None,
        check_lattice=lambda w, t: t is None or t.startswith("PRMT"),
    )
    nvprobe.write_fixture(out, rows)
    n_form = sum(not r.get("lattice") for r in rows)
    print(f"{n_form} PRMT Rd, Ra, UR, Rc words + {len(rows) - n_form} lattice words -> {out}")


def measured_group(mode):
    fields = [nvprobe.field(12, 4, "guard", 0, PROVENANCE), nvprobe.field(16, 8, "reg", 1, PROVENANCE),
              nvprobe.field(24, 8, "reg", 2, PROVENANCE), nvprobe.field(32, 8, "ureg", 3, PROVENANCE),
              nvprobe.field(64, 8, "reg", 4, PROVENANCE)]
    return nvprobe.row(
        word(guard=0, rd=0, ra=0, ur=0, rc=0, mode=mode), fields, PROVENANCE,
        "nvdisasm 13.1 sweeps: guard[15:12], Rd[23:16], Ra[31:24], selector UR[39:32] (255 = URZ), "
        f"Rc[71:64] (255 = RZ); opcode 0xc16 with bit 91 (required), mode [74:72] = {mode} "
        f"({MODES[mode] or 'plain'}; 7 = INVALID7, unclaimed). Bits 40-63, 75-90, 92-95 are text-inert - "
        "outside the row (fail-closed). The uniform-selector twin of PRMT_R_R_R_R (0x216) / PRMT_R_R_II_R (0x816).",
    )


def apply(table_path):
    path = pathlib.Path(table_path)
    table = nvprobe.load_table(path)
    ins = table["instructions"]
    if KEY in ins and all(g.get("_src") == PROVENANCE for g in ins[KEY]["mod_groups"].values()):
        print(f"{KEY}: already measured in {path}")
        return
    donor = ins["PRMT_R_R_R_R"]
    entry = {k: v for k, v in donor.items() if k not in ("mod_groups", "operand_sig", "_o2")}
    entry["operand_sig"] = "R_R_UR_R"
    entry["mod_groups"] = {MODES[m]: measured_group(m) for m in MODES}
    entry["_src"] = PROVENANCE
    ins[KEY] = entry
    nvprobe.save_table(path, table)
    print(f"{KEY}: added with groups {list(MODES.values())} in {path}")


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

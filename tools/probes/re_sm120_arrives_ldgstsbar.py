#!/usr/bin/env python3
"""Measure SM120 ARRIVES.LDGSTSBAR.64[.ARVCNT] [R+UR+imm] (arrive on a shared-memory mbarrier with the
cp.async count, PTX cp.async.mbarrier.arrive[.noinc].shared.b64) and add its canonical row.

The table had no ARRIVES row at all. FlashInfer's `cake_sparse_mla_dsv41_mixed` kernels (297 words over
the 41 census cubins) arrive on their LDGSTS pipeline barriers with `ARRIVES.LDGSTSBAR.64.ARVCNT [UR12]`.

`probe` sweeps, with nvdisasm 13.1 one word per call: the guard [15:12] (@P0..@P6, 7 = none,
@!P0..@!P6, 15 = @!PT), the base register [31:24] (255 = RZ, printed `[URn]`; otherwise `[Rn+URn]`),
the uniform register [71:64] (255 = URZ), the signed 24-bit offset [63:40] (elided at 0,
`+0x7fffff`, `+-0x800000`) and the ARVCNT flag (bit 76: set = `.ARVCNT`, clear = plain). The lattice
stays outside the rows: opcode 0x9b0 needs bit 91 (the register-plus-uniform address frame; without
it, and 0x3b0 without it, the word is illegal), bit 72 is the barrier kind (0 = LDGSTSBAR, 1 =
`???1`), [75:73] the size (5 = `.64`; 1/4/7 print `???n`), bit 77 with 76 prints `.INVALID3`, and bits
16-23, 32-39, 78-90, 92-95 are text-inert. `apply` adds the key `ARRIVES_ARURI` with the groups
`64,ARVCNT,LDGSTSBAR` and `64,LDGSTSBAR` (fields: guard, base R, UR, offset; fail-closed mask).
"""
import argparse
import pathlib
import re
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import nvprobe  # noqa: E402

PROVENANCE = "arrives-ldgstsbar-sm120-2026-11-02"
OPCODE = 0x9b0
NATIVE_CTRL = 0x000fe200 << 96
KEY = "ARRIVES_ARURI"
GROUPS = {1: "64,ARVCNT,LDGSTSBAR", 0: "64,LDGSTSBAR"}
FIXTURE = nvprobe.FIXTURES / "sm120_arrives_ldgstsbar_nvdisasm.jsonl"
TEXT = re.compile(r"(@!?P[0-6T] )?ARRIVES\.LDGSTSBAR\.64(\.ARVCNT)? \[(R\d+\+)?UR(Z|\d+)(\+-?0x[0-9a-f]+)?\]")


def word(guard=7, base=255, ur=4, imm=0, arvcnt=1, kind=0, size=5, hi_extra=0, opcode=OPCODE, bit91=1):
    hi = (bit91 << 91) | (arvcnt << 76) | (size << 73) | (kind << 72) | hi_extra
    return opcode | (guard << 12) | (base << 24) | ((imm & 0xffffff) << 40) | (ur << 64) | hi


def sweep_words():
    form = set()
    for arvcnt in (0, 1):
        form.add(word(arvcnt=arvcnt))
        for guard in range(16):
            form.add(word(arvcnt=arvcnt, guard=guard))
        for base in (0, 1, 100, 157, 254, 255):
            form.add(word(arvcnt=arvcnt, base=base))
        for ur in (0, 1, 31, 62, 63, 255):
            form.add(word(arvcnt=arvcnt, ur=ur))
        for imm in (0, 1, 0x10, 0x7fffff, 0x800000, 0xffffff):
            form.add(word(arvcnt=arvcnt, imm=imm))
        for bit in range(24):
            form.add(word(arvcnt=arvcnt, imm=1 << bit))
        form.add(word(arvcnt=arvcnt, guard=9, base=3, ur=63, imm=0x15100))
    lattice = set()
    lattice.add(word(bit91=0))
    lattice.add(word(opcode=0x3b0, bit91=0))
    lattice.add(word(kind=1))
    for size in range(8):
        lattice.add(word(size=size))
    lattice.add(word(hi_extra=1 << 77))
    lattice.add(word(arvcnt=0, hi_extra=1 << 77))
    for bit in [*range(16, 24), *range(32, 40), *range(78, 91), 92, 93, 94, 95]:
        lattice.add(word(hi_extra=1 << bit))
    lattice -= form
    return [(w, False) for w in sorted(form)] + [(w, True) for w in sorted(lattice)]


def probe(nvdisasm, out=FIXTURE):
    rows = nvprobe.probe_words(
        nvdisasm, "arrives", sweep_words(), NATIVE_CTRL,
        check_form=lambda w, t: TEXT.fullmatch(t) is not None,
        check_lattice=lambda w, t: t is None or t.startswith("ARRIVES"),
    )
    nvprobe.write_fixture(out, rows)
    n_form = sum(not r.get("lattice") for r in rows)
    print(f"{n_form} ARRIVES.LDGSTSBAR.64[.ARVCNT] words + {len(rows) - n_form} lattice words -> {out}")


def measured_group(arvcnt):
    fields = [nvprobe.field(12, 4, "guard", 0, PROVENANCE), nvprobe.field(24, 8, "sub_r0", 1, PROVENANCE),
              nvprobe.field(64, 8, "sub_ur1", 1, PROVENANCE), nvprobe.field(40, 24, "sub_imm2", 1, PROVENANCE)]
    return nvprobe.row(
        word(guard=0, base=0, ur=0, imm=0, arvcnt=arvcnt), fields, PROVENANCE,
        "nvdisasm 13.1 sweeps: guard[15:12], base register[31:24] (255 = RZ, printed [UR+imm]), uniform "
        "register[71:64] (255 = URZ), signed 24-bit offset[63:40] (elided at 0); opcode 0x9b0 with bit 91 "
        "(required: the [R+UR+imm] frame), bit 72 = 0 (LDGSTSBAR; 1 prints ???1), [75:73] = 5 (.64; other "
        f"codes print ???n), bit 76 = {arvcnt} ({'.ARVCNT' if arvcnt else 'no .ARVCNT'}; bit 77 with 76 = "
        ".INVALID3). Bits 16-23, 32-39, 78-90, 92-95 are text-inert - all outside the row (fail-closed). "
        "PTX cp.async.mbarrier.arrive" + ("" if arvcnt else ".noinc") + ".shared.b64.",
    )


def apply(table_path):
    path = pathlib.Path(table_path)
    table = nvprobe.load_table(path)
    ins = table["instructions"]
    if KEY in ins and all(g.get("_src") == PROVENANCE for g in ins[KEY]["mod_groups"].values()):
        print(f"{KEY}: already measured in {path}")
        return
    # Entry metadata cloned from the measured UBLKPF key (uniform-datapath bulk
    # op, ctrl_class alu_simple): the 297 shipped words all carry the plain
    # `stall 1, yield` control word, so the op is scheduled like a simple ALU
    # instruction - an assumption about the *schedule*, not the encoding
    # (docs/KNOWN_ISSUES.md lists it for the silicon check).
    donor = ins["UBLKPF_AURI_UR"]
    entry = {k: v for k, v in donor.items() if k not in ("mod_groups", "operand_sig", "base_op", "_src")}
    entry["base_op"] = "ARRIVES"
    entry["operand_sig"] = "ARURI"
    entry["mod_groups"] = {GROUPS[a]: measured_group(a) for a in (1, 0)}
    entry["_src"] = PROVENANCE
    ins[KEY] = entry
    nvprobe.save_table(path, table)
    print(f"{KEY}: added with groups {list(GROUPS.values())} in {path}")


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

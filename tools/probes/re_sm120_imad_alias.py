#!/usr/bin/env python3
"""Measure nvdisasm's `IMAD.MOV` / `IMAD.IADD` / `IMAD.SHL` display aliases on SM120 and rebuild the
alias-named harvest groups of the IMAD rows.

The dynamic audit (2026-11-02..04) listed 12 IMAD rows whose words nvdisasm names `IMAD.MOV` /
`IMAD.SHL` while cubit printed plain `IMAD`, and whose alias-named harvest groups (`MOV`, `MOV,U32`,
`IADD`, `IADD,U32`, `SHL,U32`) baked one sample's operands and mapped the Ra token onto the Rb field
(`IMAD.MOV.U32 R4, RZ, R14, 0x10` printed as `R4, R14, R14, 0x10`). `probe` sweeps, with nvdisasm 13.1
one word per call, the four-operand forms `R_R_R_R` (0x224), `R_R_R_II` (0x424), `R_R_II_R` (0x824)
and `R_R_R_UR` (0xe24) in the signed and `.U32` (bit 73 clear) flavours over a in {RZ, R6}, b in
{RZ, R14} or imm in {0, 1, 2, 3, 0x10, 0x80000000}, c in {RZ, R10} or imm, plus the guard. The law:

  * `.MOV`  when the product is identically zero or one times a: a = RZ, or b = RZ, or b = imm 0, or
            b = imm 1 with c = RZ - for a register or immediate c; a UR c never takes an alias;
  * `.IADD` when b = imm 1 and c is a register other than RZ (a + c);
  * `.SHL`  when b is an immediate power of two from 2 to 2^30 and c = RZ (a << log2 b);
  * plain IMAD otherwise.

The alias is a print of the operands, not an encoding: `apply` deletes the alias-named groups, adds
the missing `U32` twins of `IMAD_R_R_R_II` / `IMAD_R_R_R_R` (the plain row with bit 73 clear), and
cubit's printer / encoder apply the law (`tests/sm120_imad_alias.rs`).
"""
import argparse
import itertools
import pathlib
import re
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import nvprobe  # noqa: E402

PROVENANCE = "imad-alias-sm120-2026-11-04"
NATIVE_CTRL = 0x000fe200 << 96
FIXTURE = nvprobe.FIXTURES / "sm120_imad_alias_nvdisasm.jsonl"
TEXT = re.compile(r"(@!?P[0-6T] )?IMAD(\.(MOV|IADD|SHL))?(\.U32)? R(Z|\d+), R(Z|\d+), (R(Z|\d+)|-?0x[0-9a-f]+), (R(Z|\d+)|-?0x[0-9a-f]+|UR(Z|\d+))")
# form -> opcode low 12 bits; operand slots: a@[31:24]; R_R_R_R b@[39:32] c@[71:64]; R_R_R_II b@[71:64]
# imm@[63:32]; R_R_II_R imm@[63:32] c@[71:64]; R_R_R_UR b@[71:64] UR@[39:32] with the bit-91 frame.
FORMS = {"R_R_R_R": 0x224, "R_R_R_II": 0x424, "R_R_II_R": 0x824, "R_R_R_UR": 0xe24}
PRED_FRAME = 0x078e0000 << 64  # the cout/cin predicate slots at PT that every 4-operand IMAD word carries
IMMS = (0, 1, 2, 3, 0x10, 0x80000000)


def word(form, a, b, c, u32=False, guard=7, rd=4):
    w = FORMS[form] | (guard << 12) | (rd << 16) | (a << 24) | PRED_FRAME
    if not u32:
        w |= 1 << 73
    if form == "R_R_R_R":
        w |= (b << 32) | (c << 64)
    elif form == "R_R_R_II":
        w |= (b << 64) | ((c & 0xffffffff) << 32)
    elif form == "R_R_II_R":
        w |= ((b & 0xffffffff) << 32) | (c << 64)
    else:
        w |= (b << 64) | (c << 32) | (1 << 91)
    return w


def sweep_words():
    form = set()
    for f in FORMS:
        for u32 in (False, True):
            a_vals = (0xff, 6)
            b_vals = IMMS if f == "R_R_II_R" else (0xff, 14)
            c_vals = IMMS if f == "R_R_R_II" else ((0xff, 8) if f == "R_R_R_UR" else (0xff, 10))
            for a, b, c in itertools.product(a_vals, b_vals, c_vals):
                form.add(word(f, a, b, c, u32))
            form.add(word(f, 0xff, b_vals[0], c_vals[0], u32, guard=0))
            form.add(word(f, 0xff, b_vals[0], c_vals[0], u32, guard=15))
    return [(w, False) for w in sorted(form)]


def probe(nvdisasm, out=FIXTURE):
    rows = nvprobe.probe_words(nvdisasm, "imad_alias", sweep_words(), NATIVE_CTRL,
                               check_form=lambda w, t: TEXT.fullmatch(t) is not None)
    nvprobe.write_fixture(out, rows)
    print(f"{len(rows)} IMAD words -> {out}")


def apply(table_path):
    path = pathlib.Path(table_path)
    table = nvprobe.load_table(path)
    ins = table["instructions"]
    deleted = []
    added = []
    for key in ("IMAD_R_R_R_R", "IMAD_R_R_R_II", "IMAD_R_R_II_R", "IMAD_R_R_R_UR", "IMAD_R_R_UR_R"):
        e = ins.get(key)
        if not e:
            continue
        groups = e["mod_groups"]
        for g in list(groups):
            mods = g.split(",") if g else []
            if any(m in ("MOV", "SHL", "IADD") for m in mods):
                del groups[g]
                deleted.append(f"{key}:{g}")
        # a U32 twin whose fields map two operand tokens onto one window (the harvest's
        # `IMAD.U32 Rd, RZ, RZ, URx` shape with Ra baked) is rebuilt from the plain row
        degenerate = "U32" in groups and len({f["shift"] for f in groups["U32"]["fields"]}) < len(groups["U32"]["fields"])
        if ("U32" not in groups or degenerate) and "" in groups:
            plain = groups[""]
            twin = {k: v for k, v in plain.items()}
            ab = int(plain["and_base"], 16) & ~(1 << 73)
            twin["and_base"] = f"0x{ab:032x}"
            twin["count"] = groups["U32"].get("count") if degenerate else None
            twin["_src"] = PROVENANCE
            twin["_note"] = ("U32 twin of the plain row (bit 73 clear), 2026-11-04: the harvest only had this flavour as the "
                             "alias-named `MOV,U32` group with Ra baked to RZ and the Ra token on the Rb field. The `.MOV` / "
                             "`.IADD` / `.SHL` names are nvdisasm's print of the operands (tools/probes/re_sm120_imad_alias.py), "
                             "not an encoding.")
            groups["U32"] = twin
            added.append(f"{key}:U32" + (" (rebuilt)" if degenerate else ""))
    hist = table["_meta"].setdefault("provenance", {}).setdefault("history", {})
    hist["imad-alias-2026-11-04"] = (f"IMAD alias-named harvest groups removed ({', '.join(deleted)}); U32 twins added "
                                     f"({', '.join(added)}); the MOV/IADD/SHL display law lives in cubit's printer.")
    table["_meta"]["provenance"]["sources"][PROVENANCE] = {
        "rows": len(added), "kind": "nvdisasm 13.1 alias-law probe", "date": "2026-11-04",
        "tool": "tools/probes/re_sm120_imad_alias.py", "test": "tests/sm120_imad_alias.rs"}
    nvprobe.save_table(path, table)
    print(f"deleted {deleted}; added {added} in {path}")


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

#!/usr/bin/env python3
"""Measure the uniform-indexed shared-memory atomic `ATOMS.<op>[.S32|.64|.128] Rd, [Ra+URb(+imm)], Rb`
(opcode 0x98c with the frame bit 91) over its whole operation x type lattice and rebuild the key
`ATOMS_R_ARURI_R` from the measurement.

Why (dynamic audit T1, `T/audit/dyn13`, session T-8 2026-11-06): the 2026-10-29 probe
(`re_sm120_atoms_aruri.py`) measured ONE group of this key, `MAX,S32`; the other groups of the key
(`ADD`, `AND`, `EXCH`, `OR`, `XOR`, and a `CAS` group that carries the register-form opcode 0x38d) and the
0x98c groups of the sibling key `ATOMS_R_ARI_R_R` (`AND`, `EXCH`, `OR`, `XOR`) are harvest rows that read
the UR byte [71:64] as a fourth register operand and declare neither the UR nor the offset:
`ATOMS.AND R4, [R7+UR4], R8` printed `ATOMS.AND R4, [R7], R8, R4` and did not re-encode.

Measured with nvdisasm 13.1 (`-b SM120`, one word per call): operation [90:87] 0 ADD, 1 MIN, 2 MAX, 3 INC,
4 DEC, 5 AND, 6 OR, 7 XOR, 8 EXCH (9..15 `INVALIDn`); type [75:73] 0 plain, 1 `.S32`, 2 `.64`, 4 `.128`
(3, 5, 6, 7 `INVALIDn`); guard [15:12], Rd [23:16], Ra [31:24] (255 = RZ: the base is elided, `[UR4]`),
Rb [39:32], signed 24-bit offset [63:40] (elided at 0), URb [71:64] (255 = URZ); bits 72, 76, 77, 80-86,
92-95 text-inert; 0x98c without bit 91 and 0x38c with it are illegal. The `.64` / `.128` groups and the
`.S32` variants of INC / DEC / EXCH / AND / OR / XOR are nvdisasm-legal words no corpus has (encoding
evidence only, like every lattice row).

`probe` writes `tests/fixtures/sm120_atoms_aruri_ops_nvdisasm.jsonl`; `apply <sm120.json>` replaces the
groups of `ATOMS_R_ARURI_R` with the 36 measured ones (9 ops x 4 types) and retires the four 0x98c junk
groups of `ATOMS_R_ARI_R_R`.
"""
import argparse
import pathlib
import re
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import nvprobe  # noqa: E402

PROVENANCE = "atoms-aruri-ops-sm120-2026-11-06"
OPCODE = 0x98c
NATIVE_CTRL = 0x0001e200 << 96
KEY = "ATOMS_R_ARURI_R"
JUNK_SIBLING = ("ATOMS_R_ARI_R_R", ("AND", "EXCH", "OR", "XOR"))
OPS = {0: "ADD", 1: "MIN", 2: "MAX", 3: "INC", 4: "DEC", 5: "AND", 6: "OR", 7: "XOR", 8: "EXCH"}
TYPES = {0: "", 1: "S32", 2: "64", 4: "128"}
FIXTURE = nvprobe.FIXTURES / "sm120_atoms_aruri_ops_nvdisasm.jsonl"
TEXT = re.compile(r"(@!?P[0-6T] )?ATOMS\.(ADD|MIN|MAX|INC|DEC|AND|OR|XOR|EXCH)(\.S32|\.64|\.128)? R(Z|\d+), "
                  r"\[(R\d+\+)?UR(Z|\d+)(\+-?0x[0-9a-f]+)?\], R(Z|\d+)")


def word(op=5, ty=0, guard=7, rd=4, ra=7, rb=8, imm=0, ur=4, bit91=1, opcode=OPCODE, extra=0):
    return (opcode | (guard << 12) | (rd << 16) | (ra << 24) | (rb << 32) | ((imm & 0xffffff) << 40)
            | (ur << 64) | (ty << 73) | (op << 87) | (bit91 << 91) | extra)


def expected_text(w):
    op, ty = (w >> 87) & 0xf, (w >> 73) & 7
    guard = (w >> 12) & 0xf
    g = "" if guard == 7 else ("@" + ("!" if guard & 8 else "") + ("PT" if (guard & 7) == 7 else f"P{guard & 7}") + " ")
    reg = lambda n: "RZ" if n == 255 else f"R{n}"
    rd, ra, rb, ur = (w >> 16) & 0xff, (w >> 24) & 0xff, (w >> 32) & 0xff, (w >> 64) & 0xff
    imm = (w >> 40) & 0xffffff
    off = "" if imm == 0 else (f"+0x{imm:x}" if imm < 0x800000 else f"+-0x{0x1000000 - imm:x}")
    addr = ("" if ra == 255 else f"R{ra}+") + ("URZ" if ur == 255 else f"UR{ur}") + off
    return f"{g}ATOMS.{OPS[op]}{'.' + TYPES[ty] if TYPES[ty] else ''} {reg(rd)}, [{addr}], {reg(rb)}"


def sweep_words():
    form, lattice = set(), set()
    for op in OPS:
        for ty in TYPES:
            k = dict(op=op, ty=ty)
            form.add(word(**k))
            for guard in (0, 6, 8, 15):
                form.add(word(guard=guard, **k))
            for rd in (0, 255):
                form.add(word(rd=rd, **k))
            for ra in (0, 255):
                form.add(word(ra=ra, **k))
            for rb in (0, 255):
                form.add(word(rb=rb, **k))
            for ur in (0, 63, 255):
                form.add(word(ur=ur, **k))
            for imm in (0x10, 0x7fffff, 0x800000, 0xfffff0):
                form.add(word(imm=imm, **k))
            form.add(word(ra=255, ur=255, **k))
            form.add(word(guard=3, rd=200, ra=157, rb=58, imm=0x15100, ur=7, **k))
    base = word()
    for ty in (3, 5, 6, 7):  # INVALIDn types
        lattice.add(word(ty=ty))
    for op in range(9, 16):  # INVALIDn operations
        lattice.add(word(op=op))
    for bit in (72, 76, 77, 80, 81, 82, 83, 84, 85, 86, 92, 93, 94, 95):
        lattice.add(base | (1 << bit))
    lattice.add(word(bit91=0))  # 0x98c without the frame bit
    lattice.add(word(bit91=1, opcode=0x38c))  # the register-address opcode with the frame bit
    lattice -= form
    return [(w, False) for w in sorted(form)] + [(w, True) for w in sorted(lattice)]


def probe(nvdisasm, out=FIXTURE):
    rows = nvprobe.probe_words(
        nvdisasm, "atoms_aruri_ops", sweep_words(), NATIVE_CTRL,
        check_form=lambda w, t: TEXT.fullmatch(t) is not None and t == expected_text(w),
        check_lattice=lambda w, t: t is None or t.startswith("ATOMS"))
    nvprobe.write_fixture(out, rows)
    n_form = sum(1 for r in rows if not r.get("lattice"))
    print(f"{out}: {n_form} form words, {len(rows) - n_form} lattice words")


def measured_group(op, ty):
    src = PROVENANCE
    fields = [
        nvprobe.field(12, 4, "guard", 0, src),
        nvprobe.field(16, 8, "reg", 1, src),
        nvprobe.field(24, 8, "sub_r0", 2, src),
        nvprobe.field(64, 8, "sub_ur1", 2, src),
        nvprobe.field(40, 24, "sub_imm2", 2, src),
        nvprobe.field(32, 8, "reg", 3, src),
    ]
    mods = ",".join(sorted(m for m in (OPS[op], TYPES[ty]) if m))
    base = word(op=op, ty=ty, guard=0, rd=0, ra=0, rb=0, imm=0, ur=0)
    note = (f"ATOMS.{OPS[op]}{'.' + TYPES[ty] if TYPES[ty] else ''} Rd, [Ra+URb(+imm)], Rb (0x98c + frame bit 91): "
            "measured with nvdisasm 13.1 -b SM120, tools/probes/re_sm120_atoms_aruri_ops.py (session T-8, 2026-11-06); "
            "operation [90:87], type [75:73]; bits 72, 76, 77, 80-86, 92-95 text-inert and outside the row.")
    return mods, nvprobe.row(base, fields, src, note)


def apply(table_path):
    path = pathlib.Path(table_path)
    table = nvprobe.load_table(path)
    ins = table["instructions"]
    entry = ins[KEY]
    if all(g.get("_src") == PROVENANCE for g in entry["mod_groups"].values()) and len(entry["mod_groups"]) == 36:
        print("ATOMS_R_ARURI_R: already measured")
        return
    old = len(entry["mod_groups"])
    groups = {}
    for op in OPS:
        for ty in TYPES:
            mods, g = measured_group(op, ty)
            groups[mods] = g
    entry["mod_groups"] = groups
    entry["_src"] = PROVENANCE
    sib_key, sib_groups = JUNK_SIBLING
    removed = 0
    for gname in sib_groups:
        g = ins[sib_key]["mod_groups"].get(gname)
        if g is not None and (int(g["and_base"], 16) & 0xfff) == OPCODE:
            del ins[sib_key]["mod_groups"][gname]
            removed += 1
    prov = table["_meta"].setdefault("provenance", {})
    sources = prov.setdefault("sources", {})
    rows = [g for e in ins.values() for g in e.get("mod_groups", {}).values()]
    prov["rows_total"] = len(rows)
    prov["rows_without_src"] = sum(1 for g in rows if g.get("_src") is None)
    sources[PROVENANCE] = {
        "rows": len(groups),
        "kind": "nvdisasm 13.1 field probe (-b SM120)",
        "date": "2026-11-06",
        "tool": "tools/probes/re_sm120_atoms_aruri_ops.py",
        "test": "tests/sm120_atoms_aruri_ops.rs",
    }
    nvprobe.save_table(path, table)
    print(f"{path}: {KEY} {old} -> {len(groups)} measured groups; {removed} 0x98c junk groups of {sib_key} retired")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("probe")
    p.add_argument("--nvdisasm", default="/usr/local/lib/python3.12/dist-packages/triton/backends/nvidia/bin/nvdisasm")
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

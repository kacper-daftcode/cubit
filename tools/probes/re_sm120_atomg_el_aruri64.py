#!/usr/bin/env python3
"""Measure the 64-bit-base twin of the plain uniform-indexed `.EL` atomic — `ATOMG.E.<op>.EL.STRONG.GPU
Pd, Rd, [Ra.64+URb(+off)], Rb` (opcode 0x9a8, frame bit 91, width bit 63 SET, descriptor bit 76 clear) —
and add its two keys `ATOMG.E.{ADD,OR}.EL.STRONG.GPU_P_R_ARURI64_R` to sm120 / sm103a / sm100a.

Why (session T-7, 2026-11-06; dynamic audit T1 `T/audit/dyn10`): the plain `.EL` rows rebuilt on 2026-11-05
(`re_sm120_atomg_el_aruri.py`) exclude bit 63 by `claim_forbid` — before, the 24-bit offset field of the
harvest row swallowed the width bit and the `[R8.64+UR7]` words printed as a bogus `+-0x800000` offset. With
the exclusion they fail closed instead: the four `[R8.64+UR7(+-0x1)]` ADD / OR words of the audit are decode
misses. nvcc emits the form (`ATOMG.E.ADD.64` carriers in the BUG-444 law), no production corpus has it.

Measured with nvdisasm 13.1 (`-b SM120`; `-b SM103` / `-b SM100` print the same text for every word): the
same fields as the plain form — guard [15:12], Pd [83:81], Rd [23:16], Ra [31:24], Rb [39:32], URb [71:64],
offset [62:40] signed 23-bit — with bit 63 set; base 255 prints `[RZ.64+URb]`? (see the fixture: the
REDG `.64` twin prints the degenerate `???255` glyph, BUG-461), bit 76 with 63 = the descriptor rows
(`ATOMG_P_R_dARI_R`), bits 92-95 text-inert. `probe [--arch SM103|SM100]` writes
`tests/fixtures/sm120_atomg_el_aruri64_nvdisasm.jsonl`; `apply <table.json>` adds the two keys.
"""
import argparse
import pathlib
import re
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import nvprobe  # noqa: E402
import re_sm120_atomg_el_aruri as plain  # noqa: E402

PROVENANCE = "atomg-el-aruri64-2026-11-06"
KEYS = {op: f"ATOMG.E.{op}.EL.STRONG.GPU_P_R_ARURI64_R" for op in plain.OPS}
FIXTURE = nvprobe.FIXTURES / "sm120_atomg_el_aruri64_nvdisasm.jsonl"
TEXT = re.compile(
    r"(@!?P[0-6T] )?ATOMG\.E\.(ADD|OR)\.EL\.STRONG\.GPU P[0-6T], R(Z|\d+), "
    r"\[(R(Z|\d+)|\?\?\?255)\.64\+UR(Z|\d+)(\+-?0x[0-9a-f]+)?\], R(Z|\d+)")
W64 = 1 << 63


def word(op="ADD", **kw):
    return plain.word(op, **kw) | W64


def sweep_words():
    form_words, lattice = set(), set()
    for op in plain.OPS:
        form_words.add(word(op, ra=8, ur=7, rd=6, rb=10))
        for guard in (0, 3, 15):
            form_words.add(word(op, guard=guard, ra=8))
        for pd in range(8):
            form_words.add(word(op, pd=pd, ra=8))
        for rd in (0, 127, 254, 255):
            form_words.add(word(op, rd=rd, ra=8))
        for ra in (0, 4, 8, 127, 254, 255):
            form_words.add(word(op, ra=ra))
        for rb in (0, 5, 254, 255):
            form_words.add(word(op, rb=rb, ra=8))
        for ur in (0, 1, 62, 63, 255):
            form_words.add(word(op, ur=ur, ra=8))
        for off in (1, 0x100, 0x3fffff, 0x400000, 0x7ffff0, 0x7fffff):
            form_words.add(word(op, off=off, ra=8))
        form_words.add(word(op, guard=3, pd=5, ra=82, ur=38, off=0x7ffff0))
    base = word("ADD", ra=8)
    for bit in (76, 72, 91, 92, 93, 94, 95):
        lattice.add(base ^ (1 << bit))
    lattice.add(base ^ W64)  # the plain U32 form (the sibling rows)
    lattice -= form_words
    return [(w, False) for w in sorted(form_words)] + [(w, True) for w in sorted(lattice)]


def probe(nvdisasm, out=FIXTURE, arch="SM120"):
    def check_form(w, text):
        m = TEXT.fullmatch(text)
        if m is None:
            return False
        off = (w >> 40) & 0x7fffff
        want = "" if off == 0 else (f"+0x{off:x}" if off < 0x400000 else f"+-0x{0x800000 - off:x}")
        return (m.group(7) or "") == want

    rows = nvprobe.probe_words(
        nvdisasm, "atomg_el_aruri64", sweep_words(), plain.NATIVE_CTRL,
        check_form=check_form,
        check_lattice=lambda w, t: t is None or t.startswith("ATOMG"),
        arch=arch)
    nvprobe.write_fixture(out, rows)
    n_form = sum(1 for r in rows if not r.get("lattice"))
    print(f"{out}: {n_form} form words, {len(rows) - n_form} lattice words ({arch})")


def apply(table_path):
    path = pathlib.Path(table_path)
    table = nvprobe.load_table(path)
    ins = table["instructions"]
    if all(k in ins and all(g.get("_src") == PROVENANCE for g in ins[k]["mod_groups"].values()) for k in KEYS.values()):
        print("ATOMG .EL .64 plain form: already measured")
        return
    src = PROVENANCE
    fields = [
        nvprobe.field(12, 4, "guard", 0, src),
        nvprobe.field(81, 3, "pred", 1, src),
        nvprobe.field(16, 8, "reg", 2, src),
        nvprobe.field(24, 8, "reg", 3, src),
        nvprobe.field(64, 8, "ureg", 3, src),
        nvprobe.field(40, 23, "imm", 3, src),
        nvprobe.field(32, 8, "reg", 4, src),
    ]
    note = (
        "nvdisasm 13.1 (-b SM120; -b SM103 / -b SM100 text-identical), tools/probes/re_sm120_atomg_el_aruri64.py: "
        "the 64-bit-base twin of the plain uniform-indexed .EL atomic, `ATOMG.E.<op>.EL.STRONG.GPU Pd, Rd, "
        "[Ra.64+URb(+off)], Rb`: the fields of the U32 row (guard [15:12], Pd [83:81], Rd [23:16], Ra [31:24], Rb [39:32], "
        "URb [71:64] 8 bits, offset [62:40] signed 23-bit) with the width bit 63 SET in and_base; bit 76 (the "
        "descriptor form, legal only with bit 63 = the ATOMG_P_R_dARI_R rows) is claim_forbid. Base 255 prints the "
        "degenerate `???255.64` glyph like the REDG twin (BUG-461) and stays a text-faithful decode only."
    )
    template_key = next(k for k in plain.KEYS.values() if k in ins)
    template = {k: v for k, v in ins[template_key].items() if k != "mod_groups"}
    for op, key in KEYS.items():
        entry = dict(template)
        entry["base_op"] = f"ATOMG.E.{op}.EL.STRONG.GPU"
        entry["operand_sig"] = "P_R_ARURI64_R"
        group = nvprobe.row(word(op, guard=0, pd=0, rd=0, ra=0, rb=0, ur=0, off=0), fields, src, note)
        group["count"] = None
        group["claim_forbid"] = [{"bits": 1, "shift": 76, "values": [1]}]
        entry["mod_groups"] = {plain.GROUPS[op]: group}
        entry["_src"] = src
        ins[key] = entry
    prov = table["_meta"].setdefault("provenance", {})
    sources = prov.setdefault("sources", {})
    rows = [g for e in ins.values() for g in e.get("mod_groups", {}).values()]
    prov["rows_total"] = len(rows)
    prov["rows_without_src"] = sum(1 for g in rows if g.get("_src") is None)
    sources[src] = {
        "rows": len(KEYS),
        "kind": "nvdisasm 13.1 field probe (-b SM120 / SM103 / SM100 text-identical)",
        "date": "2026-11-06",
        "tool": "tools/probes/re_sm120_atomg_el_aruri64.py",
        "test": "tests/sm120_atomg_el_aruri64.rs",
    }
    nvprobe.save_table(path, table)
    print(f"{path}: {', '.join(KEYS.values())} added")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("probe")
    p.add_argument("--nvdisasm", default="/usr/local/lib/python3.12/dist-packages/triton/backends/nvidia/bin/nvdisasm")
    p.add_argument("--out", type=pathlib.Path, default=FIXTURE)
    p.add_argument("--arch", default="SM120")
    a = sub.add_parser("apply")
    a.add_argument("table")
    args = parser.parse_args()
    if args.command == "probe":
        probe(args.nvdisasm, args.out, args.arch)
    else:
        apply(args.table)


if __name__ == "__main__":
    main()

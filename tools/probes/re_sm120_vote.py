#!/usr/bin/env python3
"""Measure the SM120 warp-vote family -- `VOTE` (0x806, a per-thread result) and `VOTEU` (0x886, the uniform-datapath
result) -- with nvdisasm 13.1 and rewrite their four keys from the measurement.

    VOTE.<mode>  [Rd,]  Pd,  [!]Ps          VOTEU.<mode>  [URd,]  UPd,  [!]Ps          (PTX vote.sync.{all,any,uni}.pred / .ballot)

The layout is the same for both opcodes: the predicate guard [15:12]; the ballot destination [23:16] (R for VOTE, UR for
VOTEU; 255 = RZ / URZ, which nvdisasm elides -- the `_P_P` / `_UP_P` keys), the mode [73:72] (0 `.ALL`, 1 `.ANY`, 2 `.EQ`,
3 = `INVALID3`), the predicate destination [83:81] (P for VOTE, UP for VOTEU), the source predicate [89:87] with its
negation bit 90, bit 91 illegal; every other bit of the word is text-inert.

Before this probe the four keys were harvest rows (`bug226d`, `audit-fix-2026-11-06-t10`): `VOTEU_UR_UP_P` and `VOTE_R_P_P`
carried `.ANY` only, with the source predicate (VOTEU) or the predicate destination (VOTE) baked at PT -- so `VOTEU.ALL UR4,
UPT, PT`, the natural "every lane ready" test of a comm warp, did not assemble (megakernel item 11, 2026-11-08), nor did
`VOTEU.ANY UR4, UPT, P1`; the `_P_P` / `_UP_P` keys had no `.EQ` and variable masks made of control-code bits.

`probe` sweeps every field of the 2 opcodes x 3 modes x 2 forms into `tests/fixtures/sm120_vote_nvdisasm.jsonl` (+ the lattice:
`INVALID3`, bit 91, the text-inert bits); `apply` rewrites the four keys with the `ALL` / `ANY` / `EQ` rows (fields guard,
destination, predicate destination, source predicate, negation) and keeps each key's scheduling / ctrl_class.
"""
from __future__ import annotations

import argparse
import pathlib
import re
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import nvprobe  # noqa: E402

PROVENANCE = "vote-sm120-2026-11-08"
NATIVE_CTRL = 0x000fca00 << 96  # the control code cubit's scheduler puts on the vote (never part of a row)
FIXTURE = nvprobe.FIXTURES / "sm120_vote_nvdisasm.jsonl"
OPCODES = {"VOTE": 0x806, "VOTEU": 0x886}
MODES = {0: "ALL", 1: "ANY", 2: "EQ"}
# (key, opcode name, destination elided) -> the four keys
KEYS = {"VOTE_R_P_P": ("VOTE", False), "VOTE_P_P": ("VOTE", True), "VOTEU_UR_UP_P": ("VOTEU", False), "VOTEU_UP_P": ("VOTEU", True)}
TEXT = re.compile(r"(@!?P[0-6T] )?(VOTE|VOTEU)\.(ALL|ANY|EQ) ((R|UR)\d+, )?U?P[0-6T], !?P[0-6T]")


def word(op: str, guard: int = 7, dst: int = 4, mode: int = 1, pdst: int = 7, psrc: int = 7, neg: int = 0, extra: int = 0) -> int:
    return OPCODES[op] | (guard << 12) | (dst << 16) | (mode << 72) | (pdst << 81) | (psrc << 87) | (neg << 90) | extra


def expected_text(w: int) -> str:
    op = "VOTEU" if (w & 0xfff) == 0x886 else "VOTE"
    guard, dst, mode = (w >> 12) & 0xf, (w >> 16) & 0xff, (w >> 72) & 3
    pdst, psrc, neg = (w >> 81) & 7, (w >> 87) & 7, (w >> 90) & 1
    g = "" if guard == 7 else (f"@P{guard} " if guard < 7 else ("@!PT " if guard == 15 else f"@!P{guard - 8} "))
    p = lambda n: "T" if n == 7 else str(n)  # noqa: E731
    d = "" if dst == 255 else f"{'UR' if op == 'VOTEU' else 'R'}{dst}, "
    return f"{g}{op}.{MODES[mode]} {d}{'U' if op == 'VOTEU' else ''}P{p(pdst)}, {'!' if neg else ''}P{p(psrc)}"


def sweep_words():
    form = set()
    for op in OPCODES:
        for mode in MODES:
            for dst in (4, 255):
                form.add(word(op, dst=dst, mode=mode))
                for guard in range(16):
                    form.add(word(op, guard=guard, dst=dst, mode=mode))
                for pdst in range(8):
                    form.add(word(op, dst=dst, mode=mode, pdst=pdst))
                for psrc in range(8):
                    form.add(word(op, dst=dst, mode=mode, psrc=psrc))
                    form.add(word(op, dst=dst, mode=mode, psrc=psrc, neg=1))
                form.add(word(op, guard=3, dst=dst, mode=mode, pdst=2, psrc=5, neg=1))
            for dst in (0, 1, 10, 31, 62, 63, 64, 254):
                form.add(word(op, dst=dst, mode=mode))
    lattice = set()
    for op in OPCODES:
        for dst in (4, 255):
            lattice.add(word(op, dst=dst, mode=3))  # INVALID3
        base = word(op)
        for bit in list(range(24, 72)) + list(range(74, 81)) + list(range(84, 87)) + list(range(91, 105)) + [122, 123, 124]:
            lattice.add(base | (1 << bit))
    lattice -= form
    return [(w, False) for w in sorted(form)] + [(w, True) for w in sorted(lattice)]


def probe(nvdisasm: str, out: pathlib.Path = FIXTURE, jobs: int = 8) -> None:
    rows = nvprobe.probe_words(
        nvdisasm, "vote", sweep_words(), NATIVE_CTRL,
        check_form=lambda w, text: TEXT.fullmatch(text) is not None and text == expected_text(w),
        check_lattice=lambda w, text: text is None or text.startswith(("VOTE.", "VOTEU.")),
        jobs=jobs)
    nvprobe.write_fixture(out, rows)
    n_form = sum(not r.get("lattice") for r in rows)
    print(f"{n_form} VOTE / VOTEU words + {len(rows) - n_form} lattice words -> {out}")


def apply(table_path: str) -> None:
    path = pathlib.Path(table_path)
    table = nvprobe.load_table(path)
    ins = table["instructions"]
    if all(ins[k].get("_src") == PROVENANCE for k in KEYS):
        print(f"{', '.join(KEYS)}: already measured in {path}")
        return
    prov = table["_meta"]["provenance"]
    before = {}
    for e in ins.values():
        for g in e.get("mod_groups", {}).values():
            s = g.get("_src", e.get("_src"))
            before[s] = before.get(s, 0) + 1
    for key, (op, elided) in KEYS.items():
        entry = ins[key]
        assert entry["base_op"] == op, (key, entry["base_op"])
        upred = op == "VOTEU"
        tok = 0
        fields = [nvprobe.field(12, 4, "guard", 0, PROVENANCE)]
        if not elided:
            tok += 1
            fields.append(nvprobe.field(16, 8, "ureg" if upred else "reg", tok, PROVENANCE))
        tok += 1
        fields.append(nvprobe.field(81, 3, "upred" if upred else "pred", tok, PROVENANCE))
        tok += 1
        fields.append(nvprobe.field(87, 3, "pred", tok, PROVENANCE))
        fields.append(nvprobe.field(90, 1, "neg", tok, PROVENANCE))
        groups = {}
        for code, mode in MODES.items():
            template = word(op, guard=0, dst=255 if elided else 0, mode=code, pdst=0, psrc=0)
            note = (f"Measured with nvdisasm 13.1 (-b SM120; tools/probes/re_sm120_vote.py): {op}.{mode} = mode code {code} in [73:72] "
                    f"(0 ALL, 1 ANY, 2 EQ, 3 INVALID3 -- unclaimed). Fields: predicate guard [15:12], "
                    + ("" if elided else f"ballot destination {'UR' if upred else 'R'} [23:16], ")
                    + f"predicate destination {'UP' if upred else 'P'} [83:81], source predicate P [89:87] with its negation bit 90"
                    + (f"; the destination byte [23:16] is 255 ({'URZ' if upred else 'RZ'}), which nvdisasm elides -- the two-operand spelling" if elided else "")
                    + ". Bit 91 illegal; bits 24-71, 74-80, 84-86, 92-104 text-inert (outside the row, fail closed). "
                    "Replaces the harvest rows (bug226d / audit-fix-2026-11-06-t10) that baked a predicate at PT and carried no .ALL / .EQ.")
            groups[mode] = nvprobe.row(template, fields, PROVENANCE, note)
        entry["mod_groups"] = groups
        entry["_src"] = PROVENANCE
        for k in [k for k in entry if k.startswith("_bug") or k in ("_note", "_evidence")]:
            entry.pop(k)
    rows = [g for e in ins.values() if isinstance(e, dict) and isinstance(e.get("mod_groups"), dict) for g in e["mod_groups"].values()]
    after = {}
    for e in ins.values():
        for g in e.get("mod_groups", {}).values():
            s = g.get("_src", e.get("_src"))
            after[s] = after.get(s, 0) + 1
    prov["rows_total"] = len(rows)
    prov["rows_without_src"] = sum(1 for g in rows if g.get("_src") is None)
    prov["sources"][PROVENANCE] = {
        "rows": 12,
        "kind": "nvdisasm 13.1 field probe (-b SM120): the warp-vote family VOTE / VOTEU, three modes, both operand forms",
        "date": "2026-11-08",
        "tool": "tools/probes/re_sm120_vote.py",
        "test": "tests/sm120_vote.rs",
    }
    for s, n in before.items():
        if s and s != PROVENANCE and after.get(s, 0) != n and prov["sources"].get(s, {}).get("rows") == n:
            prov["sources"][s]["rows"] = after.get(s, 0)
            print(f"  legend {s}: rows {n} -> {after.get(s, 0)}")
    nvprobe.save_table(path, table)
    print(f"{path}: {', '.join(KEYS)} rewritten from the measurement (ALL / ANY / EQ on each)")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("probe")
    p.add_argument("--nvdisasm", default="/usr/local/lib/python3.12/dist-packages/triton/backends/nvidia/bin/nvdisasm")
    p.add_argument("--out", type=pathlib.Path, default=FIXTURE)
    p.add_argument("--jobs", type=int, default=8)
    a = sub.add_parser("apply")
    a.add_argument("table")
    args = parser.parse_args()
    if args.command == "probe":
        probe(args.nvdisasm, args.out, args.jobs)
    else:
        apply(args.table)


if __name__ == "__main__":
    main()

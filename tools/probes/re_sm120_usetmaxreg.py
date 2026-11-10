#!/usr/bin/env python3
"""Measure SM120 `USETMAXREG` (PTX `setmaxnreg.{dec,inc}.sync.aligned.u32`: the warpgroup register reallocation) with
nvdisasm 13.1 and rewrite its two keys from the measurement.

    USETMAXREG.DEALLOC.CTAPOOL imm            (0x9c8; setmaxnreg.dec -- the warpgroup releases registers to the CTA pool)
    USETMAXREG.TRY_ALLOC.CTAPOOL UPd, imm     (setmaxnreg.inc -- the warpgroup asks for registers; UPd = success, retried by
                                               `@!UPd BRA` in nvcc's lowering)

Layout (both forms): the uniform predicate guard [15:12] (`@UP0` ... `@!UPT`), the register count imm [41:32] -- ten bits,
printed in hex, the count itself (0x18 = 24, 0xe0 = 224; ptxas emits multiples of 8 in 24..256, the field admits 0..1023:
what the hardware does with the other values is a silicon question, not an encoding one), the operation [73:72] (1 = DEALLOC,
2 = TRY_ALLOC; 0 and 3 illegal), the pool bit 74 (set = `.CTAPOOL`; clear prints the vendor glyph `.???0` -- an unnamed
pool, unclaimed), bit 75 text-inert, the predicate destination [83:81] on TRY_ALLOC (a UP; on DEALLOC the field is
text-inert and nvcc writes 7 there -- the row bakes 7 and fails closed on the rest), bit 91 required (clear = illegal), the
reuse bits 122-124 illegal (a control-word law: no reuse flag on this opcode), every other bit text-inert.

Before this probe `USETMAXREG_II` (`audit-fix-2026-11-06-t10`) had no guard field and `USETMAXREG_UP_II` was a native-capture
row (`sm120-native-capture-control-2026-10-22`), neither measured per field (KNOWN_ISSUES T1 exception 9; megakernel item 1:
the three-role `setmaxnreg` of the persistent kernel). `probe` writes `tests/fixtures/sm120_usetmaxreg_nvdisasm.jsonl`;
`apply` rewrites the two rows (guard, count, [UPd]) and keeps each key's scheduling / ctrl_class.
"""
from __future__ import annotations

import argparse
import pathlib
import re
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import nvprobe  # noqa: E402

PROVENANCE = "usetmaxreg-sm120-2026-11-08"
OPCODE = 0x9c8
NATIVE_CTRL = 0x000fc000 << 96  # nvcc's control code on the DEALLOC word (never part of a row)
FIXTURE = nvprobe.FIXTURES / "sm120_usetmaxreg_nvdisasm.jsonl"
OPS = {1: "DEALLOC", 2: "TRY_ALLOC"}
KEYS = {"USETMAXREG_II": 1, "USETMAXREG_UP_II": 2}
TEXT = re.compile(r"(@!?UP[0-6T] )?USETMAXREG\.(DEALLOC|TRY_ALLOC)\.CTAPOOL (UP[0-6T], )?0x[0-9a-f]+")


def word(op: int, guard: int = 7, count: int = 0x18, pred: int = 7, pool: int = 1, extra: int = 0) -> int:
    return OPCODE | (guard << 12) | (count << 32) | (op << 72) | (pool << 74) | (pred << 81) | (1 << 91) | extra


def expected_text(w: int) -> str:
    guard, count, op, pred = (w >> 12) & 0xf, (w >> 32) & 0x3ff, (w >> 72) & 3, (w >> 81) & 7
    g = "" if guard == 7 else (f"@UP{guard} " if guard < 7 else ("@!UPT " if guard == 15 else f"@!UP{guard - 8} "))
    p = f"UP{'T' if pred == 7 else pred}, " if op == 2 else ""
    return f"{g}USETMAXREG.{OPS[op]}.CTAPOOL {p}0x{count:x}"


def sweep_words():
    form = set()
    counts = (0, 8, 0x18, 0x20, 0x38, 0x68, 0xd0, 0xe0, 0xe8, 0xf8, 0x100, 0x118, 0x3ff)
    for op in OPS:
        for guard in range(16):
            form.add(word(op, guard=guard))
        for count in counts:
            form.add(word(op, count=count))
        if op == 2:
            for pred in range(8):
                form.add(word(op, pred=pred))
                form.add(word(op, pred=pred, count=0xd0, guard=3))
    form.add(word(1, count=0x28, guard=0))  # the CUTLASS MXFP8 GEMM's words: DEALLOC 0x28 / TRY_ALLOC 0xe8 (UP0)
    form.add(word(2, count=0xe8, pred=0))
    lattice = set()
    for op in OPS:
        base = word(op, pred=0 if op == 2 else 7)
        lattice.add(base & ~(1 << 74))  # the unnamed pool `.???0`
        for bit in list(range(16, 32)) + list(range(42, 72)) + [75] + list(range(84, 91)) + list(range(92, 105)) + [122, 123, 124]:
            lattice.add(base | (1 << bit))
        lattice.add(base & ~(1 << 91))
    for op in (0, 3):
        lattice.add(word(op))
    for pred in (0, 3):  # DEALLOC's predicate slot is text-inert: outside the row
        lattice.add(word(1, pred=pred))
    lattice -= form
    return [(w, False) for w in sorted(form)] + [(w, True) for w in sorted(lattice)]


def probe(nvdisasm: str, out: pathlib.Path = FIXTURE, jobs: int = 8) -> None:
    rows = nvprobe.probe_words(
        nvdisasm, "usetmaxreg", sweep_words(), NATIVE_CTRL,
        check_form=lambda w, text: TEXT.fullmatch(text) is not None and text == expected_text(w),
        check_lattice=lambda w, text: text is None or text.startswith("USETMAXREG."),
        jobs=jobs)
    nvprobe.write_fixture(out, rows)
    n_form = sum(not r.get("lattice") for r in rows)
    print(f"{n_form} USETMAXREG words + {len(rows) - n_form} lattice words -> {out}")


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
    for key, op in KEYS.items():
        entry = ins[key]
        assert entry["base_op"] == "USETMAXREG", key
        fields = [nvprobe.field(12, 4, "guard", 0, PROVENANCE)]
        tok = 1
        if op == 2:
            fields.append(nvprobe.field(81, 3, "upred", tok, PROVENANCE))
            tok += 1
        fields.append(nvprobe.field(32, 10, "imm", tok, PROVENANCE))
        template = word(op, guard=0, count=0, pred=0 if op == 2 else 7)
        note = (f"Measured with nvdisasm 13.1 (-b SM120; tools/probes/re_sm120_usetmaxreg.py): USETMAXREG.{OPS[op]}.CTAPOOL = operation code "
                f"{op} in [73:72] (1 DEALLOC, 2 TRY_ALLOC; 0 and 3 illegal) with the pool bit 74 set (clear = the vendor glyph `.???0`, "
                "unclaimed). Fields: uniform predicate guard [15:12], "
                + ("predicate destination UP [83:81], " if op == 2 else "")
                + "register count imm [41:32] (ten bits, printed in hex; the count itself -- ptxas emits multiples of 8 in 24..256, the "
                "field admits 0..1023: a silicon question, not an encoding one)"
                + ("" if op == 2 else "; the predicate slot [83:81] is text-inert on DEALLOC and nvcc writes 7 there -- baked, fail closed")
                + ". Bit 75 text-inert, bit 91 required, bits 16-31, 42-71, 84-90, 92-104 text-inert (outside the row); the reuse bits "
                "122-124 are illegal on this opcode (nvdisasm: undefined value for the opex table) -- a control-word law, no reuse flag "
                "may be set on it. PTX setmaxnreg." + ("dec" if op == 1 else "inc") + ".sync.aligned.u32.")
        entry["mod_groups"] = {f"CTAPOOL,{OPS[op]}": nvprobe.row(template, fields, PROVENANCE, note)}
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
        "rows": 2,
        "kind": "nvdisasm 13.1 field probe (-b SM120): the warpgroup register reallocation, both operations",
        "date": "2026-11-08",
        "tool": "tools/probes/re_sm120_usetmaxreg.py",
        "test": "tests/sm120_usetmaxreg.rs",
    }
    for s, n in before.items():
        if s and s != PROVENANCE and after.get(s, 0) != n and prov["sources"].get(s, {}).get("rows") == n:
            prov["sources"][s]["rows"] = after.get(s, 0)
            print(f"  legend {s}: rows {n} -> {after.get(s, 0)}")
    nvprobe.save_table(path, table)
    print(f"{path}: {', '.join(KEYS)} rewritten from the measurement")


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

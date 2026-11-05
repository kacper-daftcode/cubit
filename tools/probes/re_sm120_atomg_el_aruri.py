#!/usr/bin/env python3
"""Measure the plain uniform-indexed `ATOMG.E.<op>.EL.STRONG.GPU Pd, Rd, [Ra.U32+URb(+off)], Rb`
form (opcode 0x9a8, bit 91 frame, bit 76 clear) and rebuild its two era keys on sm120 / sm103a / sm100a.

Why: the sm103a and sm100a tables carried the two era keys `ATOMG.E.ADD.EL.STRONG.GPU_P_R_dARI_R`
and `ATOMG.E.OR.EL.STRONG.GPU_P_R_dARI_R` (rt98 lineage, 2026-08-21) whose canonical words are the
PLAIN form -- nvdisasm prints `[RZ.U32+UR6]` -- but whose signature said `desc[URb][Ra.64]`. cubit
therefore printed the 64-bit descriptor glyph for a 32-bit-offset word (the BUG-041 downcast text,
`tests/b4fill2_rows.rs`), and since the wave-11 tables (blackwell-isa e99598a) carry the real
`.EL` descriptor rows (`ATOMG_P_R_dARI_R`, bits 76 + 63 set), the mis-keyed text re-encoded to a
different word. The sm120 twins (`..._P_R_ARURI_R`) had the right signature but a 24-bit offset
field that swallowed the address-width bit 63, a 6-bit UR field and no predicate-destination field.

Measured with nvdisasm 13.1 (`-b SM120`; `-b SM103` and `-b SM100` print the same text for every word):
  * guard [15:12]; Pd [83:81] (7 = PT, printed); Rd [23:16]; Ra [31:24] (255 = RZ, printed
    `RZ.U32`); Rb [39:32]; URb [71:64], 8 bits (255 prints `URZ`, 63 prints `UR63`);
  * offset [62:40], 23 bits SIGNED: bit 62 set prints `+-0x400000`, 0x7fffff prints `+-0x1`;
  * bit 63 is the address width (set: `[Ra.64+URb]` -- a different form, outside the row);
  * bit 72 `.E`; [75:73] type (S32 / 64 / 128 -- other rows); bit 76 alone is illegal (it is the
    descriptor-form bit, legal only with bit 63 = the `desc[URb][Ra.64]` rows); [80:77] scope /
    semantics; [86:84] cache policy (2 = `.EL`; 0 EF, 3 LU, 6 INVALID6 -- other rows); [90:87] the
    atomic op (0 ADD, 6 OR, 1 MIN, 2 MAX, 4 DEC, 8 EXCH ...); bit 91 frame (clear = illegal);
    bits 92-95 text-inert (stay outside the row).
`probe` writes `tests/fixtures/sm120_atomg_el_aruri_nvdisasm.jsonl` (and the `--arch SM103` /
`SM100` fixtures); `apply <table.json>` rebuilds the two keys in a canonical sm120.json /
sm103a.json / sm100a.json (the sm103a / sm100a `_dARI_R` era keys are replaced by the `_ARURI_R`
keys of the sm120 table).
"""
import argparse
import pathlib
import re
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import nvprobe  # noqa: E402

PROVENANCE = "atomg-el-aruri-2026-11-05"
OPC = 0x9a8
NATIVE_CTRL = 0x000fc400 << 96
OPS = {"ADD": 0, "OR": 6}
KEYS = {op: f"ATOMG.E.{op}.EL.STRONG.GPU_P_R_ARURI_R" for op in OPS}
GROUPS = {"ADD": "ADD,E,EL,GPU,STRONG", "OR": "E,EL,GPU,OR,STRONG"}
ERA_KEYS = {op: f"ATOMG.E.{op}.EL.STRONG.GPU_P_R_dARI_R" for op in OPS}
FIXTURE = nvprobe.FIXTURES / "sm120_atomg_el_aruri_nvdisasm.jsonl"
TEXT = re.compile(
    r"(@!?P[0-6T] )?ATOMG\.E\.(ADD|OR)\.EL\.STRONG\.GPU P[0-6T], R(Z|\d+), "
    r"\[R(Z|\d+)\.U32\+UR(Z|\d+)(\+-?0x[0-9a-f]+)?\], R(Z|\d+)")
# the constant bits of the form: .E (72), .STRONG.GPU ([80:77] = 0b0111), .EL ([86:84] = 2), frame 91
CONST = (1 << 72) | (0b111 << 77) | (2 << 84) | (1 << 91)


def word(op="ADD", guard=7, pd=7, rd=218, ra=255, rb=81, ur=6, off=0, extra=0):
    w = OPC | (guard << 12) | (rd << 16) | (ra << 24) | (rb << 32) | (off << 40) | (ur << 64) | (pd << 81)
    return w | (OPS[op] << 87) | CONST | extra


def sweep_words():
    form_words, lattice = set(), set()
    for op in OPS:
        form_words.add(word(op))
        for guard in range(16):
            form_words.add(word(op, guard=guard))
        for pd in range(8):
            form_words.add(word(op, pd=pd))
        for rd in (0, 1, 127, 254, 255):
            form_words.add(word(op, rd=rd))
        for ra in (0, 4, 5, 127, 254):
            form_words.add(word(op, ra=ra))
        for rb in (0, 5, 254, 255):
            form_words.add(word(op, rb=rb))
        for ur in (0, 1, 62, 63, 255):
            form_words.add(word(op, ur=ur))
        for off in (1, 0x100, 0x3fffff, 0x400000, 0x7ffff0, 0x7fffff):
            form_words.add(word(op, off=off))
        # a guarded, predicated, offset word with a register base (the census shape)
        form_words.add(word(op, guard=3, pd=5, ra=82, ur=38, off=0x7ffff0))
    base = word("ADD")
    # the neighbourhood: width bit 63 (the `.64` form), the descriptor bit 76 (alone illegal, with 63 the
    # desc rows), the frame bit, `.E` off, the other cache policies, the other ops, type bits, scope bits
    for bit in (63, 76, 72, 73, 74, 75, 77, 78, 79, 80, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95):
        lattice.add(base ^ (1 << bit))
    lattice.add(base | (1 << 63) | (1 << 76))
    # UR64: nvdisasm names it, the parser bounds UR to 0..63 / URZ -- the word is a text-faithful decode only
    lattice.add(word("ADD", ur=64))
    lattice.add((base & ~(0xff << 24)) | (4 << 24) | (1 << 63))
    lattice -= form_words
    return [(w, False) for w in sorted(form_words)] + [(w, True) for w in sorted(lattice)]


def probe(nvdisasm, out=FIXTURE, arch="SM120"):
    def check_form(w, text):
        m = TEXT.fullmatch(text)
        if m is None:
            return False
        # the offset must read as a signed 23-bit number
        off = (w >> 40) & 0x7fffff
        want = "" if off == 0 else (f"+0x{off:x}" if off < 0x400000 else f"+-0x{0x800000 - off:x}")
        return (m.group(6) or "") == want

    rows = nvprobe.probe_words(
        nvdisasm, "atomg_el_aruri", sweep_words(), NATIVE_CTRL,
        check_form=check_form,
        # lattice words are illegal, another ATOMG text, or (bits 92-95) text-inert copies of the form
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
        print("ATOMG .EL plain form: already measured")
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
        "nvdisasm 13.1 (-b SM120; -b SM103 / -b SM100 text-identical), tools/probes/re_sm120_atomg_el_aruri.py: "
        "plain uniform-indexed .EL atomic `ATOMG.E.<op>.EL.STRONG.GPU Pd, Rd, [Ra.U32+URb(+off)], Rb`: guard [15:12], "
        "Pd [83:81], Rd [23:16], Ra [31:24] (255 = RZ), Rb [39:32], URb [71:64] (8 bits, 255 = URZ), offset [62:40] "
        "signed 23-bit (bit 62 prints +-0x400000). Bit 63 is the address width (the `[Ra.64+URb]` form), bit 76 the "
        "descriptor form (legal only with bit 63: the ATOMG_P_R_dARI_R rows); both are claim_forbid (the decoder's broad operand-window match would otherwise claim the .64 word). Replaces the "
        "rt98-era `..._P_R_dARI_R` keys of sm103a / sm100a (same words, the desc[URb][Ra.64] glyph was the era decoder's "
        "fabrication) and the sm120 rows' 24-bit offset / 6-bit UR fields."
    )
    template_key = next((k for k in (*KEYS.values(), *ERA_KEYS.values()) if k in ins), None)
    assert template_key is not None, f"{path}: no ATOMG .EL era key to rebuild"
    template = {k: v for k, v in ins[template_key].items() if k != "mod_groups"}
    removed = []
    for op, key in KEYS.items():
        old = ins.get(key) or ins.get(ERA_KEYS[op])
        count = None
        if old is not None:
            counts = [g.get("count") for g in old["mod_groups"].values() if g.get("count") is not None]
            count = sum(counts) if counts else None
        for era in (ERA_KEYS[op],):
            if era in ins:
                del ins[era]
                removed.append(era)
        entry = dict(template)
        entry["base_op"] = f"ATOMG.E.{op}.EL.STRONG.GPU"
        entry["operand_sig"] = "P_R_ARURI_R"
        group = nvprobe.row(word(op, guard=0, pd=0, rd=0, ra=0, rb=0, ur=0, off=0), fields, src, note)
        group["count"] = count
        # the decoder's broad match for memory keys treats [63:32] as operand bits: without this
        # exclusion the `.64` width word (bit 63) would be claimed by the U32 row and printed as U32
        group["claim_forbid"] = [{"bits": 1, "shift": 63, "values": [1]}, {"bits": 1, "shift": 76, "values": [1]}]
        entry["mod_groups"] = {GROUPS[op]: group}
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
        "date": "2026-11-05",
        "tool": "tools/probes/re_sm120_atomg_el_aruri.py",
        "test": "tests/sm120_atomg_el_aruri.rs",
    }
    nvprobe.save_table(path, table)
    print(f"{path}: {', '.join(KEYS.values())} rebuilt ({len(removed)} era keys removed: {removed})")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("probe")
    p.add_argument("--nvdisasm", required=True)
    p.add_argument("--out", type=pathlib.Path, default=None)
    p.add_argument("--arch", default="SM120")
    a = sub.add_parser("apply")
    a.add_argument("table")
    args = parser.parse_args()
    if args.command == "probe":
        out = args.out or (FIXTURE if args.arch == "SM120" else nvprobe.FIXTURES / f"{args.arch.lower()}a_atomg_el_aruri_nvdisasm.jsonl")
        probe(args.nvdisasm, out, args.arch)
    else:
        apply(args.table)


if __name__ == "__main__":
    main()

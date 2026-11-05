#!/usr/bin/env python3
"""Measure the SM120 funnel shift `SHF.{L|R}[.W].{U32|S32|U64|S64}[.HI] Rd, Ra, <b>, <c>` in its five
operand forms and rebuild the family's keys from the measurement.

Why (dynamic audit 2026-11-02..04, `docs/KNOWN_ISSUES.md` T1): 40 dotted harvest keys
(`SHF.L.U32_R_R_II_R`, `SHF.R.S32.HI_R_R_II_R_II_II_?`, ...) each carried one sample's modifiers baked
into `and_base` with truncated fields (`reg` at bit 17, 5-bit / 2-bit / 1-bit `ureg` fields), and the
five generic keys mixed the opcodes of different forms inside one key (`SHF_R_R_UR_R` groups with the
immediate opcode 0x819 and an `imm` field where the UR sits): `SHF.L.U32_R_R_II_R`'s own canonical
word printed `SHF.L.S64` for nvdisasm and `SHF.R.U64` for cubit; 144 probe words of the family were
text or re-encode mismatches.

Measured with nvdisasm 13.1 (`-b SM120`, one word per call):
  * five forms (opcode [11:0]): 0x219 `Rd, Ra, Rb, Rc`; 0x419 `Rd, Ra, Rc, imm32` (the immediate is the
    FOURTH operand); 0x819 `Rd, Ra, imm32, Rc`; 0xc19 `Rd, Ra, URb, Rc` and 0xe19 `Rd, Ra, Rc, URb`
    (both UR forms need frame bit 91; it is illegal on the register / immediate forms);
  * operands: guard [15:12], Rd [23:16], Ra [31:24], Rb / URb / imm at [39:32] / [39:32] / [63:32],
    Rc [71:64] (255 = RZ / URZ);
  * modifiers (set / clear): bit 73 = unsigned / signed, bit 74 = 32-bit / 64-bit (`U32` = both set,
    `S64` = both clear), bit 75 = `.W` (wrap), bit 76 = `.R` / `.L`, bit 80 = `.HI`; print order
    `SHF.<dir>[.W].<type>[.HI]`;
  * bits 72, 77-79, 81-90 are text-inert and stay outside the rows (fail-closed).
`.reuse` on Ra / Rb / Rc reaches bits 122 / 123 / 124 through the encoder's generic 8-bit register
slots (24 / 32 / 64), no row field needed.
`probe` writes `tests/fixtures/sm120_shf_nvdisasm.jsonl`; `apply <sm120.json>` replaces the 40 dotted
keys and the five generic keys' groups with 5 x 32 measured groups.
"""
import argparse
import pathlib
import re
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import nvprobe  # noqa: E402

PROVENANCE = "shf-sm120-2026-11-05"
NATIVE_CTRL = 0x000fca00 << 96
# key suffix -> (opcode, frame bit 91, kind of the [39:32]/[63:32] slot, kind of the [71:64] slot)
FORMS = {
    "R_R_R_R": (0x219, 0, "reg", "reg"),
    "R_R_R_II": (0x419, 0, "imm", "reg"),
    "R_R_II_R": (0x819, 0, "imm", "reg"),
    "R_R_UR_R": (0xc19, 1, "ur", "reg"),
    "R_R_R_UR": (0xe19, 1, "ur", "reg"),
}
TYPES = {0: "U32", 1: "S32", 2: "U64", 3: "S64"}  # ty bit 0 = signed, bit 1 = 64-bit (see word())
FIXTURE = nvprobe.FIXTURES / "sm120_shf_nvdisasm.jsonl"
TEXT = re.compile(r"(@!?P[0-6T] )?SHF\.(L|R)(\.W)?\.(U32|S32|U64|S64)(\.HI)? R(Z|\d+), R(Z|\d+), (R(Z|\d+)|UR(Z|\d+)|0x[0-9a-f]+), (R(Z|\d+)|UR(Z|\d+)|0x[0-9a-f]+)")


def word(form, ty=0, w=0, left=0, hi=0, guard=7, rd=2, ra=4, b=5, c=3, extra=0, frame=None):
    opc, fb, _, _ = FORMS[form]
    frame = fb if frame is None else frame
    # polarity (nvdisasm 13.1): bit 73 SET = unsigned, bit 74 SET = 32-bit, bit 76 SET = right shift
    unsigned, is32, right = 1 - (ty & 1), 1 - (ty >> 1), 1 - left
    return (opc | (guard << 12) | (rd << 16) | (ra << 24) | (b << 32) | (c << 64) | (unsigned << 73)
            | (is32 << 74) | (w << 75) | (right << 76) | (hi << 80) | (frame << 91) | extra)


def sweep_words():
    form_words, lattice = set(), set()
    for form in FORMS:
        for ty in TYPES:
            for w in (0, 1):
                for left in (0, 1):
                    for hi in (0, 1):
                        k = dict(ty=ty, w=w, left=left, hi=hi)
                        form_words.add(word(form, **k))
                        if ty == 0 and w == 0:
                            for guard in (0, 15):
                                form_words.add(word(form, guard=guard, **k))
                            for rd in (0, 255):
                                form_words.add(word(form, rd=rd, **k))
                            for ra in (0, 255):
                                form_words.add(word(form, ra=ra, **k))
                            bvals = (0, 0x1f, 0xffffffff) if FORMS[form][2] == "imm" else (0, 63, 255)
                            for b in bvals:
                                form_words.add(word(form, b=b, **k))
                            for c in (0, 255):
                                form_words.add(word(form, c=c, **k))
        base = word(form)
        for bit in (72, 77, 78, 79, *range(81, 91)):
            lattice.add(base | (1 << bit))
        lattice.add(word(form, frame=1 - FORMS[form][1]))
    for opc in (0x019, 0x619, 0xa19):
        lattice.add((word("R_R_R_R") & ~0xfff) | opc)
    lattice -= form_words
    return [(w, False) for w in sorted(form_words)] + [(w, True) for w in sorted(lattice)]


def probe(nvdisasm, out=FIXTURE):
    rows = nvprobe.probe_words(
        nvdisasm, "shf", sweep_words(), NATIVE_CTRL,
        check_form=lambda w, t: TEXT.fullmatch(t) is not None,
        check_lattice=lambda w, t: t is None or t.startswith("SHF"))
    nvprobe.write_fixture(out, rows)
    n_form = sum(1 for r in rows if not r.get("lattice"))
    print(f"{out}: {n_form} form words, {len(rows) - n_form} lattice words")


def measured_group(form, ty, w, left, hi):
    opc, fb, bkind, _ = FORMS[form]
    src = PROVENANCE
    fields = [nvprobe.field(12, 4, "guard", 0, src), nvprobe.field(16, 8, "reg", 1, src), nvprobe.field(24, 8, "reg", 2, src)]
    if form in ("R_R_R_II", "R_R_R_UR"):
        fields.append(nvprobe.field(64, 8, "reg", 3, src))
        fields.append(nvprobe.field(32, 32, "imm", 4, src) if bkind == "imm" else nvprobe.field(32, 8, "ureg", 4, src))
    else:
        fields.append({"reg": nvprobe.field(32, 8, "reg", 3, src), "imm": nvprobe.field(32, 32, "imm", 3, src),
                       "ur": nvprobe.field(32, 8, "ureg", 3, src)}[bkind])
        fields.append(nvprobe.field(64, 8, "reg", 4, src))
    base = word(form, ty, w, left, hi, guard=0, rd=0, ra=0, b=0, c=0)
    mods = ",".join(sorted(m for m in (("L" if left else "R"), TYPES[ty], "W" if w else "", "HI" if hi else "") if m))
    note = f"SHF {form} {mods}: measured with nvdisasm 13.1 -b SM120 (session T-5, 2026-11-05)"
    return mods, nvprobe.row(base, fields, src, note)


def apply(table_path):
    path = pathlib.Path(table_path)
    table = nvprobe.load_table(path)
    ins = table["instructions"]
    keys = [f"SHF_{f}" for f in FORMS]
    if all(k in ins and all(g.get("_src") == PROVENANCE for g in ins[k]["mod_groups"].values()) for k in keys):
        print("SHF: already measured")
        return
    template = ins["SHF_R_R_II_R"]
    removed = [k for k in list(ins) if k.startswith("SHF.")]
    for k in removed:
        del ins[k]
    # the era alias `SHF.L.U32_P0_R_R_II_R` pointed at the dotted key: retarget it to the plain key
    aliases = table.get("_meta", {}).get("key_aliases", {})
    for alias, target in list(aliases.items()):
        if target in removed:
            aliases[alias] = "SHF_" + target.split("_", 1)[1]
    for form in FORMS:
        key = f"SHF_{form}"
        entry = dict(ins.get(key, template))
        entry = {k: v for k, v in entry.items() if k != "mod_groups"}
        entry["base_op"] = "SHF"
        entry["operand_sig"] = form
        groups = {}
        for ty in TYPES:
            for w in (0, 1):
                for left in (0, 1):
                    for hi in (0, 1):
                        mods, g = measured_group(form, ty, w, left, hi)
                        groups[mods] = g
        entry["mod_groups"] = groups
        entry["_src"] = PROVENANCE
        ins[key] = entry
    nvprobe.save_table(path, table)
    print(f"SHF: {len(removed)} dotted keys removed ({', '.join(removed[:4])} ...), 5 keys rebuilt with 32 groups each in {path}")


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

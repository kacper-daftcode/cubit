#!/usr/bin/env python3
"""The HSETP2 family (opcode 0x234: register form `HSETP2 Pd0, Pd1, Ra, Rb, Pc`; uniform form = opcode
byte 0xe34 + bit 91, `Ra, URb`): measure the whole modifier x operand lattice with nvdisasm and rebuild the
two keys from the measurement (session G, 2026-11-06; KNOWN_ISSUES T1 — the 384 + 384 harvest rows of
`HSETP2_P_P_R_R_P` / `HSETP2_P_P_R_UR_P` were the 2026-10-22 "mode grid" rows without a field-by-field
measurement, flagged `baked_operand_byte` for the modifier bits inside the [71:64] slot).

Law (nvdisasm 13.1, one word per call, `-b SM120`; `probe --arch SM103` / `SM100` print the same text for
every word of the sweep):

  [11:0] opcode 0x234 (register form, bit 91 illegal) / 0xe34 + bit 91 (uniform form; bit 91 clear illegal);
  [15:12] guard; [23:16] text-inert (no Rd); Ra [31:24]; Rb / URb [39:32]; [59:40] text-inert;
  Rb: selector [61:60] (0 natural, 2 `.H0_H0`, 3 `.H1_H1`, 1 = the vendor's `.INVALID1`), 62 `|Rb|`, 63 `-Rb`;
  [65:64] the type (0 fp16, 2 `.BF16_V2`, 1 / 3 = `HSETP2.INVALID1` / `.INVALID3`); 66-68 text-inert;
  [70:69] the boolean (0 `.AND`, 1 `.OR`, 2 `.XOR`, 3 = `.INVALID3`); 71 `.H_AND`;
  Ra: 72 `-Ra`, 73 `|Ra|`, selector [75:74] as Rb's; [79:76] the comparison (F LT EQ LE GT NE GE NUM NAN LTU
  EQU LEU GTU NEU GEU T); 80 `.FTZ`; Pd0 [83:81]; Pd1 [86:84]; Pc [89:87], 90 `!Pc`; [95:92] text-inert.
  Print order `HSETP2[.BF16_V2].<cmp>[.H_AND][.FTZ].<bool>`; signs print `-|R2|.H1_H1`; `.reuse` on Ra = bit
  122, on Rb = bit 124 (the register form; bit 123 is nvdisasm's "undefined opex" error on this opclass).

384 legal modifier groups per form (16 x 3 x 2 x 2 x 2); the INVALID codes and the text-inert bits stay
outside the rows (fail-closed), the `.INVALID1` selector value decodes to the vendor's glyph and the encoder
refuses the spelling (BUG-272).

`probe [--arch SM120|SM103|SM100] [--jobs N]` writes `tests/fixtures/<table>_hsetp2_nvdisasm.jsonl`;
`apply <sm120.json>` rewrites the two keys' groups and retires the three dotted harvest keys
(`HSETP2.GEU.AND_P_P_R_R_P` encode-only twin, `HSETP2.GEU.AND_P_P_R_R_R` / `_P_P_R_UR_UR` = the
`R2.H0_H0, R3.H0_H0` sample mis-tokenised as a third register) as `_meta.key_aliases` of the plain keys.
"""
from __future__ import annotations

import argparse
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import nvprobe  # noqa: E402

PROVENANCE = "hsetp2-family-2026-11-06"
CTRL = 0x000f_e200 << 96
TABLE_OF = {"SM120": "sm120", "SM103": "sm103a", "SM100": "sm100a"}
CMP = ["F", "LT", "EQ", "LE", "GT", "NE", "GE", "NUM", "NAN", "LTU", "EQU", "LEU", "GTU", "NEU", "GEU", "T"]
BOOL = ["AND", "OR", "XOR"]
SEL = {0: "", 2: ".H0_H0", 3: ".H1_H1", 1: ".INVALID1"}
KEYS = {0: "HSETP2_P_P_R_R_P", 1: "HSETP2_P_P_R_UR_P"}
RETIRED = {"HSETP2.GEU.AND_P_P_R_R_P": "HSETP2_P_P_R_R_P", "HSETP2.GEU.AND_P_P_R_R_R": "HSETP2_P_P_R_R_P",
           "HSETP2.GEU.AND_P_P_R_UR_UR": "HSETP2_P_P_R_UR_P"}
INERT = [*range(16, 24), *range(40, 60), 66, 67, 68, 92, 93, 94, 95]


def word(ur, cmp=14, bool_=0, hand=0, ftz=0, bf16=0, guard=7, pd0=0, pd1=7, ra=2, rb=3, pc=7, npc=0,
         nega=0, absa=0, sela=0, negb=0, absb=0, selb=0, ty=None, extra=0):
    ty = (2 if bf16 else 0) if ty is None else ty
    return ((0xe34 if ur else 0x234) | (ur << 91) | (guard << 12) | (ra << 24) | (rb << 32)
            | (selb << 60) | (absb << 62) | (negb << 63) | (ty << 64) | (bool_ << 69) | (hand << 71)
            | (nega << 72) | (absa << 73) | (sela << 74) | (cmp << 76) | (ftz << 80)
            | (pd0 << 81) | (pd1 << 84) | (pc << 87) | (npc << 90) | extra)


def pred(n, inv=0):
    return ("!" if inv else "") + ("PT" if n == 7 else f"P{n}")


def operand(n, neg, abs_, sel, ur, reuse=0):
    """nvdisasm's operand: `-|R2|.H1_H1` on a register, `-|UR3.H0_H0|` on a uniform register (the selector
    inside the bars -- the BUG-297 law of the UR half-select tokens)."""
    name = ("URZ" if n == 255 else f"UR{n}") if ur else ("RZ" if n == 255 else f"R{n}")
    bar = "|" if abs_ else ""
    body = f"{bar}{name}{SEL[sel]}{bar}" if ur else f"{bar}{name}{bar}{SEL[sel]}"
    return ("-" if neg else "") + body + (".reuse" if reuse else "")


def expected_text(w: int) -> str | None:
    """nvdisasm's text for a word of the family, None where the law says illegal / unnamed."""
    ur = (w >> 91) & 1
    if (w & 0xfff) != (0xe34 if ur else 0x234):
        return None
    ty, bool_ = (w >> 64) & 3, (w >> 69) & 3
    guard = (w >> 12) & 0xf
    g = "" if guard == 7 else (f"@P{guard} " if guard < 7 else ("@!PT " if guard == 15 else f"@!P{guard - 8} "))
    mods = [{0: "", 2: ".BF16_V2", 1: ".INVALID1", 3: ".INVALID3"}[ty], "." + CMP[(w >> 76) & 0xf],
            ".H_AND" if (w >> 71) & 1 else "", ".FTZ" if (w >> 80) & 1 else "", "." + (BOOL + ["INVALID3"])[bool_]]
    ra = operand((w >> 24) & 0xff, (w >> 72) & 1, (w >> 73) & 1, (w >> 74) & 3, 0, (w >> 122) & 1)
    rb = operand((w >> 32) & 0xff, (w >> 63) & 1, (w >> 62) & 1, (w >> 60) & 3, ur, 0 if ur else (w >> 124) & 1)
    return (f"{g}HSETP2{''.join(mods)} {pred((w >> 81) & 7)}, {pred((w >> 84) & 7)}, {ra}, {rb}, "
            f"{pred((w >> 87) & 7, (w >> 90) & 1)}")


def sweep_words():
    out, seen = [], set()

    def add(w, lattice):
        if w not in seen:
            seen.add(w)
            out.append((w, lattice))

    for ur in (0, 1):
        # every legal modifier group on the canonical operands
        for cmp in range(16):
            for bool_ in range(3):
                for hand in (0, 1):
                    for ftz in (0, 1):
                        for bf16 in (0, 1):
                            add(word(ur, cmp, bool_, hand, ftz, bf16), False)
        # the operand lattice on two groups (GEU.AND plain, BF16_V2.LT.H_AND.FTZ.XOR)
        for grp in (dict(), dict(cmp=1, bool_=2, hand=1, ftz=1, bf16=1)):
            for guard in (0, 3, 8, 15):
                add(word(ur, guard=guard, **grp), False)
            for n in range(8):
                add(word(ur, pd0=n, **grp), False)
                add(word(ur, pd1=n, **grp), False)
                add(word(ur, pc=n, **grp), False)
                add(word(ur, pc=n, npc=1, **grp), False)
            for n in (0, 1, 255):
                add(word(ur, ra=n, **grp), False)
            for n in (0, 63, 255):
                add(word(ur, rb=n, **grp), False)
            for sa in (0, 2, 3):
                for sb in (0, 2, 3):
                    add(word(ur, sela=sa, selb=sb, **grp), False)
            for signs in (dict(nega=1), dict(absa=1), dict(nega=1, absa=1), dict(negb=1), dict(absb=1), dict(negb=1, absb=1),
                          dict(nega=1, absa=1, sela=3), dict(negb=1, absb=1, selb=2), dict(nega=1, absa=1, negb=1, absb=1, sela=2, selb=3)):
                add(word(ur, **signs, **grp), False)
            add(word(ur, extra=1 << 122, **grp), False)
            if not ur:
                add(word(ur, extra=1 << 124, **grp), False)
                add(word(ur, extra=(1 << 122) | (1 << 124), **grp), False)
        # one word with every field away from its canonical value
        add(word(ur, cmp=9, bool_=1, hand=1, ftz=1, bf16=1, guard=11, pd0=5, pd1=6, ra=10, rb=20, pc=2, npc=1,
                 nega=1, absa=1, sela=3, negb=1, absb=1, selb=2), False)
        # lattice: the vendor's INVALID codes, the wrong frame bit, the text-inert bits
        add(word(ur, ty=1), True)
        add(word(ur, ty=3), True)
        add(word(ur, bool_=3), True)
        add(word(ur, bool_=3, hand=1), True)
        add(word(ur, sela=1), True)
        add(word(ur, selb=1), True)
        add(word(ur, sela=1, selb=1, nega=1, absb=1), True)
        add(word(ur) ^ (1 << 91), True)
        for bit in INERT:
            add(word(ur) | (1 << bit), True)
        add(word(ur) | (0xff << 16) | (0xfffff << 40), True)
    return out


INERT_MASK = sum(1 << b for b in INERT)


def lattice_ok(w, t):
    if t is None:
        return ((w >> 91) & 1) != ((w & 0xfff) == 0xe34)  # only the frame-bit words are illegal
    return t == expected_text(w & ~INERT_MASK)


def probe(nvdisasm, arch, out, jobs):
    rows = nvprobe.probe_words(nvdisasm, "hsetp2", sweep_words(), CTRL, check_form=lambda w, t: t == expected_text(w),
                               check_lattice=lattice_ok, arch=arch, jobs=jobs)
    nvprobe.write_fixture(out, rows)
    n_form = sum(1 for r in rows if not r.get("lattice"))
    print(f"{out}: {n_form} form words, {len(rows) - n_form} lattice words ({arch})")


NOTE = ("HSETP2 measured with nvdisasm 13.1 (-b SM120 = SM103 = SM100), tools/probes/re_sm120_hsetp2.py (session G, "
        "2026-11-06): guard [15:12], Ra [31:24] (-Ra 72, |Ra| 73, selector [75:74]), Rb / URb [39:32] (selector [61:60], "
        "|Rb| 62, -Rb 63; the uniform form = opcode byte 0xe34 + bit 91), type [65:64] (0 fp16 / 2 BF16_V2; 1, 3 INVALID), "
        "boolean [70:69] (AND / OR / XOR; 3 INVALID), H_AND 71, comparison [79:76], FTZ 80, Pd0 [83:81], Pd1 [86:84], "
        "Pc [89:87] + !Pc 90; selector value 1 is the vendor's .INVALID1 (decoded as the glyph, refused by the encoder); "
        "[23:16], [59:40], 66-68, [95:92] text-inert and fail closed.")


def measured_row(ur, cmp, bool_, hand, ftz, bf16, src=PROVENANCE):
    fields = [nvprobe.field(12, 4, "guard", 0, src), nvprobe.field(81, 3, "pred", 1, src), nvprobe.field(84, 3, "pred", 2, src),
              nvprobe.field(24, 8, "reg", 3, src), nvprobe.field(72, 1, "neg", 3, src), nvprobe.field(73, 1, "abs", 3, src),
              nvprobe.field(74, 2, "hsel", 3, src), nvprobe.field(122, 1, "reuse", 3, src),
              nvprobe.field(32, 8, "ureg" if ur else "reg", 4, src), nvprobe.field(60, 2, "hsel", 4, src),
              nvprobe.field(62, 1, "abs", 4, src), nvprobe.field(63, 1, "neg", 4, src)]
    if not ur:
        fields.append(nvprobe.field(124, 1, "reuse", 4, src))
    fields += [nvprobe.field(87, 3, "pred", 5, src), nvprobe.field(90, 1, "neg", 5, src)]
    base = word(ur, cmp, bool_, hand, ftz, bf16, guard=0, pd0=0, pd1=0, ra=0, rb=0, pc=0)
    return nvprobe.row(base, fields, src, NOTE)


def group_name(cmp, bool_, hand, ftz, bf16):
    mods = [CMP[cmp], BOOL[bool_]] + (["H_AND"] if hand else []) + (["FTZ"] if ftz else []) + (["BF16_V2"] if bf16 else [])
    return ",".join(sorted(mods))


def apply(table_path):
    path = pathlib.Path(table_path)
    table = nvprobe.load_table(path)
    ins = table["instructions"]
    rewritten = 0
    for ur, key in KEYS.items():
        old = ins[key]
        entry = {k: v for k, v in old.items() if k in ("base_op", "ctrl_class", "mercury", "operand_sig", "scheduling")}
        groups = {}
        for cmp in range(16):
            for bool_ in range(3):
                for hand in (0, 1):
                    for ftz in (0, 1):
                        for bf16 in (0, 1):
                            groups[group_name(cmp, bool_, hand, ftz, bf16)] = measured_row(ur, cmp, bool_, hand, ftz, bf16)
        assert set(groups) == set(old["mod_groups"]), "the measured lattice is the harvest's 384 groups"
        entry["mod_groups"] = groups
        entry["_src"] = PROVENANCE
        ins[key] = entry
        rewritten += len(groups)
    aliases = table["_meta"].setdefault("key_aliases", {})
    retired = []
    for junk, target in RETIRED.items():
        if junk in ins:
            del ins[junk]
            aliases[junk] = target
            retired.append(junk)
    prov = table["_meta"]["provenance"]
    rows = [g for e in ins.values() for g in e.get("mod_groups", {}).values()]
    prov["rows_total"] = len(rows)
    prov["rows_without_src"] = sum(1 for g in rows if g.get("_src") is None)
    prov["sources"][PROVENANCE] = {"rows": sum(1 for g in rows if g.get("_src") == PROVENANCE),
                                   "kind": "nvdisasm 13.1 field probe (-b SM120 / SM103 / SM100)", "date": "2026-11-06",
                                   "tool": "tools/probes/re_sm120_hsetp2.py", "test": "tests/sm120_hsetp2.rs"}
    nvprobe.save_table(path, table)
    print(f"{path}: HSETP2 rows rewritten {rewritten}, keys retired {retired}")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("probe")
    p.add_argument("--nvdisasm", default="/usr/local/lib/python3.12/dist-packages/triton/backends/nvidia/bin/nvdisasm")
    p.add_argument("--arch", default="SM120", choices=sorted(TABLE_OF))
    p.add_argument("--out", type=pathlib.Path, default=None)
    p.add_argument("--jobs", type=int, default=1)
    a = sub.add_parser("apply")
    a.add_argument("table")
    args = parser.parse_args()
    if args.command == "probe":
        out = args.out or nvprobe.FIXTURES / f"{TABLE_OF[args.arch]}_hsetp2_nvdisasm.jsonl"
        probe(args.nvdisasm, args.arch, out, args.jobs)
    else:
        apply(args.table)


if __name__ == "__main__":
    main()

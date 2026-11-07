#!/usr/bin/env python3
"""The float set / select / check family (FSET / FSEL / FCHK): measure the whole modifier x operand lattice of the nine
plain keys with nvdisasm and rebuild them from the measurement (session G, 2026-11-07; KNOWN_ISSUES T1 -- the 96-row
FSET "mode grid" of 2026-10-22, the FSEL / FCHK harvest rows and eight junk keys).

Forms (opcode [11:0]; the UR forms carry bit 91, illegal when flipped either way):
  FSET_R_R_R_P   0x20a  `FSET.BF.<cmp>[.FTZ].<bool> Rd, Ra, Rb, Pc`     .reuse Ra 122, Rb 123
  FSET_R_R_FI_P  0x80a  `... Rd, Ra, f32, Pc`                          .reuse Ra 122
  FSET_R_R_UR_P  0xc0a  `... Rd, Ra, URb, Pc`                          .reuse Ra 122
  FSEL_R_R_R_P   0x208  `FSEL[.FTZ] Rd, Ra, Rb, Pc`                    .reuse Ra 122, Rb 123
  FSEL_R_R_FI_P  0x808, FSEL_R_R_UR_P 0xc08                            .reuse Ra 122
  FCHK_P_R_R     0x302  `FCHK Pd, Ra, Rb`                              (no .reuse: text-inert)
  FCHK_P_R_FI    0x902, FCHK_P_R_UR 0xd02

Law (nvdisasm 13.1, one word per call, `-b SM120`; `probe --arch SM103` / `SM100` print the same text for every word):
guard [15:12]; Rd [23:16] (FSET / FSEL); Ra [31:24], `-Ra` 72, `|Ra|` 73; the B operand [39:32] (Rb / URb with `|B|` 62,
`-B` 63) or the f32 immediate [63:32]. FSET = the FSETP law with a register destination: the boolean [75:74] (AND / OR /
XOR; 3 = INVALID3), the comparison [79:76] (F LT EQ LE GT NE GE NUM NAN LTU EQU LEU GTU NEU GEU T), FTZ 80, Pc [89:87]
+ `!` 90; `.BF` is printed on every word (no bit selects an integer-result form on SM120); printed
`FSET.BF.<cmp>[.FTZ].<bool>`. FSEL = FTZ 80 and Pc [89:87] + `!` 90 (`PT` spelled). FCHK = Pd [83:81], no modifier.
Text-inert and fail-closed: the unused part of [61:40] on the register / UR forms, [71:64], 74-90 where unnamed, [95:92].
Immediates as on the FP32 family (nvdisasm's decimals, `+INF ` padded mid-line, the NaN glyphs).

Groups: FSET 96 per key, FSEL 2, FCHK 1 -> 297 rows on 9 keys (FSEL_R_R_II_P, the +QNAN lane, untouched).

`probe [--arch SM120|SM103|SM100] [--jobs N]` writes `tests/fixtures/<table>_fset_fsel_fchk_nvdisasm.jsonl`; `apply
<sm120.json>` rewrites the nine keys (creating FSET_R_R_FI_P / FSET_R_R_UR_P; keeping a row the measurement reproduces
field for field, with its tag) and retires eight junk keys as `_meta.key_aliases`. `FSEL_R_R_II_P` stays: it is the
BUG-178 / BUG-249 canonical `+QNAN` lane (the quiet NaN 0x7fc00000 baked, on every table; `FSEL Rd, Ra, QNAN, Pc`
encodes the canonical payload, `-QNAN` / `+SNAN` refuse) -- measured by that wave, not harvest.
"""
from __future__ import annotations

import argparse
import collections
import pathlib
import struct
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import nvprobe  # noqa: E402
from re_sm120_fsetp_dsetp import BOOL, F32_GLYPHS, F32_IMMS, FCMP, SPECIAL  # noqa: E402

PROVENANCE = "fset-fsel-fchk-family-2026-11-07"
CTRL = 0x000f_e200 << 96
TABLE_OF = {"SM120": "sm120", "SM103": "sm103a", "SM100": "sm100a"}
# key -> (opcode, frame bit 91, mnemonic, B operand kind, reuse bit of B or None)
FORMS = {
    "FSET_R_R_R_P": (0x20a, 0, "FSET", "reg", 123), "FSET_R_R_FI_P": (0x80a, 0, "FSET", "f32", None), "FSET_R_R_UR_P": (0xc0a, 1, "FSET", "ureg", None),
    "FSEL_R_R_R_P": (0x208, 0, "FSEL", "reg", 123), "FSEL_R_R_FI_P": (0x808, 0, "FSEL", "f32", None), "FSEL_R_R_UR_P": (0xc08, 1, "FSEL", "ureg", None),
    "FCHK_P_R_R": (0x302, 0, "FCHK", "reg", None), "FCHK_P_R_FI": (0x902, 0, "FCHK", "f32", None), "FCHK_P_R_UR": (0xd02, 1, "FCHK", "ureg", None),
}
RETIRED = {
    "FSET.BF.F.AND_R_R_R_P": "FSET_R_R_R_P",
    "FSEL_R_R_?_P_P": "FSEL_R_R_FI_P", "FSEL_R_R_II_P_P": "FSEL_R_R_FI_P",
    "FSEL_R_R_R_P_II_?": "FSEL_R_R_R_P", "FSEL_R_R_R_P_II_II_?": "FSEL_R_R_R_P", "FSEL_R_R_R_P_II_II_II_?": "FSEL_R_R_R_P",
    "FSEL_R_R_R_P_P": "FSEL_R_R_R_P",
    "FCHK_P_R_II": "FCHK_P_R_FI",
}


def groups_of(mn):
    if mn == "FSET":
        return {",".join(sorted(["BF", FCMP[c], BOOL[b]] + (["FTZ"] if f else []))): (b << 74) | (c << 76) | (f << 80)
                for c in range(16) for b in range(3) for f in (0, 1)}
    if mn == "FSEL":
        return {"": 0, "FTZ": 1 << 80}
    return {"": 0}


GROUPS = {mn: groups_of(mn) for mn in ("FSET", "FSEL", "FCHK")}


def word(key, mods=0, guard=7, d=4, a=2, b=None, nega=0, absa=0, negb=0, absb=0, pc=7, npc=0, pd=0, reuse=(), extra=0):
    opc, frame, mn, bkind, _ = FORMS[key]
    w = opc | (frame << 91) | (guard << 12) | (a << 24) | (nega << 72) | (absa << 73) | mods
    if mn == "FCHK":
        w |= pd << 81
    else:
        w |= (d << 16) | (pc << 87) | (npc << 90)
    if bkind == "f32":
        w |= (0x3f800000 if b is None else b) << 32
    else:
        w |= ((3 if b is None else b) << 32) | (negb << 63) | (absb << 62)
    for r in reuse:
        w |= 1 << r
    return w | extra


def key_of(w):
    frame = (w >> 91) & 1
    for key, (opc, fb, _, _, _) in FORMS.items():
        if (w & 0xfff) == opc and frame == fb:
            return key
    return None


def pred(n, inv=0):
    return ("!" if inv else "") + ("PT" if n == 7 else f"P{n}")


def expected_parts(w):
    key = key_of(w)
    if key is None:
        return None, None
    _, _, mn, bkind, rb = FORMS[key]
    guard = (w >> 12) & 0xf
    g = "" if guard == 7 else (f"@P{guard} " if guard < 7 else ("@!PT " if guard == 15 else f"@!P{guard - 8} "))
    reg = lambda n, ur: ("URZ" if n == 255 else f"UR{n}") if ur else ("RZ" if n == 255 else f"R{n}")  # noqa: E731
    sign = lambda neg, abs_, body: ("-" if neg else "") + (f"|{body}|" if abs_ else body)  # noqa: E731
    if mn == "FSET":
        mods = f".BF.{FCMP[(w >> 76) & 0xf]}{'.FTZ' if (w >> 80) & 1 else ''}.{(BOOL + ['INVALID3'])[(w >> 74) & 3]}"
    elif mn == "FSEL":
        mods = ".FTZ" if (w >> 80) & 1 else ""
    else:
        mods = ""
    a = sign((w >> 72) & 1, (w >> 73) & 1, reg((w >> 24) & 0xff, False)) + (".reuse" if mn != "FCHK" and (w >> 122) & 1 else "")
    imm = None
    if bkind == "f32":
        imm = struct.unpack("<f", struct.pack("<I", (w >> 32) & 0xffffffff))[0]
        b = "<IMM>"
    else:
        b = sign((w >> 63) & 1, (w >> 62) & 1, reg((w >> 32) & 0xff, bkind == "ureg")) + (".reuse" if rb and (w >> rb) & 1 else "")
    if mn == "FCHK":
        return f"{g}FCHK {pred((w >> 81) & 7)}, {a}, {b}", imm
    return f"{g}{mn}{mods} {reg((w >> 16) & 0xff, False)}, {a}, {b}, {pred((w >> 87) & 7, (w >> 90) & 1)}", imm


def text_ok(w, t):
    tmpl, imm = expected_parts(w)
    if tmpl is None or t is None:
        return False
    if imm is None:
        return t == tmpl
    head, _, rest = tmpl.partition("<IMM>")
    if not t.startswith(head) or not t.endswith(rest):
        return False
    tok = t[len(head):len(t) - len(rest)].strip()
    if imm != imm:
        return tok in ("+QNAN", "-QNAN", "+SNAN", "-SNAN")
    if tok == "-0.0":
        return imm == 0.0 and str(imm).startswith("-")
    val = SPECIAL.get(tok)
    if val is None:
        try:
            val = float(tok)
        except ValueError:
            return False
    return val == imm


def inert_bits(key):
    _, _, mn, bkind, _ = FORMS[key]
    bits = [*range(64, 72), 92, 93, 94, 95]
    if bkind != "f32":
        bits += list(range(40, 62))
    if mn == "FSET":
        bits += list(range(81, 87))
    elif mn == "FSEL":
        bits += list(range(74, 80)) + list(range(81, 87))
    else:
        bits += [*range(16, 24), *range(74, 81), *range(84, 91)]
    return sorted(set(bits))


def sweep_words():
    out, seen = [], set()

    def add(w, kind="form", glyph=False):
        if w not in seen:
            seen.add(w)
            out.append((w, kind, glyph))

    for key, (_, _, mn, bkind, rb) in FORMS.items():
        groups = GROUPS[mn]
        for mods in groups.values():
            add(word(key, mods))
        loaded = {"FSET": "BF,FTZ,NEU,XOR", "FSEL": "FTZ", "FCHK": ""}[mn]
        for mods in (0, groups[loaded]):
            for guard in (0, 3, 8, 15):
                add(word(key, mods, guard=guard))
            for n in (0, 1, 63, 255):
                if mn != "FCHK":
                    add(word(key, mods, d=n))
                add(word(key, mods, a=n))
            for signs in (dict(nega=1), dict(absa=1), dict(nega=1, absa=1)):
                add(word(key, mods, **signs))
            if mn != "FCHK":  # FCHK has no .reuse (text-inert: the audit's `reuse_inert` class, a schedule bit, not a row bit)
                add(word(key, mods, reuse=(122,)))
            if bkind == "f32":
                for imm in F32_IMMS:
                    add(word(key, mods, b=imm))
                for imm in F32_GLYPHS:
                    add(word(key, mods, b=imm), glyph=True)
            else:
                for n in (0, 1, 63, 255):
                    add(word(key, mods, b=n))
                for signs in (dict(negb=1), dict(absb=1), dict(negb=1, absb=1), dict(nega=1, absa=1, negb=1, absb=1)):
                    add(word(key, mods, **signs))
                if rb:
                    add(word(key, mods, reuse=(rb,)))
                    add(word(key, mods, reuse=(122, rb)))
            for n in range(8):
                if mn == "FCHK":
                    add(word(key, mods, pd=n))
                else:
                    add(word(key, mods, pc=n))
                    add(word(key, mods, pc=n, npc=1))
        moved = dict(guard=11, a=10, nega=1, absa=1, reuse=((122,) + ((rb,) if rb else ())) if mn != "FCHK" else ())
        moved.update(dict(pd=5) if mn == "FCHK" else dict(d=17, pc=2, npc=1))
        if bkind == "f32":
            moved["b"] = 0xc2f60000
        else:
            moved.update(b=20, negb=1, absb=1)
        add(word(key, groups[loaded], **moved))
        add(word(key) ^ (1 << 91), "lattice")
        for bit in inert_bits(key):
            add(word(key) | (1 << bit), "lattice")
        if mn == "FSET":
            add(word(key, 3 << 74), "lattice")  # INVALID3
            add(word(key, groups[loaded] | (3 << 74)), "lattice")
    return out


def lattice_ok(w, t):
    key = key_of(w)
    if t is None:
        return key is None
    if key is None:
        return False
    if "INVALID3" in t:
        return FORMS[key][2] == "FSET" and (w >> 74) & 3 == 3
    mask = sum(1 << b for b in inert_bits(key)) | ((1 << 122) if FORMS[key][2] == "FCHK" else 0)
    return text_ok(w & ~mask, t)


def probe(nvdisasm, arch, out, jobs):
    words = sweep_words()
    rows = nvprobe.probe_words(nvdisasm, "fset_fsel_fchk", [(w, kind != "form") for w, kind, _ in words], CTRL, check_form=text_ok,
                               check_lattice=lattice_ok, arch=arch, jobs=jobs)
    for row, (_, _, glyph) in zip(rows, words):
        if glyph:
            row["glyph"] = True
    nvprobe.write_fixture(out, rows)
    n_form = sum(1 for r in rows if not r.get("lattice") and not r.get("glyph"))
    n_glyph = sum(1 for r in rows if r.get("glyph"))
    print(f"{out}: {n_form} form words, {n_glyph} glyph words, {len(rows) - n_form - n_glyph} lattice words ({arch})")


NOTE = ("FSET / FSEL / FCHK measured with nvdisasm 13.1 (-b SM120 = SM103 = SM100), tools/probes/re_sm120_fset_fsel_fchk.py (session G, "
        "2026-11-07): guard [15:12], Rd [23:16] (FSET / FSEL) or Pd [83:81] (FCHK), Ra [31:24] (-Ra 72, |Ra| 73, .reuse 122), the B "
        "operand [39:32] (Rb / URb with |B| 62, -B 63; Rb .reuse 123) or the f32 immediate [63:32]; FSET: the boolean [75:74] "
        "(3 = INVALID3), the comparison [79:76], FTZ 80, Pc [89:87] + ! 90, .BF on every word; FSEL: FTZ 80, Pc [89:87] + ! 90; the "
        "uniform forms = opcode byte 0xc0a / 0xc08 / 0xd02 + bit 91. The unused bits fail closed.")


def measured_row(key, mods, src=PROVENANCE):
    _, _, mn, bkind, rb = FORMS[key]
    fields = [nvprobe.field(12, 4, "guard", 0, src)]
    if mn == "FCHK":
        fields.append(nvprobe.field(81, 3, "pred", 1, src))
    else:
        fields.append(nvprobe.field(16, 8, "reg", 1, src))
    fields += [nvprobe.field(24, 8, "reg", 2, src), nvprobe.field(72, 1, "neg", 2, src), nvprobe.field(73, 1, "abs", 2, src),
               nvprobe.field(122, 1, "reuse", 2, src)]
    if bkind == "f32":
        fields.append(nvprobe.field(32, 32, "f32", 3, src))
    else:
        fields += [nvprobe.field(32, 8, bkind, 3, src), nvprobe.field(62, 1, "abs", 3, src), nvprobe.field(63, 1, "neg", 3, src)]
        if rb:
            fields.append(nvprobe.field(rb, 1, "reuse", 3, src))
    if mn != "FCHK":
        fields += [nvprobe.field(87, 3, "pred", 4, src), nvprobe.field(90, 1, "inv", 4, src)]
    if mn == "FCHK":
        fields = [f for f in fields if f["extraction"] != "reuse"]  # text-inert on FCHK
    base = word(key, mods, guard=0, d=0, a=0, b=0, pc=0, pd=0)
    return nvprobe.row(base, fields, src, NOTE)


def same_row(old, new):
    strip = lambda f: {k: v for k, v in f.items() if k in ("bits", "extraction", "shift", "token_idx")}  # noqa: E731
    return (int(old["and_base"], 16) == int(new["and_base"], 16) and int(old["variable_mask"], 16) == int(new["variable_mask"], 16)
            and sorted(map(repr, map(strip, old["fields"]))) == sorted(map(repr, map(strip, new["fields"]))) and old.get("_src"))


def apply(table_path):
    path = pathlib.Path(table_path)
    table = nvprobe.load_table(path)
    ins = table["instructions"]
    live_before = collections.Counter(g.get("_src") for e in ins.values() for g in e.get("mod_groups", {}).values())
    rewritten = added = kept = 0
    for key, (_, _, mn, _, _) in FORMS.items():
        old = ins.get(key)
        template = ins[{"FSET": "FSET_R_R_R_P", "FSEL": "FSEL_R_R_R_P", "FCHK": "FCHK_P_R_R"}[mn]]
        entry = {k: v for k, v in (old or template).items() if k in ("base_op", "ctrl_class", "mercury", "scheduling")}
        entry["operand_sig"] = key.split("_", 1)[1]
        entry.setdefault("base_op", mn)
        old_groups = old["mod_groups"] if old else {}
        groups = {}
        for name, mods in GROUPS[mn].items():
            row = measured_row(key, mods)
            prev = old_groups.get(name)
            if prev is not None and same_row(prev, row):
                groups[name] = prev
                kept += 1
            else:
                groups[name] = row
                rewritten += prev is not None
                added += prev is None
        missing = set(old_groups) - set(groups)
        assert not missing, f"{key}: harvest groups outside the measured lattice: {missing}"
        entry["mod_groups"] = groups
        entry["_src"] = PROVENANCE
        ins[key] = entry
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
                                   "kind": "nvdisasm 13.1 field probe (-b SM120 / SM103 / SM100)", "date": "2026-11-07",
                                   "tool": "tools/probes/re_sm120_fset_fsel_fchk.py", "test": "tests/sm120_fset_fsel_fchk.rs"}
    live_after = collections.Counter(g.get("_src") for g in rows)
    for s, n in live_before.items():
        if s and s != PROVENANCE and live_after[s] != n and prov["sources"].get(s, {}).get("rows") == n:
            prov["sources"][s]["rows"] = live_after[s]
            print(f"  legend {s}: rows {n} -> {live_after[s]}")
    nvprobe.save_table(path, table)
    print(f"{path}: FSET / FSEL / FCHK rows rewritten {rewritten}, groups added {added}, measured rows kept with their tag {kept}, "
          f"rows with the new tag {prov['sources'][PROVENANCE]['rows']}; {len(retired)} keys retired as aliases: {retired}")


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
        out = args.out or nvprobe.FIXTURES / f"{TABLE_OF[args.arch]}_fset_fsel_fchk_nvdisasm.jsonl"
        probe(args.nvdisasm, args.arch, out, args.jobs)
    else:
        apply(args.table)


if __name__ == "__main__":
    main()

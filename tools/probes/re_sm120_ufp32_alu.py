#!/usr/bin/env python3
"""The uniform-datapath FP32 ALU (UFADD / UFMUL / UFFMA / UFSEL): measure the whole modifier x operand lattice of the
nine plain keys with nvdisasm and rebuild them from the measurement (session G, 2026-11-07; KNOWN_ISSUES T1 -- 150
harvest rows, mostly the 2026-10-22 UFMUL / UFFMA "mode grids", and nine junk keys).

Forms (opcode [11:0] + bit 91 -- the uniform frame, illegal when clear):
  UFADD_UR_UR_UR      0x254  `URd, URa, URb`        URb in the C slot [71:64] (|URb| 74, -URb 75)
  UFADD_UR_UR_FI      0x454  `URd, URa, f32`
  UFMUL_UR_UR_UR      0x256  `URd, URa, URb`        URb at [39:32] (|URb| 62, -URb 63)
  UFMUL_UR_UR_FI      0x856  `URd, URa, f32`
  UFFMA_UR_UR_UR_UR   0x255  `URd, URa, URb, URc`   URb [39:32], URc [71:64]
  UFFMA_UR_UR_UR_FI   0x455  `URd, URa, URc, f32`   the third token's register in the C slot
  UFFMA_UR_UR_FI_UR   0x855  `URd, URa, f32, URc`
  UFSEL_UR_UR_UR_UP   0x251  `URd, URa, URb, UPc`   UPc [89:87] + ! 90
  UFSEL_UR_UR_FI_UP   0x851  `URd, URa, f32, UPc`

Law (nvdisasm 13.1, one word per call, `-b SM120`; the family is SM120-only -- on `-b SM103` / `SM100` nvdisasm
rejects every word of the sweep, like UFSETP): the FP32 ALU law in the uniform datapath -- guard [15:12]
(`@[!]UPn`); URd [23:16]; URa [31:24], `-URa` 72, `|URa|` 73; the B operand at [39:32] or the f32 immediate at
[63:32]; the C slot [71:64]; UFADD `[.FTZ][.RM|.RP|.RZ][.SAT]` (80, [79:78], 77), UFMUL `[.FTZ|.FMZ][.D8|.D4|.D2|
.M2|.M4|.M8][.RM|.RP|.RZ][.SAT]` (80 / 76 -- both = `.INVALID3`; scale [86:84], 4 unspelled, 0 = `.INVALID0`),
UFFMA `[.FTZ|.FMZ][.RM|.RP|.RZ][.SAT]`, UFSEL `[.FTZ]`; no `.reuse` (nvdisasm rejects the bits on the uniform opclass
with an "undefined value for table TABLES_opex" error). Neighbours measured and left unclaimed: bit 81 on the
register forms of UFADD / UFFMA is the mixed-precision UFHADD / UFHFMA (text-inert on the immediate forms).
Text-inert and fail-closed: the unused part of [61:40], [71:64] without a C operand, 74-76 and 81-90 where unnamed,
[95:92]. Immediates as on the vector family (nvdisasm's decimals, the padded `+INF ` mid-line, the NaN glyphs).

Groups: UFADD 16 per key, UFMUL 168, UFFMA 24, UFSEL 2 -> 444 rows on 9 keys.

`probe [--arch SM120|SM103|SM100] [--jobs N]` writes `tests/fixtures/<table>_ufp32_alu_nvdisasm.jsonl`; `apply <sm120.json>`
rewrites the nine keys (keeping a row that the measurement reproduces field for field, with its tag) and retires the
nine junk keys as `_meta.key_aliases` (the `*_II*` / `_L` twins -> the f32 key: the encode path of hexadecimal literals).
"""
from __future__ import annotations

import argparse
import collections
import pathlib
import struct
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import nvprobe  # noqa: E402
from re_sm120_fp32_alu import RND, SCALE, groups_of  # noqa: E402
from re_sm120_fsetp_dsetp import F32_GLYPHS, F32_IMMS, SPECIAL  # noqa: E402

PROVENANCE = "ufp32-alu-family-2026-11-07"
CTRL = 0x000f_e200 << 96
TABLE_OF = {"SM120": "sm120", "SM103": "sm103a", "SM100": "sm100a"}

# operand descriptors after URd: ("ureg", shift, neg_bit, abs_bit), ("f32",), ("upred",)
A = ("ureg", 24, 72, 73)
B = ("ureg", 32, 63, 62)
C = ("ureg", 64, 75, 74)
# key -> (opcode, mnemonic, modifier family, operands after URd)
FORMS = {
    "UFADD_UR_UR_UR": (0x254, "UFADD", "fadd", [A, C]),
    "UFADD_UR_UR_FI": (0x454, "UFADD", "fadd", [A, ("f32",)]),
    "UFMUL_UR_UR_UR": (0x256, "UFMUL", "fmul", [A, B]),
    "UFMUL_UR_UR_FI": (0x856, "UFMUL", "fmul", [A, ("f32",)]),
    "UFFMA_UR_UR_UR_UR": (0x255, "UFFMA", "ffma", [A, B, C]),
    "UFFMA_UR_UR_UR_FI": (0x455, "UFFMA", "ffma", [A, C, ("f32",)]),
    "UFFMA_UR_UR_FI_UR": (0x855, "UFFMA", "ffma", [A, ("f32",), C]),
    "UFSEL_UR_UR_UR_UP": (0x251, "UFSEL", "fsel", [A, B, ("upred",)]),
    "UFSEL_UR_UR_FI_UP": (0x851, "UFSEL", "fsel", [A, ("f32",), ("upred",)]),
}
RETIRED = {
    "UFADD_UR_UR_II": "UFADD_UR_UR_FI", "UFMUL_UR_UR_II": "UFMUL_UR_UR_FI",
    "UFFMA_UR_UR_UR_II": "UFFMA_UR_UR_UR_FI", "UFFMA_UR_UR_UR_L": "UFFMA_UR_UR_UR_FI",
    "UFSEL_UR_UR_?_?": "UFSEL_UR_UR_FI_UP", "UFSEL_UR_UR_?_UP": "UFSEL_UR_UR_FI_UP", "UFSEL_UR_UR_II_?": "UFSEL_UR_UR_FI_UP",
    "UFSEL_UR_UR_II_UP": "UFSEL_UR_UR_FI_UP", "UFSEL_UR_UR_L_UP": "UFSEL_UR_UR_FI_UP",
}


def family_groups(family):
    if family == "fsel":
        return {"": 0, "FTZ": 1 << 80}
    return groups_of(family)


def canonical_modbits(key):
    return (4 << 84) if FORMS[key][2] == "fmul" else 0


def word(key, mods=None, guard=7, d=4, a=2, b=None, c=5, nega=0, absa=0, negb=0, absb=0, negc=0, absc=0, pc=7, npc=0, extra=0):
    opc, _, _, ops = FORMS[key]
    w = opc | (1 << 91) | (guard << 12) | (d << 16) | (a << 24) | (nega << 72) | (absa << 73)
    w |= canonical_modbits(key) if mods is None else mods
    for op in ops[1:]:
        if op[0] == "f32":
            w |= (0x3f800000 if b is None else b) << 32
        elif op[0] == "ureg" and op[1] == 32:
            w |= ((3 if b is None else b) << 32) | (negb << 63) | (absb << 62)
        elif op[0] == "ureg" and op[1] == 64:
            # UFADD's URb lives in the C slot: the `b` / `negb` / `absb` arguments drive it there
            if len(ops) == 2:
                w |= ((5 if b is None else b) << 64) | (negb << 75) | (absb << 74)
            else:
                w |= (c << 64) | (negc << 75) | (absc << 74)
        elif op[0] == "upred":
            w |= (pc << 87) | (npc << 90)
    return w | extra


def key_of(w):
    if not (w >> 91) & 1:
        return None
    for key, (opc, _, _, _) in FORMS.items():
        if (w & 0xfff) == opc:
            return key
    return None


def modifier_text(key, w):
    family = FORMS[key][2]
    ftz, fmz, sat, rnd = (w >> 80) & 1, (w >> 76) & 1, (w >> 77) & 1, RND[(w >> 78) & 3]
    if family == "fadd":
        parts = ["FTZ" if ftz else "", rnd, "SAT" if sat else ""]
    elif family in ("fmul", "ffma"):
        den = {(0, 0): "", (1, 0): "FTZ", (0, 1): "FMZ", (1, 1): "INVALID3"}[(ftz, fmz)]
        parts = [den, SCALE[(w >> 84) & 7] if family == "fmul" else "", rnd, "SAT" if sat else ""]
    else:
        parts = ["FTZ" if ftz else ""]
    return "".join("." + p for p in parts if p)


def upred(n, inv=0):
    return ("!" if inv else "") + ("UPT" if n == 7 else f"UP{n}")


def expected_parts(w):
    key = key_of(w)
    if key is None:
        return None, None
    _, mn, _, ops = FORMS[key]
    guard = (w >> 12) & 0xf
    g = "" if guard == 7 else f"@{upred(guard & 7, guard >> 3)} "
    ureg = lambda n: "URZ" if n == 255 else f"UR{n}"  # noqa: E731
    sign = lambda neg, abs_, body: ("-" if neg else "") + (f"|{body}|" if abs_ else body)  # noqa: E731
    toks = [ureg((w >> 16) & 0xff)]
    imm = None
    for op in ops:
        if op[0] == "ureg":
            _, sh, nb, ab = op
            toks.append(sign((w >> nb) & 1, (w >> ab) & 1, ureg((w >> sh) & 0xff)))
        elif op[0] == "f32":
            imm = struct.unpack("<f", struct.pack("<I", (w >> 32) & 0xffffffff))[0]
            toks.append("<IMM>")
        else:
            toks.append(upred((w >> 87) & 7, (w >> 90) & 1))
    return f"{g}{mn}{modifier_text(key, w)} " + ", ".join(toks), imm


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
    _, _, family, ops = FORMS[key]
    kinds = [op[0] for op in ops]
    bits = [92, 93, 94, 95]
    if "f32" not in kinds:
        bits += list(range(40, 62))
    if not any(op[0] == "ureg" and op[1] == 64 for op in ops):
        bits += list(range(64, 72)) + [74, 75]
    if family == "fadd":
        bits += [76, *range(82, 91)]
    elif family == "ffma":
        bits += list(range(82, 91))
    elif family == "fmul":
        bits += [81, 82, 83, 87, 88, 89, 90]
    else:  # fsel: no rounding / SAT / FMZ / scale
        bits += [76, 77, 78, 79, *range(81, 87)]
    if family in ("fadd", "ffma") and "f32" in kinds:
        bits.append(81)
    return sorted(set(bits))


def neighbour_of(key, w):
    _, _, family, ops = FORMS[key]
    imm = any(op[0] == "f32" for op in ops)
    if family == "fadd" and (w >> 81) & 1 and not imm:
        return "UFHADD"
    if family == "ffma" and (w >> 81) & 1 and not imm:
        return "UFHFMA"
    return None


def sweep_words():
    out, seen = [], set()

    def add(w, kind="form", glyph=False):
        if w not in seen:
            seen.add(w)
            out.append((w, kind, glyph))

    for key, (_, _, family, ops) in FORMS.items():
        groups = family_groups(family)
        for mods in groups.values():
            add(word(key, mods))
        loaded = {"fadd": "FTZ,RZ,SAT", "fmul": "D2,FMZ,RM,SAT", "ffma": "FTZ,RP,SAT", "fsel": "FTZ"}[family]
        kinds = {op[0] for op in ops}
        for mods in (canonical_modbits(key), groups[loaded]):
            for guard in (0, 3, 8, 15):
                add(word(key, mods, guard=guard))
            for n in (0, 1, 63, 255):
                add(word(key, mods, d=n))
                add(word(key, mods, a=n))
            for signs in (dict(nega=1), dict(absa=1), dict(nega=1, absa=1)):
                add(word(key, mods, **signs))
            if "f32" in kinds:
                for imm in F32_IMMS:
                    add(word(key, mods, b=imm))
                for imm in F32_GLYPHS:
                    add(word(key, mods, b=imm), glyph=True)
            else:
                for n in (0, 1, 63, 255):
                    add(word(key, mods, b=n))
                for signs in (dict(negb=1), dict(absb=1), dict(negb=1, absb=1), dict(nega=1, absa=1, negb=1, absb=1)):
                    add(word(key, mods, **signs))
            if len(ops) == 3 and any(op[0] == "ureg" and op[1] == 64 for op in ops):
                for n in (0, 1, 63, 255):
                    add(word(key, mods, c=n))
                for signs in (dict(negc=1), dict(absc=1), dict(negc=1, absc=1), dict(nega=1, absa=1, negc=1, absc=1)):
                    add(word(key, mods, **signs))
            if "upred" in kinds:
                for n in range(8):
                    add(word(key, mods, pc=n))
                    add(word(key, mods, pc=n, npc=1))
        moved = dict(guard=11, d=17, a=10, nega=1, absa=1, pc=2, npc=1)
        if "f32" in kinds:
            moved["b"] = 0xc2f60000
        else:
            moved.update(b=20, negb=1, absb=1)
        if len(ops) == 3 and any(op[0] == "ureg" and op[1] == 64 for op in ops):
            moved.update(c=30, negc=1, absc=1)
        add(word(key, groups[loaded], **moved))
        add(word(key) ^ (1 << 91), "lattice")
        for bit in inert_bits(key):
            add(word(key) | (1 << bit), "lattice")
        if family in ("fmul", "ffma"):
            add(word(key) | (1 << 76) | (1 << 80), "lattice")
            add(word(key, groups[loaded]) | (1 << 80), "lattice")
        if family == "fmul":
            add(word(key, 0), "lattice")
            add(word(key, groups[loaded] & ~(7 << 84)), "lattice")
        if family in ("fadd", "ffma") and "f32" not in kinds:
            add(word(key) | (1 << 81), "neighbour")
            add(word(key, groups[loaded]) | (1 << 81), "neighbour")
    return out


def lattice_ok(w, t):
    key = key_of(w)
    if t is None:
        return key is None
    if key is None:
        return False
    nb = neighbour_of(key, w)
    if nb is not None:
        return t.startswith(nb)
    if "INVALID" in t:
        family = FORMS[key][2]
        return (family in ("fmul", "ffma") and (w >> 76) & 1 and (w >> 80) & 1 and ".INVALID3" in t) or \
            (family == "fmul" and (w >> 84) & 7 == 0 and ".INVALID0" in t)
    return text_ok(w & ~sum(1 << b for b in inert_bits(key)), t)


def probe(nvdisasm, arch, out, jobs):
    words = sweep_words()
    if arch != "SM120":
        rows = nvprobe.probe_words(nvdisasm, "ufp32_alu", [(w, True) for w, _, _ in words], CTRL, check_form=text_ok,
                                   check_lattice=lambda w, t: t is None, arch=arch, jobs=jobs)
        nvprobe.write_fixture(out, rows)
        print(f"{out}: {len(rows)} words, all illegal on {arch} (the uniform float ALU is SM120-only)")
        return
    rows = nvprobe.probe_words(nvdisasm, "ufp32_alu", [(w, kind != "form") for w, kind, _ in words], CTRL, check_form=text_ok,
                               check_lattice=lattice_ok, arch=arch, jobs=jobs)
    for row, (w, kind, glyph) in zip(rows, words):
        if glyph:
            row["glyph"] = True
        if kind == "neighbour":
            row["neighbour"] = neighbour_of(key_of(w), w)
    nvprobe.write_fixture(out, rows)
    n_form = sum(1 for r in rows if not r.get("lattice") and not r.get("glyph"))
    n_glyph = sum(1 for r in rows if r.get("glyph"))
    n_nb = sum(1 for r in rows if r.get("neighbour"))
    print(f"{out}: {n_form} form words, {n_glyph} glyph words, {len(rows) - n_form - n_glyph - n_nb} lattice words, "
          f"{n_nb} neighbour words ({arch})")


NOTE = ("Uniform FP32 ALU measured with nvdisasm 13.1 (-b SM120; illegal on -b SM103 / SM100: the uniform float ALU is SM120-only), "
        "tools/probes/re_sm120_ufp32_alu.py (session G, 2026-11-07): the FP32 ALU law in the uniform datapath -- guard [15:12] (@UPn), "
        "URd [23:16], URa [31:24] (-URa 72, |URa| 73), the B operand [39:32] (|B| 62, -B 63) or the f32 immediate [63:32], the C slot "
        "[71:64] (|C| 74, -C 75; UFADD's URb lives there); UFADD: FTZ 80, rounding [79:78], SAT 77; UFMUL: FTZ 80 / FMZ 76 (both = "
        "INVALID3), scale [86:84] (0 = INVALID0), rounding, SAT; UFFMA: FTZ / FMZ, rounding, SAT; UFSEL: FTZ 80, UPc [89:87] + ! 90; "
        "opcode + bit 91 (clear = illegal); no .reuse (nvdisasm rejects the bits); bit 81 on the register forms of UFADD / UFFMA names "
        "UFHADD / UFHFMA (not modelled). The unused bits fail closed.")


def measured_row(key, mods, src=PROVENANCE):
    _, _, _, ops = FORMS[key]
    fields = [nvprobe.field(12, 4, "guard", 0, src), nvprobe.field(16, 8, "ureg", 1, src)]
    for tok, op in enumerate(ops, start=2):
        if op[0] == "ureg":
            _, sh, nb, ab = op
            fields += [nvprobe.field(sh, 8, "ureg", tok, src), nvprobe.field(nb, 1, "neg", tok, src), nvprobe.field(ab, 1, "abs", tok, src)]
        elif op[0] == "f32":
            fields.append(nvprobe.field(32, 32, "f32", tok, src))
        else:
            fields += [nvprobe.field(87, 3, "upred", tok, src), nvprobe.field(90, 1, "inv", tok, src)]
    base = word(key, mods, guard=0, d=0, a=0, b=0, c=0, pc=0)
    return nvprobe.row(base, fields, src, NOTE)


def same_row(old, new):
    """The old row carries the measured law already (and_base, mask, the same field set)."""
    strip = lambda f: {k: v for k, v in f.items() if k in ("bits", "extraction", "shift", "token_idx")}  # noqa: E731
    return (int(old["and_base"], 16) == int(new["and_base"], 16) and int(old["variable_mask"], 16) == int(new["variable_mask"], 16)
            and sorted(map(repr, map(strip, old["fields"]))) == sorted(map(repr, map(strip, new["fields"]))) and old.get("_src"))


def apply(table_path):
    path = pathlib.Path(table_path)
    table = nvprobe.load_table(path)
    ins = table["instructions"]
    live_before = collections.Counter(g.get("_src") for e in ins.values() for g in e.get("mod_groups", {}).values())
    rewritten = added = kept = 0
    for key, (_, _, family, _) in FORMS.items():
        old = ins.get(key, {"mod_groups": {}})
        entry = {k: v for k, v in old.items() if k in ("base_op", "ctrl_class", "mercury", "operand_sig", "scheduling")}
        entry.setdefault("base_op", key.split("_")[0])
        entry.setdefault("operand_sig", key.split("_", 1)[1])
        groups = {}
        for name, mods in family_groups(family).items():
            row = measured_row(key, mods)
            prev = old["mod_groups"].get(name)
            if prev is not None and same_row(prev, row):
                groups[name] = prev
                kept += 1
            else:
                groups[name] = row
                rewritten += prev is not None
                added += prev is None
        missing = set(old["mod_groups"]) - set(groups)
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
                                   "kind": "nvdisasm 13.1 field probe (-b SM120; the family is illegal on -b SM103 / SM100)", "date": "2026-11-07",
                                   "tool": "tools/probes/re_sm120_ufp32_alu.py", "test": "tests/sm120_ufp32_alu.rs"}
    # a measured row of another source replaced by this measurement (T-10's UFMUL_UR_UR_UR row had no sign fields):
    # keep that source's legend count live where it was live before (tests/sm120_audit_t10.rs pins legend == rows)
    live_after = collections.Counter(g.get("_src") for g in rows)
    for src, n in live_before.items():
        if src and src != PROVENANCE and live_after[src] != n and prov["sources"].get(src, {}).get("rows") == n:
            prov["sources"][src]["rows"] = live_after[src]
            print(f"  legend {src}: rows {n} -> {live_after[src]} (a row of that source re-measured here)")
    nvprobe.save_table(path, table)
    print(f"{path}: uniform FP32 ALU rows rewritten {rewritten}, groups added {added}, measured rows kept with their tag {kept}, "
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
        out = args.out or nvprobe.FIXTURES / f"{TABLE_OF[args.arch]}_ufp32_alu_nvdisasm.jsonl"
        probe(args.nvdisasm, args.arch, out, args.jobs)
    else:
        apply(args.table)


if __name__ == "__main__":
    main()

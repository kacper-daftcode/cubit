#!/usr/bin/env python3
"""The FP32 ALU family (FADD / FMUL / FFMA / FMNMX): measure the whole modifier x operand lattice of the 14 plain keys
with nvdisasm and rebuild them from the measurement (session G, 2026-11-07; KNOWN_ISSUES T1 -- 456 harvest rows of the
2026-10-22 "mode grids" and the 2026-06..08 harvest without a field-by-field measurement, 27 mis-tokenised / dotted /
integer-spelling junk keys).

Forms (opcode [11:0]; bit 91 = the uniform-datapath frame -- set on the UR forms, illegal when flipped either way):
  FADD_R_R_R    0x221  `Rd, Ra, Rb`        .reuse Ra 122, Rb 124 (sic: FADD's Rb reuse bit is the C-slot bit)
  FADD_R_R_FI   0x421  `Rd, Ra, f32`       .reuse Ra 122
  FADD_R_R_UR   0xe21  `Rd, Ra, URb`       .reuse Ra 122
  FMUL_R_R_R    0x220  `Rd, Ra, Rb`        .reuse Ra 122, Rb 123
  FMUL_R_R_FI   0x820  `Rd, Ra, f32`       .reuse Ra 122
  FMUL_R_R_UR   0xc20  `Rd, Ra, URb`       .reuse Ra 122
  FFMA_R_R_R_R  0x223  `Rd, Ra, Rb, Rc`    .reuse Ra 122, Rb 123, Rc 124
  FFMA_R_R_R_FI 0x423  `Rd, Ra, Rc, f32`   the register of the third token sits in the C slot [71:64]; .reuse Ra 122, Rc 123
  FFMA_R_R_FI_R 0x823  `Rd, Ra, f32, Rc`   .reuse Ra 122, Rc 124
  FFMA_R_R_UR_R 0xc23  `Rd, Ra, URb, Rc`   .reuse Ra 122, Rc 124
  FFMA_R_R_R_UR 0xe23  `Rd, Ra, Rb, URc`   Rb in the C slot [71:64], URc at [39:32]; .reuse Ra 122, Rb 123
  FMNMX_R_R_R_P 0x209  `Rd, Ra, Rb, Pc`    .reuse Ra 122, Rb 123
  FMNMX_R_R_FI_P 0x809 `Rd, Ra, f32, Pc`   .reuse Ra 122
  FMNMX_R_R_UR_P 0xc09 `Rd, Ra, URb, Pc`   .reuse Ra 122

Law (nvdisasm 13.1, one word per call, `-b SM120`; `probe --arch SM103` / `SM100` print the same text for every word):
  guard [15:12]; Rd [23:16]; Ra [31:24], `-Ra` 72, `|Ra|` 73; the B operand at [39:32] (Rb / URb with `|B|` 62 and
  `-B` 63) or the f32 immediate at [63:32]; the C slot [71:64] (FFMA: Rc, `|Rc|` 74, `-Rc` 75; text-inert on the
  three-operand mnemonics); modifiers: FADD = `.FTZ` 80, rounding [79:78] (0 RN unspelled, 1 `.RM`, 2 `.RP`, 3 `.RZ`),
  `.SAT` 77, printed `FADD[.FTZ][.RM|.RP|.RZ][.SAT]`; FMUL = denormal mode `.FTZ` 80 / `.FMZ` 76 (both = `.INVALID3`),
  the scale [86:84] (1 `.D8`, 2 `.D4`, 3 `.D2`, 4 unspelled, 5 `.M2`, 6 `.M4`, 7 `.M8`, 0 = `.INVALID0`), rounding,
  `.SAT`, printed `FMUL[.FTZ|.FMZ][.D8|...|.M8][.RM|.RP|.RZ][.SAT]`; FFMA = `FFMA[.FTZ|.FMZ][.RM|.RP|.RZ][.SAT]`
  (no scale); FMNMX = `.FTZ` 80, `.NAN` 81, `.XORSIGN` 82, printed in that order, the min/max predicate Pc [89:87] with
  `!` 90 (`PT` at 7). Neighbours measured and left unclaimed: bit 81 on FADD / FFMA is the mixed-precision FHADD /
  FHFMA (its own mnemonic; FTZ text-inert there), bit 65 on FMNMX is `FMNMX.IS_A Rd, Pd, Ra, Rb, Pc` with Pd at
  [68:66] (not modelled). Text-inert: the unused part of [61:40] on the register / UR forms, [71:64] where no C
  operand exists, 74-76 and 81-90 where unnamed, [95:92]. `.reuse` only on the register operands named above
  (nvdisasm rejects the other reuse bits with an "undefined value for table TABLES_opex" error, not an illegal
  instruction). Immediates print as nvdisasm's decimals, `+INF` / `-INF` / `-0.0` with the vendor's trailing space
  where another operand follows, the NaN payloads as `+QNAN` / `-QNAN` / `+SNAN` glyphs (KNOWN_ISSUES A8; the fixture
  marks those words `glyph`).

Groups: FADD 16 per key (FTZ x SAT x rounding), FMUL 168 (3 denormal modes x 7 scales x 4 roundings x SAT), FFMA 24,
FMNMX 8 (FTZ x NAN x XORSIGN): 696 rows on 14 keys. The harvest had FMUL_R_R_FI / _UR with 3 groups and FADD_R_R_R
with 5 -- the measurement adds the missing groups (the words are legal and nvdisasm names them).

`probe [--arch SM120|SM103|SM100] [--jobs N]` writes `tests/fixtures/<table>_fp32_alu_nvdisasm.jsonl`; `apply <sm120.json>`
rewrites the 14 keys' groups and retires the 27 junk keys as `_meta.key_aliases` of the plain key whose words they
carried (the integer-spelling twins `*_II*` -> the f32 key: the encode path of hexadecimal f32 literals).
"""
from __future__ import annotations

import argparse
import pathlib
import struct
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import nvprobe  # noqa: E402
from re_sm120_fsetp_dsetp import F32_GLYPHS, F32_IMMS, SPECIAL  # noqa: E402

PROVENANCE = "fp32-alu-family-2026-11-07"
CTRL = 0x000f_e200 << 96
TABLE_OF = {"SM120": "sm120", "SM103": "sm103a", "SM100": "sm100a"}
RND = ["", "RM", "RP", "RZ"]
SCALE = ["INVALID0", "D8", "D4", "D2", "", "M2", "M4", "M8"]

# operand descriptors (token 0 = guard, 1 = Rd; the rest in text order):
#   ("reg", shift, neg_bit, abs_bit, reuse_bit | None), ("ureg", shift, neg_bit, abs_bit), ("f32",), ("pred",)
A = ("reg", 24, 72, 73, 122)
B_REG = lambda reuse: ("reg", 32, 63, 62, reuse)  # noqa: E731
B_UR = ("ureg", 32, 63, 62)
C_REG = lambda reuse: ("reg", 64, 75, 74, reuse)  # noqa: E731
# key -> (opcode, frame bit 91, mnemonic, modifier family, operands after Rd)
FORMS = {
    "FADD_R_R_R": (0x221, 0, "FADD", "fadd", [A, B_REG(124)]),
    "FADD_R_R_FI": (0x421, 0, "FADD", "fadd", [A, ("f32",)]),
    "FADD_R_R_UR": (0xe21, 1, "FADD", "fadd", [A, B_UR]),
    "FMUL_R_R_R": (0x220, 0, "FMUL", "fmul", [A, B_REG(123)]),
    "FMUL_R_R_FI": (0x820, 0, "FMUL", "fmul", [A, ("f32",)]),
    "FMUL_R_R_UR": (0xc20, 1, "FMUL", "fmul", [A, B_UR]),
    "FFMA_R_R_R_R": (0x223, 0, "FFMA", "ffma", [A, B_REG(123), C_REG(124)]),
    "FFMA_R_R_R_FI": (0x423, 0, "FFMA", "ffma", [A, C_REG(123), ("f32",)]),
    "FFMA_R_R_FI_R": (0x823, 0, "FFMA", "ffma", [A, ("f32",), C_REG(124)]),
    "FFMA_R_R_UR_R": (0xc23, 1, "FFMA", "ffma", [A, B_UR, C_REG(124)]),
    "FFMA_R_R_R_UR": (0xe23, 1, "FFMA", "ffma", [A, C_REG(123), B_UR]),
    "FMNMX_R_R_R_P": (0x209, 0, "FMNMX", "fmnmx", [A, B_REG(123), ("pred",)]),
    "FMNMX_R_R_FI_P": (0x809, 0, "FMNMX", "fmnmx", [A, ("f32",), ("pred",)]),
    "FMNMX_R_R_UR_P": (0xc09, 1, "FMNMX", "fmnmx", [A, B_UR, ("pred",)]),
}
# junk key -> the plain key whose words it carried (every one a harvest-era mis-tokenisation, a dotted twin with the
# modifier in the key, or the integer spelling of the f32 immediate form)
RETIRED = {
    "FADD.FTZ_P_R_R_R": "FADD_R_R_R", "FADD.FTZ_R_R_R": "FADD_R_R_R", "FADD.RZ_R_R_R": "FADD_R_R_R",
    "FADD_R_L_R": "FADD_R_R_R", "FADD_R_R_L": "FADD_R_R_R", "FADD_R_R_R_?": "FADD_R_R_R", "FADD_R_R_R_II_?": "FADD_R_R_R",
    "FADD_R_R_R_II_II_?": "FADD_R_R_R", "FADD_R_R_R_R": "FADD_R_R_R",
    "FADD.FTZ_R_R_FI": "FADD_R_R_FI", "FADD.FTZ_R_R_II": "FADD_R_R_FI", "FADD_R_R_II": "FADD_R_R_FI",
    "FMUL_R_R_II": "FMUL_R_R_FI", "FMUL_R_R_R_II_?": "FMUL_R_R_R", "FMUL_R_R_R_II_II_?": "FMUL_R_R_R",
    "FMUL_R_R_R_R": "FMUL_R_R_R", "FMUL_R_R_UR_II_II_II_?": "FMUL_R_R_UR",
    "FFMA.RM_R_R_R_R": "FFMA_R_R_R_R", "FFMA.RM_R_R_R_II": "FFMA_R_R_R_FI", "FFMA.SAT_R_R_R_II": "FFMA_R_R_R_FI",
    "FFMA_R_R_R_II": "FFMA_R_R_R_FI", "FFMA_R_R_II_R": "FFMA_R_R_FI_R",
    "FMNMX.NAN_R_R_UR_UR": "FMNMX_R_R_UR_P", "FMNMX.NAN_R_R_UR_UR_?": "FMNMX_R_R_UR_P", "FMNMX_R_R_II_P": "FMNMX_R_R_FI_P",
    "FMNMX_R_R_R_P_II_II_?": "FMNMX_R_R_R_P", "FMNMX_R_R_R_R": "FMNMX_R_R_R_P",
}


def groups_of(family):
    """(group name, modifier bits) for every legal group of the modifier family."""
    out = {}
    if family == "fadd":
        for ftz in (0, 1):
            for sat in (0, 1):
                for rnd in range(4):
                    mods = [m for m in (("FTZ" if ftz else ""), RND[rnd], ("SAT" if sat else "")) if m]
                    out[",".join(sorted(mods))] = (ftz << 80) | (sat << 77) | (rnd << 78)
    elif family in ("fmul", "ffma"):
        for den, dbits in (("", 0), ("FTZ", 1 << 80), ("FMZ", 1 << 76)):
            for sat in (0, 1):
                for rnd in range(4):
                    for sc in (range(1, 8) if family == "fmul" else (0,)):
                        mods = [m for m in (den, SCALE[sc] if family == "fmul" else "", RND[rnd], ("SAT" if sat else "")) if m]
                        out[",".join(sorted(mods))] = dbits | (sat << 77) | (rnd << 78) | ((sc << 84) if family == "fmul" else 0)
    else:
        for ftz in (0, 1):
            for nan in (0, 1):
                for xs in (0, 1):
                    mods = [m for m in (("FTZ" if ftz else ""), ("NAN" if nan else ""), ("XORSIGN" if xs else "")) if m]
                    out[",".join(sorted(mods))] = (ftz << 80) | (nan << 81) | (xs << 82)
    return out


def canonical_modbits(key):
    """The plain group (no modifier; FMUL scale 4)."""
    return (4 << 84) if FORMS[key][3] == "fmul" else 0


def word(key, mods=None, guard=7, d=4, a=2, b=None, c=5, nega=0, absa=0, negb=0, absb=0, negc=0, absc=0, pc=7, npc=0,
         reuse=(), extra=0):
    opc, frame, _, family, ops = FORMS[key]
    w = opc | (frame << 91) | (guard << 12) | (d << 16) | (a << 24) | (nega << 72) | (absa << 73)
    w |= canonical_modbits(key) if mods is None else mods
    for op in ops[1:]:
        if op[0] == "f32":
            w |= (0x3f800000 if b is None else b) << 32
        elif op[0] == "ureg":
            w |= (3 if b is None else b) << 32 | (negb << 63) | (absb << 62)
        elif op[0] == "reg" and op[1] == 32:
            w |= (3 if b is None else b) << 32 | (negb << 63) | (absb << 62)
        elif op[0] == "reg" and op[1] == 64:
            w |= c << 64 | (negc << 75) | (absc << 74)
        elif op[0] == "pred":
            w |= (pc << 87) | (npc << 90)
    for r in reuse:
        w |= 1 << r
    return w | extra


def key_of(w):
    frame = (w >> 91) & 1
    for key, (opc, fb, _, _, _) in FORMS.items():
        if (w & 0xfff) == opc and frame == fb:
            return key
    return None


def modifier_text(key, w):
    family = FORMS[key][3]
    ftz, fmz, sat, rnd = (w >> 80) & 1, (w >> 76) & 1, (w >> 77) & 1, RND[(w >> 78) & 3]
    if family == "fadd":
        parts = ["FTZ" if ftz else "", rnd, "SAT" if sat else ""]
    elif family in ("fmul", "ffma"):
        den = {(0, 0): "", (1, 0): "FTZ", (0, 1): "FMZ", (1, 1): "INVALID3"}[(ftz, fmz)]
        parts = [den, SCALE[(w >> 84) & 7] if family == "fmul" else "", rnd, "SAT" if sat else ""]
    else:
        parts = ["FTZ" if ftz else "", "NAN" if (w >> 81) & 1 else "", "XORSIGN" if (w >> 82) & 1 else ""]
    return "".join("." + p for p in parts if p)


def expected_parts(w):
    """(text with the immediate as `<IMM>`, immediate value or None); None where the law says illegal."""
    key = key_of(w)
    if key is None:
        return None, None
    _, _, mn, _, ops = FORMS[key]
    guard = (w >> 12) & 0xf
    g = "" if guard == 7 else (f"@P{guard} " if guard < 7 else ("@!PT " if guard == 15 else f"@!P{guard - 8} "))
    reg = lambda n, ur: ("URZ" if n == 255 else f"UR{n}") if ur else ("RZ" if n == 255 else f"R{n}")  # noqa: E731
    sign = lambda neg, abs_, body: ("-" if neg else "") + (f"|{body}|" if abs_ else body)  # noqa: E731
    toks = [reg((w >> 16) & 0xff, False)]
    imm = None
    for op in ops:
        if op[0] == "reg":
            _, sh, nb, ab, rb = op
            t = sign((w >> nb) & 1, (w >> ab) & 1, reg((w >> sh) & 0xff, False))
            if rb is not None and (w >> rb) & 1:
                t += ".reuse"
            toks.append(t)
        elif op[0] == "ureg":
            _, sh, nb, ab = op
            toks.append(sign((w >> nb) & 1, (w >> ab) & 1, reg((w >> sh) & 0xff, True)))
        elif op[0] == "f32":
            imm = struct.unpack("<f", struct.pack("<I", (w >> 32) & 0xffffffff))[0]
            toks.append("<IMM>")
        else:
            n = (w >> 87) & 7
            toks.append(("!" if (w >> 90) & 1 else "") + ("PT" if n == 7 else f"P{n}"))
    return f"{g}{mn}{modifier_text(key, w)} " + ", ".join(toks), imm


def text_ok(w, t):
    """The vendor text matches the law; a numeric immediate is compared as a number (nvdisasm's own decimal
    spelling is recorded in the fixture), the NaN glyphs by name; the vendor pads `+INF` / `-INF` / `-0.0` with a
    space where another operand follows."""
    tmpl, imm = expected_parts(w)
    if tmpl is None or t is None:
        return False
    if imm is None:
        return t == tmpl
    head, _, rest = tmpl.partition("<IMM>")
    if not t.startswith(head) or not t.endswith(rest):
        return False
    tok = t[len(head):len(t) - len(rest)].strip()
    if imm != imm:  # NaN: the vendor glyph
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
    _, _, _, family, ops = FORMS[key]
    bits = [92, 93, 94, 95]
    kinds = [op[0] for op in ops]
    if "f32" not in kinds:
        bits += list(range(40, 62))
    if not any(op[0] == "reg" and op[1] == 64 for op in ops):
        bits += list(range(64, 72)) + [74, 75]
    if family == "fadd":
        bits += [76, *range(82, 91)]
    elif family == "ffma":
        bits += list(range(82, 91))
    if family in ("fadd", "ffma") and "f32" in kinds:
        bits.append(81)  # the mixed-precision neighbour has no immediate form: bit 81 is text-inert there
    if family == "fmul":
        bits += [81, 82, 83, 87, 88, 89, 90]
    else:  # fmnmx: bit 65 is the IS_A neighbour, [68:66] its predicate (inert without 65); 76-79 and 83-86 unnamed
        bits = [b for b in bits if b != 65] + [76, 77, 78, 79, 83, 84, 85, 86]
    return sorted(set(bits))


def neighbour_of(key, w):
    """The other mnemonic a lattice word names, or None."""
    _, _, _, family, ops = FORMS[key]
    imm = any(op[0] == "f32" for op in ops)
    if family == "fadd" and (w >> 81) & 1 and not imm:
        return "FHADD"
    if family == "ffma" and (w >> 81) & 1 and not imm:
        return "FHFMA"
    if family == "fmnmx" and (w >> 65) & 1:
        return "FMNMX.IS_A"
    return None


def sweep_words():
    """(word, kind, glyph): kind = "form" | "lattice" | "neighbour"."""
    out, seen = [], set()

    def add(w, kind="form", glyph=False):
        if w not in seen:
            seen.add(w)
            out.append((w, kind, glyph))

    for key, (_, _, _, family, ops) in FORMS.items():
        groups = groups_of(family)
        for mods in groups.values():
            add(word(key, mods))
        loaded = {"fadd": "FTZ,RZ,SAT", "fmul": "D2,FMZ,RM,SAT", "ffma": "FTZ,RP,SAT", "fmnmx": "FTZ,NAN,XORSIGN"}[family]
        for mods in (canonical_modbits(key), groups[loaded]):
            for guard in (0, 3, 8, 15):
                add(word(key, mods, guard=guard))
            for n in (0, 1, 63, 255):
                add(word(key, mods, d=n))
                add(word(key, mods, a=n))
            for signs in (dict(nega=1), dict(absa=1), dict(nega=1, absa=1)):
                add(word(key, mods, **signs))
            add(word(key, mods, reuse=(122,)))
            kinds = {op[0]: op for op in ops}
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
            c_op = next((op for op in ops if op[0] == "reg" and op[1] == 64), None)
            if c_op is not None:
                for n in (0, 1, 63, 255):
                    add(word(key, mods, c=n))
                for signs in (dict(negc=1), dict(absc=1), dict(negc=1, absc=1), dict(nega=1, absa=1, negc=1, absc=1)):
                    add(word(key, mods, **signs))
            reuse_bits = [op[4] for op in ops if op[0] == "reg" and op[4] is not None]
            for rb in reuse_bits[1:]:
                add(word(key, mods, reuse=(rb,)))
            add(word(key, mods, reuse=tuple(reuse_bits)))
            if "pred" in kinds:
                for n in range(8):
                    add(word(key, mods, pc=n))
                    add(word(key, mods, pc=n, npc=1))
        # one word per key with every field away from its canonical value
        moved = dict(guard=11, d=17, a=10, nega=1, absa=1, pc=2, npc=1, reuse=tuple(op[4] for op in ops if op[0] == "reg" and op[4]))
        if "f32" in {op[0] for op in ops}:
            moved["b"] = 0xc2f60000  # -123.0
        else:
            moved.update(b=20, negb=1, absb=1)
        if any(op[0] == "reg" and op[1] == 64 for op in ops):
            moved.update(c=30, negc=1, absc=1)
        add(word(key, groups[loaded], **moved))
        # lattice: the frame bit, the text-inert bits, the INVALID modifier states, the neighbouring mnemonics
        add(word(key) ^ (1 << 91), "lattice")
        for bit in inert_bits(key):
            add(word(key) | (1 << bit), "lattice")
        if family in ("fmul", "ffma"):
            add(word(key) | (1 << 76) | (1 << 80), "lattice")
            add(word(key, groups[loaded]) | (1 << 80), "lattice")
        if family == "fmul":
            add(word(key, 0), "lattice")
            add(word(key, groups[loaded] & ~(7 << 84)), "lattice")
        if family in ("fadd", "ffma") and "f32" not in {op[0] for op in ops}:
            add(word(key) | (1 << 81), "neighbour")
            add(word(key, groups[loaded]) | (1 << 81), "neighbour")
        if family == "fmnmx":
            add(word(key) | (1 << 65), "neighbour")
            add(word(key, groups[loaded]) | (1 << 65) | (3 << 66), "neighbour")
    return out


def lattice_ok(w, t):
    key = key_of(w)
    if t is None:
        return key is None
    if key is None:
        return False
    nb = neighbour_of(key, w)
    if nb is not None:
        return t.startswith(nb.split(".")[0]) and (nb.split(".")[-1] in t)
    if "INVALID" in t:
        family = FORMS[key][3]
        return (family in ("fmul", "ffma") and (w >> 76) & 1 and (w >> 80) & 1 and ".INVALID3" in t) or \
            (family == "fmul" and (w >> 84) & 7 == 0 and ".INVALID0" in t)
    return text_ok(w & ~sum(1 << b for b in inert_bits(key)), t)


def probe(nvdisasm, arch, out, jobs):
    words = sweep_words()
    rows = nvprobe.probe_words(nvdisasm, "fp32_alu", [(w, kind != "form") for w, kind, _ in words], CTRL, check_form=text_ok,
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


NOTE = ("FP32 ALU measured with nvdisasm 13.1 (-b SM120 = SM103 = SM100), tools/probes/re_sm120_fp32_alu.py (session G, "
        "2026-11-07): guard [15:12], Rd [23:16], Ra [31:24] (-Ra 72, |Ra| 73, .reuse 122), the B operand [39:32] (Rb / URb "
        "with |B| 62, -B 63) or the f32 immediate [63:32], the C slot [71:64] (FFMA: |Rc| 74, -Rc 75); FADD: FTZ 80, rounding "
        "[79:78] (RM / RP / RZ), SAT 77; FMUL: FTZ 80 / FMZ 76 (both = INVALID3), scale [86:84] (D8 D4 D2 - M2 M4 M8; 0 = "
        "INVALID0), rounding, SAT; FFMA: FTZ / FMZ, rounding, SAT; FMNMX: FTZ 80, NAN 81, XORSIGN 82, Pc [89:87] + ! 90. "
        "The uniform forms = opcode byte 0xe21 / 0xc20 / 0xc23 / 0xe23 / 0xc09 + bit 91. Bit 81 on FADD / FFMA names FHADD / "
        "FHFMA, bit 65 on FMNMX names FMNMX.IS_A (not modelled; fail closed). The unused bits fail closed.")


def measured_row(key, mods, src=PROVENANCE):
    _, _, _, _, ops = FORMS[key]
    fields = [nvprobe.field(12, 4, "guard", 0, src), nvprobe.field(16, 8, "reg", 1, src)]
    for tok, op in enumerate(ops, start=2):
        if op[0] == "reg":
            _, sh, nb, ab, rb = op
            fields += [nvprobe.field(sh, 8, "reg", tok, src), nvprobe.field(nb, 1, "neg", tok, src), nvprobe.field(ab, 1, "abs", tok, src)]
            if rb is not None:
                fields.append(nvprobe.field(rb, 1, "reuse", tok, src))
        elif op[0] == "ureg":
            _, sh, nb, ab = op
            fields += [nvprobe.field(sh, 8, "ureg", tok, src), nvprobe.field(nb, 1, "neg", tok, src), nvprobe.field(ab, 1, "abs", tok, src)]
        elif op[0] == "f32":
            fields.append(nvprobe.field(32, 32, "f32", tok, src))
        else:  # the predicate's `!` is spelled `neg` on the FMNMX rows of all four tables (bug247's structural pin)
            fields += [nvprobe.field(87, 3, "pred", tok, src), nvprobe.field(90, 1, "neg", tok, src)]
    base = word(key, mods, guard=0, d=0, a=0, b=0, c=0, pc=0)
    return nvprobe.row(base, fields, src, NOTE)


def apply(table_path):
    path = pathlib.Path(table_path)
    table = nvprobe.load_table(path)
    ins = table["instructions"]
    rewritten = added = 0
    for key, (_, _, _, family, _) in FORMS.items():
        old = ins[key]
        entry = {k: v for k, v in old.items() if k in ("base_op", "ctrl_class", "mercury", "operand_sig", "scheduling")}
        groups = {name: measured_row(key, mods) for name, mods in groups_of(family).items()}
        missing = set(old["mod_groups"]) - set(groups)
        assert not missing, f"{key}: harvest groups outside the measured lattice: {missing}"
        added += len(set(groups) - set(old["mod_groups"]))
        rewritten += len(old["mod_groups"])
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
                                   "tool": "tools/probes/re_sm120_fp32_alu.py", "test": "tests/sm120_fp32_alu.rs"}
    nvprobe.save_table(path, table)
    print(f"{path}: FP32 ALU rows rewritten {rewritten}, groups added {added}, measured rows {prov['sources'][PROVENANCE]['rows']}; "
          f"{len(retired)} keys retired as aliases: {retired}")


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
        out = args.out or nvprobe.FIXTURES / f"{TABLE_OF[args.arch]}_fp32_alu_nvdisasm.jsonl"
        probe(args.nvdisasm, args.arch, out, args.jobs)
    else:
        apply(args.table)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""The float conversions F2I / I2F / FRND and the MUFU transcendentals: measure the whole type x modifier x operand
lattice of the 12 plain keys with nvdisasm and rebuild them from the measurement (session G, 2026-11-07; KNOWN_ISSUES
T1 -- 195 harvest rows, 207 dotted F2I keys with one row each, the dotted I2F / FRND samples, the integer-spelling
MUFU twin).

Opcodes (two paths per conversion -- the "32-bit" opcode and the "64-bit" one -- x three operand forms: register
[11:9] = 1, immediate 4 (0x9xx), uniform register 6 + bit 91 (0xdxx)):
  F2I   0x305 / 0x311   `F2I[.FTZ][.dst][.src][.FLOOR|.CEIL|.TRUNC][.NTZ] Rd, [-|]Ra[|]`
  I2F   0x306 / 0x312   `I2F[.dst][.src][.RM|.RP|.RZ] Rd, Ra[.B1|.B2|.B3|.H1]`
  FRND  0x307 / 0x313   `FRND[.FTZ][.type][.FLOOR|.CEIL|.TRUNC] Rd, [-|]Ra[|]`
  MUFU  0x308           `MUFU.<fn>[.F16|.BF16] Rd, [-|]Ra[|]`
  keys: F2I_R_{R,UR,FI}, I2F_R_{R,UR,II}, FRND_R_{R,UR,FI}, MUFU_R_{R,UR,FI}

Law (nvdisasm 13.1, one word per call, `-b SM120`; `probe --arch SM103` / `SM100` print the same text for every
word): guard [15:12]; Rd [23:16]; the source at [39:32] (Ra / URa; the immediate at [63:32]: f32, the f16 / bf16 half
at [47:32] with [63:48] text-inert, the high dword of the f64, or the integer); `|Ra|` 62, `-Ra` 63 on F2I / FRND /
MUFU (text-inert on I2F); no `.reuse` (the bits are text-inert on the whole family and 0 census words carry them).
  F2I: destination width [76:75] (0 = 8, 1 = 16, 2 = 32, 3 = 64) + signed 72 (S32 unspelled; width 3 on the 0x305
  path prints the vendor glyph `???6` / `???7`), source type [86:84] (1 F16, 2 F32 unspelled, 3 F64, 4 BF16; the
  others illegal); the 0x311 path carries the 64-bit destinations and the F64 source (the 0x305 path everything
  else); NTZ 77; rounding [79:78] (0 RN unspelled, 1 FLOOR, 2 CEIL, 3 TRUNC); FTZ 80. 32 (dst, src) pairs x 16 = 512 groups.
  I2F: destination type [77:75] (1 F16, 2 F32 unspelled, 3 F64 -- on the 0x312 path only --, 4 BF16; 0 / 5 / 6 / 7 =
  the `???n` glyphs), source width [85:84] (bit 86 text-inert; 3 = 64-bit, 0x312 path) + signed 74 (S32 unspelled),
  rounding [79:78]; the 8-bit sources take the byte selector [61:60] (`.B1` .. `.B3`), the 16-bit ones `.H1` at 60
  (61 = the `INVALID2` glyph) -- and so do the F16 / BF16 sources of F2I / FRND / MUFU (`-|R2.H1|`: the selector
  composes inside the sign wrapper, on R and UR alike); the immediate form exists for the 32- and 64-bit sources only and prints the integer
  as a signed hexadecimal for the signed types, unsigned otherwise. 4 x 8 x 4 = 128 groups (64 on the immediate key).
  FRND: type [77:75] = [86:84] (1 F16, 2 F32 unspelled, 4 BF16; 3 F64 on the 0x313 path -- every other pair of the
  0x313 path is a `???n` glyph), FTZ 80, rounding [79:78] (FLOOR / CEIL / TRUNC). 4 x 2 x 4 = 32 groups.
  MUFU: function [77:74] (COS SIN EX2 LG2 RCP RSQ RCP64H RSQ64H SQRT TANH; 10..15 = INVALIDn), half type [73:72]
  (1 F16, 2 BF16, 3 illegal; RCP64H / RSQ64H with a half type = INVALID6 / INVALID7); the immediate follows the type
  (f32, the half, the f64 high dword for RCP64H / RSQ64H). 10 + 8 x 2 = 26 groups.
  Text-inert and fail-closed: [71:64] on the whole family, [61:40] on the register / UR forms (less the I2F
  selectors), 73-74 / 81-83 / 87-90 on F2I, 62-63 / 72-73 / 80-83 / 86-90 on I2F, 72-74 / 81-83 / 87-90 on FRND,
  78-90 on MUFU, [95:92]; the vendor-invalid glyph states and the illegal combinations have no row.

`probe [--arch SM120|SM103|SM100] [--jobs N]` writes `tests/fixtures/<table>_conv_nvdisasm.jsonl`; `apply <sm120.json>`
rewrites the 12 keys (creating F2I_R_FI, I2F_R_II, FRND_R_UR, FRND_R_FI; keeping a row that the measurement
reproduces field for field, with its tag -- T's 26 MUFU_R_UR rows) and retires every dotted F2I / I2F / FRND key and
the integer-spelling MUFU_R_II twin as `_meta.key_aliases` of the plain key with the same operand signature.
"""
from __future__ import annotations

import argparse
import collections
import pathlib
import struct
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import nvprobe  # noqa: E402
from re_sm120_fsetp_dsetp import F32_GLYPHS, F32_IMMS, SPECIAL  # noqa: E402

PROVENANCE = "conv-family-2026-11-07"
CTRL = 0x000f_e200 << 96
TABLE_OF = {"SM120": "sm120", "SM103": "sm103a", "SM100": "sm100a"}
RND_F2I = ["", "FLOOR", "CEIL", "TRUNC"]
RND_I2F = ["", "RM", "RP", "RZ"]
MUFU_FN = ["COS", "SIN", "EX2", "LG2", "RCP", "RSQ", "RCP64H", "RSQ64H", "SQRT", "TANH"]
INT_TYPES = [("U8", 0, 0), ("S8", 0, 1), ("U16", 1, 0), ("S16", 1, 1), ("U32", 2, 0), ("S32", 2, 1), ("U64", 3, 0), ("S64", 3, 1)]
F2I_SRC = [("F16", 1), ("F32", 2), ("F64", 3), ("BF16", 4)]
I2F_DST = [("F16", 1), ("F32", 2), ("F64", 3), ("BF16", 4)]
FRND_T = [("F16", 1), ("F32", 2), ("F64", 3), ("BF16", 4)]
IMM_OF = {"F16": "f16", "F32": "f32", "F64": "f64hi", "BF16": "bf16"}
# key -> (mnemonic, form); form "R" (0x3xx), "UR" (0xdxx + 91), "I" (0x9xx)
FORMS = {
    "F2I_R_R": ("F2I", "R"), "F2I_R_UR": ("F2I", "UR"), "F2I_R_FI": ("F2I", "I"),
    "I2F_R_R": ("I2F", "R"), "I2F_R_UR": ("I2F", "UR"), "I2F_R_II": ("I2F", "I"),
    "FRND_R_R": ("FRND", "R"), "FRND_R_UR": ("FRND", "UR"), "FRND_R_FI": ("FRND", "I"),
    "MUFU_R_R": ("MUFU", "R"), "MUFU_R_UR": ("MUFU", "UR"), "MUFU_R_FI": ("MUFU", "I"),
}
BASE_OPC = {"F2I": (0x305, 0x311), "I2F": (0x306, 0x312), "FRND": (0x307, 0x313), "MUFU": (0x308, 0x308)}


def name_of(tokens):
    return ",".join(sorted(t for t in tokens if t))


def groups_of(mn):
    """name -> dict(opc=12-bit opcode of the register form, bits=modifier bits in [90:72] and [86:84], imm=immediate
    kind, sel=the I2F source selector kind, signed=the I2F immediate sign)."""
    out = {}
    if mn == "F2I":
        for dname, width, signed in INT_TYPES:
            for sname, scode in F2I_SRC:
                opc = 0x311 if (width == 3 or sname == "F64") else 0x305
                for ftz in (0, 1):
                    for rnd in range(4):
                        for ntz in (0, 1):
                            bits = (width << 75) | (signed << 72) | (scode << 84) | (ftz << 80) | (rnd << 78) | (ntz << 77)
                            name = name_of([dname if dname != "S32" else "", sname if sname != "F32" else "", "FTZ" if ftz else "",
                                            RND_F2I[rnd], "NTZ" if ntz else ""])
                            out[name] = dict(opc=opc, bits=bits, imm=IMM_OF[sname], sel="half" if sname in ("F16", "BF16") else None, signed=None)
    elif mn == "I2F":
        for dname, dcode in I2F_DST:
            for sname, width, signed in INT_TYPES:
                opc = 0x312 if (dname == "F64" or width == 3) else 0x306
                for rnd in range(4):
                    bits = (dcode << 75) | (width << 84) | (signed << 74) | (rnd << 78)
                    name = name_of([dname if dname != "F32" else "", sname if sname != "S32" else "", RND_I2F[rnd]])
                    out[name] = dict(opc=opc, bits=bits, imm="imm" if width >= 2 else None, sel={0: "byte", 1: "half"}.get(width), signed=signed)
    elif mn == "FRND":
        for tname, tcode in FRND_T:
            opc = 0x313 if tname == "F64" else 0x307
            for ftz in (0, 1):
                for rnd in range(4):
                    bits = (tcode << 75) | (tcode << 84) | (ftz << 80) | (rnd << 78)
                    out[name_of([tname if tname != "F32" else "", "FTZ" if ftz else "", RND_F2I[rnd]])] = dict(
                        opc=opc, bits=bits, imm=IMM_OF[tname], sel="half" if tname in ("F16", "BF16") else None, signed=None)
    else:
        for fn, fname in enumerate(MUFU_FN):
            for half, hname in ((0, ""), (1, "F16"), (2, "BF16")):
                if half and fn in (6, 7):
                    continue
                imm = {0: "f64hi" if fn in (6, 7) else "f32", 1: "f16", 2: "bf16"}[half]
                out[name_of([fname, hname])] = dict(opc=0x308, bits=(fn << 74) | (half << 72), imm=imm, sel="half" if half else None, signed=None)
    return out


GROUPS = {mn: groups_of(mn) for mn in BASE_OPC}
PLAIN = {"F2I": "", "I2F": "", "FRND": "", "MUFU": "RCP"}  # the canonical group of the sweeps


def form_opc(opc, form):
    return {"R": opc, "UR": (opc & 0x1ff) | 0xc00 | (1 << 91), "I": (opc & 0x1ff) | 0x800}[form]


def canonical_imm(kind):
    return {"f32": 0x3f800000, "f16": 0x3c00, "bf16": 0x3f80, "f64hi": 0x3ff00000, "imm": 0x10}[kind]


def word(key, group=None, guard=7, d=4, a=2, nega=0, absa=0, sel=0, imm=None, extra=0):
    mn, form = FORMS[key]
    g = GROUPS[mn][group if group is not None else PLAIN[mn]]
    w = form_opc(g["opc"], form) | g["bits"] | (guard << 12) | (d << 16)
    if form == "I":
        w |= (canonical_imm(g["imm"]) if imm is None else imm) << 32
    else:
        w |= (a << 32) | (nega << 63) | (absa << 62) | (sel << 60)
    return w | extra


def key_of(w):
    frame = (w >> 91) & 1
    for key, (mn, form) in FORMS.items():
        opcs = {form_opc(o, form) & 0xfff for o in BASE_OPC[mn]}
        if (w & 0xfff) in opcs and frame == (1 if form == "UR" else 0):
            return key
    return None


def group_of(w):
    """The group a word's opcode + modifier bits select, or None (an invalid / unmodelled state)."""
    key = key_of(w)
    if key is None:
        return None, None
    mn, form = FORMS[key]
    for name, g in GROUPS[mn].items():
        if (w & 0xfff) == (form_opc(g["opc"], form) & 0xfff) and (w & MODMASK[mn]) == g["bits"]:
            if form == "I" and g["imm"] is None:
                return key, None
            return key, name
    return key, None


MODMASK = {"F2I": (3 << 75) | (1 << 72) | (7 << 84) | (1 << 80) | (3 << 78) | (1 << 77),
           "I2F": (7 << 75) | (3 << 84) | (1 << 74) | (3 << 78),
           "FRND": (7 << 75) | (7 << 84) | (1 << 80) | (3 << 78),
           "MUFU": (0xf << 74) | (3 << 72)}


def modifier_text(mn, name):
    toks = [t for t in name.split(",") if t]
    if mn == "F2I":
        order = ["FTZ"] + [t[0] for t in INT_TYPES] + [t[0] for t in F2I_SRC] + ["FLOOR", "CEIL", "TRUNC", "NTZ"]
    elif mn == "I2F":
        order = [t[0] for t in I2F_DST] + [t[0] for t in INT_TYPES] + ["RM", "RP", "RZ"]
    elif mn == "FRND":
        order = ["FTZ"] + [t[0] for t in FRND_T] + ["FLOOR", "CEIL", "TRUNC"]
    else:
        order = MUFU_FN + ["F16", "BF16"]
    return "".join("." + t for t in sorted(toks, key=order.index))


def imm_value(kind, bits32):
    if kind == "f32":
        return struct.unpack("<f", struct.pack("<I", bits32))[0]
    if kind == "f16":
        return struct.unpack("<e", struct.pack("<H", bits32 & 0xffff))[0]
    if kind == "bf16":
        return struct.unpack("<f", struct.pack("<I", (bits32 & 0xffff) << 16))[0]
    if kind == "f64hi":
        return struct.unpack("<d", struct.pack("<Q", bits32 << 32))[0]
    return bits32


def expected_parts(w):
    key, name = group_of(w)
    if name is None:
        return None, None, None
    mn, form = FORMS[key]
    g = GROUPS[mn][name]
    guard = (w >> 12) & 0xf
    gtxt = "" if guard == 7 else (f"@P{guard} " if guard < 7 else ("@!PT " if guard == 15 else f"@!P{guard - 8} "))
    reg = lambda n, ur: ("URZ" if n == 255 else f"UR{n}") if ur else ("RZ" if n == 255 else f"R{n}")  # noqa: E731
    rd = reg((w >> 16) & 0xff, False)
    if form == "I":
        return f"{gtxt}{mn}{modifier_text(mn, name)} {rd}, <IMM>", g["imm"], (w >> 32) & 0xffffffff
    src = reg((w >> 32) & 0xff, form == "UR")
    if g["sel"] == "byte" and (w >> 60) & 3:
        src += f".B{(w >> 60) & 3}"
    elif g["sel"] == "half" and (w >> 60) & 1:
        src += ".H1"  # inside the sign wrapper: `-|R2.H1|`
    if mn != "I2F":
        if (w >> 62) & 1:
            src = f"|{src}|"
        if (w >> 63) & 1:
            src = "-" + src
    return f"{gtxt}{mn}{modifier_text(mn, name)} {rd}, {src}", None, None


def text_ok(w, t):
    tmpl, kind, bits = expected_parts(w)
    if tmpl is None or t is None:
        return False
    if kind is None:
        return t == tmpl
    head, _, rest = tmpl.partition("<IMM>")
    if not t.startswith(head) or not t.endswith(rest):
        return False
    tok = t[len(head):len(t) - len(rest)].strip()
    if kind == "imm":
        key, name = group_of(w)
        signed = GROUPS["I2F"][name]["signed"]
        val = bits - (1 << 32) if (signed and bits >= 1 << 31) else bits
        return tok == (f"-0x{-val:x}" if val < 0 else f"0x{val:x}")
    val = imm_value(kind, bits)
    if val != val:
        return tok in ("+QNAN", "-QNAN", "+SNAN", "-SNAN")
    if tok == "-0.0":
        return val == 0.0 and str(val).startswith("-")
    sp = SPECIAL.get(tok)
    if sp is None:
        try:
            sp = float(tok)
        except ValueError:
            return False
    return sp == val


def inert_bits(key):
    mn, form = FORMS[key]
    bits = [*range(64, 72), 92, 93, 94, 95]
    if form != "I":
        bits += list(range(40, 62))  # incl. [61:60]: the canonical I2F group is S32 -> F32, no selector there
    if mn == "F2I":
        bits += [73, 74, 81, 82, 83, 87, 88, 89, 90]
    elif mn == "I2F":
        bits += [72, 73, 80, 81, 82, 83, 86, 87, 88, 89, 90] + ([62, 63] if form != "I" else [])
    elif mn == "FRND":
        bits += [72, 73, 74, 81, 82, 83, 87, 88, 89, 90]
    else:
        bits += list(range(78, 91))
    return sorted(set(bits))


def sweep_words():
    out, seen = [], set()

    def add(w, kind="form", glyph=False):
        if w not in seen:
            seen.add(w)
            out.append((w, kind, glyph))

    for key, (mn, form) in FORMS.items():
        groups = GROUPS[mn]
        legal = {n: g for n, g in groups.items() if not (form == "I" and g["imm"] is None)}
        for name in legal:
            add(word(key, name))
        # the operand lattice on two groups: the plain one and a loaded one
        loaded = {"F2I": "FTZ,NTZ,TRUNC,U16", "I2F": "BF16,RM,S16" if form != "I" else "BF16,RM,U64", "FRND": "BF16,FLOOR,FTZ", "MUFU": "F16,SQRT"}[mn]
        for name in (PLAIN[mn], loaded):
            for guard in (0, 3, 8, 15):
                add(word(key, name, guard=guard))
            for n in (0, 1, 63, 255):
                add(word(key, name, d=n))
            if form == "I":
                kind = legal[name]["imm"]
                if kind == "imm":
                    for imm in (0, 1, 0x7fffffff, 0x80000000, 0xfffffff0, 0xffffffff, 0x12345678):
                        add(word(key, name, imm=imm))
                elif kind == "f32":
                    for imm in F32_IMMS:
                        add(word(key, name, imm=imm))
                    for imm in F32_GLYPHS:
                        add(word(key, name, imm=imm), glyph=True)
                elif kind == "f64hi":
                    for imm in (0, 0x3ff00000, 0xbff00000, 0x40000000, 0x3fe00000, 0x00100000, 0x7fefffff, 0x00000001, 0x7ff00000, 0xfff00000, 0x80000000, 0x3fd33333):
                        add(word(key, name, imm=imm))
                    for imm in (0x7ff80000, 0xfff80000, 0x7ff00001):
                        add(word(key, name, imm=imm), glyph=True)
                elif kind == "f16":
                    for imm in (0, 0x3c00, 0xbc00, 0x4000, 0x3800, 0x0400, 0x7bff, 0x0001, 0x7c00, 0xfc00, 0x8000, 0x3266):
                        add(word(key, name, imm=imm))
                    for imm in (0x7e00, 0xfe00, 0x7c01):
                        add(word(key, name, imm=imm), glyph=True)
                else:  # bf16
                    for imm in (0, 0x3f80, 0xbf80, 0x4000, 0x3f00, 0x0080, 0x7f7f, 0x0001, 0x7f80, 0xff80, 0x8000, 0x3e4d):
                        add(word(key, name, imm=imm))
                    for imm in (0x7fc0, 0xffc0, 0x7f81):
                        add(word(key, name, imm=imm), glyph=True)
            else:
                for n in (0, 1, 63, 255):
                    add(word(key, name, a=n))
                if mn != "I2F":
                    for signs in (dict(nega=1), dict(absa=1), dict(nega=1, absa=1)):
                        add(word(key, name, **signs))
        if mn == "I2F" and form != "I":
            for name in ("S8", "U8", "BF16,U8", "F64,S8", "S16", "U16", "F16,S16", "F64,U16"):
                for sel in (1, 2, 3) if "8" in name else (1,):
                    add(word(key, name, sel=sel))
        if mn != "I2F" and form != "I":
            half_names = {"F2I": ("F16", "BF16", "BF16,FTZ,NTZ,TRUNC,U16", "BF16,S64"), "FRND": ("F16", "BF16", "BF16,FLOOR,FTZ"),
                          "MUFU": ("F16,RCP", "BF16,RCP", "F16,SQRT")}[mn]
            for name in half_names:
                add(word(key, name, sel=1))
                add(word(key, name, sel=1, nega=1, absa=1))
                add(word(key, name, sel=2), "lattice")  # INVALID2
            add(word(key, "F64" if mn != "MUFU" else "RCP64H", sel=1), "lattice")  # [61:60] text-inert without a half source
        # one word per key with every field away from its canonical value
        moved = dict(guard=11, d=17)
        if form == "I":
            kind = legal[loaded]["imm"]
            moved["imm"] = {"f32": 0xc2f60000, "f16": 0xc2f6, "bf16": 0xc2f6, "f64hi": 0xc05ec000, "imm": 0x89abcdef}[kind]
        else:
            moved.update(a=10, **({} if mn == "I2F" else dict(nega=1, absa=1)))
        add(word(key, loaded, **moved))
        # lattice: the frame bit, the text-inert bits, the vendor-invalid / illegal modifier states
        add(word(key) ^ (1 << 91), "lattice")
        for bit in inert_bits(key):
            add(word(key) | (1 << bit), "lattice")
        if form == "I" and mn != "I2F":
            for name in (("F16", "BF16") if mn != "MUFU" else ("F16,RCP", "BF16,RCP")):
                add(word(key, name) | (0xabcd << 48), "lattice")  # the high half above a half immediate is text-inert
        if mn == "F2I":
            add(word(key) | (3 << 75), "lattice")  # width 3 on the 0x305 path: ???7
            add(word(key, "U32") | (3 << 75), "lattice")  # ???6
            add(word(key) & ~(7 << 84), "lattice")  # src 0: illegal
            add(word(key) | (7 << 84), "lattice")  # src 7: illegal
        elif mn == "I2F":
            for dst in (0, 3, 5, 6, 7):
                add((word(key) & ~(7 << 75)) | (dst << 75), "lattice")  # ???n on 0x306 (3 = F64 is 0x312-only)
            if form != "I":
                add(word(key, "S16") | (2 << 60), "lattice")  # INVALID2
                add(word(key, "S16") | (3 << 60), "lattice")  # INVALID3
            else:
                add(word(key, "BF16,RM,U64") & ~(3 << 84), "lattice")  # an 8-bit source on the immediate form: illegal
        elif mn == "FRND":
            add((word(key, "F64") & ~(7 << 84)) | (2 << 84), "lattice")  # (3, 2) on 0x313: ???19
            add((word(key) & ~(7 << 84)) | (1 << 84), "lattice")  # (2, 1) on 0x307: illegal
        else:
            for fn in (10, 15):
                add((word(key, "COS") & ~(0xf << 74)) | (fn << 74), "lattice")  # INVALIDn
            add(word(key, "RCP64H") | (1 << 72), "lattice")  # INVALID6.F16
            add(word(key, "COS") | (3 << 72), "lattice")  # half 3: illegal
    return out


def lattice_ok(w, t):
    if t is None:
        return True
    if "???" in t or "INVALID" in t:
        return True
    key, name = group_of(w)
    if name is None:
        return False
    mask = sum(1 << b for b in inert_bits(key))
    if FORMS[key][1] == "I" and GROUPS[FORMS[key][0]][name]["imm"] in ("f16", "bf16"):
        mask |= 0xffff << 48
    return text_ok(w & ~mask, t)


def probe(nvdisasm, arch, out, jobs):
    words = sweep_words()
    rows = nvprobe.probe_words(nvdisasm, "conv", [(w, kind != "form") for w, kind, _ in words], CTRL, check_form=text_ok,
                               check_lattice=lattice_ok, arch=arch, jobs=jobs)
    for row, (_, _, glyph) in zip(rows, words):
        if glyph:
            row["glyph"] = True
    nvprobe.write_fixture(out, rows)
    n_form = sum(1 for r in rows if not r.get("lattice") and not r.get("glyph"))
    n_glyph = sum(1 for r in rows if r.get("glyph"))
    print(f"{out}: {n_form} form words, {n_glyph} glyph words, {len(rows) - n_form - n_glyph} lattice words ({arch})")


NOTE = ("Float conversions / MUFU measured with nvdisasm 13.1 (-b SM120 = SM103 = SM100), tools/probes/re_sm120_conv.py (session G, "
        "2026-11-07): guard [15:12], Rd [23:16], the source at [39:32] (Ra / URa; |Ra| 62, -Ra 63 except on I2F) or the immediate at "
        "[63:32] (f32 / the f16 / bf16 half / the f64 high dword / the integer, by the group's type); F2I: destination width [76:75] + "
        "signed 72, source type [86:84], NTZ 77, rounding [79:78], FTZ 80 (0x311 = the 64-bit destinations and the F64 source); I2F: "
        "destination type [77:75], source width [85:84] + signed 74, rounding [79:78], the 8-bit byte selector [61:60] / the 16-bit "
        "H1 at 60 (0x312 = the F64 destination and the 64-bit sources); FRND: type [77:75] = [86:84], FTZ 80, rounding [79:78] (0x313 = "
        "F64); MUFU: function [77:74], half type [73:72]. The uniform forms = opcode + 0xc00 + bit 91, the immediate forms = + 0x800. "
        "No .reuse (text-inert). The unused bits, the vendor-invalid glyph states and the illegal combinations fail closed.")


def measured_row(key, name, src=PROVENANCE):
    mn, form = FORMS[key]
    g = GROUPS[mn][name]
    fields = [nvprobe.field(12, 4, "guard", 0, src), nvprobe.field(16, 8, "reg", 1, src)]
    if form == "I":
        width = 16 if g["imm"] in ("f16", "bf16") else 32
        fields.append(nvprobe.field(32, width, g["imm"], 2, src))
    else:
        fields.append(nvprobe.field(32, 8, "ureg" if form == "UR" else "reg", 2, src))
        if mn != "I2F":
            fields += [nvprobe.field(62, 1, "abs", 2, src), nvprobe.field(63, 1, "neg", 2, src)]
        if g["sel"] == "byte":
            fields.append(nvprobe.field(60, 2, "byte_sel", 2, src))
        elif g["sel"] == "half":
            fields.append(nvprobe.field(60, 1, "opmod:H1", 2, src))
    base = word(key, name, guard=0, d=0, a=0, imm=0)
    return nvprobe.row(base, fields, src, NOTE)


def same_row(old, new):
    strip = lambda f: {k: v for k, v in f.items() if k in ("bits", "extraction", "shift", "token_idx")}  # noqa: E731
    return (int(old["and_base"], 16) == int(new["and_base"], 16) and int(old["variable_mask"], 16) == int(new["variable_mask"], 16)
            and sorted(map(repr, map(strip, old["fields"]))) == sorted(map(repr, map(strip, new["fields"]))) and old.get("_src"))


SCHED_TEMPLATE = {"F2I": "F2I_R_R", "I2F": "I2F_R_R", "FRND": "FRND_R_R", "MUFU": "MUFU_R_R"}


def apply(table_path):
    path = pathlib.Path(table_path)
    table = nvprobe.load_table(path)
    ins = table["instructions"]
    live_before = collections.Counter(g.get("_src") for e in ins.values() for g in e.get("mod_groups", {}).values())
    rewritten = added = kept = 0
    for key, (mn, form) in FORMS.items():
        old = ins.get(key)
        template = ins[SCHED_TEMPLATE[mn]]
        entry = {k: v for k, v in (old or template).items() if k in ("base_op", "ctrl_class", "mercury", "scheduling")}
        entry["operand_sig"] = key.split("_", 1)[1]
        entry.setdefault("base_op", mn)
        old_groups = old["mod_groups"] if old else {}
        groups = {}
        for name, g in GROUPS[mn].items():
            if form == "I" and g["imm"] is None:
                continue
            row = measured_row(key, name)
            prev = old_groups.get(name)
            if prev is not None and same_row(prev, row):
                groups[name] = prev
                kept += 1
            else:
                groups[name] = row
                rewritten += prev is not None
                added += prev is None
        # the harvest spelled the unspelled defaults in some names ('F64,RM,S32' next to 'F64,RM'): duplicates, dropped
        normalise = lambda n: name_of(t for t in n.split(",") if t not in ("S32", "F32"))  # noqa: E731
        missing = {normalise(n) for n in old_groups} - set(groups)
        assert not missing, f"{key}: harvest groups outside the measured lattice: {missing}"
        dups = [n for n in old_groups if normalise(n) != n]
        if dups:
            print(f"  {key}: {len(dups)} harvest groups spelled the default type ({dups[:3]}...): folded into the measured groups")
        entry["mod_groups"] = groups
        entry["_src"] = PROVENANCE
        ins[key] = entry
    aliases = table["_meta"].setdefault("key_aliases", {})
    retired = []
    for k in sorted(ins):
        stem, _, sig = k.partition("_")
        mn = stem.split(".")[0]
        if mn in ("F2I", "I2F", "FRND") and "." in stem:
            target = {"R_R": f"{mn}_R_R", "R_UR": f"{mn}_R_UR"}.get(sig)
            assert target, f"{k}: an operand signature outside the measured forms"
            del ins[k]
            aliases[k] = target
            retired.append(k)
    if "MUFU_R_II" in ins:
        del ins["MUFU_R_II"]
        aliases["MUFU_R_II"] = "MUFU_R_FI"
        retired.append("MUFU_R_II")
    prov = table["_meta"]["provenance"]
    rows = [g for e in ins.values() for g in e.get("mod_groups", {}).values()]
    prov["rows_total"] = len(rows)
    prov["rows_without_src"] = sum(1 for g in rows if g.get("_src") is None)
    prov["sources"][PROVENANCE] = {"rows": sum(1 for g in rows if g.get("_src") == PROVENANCE),
                                   "kind": "nvdisasm 13.1 field probe (-b SM120 / SM103 / SM100)", "date": "2026-11-07",
                                   "tool": "tools/probes/re_sm120_conv.py", "test": "tests/sm120_conv.rs"}
    # the measured rows of other sources this measurement replaced (dotted-key rows of the 2026-09 bug waves, T-10's
    # F2I_R_UR row): a legend count that was live before follows the live count
    live_after = collections.Counter(g.get("_src") for g in rows)
    for s, n in live_before.items():
        if s and s != PROVENANCE and live_after[s] != n and prov["sources"].get(s, {}).get("rows") == n:
            prov["sources"][s]["rows"] = live_after[s]
            print(f"  legend {s}: rows {n} -> {live_after[s]}")
    nvprobe.save_table(path, table)
    print(f"{path}: conversion rows rewritten {rewritten}, groups added {added}, measured rows kept with their tag {kept}, "
          f"rows with the new tag {prov['sources'][PROVENANCE]['rows']}; {len(retired)} keys retired as aliases "
          f"({sum(1 for k in retired if k.startswith('F2I'))} F2I, {sum(1 for k in retired if k.startswith('I2F'))} I2F, "
          f"{sum(1 for k in retired if k.startswith('FRND'))} FRND, {sum(1 for k in retired if k.startswith('MUFU'))} MUFU)")


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
        out = args.out or nvprobe.FIXTURES / f"{TABLE_OF[args.arch]}_conv_nvdisasm.jsonl"
        probe(args.nvdisasm, args.arch, out, args.jobs)
    else:
        apply(args.table)


if __name__ == "__main__":
    main()

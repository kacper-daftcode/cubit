#!/usr/bin/env python3
"""The FSETP / DSETP family (float compare-and-set predicate): measure the whole modifier x operand lattice
of the six keys with nvdisasm and rebuild them from the measurement (session G, 2026-11-06; KNOWN_ISSUES
T1 -- 96 x 3 + 48 x 3 harvest "mode grid" rows of 2026-10-22 without a field-by-field measurement, 100
dotted encode-only twins, 11 mis-tokenised harvest keys and an integer-spelling twin of the f32 form).

Forms (opcode [11:0]; bit 91 = the uniform-datapath frame, illegal when flipped either way):
  FSETP_P_P_R_R_P   0x20b          `Pd0, Pd1, Ra, Rb, Pc`        .reuse Ra 122, Rb 123
  FSETP_P_P_R_UR_P  0xc0b + bit 91 `Pd0, Pd1, Ra, URb, Pc`       .reuse Ra 122
  FSETP_P_P_R_FI_P  0x80b          `Pd0, Pd1, Ra, f32, Pc`       .reuse Ra 122
  DSETP_P_P_R_R_P   0x22a          `Pd0, Pd1, Ra, Rb, Pc`        (no .reuse: the bits are text-inert on DSETP)
  DSETP_P_P_R_UR_P  0xe2a + bit 91 `Pd0, Pd1, Ra, URb, Pc`
  DSETP_P_P_R_FI_P  0x42a          `Pd0, Pd1, Ra, f64, Pc`       (the high 32 bits of the double at [63:32])

Law (nvdisasm 13.1, one word per call, `-b SM120`; `probe --arch SM103` / `SM100` print the same text for
every word of the sweep):
  guard [15:12]; [23:16] text-inert; Ra [31:24], `-Ra` 72, `|Ra|` 73; Rb / URb [39:32] with `|Rb|` 62 and
  `-Rb` 63 (the immediate forms: the immediate occupies [63:32]); [61:40] and [71:64] text-inert on the
  register forms; [75:74] the boolean (0 `.AND`, 1 `.OR`, 2 `.XOR`, 3 = `.INVALID3`); [79:76] the comparison
  -- FSETP: F LT EQ LE GT NE GE NUM NAN LTU EQU LEU GTU NEU GEU T; DSETP names 0 / 15 `MIN` / `MAX` instead
  of `F` / `T`; 80 = `.FTZ` on FSETP (text-inert on DSETP); Pd0 [83:81]; Pd1 [86:84]; Pc [89:87], `!` 90;
  [95:92] text-inert. Print order `FSETP.<cmp>[.FTZ].<bool>` / `DSETP.<cmp>.<bool>`; immediates print as
  nvdisasm's decimals (`1`, `-1.5`, `1.175494350822287508e-38`), `+INF ` / `-INF ` / `-0.0 ` with the
  vendor's trailing space, and the NaN payloads as `+QNAN ` / `-QNAN ` / `+SNAN ` glyphs (KNOWN_ISSUES A8:
  cubit's lossless print keeps the payload as a hexadecimal; the fixture marks those words `glyph`).

96 groups per FSETP key (16 x 3 x FTZ), 48 per DSETP key; 432 rows.

`probe [--arch SM120|SM103|SM100] [--jobs N]` writes `tests/fixtures/<table>_fsetp_dsetp_nvdisasm.jsonl`;
`apply <sm120.json>` rewrites the six keys' groups and retires: the 100 dotted encode-only twins whose row
is a byte-identical copy of the plain key's group and the five remaining "label" rows of `FSETP_P_P_L_L_P`
(deleted -- decoder-invisible / vendor-rejected words, 0 census witnesses; the 2026-11-03 audit had already
deleted that key's other five rows and its `_L_FI_P` sibling); the mis-tokenised harvest keys
`FSETP.<m>_P_P_R_R_R`, `_P_P_R_UR_UR`, `_P_P_R_R_?`, `_P_P_R_R_P_?`, `FSETP_P_P_II_II_P`, `FSETP_P_P_II_R_P` and the integer-spelling twin
`FSETP_P_P_R_II_P` (the encode path of hexadecimal f32 literals, kept as an alias of the f32 key) as
`_meta.key_aliases` of the plain keys.
"""
from __future__ import annotations

import argparse
import pathlib
import struct
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import nvprobe  # noqa: E402

PROVENANCE = "fsetp-dsetp-family-2026-11-06"
CTRL = 0x000f_e200 << 96
TABLE_OF = {"SM120": "sm120", "SM103": "sm103a", "SM100": "sm100a"}
FCMP = ["F", "LT", "EQ", "LE", "GT", "NE", "GE", "NUM", "NAN", "LTU", "EQU", "LEU", "GTU", "NEU", "GEU", "T"]
DCMP = ["MIN"] + FCMP[1:15] + ["MAX"]
BOOL = ["AND", "OR", "XOR"]
# key -> (opcode, frame bit 91, b operand kind, double)
FORMS = {
    "FSETP_P_P_R_R_P": (0x20b, 0, "reg", False),
    "FSETP_P_P_R_UR_P": (0xc0b, 1, "ureg", False),
    "FSETP_P_P_R_FI_P": (0x80b, 0, "f32", False),
    "DSETP_P_P_R_R_P": (0x22a, 0, "reg", True),
    "DSETP_P_P_R_UR_P": (0xe2a, 1, "ureg", True),
    "DSETP_P_P_R_FI_P": (0x42a, 0, "f64hi", True),
}
# immediates: (bits at [63:32], nvdisasm text, glyph) -- the text is checked numerically where it is a number
F32_IMMS = [0x00000000, 0x3f800000, 0xbf800000, 0x3fc00000, 0x00800000, 0xf1a18f08, 0x7f7fffff, 0x00000001,
            0x7f800000, 0xff800000, 0x80000000, 0x3e99999a, 0x4b000000, 0x322bcc77]
F32_GLYPHS = [0x7fc00000, 0xffc00000, 0x7f800001]
F64_IMMS = [0x00000000, 0x3ff00000, 0xbff00000, 0x40000000, 0x3fe00000, 0x00100000, 0x7fefffff, 0x00000001,
            0x7ff00000, 0xfff00000, 0x80000000, 0x3fd33333, 0x41600000]
F64_GLYPHS = [0x7ff80000, 0xfff80000, 0x7ff00001]
SPECIAL = {"+INF": float("inf"), "-INF": float("-inf"), "-0.0": -0.0}
REMOVED_JUNK = {"FSETP.GE.FTZ.AND_P_P_R_R_R": "FSETP_P_P_R_R_P", "FSETP.NAN.FTZ.AND_P_P_R_R_R": "FSETP_P_P_R_R_P",
                "FSETP.GEU.AND_P_P_R_UR_UR": "FSETP_P_P_R_UR_P", "FSETP.NEU.AND_P_P_R_UR_UR": "FSETP_P_P_R_UR_P",
                "FSETP.NEU.OR_P_P_R_UR_UR": "FSETP_P_P_R_UR_P", "FSETP.NE.FTZ.AND_P_P_R_R_?": "FSETP_P_P_R_FI_P",
                "FSETP.NEU.AND_P_P_R_R_P_?": "FSETP_P_P_R_R_P", "FSETP.NEU.OR_P_P_R_R_P_?": "FSETP_P_P_R_R_P",
                "FSETP_P_P_II_II_P": "FSETP_P_P_R_FI_P",
                "FSETP_P_P_II_R_P": "FSETP_P_P_R_R_P", "FSETP_P_P_R_II_P": "FSETP_P_P_R_FI_P"}


def word(key, cmp=4, bool_=0, ftz=0, guard=7, pd0=0, pd1=7, a=2, b=None, pc=7, npc=0, nega=0, absa=0, negb=0, absb=0, extra=0):
    opc, frame, bkind, _ = FORMS[key]
    if b is None:
        b = {"reg": 4, "ureg": 4, "f32": 0x3f800000, "f64hi": 0x3ff00000}[bkind]
    w = (opc | (frame << 91) | (guard << 12) | (a << 24) | (b << 32) | (nega << 72) | (absa << 73) | (bool_ << 74)
         | (cmp << 76) | (ftz << 80) | (pd0 << 81) | (pd1 << 84) | (pc << 87) | (npc << 90) | extra)
    if bkind in ("reg", "ureg"):
        w |= (absb << 62) | (negb << 63)
    return w


def key_of(w: int) -> str | None:
    frame = (w >> 91) & 1
    for key, (opc, fb, _, _) in FORMS.items():
        if (w & 0xfff) == opc and frame == fb:
            return key
    return None


def pred(n, inv=0):
    return ("!" if inv else "") + ("PT" if n == 7 else f"P{n}")


def expected_parts(w: int):
    """(text with the immediate as `<IMM>`, immediate value or None); None where the law says illegal."""
    key = key_of(w)
    if key is None:
        return None, None
    _, _, bkind, double = FORMS[key]
    guard = (w >> 12) & 0xf
    g = "" if guard == 7 else (f"@P{guard} " if guard < 7 else ("@!PT " if guard == 15 else f"@!P{guard - 8} "))
    cmp = (DCMP if double else FCMP)[(w >> 76) & 0xf]
    bool_ = (BOOL + ["INVALID3"])[(w >> 74) & 3]
    ftz = ".FTZ" if (not double and (w >> 80) & 1) else ""
    mn = f"{'D' if double else 'F'}SETP.{cmp}{ftz}.{bool_}"
    reg = lambda n, ur: ("URZ" if n == 255 else f"UR{n}") if ur else ("RZ" if n == 255 else f"R{n}")  # noqa: E731
    sign = lambda neg, abs_, body: ("-" if neg else "") + (f"|{body}|" if abs_ else body)  # noqa: E731
    a = sign((w >> 72) & 1, (w >> 73) & 1, reg((w >> 24) & 0xff, False)) + (".reuse" if (not double and (w >> 122) & 1) else "")
    imm = None
    if bkind in ("reg", "ureg"):
        b = sign((w >> 63) & 1, (w >> 62) & 1, reg((w >> 32) & 0xff, bkind == "ureg"))
        if bkind == "reg" and not double and (w >> 123) & 1:
            b += ".reuse"
    else:
        bits = (w >> 32) & 0xffffffff
        imm = struct.unpack("<f", struct.pack("<I", bits))[0] if bkind == "f32" else struct.unpack("<d", struct.pack("<Q", bits << 32))[0]
        b = "<IMM>"
    return f"{g}{mn} {pred((w >> 81) & 7)}, {pred((w >> 84) & 7)}, {a}, {b}, {pred((w >> 87) & 7, (w >> 90) & 1)}", imm


def text_ok(w: int, t: str) -> bool:
    """The vendor text matches the law; a numeric immediate is compared as a number (nvdisasm's own decimal
    spelling is recorded in the fixture), the NaN glyphs by name."""
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
    val = SPECIAL.get(tok)
    if val is None:
        try:
            val = float(tok)
        except ValueError:
            return False
    if tok == "-0.0":
        return imm == 0.0 and str(imm).startswith("-")
    return val == imm or (tok in ("+INF", "-INF") and val == imm)


def inert_bits(key):
    _, _, bkind, double = FORMS[key]
    bits = [*range(16, 24), 92, 93, 94, 95]
    if bkind in ("reg", "ureg"):
        bits += [*range(40, 62), *range(64, 72)]
    else:
        bits += [*range(64, 72)]
    if double:
        bits.append(80)
    return bits


def sweep_words():
    out, seen = [], set()

    def add(w, lattice=False, glyph=False):
        if w not in seen:
            seen.add(w)
            out.append((w, lattice, glyph))

    for key, (_, _, bkind, double) in FORMS.items():
        for cmp in range(16):
            for bool_ in range(3):
                for ftz in ((0,) if double else (0, 1)):
                    add(word(key, cmp, bool_, ftz))
        for grp in (dict(), dict(cmp=13, bool_=2, ftz=0 if double else 1)):
            for guard in (0, 3, 8, 15):
                add(word(key, guard=guard, **grp))
            for n in range(8):
                add(word(key, pd0=n, **grp))
                add(word(key, pd1=n, **grp))
                add(word(key, pc=n, **grp))
                add(word(key, pc=n, npc=1, **grp))
            for n in (0, 1, 255):
                add(word(key, a=n, **grp))
            for signs in (dict(nega=1), dict(absa=1), dict(nega=1, absa=1)):
                add(word(key, **signs, **grp))
            if bkind in ("reg", "ureg"):
                for n in (0, 63, 255):
                    add(word(key, b=n, **grp))
                for signs in (dict(negb=1), dict(absb=1), dict(negb=1, absb=1), dict(nega=1, absa=1, negb=1, absb=1)):
                    add(word(key, **signs, **grp))
            else:
                for imm in (F32_IMMS if bkind == "f32" else F64_IMMS):
                    add(word(key, b=imm, **grp))
                for imm in (F32_GLYPHS if bkind == "f32" else F64_GLYPHS):
                    add(word(key, b=imm, **grp), glyph=True)
            if not double:
                add(word(key, extra=1 << 122, **grp))
                if bkind == "reg":
                    add(word(key, extra=1 << 123, **grp))
                    add(word(key, extra=(1 << 122) | (1 << 123), **grp))
        add(word(key, cmp=9, bool_=1, ftz=0 if double else 1, guard=11, pd0=5, pd1=6, a=10, pc=2, npc=1, nega=1, absa=1,
                 **({} if bkind not in ("reg", "ureg") else dict(b=20, negb=1, absb=1))))
        # lattice: INVALID3, the frame bit, the text-inert bits
        add(word(key, bool_=3), lattice=True)
        add(word(key) ^ (1 << 91), lattice=True)
        for bit in inert_bits(key):
            add(word(key) | (1 << bit), lattice=True)
    return out


def lattice_ok(w, t):
    key = key_of(w)
    if t is None:
        return key is None
    if key is None:
        return False
    return text_ok(w & ~sum(1 << b for b in inert_bits(key)), t)


def probe(nvdisasm, arch, out, jobs):
    words = sweep_words()
    rows = nvprobe.probe_words(nvdisasm, "fsetp_dsetp", [(w, lat) for w, lat, _ in words], CTRL, check_form=text_ok,
                               check_lattice=lattice_ok, arch=arch, jobs=jobs)
    for row, (_, _, glyph) in zip(rows, words):
        if glyph:
            row["glyph"] = True
    nvprobe.write_fixture(out, rows)
    n_form = sum(1 for r in rows if not r.get("lattice") and not r.get("glyph"))
    n_glyph = sum(1 for r in rows if r.get("glyph"))
    print(f"{out}: {n_form} form words, {n_glyph} glyph words, {len(rows) - n_form - n_glyph} lattice words ({arch})")


NOTE = ("FSETP / DSETP measured with nvdisasm 13.1 (-b SM120 = SM103 = SM100), tools/probes/re_sm120_fsetp_dsetp.py (session G, "
        "2026-11-06): guard [15:12], Ra [31:24] (-Ra 72, |Ra| 73), Rb / URb [39:32] (|Rb| 62, -Rb 63) or the immediate [63:32] "
        "(f32; the high 32 bits of the f64), the boolean [75:74] (3 = INVALID3), the comparison [79:76] (DSETP names 0 / 15 "
        "MIN / MAX), FTZ 80 (FSETP only; text-inert on DSETP), Pd0 [83:81], Pd1 [86:84], Pc [89:87] + ! 90; the uniform forms = "
        "opcode byte 0xc0b / 0xe2a + bit 91; .reuse Ra 122 / Rb 123 on FSETP (text-inert on DSETP). [23:16], the unused part of "
        "[71:40] and [95:92] text-inert and fail closed.")


def measured_row(key, cmp, bool_, ftz, src=PROVENANCE):
    _, _, bkind, double = FORMS[key]
    fields = [nvprobe.field(12, 4, "guard", 0, src), nvprobe.field(81, 3, "pred", 1, src), nvprobe.field(84, 3, "pred", 2, src),
              nvprobe.field(24, 8, "reg", 3, src), nvprobe.field(72, 1, "neg", 3, src), nvprobe.field(73, 1, "abs", 3, src)]
    if not double:
        fields.append(nvprobe.field(122, 1, "reuse", 3, src))
    if bkind in ("reg", "ureg"):
        fields += [nvprobe.field(32, 8, bkind, 4, src), nvprobe.field(62, 1, "abs", 4, src), nvprobe.field(63, 1, "neg", 4, src)]
        if bkind == "reg" and not double:
            fields.append(nvprobe.field(123, 1, "reuse", 4, src))
    else:
        fields.append(nvprobe.field(32, 32, bkind, 4, src))
    fields += [nvprobe.field(87, 3, "pred", 5, src), nvprobe.field(90, 1, "inv", 5, src)]
    base = word(key, cmp, bool_, ftz, guard=0, pd0=0, pd1=0, a=0, b=0, pc=0)
    return nvprobe.row(base, fields, src, NOTE)


def group_name(key, cmp, bool_, ftz):
    double = FORMS[key][3]
    return ",".join(sorted([(DCMP if double else FCMP)[cmp], BOOL[bool_]] + (["FTZ"] if ftz else [])))


def apply(table_path):
    path = pathlib.Path(table_path)
    table = nvprobe.load_table(path)
    ins = table["instructions"]
    rewritten = 0
    for key, (_, _, _, double) in FORMS.items():
        old = ins[key]
        entry = {k: v for k, v in old.items() if k in ("base_op", "ctrl_class", "mercury", "operand_sig", "scheduling")}
        groups = {}
        for cmp in range(16):
            for bool_ in range(3):
                for ftz in ((0,) if double else (0, 1)):
                    groups[group_name(key, cmp, bool_, ftz)] = measured_row(key, cmp, bool_, ftz)
        assert set(groups) == set(old["mod_groups"]), f"{key}: the measured lattice is the harvest's groups"
        entry["mod_groups"] = groups
        entry["_src"] = PROVENANCE
        ins[key] = entry
        rewritten += len(groups)
    # the dotted encode-only twins: byte-identical copies of a plain group -> deleted
    plain_of = {"P_P_R_R_P": "FSETP_P_P_R_R_P", "P_P_R_UR_P": "FSETP_P_P_R_UR_P", "P_P_R_FI_P": "FSETP_P_P_R_FI_P", "P_P_R_II_P": "FSETP_P_P_R_FI_P"}
    deleted = []
    if "FSETP_P_P_L_L_P" in ins:  # the "label"-typed junk key: its words are vendor-rejected (the 2026-11-03 audit)
        del ins["FSETP_P_P_L_L_P"]
        deleted.append("FSETP_P_P_L_L_P")
    for k in list(ins):
        if k.startswith("FSETP.") and k not in REMOVED_JUNK:
            osig = k.split("_", 1)[1]
            name = ",".join(sorted(k.split("_")[0].split(".")[1:]))
            assert osig in plain_of and name in ins[plain_of[osig]]["mod_groups"] and ins[k].get("encode_only"), k
            del ins[k]
            deleted.append(k)
    aliases = table["_meta"].setdefault("key_aliases", {})
    retired = []
    for junk, target in REMOVED_JUNK.items():
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
                                   "tool": "tools/probes/re_sm120_fsetp_dsetp.py", "test": "tests/sm120_fsetp_dsetp.rs"}
    nvprobe.save_table(path, table)
    print(f"{path}: FSETP / DSETP rows rewritten {rewritten}; {len(deleted)} keys deleted (the dotted twins + FSETP_P_P_L_L_P); {len(retired)} keys retired as aliases: {retired}")


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
        out = args.out or nvprobe.FIXTURES / f"{TABLE_OF[args.arch]}_fsetp_dsetp_nvdisasm.jsonl"
        probe(args.nvdisasm, args.arch, out, args.jobs)
    else:
        apply(args.table)


if __name__ == "__main__":
    main()

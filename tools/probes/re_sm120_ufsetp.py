#!/usr/bin/env python3
"""The UFSETP family (the uniform-datapath float compare-and-set predicate): measure the whole modifier x operand
lattice of the two keys with nvdisasm and rebuild them from the measurement (session G, 2026-11-06; KNOWN_ISSUES T1
-- 96 + 96 harvest "mode grid" rows of 2026-10-22, an integer-spelling twin and five dotted junk keys).

Forms (opcode [11:0] + bit 91, the uniform frame -- illegal when clear):
  UFSETP_UP_UP_UR_UR_UP  0x253  `UFSETP.<cmp>[.FTZ].<bool> UPd0, UPd1, URa, URb, UPc`
  UFSETP_UP_UP_UR_FI_UP  0x853  `UFSETP.<cmp>[.FTZ].<bool> UPd0, UPd1, URa, f32, UPc`

Law (nvdisasm 13.1, one word per call, `-b SM120`; the family is SM120-only -- on `-b SM103` / `SM100` nvdisasm
rejects every word of the sweep, like the other uniform float ops): the FSETP law in the uniform datapath -- guard [15:12] (`@[!]UPn`); [23:16] text-inert; URa [31:24], `-URa` 72, `|URa|` 73;
URb [39:32] with `|URb|` 62 and `-URb` 63, or the f32 immediate at [63:32]; [61:40] and [71:64] text-inert on the
register form; [75:74] the boolean (3 = `INVALID3`); [79:76] the comparison (F LT EQ LE GT NE GE NUM NAN LTU EQU
LEU GTU NEU GEU T); 80 `.FTZ`; UPd0 [83:81]; UPd1 [86:84]; UPc [89:87] + `!` 90; [95:92] text-inert; no `.reuse`
(nvdisasm rejects the bits on the uniform opclass).

`probe [--arch SM120|SM103|SM100] [--jobs N]` writes `tests/fixtures/<table>_ufsetp_nvdisasm.jsonl`; `apply <sm120.json>`
rewrites the two keys' groups (96 each) and retires the integer-spelling twin `UFSETP_UP_UP_UR_II_UP` (the hex-f32
encode path, kept as an alias of the f32 key) and the five dotted junk keys as `_meta.key_aliases`.
"""
from __future__ import annotations

import argparse
import pathlib
import struct
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import nvprobe  # noqa: E402
from re_sm120_fsetp_dsetp import BOOL, F32_GLYPHS, F32_IMMS, FCMP, SPECIAL  # noqa: E402

PROVENANCE = "ufsetp-family-2026-11-06"
CTRL = 0x000f_e200 << 96
TABLE_OF = {"SM120": "sm120", "SM103": "sm103a", "SM100": "sm100a"}
FORMS = {"UFSETP_UP_UP_UR_UR_UP": (0x253, "ureg"), "UFSETP_UP_UP_UR_FI_UP": (0x853, "f32")}
RETIRED = {"UFSETP.GT.AND_UP_UP_UR_UR_UP": "UFSETP_UP_UP_UR_UR_UP", "UFSETP.NEU.AND_UP_UP_UR_UR_UP": "UFSETP_UP_UP_UR_UR_UP",
           "UFSETP.NEU.OR_UP_UP_UR_UR_UP": "UFSETP_UP_UP_UR_UR_UP", "UFSETP.NEU.AND_UP_UP_UR_FI_UP": "UFSETP_UP_UP_UR_FI_UP",
           "UFSETP.NEU.AND_UP_UP_UR_II_UP": "UFSETP_UP_UP_UR_FI_UP", "UFSETP_UP_UP_UR_II_UP": "UFSETP_UP_UP_UR_FI_UP"}


def word(key, cmp=4, bool_=0, ftz=0, guard=7, pd0=0, pd1=7, a=2, b=None, pc=7, npc=0, nega=0, absa=0, negb=0, absb=0, extra=0):
    opc, bkind = FORMS[key]
    if b is None:
        b = 4 if bkind == "ureg" else 0x3f800000
    w = (opc | (1 << 91) | (guard << 12) | (a << 24) | (b << 32) | (nega << 72) | (absa << 73) | (bool_ << 74) | (cmp << 76)
         | (ftz << 80) | (pd0 << 81) | (pd1 << 84) | (pc << 87) | (npc << 90) | extra)
    if bkind == "ureg":
        w |= (absb << 62) | (negb << 63)
    return w


def key_of(w):
    if not (w >> 91) & 1:
        return None
    for key, (opc, _) in FORMS.items():
        if (w & 0xfff) == opc:
            return key
    return None


def upred(n, inv=0):
    return ("!" if inv else "") + ("UPT" if n == 7 else f"UP{n}")


def expected_parts(w):
    key = key_of(w)
    if key is None:
        return None, None
    bkind = FORMS[key][1]
    guard = (w >> 12) & 0xf
    g = "" if guard == 7 else f"@{upred(guard & 7, guard >> 3)} "
    mn = f"UFSETP.{FCMP[(w >> 76) & 0xf]}{'.FTZ' if (w >> 80) & 1 else ''}.{(BOOL + ['INVALID3'])[(w >> 74) & 3]}"
    ureg = lambda n: "URZ" if n == 255 else f"UR{n}"  # noqa: E731
    sign = lambda neg, abs_, body: ("-" if neg else "") + (f"|{body}|" if abs_ else body)  # noqa: E731
    a = sign((w >> 72) & 1, (w >> 73) & 1, ureg((w >> 24) & 0xff))
    imm = None
    if bkind == "ureg":
        b = sign((w >> 63) & 1, (w >> 62) & 1, ureg((w >> 32) & 0xff))
    else:
        imm = struct.unpack("<f", struct.pack("<I", (w >> 32) & 0xffffffff))[0]
        b = "<IMM>"
    return f"{g}{mn} {upred((w >> 81) & 7)}, {upred((w >> 84) & 7)}, {a}, {b}, {upred((w >> 87) & 7, (w >> 90) & 1)}", imm


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
    bits = [*range(16, 24), *range(64, 72), 92, 93, 94, 95]
    if FORMS[key][1] == "ureg":
        bits += list(range(40, 62))
    return bits


def sweep_words():
    out, seen = [], set()

    def add(w, lattice=False, glyph=False):
        if w not in seen:
            seen.add(w)
            out.append((w, lattice, glyph))

    for key, (_, bkind) in FORMS.items():
        for cmp in range(16):
            for bool_ in range(3):
                for ftz in (0, 1):
                    add(word(key, cmp, bool_, ftz))
        for grp in (dict(), dict(cmp=13, bool_=2, ftz=1)):
            for guard in (0, 3, 8, 15):
                add(word(key, guard=guard, **grp))
            for n in range(8):
                add(word(key, pd0=n, **grp))
                add(word(key, pd1=n, **grp))
                add(word(key, pc=n, **grp))
                add(word(key, pc=n, npc=1, **grp))
            for n in (0, 1, 63, 255):
                add(word(key, a=n, **grp))
            for signs in (dict(nega=1), dict(absa=1), dict(nega=1, absa=1)):
                add(word(key, **signs, **grp))
            if bkind == "ureg":
                for n in (0, 63, 255):
                    add(word(key, b=n, **grp))
                for signs in (dict(negb=1), dict(absb=1), dict(negb=1, absb=1), dict(nega=1, absa=1, negb=1, absb=1)):
                    add(word(key, **signs, **grp))
            else:
                for imm in F32_IMMS:
                    add(word(key, b=imm, **grp))
                for imm in F32_GLYPHS:
                    add(word(key, b=imm, **grp), glyph=True)
        add(word(key, cmp=9, bool_=1, ftz=1, guard=11, pd0=5, pd1=6, a=10, pc=2, npc=1, nega=1, absa=1,
                 **({} if bkind != "ureg" else dict(b=20, negb=1, absb=1))))
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
    if arch != "SM120":
        # the uniform float compare is SM120-only: on -b SM103 / SM100 nvdisasm rejects every word of the sweep
        rows = nvprobe.probe_words(nvdisasm, "ufsetp", [(w, True) for w, _, _ in words], CTRL, check_form=text_ok,
                                   check_lattice=lambda w, t: t is None, arch=arch, jobs=jobs)
        nvprobe.write_fixture(out, rows)
        print(f"{out}: {len(rows)} words, all illegal on {arch} (UFSETP is SM120-only)")
        return
    rows = nvprobe.probe_words(nvdisasm, "ufsetp", [(w, lat) for w, lat, _ in words], CTRL, check_form=text_ok,
                               check_lattice=lattice_ok, arch=arch, jobs=jobs)
    for row, (_, _, glyph) in zip(rows, words):
        if glyph:
            row["glyph"] = True
    nvprobe.write_fixture(out, rows)
    n_form = sum(1 for r in rows if not r.get("lattice") and not r.get("glyph"))
    n_glyph = sum(1 for r in rows if r.get("glyph"))
    print(f"{out}: {n_form} form words, {n_glyph} glyph words, {len(rows) - n_form - n_glyph} lattice words ({arch})")


NOTE = ("UFSETP measured with nvdisasm 13.1 (-b SM120; illegal on -b SM103 / SM100: the uniform float compare is SM120-only), "
        "tools/probes/re_sm120_ufsetp.py (session G, 2026-11-06): "
        "the FSETP law in the uniform datapath -- guard [15:12] (@UPn), URa [31:24] (-URa 72, |URa| 73), URb [39:32] (|URb| 62, "
        "-URb 63) or the f32 immediate [63:32], the boolean [75:74] (3 = INVALID3), the comparison [79:76], FTZ 80, UPd0 [83:81], "
        "UPd1 [86:84], UPc [89:87] + ! 90; opcode byte 0x253 / 0x853 + bit 91 (illegal when clear); no .reuse (nvdisasm rejects "
        "the bits); [23:16], the unused part of [71:40] and [95:92] text-inert and fail closed.")


def measured_row(key, cmp, bool_, ftz, src=PROVENANCE):
    bkind = FORMS[key][1]
    fields = [nvprobe.field(12, 4, "guard", 0, src), nvprobe.field(81, 3, "upred", 1, src), nvprobe.field(84, 3, "upred", 2, src),
              nvprobe.field(24, 8, "ureg", 3, src), nvprobe.field(72, 1, "neg", 3, src), nvprobe.field(73, 1, "abs", 3, src)]
    if bkind == "ureg":
        fields += [nvprobe.field(32, 8, "ureg", 4, src), nvprobe.field(62, 1, "abs", 4, src), nvprobe.field(63, 1, "neg", 4, src)]
    else:
        fields.append(nvprobe.field(32, 32, "f32", 4, src))
    fields += [nvprobe.field(87, 3, "upred", 5, src), nvprobe.field(90, 1, "inv", 5, src)]
    base = word(key, cmp, bool_, ftz, guard=0, pd0=0, pd1=0, a=0, b=0, pc=0)
    return nvprobe.row(base, fields, src, NOTE)


def group_name(cmp, bool_, ftz):
    return ",".join(sorted([FCMP[cmp], BOOL[bool_]] + (["FTZ"] if ftz else [])))


def apply(table_path):
    path = pathlib.Path(table_path)
    table = nvprobe.load_table(path)
    ins = table["instructions"]
    rewritten = 0
    for key in FORMS:
        old = ins[key]
        entry = {k: v for k, v in old.items() if k in ("base_op", "ctrl_class", "mercury", "operand_sig", "scheduling")}
        groups = {group_name(c, b, f): measured_row(key, c, b, f) for c in range(16) for b in range(3) for f in (0, 1)}
        assert set(groups) == set(old["mod_groups"]), key
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
    prov["sources"][PROVENANCE] = {"rows": rewritten, "kind": "nvdisasm 13.1 field probe (-b SM120; the family is illegal on -b SM103 / SM100)", "date": "2026-11-06",
                                   "tool": "tools/probes/re_sm120_ufsetp.py", "test": "tests/sm120_ufsetp.rs"}
    nvprobe.save_table(path, table)
    print(f"{path}: UFSETP rows rewritten {rewritten}; keys retired as aliases: {retired}")


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
        out = args.out or nvprobe.FIXTURES / f"{TABLE_OF[args.arch]}_ufsetp_nvdisasm.jsonl"
        probe(args.nvdisasm, args.arch, out, args.jobs)
    else:
        apply(args.table)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""The ISETP / UISETP family (integer compare-and-set predicate): measure the whole modifier x operand
lattice of the ten keys with nvdisasm and rebuild them from the measurement (session G, 2026-11-06;
KNOWN_ISSUES T1 -- the harvest rows of the register / immediate forms baked a PT guard or a sample's
predicates, the immediate keys had 26 / 41 of their 96 groups missing, the four UISETP keys were
harvest "mode grid" rows without a field-by-field measurement).

Forms (opcode [11:0]; bit 91 is the uniform-datapath frame -- flipped either way the word is illegal):
  ISETP_P_P_R_R_P    0x20c           `Pd0, Pd1, Ra, Rb, Pc`        .reuse Ra 122, Rb 123
  ISETP_P_P_R_UR_P   0xc0c + bit 91  `Pd0, Pd1, Ra, URb, Pc`       .reuse Ra 122
  ISETP_P_P_R_II_P   0x80c           `Pd0, Pd1, Ra, imm32, Pc`     .reuse Ra 122
  UISETP_UP_UP_UR_UR_UP  0x28c + 91  `UPd0, UPd1, URa, URb, UPc`   (no reuse: nvdisasm rejects the bits)
  UISETP_UP_UP_UR_II_UP  0x88c + 91  `UPd0, UPd1, URa, imm32, UPc`
plus the `.EX` twin of each (`_P` / `_UP` appended to the key: the sixth operand `[!]Pcin`).

Law (nvdisasm 13.1, one word per call, `-b SM120`; `probe --arch SM103` / `SM100` print the same text for
every word of the sweep EXCEPT the width bit 80: the 64-bit compare (`.S64` / `.U64`) is SM120-only, on
`-b SM103` / `SM100` bit 80 is text-inert -- `ISETP.NE.S64.AND` reads `ISETP.NE.AND` there):
  guard [15:12] (`@[!]Pn` / `@[!]UPn` on UISETP); [23:16] text-inert; Ra / URa [31:24]; Rb / URb [39:32] or
  imm32 [63:32] (printed as a signed hexadecimal, `-0x1` for 0xffffffff); the rest of [67:40] text-inert;
  [71:68] the `.EX` carry-in predicate -- [70:68] P0..P6 / 7 = PT, bit 71 `!` -- read only when bit 72 (`.EX`)
  is set; without `.EX` the window is text-inert and nvcc always writes PT there (7 414 / 7 414 census
  words), so the non-EX rows bake `[70:68] = 7` and fail closed on anything else; 73 = signed (the
  32-bit signed mode prints no type: `ISETP.GE.AND`; clear = `.U32`); [75:74] the boolean (0 `.AND`,
  1 `.OR`, 2 `.XOR`, 3 = `.INVALID3`); [78:76] the comparison (F LT EQ LE GT NE GE T); 79 text-inert;
  80 = 64-bit (`.S64` / `.U64`); Pd0 [83:81]; Pd1 [86:84]; Pc [89:87] + `!` 90; [95:92] text-inert.
  Print order `ISETP.<cmp>[.U32|.S64|.U64].<bool>[.EX]`.

96 groups per key (8 comparisons x 3 booleans x 4 types); 960 rows. The `UISETP_UP_UP_UR_UR_UP` key keeps
its encode-only `""` retention group (BUG-092, a frozen-era `?`-spelling) untouched.

`probe [--arch SM120|SM103|SM100] [--jobs N]` writes `tests/fixtures/<table>_isetp_nvdisasm.jsonl`;
`apply <sm120.json>` rewrites the groups of the ten keys. Rows the dsv41 probe of 2026-10-22 had already
measured (`dsv41-sm120-2026-10-22`) are kept when the new measurement reproduces them field for field.
"""
from __future__ import annotations

import argparse
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import nvprobe  # noqa: E402

PROVENANCE = "isetp-family-2026-11-06"
DSV41 = "dsv41-sm120-2026-10-22"
CTRL = 0x000f_e200 << 96
TABLE_OF = {"SM120": "sm120", "SM103": "sm103a", "SM100": "sm100a"}
CMP = ["F", "LT", "EQ", "LE", "GT", "NE", "GE", "T"]
BOOL = ["AND", "OR", "XOR"]
# key stem -> (opcode, frame bit 91, b operand kind, uniform datapath)
FORMS = {
    "ISETP_P_P_R_R_P": (0x20c, 0, "reg", False),
    "ISETP_P_P_R_UR_P": (0xc0c, 1, "ureg", False),
    "ISETP_P_P_R_II_P": (0x80c, 0, "imm", False),
    "UISETP_UP_UP_UR_UR_UP": (0x28c, 1, "ureg", True),
    "UISETP_UP_UP_UR_II_UP": (0x88c, 1, "imm", True),
}
TYPES = {(1, 0): "", (0, 0): "U32", (1, 1): "S64", (0, 1): "U64"}  # (signed bit 73, width bit 80) -> suffix


def ex_key(stem: str) -> str:
    return stem + ("_UP" if stem.startswith("U") else "_P")


def word(stem, cmp=6, bool_=0, signed=1, w64=0, ex=0, guard=7, pd0=0, pd1=7, a=2, b=3, pc=7, npc=0, pex=7, npex=0, extra=0):
    opc, frame, bkind, _ = FORMS[stem]
    return (opc | (frame << 91) | (guard << 12) | (a << 24) | (b << (32 if bkind != "imm" else 32)) | (pex << 68) | (npex << 71)
            | (ex << 72) | (signed << 73) | (bool_ << 74) | (cmp << 76) | (w64 << 80) | (pd0 << 81) | (pd1 << 84) | (pc << 87)
            | (npc << 90) | extra)


def stem_of(w: int) -> str | None:
    frame = (w >> 91) & 1
    for stem, (opc, fb, _, _) in FORMS.items():
        if (w & 0xfff) == opc and frame == fb:
            return stem
    return None


def pred(n, inv, uniform):
    return ("!" if inv else "") + ("U" if uniform else "") + ("PT" if n == 7 else f"P{n}")


def expected_text(w: int, arch: str = "SM120") -> str | None:
    """nvdisasm's text; on `-b SM103` / `SM100` the width bit 80 is text-inert (no 64-bit compare there)."""
    stem = stem_of(w)
    if stem is None:
        return None
    _, _, bkind, uniform = FORMS[stem]
    guard = (w >> 12) & 0xf
    u = "U" if uniform else ""
    g = "" if guard == 7 else f"@{pred(guard & 7, guard >> 3, uniform)} "
    bool_ = (w >> 74) & 3
    ty = TYPES[((w >> 73) & 1, (w >> 80) & 1 if arch == "SM120" else 0)]
    ex = (w >> 72) & 1
    mn = f"{u}ISETP.{CMP[(w >> 76) & 7]}" + (f".{ty}" if ty else "") + "." + (BOOL + ["INVALID3"])[bool_] + (".EX" if ex else "")
    reg = lambda n, ur: ("URZ" if n == 255 else f"UR{n}") if ur else ("RZ" if n == 255 else f"R{n}")  # noqa: E731
    a = reg((w >> 24) & 0xff, uniform) + (".reuse" if (not uniform and (w >> 122) & 1) else "")
    if bkind == "imm":
        v = (w >> 32) & 0xffffffff
        b = f"-0x{(1 << 32) - v:x}" if v >> 31 else f"0x{v:x}"
    else:
        b = reg((w >> 32) & 0xff, bkind == "ureg") + (".reuse" if (bkind == "reg" and (w >> 123) & 1) else "")
    out = f"{g}{mn} {pred((w >> 81) & 7, 0, uniform)}, {pred((w >> 84) & 7, 0, uniform)}, {a}, {b}, {pred((w >> 87) & 7, (w >> 90) & 1, uniform)}"
    if ex:
        out += f", {pred((w >> 68) & 7, (w >> 71) & 1, uniform)}"
    return out


def inert_bits(stem):
    _, _, bkind, _ = FORMS[stem]
    return [*range(16, 24), *(range(40, 68) if bkind != "imm" else range(64, 68)), 79, 92, 93, 94, 95]


def sweep_words():
    out, seen = [], set()

    def add(w, lattice):
        if w not in seen:
            seen.add(w)
            out.append((w, lattice))

    for stem, (_, _, bkind, uniform) in FORMS.items():
        for ex in (0, 1):
            for cmp in range(8):
                for bool_ in range(3):
                    for signed, w64 in TYPES:
                        add(word(stem, cmp, bool_, signed, w64, ex), False)
            # the operand lattice on two groups (GE signed 32 / LT.U64.XOR)
            for grp in (dict(), dict(cmp=1, bool_=2, signed=0, w64=1)):
                k = dict(ex=ex, **grp)
                for guard in (0, 3, 8, 15):
                    add(word(stem, guard=guard, **k), False)
                for n in range(8):
                    add(word(stem, pd0=n, **k), False)
                    add(word(stem, pd1=n, **k), False)
                    add(word(stem, pc=n, **k), False)
                    add(word(stem, pc=n, npc=1, **k), False)
                    if ex:
                        add(word(stem, pex=n, **k), False)
                        add(word(stem, pex=n, npex=1, **k), False)
                for n in (0, 1, 255):
                    add(word(stem, a=n, **k), False)
                for n in ((0, 1, 0x7f, 0x7fffffff, 0x80000000, 0xffffffff) if bkind == "imm" else (0, 63, 255)):
                    add(word(stem, b=n, **k), False)
                if not uniform:
                    add(word(stem, extra=1 << 122, **k), False)
                    if bkind == "reg":
                        add(word(stem, extra=1 << 123, **k), False)
                        add(word(stem, extra=(1 << 122) | (1 << 123), **k), False)
            # one word with every field away from its canonical value
            add(word(stem, cmp=3, bool_=1, signed=0, w64=1, ex=ex, guard=11, pd0=5, pd1=6, a=10, b=0x1234 if bkind == "imm" else 20,
                     pc=2, npc=1, pex=4 if ex else 7, npex=ex), False)
        # lattice: the INVALID3 boolean, the frame bit, the text-inert bits, the carry-in window without .EX
        add(word(stem, bool_=3), True)
        add(word(stem, bool_=3, ex=1), True)
        add(word(stem) ^ (1 << 91), True)
        for bit in inert_bits(stem):
            add(word(stem) | (1 << bit), True)
        for pex, npex in ((0, 0), (3, 0), (7, 1), (0, 1)):
            add(word(stem, pex=pex, npex=npex), True)
    return out


def lattice_ok(w, t, arch="SM120"):
    stem = stem_of(w)
    if t is None:
        return stem is None  # only the frame-bit words are illegal
    if stem is None:
        return False
    canon = w & ~sum(1 << b for b in inert_bits(stem))
    if not (canon >> 72) & 1:
        canon = (canon & ~(0xf << 68)) | (7 << 68)
    return t == expected_text(canon, arch)


def probe(nvdisasm, arch, out, jobs):
    rows = nvprobe.probe_words(nvdisasm, "isetp", sweep_words(), CTRL, check_form=lambda w, t: t == expected_text(w, arch),
                               check_lattice=lambda w, t: lattice_ok(w, t, arch), arch=arch, jobs=jobs)
    nvprobe.write_fixture(out, rows)
    n_form = sum(1 for r in rows if not r.get("lattice"))
    print(f"{out}: {n_form} form words, {len(rows) - n_form} lattice words ({arch})")


NOTE = ("ISETP / UISETP measured with nvdisasm 13.1 (-b SM120 = SM103 = SM100), tools/probes/re_sm120_isetp.py (session G, "
        "2026-11-06): guard [15:12], Ra [31:24], Rb [39:32] / imm32 [63:32], Pd0 [83:81], Pd1 [86:84], Pc [89:87] + ! 90; "
        "[71:68] the .EX carry-in predicate (bit 72 = .EX; without it the window is text-inert and nvcc writes PT: baked 7, "
        "fail-closed), 73 signed (no type suffix in the 32-bit mode), [75:74] the boolean (3 = INVALID3), [78:76] the "
        "comparison, 80 = 64-bit; the uniform forms = opcode byte 0xc0c / 0x28c / 0x88c + bit 91; .reuse Ra 122 / Rb 123 "
        "(ISETP; UISETP has none). [23:16], the unused part of [67:40], 79 and [95:92] text-inert and fail closed.")


def measured_row(stem, cmp, bool_, signed, w64, ex, src=PROVENANCE):
    _, _, bkind, uniform = FORMS[stem]
    p, n = ("upred", "inv") if uniform else ("pred", "neg")
    r = "ureg" if uniform else "reg"
    fields = [nvprobe.field(12, 4, "guard", 0, src), nvprobe.field(81, 3, p, 1, src), nvprobe.field(84, 3, p, 2, src),
              nvprobe.field(24, 8, r, 3, src)]
    if not uniform:
        fields.append(nvprobe.field(122, 1, "reuse", 3, src))
    fields.append({"reg": nvprobe.field(32, 8, "reg", 4, src), "ureg": nvprobe.field(32, 8, "ureg", 4, src),
                   "imm": nvprobe.field(32, 32, "imm", 4, src)}[bkind])
    if bkind == "reg":
        fields.append(nvprobe.field(123, 1, "reuse", 4, src))
    fields += [nvprobe.field(87, 3, p, 5, src), nvprobe.field(90, 1, n, 5, src)]
    if ex:
        fields += [nvprobe.field(68, 3, p, 6, src), nvprobe.field(71, 1, n, 6, src)]
    base = word(stem, cmp, bool_, signed, w64, ex, guard=0, pd0=0, pd1=0, a=0, b=0, pc=0, pex=0 if ex else 7)
    return nvprobe.row(base, fields, src, NOTE)


def group_name(cmp, bool_, signed, w64, ex):
    mods = [CMP[cmp], BOOL[bool_]] + ([TYPES[(signed, w64)]] if TYPES[(signed, w64)] else []) + (["EX"] if ex else [])
    return ",".join(sorted(mods))


def same_row(a: dict, b: dict) -> bool:
    strip = lambda f: {k: v for k, v in f.items() if k != "_src"}  # noqa: E731
    return (a["and_base"] == b["and_base"] and a["variable_mask"] == b["variable_mask"]
            and sorted(map(strip, a["fields"]), key=lambda f: f["shift"]) == sorted(map(strip, b["fields"]), key=lambda f: f["shift"]))


def apply(table_path):
    path = pathlib.Path(table_path)
    table = nvprobe.load_table(path)
    ins = table["instructions"]
    stats = {"rewritten": 0, "added": 0, "kept_dsv41": 0}
    for stem in FORMS:
        for ex in (0, 1):
            key = ex_key(stem) if ex else stem
            old = ins[key]
            entry = {k: v for k, v in old.items() if k in ("base_op", "ctrl_class", "mercury", "operand_sig", "scheduling")}
            groups = {}
            for cmp in range(8):
                for bool_ in range(3):
                    for signed, w64 in TYPES:
                        name = group_name(cmp, bool_, signed, w64, ex)
                        row = measured_row(stem, cmp, bool_, signed, w64, ex)
                        prev = old["mod_groups"].get(name)
                        if prev is None:
                            stats["added"] += 1
                        elif prev.get("_src") == DSV41 and same_row(prev, row):
                            stats["kept_dsv41"] += 1
                            row = prev
                        else:
                            stats["rewritten"] += 1
                        groups[name] = row
            for name, g in old["mod_groups"].items():
                if name not in groups:
                    assert name == "" and g.get("encode_only"), f"{key}: unexpected harvest group {name!r}"
                    groups[name] = g  # the BUG-092 retention row
            entry["mod_groups"] = groups
            entry["_src"] = PROVENANCE
            ins[key] = entry
    prov = table["_meta"]["provenance"]
    rows = [g for e in ins.values() for g in e.get("mod_groups", {}).values()]
    prov["rows_total"] = len(rows)
    prov["rows_without_src"] = sum(1 for g in rows if g.get("_src") is None)
    prov["sources"][PROVENANCE] = {"rows": sum(1 for g in rows if g.get("_src") == PROVENANCE),
                                   "kind": "nvdisasm 13.1 field probe (-b SM120 / SM103 / SM100)", "date": "2026-11-06",
                                   "tool": "tools/probes/re_sm120_isetp.py", "test": "tests/sm120_isetp.rs"}
    nvprobe.save_table(path, table)
    print(f"{path}: ISETP / UISETP rows rewritten {stats['rewritten']}, added {stats['added']}, dsv41 rows kept {stats['kept_dsv41']}")


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
        out = args.out or nvprobe.FIXTURES / f"{TABLE_OF[args.arch]}_isetp_nvdisasm.jsonl"
        probe(args.nvdisasm, args.arch, out, args.jobs)
    else:
        apply(args.table)


if __name__ == "__main__":
    main()

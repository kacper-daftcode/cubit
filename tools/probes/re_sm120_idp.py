#!/usr/bin/env python3
"""The IDP family (opcode 0x226, register form 0x7226 / uniform-register form 0x7c26): measure the whole
mode x type x operand lattice with nvdisasm and rebuild the rows from the measurement (session T-11,
2026-11-06; the review of coldface's D2 rows for NEEDS 36).

Law (nvdisasm 13.1, identical text on `-b SM120`, `SM103`, `SM100`, `SM121` for every probe word):

  [15:12] guard, Rd [23:16], Ra [31:24], Rb [39:32] (register form) / URb [39:32] (uniform form, opcode
  byte 0xc26 + bit 91 -- bit 91 clear on 0xc26 or set on 0x226 is illegal), Rc [71:64];
  the enum window [79:72]: [77:76] = the mode (00 `4A`, 01 `2A.LO`, 11 `2A.HI`, 10 illegal),
  73 = the first type is signed (`S8` on 4A, `S16` on 2A; else `U8` / `U16`), 74 = the second type is
  signed (`S8`, else `U8`), 75 = `-Rc`; 72, 78, 79 text-inert, as are [63:40] and [95:80] without 91.

Twelve legal forms per operand shape. The type pair is order-sensitive and the sorted mod-group name
cannot tell `S8.U8` from `U8.S8` (`U16.S8` would print as `S8.U16`), so the mixed-type forms carry
typed keys (D2, the owner's decision for NEEDS 36 of 2026-11-06; coldface's `IDP.4A.{S8.U8,U8.S8}`
rows are the first of them) and the symmetric forms stay mod-group rows of `IDP_R_R_R_R` /
`IDP_R_R_UR_R` (sm121a keeps its typed keys for every register form).

`probe [--arch SM120|SM103|SM100|SM121]` writes `tests/fixtures/<table>_idp_nvdisasm.jsonl`;
`apply <table.json>` rewrites the family's rows on that table (the schema follows the table: sm121a
carries typed register-form keys).
"""
from __future__ import annotations

import argparse
import itertools
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import nvprobe  # noqa: E402

PROVENANCE = "idp-family-2026-11-06"
D2_PROVENANCE = "idp-mixed-d2-2026-11-06"
LANE_PROVENANCE = "idp-types-sm120-2026-11-04"
CTRL = 0x001f_8c00 << 96
TABLE_OF = {"SM120": "sm120", "SM103": "sm103a", "SM100": "sm100a", "SM121": "sm121a"}
MODES = {0: "4A", 1: "2A.LO", 3: "2A.HI"}
FORMS = [(mode, s1, s2) for mode in (0, 1, 3) for s1 in (0, 1) for s2 in (0, 1)]


def mnemonic(mode: int, s1: int, s2: int) -> str:
    t1 = ("S" if s1 else "U") + ("8" if mode == 0 else "16")
    t2 = ("S" if s2 else "U") + "8"
    return f"IDP.{MODES[mode]}.{t1}.{t2}"


def word(mode, s1, s2, ur, rd=15, ra=15, rb=6, rc=7, neg=0, guard=7, extra=0):
    enum = (mode << 4) | (s1 << 1) | (s2 << 2) | (neg << 3)
    return ((ur << 91) | (enum << 72) | (rc << 64) | (rb << 32) | (ra << 24) | (rd << 16) | (guard << 12)
            | (0xc26 if ur else 0x226) | extra)


def expected_text(w: int) -> str | None:
    enum = (w >> 72) & 0xff
    mode = (enum >> 4) & 3
    ur = (w >> 91) & 1
    if mode == 2 or ((w & 0xfff) == 0xc26) != bool(ur):
        return None
    s1, s2, neg = (enum >> 1) & 1, (enum >> 2) & 1, (enum >> 3) & 1
    guard = (w >> 12) & 0xf
    g = "" if guard == 7 else (f"@P{guard} " if guard < 7 else ("@!PT " if guard == 15 else f"@!P{guard - 8} "))
    reg = lambda n: "RZ" if n == 255 else f"R{n}"  # noqa: E731
    ureg = lambda n: "URZ" if n == 255 else f"UR{n}"  # noqa: E731
    rd, ra, rb, rc = (w >> 16) & 0xff, (w >> 24) & 0xff, (w >> 32) & 0xff, (w >> 64) & 0xff
    return f"{g}{mnemonic(mode, s1, s2)} {reg(rd)}, {reg(ra)}, {ureg(rb) if ur else reg(rb)}, {'-' if neg else ''}{reg(rc)}"


def sweep_words():
    """(word, lattice) pairs: the form words (every legal text predicted) and the lattice around them."""
    out, seen = [], set()

    def add(w, lattice):
        if w not in seen:
            seen.add(w)
            out.append((w, lattice))

    for ur in (0, 1):
        for mode, s1, s2 in FORMS:
            add(word(mode, s1, s2, ur), False)
            add(word(mode, s1, s2, ur, neg=1), False)
        for mode, s1, s2 in ((0, 1, 1), (3, 0, 1)):  # the operand lattice on one 4A and one 2A form
            for n in (0, 1, 200, 255):
                add(word(mode, s1, s2, ur, rd=n), False)
                add(word(mode, s1, s2, ur, ra=n), False)
                add(word(mode, s1, s2, ur, rc=n), False)
            for n in (0, 1, 63, 200, 255):
                add(word(mode, s1, s2, ur, rb=n), False)
            for g in (3, 8, 15):
                add(word(mode, s1, s2, ur, guard=g), False)
        # the whole enum window: the 64 illegal mode-10 words and the text-inert 72 / 78 / 79 variants
        for v in range(256):
            w = word(0, 0, 0, ur) & ~(0xff << 72) | (v << 72)
            add(w, True)
        # the frame bit and a few text-inert bits
        add(word(0, 1, 1, ur) ^ (1 << 91), True)
        for bit in (40, 51, 62, 63, 80, 90, 95):
            add(word(0, 1, 1, ur) | (1 << bit), True)
    return out


def lattice_ok(w, t):
    if t is None:
        return True
    canonical = w & ~((1 << 72) | (1 << 78) | (1 << 79) | (0xffffff << 40) | (0x7ff << 80) | (0xf << 92))
    return t == expected_text(canonical)


def probe(nvdisasm, arch, out):
    rows = nvprobe.probe_words(nvdisasm, "idp", sweep_words(), CTRL,
                               check_form=lambda w, t: t == expected_text(w),
                               check_lattice=lattice_ok, arch=arch)
    nvprobe.write_fixture(out, rows)
    n_form = sum(1 for r in rows if not r.get("lattice"))
    print(f"{out}: {n_form} form words, {len(rows) - n_form} lattice words ({arch})")


NOTE = ("IDP measured with nvdisasm 13.1 (-b SM120 = SM103 = SM100 = SM121), tools/probes/re_sm120_idp.py (session T-11, "
        "2026-11-06): guard [15:12], Rd [23:16], Ra [31:24], Rb / URb [39:32] (the uniform form = opcode byte 0xc26 + bit 91), "
        "Rc [71:64]; [77:76] the mode (4A / 2A.LO / 2A.HI, 10 illegal), 73 / 74 the signedness of the two types, 75 -Rc; "
        "72, 78, 79, [63:40], [95:80] text-inert and fail closed. The mixed-type forms are typed keys (D2, NEEDS 36).")


def measured_row(mode, s1, s2, ur, src=PROVENANCE):
    fields = [nvprobe.field(12, 4, "guard", 0, src), nvprobe.field(16, 8, "reg", 1, src), nvprobe.field(24, 8, "reg", 2, src),
              nvprobe.field(32, 8, "ureg" if ur else "reg", 3, src), nvprobe.field(64, 8, "reg", 4, src),
              nvprobe.field(75, 1, "neg", 4, src),
              nvprobe.field(122, 1, "reuse", 2, src), nvprobe.field(123, 1, "reuse", 3, src), nvprobe.field(124, 1, "reuse", 4, src)]
    base = word(mode, s1, s2, ur, rd=0, ra=0, rb=0, rc=0, guard=0)
    return nvprobe.row(base, fields, src, NOTE)


def group_name(mode, s1, s2):
    """The sorted mod-group name of a symmetric form (`extract_mod_group` sorts the dotted tokens)."""
    return ",".join(sorted(mnemonic(mode, s1, s2).split(".")[1:]))


def apply(table_path):
    path = pathlib.Path(table_path)
    table = nvprobe.load_table(path)
    ins = table["instructions"]
    arch = table["_meta"]["architecture"]
    sm121a = arch.upper().startswith("SM121")
    sched_r = ins["IDP.4A.S8.S8_R_R_R_R"] if sm121a else ins["IDP_R_R_R_R"]
    sched_ur = ins["IDP_R_R_UR_R"]
    changed, added, retired = 0, 0, []

    def typed_key(mode, s1, s2, ur):
        return f"{mnemonic(mode, s1, s2)}_R_R_{'UR' if ur else 'R'}_R"

    def put_typed(key, mode, s1, s2, ur, template):
        nonlocal changed, added
        row = measured_row(mode, s1, s2, ur)
        entry = {k: v for k, v in template.items() if k in ("ctrl_class", "mercury", "scheduling")}
        entry.update({"base_op": mnemonic(mode, s1, s2), "operand_sig": f"R_R_{'UR' if ur else 'R'}_R",
                      "mod_groups": {"": row}, "_src": PROVENANCE})
        if key in ins:
            changed += 1
        else:
            added += 1
        ins[key] = entry

    def put_group(key, mode, s1, s2, ur):
        nonlocal changed, added
        name = group_name(mode, s1, s2)
        groups = ins[key]["mod_groups"]
        if name in groups:
            changed += 1
        else:
            added += 1
        groups[name] = measured_row(mode, s1, s2, ur)

    for mode, s1, s2 in FORMS:
        mixed = s1 != s2
        # register form
        if sm121a or mixed:
            if not sm121a and (mode, s1, s2) in ((0, 1, 0), (0, 0, 1)) and \
                    ins.get(typed_key(mode, s1, s2, 0), {}).get("mod_groups", {}).get("", {}).get("_src") == D2_PROVENANCE:
                pass  # coldface's D2 rows (NEEDS 36): a verbatim copy of the lane's measured 4A sibling, kept as taken
            else:
                put_typed(typed_key(mode, s1, s2, 0), mode, s1, s2, 0, sched_r)
        else:
            name = group_name(mode, s1, s2)
            if ins["IDP_R_R_R_R"]["mod_groups"].get(name, {}).get("_src") == LANE_PROVENANCE:
                pass  # the wave-11 lane's measured 4A rows (2026-11-04) stay
            else:
                put_group("IDP_R_R_R_R", mode, s1, s2, 0)
        # uniform-register form
        if mixed:
            put_typed(typed_key(mode, s1, s2, 1), mode, s1, s2, 1, sched_ur)
        else:
            put_group("IDP_R_R_UR_R", mode, s1, s2, 1)
    # the UR S8.S8 harvest row carried a `count` and the donor notes; the measured row replaces it whole
    for k in ("count",):
        ins["IDP_R_R_UR_R"]["mod_groups"]["4A,S8,S8"].pop(k, None)
    # coldface's typed U8.U8 UR key becomes the mod-group row like its register-form sibling
    aliases = table["_meta"].setdefault("key_aliases", {})
    if "IDP.4A.U8.U8_R_R_UR_R" in ins:
        del ins["IDP.4A.U8.U8_R_R_UR_R"]
        retired.append("IDP.4A.U8.U8_R_R_UR_R")
    if sm121a:
        # the two junk twins of the measured S8.S8 register row (one shares its and_base and mask, the other bakes
        # Rd = R65 / Rc = R44 under 8-bit fields at 27 / 34); their words decode through the measured key
        for junk in ("IDP.4A.S8.S8_R_R_R_R_?", "IDP.4A.S8.S8_R_R_R_R_II_?"):
            if junk in ins:
                del ins[junk]
                aliases[junk] = "IDP.4A.S8.S8_R_R_R_R"
                retired.append(junk)
    prov = table["_meta"].setdefault("provenance", {})
    sources = prov.setdefault("sources", {})
    rows = [g for e in ins.values() for g in e.get("mod_groups", {}).values()]
    prov["rows_total"] = len(rows)
    prov["rows_without_src"] = sum(1 for g in rows if g.get("_src") is None)
    sources[PROVENANCE] = {"rows": sum(1 for g in rows if g.get("_src") == PROVENANCE),
                           "kind": "nvdisasm 13.1 field probe (-b SM120 / SM103 / SM100 / SM121)", "date": "2026-11-06",
                           "tool": "tools/probes/re_sm120_idp.py", "test": "tests/sm120_idp.rs"}
    d2_rows = sum(1 for g in rows if g.get("_src") == D2_PROVENANCE)
    if d2_rows:  # coldface's D2 rows (blackwell-isa 42192f0) carried the tag without its legend entry
        sources[D2_PROVENANCE] = {"rows": d2_rows, "kind": "the wave-11 measured 4A sibling with the type bits 73 / 74 set "
                                  "(nvdisasm 13.3 -b SM103 / SM100 / SM120 / SM121 fixture, coldface, B300; re-measured on 13.1 by T-11)",
                                  "date": "2026-11-06", "tool": "pubwave/wave11/b300/idp_mixed_fixture.jsonl (B300) + tools/probes/re_sm120_idp.py",
                                  "test": "tests/wave11_idp_type_law.rs"}
    elif D2_PROVENANCE in sources:
        del sources[D2_PROVENANCE]
    nvprobe.save_table(path, table)
    print(f"{path} ({arch}): IDP rows rewritten {changed}, added {added}, keys retired {retired}")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("probe")
    p.add_argument("--nvdisasm", default="/usr/local/lib/python3.12/dist-packages/triton/backends/nvidia/bin/nvdisasm")
    p.add_argument("--arch", default="SM120", choices=sorted(TABLE_OF))
    p.add_argument("--out", type=pathlib.Path, default=None)
    a = sub.add_parser("apply")
    a.add_argument("table")
    args = parser.parse_args()
    if args.command == "probe":
        out = args.out or nvprobe.FIXTURES / f"{TABLE_OF[args.arch]}_idp_nvdisasm.jsonl"
        probe(args.nvdisasm, args.arch, out)
    else:
        apply(args.table)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""The predicate-file family PLOP3 / P2R / R2P: measure the whole operand lattice with nvdisasm and rebuild the
four keys from the measurement (session G, 2026-11-06; KNOWN_ISSUES T1 -- three PLOP3 harvest rows (one of
them a dotted twin), seven P2R and two R2P junk keys next to the dsv41 rows of 2026-10-22).

Forms (opcode [11:0]; bit 91 illegal on all three):
  PLOP3_P_P_P_P_P_II_II   0x81c  `PLOP3.LUT Pd0, Pd1, [!]Pa, [!]Pb, [!]Pc, lut, imm8`
  PLOP3_P_P_P_P_UP_II_II  0x81c + bit 67  -- the third source predicate is a uniform predicate `[!]UPc`
  P2R_R_II_R_II           0x803  `P2R[.B1|.B2|.B3] Rd, PR, Ra, imm32`
  R2P_II_R_II             0x804  `R2P PR, Ra[.B1|.B2|.B3], imm32`

Law (nvdisasm 13.1, one word per call, `-b SM120`; `probe --arch SM103` / `SM100` print the same text):
  PLOP3: guard [15:12]; imm8 [23:16]; [63:24] text-inert; the LUT = [66:64] (low 3 bits) + [76:72] (high 5
  bits); 67 = `UPc`; Pc [70:68] + `!` 71 (`PT` / `UPT` at 7); Pb [79:77] + `!` 80; Pd0 [83:81]; Pd1 [86:84];
  Pa [89:87] + `!` 90; `.LUT` is the only spelling ([95:92] text-inert).
  P2R: guard [15:12]; Rd [23:16]; Ra [31:24]; imm32 [63:32] (the dsv41 row of 2026-10-22 had swept 0..255
  and carried an 8-bit field -- the whole circumference moves the text); [77:76] the byte selector
  (`.B1` / `.B2` / `.B3`, 0 = none); `.reuse` Ra 122; the rest of [95:64] text-inert.
  R2P: guard [15:12]; [23:16] text-inert; Ra [31:24] with the byte selector [77:76] (`R0.B1`); imm32 [63:32],
  ELIDED by the vendor when it is 0xff (`R2P PR, R0`, `R2P PR, R0.B1`; every other value prints); `.reuse`
  Ra 122; the rest of [95:64] text-inert. cubit prints the elision and encodes the bare spelling through the
  encode-only row `R2P_II_R` (0xff baked at [63:32]); the explicit `, 0xff` stays a bitwise alias.

`probe [--arch SM120|SM103|SM100] [--jobs N]` writes `tests/fixtures/<table>_plop3_p2r_r2p_nvdisasm.jsonl`;
`apply <sm120.json>` rewrites the four keys and retires as `_meta.key_aliases`: `PLOP3.LUT_P_P_P_P_P_II_II`
(the dotted twin; the era alias `PLOP3.LUT_P1_P_P_P_P_P_II_II` is retargeted), the seven P2R junk keys
(`P2R.B1_R_R_R_II`, `P2R_R_L_R_II`, `P2R_R_R_R_II`, `P2R_R_R_R_II_II`, `P2R_R_R_R_II_II_?`,
`P2R_R_R_R_II_II_II_?`, `P2R_R_R_R_II_II_II_II_?` -- the `PR` token read as a register / label, 7-bit and
2-bit-shifted fields) and the two R2P junk keys (`R2P_?_R_II` with a 2-bit-shifted register, `R2P_L_R_II`).
"""
from __future__ import annotations

import argparse
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import nvprobe  # noqa: E402

PROVENANCE = "plop3-p2r-r2p-family-2026-11-06"
CTRL = 0x000f_e200 << 96
TABLE_OF = {"SM120": "sm120", "SM103": "sm103a", "SM100": "sm100a", "SM121": "sm121a"}
BSEL = {0: "", 1: ".B1", 2: ".B2", 3: ".B3"}
RETIRED = {"PLOP3.LUT_P_P_P_P_P_II_II": "PLOP3_P_P_P_P_P_II_II",
           "P2R.B1_R_R_R_II": "P2R_R_II_R_II", "P2R_R_L_R_II": "P2R_R_II_R_II", "P2R_R_R_R_II": "P2R_R_II_R_II",
           "P2R_R_R_R_II_II": "P2R_R_II_R_II", "P2R_R_R_R_II_II_?": "P2R_R_II_R_II", "P2R_R_R_R_II_II_II_?": "P2R_R_II_R_II",
           "P2R_R_R_R_II_II_II_II_?": "P2R_R_II_R_II", "R2P_?_R_II": "R2P_II_R_II", "R2P_L_R_II": "R2P_II_R_II"}


def pred(n, inv=0, uniform=False):
    return ("!" if inv else "") + ("U" if uniform else "") + ("PT" if n == 7 else f"P{n}")


def reg(n):
    return "RZ" if n == 255 else f"R{n}"


def plop3(up=0, guard=7, pd0=0, pd1=7, pa=1, npa=0, pb=7, npb=0, pc=7, npc=0, lut=0x8, imm=0x80, extra=0):
    return (0x81c | (guard << 12) | (imm << 16) | ((lut & 7) << 64) | (up << 67) | (pc << 68) | (npc << 71) | ((lut >> 3) << 72)
            | (pb << 77) | (npb << 80) | (pd0 << 81) | (pd1 << 84) | (pa << 87) | (npa << 90) | extra)


def p2r(bsel=0, guard=7, rd=17, ra=255, imm=0x40, extra=0):
    return 0x803 | (guard << 12) | (rd << 16) | (ra << 24) | (imm << 32) | (bsel << 76) | extra


def r2p(bsel=0, guard=7, ra=0, imm=0x6, extra=0):
    return 0x804 | (guard << 12) | (ra << 24) | (imm << 32) | (bsel << 76) | extra


def expected_text(w: int) -> str | None:
    if (w >> 91) & 1:
        return None
    guard = (w >> 12) & 0xf
    g = "" if guard == 7 else (f"@P{guard} " if guard < 7 else ("@!PT " if guard == 15 else f"@!P{guard - 8} "))
    opc = w & 0xfff
    if opc == 0x81c:
        lut = ((w >> 64) & 7) | (((w >> 72) & 0x1f) << 3)
        up = (w >> 67) & 1
        return (f"{g}PLOP3.LUT {pred((w >> 81) & 7)}, {pred((w >> 84) & 7)}, {pred((w >> 87) & 7, (w >> 90) & 1)}, "
                f"{pred((w >> 77) & 7, (w >> 80) & 1)}, {pred((w >> 68) & 7, (w >> 71) & 1, bool(up))}, 0x{lut:x}, 0x{(w >> 16) & 0xff:x}")
    reuse = ".reuse" if (w >> 122) & 1 else ""
    if opc == 0x803:
        return f"{g}P2R{BSEL[(w >> 76) & 3]} {reg((w >> 16) & 0xff)}, PR, {reg((w >> 24) & 0xff)}{reuse}, 0x{(w >> 32) & 0xffffffff:x}"
    if opc == 0x804:
        imm = (w >> 32) & 0xffffffff
        mask = "" if imm == 0xff else f", 0x{imm:x}"  # the vendor elides the all-ones byte mask
        return f"{g}R2P PR, {reg((w >> 24) & 0xff)}{reuse}{BSEL[(w >> 76) & 3]}{mask}"  # `R20.reuse.B2`
    return None


INERT = {0x81c: [*range(24, 64), 92, 93, 94, 95], 0x803: [*range(64, 76), *range(78, 91), 92, 93, 94, 95],
         0x804: [*range(16, 24), *range(64, 76), *range(78, 91), 92, 93, 94, 95]}


def sweep_words():
    out, seen = [], set()

    def add(w, lattice=False):
        if w not in seen:
            seen.add(w)
            out.append((w, lattice))

    for up in (0, 1):
        add(plop3(up))
        for guard in (0, 3, 8, 15):
            add(plop3(up, guard=guard))
        for n in range(8):
            add(plop3(up, pd0=n))
            add(plop3(up, pd1=n))
            add(plop3(up, pa=n))
            add(plop3(up, pa=n, npa=1))
            add(plop3(up, pb=n))
            add(plop3(up, pb=n, npb=1))
            add(plop3(up, pc=n))
            add(plop3(up, pc=n, npc=1))
        for lut in (0, 1, 7, 8, 0x80, 0xc0, 0xf8, 0xff, 0x96):
            add(plop3(up, lut=lut))
        for imm in (0, 1, 0x7f, 0xff, 0x8):
            add(plop3(up, imm=imm))
        add(plop3(up, guard=11, pd0=5, pd1=6, pa=2, npa=1, pb=3, npb=1, pc=4, npc=1, lut=0x5a, imm=0xa5))
    for bsel in range(4):
        add(p2r(bsel))
        add(r2p(bsel))
    for guard in (0, 3, 8, 15):
        add(p2r(guard=guard))
        add(r2p(guard=guard))
    for n in (0, 1, 200, 255):
        add(p2r(rd=n))
        add(p2r(ra=n))
        add(r2p(ra=n))
    for imm in (0, 1, 0xff, 0x100, 0xffff, 0x7fffffff, 0x80000000, 0xffffffff):
        add(p2r(imm=imm))
        add(r2p(imm=imm))
    add(p2r(extra=1 << 122))
    add(r2p(extra=1 << 122))
    add(p2r(bsel=3, guard=11, rd=10, ra=20, imm=0x12345678, extra=1 << 122))
    add(r2p(bsel=2, guard=11, ra=20, imm=0x12345678, extra=1 << 122))
    # lattice: the frame bit, the text-inert bits
    for base in (plop3(0), plop3(1), p2r(), r2p()):
        add(base | (1 << 91), lattice=True)
        for bit in INERT[base & 0xfff]:
            add(base | (1 << bit), lattice=True)
    return out


def lattice_ok(w, t):
    if t is None:
        return (w >> 91) & 1 == 1
    return t == expected_text(w & ~sum(1 << b for b in INERT[w & 0xfff]))


def probe(nvdisasm, arch, out, jobs):
    rows = nvprobe.probe_words(nvdisasm, "plop3_p2r_r2p", sweep_words(), CTRL, check_form=lambda w, t: t == expected_text(w),
                               check_lattice=lattice_ok, arch=arch, jobs=jobs)
    nvprobe.write_fixture(out, rows)
    n_form = sum(1 for r in rows if not r.get("lattice"))
    print(f"{out}: {n_form} form words, {len(rows) - n_form} lattice words ({arch})")


NOTE = ("PLOP3 / P2R / R2P measured with nvdisasm 13.1 (-b SM120 = SM103 = SM100), tools/probes/re_sm120_plop3_p2r_r2p.py "
        "(session G, 2026-11-06). PLOP3 (0x81c): guard [15:12], imm8 [23:16], LUT = [66:64] + [76:72], bit 67 = the third source "
        "predicate is uniform (UPc), Pc [70:68] + ! 71, Pb [79:77] + ! 80, Pd0 [83:81], Pd1 [86:84], Pa [89:87] + ! 90; [63:24] and "
        "[95:92] text-inert. P2R (0x803): Rd [23:16], Ra [31:24], imm32 [63:32] (the whole circumference moves the text; the "
        "2026-10-22 row had 8 bits), byte selector [77:76] as the mnemonic suffix, .reuse Ra 122. R2P (0x804): Ra [31:24] with the "
        "byte selector [77:76] as the operand suffix, imm32 [63:32], .reuse Ra 122, [23:16] text-inert. Bit 91 illegal on all three; "
        "the rest of [95:64] text-inert and fail closed.")


def rows():
    src = PROVENANCE
    out = {}
    for up in (0, 1):
        p = "upred" if up else "pred"
        n = "inv" if up else "neg"
        fields = [nvprobe.field(12, 4, "guard", 0, src), nvprobe.field(81, 3, "pred", 1, src), nvprobe.field(84, 3, "pred", 2, src),
                  nvprobe.field(87, 3, "pred", 3, src), nvprobe.field(90, 1, "neg", 3, src), nvprobe.field(77, 3, "pred", 4, src),
                  nvprobe.field(80, 1, "neg", 4, src), nvprobe.field(68, 3, p, 5, src), nvprobe.field(71, 1, n, 5, src),
                  nvprobe.field(64, 3, "imm", 6, src), nvprobe.field(72, 5, "imm_shr3", 6, src), nvprobe.field(16, 8, "imm", 7, src)]
        key = "PLOP3_P_P_P_P_UP_II_II" if up else "PLOP3_P_P_P_P_P_II_II"
        out[key] = {"LUT": nvprobe.row(0x81c | (up << 67), fields, src, NOTE)}
    p2r_fields = [nvprobe.field(12, 4, "guard", 0, src), nvprobe.field(16, 8, "reg", 1, src), nvprobe.field(24, 8, "reg", 3, src),
                  nvprobe.field(32, 32, "imm", 4, src), nvprobe.field(122, 1, "reuse", 3, src)]
    out["P2R_R_II_R_II"] = {BSEL[b].lstrip("."): nvprobe.row(0x803 | (b << 76), p2r_fields, src, NOTE) for b in range(4)}
    r2p_fields = [nvprobe.field(12, 4, "guard", 0, src), nvprobe.field(24, 8, "reg", 2, src), nvprobe.field(76, 2, "byte_sel", 2, src),
                  nvprobe.field(32, 32, "imm", 3, src), nvprobe.field(122, 1, "reuse", 2, src)]
    out["R2P_II_R_II"] = {"": nvprobe.row(0x804, r2p_fields, src, NOTE)}
    # the vendor's elided spelling `R2P PR, Ra[.Bn]` = the byte mask 0xff: an encode-only row with the mask baked
    out["R2P_II_R"] = {"": nvprobe.row(0x804 | (0xff << 32), [f for f in r2p_fields if f["shift"] != 32], src, NOTE)}
    return out


def apply(table_path):
    path = pathlib.Path(table_path)
    table = nvprobe.load_table(path)
    ins = table["instructions"]
    n_rows = 0
    for key, groups in rows().items():
        old = ins.get(key) or ins["R2P_II_R_II"]  # R2P_II_R is new: the entry attributes of its 3-operand twin
        entry = {k: v for k, v in old.items() if k in ("base_op", "ctrl_class", "mercury", "operand_sig", "scheduling")}
        if key in ins:
            # sm120 (2026-11-06): the harvest had exactly the measured groups; sm103a / sm100a / sm121a (T-21, 2026-11-08):
            # a subset (P2R without the .B2 / .B3 selectors), never a group outside the lattice
            assert set(old["mod_groups"]) <= set(groups), f"{key}: harvest groups outside the lattice: {set(old['mod_groups']) - set(groups)}"
        else:
            entry["operand_sig"] = "II_R"
            entry["encode_only"] = True
        entry["mod_groups"] = groups
        entry["_src"] = PROVENANCE
        ins[key] = entry
        n_rows += len(groups)
    aliases = table["_meta"].setdefault("key_aliases", {})
    retired = []
    for junk, target in RETIRED.items():
        if junk in ins:
            del ins[junk]
            aliases[junk] = target
            retired.append(junk)
    for alias, target in list(aliases.items()):
        if target in RETIRED:
            aliases[alias] = RETIRED[target]  # the era alias PLOP3.LUT_P1_... follows its retired target
    prov = table["_meta"]["provenance"]
    all_rows = [g for e in ins.values() for g in e.get("mod_groups", {}).values()]
    prov["rows_total"] = len(all_rows)
    prov["rows_without_src"] = sum(1 for g in all_rows if g.get("_src") is None)
    arch = next((a for a, t in TABLE_OF.items() if path.name.startswith(t)), "SM120")
    # T-21 (2026-11-08): sm103a / sm100a / sm121a -- the same law measured on the table's own target (the probe run with
    # --arch SM103 / SM100 / SM121 asserts it word by word). The sm103a / sm100a harvest PLOP3_P_P_P_P_P_II_II row carried a
    # 4-bit "pred" field at bit 2 -- inside the opcode nibble -- and claimed every word of opcodes 0x80c..0x83c that fit
    # its remaining bits (the bit-80 ISETP immediate words of NEEDS 46 decoded as `PLOP3.LUT P0, P3, PT, !P0, ...`).
    prov["sources"][PROVENANCE] = {"rows": n_rows, "kind": "nvdisasm 13.1 field probe (-b SM120 / SM103 / SM100 / SM121)",
                                   "date": "2026-11-06" if arch == "SM120" else "2026-11-08",
                                   "tool": "tools/probes/re_sm120_plop3_p2r_r2p.py",
                                   "test": {"SM120": "tests/sm120_plop3_p2r_r2p.rs", "SM121": "tests/sm121a_plop3_p2r_r2p.rs"}.get(arch, "tests/sm103a_sm100a_plop3_p2r_r2p.rs")}
    nvprobe.save_table(path, table)
    print(f"{path}: PLOP3 / P2R / R2P rows rewritten {n_rows}; keys retired as aliases: {retired}")


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
        out = args.out or nvprobe.FIXTURES / f"{TABLE_OF[args.arch]}_plop3_p2r_r2p_nvdisasm.jsonl"
        probe(args.nvdisasm, args.arch, out, args.jobs)
    else:
        apply(args.table)


if __name__ == "__main__":
    main()

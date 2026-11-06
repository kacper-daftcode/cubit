#!/usr/bin/env python3
"""Measure the SM120 register-indirect control-flow family -- `BRX` (0x949), `BRXU` (0x958 + the frame
bit 91) and `RET` (0x950; bit 91 = the uniform-register form) -- over its modifier x operand lattice
with nvdisasm and rebuild the keys from the measurement.

Why (dynamic audit T1, session T-10 2026-11-06): the 13 harvest keys / 15 rows of the three opcodes
(`BRX_II`, `BRX_L`, `BRXU_II`, `BRXU_L`, `RET_II`, `RET_L`, `RET.REL.NODEC_II`, `RET.REL.NODEC_R`,
`RET.ABS.NODEC_?`, ...) carried the register under junk fields (`imm@18:20` + `reg@25:8`, `guard_neg@16`,
a `_?` key without fields) and decoded `RET.REL.NODEC R8 -0x1fef0` as `RET.REL.NODEC 0xfffe0110`
(no register, the 32-bit wrap of the offset) or `BRXU UR20 -0x1fdf0` as `BRXU 0xfffe0220`; the printer
spelt the vendor's `BRX R8 -0x3f00` (register and target are one operand, no comma) as `BRX R8, -0x3f00`.

Measured with nvdisasm 13.1 (`-b SM120`, one word per call; `-b SM103` / `-b SM100` print the same
text for the 0x949 / 0x950 / 0x958 words):

  * register operand [31:24] (255 = RZ / URZ); the offset is a signed 56-bit dword at [23:16] (bits
    [9:2]) + [81:34] (bits [57:10]) -- the BRA split;
  * BRX / BRXU print `Rn <off * 4>` relative to the register (no PC term; the `0x0` offset is elided:
    `BRX R8`); RET.REL prints `Rn <PC + 16 + off * 4>` (always), RET.ABS `Rn <off * 4>` (always);
  * guard [15:12]; predicate operand [89:87] + `!` 90, printed before the register with a comma when
    not `PT` (`BRX !P3, R8 0x100`, `RET.ABS.NODEC P2, UR8 0x100`);
  * BRX: 85 `.INC`, 86 `.DEC` (both `.INVALID3`); bit 91 illegal; bits 32-33 inert;
    BRXU: 85 `.INC`, 86 `.DEC`, mode [33:32] 0 plain / 1 `.U` / 2 `.DIV` / 3 `.CONV`, print order
    `BRXU[.INC|.DEC][.U|.DIV|.CONV]`; bit 91 required;
    RET: 85 `.ABS` (clear = `.REL`, always printed), 86 `.NODEC`; bits 32-33 inert; bit 91 = UR form;
  * bits 82-84 and 92-95 text-inert on the three opcodes (baked at 0, outside the rows: fail-closed).

`probe` writes `tests/fixtures/sm120_brx_ret_nvdisasm.jsonl`; `apply <sm120.json>` replaces every
`BRX*` / `BRXU*` / `RET*` key with the measured keys `BRX_R_II`, `BRX_P_R_II`, `BRXU_UR_II`,
`BRXU_P_UR_II`, `RET_R_II`, `RET_P_R_II`, `RET_UR_II`, `RET_P_UR_II` (one group per legal modifier
set; `PT` elided = baked on the keys without `_P_`). Test: `tests/sm120_brx_ret.rs`.
"""
import argparse
import itertools
import pathlib
import re
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import nvprobe  # noqa: E402

PROVENANCE = "brx-ret-family-2026-11-06"
CTRL = 0x000fe200 << 96
FIXTURE = nvprobe.FIXTURES / "sm120_brx_ret_nvdisasm.jsonl"
OPC = {"BRX": 0x949, "BRXU": 0x958, "RET": 0x950}
MODE = {0: "", 1: "U", 2: "DIV", 3: "CONV"}
TEXT = re.compile(
    r"(@!?P[0-6T] )?(BRX|BRXU|RET)((?:\.(?:INC|DEC|U|DIV|CONV|REL|ABS|NODEC))*)"
    r"( !?P[0-6T],)? (?:R|UR)(?:Z|\d+)( -?0x[0-9a-f]+)?")


def word(op, reg=8, off=0x40, guard=7, pred=7, neg=0, inc=0, dec=0, mode=0, abs_=0, nodec=0, uform=False, extra=0):
    o = off & ((1 << 56) - 1)
    w = (OPC[op] | (guard << 12) | (reg << 24) | ((o & 0xff) << 16) | ((o >> 8) << 34) | (pred << 87) | (neg << 90) | extra)
    if op == "BRXU":
        w |= (1 << 91) | (mode << 32) | (inc << 85) | (dec << 86)
    elif op == "BRX":
        w |= (inc << 85) | (dec << 86)
    else:
        w |= (abs_ << 85) | (nodec << 86) | ((1 << 91) if uform else 0)
    return w


def op_of(w):
    return {v: k for k, v in OPC.items()}[w & 0xfff]


def mods_of(w):
    op = op_of(w)
    toks = []
    if op in ("BRX", "BRXU"):
        if (w >> 85) & 1:
            toks.append("INC")
        if (w >> 86) & 1:
            toks.append("DEC")
        if op == "BRXU" and MODE[(w >> 32) & 3]:
            toks.append(MODE[(w >> 32) & 3])
    else:
        toks.append("ABS" if (w >> 85) & 1 else "REL")
        if (w >> 86) & 1:
            toks.append("NODEC")
    return toks


def expected_text(w):
    """The vendor text of a legal form word, predicted from the layout (asserted by `probe`)."""
    op = op_of(w)
    guard = (w >> 12) & 0xf
    g = "" if guard == 7 else ("@" + ("!" if guard & 8 else "") + ("PT" if (guard & 7) == 7 else f"P{guard & 7}") + " ")
    mods = "".join("." + m for m in mods_of(w))
    p, n = (w >> 87) & 7, (w >> 90) & 1
    pred = "" if (p == 7 and n == 0) else (("!" if n else "") + ("PT" if p == 7 else f"P{p}") + ", ")
    reg = (w >> 24) & 0xff
    uniform = op == "BRXU" or (op == "RET" and (w >> 91) & 1)
    reg_s = ("URZ" if uniform else "RZ") if reg == 255 else (f"UR{reg}" if uniform else f"R{reg}")
    off = ((w >> 16) & 0xff) | (((w >> 34) & ((1 << 48) - 1)) << 8)
    if off & (1 << 55):
        off -= 1 << 56
    if op == "RET" and not (w >> 85) & 1:
        tgt = 16 + (off << 2)
    else:
        tgt = off << 2
    if op != "RET" and tgt == 0:
        tgt_s = ""
    else:
        tgt_s = f" -0x{-tgt:x}" if tgt < 0 else f" 0x{tgt:x}"
    return f"{g}{op}{mods} {pred}{reg_s}{tgt_s}"


def legal_mods(op):
    out = []
    if op == "BRX":
        for inc, dec in ((0, 0), (1, 0), (0, 1)):
            out.append(dict(inc=inc, dec=dec))
    elif op == "BRXU":
        for mode, (inc, dec) in itertools.product(range(4), ((0, 0), (1, 0), (0, 1))):
            out.append(dict(mode=mode, inc=inc, dec=dec))
    else:
        for abs_, nodec, uform in itertools.product((0, 1), (0, 1), (False, True)):
            out.append(dict(abs_=abs_, nodec=nodec, uform=uform))
    return out


def sweep_words():
    form, lattice = set(), set()
    offs = (0x40, 0, 0x3fc, -0x4, -0x10, -0x3f10, 0x10000, -0x10000, 0x7ffffffffffffc, -0x80000000000000)
    for op in OPC:
        for m in legal_mods(op):
            for off in offs:
                form.add(word(op, off=off, **m))
            for reg in (0, 2, 255):
                form.add(word(op, reg=reg, **m))
            for guard in (0, 6, 8, 15):
                form.add(word(op, guard=guard, **m))
            for pred, neg in ((0, 0), (2, 0), (3, 1), (7, 1)):
                form.add(word(op, pred=pred, neg=neg, **m))
            form.add(word(op, guard=2, pred=5, neg=1, reg=20, off=-0x50, **m))
        base = word(op)
        for bit in (82, 83, 84, 92, 93, 94, 95):
            lattice.add(base | (1 << bit))  # text-inert
        if op in ("BRX", "BRXU"):
            lattice.add(word(op, inc=1, dec=1))  # INVALID3
        if op == "BRX":
            lattice.add(base | (1 << 91))  # the frame bit on BRX: illegal
            lattice.add(base | (1 << 32))  # mode bits inert on BRX
            lattice.add(base | (1 << 33))
        if op == "RET":
            lattice.add(base | (1 << 32))
            lattice.add(base | (1 << 33))
        if op == "BRXU":
            lattice.add(base & ~(1 << 91))  # BRXU without the frame bit: illegal
    lattice -= form
    return [(w, False) for w in sorted(form)] + [(w, True) for w in sorted(lattice)]


def lattice_ok(w, t):
    if t is None:
        return True
    inert = t == expected_text(w & ~((0xf << 92) | (7 << 82) | (3 << 32)))
    return inert or "INVALID" in t


def probe(nvdisasm, out=FIXTURE, arch="SM120"):
    rows = nvprobe.probe_words(
        nvdisasm, "brx_ret", sweep_words(), CTRL,
        check_form=lambda w, t: TEXT.fullmatch(t) is not None and t == expected_text(w),
        check_lattice=lattice_ok, arch=arch)
    nvprobe.write_fixture(out, rows)
    n_form = sum(1 for r in rows if not r.get("lattice"))
    print(f"{out}: {n_form} form words, {len(rows) - n_form} lattice words")


NOTE = ("BRX / BRXU / RET family (0x949 / 0x958 + bit 91 / 0x950, bit 91 = the UR form) measured with nvdisasm 13.1 "
        "-b SM120, tools/probes/re_sm120_brx_ret.py (session T-10, 2026-11-06): register [31:24], offset = a signed "
        "56-bit dword [23:16] + [81:34] printed as `Rn off*4` (BRX/BRXU, 0 elided; RET.ABS) or `Rn PC+16+off*4` "
        "(RET.REL); predicate operand [89:87] + 90 before the register; BRX/BRXU 85 INC, 86 DEC, BRXU mode [33:32] "
        "U/DIV/CONV; RET 85 ABS (else REL), 86 NODEC; bits 82-84, 92-95 text-inert and outside the row.")


def group_rows(op, with_pred, uniform):
    src = PROVENANCE
    groups = {}
    for m in legal_mods(op):
        if op == "RET" and m["uform"] != uniform:
            continue
        tok = 1
        fields = [nvprobe.field(12, 4, "guard", 0, src)]
        if with_pred:
            fields += [nvprobe.field(87, 3, "pred", tok, src), nvprobe.field(90, 1, "neg", tok, src)]
            tok += 1
        fields.append(nvprobe.field(24, 8, "ureg" if uniform else "reg", tok, src))
        tok += 1
        fields += [nvprobe.field(16, 8, "imm_shr2", tok, src), nvprobe.field(34, 48, "imm_shr10", tok, src)]
        base = word(op, reg=0, off=0, guard=0, pred=0 if with_pred else 7, neg=0, **m)
        base &= ~nvprobe.field_mask(fields)
        name = ",".join(sorted(mods_of(word(op, **m))))
        groups[name] = nvprobe.row(base, fields, src, NOTE)
    return groups


def apply(table_path):
    path = pathlib.Path(table_path)
    table = nvprobe.load_table(path)
    ins = table["instructions"]
    old_keys = [k for k in ins if k.split("_")[0].split(".")[0] in OPC]
    new_keys = ["BRX_R_II", "BRX_P_R_II", "BRXU_UR_II", "BRXU_P_UR_II", "RET_R_II", "RET_P_R_II", "RET_UR_II", "RET_P_UR_II"]
    if sorted(old_keys) == sorted(new_keys) and all(g.get("_src") == PROVENANCE for k in old_keys for g in ins[k]["mod_groups"].values()):
        print("BRX/BRXU/RET: already measured")
        return
    old_rows = sum(len(ins[k]["mod_groups"]) for k in old_keys)
    for k in old_keys:
        del ins[k]
    new = {
        "BRX_R_II": ("BRX", group_rows("BRX", False, False)),
        "BRX_P_R_II": ("BRX", group_rows("BRX", True, False)),
        "BRXU_UR_II": ("BRXU", group_rows("BRXU", False, True)),
        "BRXU_P_UR_II": ("BRXU", group_rows("BRXU", True, True)),
        "RET_R_II": ("RET", group_rows("RET", False, False)),
        "RET_P_R_II": ("RET", group_rows("RET", True, False)),
        "RET_UR_II": ("RET", group_rows("RET", False, True)),
        "RET_P_UR_II": ("RET", group_rows("RET", True, True)),
    }
    total = 0
    for key, (op, groups) in new.items():
        ins[key] = {"base_op": op, "operand_sig": key[len(op):], "mod_groups": groups, "_src": PROVENANCE}
        total += len(groups)
    aliases = table["_meta"].setdefault("key_aliases", {})
    for old, plain in (("RET.REL.NODEC_R_II", "RET_R_II"), ("RET.REL.NODEC_R", "RET_R_II"), ("BRXU.U_UR_II", "BRXU_UR_II")):
        if old in old_keys:
            aliases[old] = plain
    prov = table["_meta"].setdefault("provenance", {})
    sources = prov.setdefault("sources", {})
    rows = [g for e in ins.values() for g in e.get("mod_groups", {}).values()]
    prov["rows_total"] = len(rows)
    prov["rows_without_src"] = sum(1 for g in rows if g.get("_src") is None)
    sources[PROVENANCE] = {
        "rows": total,
        "kind": "nvdisasm 13.1 field probe (-b SM120)",
        "date": "2026-11-06",
        "tool": "tools/probes/re_sm120_brx_ret.py",
        "test": "tests/sm120_brx_ret.rs",
    }
    nvprobe.save_table(path, table)
    print(f"{path}: BRX/BRXU/RET {len(old_keys)} keys / {old_rows} rows -> {len(new)} keys / {total} measured rows")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("probe")
    p.add_argument("--nvdisasm", default="/usr/local/lib/python3.12/dist-packages/triton/backends/nvidia/bin/nvdisasm")
    p.add_argument("--out", type=pathlib.Path, default=FIXTURE)
    p.add_argument("--arch", default="SM120", choices=["SM120", "SM103", "SM100"])
    a = sub.add_parser("apply")
    a.add_argument("table")
    args = parser.parse_args()
    if args.command == "probe":
        probe(args.nvdisasm, args.out, args.arch)
    else:
        apply(args.table)


if __name__ == "__main__":
    main()

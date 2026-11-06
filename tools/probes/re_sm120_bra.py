#!/usr/bin/env python3
"""Measure the SM120 `BRA` family (opcode 0x947, the uniform-predicate form 0x547) over its whole
modifier x operand lattice with nvdisasm and rebuild the `BRA*` keys from the measurement.

Why (dynamic audit T1, session T-9 2026-11-06, the family with the most defective rows after LEA):
the 15 harvest keys / 33 rows (`BRA_II_II_II_?`, `BRA_P_II_II_?`, `BRA.U_?_II`, `BRA.DIV_UR_II`,
triplicated `CONV` / `DIV` groups with `guard@29` / `imm_shr3@28` junk fields, `BRA_UP_II [""]` and
`BRA_UR_II [""]` twins of `BRA_II [""]`, `BRA_UP_II [U]` claiming `BRA.INVALID1 UR0, 0x50` words,
`BRA_P_UR_II [CONV]` printing `PT, UR6` for the vendor's `~UR6`) and the printer's 32-bit wrap of
a negative target (`BRA 0xffffeb60` for nvdisasm's `BRA -0x14a0`).

Measured with nvdisasm 13.1 (`-b SM120`, one word per call; `-b SM103` / `-b SM100` print the same
text for every probe word -- the 0x547 uniform-predicate form is illegal there):

  * target: a signed 56-bit dword offset from PC + 16, bits [9:2] at [23:16] and [57:10] at [81:34];
    nvdisasm prints `PC + 16 + offset` as a signed hexadecimal (`BRA -0x14a0` at address 0);
  * guard [15:12] (7 = none); predicate operand [89:87] + `!` 90 (7 / 0 elided, `BRA !PT, 0x50`
    printed); uniform register operand [31:24] (255 = URZ) only with the frame bit 91, `~` = bit 82;
  * mode [33:32]: 0 plain, 1 `.U`, 2 `.DIV`, 3 `.CONV`; bit 85 `.INC`, bit 86 `.DEC` (both =
    `.INVALID3`); with `.U` only: bit 83 `.NOT_TID0`, bit 84 `.ANY` (inert otherwise);
    print order `BRA[.INC|.DEC][.U|.DIV|.CONV][.ANY][.NOT_TID0]`;
  * bit 91 (the UR operand) is legal with `.DIV` / `.CONV` only (`.INVALID0` / `.INVALID1` else);
  * opcode 0x547 + bit 91 = the uniform-predicate form `BRA.U[.ANY][.NOT_TID0] [!]UPn, target`
    (UP [26:24], `!` 27; `.U` required, `.???n` without it; `INC` / `DEC` legal; `.DIV` / `.CONV`
    `.???n`); a vector predicate operand may precede the UP (`BRA.U P2, UP0, 0x50`);
  * bits 92-95 and the UR field without bit 91 text-inert (baked at 0, outside the rows).

`probe` writes `tests/fixtures/sm120_bra_nvdisasm.jsonl` (every legal combination as a form word
plus the lattice); `apply <sm120.json>` replaces every `BRA*` key with the measured keys
`BRA_II`, `BRA_P_II`, `BRA_UR_II`, `BRA_P_UR_II`, `BRA_UP_II`, `BRA_P_UP_II` (one group per legal
modifier set; the `PT` operand elided = baked on the keys without `_P_`).

SM103a / SM100a parity (session T-10, 2026-11-06): `probe --arch SM103` / `SM100` measures the same
551 words with `nvdisasm -b SM103` / `-b SM100` -- every text is identical to the SM120 text, the
uniform-predicate form 0x547 included (T-9's note that it was sm_120-only was wrong: nvdisasm 13.1
renders `BRA.U UP0, 0x110` on the three targets, and the sm103a harvest counted 17 806 such words).
`apply --arch sm103a <sm103a.json>` (and `sm100a`) replaces the 5 harvest keys / 9 rows of those
tables with the same six measured keys (fixtures `tests/fixtures/sm103a_bra_nvdisasm.jsonl`,
`sm100a_bra_nvdisasm.jsonl`; test `tests/sm103a_sm100a_bra.rs`).
"""
import argparse
import itertools
import pathlib
import re
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import nvprobe  # noqa: E402

PROVENANCE = "bra-family-2026-11-06"
NATIVE_CTRL = 0x000fea00 << 96  # the vendor's BRA control word; nvdisasm rejects 0x947 with others
FIXTURE = nvprobe.FIXTURES / "sm120_bra_nvdisasm.jsonl"
MODE = {0: "", 1: "U", 2: "DIV", 3: "CONV"}
TEXT = re.compile(
    r"(@!?P[0-6T] )?BRA((?:\.(?:INC|DEC|U|DIV|CONV|ANY|NOT_TID0))*)"
    r"( !?P[0-6T],)?( !?UP[0-7T],| ~?UR(?:Z|\d+),)? (-?0x[0-9a-f]+)")


def word(mode=0, inc=0, dec=0, any_=0, nt=0, guard=7, pred=7, neg=0, ur=None, inv=0, up=None,
         upneg=0, upform=False, off=0x40, extra=0):
    opc = 0x547 if upform else 0x947
    o = off & ((1 << 56) - 1)
    w = (opc | (guard << 12) | ((o >> 0) & 0xff) << 16 | ((o >> 8) & ((1 << 48) - 1)) << 34
         | (mode << 32) | (inc << 85) | (dec << 86) | (any_ << 84) | (nt << 83)
         | (pred << 87) | (neg << 90) | extra)
    if ur is not None:
        w |= (1 << 91) | (ur << 24) | (inv << 82)
    if up is not None:
        w |= (1 << 91) | (up << 24) | (upneg << 27)
    return w


def mods_of(w):
    mode = (w >> 32) & 3
    toks = []
    if (w >> 85) & 1:
        toks.append("INC")
    if (w >> 86) & 1:
        toks.append("DEC")
    if MODE[mode]:
        toks.append(MODE[mode])
    if mode == 1 and (w >> 84) & 1:
        toks.append("ANY")
    if mode == 1 and (w >> 83) & 1 and (w & 0xfff) != 0x547:
        toks.append("NOT_TID0")
    return toks


def expected_text(w):
    """The vendor text of a legal form word, predicted from the layout (asserted by `probe`)."""
    guard = (w >> 12) & 0xf
    g = "" if guard == 7 else ("@" + ("!" if guard & 8 else "") + ("PT" if (guard & 7) == 7 else f"P{guard & 7}") + " ")
    mods = "".join("." + m for m in mods_of(w))
    ops = []
    p, n = (w >> 87) & 7, (w >> 90) & 1
    if not (p == 7 and n == 0):
        ops.append(("!" if n else "") + ("PT" if p == 7 else f"P{p}"))
    if (w >> 91) & 1:
        if (w & 0xfff) == 0x547:
            up, un = (w >> 24) & 7, (w >> 27) & 1
            ops.append(("!" if un else "") + ("UPT" if up == 7 else f"UP{up}"))
        else:
            ur = (w >> 24) & 0xff
            ops.append(("~" if (w >> 82) & 1 else "") + ("URZ" if ur == 255 else f"UR{ur}"))
    off = ((w >> 16) & 0xff) | (((w >> 34) & ((1 << 48) - 1)) << 8)
    if off & (1 << 55):
        off -= 1 << 56
    tgt = 16 + (off << 2)
    ops.append(f"-0x{-tgt:x}" if tgt < 0 else f"0x{tgt:x}")
    return f"{g}BRA{mods} {', '.join(ops)}"


def legal_mods(upform):
    """Every modifier combination the family admits (the lattice words document the rest)."""
    out = []
    for mode, inc, dec, any_, nt in itertools.product(range(4), (0, 1), (0, 1), (0, 1), (0, 1)):
        if inc and dec:
            continue
        if (any_ or nt) and mode != 1:
            continue
        if upform and (mode != 1 or nt):
            continue  # the UP form: `.U` required, bit 83 (NOT_TID0) text-inert
        out.append(dict(mode=mode, inc=inc, dec=dec, any_=any_, nt=nt))
    return out


def sweep_words():
    form, lattice = set(), set()
    offs = (0x40, 0, 0x3fc, 0x400, 0x10000, -0x50, -0x14b0, -0x10000, 0x7ffffffffffffc, -0x80000000000000)
    for m in legal_mods(False):
        for off in offs:
            form.add(word(off=off, **m))
        for guard in (0, 6, 8, 15):
            form.add(word(guard=guard, **m))
        for pred, neg in ((0, 0), (2, 0), (2, 1), (6, 1), (7, 1)):
            form.add(word(pred=pred, neg=neg, **m))
        if m["mode"] in (2, 3):
            for ur in (0, 6, 63, 255):
                form.add(word(ur=ur, **m))
                form.add(word(ur=ur, inv=1, **m))
            form.add(word(ur=6, pred=2, neg=1, **m))
            form.add(word(ur=6, inv=1, pred=7, neg=1, **m))
            form.add(word(ur=6, guard=3, pred=5, off=-0x50, **m))
        else:
            lattice.add(word(ur=6, **m))  # bit 91 without DIV / CONV: INVALIDn
    for m in legal_mods(True):
        for up in (0, 3, 7):
            form.add(word(up=up, upform=True, **m))
            form.add(word(up=up, upneg=1, upform=True, **m))
        form.add(word(up=0, pred=2, upform=True, **m))
        form.add(word(up=0, pred=7, neg=1, upform=True, **m))
        form.add(word(up=3, guard=9, off=-0x50, upform=True, **m))
    base = word()
    lattice.add(word(inc=1, dec=1))  # INVALID3
    for bit in (92, 93, 94, 95):
        lattice.add(base | (1 << bit))
    for bit in (83, 84):  # inert without .U
        lattice.add(base | (1 << bit))
        lattice.add(word(mode=2) | (1 << bit))
    lattice.add(word(ur=6, inv=1) & ~(1 << 91))  # bit 82 without the UR form: inert
    lattice.add(base | (6 << 24))  # UR field without bit 91: inert
    for mode in (0, 2, 3):  # 0x547 without .U / with DIV / CONV: ???n
        lattice.add(word(up=0, upform=True, mode=mode))
    lattice.add(word(up=0, upform=True, mode=1, nt=1))  # bit 83 inert on the UP form
    lattice.add(word(upform=True))  # 0x547 without bit 91: illegal
    lattice.add(word(mode=1, upform=True))
    lattice -= form
    return [(w, False) for w in sorted(form)] + [(w, True) for w in sorted(lattice)]


def lattice_ok(w, t):
    if t is None:
        return True
    inert = TEXT.fullmatch(t) is not None and t == expected_text(w & ~((0xf << 92) | (3 << 83) | (1 << 82) | (0xff << 24)))
    return inert or "INVALID" in t or "???" in t


def probe(nvdisasm, out=FIXTURE, arch="SM120"):
    rows = nvprobe.probe_words(
        nvdisasm, "bra", sweep_words(), NATIVE_CTRL,
        check_form=lambda w, t: TEXT.fullmatch(t) is not None and t == expected_text(w),
        check_lattice=lattice_ok, arch=arch)
    nvprobe.write_fixture(out, rows)
    n_form = sum(1 for r in rows if not r.get("lattice"))
    print(f"{out}: {n_form} form words, {len(rows) - n_form} lattice words")


def group_rows(key, upform, with_pred, with_ur):
    src = PROVENANCE
    groups = {}
    for m in legal_mods(upform):
        tok = 1
        fields = [nvprobe.field(12, 4, "guard", 0, src)]
        if with_pred:
            fields += [nvprobe.field(87, 3, "pred", tok, src), nvprobe.field(90, 1, "neg", tok, src)]
            tok += 1
        if with_ur and upform:
            fields += [nvprobe.field(24, 3, "upred", tok, src), nvprobe.field(27, 1, "inv", tok, src)]
            tok += 1
        elif with_ur:
            fields += [nvprobe.field(24, 8, "ureg", tok, src), nvprobe.field(82, 1, "inv", tok, src)]
            tok += 1
        fields += [nvprobe.field(16, 8, "imm_shr2", tok, src), nvprobe.field(34, 48, "imm_shr10", tok, src)]
        base = word(guard=0, pred=0 if with_pred else 7, neg=0, off=0, upform=upform,
                    **({"up": 0} if (with_ur and upform) else {"ur": 0} if with_ur else {}), **m)
        base &= ~nvprobe.field_mask(fields)
        name = ",".join(sorted(mods_of(word(**m))))
        note = ("BRA family (0x947; 0x547 + bit 91 = the uniform-predicate form) measured with nvdisasm 13.1 -b SM120, "
                "tools/probes/re_sm120_bra.py (session T-9, 2026-11-06): target = PC + 16 + signed 56-bit dword offset "
                "[23:16] + [81:34]; mode [33:32] plain/U/DIV/CONV, 85 INC, 86 DEC, 84 ANY and 83 NOT_TID0 with .U; "
                "predicate operand [89:87] + 90; UR operand [31:24] + ~ 82 with the frame bit 91 (DIV/CONV only); "
                "bits 92-95 text-inert and outside the row.")
        groups[name] = nvprobe.row(base, fields, src, note)
    return groups


def apply(table_path, arch="sm120"):
    path = pathlib.Path(table_path)
    table = nvprobe.load_table(path)
    ins = table["instructions"]
    old_keys = [k for k in ins if k.split("_")[0].split(".")[0] == "BRA"]
    if old_keys == ["BRA_II", "BRA_P_II", "BRA_UR_II", "BRA_P_UR_II", "BRA_UP_II", "BRA_P_UP_II"] and \
            all(g.get("_src") == PROVENANCE for k in old_keys for g in ins[k]["mod_groups"].values()):
        print("BRA: already measured")
        return
    old_rows = sum(len(ins[k]["mod_groups"]) for k in old_keys)
    for k in old_keys:
        del ins[k]
    new = {
        "BRA_II": group_rows("BRA_II", False, False, False),
        "BRA_P_II": group_rows("BRA_P_II", False, True, False),
        "BRA_UR_II": {n: g for n, g in group_rows("BRA_UR_II", False, False, True).items() if "DIV" in n or "CONV" in n},
        "BRA_P_UR_II": {n: g for n, g in group_rows("BRA_P_UR_II", False, True, True).items() if "DIV" in n or "CONV" in n},
        "BRA_UP_II": group_rows("BRA_UP_II", True, False, True),
        "BRA_P_UP_II": group_rows("BRA_P_UP_II", True, True, True),
    }
    total = 0
    for key, groups in new.items():
        ins[key] = {"base_op": "BRA", "operand_sig": key[len("BRA"):], "mod_groups": groups, "_src": PROVENANCE}
        total += len(groups)
    # key aliases of the retired dotted keys (user text and old tests resolve to the plain keys)
    aliases = table["_meta"].setdefault("key_aliases", {})
    for old, plain in (("BRA.U_UP_II", "BRA_UP_II"), ("BRA.DIV_UR_II", "BRA_UR_II"), ("BRA.U_?_II", "BRA_II")):
        if old in old_keys:
            aliases[old] = plain
    prov = table["_meta"].setdefault("provenance", {})
    sources = prov.setdefault("sources", {})
    rows = [g for e in ins.values() for g in e.get("mod_groups", {}).values()]
    prov["rows_total"] = len(rows)
    prov["rows_without_src"] = sum(1 for g in rows if g.get("_src") is None)
    nv_arch = {"sm120": "SM120", "sm103a": "SM103", "sm100a": "SM100"}[arch]
    sources[PROVENANCE] = {
        "rows": total,
        "kind": f"nvdisasm 13.1 field probe (-b {nv_arch})",
        "date": "2026-11-06",
        "tool": "tools/probes/re_sm120_bra.py",
        "test": "tests/sm120_bra.rs" if arch == "sm120" else "tests/sm103a_sm100a_bra.rs",
    }
    if arch != "sm120":
        sources[PROVENANCE]["note"] = ("SM103a / SM100a parity of the SM120 measurement (T-10): the 551 probe words render "
                                       f"the same text on -b {nv_arch}; fixture tests/fixtures/{arch}_bra_nvdisasm.jsonl")
    nvprobe.save_table(path, table)
    print(f"{path}: BRA {len(old_keys)} keys / {old_rows} rows -> 6 keys / {total} measured rows")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("probe")
    p.add_argument("--nvdisasm", default="/usr/local/lib/python3.12/dist-packages/triton/backends/nvidia/bin/nvdisasm")
    p.add_argument("--out", type=pathlib.Path, default=None)
    p.add_argument("--arch", default="SM120", choices=["SM120", "SM103", "SM100"], help="nvdisasm -b target")
    a = sub.add_parser("apply")
    a.add_argument("table")
    a.add_argument("--arch", default="sm120", choices=["sm120", "sm103a", "sm100a"])
    args = parser.parse_args()
    if args.command == "probe":
        out = args.out or (FIXTURE if args.arch == "SM120" else nvprobe.FIXTURES / f"{args.arch.lower()}a_bra_nvdisasm.jsonl")
        probe(args.nvdisasm, out, args.arch)
    else:
        apply(args.table, args.arch)


if __name__ == "__main__":
    main()

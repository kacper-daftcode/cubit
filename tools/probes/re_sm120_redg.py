#!/usr/bin/env python3
"""The global reduction (opcode 0x98e) in its two uniform-indexed address forms: measure the whole modifier x operand
lattice of the plain keys `REDG_ARURI_R` (`[Ra.U32+URb(+off)]`) and `REDG_ARURI64_R` (`[Ra.64+URb(+off)]`) with
nvdisasm and rebuild them from the measurement (session G, 2026-11-07, run 4; KNOWN_ISSUES T1 / NEEDS 45 -- the
6 144 dotted one-group harvest keys `REDG.E.<op>[.cache][.type].<scope>_{ARURI,ARURI64}_R` of 2026-08/09, 0 census
witnesses). The descriptor form (`REDG_dARI_R`, census-bearing, T's bug203 / bug206 rows) and the plain `[Ra(+off)]`
form (`REDG_ARI_R`, bit 91 clear) are not touched here.

Form:  `REDG[.E].<op>[.cache][.type][.strength[.scope]][.PRIVATE] <addr>, Rb`
  addr  ARURI    bit 91 = 1, 90 = 0   `[Ra.U32+URb(+off)]`   Ra = RZ prints `[RZ.U32+URb(+off)]` (not elided)
        ARURI64  bit 91 = 1, 90 = 1   `[Ra.64+URb(+off)]`    Ra = RZ prints the vendor's degenerate glyph
                                                             `[???255.64+URb(+off)]` (BUG-461: printed text-faithfully,
                                                             never minted by the encoder)
  (bit 81 with 91 = 1 and 90 = 1 is the descriptor form `desc[URb][Ra.64]`, with 90 = 0 illegal; bit 91 clear is the
   `[Ra(+off)]` form in which 90 and 81 are inert -- all outside this probe's keys)

Law (nvdisasm 13.1, one word per call, `-b SM120`; `probe --arch SM103` / `SM100` record the other targets):
guard [15:12]; [23:16] text-inert (the atomic's destination slot; no register on the reduction); Ra [31:24]; Rb
[39:32]; the offset [63:40] = a signed 24-bit byte count (`+0x1` .. `+0x7fffff`, `+-0x800000` .. `+-0x1`); URb
[71:64] (255 = URZ); 72 = `.E`; [75:73] = the type (0 none = U32, 1 S32, 2 64, 3 S64; 4..7 = INVALIDn -- a lattice
plane); 76 text-inert; [80:77] = the 16-value strength / scope / PRIVATE enum (0 none, 1 CONSTANT.PRIVATE, 2
CONSTANT.CTA, 3 CONSTANT.CTA.PRIVATE, 4 STRONG.SM.PRIVATE, 5 STRONG.SM, 6 STRONG.GPU.PRIVATE, 7 STRONG.GPU, 8 MMIO.GPU,
9 CONSTANT.SM, 10 STRONG.SYS, 11 CONSTANT.SM.PRIVATE, 12 MMIO.SYS, 13 CONSTANT.VC, 14 CONSTANT.VC.PRIVATE, 15
CONSTANT.GPU -- the load's enum with STRONG.SM.PRIVATE at 4); 81 = descriptor (not here); 82, 83 text-inert; cache
[86:84] (0 EF, 1 none, 2 EL, 3 LU, 4 EU, 5 NA; 6 / 7 = INVALID6 / INVALID7); [89:87] = the op (ADD, MIN, MAX, INC, DEC,
AND, OR, XOR); 90 = the `.64` base; 91 = the uniform-indexed form. [95:92] text-inert. Every text-inert bit fails
closed on the measured rows.

Groups: U32 form 2 (E) x 8 ops x 4 types x 6 cache x 16 scope = 6 144; `.64` form 3 072 (`.E` only -- without it the
vendor prints `REDG.???0.<op>…`, the 64-bit base needs the extended-address flag; a lattice plane); 9 216 on the two
keys (the harvest covered the 3 072 `.E` groups per key, one dotted key each, and never saw the no-`.E` words).

`probe [--arch SM120|SM103|SM100] [--jobs N]` writes `tests/fixtures/<table>_redg_aruri_nvdisasm.jsonl`;
`apply <sm120.json>` rewrites the two keys (creating them) and retires the dotted one-group keys of the two forms as
`_meta.key_aliases` of the plain key of their operand signature (every retired key's modifier tokens name a group of
the target).
"""
from __future__ import annotations

import argparse
import collections
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import nvprobe  # noqa: E402

PROVENANCE = "redg-aruri-family-2026-11-07"
CTRL = 0x000f_e200 << 96
OPC = 0x98e
FRAME = 1 << 91  # the uniform-indexed form
TABLE_OF = {"SM120": "sm120", "SM103": "sm103a", "SM100": "sm100a"}
ADDR = {"ARURI": 0, "ARURI64": 1}  # address form -> bit 90
SCOPE = ["", "CONSTANT.PRIVATE", "CONSTANT.CTA", "CONSTANT.CTA.PRIVATE", "STRONG.SM.PRIVATE", "STRONG.SM",
         "STRONG.GPU.PRIVATE", "STRONG.GPU", "MMIO.GPU", "CONSTANT.SM", "STRONG.SYS", "CONSTANT.SM.PRIVATE", "MMIO.SYS",
         "CONSTANT.VC", "CONSTANT.VC.PRIVATE", "CONSTANT.GPU"]
CACHE = ["EF", "", "EL", "LU", "EU", "NA", "INVALID6", "INVALID7"]
TYPE = ["", "S32", "64", "S64", "INVALID4", "INVALID5", "INVALID6", "INVALID7"]
OP = ["ADD", "MIN", "MAX", "INC", "DEC", "AND", "OR", "XOR"]


def key_name(form):
    return f"REDG_{form}_R"


KEYS = [key_name(form) for form in ADDR]
SIGS = {k.split("_", 1)[1] for k in KEYS}


def groups_of(form):
    """group name (sorted tokens) -> modifier bits, the legal grid of the address form (the `.64` base needs `.E`:
    the no-`.E` words of that form print the `???0` glyph -- a lattice plane)."""
    out = {}
    for e in ((1, 0) if form == "ARURI" else (1,)):
        for op in range(8):
            for ty in range(4):
                for c in range(6):
                    for sc in range(16):
                        toks = [OP[op]] + (["E"] if e else []) + ([TYPE[ty]] if TYPE[ty] else []) + ([CACHE[c]] if CACHE[c] else []) \
                            + (SCOPE[sc].split(".") if SCOPE[sc] else [])
                        out[",".join(sorted(toks))] = (e << 72) | (op << 87) | (ty << 73) | (c << 84) | (sc << 77)
    assert len(out) == (6144 if form == "ARURI" else 3072)
    return out


GROUPS = {form: groups_of(form) for form in ADDR}
LOADED = ",".join(sorted(["E", "XOR", "S64", "NA", "CONSTANT", "VC", "PRIVATE"]))
PLAIN = ",".join(sorted(["ADD", "E"]))


def word(form, mods=0, guard=7, ra=2, rb=6, ur=4, imm=0, extra=0):
    return OPC | FRAME | (ADDR[form] << 90) | (guard << 12) | (ra << 24) | (rb << 32) | ((imm & 0xffffff) << 40) | (ur << 64) | mods | extra


def form_of(w):
    if (w & 0xfff) != OPC or not (w >> 91) & 1 or (w >> 81) & 1:
        return None
    return "ARURI64" if (w >> 90) & 1 else "ARURI"


def key_of(w):
    form = form_of(w)
    return None if form is None else key_name(form)


def expected_text(w):
    form = form_of(w)
    if form is None:
        return None
    ty, c = (w >> 73) & 7, (w >> 84) & 7
    if ty >= 4 or c >= 6:
        return None  # INVALID planes: named by the vendor, not a form word
    if form == "ARURI64" and not (w >> 72) & 1:
        return None  # the `.64` base without `.E`: the vendor's `???0` glyph, a lattice plane
    guard = (w >> 12) & 0xf
    g = "" if guard == 7 else (f"@P{guard} " if guard < 7 else ("@!PT " if guard == 15 else f"@!P{guard - 8} "))
    reg = lambda n: "RZ" if n == 255 else f"R{n}"  # noqa: E731
    ureg = lambda n: "URZ" if n == 255 else f"UR{n}"  # noqa: E731
    e, op, sc = (w >> 72) & 1, (w >> 87) & 7, (w >> 77) & 0xf
    mods = (".E" if e else "") + f".{OP[op]}" + (f".{CACHE[c]}" if CACHE[c] else "") + (f".{TYPE[ty]}" if TYPE[ty] else "") \
        + (f".{SCOPE[sc]}" if SCOPE[sc] else "")
    imm = (w >> 40) & 0xffffff
    if imm & 0x800000:
        imm -= 1 << 24
    off = "" if imm == 0 else (f"+{imm:#x}" if imm > 0 else f"+-{-imm:#x}")
    ra, ur = (w >> 24) & 0xff, (w >> 64) & 0xff
    if form == "ARURI64":
        base = "???255" if ra == 255 else f"R{ra}"
        addr = f"[{base}.64+{ureg(ur)}{off}]"
    else:
        addr = f"[{reg(ra)}.U32+{ureg(ur)}{off}]"
    return f"{g}REDG{mods} {addr}, {reg((w >> 32) & 0xff)}"


def text_ok(w, t):
    return t is not None and t == expected_text(w)


INERT = [16, 17, 18, 19, 20, 21, 22, 23, 76, 82, 83, 92, 93, 94, 95]


def sweep_words():
    out, seen = [], set()

    def add(w, kind="form"):
        if w not in seen:
            seen.add(w)
            out.append((w, kind))

    for form in ADDR:
        groups = GROUPS[form]
        for mods in groups.values():
            add(word(form, mods))
        for mods in (groups[PLAIN], groups[LOADED]):
            for guard in (0, 3, 8, 15):
                add(word(form, mods, guard=guard))
            for n in (0, 1, 63, 255):
                add(word(form, mods, rb=n))
                add(word(form, mods, ur=n))
                add(word(form, mods, ra=n))
            add(word(form, mods, ra=255, ur=255))
            for imm in (1, 0x10, 0x1234, 0x7fffff, 0x800000, 0xffffff):
                add(word(form, mods, imm=imm))
                add(word(form, mods, ra=255, imm=imm))
        add(word(form, groups[LOADED], guard=11, ra=10, rb=250, ur=20, imm=0x123456))
        # the lattice: the form bit, the inert bits, the INVALID type / cache planes, the descriptor bit, the `.64`
        # base without `.E` (the `???0` glyph plane)
        base = word(form, groups[PLAIN])
        add(base ^ (1 << 91), "lattice")
        for bit in INERT:
            add(base | (1 << bit), "lattice")
        add(word(form, groups[LOADED]) | (1 << 83) | (1 << 20), "lattice")
        for ty in (4, 5, 6, 7):
            add(word(form, groups[PLAIN] | (ty << 73)), "lattice")
        for c in (6, 7):
            add(word(form, groups[PLAIN] | (c << 84)), "lattice")
            add(word(form, groups[LOADED] & ~(7 << 84) | (c << 84)), "lattice")
        add(word(form, groups[PLAIN] | (7 << 73) | (7 << 84)), "lattice")
        add(base | (1 << 81), "lattice")
        if form == "ARURI64":
            for mods in (groups[PLAIN], groups[LOADED], groups[",".join(sorted(["E", "MAX", "64", "EL", "STRONG", "GPU"]))]):
                add(word(form, mods & ~(1 << 72)), "lattice")
                add(word(form, mods & ~(1 << 72), ra=255, imm=0x10), "lattice")
    return out


def lattice_ok(w, t):
    """Lattice words: illegal, or named with an INVALIDn glyph, or the inert-bit twin of a form word, or a word of
    another form (the descriptor form, the `[Ra(+off)]` form) -- never a word this probe's keys should claim."""
    if t is None:
        return True
    if (w & 0xfff) != OPC:
        return False
    if not (w >> 91) & 1:
        return t.startswith("REDG") and "+UR" not in t  # the `[Ra(+off)]` form
    if (w >> 81) & 1:
        return "desc[" in t  # the descriptor form (bit 90 set; with 90 clear the vendor rejects the word)
    if (w >> 90) & 1 and not (w >> 72) & 1:
        return "REDG.???0." in t  # the `.64` base without `.E`
    ty, c = (w >> 73) & 7, (w >> 84) & 7
    glyph = lambda n: f".INVALID{n}." in t or f".INVALID{n} " in t  # noqa: E731  (the glyph may be the last modifier)
    if ty >= 4:
        return glyph(ty)
    if c >= 6:
        return glyph(c)
    mask = sum(1 << b for b in INERT)
    return text_ok(w & ~mask, t)


def probe(nvdisasm, arch, out, jobs):
    words = sweep_words()
    rows = nvprobe.probe_words(nvdisasm, "redg_aruri", [(w, kind != "form") for w, kind in words], CTRL,
                               check_form=text_ok, check_lattice=lattice_ok, arch=arch, jobs=jobs)
    nvprobe.write_fixture(out, rows)
    n_form = sum(1 for r in rows if not r.get("lattice"))
    keys = collections.Counter(key_of(int(r["word"], 16)) for r in rows if not r.get("lattice"))
    print(f"{out}: {n_form} form words ({dict(keys)}), {len(rows) - n_form} lattice words ({arch})")


NOTE = ("REDG 0x98e (the global reduction, uniform-indexed address forms) measured with nvdisasm 13.1 (-b SM120), "
        "tools/probes/re_sm120_redg.py (session G, 2026-11-07): guard [15:12], Ra [31:24], Rb [39:32], the signed 24-bit byte offset "
        "[63:40], URb [71:64], .E 72, the type [75:73], the 16-value strength / scope / PRIVATE enum [80:77], cache [86:84], the op "
        "[89:87], the .64 base 90, the uniform-indexed form 91. [23:16], 76, 82, 83 and [95:92] are text-inert and fail closed; "
        "bit 81 (the descriptor form) is another key; the .64 form prints base 255 as the vendor's ???255 glyph (BUG-461).")


def measured_row(key, mods, src=PROVENANCE):
    form = key.split("_")[1]
    fields = [nvprobe.field(12, 4, "guard", 0, src), nvprobe.field(24, 8, "reg", 1, src), nvprobe.field(64, 8, "ureg", 1, src),
              nvprobe.field(40, 24, "imm", 1, src), nvprobe.field(32, 8, "reg", 2, src)]
    base = word(form, mods, guard=0, ra=0, rb=0, ur=0)
    return nvprobe.row(base, fields, src, NOTE)


def same_row(old, new):
    strip = lambda f: {k: v for k, v in f.items() if k in ("bits", "extraction", "shift", "token_idx")}  # noqa: E731
    return (int(old["and_base"], 16) == int(new["and_base"], 16) and int(old["variable_mask"], 16) == int(new["variable_mask"], 16)
            and sorted(map(repr, map(strip, old["fields"]))) == sorted(map(repr, map(strip, new["fields"])))
            and old.get("claim_forbid") == new.get("claim_forbid") and old.get("_src"))


def dotted_keys(ins):
    """The dotted one-group REDG keys of the two forms, with the plain key they alias to."""
    out = {}
    for k in ins:
        if not k.startswith("REDG.") or "_" not in k:
            continue
        mn, sig = k.split("_", 1)
        if sig not in SIGS:
            continue
        groups = ins[k].get("mod_groups", {})
        assert len(groups) == 1, f"{k}: {len(groups)} groups"
        (g,) = groups.values()
        assert int(g["and_base"], 16) & 0xfff == OPC, f"{k}: not on 0x98e"
        toks = sorted(mn.split(".")[1:])
        assert ",".join(toks) in GROUPS[sig.split("_")[0]], f"{k}: the modifier tokens {toks} name no measured group"
        out[k] = f"REDG_{sig}"
    return out


def apply(table_path):
    path = pathlib.Path(table_path)
    table = nvprobe.load_table(path)
    ins = table["instructions"]
    live_before = collections.Counter(g.get("_src") for e in ins.values() for g in e.get("mod_groups", {}).values())
    retire = dotted_keys(ins)
    template = ins[next(iter(retire))] if retire else ins["REDG_dARI_R"]
    rewritten = added = kept = 0
    for key in KEYS:
        old = ins.get(key)
        entry = {k: v for k, v in (old or template).items() if k in ("ctrl_class", "scheduling")}
        entry["base_op"] = "REDG"
        entry["operand_sig"] = key.split("_", 1)[1]
        old_groups = old["mod_groups"] if old else {}
        groups = {}
        for name, mods in GROUPS[key.split("_")[1]].items():
            row = measured_row(key, mods)
            prev = old_groups.get(name)
            if prev is not None and same_row(prev, row):
                groups[name] = prev
                kept += 1
            else:
                groups[name] = row
                rewritten += prev is not None
                added += prev is None
        missing = set(old_groups) - set(groups)
        if missing:
            print(f"  {key}: {len(missing)} harvest groups outside the measured lattice retired: {sorted(missing)[:5]} ...")
        entry["mod_groups"] = groups
        entry["_src"] = PROVENANCE
        ins[key] = entry
    aliases = table["_meta"].setdefault("key_aliases", {})
    for junk, target in retire.items():
        del ins[junk]
        aliases[junk] = target
    prov = table["_meta"]["provenance"]
    rows = [g for e in ins.values() for g in e.get("mod_groups", {}).values()]
    prov["rows_total"] = len(rows)
    prov["rows_without_src"] = sum(1 for g in rows if g.get("_src") is None)
    prov["sources"][PROVENANCE] = {"rows": sum(1 for g in rows if g.get("_src") == PROVENANCE),
                                   "kind": "nvdisasm 13.1 field probe (-b SM120 / SM103 / SM100)", "date": "2026-11-07",
                                   "tool": "tools/probes/re_sm120_redg.py", "test": "tests/sm120_redg_aruri.rs"}
    live_after = collections.Counter(g.get("_src") for g in rows)
    for s, n in live_before.items():
        if s and s != PROVENANCE and live_after[s] != n and prov["sources"].get(s, {}).get("rows") == n:
            prov["sources"][s]["rows"] = live_after[s]
            print(f"  legend {s}: rows {n} -> {live_after[s]}")
    nvprobe.save_table(path, table)
    print(f"{path}: REDG ARURI / ARURI64: rows rewritten {rewritten}, groups added {added}, measured rows kept with their tag {kept}, "
          f"rows with the tag {prov['sources'][PROVENANCE]['rows']}; {len(retire)} dotted keys retired as aliases "
          f"({collections.Counter(retire.values())})")


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
        out = args.out or nvprobe.FIXTURES / f"{TABLE_OF[args.arch]}_redg_aruri_nvdisasm.jsonl"
        probe(args.nvdisasm, args.arch, out, args.jobs)
    else:
        apply(args.table)


if __name__ == "__main__":
    main()

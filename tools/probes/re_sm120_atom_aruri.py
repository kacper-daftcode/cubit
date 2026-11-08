#!/usr/bin/env python3
"""The global atomics ATOM (opcode 0x98a) and ATOMG (0x9a8) in the plain uniform-indexed address form: measure the whole
modifier x operand lattice of the plain keys `ATOM_P_R_ARURI_R` / `ATOMG_P_R_ARURI_R` (`Pd, Rd, [Ra.U32+URb(+off)], Rb`)
with nvdisasm and rebuild them from the measurement (session T-22, 2026-11-08; the sm121a line of KNOWN_ISSUES T1 -- the
3 456 + 3 456 dotted one-group harvest keys `ATOM[G].E.<op>[.type][.cache].<scope>_P_R_ARURI_R` of the GB10 line's
2026-08/09 rides, 0 census witnesses in the uniform-indexed form). Modelled on `re_sm120_redg.py` (G, 2026-11-07) and on
T-6's `re_sm120_atomg_el_aruri.py`, whose two `.EL` rows measured the operand layout of this form on sm120.

Form:  `ATOM[G][.E].<op>[.cache][.type][.strength[.scope]][.PRIVATE] Pd, Rd, [Ra.U32+URb(+off)], Rb`
  bit 91 = 1 (the uniform-indexed frame), bit 63 = 0 (the `.64` base `[Ra.64+URb]` is the `_P_R_ARURI64_R` form -- sm120's
  measured `ATOMG.E.{ADD,OR}.EL.STRONG.GPU_P_R_ARURI64_R` rows), bit 76 = 0 (with 63 it is the descriptor form
  `desc[URb][Ra.64]` -- the wave-11 `ATOM[G]_P_R_dARI_R` lattices; alone it is illegal).

Law (nvdisasm 13.1, one word per call; `-b SM121` = `-b SM120` = `-b SM103` = `-b SM100` for every word of the sweep):
guard [15:12]; Rd [23:16] (255 = RZ, printed); Ra [31:24] (255 prints `RZ.U32`); Rb [39:32]; the offset [62:40] = a
signed 23-bit byte count (`+0x1` .. `+0x3fffff`, `+-0x400000` .. `+-0x1`); URb [71:64] (255 = URZ); 72 = `.E`; [75:73] =
the type (0 none = U32, 1 S32, 2 64, 3 S64, 4 128; 5..7 = INVALIDn -- a lattice plane); 76 = the descriptor bit (not
here); [80:77] = the 16-value strength / scope / PRIVATE enum of the load / REDG (0 none, 1 CONSTANT.PRIVATE, 2
CONSTANT.CTA, 3 CONSTANT.CTA.PRIVATE, 4 STRONG.SM.PRIVATE, 5 STRONG.SM, 6 STRONG.GPU.PRIVATE, 7 STRONG.GPU, 8 MMIO.GPU,
9 CONSTANT.SM, 10 STRONG.SYS, 11 CONSTANT.SM.PRIVATE, 12 MMIO.SYS, 13 CONSTANT.VC, 14 CONSTANT.VC.PRIVATE, 15
CONSTANT.GPU); Pd [83:81] (7 = PT, printed); cache [86:84] (0 EF, 1 none, 2 EL, 3 LU, 4 EU, 5 NA; 6 / 7 = INVALID6 /
INVALID7); [90:87] = the op (0 ADD, 1 MIN, 2 MAX, 3 INC, 4 DEC, 5 AND, 6 OR, 7 XOR, 8 EXCH, 9 SAFEADD on ATOMG -- INVALID9
on ATOM --, 10..15 INVALIDn); 91 = the uniform-indexed form; [95:92] text-inert. Every text-inert bit fails closed on
the measured rows. The CAS form (`Pd, Rd, [addr], Rb, Rc`, the `_P_R_ARI_R_R` keys) and the float ops (`.F32.FTZ.RN`,
`.F64.RN` -- other type planes under other opcodes' frames) are outside this probe.

Groups: ATOM 2 (E) x 9 ops x 5 types x 6 cache x 16 scope = 8 640; ATOMG 2 x 10 x 5 x 6 x 16 = 9 600 (the harvest covered
the `.E` plane of 9 ops x 4 types = 3 456 one-group keys per opcode and never saw the no-`.E` words, the `.128` type or
SAFEADD).

`probe [--arch SM121|SM120|SM103|SM100] [--jobs N] [--witnesses <corpus.jsonl>]` writes
`tests/fixtures/<table>_atom_aruri_nvdisasm.jsonl`; `apply <table.json>` rewrites the two keys (creating them) and retires
the dotted one-group keys of the form as `_meta.key_aliases` of the plain key of their opcode (every retired key's
modifier tokens name a group of the target).
"""
from __future__ import annotations

import argparse
import collections
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import nvprobe  # noqa: E402

PROVENANCE = "atom-aruri-family-2026-11-08"
CTRL = 0x000f_e200 << 96
OPCS = {"ATOM": 0x98a, "ATOMG": 0x9a8}
FRAME = 1 << 91  # the uniform-indexed form
TABLE_OF = {"SM120": "sm120", "SM103": "sm103a", "SM100": "sm100a", "SM121": "sm121a"}
SCOPE = ["", "CONSTANT.PRIVATE", "CONSTANT.CTA", "CONSTANT.CTA.PRIVATE", "STRONG.SM.PRIVATE", "STRONG.SM",
         "STRONG.GPU.PRIVATE", "STRONG.GPU", "MMIO.GPU", "CONSTANT.SM", "STRONG.SYS", "CONSTANT.SM.PRIVATE", "MMIO.SYS",
         "CONSTANT.VC", "CONSTANT.VC.PRIVATE", "CONSTANT.GPU"]
CACHE = ["EF", "", "EL", "LU", "EU", "NA", "INVALID6", "INVALID7"]
TYPE = ["", "S32", "64", "S64", "128", "INVALID5", "INVALID6", "INVALID7"]
OP = ["ADD", "MIN", "MAX", "INC", "DEC", "AND", "OR", "XOR", "EXCH", "SAFEADD"] + [f"INVALID{n}" for n in range(10, 16)]
N_OPS = {"ATOM": 9, "ATOMG": 10}  # SAFEADD (op 9) exists on ATOMG only; ATOM prints INVALID9
N_TYPES = 5


def key_name(mn):
    return f"{mn}_P_R_ARURI_R"


KEYS = {mn: key_name(mn) for mn in OPCS}


def groups_of(mn):
    """group name (sorted tokens) -> modifier bits, the legal grid of the opcode."""
    out = {}
    for e in (1, 0):
        for op in range(N_OPS[mn]):
            for ty in range(N_TYPES):
                for c in range(6):
                    for sc in range(16):
                        toks = [OP[op]] + (["E"] if e else []) + ([TYPE[ty]] if TYPE[ty] else []) + ([CACHE[c]] if CACHE[c] else []) \
                            + (SCOPE[sc].split(".") if SCOPE[sc] else [])
                        out[",".join(sorted(toks))] = (e << 72) | (op << 87) | (ty << 73) | (c << 84) | (sc << 77)
    assert len(out) == 2 * N_OPS[mn] * N_TYPES * 6 * 16
    return out


GROUPS = {mn: groups_of(mn) for mn in OPCS}
LOADED = ",".join(sorted(["E", "XOR", "S64", "NA", "CONSTANT", "VC", "PRIVATE"]))
PLAIN = ",".join(sorted(["ADD", "E", "STRONG", "GPU"]))


def word(mn, mods=0, guard=7, pd=7, rd=4, ra=2, rb=6, ur=4, imm=0, extra=0):
    return OPCS[mn] | FRAME | (guard << 12) | (rd << 16) | (ra << 24) | (rb << 32) | ((imm & 0x7fffff) << 40) | (ur << 64) \
        | (pd << 81) | mods | extra


def mnemonic_of(w):
    for mn, opc in OPCS.items():
        if (w & 0xfff) == opc:
            return mn
    return None


def form_of(w):
    """The mnemonic when the word is in the probed form (frame set, neither the `.64` base nor the descriptor bit)."""
    mn = mnemonic_of(w)
    if mn is None or not (w >> 91) & 1 or (w >> 63) & 1 or (w >> 76) & 1:
        return None
    return mn


def key_of(w):
    mn = form_of(w)
    return None if mn is None else KEYS[mn]


def pred_text(n):
    return "PT" if n == 7 else f"P{n}"


def expected_text(w):
    mn = form_of(w)
    if mn is None:
        return None
    op, ty, c = (w >> 87) & 0xf, (w >> 73) & 7, (w >> 84) & 7
    if op >= N_OPS[mn] or ty >= N_TYPES or c >= 6:
        return None  # INVALID planes: named by the vendor, not a form word
    guard = (w >> 12) & 0xf
    g = "" if guard == 7 else (f"@P{guard} " if guard < 7 else ("@!PT " if guard == 15 else f"@!P{guard - 8} "))
    reg = lambda n: "RZ" if n == 255 else f"R{n}"  # noqa: E731
    ureg = lambda n: "URZ" if n == 255 else f"UR{n}"  # noqa: E731
    e, sc = (w >> 72) & 1, (w >> 77) & 0xf
    mods = (".E" if e else "") + f".{OP[op]}" + (f".{CACHE[c]}" if CACHE[c] else "") + (f".{TYPE[ty]}" if TYPE[ty] else "") \
        + (f".{SCOPE[sc]}" if SCOPE[sc] else "")
    imm = (w >> 40) & 0x7fffff
    if imm & 0x400000:
        imm -= 1 << 23
    off = "" if imm == 0 else (f"+{imm:#x}" if imm > 0 else f"+-{-imm:#x}")
    ra, ur = (w >> 24) & 0xff, (w >> 64) & 0xff
    addr = f"[{reg(ra)}.U32+{ureg(ur)}{off}]"
    return f"{g}{mn}{mods} {pred_text((w >> 81) & 7)}, {reg((w >> 16) & 0xff)}, {addr}, {reg((w >> 32) & 0xff)}"


def text_ok(w, t):
    return t is not None and t == expected_text(w)


INERT = [92, 93, 94, 95]


def sweep_words():
    out, seen = [], set()

    def add(w, kind="form"):
        if w not in seen:
            seen.add(w)
            out.append((w, kind))

    for mn in OPCS:
        groups = GROUPS[mn]
        for mods in groups.values():
            add(word(mn, mods))
        for mods in (groups[PLAIN], groups[LOADED]):
            for guard in (0, 3, 8, 15):
                add(word(mn, mods, guard=guard))
            for pd in (0, 1, 6):
                add(word(mn, mods, pd=pd))
                add(word(mn, mods, pd=pd, guard=9))
            for n in (0, 1, 63, 255):
                add(word(mn, mods, rd=n))
                add(word(mn, mods, rb=n))
                add(word(mn, mods, ur=n))
                add(word(mn, mods, ra=n))
            add(word(mn, mods, ra=255, ur=255, rd=255))
            for imm in (1, 0x10, 0x1234, 0x3fffff, 0x400000, 0x7fffff):
                add(word(mn, mods, imm=imm))
                add(word(mn, mods, ra=255, imm=imm))
        add(word(mn, groups[LOADED], guard=11, pd=2, rd=200, ra=10, rb=250, ur=20, imm=0x123456))
        # the lattice: the frame bit, the inert bits, the INVALID op / type / cache planes, the `.64` base, the
        # descriptor bit alone and with the base
        base = word(mn, groups[PLAIN])
        add(base ^ (1 << 91), "lattice")
        for bit in INERT:
            add(base | (1 << bit), "lattice")
        add(word(mn, groups[LOADED]) | (1 << 95) | (1 << 92), "lattice")
        for op in range(N_OPS[mn], 16):
            add(word(mn, groups[PLAIN] & ~(0xf << 87) | (op << 87)), "lattice")
        for ty in range(N_TYPES, 8):
            add(word(mn, groups[PLAIN] | (ty << 73)), "lattice")
            add(word(mn, groups[LOADED] & ~(7 << 73) | (ty << 73)), "lattice")
        for c in (6, 7):
            add(word(mn, groups[PLAIN] & ~(7 << 84) | (c << 84)), "lattice")
            add(word(mn, groups[LOADED] & ~(7 << 84) | (c << 84)), "lattice")
        add(word(mn, groups[PLAIN] | (7 << 73) | (7 << 84)), "lattice")
        add(base | (1 << 63), "lattice")
        add(base | (1 << 63), "lattice")
        add(word(mn, groups[LOADED]) | (1 << 63), "lattice")
        add(base | (1 << 76), "lattice")
        add(base | (1 << 76) | (1 << 63), "lattice")
    return out


def lattice_ok(w, t):
    """Lattice words: illegal, or named with an INVALIDn glyph, or the inert-bit twin of a form word, or a word of
    another form (the `.64` base, the descriptor form, the `[Ra(+off)]` form) -- never a word this probe's keys should
    claim."""
    if t is None:
        return True
    mn = mnemonic_of(w)
    if mn is None:
        return False
    if not (w >> 91) & 1:
        return t.startswith(mn) and "+UR" not in t  # the `[Ra(+off)]` form
    if (w >> 76) & 1:
        return "desc[" in t  # the descriptor form (with bit 63; alone the vendor rejects the word)
    if (w >> 63) & 1:
        return ".64+UR" in t  # the `.64` base: another key
    op, ty, c = (w >> 87) & 0xf, (w >> 73) & 7, (w >> 84) & 7
    glyph = lambda n: f".INVALID{n}." in t or f".INVALID{n} " in t  # noqa: E731  (the glyph may be the last modifier)
    if op >= N_OPS[mn]:
        return glyph(op)
    if ty >= N_TYPES:
        return glyph(ty)
    if c >= 6:
        return glyph(c)
    mask = sum(1 << b for b in INERT)
    return text_ok(w & ~mask, t)


def witness_words(corpus: pathlib.Path) -> list[int]:
    """The words of a census corpus (`{"hex", "sass"}` lines; the GB10 corpus of sm121a) on the two opcodes whose text
    starts with the mnemonic, with their own control codes, distinct, sorted."""
    import json
    import re
    out = set()
    for line in corpus.read_text().splitlines():
        if not line.strip():
            continue
        r = json.loads(line)
        w = int(r["hex"], 16)
        mn = mnemonic_of(w)
        if mn is not None and re.match(r"^(@!?U?P[T\d] )?" + mn + r"\b", r["sass"]):
            out.add(w)
    return sorted(out)


def probe(nvdisasm, arch, out, jobs, witnesses=None):
    words = sweep_words()
    rows = nvprobe.probe_words(nvdisasm, "atom_aruri", [(w, kind != "form") for w, kind in words], CTRL,
                               check_form=text_ok, check_lattice=lattice_ok, arch=arch, jobs=jobs)
    n_wit = 0
    if witnesses is not None:
        wit_all = witness_words(witnesses)
        wit = [w for w in wit_all if key_of(w) is not None]
        if len(wit) != len(wit_all):
            print(f"  {len(wit_all) - len(wit)} corpus words of the opcodes are outside the probed form (skipped)")
        wrows = nvprobe.probe_words(nvdisasm, "atom_wit", [(w, False) for w in wit], 0, check_form=text_ok, arch=arch, jobs=jobs)
        for row in wrows:
            row["witness"] = True
        rows += wrows
        n_wit = len(wrows)
    nvprobe.write_fixture(out, rows)
    n_form = sum(1 for r in rows if not r.get("lattice") and not r.get("witness"))
    keys = collections.Counter(key_of(int(r["word"], 16)) for r in rows if not r.get("lattice") and not r.get("witness"))
    print(f"{out}: {n_form} form words ({dict(keys)}), {len(rows) - n_form - n_wit} lattice words, {n_wit} witness words ({arch})")


NOTE = ("ATOM 0x98a / ATOMG 0x9a8 (the global atomics, plain uniform-indexed address form) measured with nvdisasm 13.1 (-b SM121), "
        "tools/probes/re_sm120_atom_aruri.py (session T-22, 2026-11-08): guard [15:12], Rd [23:16], Ra [31:24], Rb [39:32], the signed "
        "23-bit byte offset [62:40], URb [71:64], .E 72, the type [75:73] (U32 / S32 / 64 / S64 / 128), the 16-value strength / scope / "
        "PRIVATE enum [80:77], Pd [83:81], cache [86:84], the op [90:87] (SAFEADD on ATOMG only), the uniform-indexed form 91. [95:92] "
        "are text-inert and fail closed; bit 63 (the .64 base) and bit 76 (the descriptor form) are other keys and claim_forbid.")


# One note for the family (in `_meta.provenance.sources[PROVENANCE].note`), a pointer per row, and no per-field `_src`
# (the row's `_src` names the measurement of every field): sm121a.json is within 10 MiB of GitHub's 100 MiB file limit with
# this lattice, and the per-row prose of the earlier lattices is 23 MB of the 84 (T/NEEDS_OWNER.md 61).
ROW_NOTE = "measured lattice row; the law: _meta.provenance.sources[" + PROVENANCE + "].note"


def measured_row(mn, mods, src=PROVENANCE, note=ROW_NOTE):
    fields = [nvprobe.field(12, 4, "guard", 0, src), nvprobe.field(81, 3, "pred", 1, src), nvprobe.field(16, 8, "reg", 2, src),
              nvprobe.field(24, 8, "reg", 3, src), nvprobe.field(64, 8, "ureg", 3, src), nvprobe.field(40, 23, "imm", 3, src),
              nvprobe.field(32, 8, "reg", 4, src)]
    for f in fields:
        f.pop("_src", None)
    base = word(mn, mods, guard=0, pd=0, rd=0, ra=0, rb=0, ur=0)
    row = nvprobe.row(base, fields, src, note)
    # the `.64` base (63) and the descriptor bit (76) are other forms: never claimed through a tolerant match (the
    # convention of T-6's .EL rows)
    row["claim_forbid"] = [{"bits": 1, "shift": 63, "values": [1]}, {"bits": 1, "shift": 76, "values": [1]}]
    return row


def arch_of_table(path: pathlib.Path) -> str:
    return next((a for a, t in TABLE_OF.items() if path.name.startswith(t)), "SM120")


def same_row(old, new):
    strip = lambda f: {k: v for k, v in f.items() if k in ("bits", "extraction", "shift", "token_idx")}  # noqa: E731
    return (int(old["and_base"], 16) == int(new["and_base"], 16) and int(old["variable_mask"], 16) == int(new["variable_mask"], 16)
            and sorted(map(repr, map(strip, old["fields"]))) == sorted(map(repr, map(strip, new["fields"])))
            and old.get("claim_forbid") == new.get("claim_forbid") and old.get("_src"))


def dotted_keys(ins):
    """The dotted one-group ATOM / ATOMG keys of the form, with the plain key they alias to."""
    out = {}
    for k in ins:
        mn, _, sig = k.partition("_")
        base = mn.split(".")[0]
        if base not in OPCS or "." not in mn or sig != "P_R_ARURI_R":
            continue
        groups = ins[k].get("mod_groups", {})
        assert len(groups) == 1, f"{k}: {len(groups)} groups"
        (g,) = groups.values()
        assert int(g["and_base"], 16) & 0xfff == OPCS[base], f"{k}: not on {OPCS[base]:#x}"
        if g.get("_src") is not None and g.get("_src") != PROVENANCE:
            print(f"  {k}: measured by {g['_src']} -- kept as its own key")
            continue
        toks = sorted(mn.split(".")[1:])
        assert ",".join(toks) in GROUPS[base], f"{k}: the modifier tokens {toks} name no measured group"
        out[k] = KEYS[base]
    return out


def apply(table_path):
    path = pathlib.Path(table_path)
    table = nvprobe.load_table(path)
    ins = table["instructions"]
    live_before = collections.Counter(g.get("_src") for e in ins.values() for g in e.get("mod_groups", {}).values())
    retire = dotted_keys(ins)
    arch = arch_of_table(path)
    note = NOTE if arch == "SM121" else NOTE.replace("(-b SM121)", f"(-b {arch}; the same text as on -b SM121 for every word of the sweep)")
    rewritten = added = kept = 0
    for mn, key in KEYS.items():
        old = ins.get(key)
        template = old or next((ins[k] for k, t in retire.items() if t == key), None) or ins.get(f"{mn}_P_R_dARI_R")
        assert template is not None, f"{path}: no {mn} entry to take ctrl_class / scheduling from"
        entry = {k: v for k, v in template.items() if k in ("ctrl_class", "scheduling", "mercury")}
        entry["base_op"] = mn
        entry["operand_sig"] = "P_R_ARURI_R"
        old_groups = old["mod_groups"] if old else {}
        groups = {}
        for name, mods in GROUPS[mn].items():
            row = measured_row(mn, mods)
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
                                   "kind": f"nvdisasm 13.1 field probe (-b {arch})", "date": "2026-11-08",
                                   "tool": "tools/probes/re_sm120_atom_aruri.py", "note": note,
                                   "test": {"SM121": "tests/sm121a_atom_aruri.rs", "SM120": "tests/sm120_atom_aruri.rs"}.get(arch, "tests/sm103a_sm100a_atom_aruri.rs")}
    live_after = collections.Counter(g.get("_src") for g in rows)
    for s, n in live_before.items():
        if s and s != PROVENANCE and live_after[s] != n and prov["sources"].get(s, {}).get("rows") == n:
            prov["sources"][s]["rows"] = live_after[s]
            print(f"  legend {s}: rows {n} -> {live_after[s]}")
    nvprobe.save_table(path, table)
    print(f"{path}: ATOM / ATOMG ARURI: rows rewritten {rewritten}, groups added {added}, measured rows kept with their tag {kept}, "
          f"rows with the tag {prov['sources'][PROVENANCE]['rows']}; {len(retire)} dotted keys retired as aliases "
          f"({collections.Counter(retire.values())}); rows without _src now {prov['rows_without_src']}")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("probe")
    p.add_argument("--nvdisasm", default="/usr/local/lib/python3.12/dist-packages/triton/backends/nvidia/bin/nvdisasm")
    p.add_argument("--arch", default="SM121", choices=sorted(TABLE_OF))
    p.add_argument("--out", type=pathlib.Path, default=None)
    p.add_argument("--jobs", type=int, default=1)
    p.add_argument("--witnesses", type=pathlib.Path, default=None,
                   help="a census corpus ({hex, sass} lines; the GB10 corpus of sm121a): its words of this form become witness rows")
    a = sub.add_parser("apply")
    a.add_argument("table")
    args = parser.parse_args()
    if args.command == "probe":
        out = args.out or nvprobe.FIXTURES / f"{TABLE_OF[args.arch]}_atom_aruri_nvdisasm.jsonl"
        probe(args.nvdisasm, args.arch, out, args.jobs, args.witnesses)
    else:
        apply(args.table)


if __name__ == "__main__":
    main()

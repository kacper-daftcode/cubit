#!/usr/bin/env python3
"""The 256-bit global load (opcode 0x97e): measure the whole modifier x operand lattice of the twelve plain keys
`LDG_R_R_{dARI,ARURI,ARURI64}[_II][_P]` with nvdisasm and rebuild them from the measurement (session G, 2026-11-07,
run 3; KNOWN_ISSUES T1 / NEEDS 45 -- the 6 990 dotted one-group harvest keys `LDG.E.<cache>.<L2>[.LTC].256.<scope>_R_R_*`
of 2026-08/09, 0 census witnesses).

Form (one opcode, three address forms, the trailing immediate and the trailing predicate optional):
  `LDG.E[.cache].<L2>[.LTC].256[.scope] Rd0, Rd1, <addr>[, 0xNN][, [!]Pc]`
  addr  dARI     bits 75 = 1, 76 = 1   `desc[URb][Ra.64(+off)]`          Ra = RZ illegal (claim_forbid)
        ARURI64  bits 75 = 1, 76 = 0   `[Ra.64+URb(+off)]`               Ra = RZ prints `[URb(+off)]`
        ARURI    bits 75 = 0, 76 = 0   `[Ra.U32+URb(+off)]`              Ra = RZ prints `[URb(+off)]` (the same text as the .64 twin)
        (75 = 0 with 76 = 1 is illegal)

Law (nvdisasm 13.1, one word per call, `-b SM120`; `probe --arch SM103` / `SM100` record the other targets):
guard [15:12]; Rd1 [23:16]; Ra [31:24]; URb [39:32] (255 = URZ); the offset [56:40] = a signed 17-bit count of 32-byte
units (`sub_imm2_shr5`: +0x20 .. +0x1fffe0, -0x20 .. -0x200000); the trailing byte = [63:57] low 7 bits + bit 72 as
bit 7, **elided at 0xff** (the `_II` keys carry it as `imm@57:7` + `imm_shr7@72:1`, the plain keys bake 0xff); Rd0
[71:64]; LTC [74:73] (0 none, LTC64B, LTC128B, LTC256B); [80:77] = the 16-value strength / scope / PRIVATE enum
(0 none, 1 CONSTANT.PRIVATE, 2 CONSTANT.CTA, 3 CONSTANT.CTA.PRIVATE, 4 CONSTANT, 5 STRONG.SM, 6 STRONG.GPU.PRIVATE,
7 STRONG.GPU, 8 MMIO.GPU, 9 CONSTANT.SM, 10 STRONG.SYS, 11 CONSTANT.SM.PRIVATE, 12 MMIO.SYS, 13 CONSTANT.VC,
14 CONSTANT.VC.PRIVATE, 15 CONSTANT.GPU); L2 [82:81] (0 EFL2, 1 ENL2, 2 ELL2; 3 = `RML2` with `???0.???1` scope
glyphs -- a lattice plane); cache [86:84] (0 EF, 1 none, 2 EL, 3 LU, 4 EU, 5 NA; 6 / 7 = INVALID6 / INVALID7); the
trailing predicate [90:87] = `pred_inv4` (0 = PT elided, 1..7 = P(7-v), 8 = !PT, 9..15 = !P(15-v)); bit 91 is the frame
(set on every legal word, illegal when clear). Text-inert and fail-closed: 83, [95:92]. `.E` and `.256` are on every
word (no bit selects them).
Printed `LDG.E[.cache].<L2>[.LTC].256[.strength[.scope]][.PRIVATE]`.

Groups: 6 cache x 3 L2 x 4 LTC x 16 scope = 1 152 per key, 4 608 per address form, 13 824 on the twelve keys.

`probe --form dARI|ARURI|ARURI64 [--arch SM120|SM103|SM100] [--jobs N]` writes
`tests/fixtures/<table>_ldg256_<form>_nvdisasm.jsonl`; `apply --form F <sm120.json>` rewrites the four keys of that
address form (creating them; keeping a row the measurement reproduces field for field, with its tag) and retires the
dotted one-group keys of the form as `_meta.key_aliases` of the plain key of their operand signature (every retired
key's modifier tokens name a group of the target). One address form = one batch (T reviews incrementally).
"""
from __future__ import annotations

import argparse
import collections
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import nvprobe  # noqa: E402

PROVENANCE = "ldg256-family-2026-11-07"
CTRL = 0x000f_e200 << 96
OPC = 0x97e
FRAME = 1 << 91  # set on every legal word of the form (clearing it is illegal)
TABLE_OF = {"SM120": "sm120", "SM103": "sm103a", "SM100": "sm100a", "SM121": "sm121a"}
ADDR = {"dARI": (1, 1), "ARURI64": (1, 0), "ARURI": (0, 0)}  # address form -> (bit 75, bit 76)
SCOPE = ["", "CONSTANT.PRIVATE", "CONSTANT.CTA", "CONSTANT.CTA.PRIVATE", "CONSTANT", "STRONG.SM", "STRONG.GPU.PRIVATE",
         "STRONG.GPU", "MMIO.GPU", "CONSTANT.SM", "STRONG.SYS", "CONSTANT.SM.PRIVATE", "MMIO.SYS", "CONSTANT.VC",
         "CONSTANT.VC.PRIVATE", "CONSTANT.GPU"]
CACHE = ["EF", "", "EL", "LU", "EU", "NA", "INVALID6", "INVALID7"]
L2 = ["EFL2", "ENL2", "ELL2", "RML2"]
LTC = ["", "LTC64B", "LTC128B", "LTC256B"]


def key_name(form, ii, p):
    return f"LDG_R_R_{form}" + ("_II" if ii else "") + ("_P" if p else "")


def keys_of(form):
    return [key_name(form, ii, p) for ii in (0, 1) for p in (0, 1)]


KEYS = [k for form in ADDR for k in keys_of(form)]


def groups_of():
    """group name (sorted tokens) -> modifier bits, the legal grid."""
    out = {}
    for c in range(6):
        for l2 in range(3):
            for ltc in range(4):
                for sc in range(16):
                    toks = ["E", "256", L2[l2]] + ([CACHE[c]] if CACHE[c] else []) + ([LTC[ltc]] if LTC[ltc] else []) \
                        + (SCOPE[sc].split(".") if SCOPE[sc] else [])
                    out[",".join(sorted(toks))] = (c << 84) | (l2 << 81) | (ltc << 73) | (sc << 77)
    assert len(out) == 1152
    return out


GROUPS = groups_of()
LOADED = ",".join(sorted(["E", "256", "LU", "ELL2", "LTC256B", "STRONG", "GPU", "PRIVATE"]))


def word(form, mods=0, guard=7, rd0=4, rd1=6, ra=2, ur=4, imm=0, ii=None, pc=0, extra=0):
    """A word of the address form; `ii` None = the trailing byte elided (0xff), `pc` = the pred_inv4 value."""
    b75, b76 = ADDR[form]
    w = OPC | FRAME | (b75 << 75) | (b76 << 76) | (guard << 12) | (rd1 << 16) | (ra << 24) | (ur << 32) | ((imm & 0x1ffff) << 40) | (rd0 << 64)
    trailing = 0xff if ii is None else ii
    w |= ((trailing & 0x7f) << 57) | (((trailing >> 7) & 1) << 72)
    return w | (pc << 87) | mods | extra


def form_of(w):
    if (w & 0xfff) != OPC or not (w >> 91) & 1:
        return None
    bits = ((w >> 75) & 1, (w >> 76) & 1)
    for form, fb in ADDR.items():
        if fb == bits:
            return form
    return None


def key_of(w):
    """The canonical key of a legal word: the trailing byte away from 0xff makes it `_II`, a predicate away from PT `_P`."""
    form = form_of(w)
    if form is None:
        return None
    trailing = ((w >> 57) & 0x7f) | (((w >> 72) & 1) << 7)
    return key_name(form, trailing != 0xff, (w >> 87) & 0xf != 0)


def pred_inv4(v):
    if v == 0:
        return None
    if v == 8:
        return "!PT"
    return f"P{7 - v}" if v < 8 else f"!P{15 - v}"


def expected_text(w):
    form = form_of(w)
    if form is None:
        return None
    guard = (w >> 12) & 0xf
    g = "" if guard == 7 else (f"@P{guard} " if guard < 7 else ("@!PT " if guard == 15 else f"@!P{guard - 8} "))
    reg = lambda n: "RZ" if n == 255 else f"R{n}"  # noqa: E731
    ureg = lambda n: "URZ" if n == 255 else f"UR{n}"  # noqa: E731
    c, l2, ltc, sc = (w >> 84) & 7, (w >> 81) & 3, (w >> 73) & 3, (w >> 77) & 0xf
    mods = ".E" + (f".{CACHE[c]}" if CACHE[c] else "") + f".{L2[l2]}" + (f".{LTC[ltc]}" if LTC[ltc] else "") + ".256" \
        + (f".{SCOPE[sc]}" if SCOPE[sc] else "")
    imm = (w >> 40) & 0x1ffff
    if imm & 0x10000:
        imm -= 1 << 17
    off = "" if imm == 0 else (f"+{imm * 32:#x}" if imm > 0 else f"+-{-imm * 32:#x}")
    ra, ur = (w >> 24) & 0xff, (w >> 32) & 0xff
    if form == "dARI":
        if ra == 255:
            return None  # illegal
        addr = f"desc[{ureg(ur)}][R{ra}.64{off}]"
    elif ra == 255:
        addr = f"[{ureg(ur)}{off}]"
    else:
        addr = f"[R{ra}.{'64' if form == 'ARURI64' else 'U32'}+{ureg(ur)}{off}]"
    trailing = ((w >> 57) & 0x7f) | (((w >> 72) & 1) << 7)
    tail = "" if trailing == 0xff else f", {trailing:#x}"
    pc = pred_inv4((w >> 87) & 0xf)
    tail += f", {pc}" if pc else ""
    return f"{g}LDG{mods} {reg((w >> 64) & 0xff)}, {reg((w >> 16) & 0xff)}, {addr}{tail}"


def text_ok(w, t):
    return t is not None and t == expected_text(w)


INERT = [83, 92, 93, 94, 95]


def sweep_words(form):
    out, seen = [], set()

    def add(w, kind="form"):
        if w not in seen:
            seen.add(w)
            out.append((w, kind))

    for ii in (0, 1):
        for p in (0, 1):
            kw = dict(ii=0 if ii else None, pc=1 if p else 0)
            for mods in GROUPS.values():
                add(word(form, mods, **kw))
            for mods in (0, GROUPS[LOADED]):
                for guard in (0, 3, 8, 15):
                    add(word(form, mods, guard=guard, **kw))
                for n in (0, 1, 63, 255):
                    add(word(form, mods, rd0=n, **kw))
                    add(word(form, mods, rd1=n, **kw))
                    add(word(form, mods, ur=n, **kw))
                    add(word(form, mods, ra=n, **kw), "lattice" if form == "dARI" and n == 255 else "form")
                add(word(form, mods, ra=255, ur=255, **kw), "lattice" if form == "dARI" else "form")
                for imm in (1, 2, 0x1234, 0xffff, 0x10000, 0x1ffff):
                    add(word(form, mods, imm=imm, **kw))
                    add(word(form, mods, ra=255, imm=imm, **kw), "lattice" if form == "dARI" else "form")
                if ii:
                    for v in (0x01, 0x12, 0x7f, 0x80, 0xfe):
                        add(word(form, mods, **dict(kw, ii=v)))
                if p:
                    for v in range(2, 16):
                        add(word(form, mods, **dict(kw, pc=v)))
            moved = dict(guard=11, rd0=17, rd1=250, ra=10, ur=20, imm=0x1234)
            if ii:
                moved["ii"] = 0x5a
            if p:
                moved["pc"] = 12
            add(word(form, GROUPS[LOADED], **{**kw, **moved}))
    # the lattice: the frame bit, the inert bits, the INVALID cache codes, the RML2 plane, the illegal address bits
    base = word(form)
    add(base ^ (1 << 91), "lattice")
    for bit in INERT:
        add(base | (1 << bit), "lattice")
    add(word(form, GROUPS[LOADED]) | (1 << 83), "lattice")
    for c in (6, 7):
        add(word(form, (c << 84)), "lattice")
        add(word(form, (c << 84) | (3 << 77) | (1 << 81)), "lattice")
    for sc in (0, 3, 7, 15):
        add(word(form, (3 << 81) | (sc << 77)), "lattice")
    add(word(form, (3 << 81) | (1 << 73) | (2 << 84)), "lattice")
    b75, b76 = ADDR[form]
    for other in ((0, 1),):
        add((base & ~(3 << 75)) | (other[0] << 75) | (other[1] << 76), "lattice")
    return out


def lattice_ok(w, t):
    key = key_of(w)
    if t is None:
        return key is None or (form_of(w) == "dARI" and (w >> 24) & 0xff == 255)
    if key is None:
        return False
    c, l2 = (w >> 84) & 7, (w >> 81) & 3
    if c >= 6:
        return f".INVALID{c}." in t
    if l2 == 3:  # SM120 names the plane `RML2` with `???` scope glyphs, SM103 / SM100 call it `INVALID3`
        return ".RML2." in t or ".INVALID3." in t
    mask = sum(1 << b for b in INERT)
    return text_ok(w & ~mask, t)




def witness_words(corpus: pathlib.Path, mnemonic: str, opc: int) -> list[int]:
    """T-21: the words of a census corpus (`{"hex", "sass"}` lines; the GB10 corpus of sm121a) whose opcode is the
    form's and whose text starts with the mnemonic, with their own control codes, distinct, sorted."""
    import json
    import re
    out = set()
    for line in corpus.read_text().splitlines():
        if not line.strip():
            continue
        r = json.loads(line)
        w = int(r["hex"], 16)
        if (w & 0xfff) == opc and re.match(r"^(@!?U?P[T\d] )?" + mnemonic + r"\b", r["sass"]):
            out.add(w)
    return sorted(out)


def probe(nvdisasm, form, arch, out, jobs, witnesses=None):
    words = sweep_words(form)
    rows = nvprobe.probe_words(nvdisasm, f"ldg256_{form.lower()}", [(w, kind != "form") for w, kind in words], CTRL,
                               check_form=text_ok, check_lattice=lattice_ok, arch=arch, jobs=jobs)
    n_wit = 0
    if witnesses is not None:
        # T-21 (2026-11-08): the census words of the table's own corpus (the GB10 corpus of sm121a), each with its own
        # control code, checked against the law like a form word (text_ok ignores nothing: the word's bits are the law's)
        wit_all = witness_words(witnesses, "LDG", OPC)
        # only the words of the forms this probe measures (the opcode is shared with other address forms: the
        # descriptor-form REDG words of the GB10 corpus are outside the uniform-indexed lattice)
        wit = [w for w in wit_all if key_of(w) is not None]
        if len(wit) != len(wit_all):
            print(f"  {len(wit_all) - len(wit)} corpus words of the opcode are outside the probed forms (skipped)")
        wrows = nvprobe.probe_words(nvdisasm, "ldg_wit", [(w, False) for w in wit], 0, check_form=text_ok, arch=arch, jobs=jobs)
        for row in wrows:
            row["witness"] = True
        rows += wrows
        n_wit = len(wrows)
    nvprobe.write_fixture(out, rows)
    n_form = sum(1 for r in rows if not r.get("lattice") and not r.get("witness"))
    keys = collections.Counter(key_of(int(r["word"], 16)) for r in rows if not r.get("lattice") and not r.get("witness"))
    print(f"{out}: {n_form} form words ({dict(keys)}), {len(rows) - n_form - n_wit} lattice words, {n_wit} witness words ({arch})")


NOTE = ("LDG 0x97e (the 256-bit global load) measured with nvdisasm 13.1 (-b SM120), tools/probes/re_sm120_ldg256.py (session G, "
        "2026-11-07): guard [15:12], Rd1 [23:16], Ra [31:24], URb [39:32], the signed 17-bit offset in 32-byte units [56:40], the "
        "trailing byte [63:57] + bit 72 (elided at 0xff: the plain keys bake it, the _II keys carry it), Rd0 [71:64], LTC [74:73], "
        "the base width 75 / the descriptor form 76, the 16-value strength / scope / PRIVATE enum [80:77], L2 [82:81], cache [86:84], "
        "the trailing predicate [90:87] (pred_inv4, PT elided: the plain keys bake 0, the _P keys carry it), the frame bit 91. Bit 83 "
        "and [95:92] are text-inert and fail closed; bit 91 clear is illegal; desc[UR][RZ.64] is illegal (claim_forbid).")


def measured_row(key, mods, src=PROVENANCE, note=NOTE):
    form = key.split("_")[3]
    has_ii, has_p = "_II" in key, key.endswith("_P")
    fields = [nvprobe.field(12, 4, "guard", 0, src), nvprobe.field(64, 8, "reg", 1, src), nvprobe.field(16, 8, "reg", 2, src)]
    if form == "dARI":
        fields += [nvprobe.field(32, 8, "sub_ur0", 3, src), nvprobe.field(24, 8, "sub_r1", 3, src)]
    else:
        fields += [nvprobe.field(24, 8, "sub_r0", 3, src), nvprobe.field(32, 8, "sub_ur1", 3, src)]
    fields.append(nvprobe.field(40, 17, "sub_imm2_shr5", 3, src))
    tok = 4
    if has_ii:
        fields += [nvprobe.field(57, 7, "imm", tok, src), nvprobe.field(72, 1, "imm_shr7", tok, src)]
        tok += 1
    if has_p:
        fields.append(nvprobe.field(87, 4, "pred_inv4", tok, src))
    base = word(form, mods, guard=0, rd0=0, rd1=0, ra=0, ur=0, ii=0 if has_ii else None, pc=0)
    row = nvprobe.row(base, fields, src, note)
    if form == "dARI":
        row["claim_forbid"] = [{"shift": 24, "bits": 8, "values": [255]}]
    return row

def arch_of_table(path: pathlib.Path) -> str:
    """The nvdisasm target of a table file (sm120.json -> SM120, sm103a.json -> SM103, sm100a.json -> SM100)."""
    return next((a for a, t in TABLE_OF.items() if path.name.startswith(t)), "SM120")



def same_row(old, new):
    strip = lambda f: {k: v for k, v in f.items() if k in ("bits", "extraction", "shift", "token_idx")}  # noqa: E731
    return (int(old["and_base"], 16) == int(new["and_base"], 16) and int(old["variable_mask"], 16) == int(new["variable_mask"], 16)
            and sorted(map(repr, map(strip, old["fields"]))) == sorted(map(repr, map(strip, new["fields"])))
            and old.get("claim_forbid") == new.get("claim_forbid") and old.get("_src"))


def dotted_keys(ins, form):
    """The dotted one-group LDG keys of the address form (opcode 0x97e), with the plain key they alias to."""
    out = {}
    for k in ins:
        if not k.startswith("LDG.") or "_" not in k:
            continue
        mn, sig = k.split("_", 1)
        if sig not in {key.split("_", 1)[1] for key in keys_of(form)}:
            continue
        groups = ins[k].get("mod_groups", {})
        assert len(groups) == 1, f"{k}: {len(groups)} groups"
        (g,) = groups.values()
        assert int(g["and_base"], 16) & 0xfff == OPC, f"{k}: not on 0x97e"
        toks = sorted(mn.split(".")[1:])
        assert ",".join(toks) in GROUPS, f"{k}: the modifier tokens {toks} name no measured group"
        out[k] = f"LDG_{sig}"
    return out


def apply(table_path, form):
    path = pathlib.Path(table_path)
    table = nvprobe.load_table(path)
    arch = arch_of_table(path)
    # sm103a / sm100a (session T-20, 2026-11-08): the same law, measured on the table's own target -- the rows say so
    note = NOTE if arch == "SM120" else NOTE.replace("(-b SM120)", f"(-b {arch}; the same text as on -b SM120 for every form word of the sweep -- session T-20 / T-21, 2026-11-08, on the {TABLE_OF[arch]} table)")
    ins = table["instructions"]
    live_before = collections.Counter(g.get("_src") for e in ins.values() for g in e.get("mod_groups", {}).values())
    retire = dotted_keys(ins, form)
    template = ins[next(iter(retire))] if retire else ins["LDG_R_dARI"]
    rewritten = added = kept = 0
    for key in keys_of(form):
        old = ins.get(key)
        entry = {k: v for k, v in (old or template).items() if k in ("ctrl_class", "scheduling")}
        entry["base_op"] = "LDG"
        entry["operand_sig"] = key.split("_", 1)[1]
        old_groups = old["mod_groups"] if old else {}
        groups = {}
        for name, mods in GROUPS.items():
            row = measured_row(key, mods, note=note)
            prev = old_groups.get(name)
            if prev is not None and same_row(prev, row):
                groups[name] = prev
                kept += 1
            else:
                groups[name] = row
                rewritten += prev is not None
                added += prev is None
        missing = set(old_groups) - set(groups)
        if missing:  # harvest groups outside the measured lattice: report, they are retired with the key's rewrite
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
                                   "kind": "nvdisasm 13.1 field probe (-b SM120 / SM103 / SM100 / SM121)", "date": "2026-11-07" if arch == "SM120" else "2026-11-08",
                                   "tool": "tools/probes/re_sm120_ldg256.py",
                                   "test": {"SM120": "tests/sm120_ldg256_dari.rs, tests/sm120_ldg256_aruri64.rs, tests/sm120_ldg256_aruri.rs", "SM121": "tests/sm121a_ldg256_dari.rs, tests/sm121a_ldg256_aruri64.rs, tests/sm121a_ldg256_aruri.rs"}.get(arch, "tests/sm103a_sm100a_ldg256_dari.rs, tests/sm103a_sm100a_ldg256_aruri64.rs, tests/sm103a_sm100a_ldg256_aruri.rs")}
    live_after = collections.Counter(g.get("_src") for g in rows)
    for s, n in live_before.items():
        if s and s != PROVENANCE and live_after[s] != n and prov["sources"].get(s, {}).get("rows") == n:
            prov["sources"][s]["rows"] = live_after[s]
            print(f"  legend {s}: rows {n} -> {live_after[s]}")
    nvprobe.save_table(path, table)
    print(f"{path}: LDG.256 {form}: rows rewritten {rewritten}, groups added {added}, measured rows kept with their tag {kept}, "
          f"rows with the tag {prov['sources'][PROVENANCE]['rows']}; {len(retire)} dotted keys retired as aliases "
          f"({collections.Counter(retire.values())})")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("probe")
    p.add_argument("--form", required=True, choices=sorted(ADDR))
    p.add_argument("--nvdisasm", default="/usr/local/lib/python3.12/dist-packages/triton/backends/nvidia/bin/nvdisasm")
    p.add_argument("--arch", default="SM120", choices=sorted(TABLE_OF))
    p.add_argument("--out", type=pathlib.Path, default=None)
    p.add_argument("--jobs", type=int, default=1)
    p.add_argument("--witnesses", type=pathlib.Path, default=None,
                   help="a census corpus ({hex, sass} lines; the GB10 corpus of sm121a): its words of this form become witness rows")
    a = sub.add_parser("apply")
    a.add_argument("--form", required=True, choices=sorted(ADDR))
    a.add_argument("table")
    args = parser.parse_args()
    if args.command == "probe":
        out = args.out or nvprobe.FIXTURES / f"{TABLE_OF[args.arch]}_ldg256_{args.form.lower()}_nvdisasm.jsonl"
        probe(args.nvdisasm, args.form, args.arch, out, args.jobs, args.witnesses)
    else:
        apply(args.table, args.form)


if __name__ == "__main__":
    main()

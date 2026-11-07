#!/usr/bin/env python3
"""The 256-bit global store (opcode 0x97f): measure the whole modifier x operand lattice of the six plain keys
`STG_{dARI,ARURI,ARURI64}_R_R[_II]` with nvdisasm and rebuild them from the measurement (session G, 2026-11-07,
run 4; KNOWN_ISSUES T1 / NEEDS 45 -- the 1 164 dotted one-group harvest keys `STG.E.<cache>.<L2>.256.<scope>_*`
of 2026-08/09, 0 census witnesses; the store twin of the LDG.256 family of re_sm120_ldg256.py).

Form (one opcode, three address forms, the trailing immediate optional; no trailing predicate on the store):
  `STG.E[.cache].<L2>.256[.scope] <addr>, Rs0, Rs1[, 0xNN]`
  addr  dARI     bits 75 = 1, 76 = 1   `desc[URb][Ra.64(+off)]`          Ra = RZ illegal (claim_forbid)
        ARURI64  bits 75 = 1, 76 = 0   `[Ra.64+URb(+off)]`               Ra = RZ prints `[URb(+off)]`
        ARURI    bits 75 = 0, 76 = 0   `[Ra.U32+URb(+off)]`              Ra = RZ prints `[URb(+off)]` (the same text as the .64 twin)
        (75 = 0 with 76 = 1 is illegal)

Law (nvdisasm 13.1, one word per call, `-b SM120`; `probe --arch SM103` / `SM100` record the other targets):
guard [15:12]; Rs1 [23:16] (the third operand); Ra [31:24]; Rs0 [39:32] (the second operand); the offset [58:40] =
a signed 19-bit count of 32-byte units (`sub_imm2_shr5`: +0x20 .. +0x7fffe0, -0x20 .. -0x800000); the trailing byte
= [63:59] low 5 bits + [90:88] high 3 bits, **elided at 0xff** (the `_II` keys carry it as `imm@59:5` +
`imm_shr5@88:3`, the plain keys bake 0xff); URb [71:64] (255 = URZ); [80:77] = the 16-value strength / scope /
ORDERED / PRIVATE enum (0 none, 1 CONSTANT.PRIVATE, 2 CONSTANT.CTA, 3 CONSTANT.CTA.PRIVATE, 4 STRONG.SM.PRIVATE,
5 STRONG.SM, 6 STRONG.GPU.PRIVATE, 7 STRONG.GPU, 8 MMIO.GPU, 9 CONSTANT.SM, 10 STRONG.SYS, 11 CONSTANT.SM.PRIVATE,
12 MMIO.SYS, 13 SYS.ORDERED, 14 STRONG.SYS.ORDERED, 15 MMIO.SYS.ORDERED -- the load's enum has CONSTANT at 4 and
the VC / GPU constants at 13..15 instead); L2 [82:81] (0 EFL2, 1 ENL2, 2 ELL2; 3 = `INVALID3` -- a lattice plane);
cache [86:84] (0 EF, 1 none, 2 EL, 3 LU, 4 EU, 5 NA; 6 / 7 = INVALID6 / INVALID7); bit 91 is the frame (set on every
legal word, illegal when clear). Text-inert and fail-closed: [74:72] (no LTC width on the store), 83, 87, [95:92].
`.E` and `.256` are on every word (no bit selects them).
Printed `STG.E[.cache].<L2>.256[.strength[.scope]][.ORDERED][.PRIVATE]`.

Groups: 6 cache x 3 L2 x 16 scope = 288 per key, 1 728 on the six keys.

`probe [--arch SM120|SM103|SM100] [--jobs N]` writes `tests/fixtures/<table>_stg256_nvdisasm.jsonl`;
`apply <sm120.json>` rewrites the six keys (creating them; keeping a row the measurement reproduces field for
field, with its tag) and retires the dotted one-group keys of the opcode as `_meta.key_aliases` of the plain key
of their operand signature (every retired key's modifier tokens name a group of the target).
"""
from __future__ import annotations

import argparse
import collections
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import nvprobe  # noqa: E402

PROVENANCE = "stg256-family-2026-11-07"
CTRL = 0x000f_e200 << 96
OPC = 0x97f
FRAME = 1 << 91
TABLE_OF = {"SM120": "sm120", "SM103": "sm103a", "SM100": "sm100a"}
ADDR = {"dARI": (1, 1), "ARURI64": (1, 0), "ARURI": (0, 0)}  # address form -> (bit 75, bit 76)
SCOPE = ["", "CONSTANT.PRIVATE", "CONSTANT.CTA", "CONSTANT.CTA.PRIVATE", "STRONG.SM.PRIVATE", "STRONG.SM",
         "STRONG.GPU.PRIVATE", "STRONG.GPU", "MMIO.GPU", "CONSTANT.SM", "STRONG.SYS", "CONSTANT.SM.PRIVATE", "MMIO.SYS",
         "SYS.ORDERED", "STRONG.SYS.ORDERED", "MMIO.SYS.ORDERED"]
CACHE = ["EF", "", "EL", "LU", "EU", "NA", "INVALID6", "INVALID7"]
L2 = ["EFL2", "ENL2", "ELL2", "INVALID3"]


def key_name(form, ii):
    return f"STG_{form}_R_R" + ("_II" if ii else "")


KEYS = [key_name(form, ii) for form in ADDR for ii in (0, 1)]
SIGS = {k.split("_", 1)[1] for k in KEYS}


def groups_of():
    """group name (sorted tokens) -> modifier bits, the legal grid."""
    out = {}
    for c in range(6):
        for l2 in range(3):
            for sc in range(16):
                toks = ["E", "256", L2[l2]] + ([CACHE[c]] if CACHE[c] else []) + (SCOPE[sc].split(".") if SCOPE[sc] else [])
                out[",".join(sorted(toks))] = (c << 84) | (l2 << 81) | (sc << 77)
    assert len(out) == 288
    return out


GROUPS = groups_of()
LOADED = ",".join(sorted(["E", "256", "LU", "ELL2", "STRONG", "SYS", "ORDERED"]))


def word(form, mods=0, guard=7, ra=2, rs0=6, rs1=8, ur=4, imm=0, ii=None, extra=0):
    """A word of the address form; `ii` None = the trailing byte elided (0xff)."""
    b75, b76 = ADDR[form]
    w = OPC | FRAME | (b75 << 75) | (b76 << 76) | (guard << 12) | (rs1 << 16) | (ra << 24) | (rs0 << 32) | ((imm & 0x7ffff) << 40) | (ur << 64)
    trailing = 0xff if ii is None else ii
    w |= ((trailing & 0x1f) << 59) | (((trailing >> 5) & 7) << 88)
    return w | mods | extra


def form_of(w):
    if (w & 0xfff) != OPC or not (w >> 91) & 1:
        return None
    bits = ((w >> 75) & 1, (w >> 76) & 1)
    for form, fb in ADDR.items():
        if fb == bits:
            return form
    return None


def trailing_of(w):
    return ((w >> 59) & 0x1f) | (((w >> 88) & 7) << 5)


def key_of(w):
    """The canonical key of a legal word: the trailing byte away from 0xff makes it `_II`."""
    form = form_of(w)
    if form is None:
        return None
    return key_name(form, trailing_of(w) != 0xff)


def expected_text(w):
    form = form_of(w)
    if form is None:
        return None
    guard = (w >> 12) & 0xf
    g = "" if guard == 7 else (f"@P{guard} " if guard < 7 else ("@!PT " if guard == 15 else f"@!P{guard - 8} "))
    reg = lambda n: "RZ" if n == 255 else f"R{n}"  # noqa: E731
    ureg = lambda n: "URZ" if n == 255 else f"UR{n}"  # noqa: E731
    c, l2, sc = (w >> 84) & 7, (w >> 81) & 3, (w >> 77) & 0xf
    mods = ".E" + (f".{CACHE[c]}" if CACHE[c] else "") + f".{L2[l2]}" + ".256" + (f".{SCOPE[sc]}" if SCOPE[sc] else "")
    imm = (w >> 40) & 0x7ffff
    if imm & 0x40000:
        imm -= 1 << 19
    off = "" if imm == 0 else (f"+{imm * 32:#x}" if imm > 0 else f"+-{-imm * 32:#x}")
    ra, ur = (w >> 24) & 0xff, (w >> 64) & 0xff
    if form == "dARI":
        if ra == 255:
            return None  # illegal
        addr = f"desc[{ureg(ur)}][R{ra}.64{off}]"
    elif ra == 255:
        addr = f"[{ureg(ur)}{off}]"
    else:
        addr = f"[R{ra}.{'64' if form == 'ARURI64' else 'U32'}+{ureg(ur)}{off}]"
    trailing = trailing_of(w)
    tail = "" if trailing == 0xff else f", {trailing:#x}"
    return f"{g}STG{mods} {addr}, {reg((w >> 32) & 0xff)}, {reg((w >> 16) & 0xff)}{tail}"


def text_ok(w, t):
    return t is not None and t == expected_text(w)


INERT = [72, 73, 74, 83, 87, 92, 93, 94, 95]


def sweep_words():
    out, seen = [], set()

    def add(w, kind="form"):
        if w not in seen:
            seen.add(w)
            out.append((w, kind))

    for form in ADDR:
        for ii in (0, 1):
            kw = dict(ii=0 if ii else None)
            for mods in GROUPS.values():
                add(word(form, mods, **kw))
            for mods in (0, GROUPS[LOADED]):
                for guard in (0, 3, 8, 15):
                    add(word(form, mods, guard=guard, **kw))
                for n in (0, 1, 63, 255):
                    add(word(form, mods, rs0=n, **kw))
                    add(word(form, mods, rs1=n, **kw))
                    add(word(form, mods, ur=n, **kw))
                    add(word(form, mods, ra=n, **kw), "lattice" if form == "dARI" and n == 255 else "form")
                add(word(form, mods, ra=255, ur=255, **kw), "lattice" if form == "dARI" else "form")
                for imm in (1, 2, 0x1234, 0x3ffff, 0x40000, 0x7ffff):
                    add(word(form, mods, imm=imm, **kw))
                    add(word(form, mods, ra=255, imm=imm, **kw), "lattice" if form == "dARI" else "form")
                if ii:
                    for v in (0x01, 0x12, 0x1f, 0x20, 0x7f, 0x80, 0xfe):
                        add(word(form, mods, **dict(kw, ii=v)))
            moved = dict(guard=11, rs0=17, rs1=250, ra=10, ur=20, imm=0x1234)
            if ii:
                moved["ii"] = 0x5a
            add(word(form, GROUPS[LOADED], **{**kw, **moved}))
        # the lattice: the frame bit, the inert bits, the INVALID cache codes, the INVALID3 L2 plane, the illegal address bits
        base = word(form)
        add(base ^ (1 << 91), "lattice")
        for bit in INERT:
            add(base | (1 << bit), "lattice")
        add(word(form, GROUPS[LOADED]) | (1 << 83) | (1 << 73), "lattice")
        for c in (6, 7):
            add(word(form, (c << 84)), "lattice")
            add(word(form, (c << 84) | (3 << 77) | (1 << 81)), "lattice")
        for sc in (0, 3, 7, 15):
            add(word(form, (3 << 81) | (sc << 77)), "lattice")
        add(word(form, (3 << 81) | (2 << 84)), "lattice")
    add((word("dARI") & ~(3 << 75)) | (1 << 76), "lattice")
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
    if l2 == 3:
        return ".INVALID3." in t
    mask = sum(1 << b for b in INERT)
    return text_ok(w & ~mask, t)


def probe(nvdisasm, arch, out, jobs):
    words = sweep_words()
    rows = nvprobe.probe_words(nvdisasm, "stg256", [(w, kind != "form") for w, kind in words], CTRL,
                               check_form=text_ok, check_lattice=lattice_ok, arch=arch, jobs=jobs)
    nvprobe.write_fixture(out, rows)
    n_form = sum(1 for r in rows if not r.get("lattice"))
    keys = collections.Counter(key_of(int(r["word"], 16)) for r in rows if not r.get("lattice"))
    print(f"{out}: {n_form} form words ({dict(keys)}), {len(rows) - n_form} lattice words ({arch})")


NOTE = ("STG 0x97f (the 256-bit global store) measured with nvdisasm 13.1 (-b SM120), tools/probes/re_sm120_stg256.py (session G, "
        "2026-11-07): guard [15:12], Rs1 [23:16], Ra [31:24], Rs0 [39:32], the signed 19-bit offset in 32-byte units [58:40], the "
        "trailing byte [63:59] + [90:88] (elided at 0xff: the plain keys bake it, the _II keys carry it), URb [71:64], the base width "
        "75 / the descriptor form 76, the 16-value strength / scope / ORDERED / PRIVATE enum [80:77], L2 [82:81], cache [86:84], the "
        "frame bit 91. [74:72], 83, 87 and [95:92] are text-inert and fail closed; bit 91 clear is illegal; desc[UR][RZ.64] is illegal "
        "(claim_forbid).")


def measured_row(key, mods, src=PROVENANCE):
    form = key.split("_")[1]
    has_ii = key.endswith("_II")
    fields = [nvprobe.field(12, 4, "guard", 0, src)]
    if form == "dARI":
        fields += [nvprobe.field(64, 8, "sub_ur0", 1, src), nvprobe.field(24, 8, "sub_r1", 1, src)]
    else:
        fields += [nvprobe.field(24, 8, "sub_r0", 1, src), nvprobe.field(64, 8, "sub_ur1", 1, src)]
    fields += [nvprobe.field(40, 19, "sub_imm2_shr5", 1, src), nvprobe.field(32, 8, "reg", 2, src), nvprobe.field(16, 8, "reg", 3, src)]
    if has_ii:
        fields += [nvprobe.field(59, 5, "imm", 4, src), nvprobe.field(88, 3, "imm_shr5", 4, src)]
    base = word(form, mods, guard=0, ra=0, rs0=0, rs1=0, ur=0, ii=0 if has_ii else None)
    row = nvprobe.row(base, fields, src, NOTE)
    if form == "dARI":
        row["claim_forbid"] = [{"shift": 24, "bits": 8, "values": [255]}]
    return row


def same_row(old, new):
    strip = lambda f: {k: v for k, v in f.items() if k in ("bits", "extraction", "shift", "token_idx")}  # noqa: E731
    return (int(old["and_base"], 16) == int(new["and_base"], 16) and int(old["variable_mask"], 16) == int(new["variable_mask"], 16)
            and sorted(map(repr, map(strip, old["fields"]))) == sorted(map(repr, map(strip, new["fields"])))
            and old.get("claim_forbid") == new.get("claim_forbid") and old.get("_src"))


def dotted_keys(ins):
    """The dotted one-group STG keys of the opcode, with the plain key they alias to."""
    out = {}
    for k in ins:
        if not k.startswith("STG.") or "_" not in k:
            continue
        mn, sig = k.split("_", 1)
        if sig not in SIGS:
            continue
        groups = ins[k].get("mod_groups", {})
        if not any(int(g["and_base"], 16) & 0xfff == OPC for g in groups.values()):
            continue
        assert len(groups) == 1, f"{k}: {len(groups)} groups"
        toks = sorted(mn.split(".")[1:])
        assert ",".join(toks) in GROUPS, f"{k}: the modifier tokens {toks} name no measured group"
        out[k] = f"STG_{sig}"
    return out


def apply(table_path):
    path = pathlib.Path(table_path)
    table = nvprobe.load_table(path)
    ins = table["instructions"]
    live_before = collections.Counter(g.get("_src") for e in ins.values() for g in e.get("mod_groups", {}).values())
    retire = dotted_keys(ins)
    template = ins[next(iter(retire))] if retire else ins["STG_dARI_R"]
    rewritten = added = kept = 0
    for key in KEYS:
        old = ins.get(key)
        entry = {k: v for k, v in (old or template).items() if k in ("ctrl_class", "scheduling")}
        entry["base_op"] = "STG"
        entry["operand_sig"] = key.split("_", 1)[1]
        old_groups = old["mod_groups"] if old else {}
        groups = {}
        for name, mods in GROUPS.items():
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
                                   "tool": "tools/probes/re_sm120_stg256.py", "test": "tests/sm120_stg256.rs"}
    live_after = collections.Counter(g.get("_src") for g in rows)
    for s, n in live_before.items():
        if s and s != PROVENANCE and live_after[s] != n and prov["sources"].get(s, {}).get("rows") == n:
            prov["sources"][s]["rows"] = live_after[s]
            print(f"  legend {s}: rows {n} -> {live_after[s]}")
    nvprobe.save_table(path, table)
    print(f"{path}: STG.256: rows rewritten {rewritten}, groups added {added}, measured rows kept with their tag {kept}, "
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
        out = args.out or nvprobe.FIXTURES / f"{TABLE_OF[args.arch]}_stg256_nvdisasm.jsonl"
        probe(args.nvdisasm, args.arch, out, args.jobs)
    else:
        apply(args.table)


if __name__ == "__main__":
    main()

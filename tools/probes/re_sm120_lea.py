#!/usr/bin/env python3
"""Measure the `LEA` family — `LEA[.HI][.X][.SX32] Rd, [Pd,] Ra, <b>, [Rc,] imm5 [, Pcin]` in its three
operand forms — and rebuild the family's keys from the measurement on sm120 / sm103a / sm100a.

Why (dynamic audit 2026-11-02..06, `docs/KNOWN_ISSUES.md` T1, NEEDS_OWNER 30): the family was the audit's
largest (39 LEA + 5 LEA.HI.X rows with at least one defect; 56 keys / 100 rows on sm120): dozens of `?` junk
keys (`LEA_R_P_R_UR_II_II_II_II_II_?`, `LEA.HI.X_R_R_UR_R_II_P_II_II_?`, ...) with one sample's operands
baked into `and_base` and fields at the wrong bit (`reg@17`, `reg@18`, `ureg@33:4`, `pred@88:1`), `HI`
groups cloned across unrelated keys, the modifier bits 73 / 74 / 80 neither in `and_base` nor in the
mask (the plain `LEA R4, R8, R10, 0x1` word decoded as `LEA.HI.X R4, R8, R10, RZ, 0x1, PT`), the
carry-in `, PT` operand of the `.X` forms dropped from the text, and the bitwise-inverse glyph of the
`.X` forms printed as a negation (`-R12` for nvdisasm's `~R12`). On sm103a / sm100a coldface's B300-1 /
B300-4 rows (`LEA_R_P_R_UR_R_II [HI]`, `LEA.HI.X_R_P_R_UR_R_II_P`, 2026-11-05) measured the UR form only,
with `neg` fields on the `.X` row; the harvest rows around them still shadow their `Pd = PT` words.

Measured with nvdisasm 13.1 (`-b SM120`; `-b SM103` / `-b SM100` print the same text for every word):
  * three forms (opcode [11:0]): 0x211 `<b>` = Rb [39:32]; 0x811 `<b>` = imm32 [63:32]; 0xc11 `<b>` = URb
    [39:32] (the UR form needs the frame bit 91, which is illegal on the other two); 0x011 / 0x611 /
    0xa11 / 0xe11 are illegal, 0x411 is the degenerate `LEA.???0` glyph;
  * operands: guard [15:12], Rd [23:16], Pd [83:81] (7 = PT, elided from the text), Ra [31:24], Rc [71:64]
    (255 = RZ; printed only by `.HI` without `.SX32`), imm5 [79:75], carry-in Pcin [89:87] + `!` 90
    (printed only by `.X`);
  * modifiers: bit 80 = `.HI`, bit 74 = `.X`, bit 73 = `.SX32` (legal only with `.HI`: `LEA.SX32` and
    `LEA.X.SX32` are illegal); print order `LEA[.HI][.X][.SX32]`;
  * sign bits: 72 on Ra and 63 on Rb / URb — `-R` / `-UR` on the forms without `.X`, the bitwise inverse
    `~R` / `~UR` on the `.X` forms (on the immediate form bit 63 is imm32 bit 31: no `<b>` sign);
  * text-inert: Rc on the forms that do not print it, Pcin on the forms without `.X`, bits 84-86 and
    92-95 on every form, the imm32 window [62:40] on the register / UR forms; nvcc's values (Rc = RZ,
    Pcin = `!PT` = [90:87] 0xf, the rest clear) are baked into `and_base` and stay outside the mask
    (fail-closed; the decoder's sign-tolerant fallback is off for the family).
`.reuse` on Ra / Rb / Rc reaches bits 122 / 123 / 124 through the encoder's generic register slots.

Keys: for each form `<b>` in {R, II, UR} and each legal modifier group -- "" / "HI,SX32" on
`LEA_R_[P_]R_<b>_II`, "X" / "HI,SX32,X" on `LEA_R_[P_]R_<b>_II_P`, "HI" on `LEA_R_[P_]R_<b>_R_II`, "HI,X"
on `LEA_R_[P_]R_<b>_R_II_P` -- one row with the `Pd` token (pred [83:81]) and one without it (`PT` baked:
the vendor elides it, the decoder's shorter-key tiebreak picks that row for `Pd = PT` words).
`probe [--arch SM103|SM100]` writes `tests/fixtures/sm120_lea_nvdisasm.jsonl` (or the arch-prefixed
sibling); `apply <table.json>` replaces every LEA key of the table with the 24 measured keys (36 rows).
"""
import argparse
import pathlib
import re
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import nvprobe  # noqa: E402

PROVENANCE = "lea-family-2026-11-06"
NATIVE_CTRL = 0x000fca00 << 96
FORMS = {"R": 0x211, "II": 0x811, "UR": 0xc11}
# mod group -> (hi, x, sx32)
GROUPS = {"": (0, 0, 0), "X": (0, 1, 0), "HI": (1, 0, 0), "HI,X": (1, 1, 0), "HI,SX32": (1, 0, 1), "HI,SX32,X": (1, 1, 1)}
FIXTURE = nvprobe.FIXTURES / "sm120_lea_nvdisasm.jsonl"
TEXT = re.compile(
    r"(@!?P[0-6T] )?LEA(\.HI)?(\.X)?(\.SX32)? R(Z|\d+), (P[0-6], )?[-~]?R(Z|\d+), "
    r"([-~]?R(Z|\d+)|[-~]?UR(Z|\d+)|0x[0-9a-f]+), (R(Z|\d+), )?0x[0-9a-f]+(, !?P[0-6T])?")


def prints_rc(group):
    hi, _x, sx = GROUPS[group]
    return hi == 1 and sx == 0


def prints_cin(group):
    return GROUPS[group][1] == 1


def word(form, group="", guard=7, rd=4, ra=8, b=10, c=255, imm=1, pd=7, cin=None, cneg=0, nega=0, negb=0,
         frame=None, extra=0):
    """The family word; `cin=None` = nvcc's text-inert `!PT` on the forms without .X, `PT` with .X."""
    opc = FORMS[form]
    hi, x, sx = GROUPS[group]
    if cin is None:
        cin, cneg = (7, 0) if x else (7, 1)
    fr = (1 if form == "UR" else 0) if frame is None else frame
    w = (opc | (guard << 12) | (rd << 16) | (ra << 24) | (b << 32) | (c << 64) | (nega << 72) | (sx << 73)
         | (x << 74) | (imm << 75) | (hi << 80) | (pd << 81) | (cin << 87) | (cneg << 90) | (fr << 91) | extra)
    if form != "II":
        w |= negb << 63
    return w


def sweep_words():
    form_words, lattice = set(), set()
    for form in FORMS:
        bvals = (0, 5, 0x7fffffff, 0x80000000, 0xffffffff) if form == "II" else (0, 63, 254, 255)
        for group in GROUPS:
            k = dict(form=form, group=group)
            form_words.add(word(**k))
            for guard in (0, 6, 8, 15):
                form_words.add(word(guard=guard, **k))
            for pd in range(7):
                form_words.add(word(pd=pd, **k))
            for rd in (0, 255):
                form_words.add(word(rd=rd, **k))
            for ra in (0, 255):
                form_words.add(word(ra=ra, **k))
            for b in bvals:
                form_words.add(word(b=b, **k))
            for imm in (0, 0x1f):
                form_words.add(word(imm=imm, **k))
            form_words.add(word(nega=1, **k))
            if form != "II":
                form_words.add(word(negb=1, **k))
                form_words.add(word(nega=1, negb=1, **k))
            if prints_rc(group):
                for c in (0, 6, 254):
                    form_words.add(word(c=c, **k))
            if prints_cin(group):
                for cin in range(8):
                    form_words.add(word(cin=cin, **k))
                    form_words.add(word(cin=cin, cneg=1, **k))
            form_words.add(word(guard=3, pd=5, rd=200, ra=7, b=(0xdeadbeef if form == "II" else 12), c=(9 if prints_rc(group) else 255),
                                imm=0x15, cin=(2 if prints_cin(group) else None), **k))
        # lattice: text-inert bits, illegal neighbours
        for group in GROUPS:
            base = word(form, group)
            for bit in (84, 85, 86, 92, 93, 94, 95):
                lattice.add(base | (1 << bit))
            if form != "II":
                for bit in (40, 62):  # the imm32 window's bits are text-inert on the register / UR forms
                    lattice.add(base | (1 << bit))
            if not prints_rc(group):
                lattice.add(word(form, group, c=6))
            if not prints_cin(group):
                lattice.add(word(form, group, cin=2, cneg=0))
                lattice.add(word(form, group, cin=7, cneg=0))
            lattice.add(word(form, group, frame=0 if form == "UR" else 1))
        base = word(form)
        lattice.add(base | (1 << 73))              # .SX32 without .HI
        lattice.add(base | (1 << 73) | (1 << 74))  # .X.SX32 without .HI
    for opc in (0x011, 0x411, 0x611, 0xa11, 0xe11):
        lattice.add((word("R") & ~0xfff) | opc)
    lattice -= form_words
    return [(w, False) for w in sorted(form_words)] + [(w, True) for w in sorted(lattice)]


def expected_text(w):
    """nvdisasm's text for a family word, from the measured layout (the probe asserts it)."""
    opc = w & 0xfff
    form = {v: k for k, v in FORMS.items()}[opc]
    hi, x, sx = (w >> 80) & 1, (w >> 74) & 1, (w >> 73) & 1
    guard = (w >> 12) & 0xf
    g = "" if guard == 7 else ("@" + ("!" if guard & 8 else "") + ("PT" if (guard & 7) == 7 else f"P{guard & 7}") + " ")
    mn = "LEA" + (".HI" if hi else "") + (".X" if x else "") + (".SX32" if sx else "")
    reg = lambda n: "RZ" if n == 255 else f"R{n}"
    sign = "~" if x else "-"
    rd, ra, b, c, imm, pd = (w >> 16) & 0xff, (w >> 24) & 0xff, (w >> 32) & 0xff, (w >> 64) & 0xff, (w >> 75) & 0x1f, (w >> 81) & 7
    ops = [reg(rd)]
    if pd != 7:
        ops.append(f"P{pd}")
    ops.append((sign if (w >> 72) & 1 else "") + reg(ra))
    if form == "II":
        ops.append(f"0x{(w >> 32) & 0xffffffff:x}")
    elif form == "R":
        ops.append((sign if (w >> 63) & 1 else "") + reg(b))
    else:
        ops.append((sign if (w >> 63) & 1 else "") + ("URZ" if b == 255 else f"UR{b}"))
    if hi and not sx:
        ops.append(reg(c))
    ops.append(f"0x{imm:x}")
    if x:
        cin, cneg = (w >> 87) & 7, (w >> 90) & 1
        ops.append(("!" if cneg else "") + ("PT" if cin == 7 else f"P{cin}"))
    return g + mn + " " + ", ".join(ops)


def probe(nvdisasm, out=FIXTURE, arch="SM120"):
    rows = nvprobe.probe_words(
        nvdisasm, "lea", sweep_words(), NATIVE_CTRL,
        check_form=lambda w, t: TEXT.fullmatch(t) is not None and t == expected_text(w),
        check_lattice=lambda w, t: t is None or t.startswith("LEA"),
        arch=arch)
    nvprobe.write_fixture(out, rows)
    n_form = sum(1 for r in rows if not r.get("lattice"))
    print(f"{out}: {n_form} form words, {len(rows) - n_form} lattice words ({arch})")


def key_for(form, group, with_pd):
    hi, x, sx = GROUPS[group]
    toks = ["R"] + (["P"] if with_pd else []) + ["R", form] + (["R"] if prints_rc(group) else []) + ["II"] + (["P"] if x else [])
    return "LEA_" + "_".join(toks)


def measured_group(form, group, with_pd):
    hi, x, sx = GROUPS[group]
    src = PROVENANCE
    sign = "inv" if x else "neg"
    tok = 1
    fields = [nvprobe.field(12, 4, "guard", 0, src), nvprobe.field(16, 8, "reg", tok, src)]
    tok += 1
    if with_pd:
        fields.append(nvprobe.field(81, 3, "pred", tok, src))
        tok += 1
    fields += [nvprobe.field(24, 8, "reg", tok, src), nvprobe.field(72, 1, sign, tok, src)]
    tok += 1
    if form == "II":
        fields.append(nvprobe.field(32, 32, "imm", tok, src))
    else:
        fields += [nvprobe.field(32, 8, "reg" if form == "R" else "ureg", tok, src), nvprobe.field(63, 1, sign, tok, src)]
    tok += 1
    if prints_rc(group):
        fields.append(nvprobe.field(64, 8, "reg", tok, src))
        tok += 1
    fields.append(nvprobe.field(75, 5, "imm", tok, src))
    tok += 1
    if x:
        fields += [nvprobe.field(87, 3, "pred", tok, src), nvprobe.field(90, 1, "neg", tok, src)]
    base = word(form, group, guard=0, rd=0, ra=0, b=0, c=255 if not prints_rc(group) else 0, imm=0,
                pd=7 if not with_pd else 0, cin=None if not x else 0, cneg=0)
    mn = "LEA" + "".join(f".{m}" for m in ("HI", "X", "SX32") if m in group.split(","))
    note = (f"{mn} {form} form{' with Pd' if with_pd else ' (Pd = PT elided)'}: measured with nvdisasm 13.1 -b SM120 "
            f"(-b SM103 / -b SM100 text-identical), tools/probes/re_sm120_lea.py (session T-8, 2026-11-06). "
            + ("Sign bits 72 / 63 are the bitwise inverse `~` on the .X forms; " if x else "Sign bits 72 / 63 print `-`; ")
            + ("Rc [71:64] is text-inert here and baked RZ; " if not prints_rc(group) else "")
            + ("the carry-in [90:87] is text-inert here and baked `!PT` (nvcc's value); " if not x else "")
            + "bits 84-86 / 92-95 text-inert, outside the row.")
    return nvprobe.row(base, fields, src, note)


def apply(table_path):
    path = pathlib.Path(table_path)
    table = nvprobe.load_table(path)
    ins = table["instructions"]
    lea_keys = [k for k in ins if k.split("_")[0].split(".")[0] == "LEA"]
    if lea_keys and all(all(g.get("_src") == PROVENANCE for g in ins[k]["mod_groups"].values()) for k in lea_keys):
        print("LEA: already measured")
        return
    template_key = "LEA_R_P_R_R_II" if "LEA_R_P_R_R_II" in ins else lea_keys[0]
    template = {k: v for k, v in ins[template_key].items() if k not in ("mod_groups", "_o2", "_o2_fleet")}
    removed_rows = sum(len(ins[k]["mod_groups"]) for k in lea_keys)
    aliases = table.get("_meta", {}).get("key_aliases", {})
    for alias, target in list(aliases.items()):
        if target in lea_keys:
            del aliases[alias]
            print(f"  alias {alias} -> {target} dropped (target retired)")
    new_entries, added = {}, 0
    for form in FORMS:
        for with_pd in (False, True):
            for group in GROUPS:
                key = key_for(form, group, with_pd)
                entry = new_entries.setdefault(key, dict(template))
                entry["base_op"] = "LEA"
                entry["operand_sig"] = key[len("LEA_"):]
                entry.setdefault("mod_groups", {})
                entry["mod_groups"][group] = measured_group(form, group, with_pd)
                entry["_src"] = PROVENANCE
                added += 1
    # the new keys take the place of the first retired key (the tables are in insertion order; a
    # minimal diff keeps the review readable)
    rebuilt, placed = {}, False
    for k, v in ins.items():
        if k in lea_keys:
            if not placed:
                rebuilt.update((nk, new_entries[nk]) for nk in sorted(new_entries))
                placed = True
            continue
        rebuilt[k] = v
    if not placed:
        rebuilt.update((nk, new_entries[nk]) for nk in sorted(new_entries))
    table["instructions"] = ins = rebuilt
    prov = table["_meta"].setdefault("provenance", {})
    sources = prov.setdefault("sources", {})
    rows = [g for e in ins.values() for g in e.get("mod_groups", {}).values()]
    prov["rows_total"] = len(rows)
    prov["rows_without_src"] = sum(1 for g in rows if g.get("_src") is None)
    sources[PROVENANCE] = {
        "rows": added,
        "kind": "nvdisasm 13.1 field probe (-b SM120 / SM103 / SM100 text-identical)",
        "date": "2026-11-06",
        "tool": "tools/probes/re_sm120_lea.py",
        "test": "tests/sm120_lea.rs",
    }
    nvprobe.save_table(path, table)
    n_keys = sum(1 for k in ins if k.startswith("LEA_"))
    print(f"{path}: {len(lea_keys)} LEA keys / {removed_rows} rows replaced by {n_keys} keys / {added} measured rows")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("probe")
    p.add_argument("--nvdisasm", default="/usr/local/lib/python3.12/dist-packages/triton/backends/nvidia/bin/nvdisasm")
    p.add_argument("--out", type=pathlib.Path, default=FIXTURE)
    p.add_argument("--arch", default="SM120")
    a = sub.add_parser("apply")
    a.add_argument("table")
    args = parser.parse_args()
    if args.command == "probe":
        probe(args.nvdisasm, args.out, args.arch)
    else:
        apply(args.table)


if __name__ == "__main__":
    main()

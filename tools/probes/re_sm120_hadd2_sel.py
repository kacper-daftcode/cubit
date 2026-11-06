#!/usr/bin/env python3
"""Measure the SM120 register form of `HADD2` (opcode 0x230, `HADD2[.F32|.BF16_V2][.FTZ][.SAT] Rd, Ra, Rb`)
with nvdisasm 13.1 and rebuild `HADD2_R_R_R` from the measurement (session T-7, 2026-11-06).

Why: BUG-484 — cubit's own 2026-08-08 mnemonic-suffix row `HADD2.H1H1A_R_R_R` (blackwell-isa 8f773da,
"Ra = H1_H1 baked into the mnemonic", added because the plain row then dropped the selector) was retired
at the O2 cut (4340cdf) without an alias; the production kernels `exl3-wave-m8/k1_m8{,g}.sass` (256
sites, cubit 5912400) stopped assembling. Measuring the form for the alias showed the plain row itself
incomplete (dynamic audit T1, "HADD2 10 rows"): `HADD2_R_R_R` had no `|Ra|` / `|Rb|` fields on the plain
group, no sign fields at all on `BF16_V2`, and a harvest `F32` group with a baked sample (`-Ra`, `Rd = RZ`,
`Rb.H0_H0` in `and_base`); words with `|R5|` fell to the junk row `HADD2_R_R_II_II_II_II_?` and printed
`HADD2 R9, R2, 0x7000, 0x5, 0, 0, UR0`.

Measured (nvdisasm 13.1 `-b SM120`, one word per call; all SM120 bits named below move the text, every
other bit of [64:96) is text-inert except bit 91 = illegal on this form):
  * operands: guard [15:12], Rd [23:16], Ra [31:24], Rb [39:32];
  * Ra: selector [75:74] (0 natural, 2 `.H0_H0`, 3 `.H1_H1`, 1 = `INVALID1`), bit 72 = `-Ra`, 73 = `|Ra|`
    (`|Ra|` is text-inert under `.F32`); Rb: selector [61:60] likewise, bit 63 = `-Rb`, 62 = `|Rb|`;
    print: `-|R2|.H1_H1`;
  * modifiers: bit 77 `.SAT`, 78 `.F32`, 80 `.FTZ`, 85 `.BF16_V2` (`.F32` + `.BF16_V2` = illegal);
    print order `HADD2[.F32|.BF16_V2][.FTZ][.SAT]`;
  * `.reuse` on Ra / Rb reaches bits 122 / 124 through the encoder's generic register slots.
`probe` writes `tests/fixtures/sm120_hadd2_sel_nvdisasm.jsonl` (181 form + 36 lattice words); `apply <sm120.json>` replaces the groups of
`HADD2_R_R_R` with the 12 measured groups, removes the dotted twins `HADD2.F32_R_R_R` /
`HADD2.BF16_V2_R_R_R` (their words are the plain key's groups) and the register-opcode junk rows
`HADD2_R_R_R_R`, `HADD2_R_R_R_II_?`, `HADD2_R_R_R_II_II_?`, `HADD2_R_R_II`, `HADD2_R_R_II_II_II_II_?`
(harvest rows with opcode 0x230 and `imm`/`reg` fields on the Rb byte whose only role was to absorb what
the plain row's mask did not cover).
"""
import argparse
import pathlib
import re
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import nvprobe  # noqa: E402

PROVENANCE = "hadd2-rrr-sm120-2026-11-06"
NATIVE_CTRL = 0x000fc200 << 96
FIXTURE = nvprobe.FIXTURES / "sm120_hadd2_sel_nvdisasm.jsonl"
OPND = r"-?\|?R(?:Z|\d+)\|?(?:\.H[01]_H[01])?"  # nvdisasm: `-R2.H1_H1`, `|R5|.H1_H1`, `-|R2|.H1_H1`
TEXT = re.compile(rf"(?:@!?P[0-6T] )?HADD2(?:\.F32|\.BF16_V2)?(?:\.FTZ)?(?:\.SAT)? R(?:Z|\d+), {OPND}, {OPND}$")
MODS = {"F32": 78, "BF16_V2": 85, "FTZ": 80, "SAT": 77}
TYPES = ("", "F32", "BF16_V2")
REMOVED_KEYS = ["HADD2.F32_R_R_R", "HADD2.BF16_V2_R_R_R", "HADD2_R_R_R_R", "HADD2_R_R_R_II_?",
                "HADD2_R_R_R_II_II_?", "HADD2_R_R_II", "HADD2_R_R_II_II_II_II_?"]


def word(rd=9, ra=2, rb=5, sa=0, sb=0, nega=0, absa=0, negb=0, absb=0, ty="", ftz=0, sat=0, guard=7, extra=0):
    w = (0x230 | (guard << 12) | (rd << 16) | (ra << 24) | (rb << 32) | (sb << 60) | (absb << 62) | (negb << 63)
         | (nega << 72) | (absa << 73) | (sa << 74) | (ftz << 80) | (sat << 77) | extra)
    if ty:
        w |= 1 << MODS[ty]
    return w


def group_words(ty, ftz, sat):
    """(form words, lattice words) of one modifier group: under `.F32` the `|Ra|` bit 73 is text-inert
    (nvdisasm prints nothing for it), so the words that set it are lattice words there."""
    k = dict(ty=ty, ftz=ftz, sat=sat)
    out, inert = [word(**k)], []
    for sa in (2, 3):
        for sb in (0, 2, 3):
            out.append(word(sa=sa, sb=sb, **k))
    out.append(word(sb=2, **k))
    out.append(word(sb=3, **k))
    for signs in (dict(nega=1), dict(absa=1), dict(negb=1), dict(absb=1), dict(nega=1, absa=1, negb=1, absb=1),
                  dict(sa=3, nega=1, absb=1)):
        (inert if ty == "F32" and signs.get("absa") else out).append(word(**signs, **k))
    return out, inert


def sweep_words():
    form, lattice = [], set()
    for ty in TYPES:
        for ftz in (0, 1):
            for sat in (0, 1):
                f, inert = group_words(ty, ftz, sat)
                form.extend(f)
                lattice.update(inert)
    # operand field edges on the plain group
    for guard in (0, 15):
        form.append(word(guard=guard))
    for rd in (0, 255):
        form.append(word(rd=rd))
    for ra in (0, 255):
        form.append(word(ra=ra))
    for rb in (0, 255):
        form.append(word(rb=rb))
    form.append(word(ra=16, rb=16, rd=16, sa=3))  # the shipped exl3 shape `HADD2 R16, R16.H1_H1, R16`
    seen = set()
    form_words = [(w, False) for w in form if not (w in seen or seen.add(w))]
    # lattice: INVALID1 selector codes, the illegal F32 x BF16_V2, bit 91, the text-inert band
    lattice.add(word(sa=1))
    lattice.add(word(sb=1))
    lattice.add(word(sa=1, sb=1))
    lattice.add(word(ty="F32", extra=1 << 85))
    lattice.add(word(extra=1 << 91))
    for bit in (64, 65, 66, 67, 68, 69, 70, 71, 76, 79, 81, 82, 83, 84, 86, 87, 88, 89, 90, 92, 93, 94, 95):
        lattice.add(word(extra=1 << bit))
    lattice -= set(form)
    return form_words + [(w, True) for w in sorted(lattice)]


def probe(nvdisasm, out=FIXTURE):
    rows = nvprobe.probe_words(
        nvdisasm, "hadd2_sel", sweep_words(), NATIVE_CTRL,
        check_form=lambda w, t: TEXT.match(t) is not None,
        check_lattice=lambda w, t: t is None or t.startswith("HADD2"))
    nvprobe.write_fixture(out, rows)
    n_form = sum(1 for r in rows if not r.get("lattice"))
    print(f"{out}: {n_form} form words, {len(rows) - n_form} lattice words")


def measured_group(ty, ftz, sat):
    src = PROVENANCE
    fields = [
        nvprobe.field(12, 4, "guard", 0, src),
        nvprobe.field(16, 8, "reg", 1, src),
        nvprobe.field(24, 8, "reg", 2, src),
        nvprobe.field(72, 1, "neg", 2, src),
        nvprobe.field(74, 2, "hsel", 2, src),
        nvprobe.field(122, 1, "reuse", 2, src),
        nvprobe.field(32, 8, "reg", 3, src),
        nvprobe.field(63, 1, "neg", 3, src),
        nvprobe.field(62, 1, "abs", 3, src),
        nvprobe.field(60, 2, "hsel", 3, src),
        nvprobe.field(124, 1, "reuse", 3, src),
    ]
    if ty != "F32":
        fields.insert(4, nvprobe.field(73, 1, "abs", 2, src))  # `|Ra|` is text-inert under .F32
    base = word(ty=ty, ftz=ftz, sat=sat, guard=0, rd=0, ra=0, rb=0)
    mods = ",".join(sorted(m for m in (ty, "FTZ" if ftz else "", "SAT" if sat else "") if m))
    note = (f"HADD2 R_R_R {mods or 'plain'}: measured with nvdisasm 13.1 -b SM120 (session T-7, 2026-11-06): "
            "Ra sel [75:74], -Ra 72, |Ra| 73" + (" (text-inert under .F32, not a field)" if ty == "F32" else "")
            + "; Rb sel [61:60], -Rb 63, |Rb| 62; SAT 77, F32 78, FTZ 80, BF16_V2 85; bit 91 illegal, the rest of [64:96) text-inert")
    return mods, nvprobe.row(base, fields, src, note)


def apply(table_path):
    path = pathlib.Path(table_path)
    table = nvprobe.load_table(path)
    ins = table["instructions"]
    key = "HADD2_R_R_R"
    if key in ins and all(g.get("_src") == PROVENANCE for g in ins[key]["mod_groups"].values()):
        print("HADD2_R_R_R: already measured")
        return
    entry = {k: v for k, v in ins[key].items() if k != "mod_groups"}
    entry["base_op"] = "HADD2"
    entry["operand_sig"] = "R_R_R"
    groups = {}
    for ty in TYPES:
        for ftz in (0, 1):
            for sat in (0, 1):
                mods, g = measured_group(ty, ftz, sat)
                groups[mods] = g
    entry["mod_groups"] = groups
    entry["_src"] = PROVENANCE
    ins[key] = entry
    removed = [k for k in REMOVED_KEYS if k in ins]
    for k in removed:
        del ins[k]
    aliases = table.get("_meta", {}).get("key_aliases", {})
    for alias, target in list(aliases.items()):
        if target in removed:
            aliases[alias] = key
    prov = table["_meta"]["provenance"]
    prov["sources"][PROVENANCE] = {
        "rows": len(groups), "kind": "nvdisasm 13.1 field probe", "date": "2026-11-06",
        "tool": "tools/probes/re_sm120_hadd2_sel.py", "test": "tests/bug484_hadd2_h1h1a_spelling.rs",
    }
    rows = [g for e in ins.values() for g in e.get("mod_groups", {}).values()]
    prov["rows_total"] = len(rows)
    prov["rows_without_src"] = sum(1 for g in rows if g.get("_src") is None)
    nvprobe.save_table(path, table)
    print(f"HADD2_R_R_R rebuilt with {len(groups)} groups; removed {len(removed)} keys ({', '.join(removed)}) in {path}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("probe")
    p.add_argument("--nvdisasm", default="/usr/local/lib/python3.12/dist-packages/triton/backends/nvidia/bin/nvdisasm")
    p.add_argument("--out", type=pathlib.Path, default=FIXTURE)
    a = sub.add_parser("apply")
    a.add_argument("table")
    args = parser.parse_args()
    if args.command == "probe":
        probe(args.nvdisasm, args.out)
    else:
        apply(args.table)


if __name__ == "__main__":
    main()

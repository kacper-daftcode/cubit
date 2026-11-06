#!/usr/bin/env python3
"""Measure the SM120 dense `IMMA` family (opcode 0x237, the 8-bit integer tensor-core MMA) over its type x shape x
saturation x operand lattice with nvdisasm and rebuild the keys from the measurement.

Why (dynamic audit T1, session T-10 2026-11-06): the harvest rows of the mixed-type and `.SAT` forms carried
2-bit-shifted register fields (`reg@18` / `reg@26` / `reg@66`: `IMMA.16816.S8.S8.SAT R4, R6.ROW, R8.COL, R10`
printed for the vendor's `R16, R24.ROW, R8.COL, R40`), `neg` junk fields on the layout bits 73 / 74 (their
canonical words rendered `R8.???0` — the B layout bit cleared) and phantom `_P_` twins; only the four
`IMMA.168{16,32}.{S8.S8,U8.U8}_R_R_R_R` rows had the right fields.

Measured with nvdisasm 13.1 (`-b SM120`, one word per call):

  * Rd [23:16], Ra [31:24] (printed `.ROW`), Rb [39:32] (printed `.COL`), Rc [71:64] (255 = RZ); guard [15:12];
  * bit 86 = the dense shape frame (clear = `INVALID0`), bit 75: 0 = `16816`, 1 = `16832`; bit 85 = `INVALID6`;
  * A type bit 76 (1 = `S8`, 0 = `U8`; 77 = `INVALID3`, 83 = `INVALID5`), B type bit 78 (1 = `S8`, 0 = `U8`;
    79 = `INVALID3`, 84 = `INVALID5`); bit 82 = `.SAT`;
  * bit 73 = the A layout (0 = `.ROW`, 1 = `.???1`), bit 74 = the B layout (1 = `.COL`, 0 = `.???0`): only
    ROW / COL exist -- baked, fail-closed;
  * a fifth operand `[!]UPn`: the 4-bit `pred_inv4` window [90:87] -- bit 90 = `!`, [89:87] = 7 - n
    (0 = `UPT`, elided unless negated: `IMMA… R40, UP6` = [89:87] 1, `…, !UPT` = bit 90 alone);
  * bit 72 = the sparse form (`IMMA.SP.*` keys of their own, not touched here); bit 91 illegal; bits 80, 81,
    92-95 text-inert (baked 0, outside the rows).

Keys: the type pair is order-sensitive and the mod-group name is sorted (`S8,U8` would name both `S8.U8` and
`U8.S8`), so the family uses TYPED keys (the schema's convention for this collision, NEEDS 36 / D2):
`IMMA.<16816|16832>.<A>.<B>[.SAT]_R_R_R_R` and the same with `_UP` -- 32 keys, one measured row each. The four
existing typed rows are replaced by measured rows of the same key; the `.SAT` / mixed-type harvest keys and the
`_P_` / `_?` twins are retired (no census witness).

`probe` writes `tests/fixtures/sm120_imma_nvdisasm.jsonl`; `apply <sm120.json>` rewrites the dense keys.
Test: `tests/sm120_imma.rs`.
"""
import argparse
import itertools
import pathlib
import re
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import nvprobe  # noqa: E402

PROVENANCE = "imma-family-2026-11-06"
CTRL = 0x000fe200 << 96
FIXTURE = nvprobe.FIXTURES / "sm120_imma_nvdisasm.jsonl"
TEXT = re.compile(r"(@!?P[0-6T] )?IMMA\.(16816|16832)\.(S8|U8)\.(S8|U8)(\.SAT)? R(?:Z|\d+), R(?:Z|\d+)\.ROW, R(?:Z|\d+)\.COL, R(?:Z|\d+)(, !?UP[0-6T])?")


def word(shape=16816, a="S8", b="S8", sat=0, rd=16, ra=24, rb=8, rc=40, guard=7, up=7, upneg=0, extra=0):
    """`up` = the UP operand number (7 = UPT); the field carries 7 - up (pred_inv4)."""
    w = (0x237 | (guard << 12) | (rd << 16) | (ra << 24) | (rb << 32) | (rc << 64) | (1 << 86) | (1 << 74)
         | ((1 << 75) if shape == 16832 else 0) | ((1 << 76) if a == "S8" else 0) | ((1 << 78) if b == "S8" else 0)
         | (sat << 82) | ((7 - up) << 87) | (upneg << 90) | extra)
    return w


def reg(n):
    return "RZ" if n == 255 else f"R{n}"


def expected_text(w):
    guard = (w >> 12) & 0xf
    g = "" if guard == 7 else ("@" + ("!" if guard & 8 else "") + ("PT" if (guard & 7) == 7 else f"P{guard & 7}") + " ")
    shape = "16832" if (w >> 75) & 1 else "16816"
    a = "S8" if (w >> 76) & 1 else "U8"
    b = "S8" if (w >> 78) & 1 else "U8"
    sat = ".SAT" if (w >> 82) & 1 else ""
    up, un = 7 - ((w >> 87) & 7), (w >> 90) & 1
    tail = "" if (up == 7 and un == 0) else (", " + ("!" if un else "") + ("UPT" if up == 7 else f"UP{up}"))
    return (f"{g}IMMA.{shape}.{a}.{b}{sat} {reg((w >> 16) & 0xff)}, {reg((w >> 24) & 0xff)}.ROW, "
            f"{reg((w >> 32) & 0xff)}.COL, {reg((w >> 64) & 0xff)}{tail}")


def sweep_words():
    form, lattice = set(), set()
    for shape, a, b, sat in itertools.product((16816, 16832), ("S8", "U8"), ("S8", "U8"), (0, 1)):
        m = dict(shape=shape, a=a, b=b, sat=sat)
        form.add(word(**m))
        # (RZ as the destination renders but the encoder's BUG-037 alignment guard refuses it -- its silicon
        # legality is unmeasured; kept out of the form sweep)
        for rd, ra, rb, rc in ((0, 4, 2, 0), (4, 8, 12, 4), (252, 252, 254, 252), (16, 24, 8, 255), (20, 0, 0, 255)):
            form.add(word(rd=rd, ra=ra, rb=rb, rc=rc, **m))
        for guard in (0, 6, 8, 15):
            form.add(word(guard=guard, **m))
        for up, un in ((0, 0), (3, 0), (6, 1), (7, 1)):
            form.add(word(up=up, upneg=un, **m))
        form.add(word(guard=2, up=5, upneg=1, rd=8, ra=12, rb=6, rc=8, **m))
    base = word()
    lattice.add(base | (1 << 73))  # A layout ???1
    lattice.add(base & ~(1 << 74))  # B layout ???0
    for bit in (77, 79, 83, 84, 85):  # INVALID type / shape codes
        lattice.add(base | (1 << bit))
    lattice.add(base & ~(1 << 86))  # INVALID0
    lattice.add(base | (1 << 91))  # illegal
    lattice.add(base | (1 << 72))  # the sparse form (another family)
    for bit in (80, 81, 92, 93, 94, 95):
        lattice.add(base | (1 << bit))  # text-inert
    lattice -= form
    return [(w, False) for w in sorted(form)] + [(w, True) for w in sorted(lattice)]


def lattice_ok(w, t):
    if t is None:
        return True
    inert = t == expected_text(w & ~((0xf << 92) | (3 << 80)))
    return inert or "INVALID" in t or "???" in t or ".SP." in t


def probe(nvdisasm, out=FIXTURE):
    rows = nvprobe.probe_words(nvdisasm, "imma", sweep_words(), CTRL,
                               check_form=lambda w, t: TEXT.fullmatch(t) is not None and t == expected_text(w),
                               check_lattice=lattice_ok)
    nvprobe.write_fixture(out, rows)
    n_form = sum(1 for r in rows if not r.get("lattice"))
    print(f"{out}: {n_form} form words, {len(rows) - n_form} lattice words")


NOTE = ("dense IMMA (0x237) measured with nvdisasm 13.1 -b SM120, tools/probes/re_sm120_imma.py (session T-10, 2026-11-06): "
        "Rd [23:16], Ra [31:24] .ROW, Rb [39:32] .COL, Rc [71:64]; bit 86 dense frame, 75 shape (16832), 76 A = S8, 78 B = S8, "
        "82 .SAT, 73 / 74 the only legal layouts (ROW / COL) baked; [89:87] + 90 the optional UP operand; 80, 81, 92-95 text-inert.")


def apply(table_path):
    path = pathlib.Path(table_path)
    table = nvprobe.load_table(path)
    ins = table["instructions"]
    dense = [k for k in ins if k.startswith("IMMA.168")]  # the SP / SF keys stay
    if dense and all(g.get("_src") == PROVENANCE for k in dense for g in ins[k]["mod_groups"].values()) and len(dense) == 32:
        print("IMMA: already measured")
        return
    old_rows = sum(len(ins[k]["mod_groups"]) for k in dense)
    for k in dense:
        del ins[k]
    total = 0
    for shape, a, b, sat, up in itertools.product((16816, 16832), ("S8", "U8"), ("S8", "U8"), (0, 1), (False, True)):
        src = PROVENANCE
        fields = [nvprobe.field(12, 4, "guard", 0, src), nvprobe.field(16, 8, "reg", 1, src), nvprobe.field(24, 8, "reg", 2, src),
                  nvprobe.field(32, 8, "reg", 3, src), nvprobe.field(64, 8, "reg", 4, src),
                  nvprobe.field(122, 1, "reuse", 2, src), nvprobe.field(123, 1, "reuse", 3, src), nvprobe.field(124, 1, "reuse", 4, src)]
        if up:
            fields += [nvprobe.field(87, 4, "pred_inv4", 5, src)]
        base = word(shape=shape, a=a, b=b, sat=sat, rd=0, ra=0, rb=0, rc=0, guard=0, up=7)  # the UP window is 0 = UPT
        base &= ~nvprobe.field_mask(fields)
        key = f"IMMA.{shape}.{a}.{b}{'.SAT' if sat else ''}_R_R_R_R{'_UP' if up else ''}"
        ins[key] = {"base_op": "IMMA", "operand_sig": key[len("IMMA"):], "mod_groups": {"": nvprobe.row(base, fields, src, NOTE)}, "_src": PROVENANCE}
        total += 1
    aliases = table["_meta"].setdefault("key_aliases", {})
    for old in dense:
        if old.endswith("_?") or "_P_R_R_R_R" in old or old.endswith("_II_?"):
            plain = old.replace("_P_R_R_R_R", "_R_R_R_R").replace("_R_R_R_R_II_?", "_R_R_R_R").replace("_R_R_R_R_?", "_R_R_R_R")
            if plain in ins:
                aliases[old] = plain
    prov = table["_meta"].setdefault("provenance", {})
    sources = prov.setdefault("sources", {})
    rows = [g for e in ins.values() for g in e.get("mod_groups", {}).values()]
    prov["rows_total"] = len(rows)
    prov["rows_without_src"] = sum(1 for g in rows if g.get("_src") is None)
    sources[PROVENANCE] = {"rows": total, "kind": "nvdisasm 13.1 field probe (-b SM120)", "date": "2026-11-06",
                           "tool": "tools/probes/re_sm120_imma.py", "test": "tests/sm120_imma.rs"}
    nvprobe.save_table(path, table)
    print(f"{path}: dense IMMA {len(dense)} keys / {old_rows} rows -> {total} measured keys / rows")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
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

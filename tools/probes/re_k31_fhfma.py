#!/usr/bin/env python3
"""Measure and register FlashMLA FHFMA.BF16 register forms."""
import argparse, copy, json, pathlib, sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from nvprobe import field, field_mask, load_table, probe_words, row, save_table, write_fixture

SRC = "k31-fhfma-bf16-flashmla-2026-11-07"
ROOT = pathlib.Path(__file__).resolve().parents[3]
VENDOR = ROOT.parent / "inbox-hgx02/2026-11-07-k31-prefill-gaps/vendor/fixture_flashmla_sm100.jsonl"
FIXTURE = pathlib.Path(__file__).resolve().parents[2] / "tests/fixtures/k31_fhfma_nvdisasm.jsonl"
KEY = "FHFMA.BF16_R_R_R_R"
H1_KEY = "FHFMA.BF16.H1_R_R_R_R"


def put(word, shift, bits, value):
    return (word & ~(((1 << bits) - 1) << shift)) | (value << shift)


def production():
    out = []
    with VENDOR.open() as fh:
        for line in fh:
            r = json.loads(line)
            if r["text"].startswith("FHFMA.BF16 "):
                assert int(r["word"], 16) & 0xfff == 0x223
                out.append({"word": r["word"][2:], "nvidia_sass": r["text"], "arch": "SM100",
                            "op": "FHFMA.BF16", "nvdisasm": r["nvdisasm"], "source": r["source"],
                            "occurrences": r["occurrences"], "evidence": "H production witness (not re-probed)"})
    assert len(out) == 389
    assert sum(r["occurrences"] for r in out) == 2560
    return out


def probe(args):
    out = []
    production_rows = production()
    for arch in ("SM103", "SM100"):
        if arch == "SM100":
            out.extend(production_rows)
        base = int(production_rows[0]["word"], 16)
        words = {put(base, 12, 4, guard) for guard in range(16)}
        for shift in (16, 24, 32, 64):
            for value in (0, 5, 47, 100, 255):
                words.add(put(base, shift, 8, value))
        for shift in (62, 63, 72, 73, 74, 75, 122, 123, 124):
            words.add(put(base, shift, 1, 0))
            words.add(put(base, shift, 1, 1))
        for shifts in ((83,), (84,), (83, 84)):
            h1 = base
            for shift in shifts:
                h1 = put(h1, shift, 1, 1)
            words.add(h1)
        words = sorted(words)
        measured = probe_words(args.nvdisasm, "k31_fhfma", [(w, False) for w in words], 0,
                               lambda _w, text: "FHFMA.BF16" in text, arch=arch, jobs=args.jobs)
        for rec, word in zip(measured, words):
            rec.update({"word": f"{word:032x}", "arch": arch, "op": "FHFMA.BF16", "occurrences": 0,
                        "evidence": "independent raw nvdisasm field probe"})
            out.append(rec)
    write_fixture(args.out, out)
    print(len(out), "records ->", args.out)


def apply(tables):
    donor = load_table(ROOT / "isa-k31/sm120.json")["instructions"]["FFMA_R_R_R_R"]
    anchor = int(production()[0]["word"], 16)
    for path in tables:
        table = load_table(path)
        ins = table["instructions"]
        entry = copy.deepcopy(donor)
        entry["base_op"] = "FHFMA.BF16"
        entry["operand_sig"] = "R_R_R_R"
        fields = copy.deepcopy(donor["mod_groups"]["FTZ"]["fields"])
        for f in fields:
            f["_src"] = SRC
        base = (anchor & ~field_mask(fields) & ~(((1 << 23) - 1) << 105) & ~0xfff) | 0x223
        group = row(base, fields, SRC,
                    "FlashMLA 389 production words + SM103/SM100 nvdisasm 13.3.73 field probes: "
                    "FHFMA.BF16 keeps FFMA's four-register and sign/reuse geometry; bits 81 and 82 select "
                    "this exact mixed-precision mnemonic. Other rounding modes remain outside the row.")
        entry["mod_groups"] = {"": group}
        entry["_src"] = SRC
        ins[KEY] = entry
        h1_fields = copy.deepcopy(fields)
        h1_fields.extend([field(83, 1, "opmod:H1", 2, SRC), field(84, 1, "opmod:H1", 3, SRC)])
        h1_base = (anchor & ~field_mask(h1_fields) & ~(((1 << 23) - 1) << 105) & ~0xfff) | 0x223
        h1_group = row(h1_base, h1_fields, SRC,
                       "Measured `.H1` half selectors: bit 83 belongs to operand 2 and bit 84 to operand 3. "
                       "The separate key prevents an operand modifier from becoming an invented mnemonic modifier.")
        h1_entry = copy.deepcopy(entry)
        h1_entry["mod_groups"] = {"": h1_group}
        ins[H1_KEY] = h1_entry
        pro = table["_meta"]["provenance"]
        pro["sources"][SRC] = {"rows": 2, "kind": "measured FFMA geometry + nvdisasm 13.3.73 target probes + production witnesses",
                              "date": "2026-11-07", "tool": "tools/probes/re_k31_fhfma.py", "test": "tests/k31_fhfma.rs"}
        pro["rows_total"] = sum(len(e.get("mod_groups", {})) for e in ins.values())
        pro["rows_without_src"] = sum(1 for e in ins.values() for g in e.get("mod_groups", {}).values() if "_src" not in g)
        save_table(path, table)
        print(path, "FHFMA.BF16 plain and H1 rows installed")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest="command", required=True)
    p = sub.add_parser("probe")
    p.add_argument("--nvdisasm", default="/usr/local/cuda/bin/nvdisasm")
    p.add_argument("--out", type=pathlib.Path, default=FIXTURE)
    p.add_argument("--jobs", type=int, default=8)
    a = sub.add_parser("apply")
    a.add_argument("tables", nargs="+", type=pathlib.Path)
    args = ap.parse_args()
    if args.command == "probe":
        probe(args)
    else:
        apply(args.tables)


if __name__ == "__main__":
    main()

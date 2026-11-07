#!/usr/bin/env python3
"""Measure the single MOVM.16.MT88 register form used by FlashKDA."""
import argparse, copy, json, pathlib, sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from nvprobe import SCHEDULE, field_mask, load_table, probe_words, row, save_table, write_fixture

SRC = "k31-movm16-mt88-2026-11-07"
ROOT = pathlib.Path(__file__).resolve().parents[3]
VENDOR = ROOT.parent / "inbox-hgx02/2026-11-07-k31-prefill-gaps/vendor/fixture_flashkda_sm100.jsonl"
FIXTURE = pathlib.Path(__file__).resolve().parents[2] / "tests/fixtures/k31_movm_nvdisasm.jsonl"
OP = "MOVM.16.MT88"


def put(word, shift, bits, value):
    return (word & ~(((1 << bits) - 1) << shift)) | (value << shift)


def production():
    out = []
    with VENDOR.open() as fh:
        for line in fh:
            r = json.loads(line)
            if r["text"].startswith(OP + " "):
                out.append({"word": r["word"][2:], "nvidia_sass": r["text"], "arch": "SM100", "op": OP,
                            "nvdisasm": r["nvdisasm"], "source": r["source"], "occurrences": r["occurrences"],
                            "evidence": "H production witness, not bulk-reprobed"})
    assert len(out) == 1907
    assert sum(r["occurrences"] for r in out) == 7712
    return out


def probe(args):
    out = []
    records = production()
    for arch in ("SM103", "SM100"):
        if arch == "SM100":
            out.extend(records)
        base = int(records[0]["word"], 16)
        words = {put(base, 12, 4, guard) for guard in range(16)}
        for shift in (16, 24):
            for value in (0, 5, 63, 64, 100, 127, 128, 255):
                words.add(put(base, shift, 8, value))
        words = sorted(words)
        measured = probe_words(args.nvdisasm, "k31_movm", [(w, False) for w in words], 0,
                               lambda _w, text: OP + " " in text, arch=arch, jobs=args.jobs)
        for rec, word in zip(measured, words):
            rec.update({"word": f"{word:032x}", "arch": arch, "op": OP, "occurrences": 0,
                        "evidence": "independent guard/register nvdisasm field probe"})
            out.append(rec)
    write_fixture(args.out, out)
    print(len(out), "records ->", args.out)


def apply(tables):
    donor = load_table(ROOT / "isa-k31/sm120.json")["instructions"][OP + "_R_R"]
    for path in tables:
        table = load_table(path)
        assert OP + "_R_R" not in table["instructions"]
        entry = copy.deepcopy(donor)
        fields = copy.deepcopy(entry["mod_groups"][""]["fields"])
        assert [(f["shift"], f["bits"], f["extraction"], f["token_idx"]) for f in fields] == [
            (12, 4, "guard", 0), (16, 8, "reg", 1), (24, 8, "reg", 2)]
        for f in fields:
            f["_src"] = SRC
        word = int(production()[0]["word"], 16)
        base = (word & ~field_mask(fields) & ~SCHEDULE & ~0xfff) | 0x23a
        entry["_src"] = SRC
        entry["mod_groups"] = {"": row(base, fields, SRC,
            "FlashKDA MOVM.16.MT88 with full guard and two 8-bit register fields, measured on both targets.")}
        table["instructions"][OP + "_R_R"] = entry
        provenance = table["_meta"]["provenance"]
        provenance["sources"][SRC] = {"rows": 1, "kind": "FlashKDA production witnesses + guard/register probes",
            "date": "2026-11-07", "tool": "tools/probes/re_k31_movm.py", "test": "tests/k31_movm.rs"}
        provenance["rows_total"] = sum(len(e.get("mod_groups", {})) for e in table["instructions"].values())
        provenance["rows_without_src"] = sum(1 for e in table["instructions"].values()
                                             for g in e.get("mod_groups", {}).values() if "_src" not in g)
        save_table(path, table)
        print(path, "MOVM.16.MT88 installed")


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
    probe(args) if args.command == "probe" else apply(args.tables)


if __name__ == "__main__":
    main()

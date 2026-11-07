#!/usr/bin/env python3
"""Remove the scheduling-yield / operand-reuse confusion on PRMT."""
import argparse, json, pathlib, sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from nvprobe import field_mask, load_table, probe_words, save_table, write_fixture

SRC = "k31-prmt-yield-is-not-reuse-2026-11-07"
ROOT = pathlib.Path(__file__).resolve().parents[3]
VENDOR = ROOT.parent / "inbox-hgx02/2026-11-07-k31-prefill-gaps/vendor/fixture_flashmla_sm100.jsonl"
FIXTURE = pathlib.Path(__file__).resolve().parents[2] / "tests/fixtures/k31_prmt_nvdisasm.jsonl"


def put(word, shift, bits, value):
    return (word & ~(((1 << bits) - 1) << shift)) | (value << shift)


def production():
    rows = []
    with VENDOR.open() as fh:
        for line in fh:
            r = json.loads(line)
            if r["text"].startswith("PRMT "):
                rows.append({"word": r["word"][2:], "nvidia_sass": r["text"], "arch": "SM100",
                             "op": "PRMT", "nvdisasm": r["nvdisasm"], "source": r["source"],
                             "occurrences": r["occurrences"], "evidence": "H production witness, not bulk-reprobed"})
    assert len(rows) == 22
    return rows


def probe(args):
    out = []
    production_rows = production()
    for arch in ("SM103", "SM100"):
        if arch == "SM100":
            out.extend(production_rows)
        base = int(production_rows[0]["word"], 16)
        words = {put(base, 12, 4, guard) for guard in range(16)}
        for shift in (16, 24, 32, 64):
            for value in (0, 5, 63, 64, 255):
                words.add(put(base, shift, 8, value))
        words = sorted(words)
        measured = probe_words(args.nvdisasm, "k31_prmt", [(w, False) for w in words], 0,
                               lambda _w, text: "PRMT" in text, arch=arch, jobs=args.jobs)
        for rec, word in zip(measured, words):
            rec.update({"word": f"{word:032x}", "arch": arch, "op": "PRMT", "occurrences": 0,
                        "evidence": "independent guard/register nvdisasm field probe"})
            out.append(rec)
    write_fixture(args.out, out)
    print(len(out), "records ->", args.out)


def apply(tables):
    for path in tables:
        table = load_table(path)
        group = table["instructions"]["PRMT_R_R_R_R"]["mod_groups"][""]
        group["fields"] = [f for f in group["fields"] if not (f["shift"] == 109 and f["extraction"] == "reuse")]
        assert not any(f["shift"] == 109 for f in group["fields"])
        assert any(f["shift"] == 123 for f in group["fields"])
        group["variable_mask"] = f"0x{field_mask(group['fields']):032x}"
        for f in group["fields"]:
            f["_src"] = SRC
        group["_src"] = SRC
        group["_note"] = "Bit 109 is the scheduling yield flag, not an operand reuse selector. PRMT's actual reuse fields are at 121/122/123. Removing the false reuse preserves source absence and avoids minting bit 123 from yield."
        provenance = table["_meta"]["provenance"]
        provenance["sources"][SRC] = {"rows": 1, "kind": "nvdisasm production witnesses + scheduling/reuse separation proof",
            "date": "2026-11-07", "tool": "tools/probes/re_k31_prmt.py", "test": "tests/k31_prmt.rs"}
        save_table(path, table)
        print(path, "removed scheduling-yield reuse field; mask recomputed")


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
    if args.command == "probe": probe(args)
    else: apply(args.tables)


if __name__ == "__main__": main()

#!/usr/bin/env python3
"""Collect the existing H UTCHMMA production witnesses without a bulk census."""
import argparse, json, pathlib
import sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from nvprobe import load_table, save_table

ROOT = pathlib.Path(__file__).resolve().parents[3]
SOURCE = ROOT.parent / "inbox-hgx02/2026-11-07-k31-prefill-gaps/vendor/fixture_flashmla_sm100.jsonl"
OUT = pathlib.Path(__file__).resolve().parents[2] / "tests/fixtures/k31_utchmma_words_nvdisasm.jsonl"
SRC = "k31-utchmma-descriptor-kinds-2026-11-07"

__doc__ = __doc__


def build():
    rows = []
    with SOURCE.open() as fh:
        for line in fh:
            r = json.loads(line)
            if r["text"].startswith("UTCHMMA"):
                rows.append({"word": r["word"][2:], "nvidia_sass": r["text"], "arch": "SM100",
                             "op": r["text"].split()[0], "nvdisasm": r["nvdisasm"],
                             "source": r["source"], "occurrences": r["occurrences"],
                             "evidence": "H production witness, not repeated for this package"})
    assert len(rows) == 410, len(rows)
    assert sum(r["occurrences"] for r in rows) == 757
    with OUT.open("w") as fh:
        for r in rows:
            fh.write(json.dumps(r) + "\n")
    print(len(rows), "records ->", OUT)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest="command", required=True)
    sub.add_parser("probe")
    a = sub.add_parser("apply")
    a.add_argument("tables", nargs="+", type=pathlib.Path)
    args = ap.parse_args()
    if args.command == "probe":
        build()
    else:
        apply(args.tables)


def apply(tables):
    for path in tables:
        table = load_table(path)
        group = table["instructions"]["UTCHMMA_II_II_II_II_II_UP"]["mod_groups"]["WS"]
        matched = False
        for f in group["fields"]:
            if f["token_idx"] == 1 and f.get("extraction") == "gdesc_ur":
                f["extraction"] = "tdesc_ur"
                matched = True
            f["_src"] = SRC
        assert matched or any(f["token_idx"] == 1 and f["extraction"] == "tdesc_ur" for f in group["fields"])
        group["_src"] = SRC
        group["_note_kind_probe"] = "SM103/SM100 nvdisasm dsel2: 0/3=hole or UTCQMMA; 1=gdesc; 2=tmem. WS token 1 is mixed-kind; naming it gdesc_ur erased tmem on both print and encode."
        cta = table["instructions"]["UTCHMMA_II_II_II_II_II_UP"]["mod_groups"]["2CTA"]
        split = False
        for f in cta["fields"]:
            if f["token_idx"] == 6 and f["shift"] == 87 and f["bits"] == 4 and f["extraction"] == "pred":
                f["bits"] = 3
                split = True
            f["_src"] = SRC
        assert split or cta["fields"][-1]["extraction"] == "neg"
        if not any(f["token_idx"] == 6 and f["shift"] == 90 and f["extraction"] == "neg" for f in cta["fields"]):
            cta["fields"].append({"bits": 1, "extraction": "neg", "shift": 90, "token_idx": 6, "_src": SRC})
        cta["_src"] = SRC
        cta["_note_predicate_probe"] = "UP0/UPn and negated UPT production words: predicate value[89:87], negation bit[90]. The donor's packed 4-bit pred hid negation; split without changing the mask."
        provenance = table["_meta"]["provenance"]
        provenance["sources"][SRC] = {"rows": 2, "kind": "nvdisasm 13.3.73 dsel2/type selector + production witnesses",
            "date": "2026-11-07", "tool": "tools/probes/re_k31_utchmma_words.py", "test": "tests/k31_utchmma_words.rs"}
        save_table(path, table)
        print(path, "WS mixed descriptor kind fixed without mask changes")


if __name__ == "__main__":
    main()

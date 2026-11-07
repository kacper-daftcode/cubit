#!/usr/bin/env python3
"""Restore measured register-relative BRXU.UR_II encodings."""
import argparse, copy, json, pathlib, sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from nvprobe import load_table, save_table

SRC = "k31-brxu-register-offset-2026-11-07"
ROOT = pathlib.Path(__file__).resolve().parents[3]
VENDOR = ROOT.parent / "inbox-hgx02/2026-11-07-k31-prefill-gaps/vendor/fixture_flashmla_sm100.jsonl"
FIXTURE = pathlib.Path(__file__).resolve().parents[2] / "tests/fixtures/k31_brxu_nvdisasm.jsonl"


def build():
    rows = []
    with VENDOR.open() as fh:
        for line in fh:
            r = json.loads(line)
            if r["text"].startswith("BRXU UR"):
                rows.append({"word": r["word"][2:], "nvidia_sass": r["text"].split("(*")[0].rstrip(), "arch": "SM100",
                             "op": "BRXU", "nvdisasm": r["nvdisasm"], "source": r["source"],
                             "occurrences": r["occurrences"], "evidence": "H production witness"})
    assert len(rows) == 13
    assert sum(r["occurrences"] for r in rows) == 13
    with FIXTURE.open("w") as fh:
        for r in rows:
            fh.write(json.dumps(r) + "\n")
    print(len(rows), "records ->", FIXTURE)


def apply(tables):
    donor = load_table(ROOT / "isa-k31/sm120.json")["instructions"]["BRXU_UR_II"]
    for path in tables:
        table = load_table(path)
        entry = copy.deepcopy(donor)
        group = entry["mod_groups"][""].copy()
        for f in group["fields"]:
            f["_src"] = SRC
        group["_src"] = SRC
        entry["_src"] = SRC
        entry["mod_groups"] = {"": group}
        table["instructions"]["BRXU_UR_II"] = entry
        old = table["instructions"].pop("BRXU_L", None)
        assert old is not None
        table["_meta"].setdefault("key_aliases", {})["BRXU_L"] = "BRXU_UR_II"
        pro = table["_meta"]["provenance"]
        pro["sources"][SRC] = {"rows": 1, "kind": "brx-ret-family measured donor + FlashMLA production witnesses",
                              "date": "2026-11-07", "tool": "tools/probes/re_k31_brxu.py", "test": "tests/k31_brxu.rs"}
        pro["rows_total"] = sum(len(e.get("mod_groups", {})) for e in table["instructions"].values())
        pro["rows_without_src"] = sum(1 for e in table["instructions"].values() for g in e.get("mod_groups", {}).values() if "_src" not in g)
        save_table(path, table)
        print(path, "BRXU_UR_II installed with signed dword split")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest="command", required=True)
    sub.add_parser("probe")
    a = sub.add_parser("apply")
    a.add_argument("tables", nargs="+", type=pathlib.Path)
    args = ap.parse_args()
    if args.command == "probe": build()
    else: apply(args.tables)


if __name__ == "__main__": main()

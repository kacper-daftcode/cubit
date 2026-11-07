#!/usr/bin/env python3
"""Freeze UTCHMMA's structured-address witnesses and register row provenance."""
import argparse, json, pathlib, sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from nvprobe import load_table, save_table

SRC = "k31-utchmma-tmem-addr-2026-11-07"
KEY = "UTCHMMA_II_II_II_II_II_UP"
VENDOR = pathlib.Path("/root/sm103a/inbox-hgx02/2026-11-07-k31-prefill-gaps/vendor/fixture_trtllm_moe_sm103a.jsonl")
FIXTURE = pathlib.Path(__file__).resolve().parents[2] / "tests/fixtures/k31_utchmma_nvdisasm.jsonl"


def probe(out):
    rows = []
    with VENDOR.open() as fh:
        for line in fh:
            r = json.loads(line)
            if not r["text"].startswith("UTCHMMA"):
                continue
            rows.append({"word": r["word"][2:], "nvidia_sass": r["text"], "arch": "SM103",
                "nvdisasm": r["nvdisasm"], "source": r["source"], "occurrences": r["occurrences"],
                "evidence": "H production witness (not re-probed)"})
    assert len(rows) == 153 and sum(r["occurrences"] for r in rows) == 528
    assert len({r["word"] for r in rows}) == len(rows)
    with out.open("w") as fh:
        for r in rows:
            fh.write(json.dumps(r) + "\n")
    print(len(rows), "UTCHMMA records ->", out)


def apply(tables):
    for path in tables:
        table = load_table(path)
        group = table["instructions"][KEY]["mod_groups"][""]
        assert any(f["extraction"] == "tdesc_off" and f["shift"] == 70 and f["token_idx"] == 1 for f in group["fields"])
        assert any(f["extraction"] == "tmem_ur" and f["shift"] == 64 and f["token_idx"] == 3 for f in group["fields"])
        for f in group["fields"]:
            f["_src"] = SRC
        group["_src"] = SRC
        table["instructions"][KEY]["_src"] = SRC
        table["_meta"]["provenance"]["sources"][SRC] = {
            "rows": 1, "kind": "nvdisasm witness + cubit UTCHMMA Addr/UR component round trip",
            "date": "2026-11-07", "tool": "tools/probes/re_k31_utchmma.py", "test": "tests/k31_utchmma.rs"}
        table["_meta"]["provenance"]["rows_without_src"] = sum(1 for e in table["instructions"].values() for g in e.get("mod_groups", {}).values() if "_src" not in g)
        save_table(path, table)
        print(path, "registered measured structured-address row")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest="command", required=True)
    p = sub.add_parser("probe")
    p.add_argument("--out", type=pathlib.Path, default=FIXTURE)
    a = sub.add_parser("apply")
    a.add_argument("tables", type=pathlib.Path, nargs="+")
    args = ap.parse_args()
    if args.command == "probe":
        probe(args.out)
    else:
        apply(args.tables)


if __name__ == "__main__":
    main()

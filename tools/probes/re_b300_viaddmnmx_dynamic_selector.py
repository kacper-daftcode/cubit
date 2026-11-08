#!/usr/bin/env python3
"""Preserve the measured RELU rows and repair the two plain selector rows."""

import argparse
import collections
import copy
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from nvprobe import load_table, row, save_table

SRC = "hidden-b300-viaddmnmx-dynamic-selector-2026-11-08"
PLAN = {
    "plain": ("VIADDMNMX_R_R_R_UR_P", "hidden-b300-viaddmnmx-relu-closure-2026-11-08"),
    "reversed": ("VIADDMNMX_R_R_UR_R_P", "hidden-b300-viaddmnmx-reversed-ur-2026-11-08"),
}
OTHER_PLAIN_KEYS = (
    "VIADDMNMX_R_R_R_R_P", "VIADDMNMX_R_R_R_II_P", "VIADDMNMX_R_R_II_R_P",
)
NOTE = (
    "nvdisasm 13.3 V13.3.73 SM103/SM100 raw full128 probes over all eight "
    "predicate values and both inversions for both plain UR operand orders. "
    "The trailing predicate is [89:87], inversion is bit90, not opcode bits[11:9]. "
    "Operand fields, plain type and RELU separation are inherited exactly from "
    "their separately measured rows. No execution or min/max semantic claim."
)


def plain_spec(relu):
    assert relu["_src"] in {tag for _key, tag in PLAN.values()}
    assert any(f["extraction"] == "pred" and f["shift"] == 87 and f["bits"] == 3
               for f in relu["fields"])
    fields = copy.deepcopy(relu["fields"])
    for item in fields:
        item["_src"] = SRC
    base = int(relu["and_base"], 16) & ~(1 << 76)
    assert base >> 96 == 0 and (base >> 72) & 3 == 1
    spec = row(base, fields, SRC, NOTE)
    spec["row_probe"] = True
    spec["claim_forbid"] = copy.deepcopy(relu.get("claim_forbid", []))
    block = {"shift": 76, "bits": 1, "values": [1]}
    if block not in spec["claim_forbid"]:
        spec["claim_forbid"].append(block)
    return spec


def build(args):
    data = json.loads(args.probe.read_text())
    fixtures = {}
    specs = {}
    for arch in ("sm103a", "sm100a"):
        specs[arch] = {}
        for family, (key, _tag) in PLAN.items():
            prior = load_table(args.prior_roots[family] / f"{arch}.json")
            specs[arch][key] = plain_spec(prior["instructions"][key]["mod_groups"]["RELU"])
    for target in ("sm103", "sm100"):
        rows = [r for r in data["records"] if r["target"] == target.upper()]
        assert len(rows) == 33
        fixture = []
        for record in rows:
            positive = record["family"] in PLAN
            key = PLAN.get(record["family"], (None, None))[0]
            role = "adopt" if positive else "reject-scoped"
            assert (record["rc"] == 0) == positive
            if positive:
                assert record["text"] and record["text"].startswith("VIADDMNMX ")
            else:
                assert "Illegal instruction" in record["stderr"]
            fixture.append({"word": record["word"], "nvidia_sass": record["text"],
                "role": role, "expected_group": "", "expected_key": key or "",
                "kind": record["label"], "family": record["family"], "rc": record["rc"]})
        path = args.cubit / "tests/fixtures" / f"{target}_viaddmnmx_dynamic_selector_nvdisasm.jsonl"
        with path.open("w") as stream:
            for item in fixture:
                stream.write(json.dumps(item, sort_keys=True) + "\n")
        counts = collections.Counter(r["role"] for r in fixture)
        assert counts == {"adopt": 32, "reject-scoped": 1}
        fixtures[target] = {"unique_words": len(fixture), "roles": dict(counts)}
    result = {"source": SRC, "targets": fixtures, "rows_repaired": 2,
              "prior_sources_preserved": {key: tag for key, tag in PLAN.values()},
              "retained_relu_rows": 5}
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "prepare-summary.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def apply(args):
    for arch, path in {arch: args.isa / f"{arch}.json" for arch in ("sm103a", "sm100a")}.items():
        table = load_table(path)
        provenance = table["_meta"]["provenance"]
        for family, (key, tag) in PLAN.items():
            prior = load_table(args.prior_roots[family] / f"{arch}.json")
            previous = prior["instructions"][key]["mod_groups"]["RELU"]
            entry = table["instructions"][key]
            entry["mod_groups"] = copy.deepcopy(prior["instructions"][key]["mod_groups"])
            if "RELU" not in entry["mod_groups"]:
                provenance["rows_total"] += 1
            if tag not in provenance["sources"]:
                provenance["sources"][tag] = copy.deepcopy(prior["_meta"]["provenance"]["sources"][tag])
            else:
                assert provenance["sources"][tag] == prior["_meta"]["provenance"]["sources"][tag]
            entry["mod_groups"]["RELU"] = copy.deepcopy(previous)
            entry["mod_groups"][""] = plain_spec(previous)
        for key in OTHER_PLAIN_KEYS:
            prior = load_table(args.plain_isa / f"{arch}.json")
            previous = prior["instructions"][key]["mod_groups"]["RELU"]
            entry = table["instructions"][key]
            entry["mod_groups"] = copy.deepcopy(prior["instructions"][key]["mod_groups"])
            if "RELU" not in entry["mod_groups"]:
                provenance["rows_total"] += 1
            tag = PLAN["plain"][1]
            if tag not in provenance["sources"]:
                provenance["sources"][tag] = copy.deepcopy(
                    prior["_meta"]["provenance"]["sources"][tag])
            else:
                assert provenance["sources"][tag] == prior["_meta"]["provenance"]["sources"][tag]
            entry["mod_groups"]["RELU"] = copy.deepcopy(previous)
        fresh = SRC not in provenance["sources"]
        if fresh:
            provenance["sources"][SRC] = {"rows": 2, "date": "2026-11-08",
                "kind": "Controlled dynamic P0-P6/PT selector probes and plain-row selector repair",
                "tool": "tools/probes/re_b300_viaddmnmx_dynamic_selector.py",
                "test": "tests/hidden_b300_viaddmnmx_dynamic_selector.rs"}
        assert provenance["sources"][SRC]["rows"] == 2
        save_table(path, table)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--isa", required=True, type=pathlib.Path)
    parser.add_argument("--cubit", required=True, type=pathlib.Path)
    parser.add_argument("--probe", required=True, type=pathlib.Path)
    parser.add_argument("--plain-isa", required=True, type=pathlib.Path)
    parser.add_argument("--reverse-isa", required=True, type=pathlib.Path)
    parser.add_argument("--out", required=True, type=pathlib.Path)
    parser.add_argument("--fixture-only", action="store_true")
    args = parser.parse_args()
    args.prior_roots = {"plain": args.plain_isa, "reversed": args.reverse_isa}
    result = build(args)
    if not args.fixture_only:
        apply(args)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()

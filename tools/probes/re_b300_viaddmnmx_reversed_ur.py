#!/usr/bin/env python3
"""Adopt only the measured reversed-UR/R plain VIADDMNMX.RELU row."""

import argparse
import collections
import json
import pathlib
import re
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from nvprobe import SCHEDULE, field, field_mask, load_table, row, save_table


SRC = "hidden-b300-viaddmnmx-reversed-ur-2026-11-08"
KEY = "VIADDMNMX_R_R_UR_R_P"
ANCHOR = 0x040FE2000B80110D000000050F1B7C46
NOTE = (
    "Independent nvdisasm 13.3 V13.3.73 SM103/SM100 raw full128 lattice. One bit9 "
    "transition from the separately licensed R,R,R,UR production anchor yields "
    "R,R,UR,R. Complete independent 8-bit operand sweeps, all 16 trailing predicate "
    "encodings and all guard codes. Type[73:72]: 0=U32,1=plain,2=U16x2,3=S16x2; "
    "only plain RELU is adopted. bit63 negates UR, bit122/bit124 are measured reuse; "
    "bit123 rejects and must fail closed. bit62/74/75 are text-inert on this anchor. "
    "Vendor-text and exact encoding evidence only, not execution or RELU arithmetic."
)


def fields():
    result = [
        field(12, 4, "guard", 0, SRC),
        field(16, 8, "reg", 1, SRC), field(24, 8, "reg", 2, SRC),
        field(122, 1, "reuse", 2, SRC),
        field(32, 8, "ureg", 3, SRC), field(63, 1, "neg", 3, SRC),
        field(64, 8, "reg", 4, SRC), field(124, 1, "reuse", 4, SRC),
        field(87, 3, "pred", 5, SRC), field(90, 1, "neg", 5, SRC),
    ]
    field_mask(result)
    return result


def measured_row():
    spec = row(ANCHOR & ~field_mask(fields()) & ~SCHEDULE, fields(), SRC, NOTE)
    spec["row_probe"] = True
    assert (ANCHOR >> 72) & 3 == 1
    assert (ANCHOR >> 76) & 1 == 1
    spec["claim_forbid"] = [
        {"shift": 72, "bits": 2, "values": [0, 2, 3]},
        *[{"shift": bit, "bits": 1, "values": [1]} for bit in (62, 74, 75, 123)],
    ]
    return spec


def matches(spec, word):
    mask = (1 << 96) - 1
    variable = int(spec["variable_mask"], 16)
    if (word & mask & ~variable) != (int(spec["and_base"], 16) & mask & ~variable):
        return False
    return not any(((word >> b["shift"]) & ((1 << b["bits"]) - 1)) in b["values"]
                   for b in spec["claim_forbid"])


def canonical_operand(token):
    return token.strip().rstrip(";").replace(".reuse", "").lstrip("-")


def reversed_uru_shape(text):
    parts = text.split()
    if parts and parts[0].startswith("@"):
        parts = parts[1:]
    if len(parts) != 6 or parts[0] not in ("VIADDMNMX.RELU", "VIADDMNMX"):
        return False
    operands = " ".join(parts[1:]).split(",")
    return len(operands) == 5 and all(re.fullmatch(r"-?R(Z|\d+)(\.reuse)?", canonical_operand(x))
                                    for x in (operands[0], operands[1], operands[3])) and \
        re.fullmatch(r"-?UR(Z|\d+)", canonical_operand(operands[2])) is not None and \
        re.fullmatch(r"!?(PT|P[0-6])", operands[4].strip().rstrip(";")) is not None


def classify(record, spec):
    word = int(record["word"], 16)
    text = record.get("nvidia_sass")
    if record["field"] == "bit123":
        assert record["rc"] != 0
        return "auxiliary-control", ""
    if record["field"] == "bit125":
        return "auxiliary-control", ""
    if record["field"] == "guard@[15:12]":
        # Upper schedule/reuse is fixed; only the independently decoded guard is varied.
        if text and reversed_uru_shape(text) and matches(spec, word):
            return "adopt", KEY
        return "reject-scoped", ""
    if record["field"] == "bit9":
        return "auxiliary-existing", ""
    if record["field"] in ("bit62", "bit74", "bit75", "bit76", "type@[73:72]"):
        if record["field"] == "bit76":
            return "auxiliary-existing", ""
        return "reject-scoped", ""
    if text == "VIADDMNMX.RELU R27, R15.reuse, -UR5, R13, PT" and record["field"] == "bit63":
        return "adopt", KEY
    if text and text.startswith("VIADDMNMX.RELU") and reversed_uru_shape(text) and matches(spec, word):
        return "adopt", KEY
    return "reject-scoped", ""


def build(args):
    spec = measured_row()
    raw = [json.loads(line) for line in args.lattice.read_text().splitlines()]
    summary = {}
    cross_target = {}
    for target, arch in (("SM103", "sm103a"), ("SM100", "sm100a")):
        records = [r for r in raw if r["target"] == target]
        assert len(records) == len(raw) // 2
        fixture = []
        for record in records:
            role, key = classify(record, spec)
            word, text = record["word"], record.get("nvidia_sass")
            if role == "adopt":
                assert record["rc"] == 0 and text and reversed_uru_shape(text), record
                tokens = text.split()
                if tokens[0].startswith("@"):
                    tokens = tokens[1:]
                assert (tokens[0] == "VIADDMNMX.RELU") == (((int(word, 16) >> 76) & 1) == 1)
            if role == "reject-scoped":
                assert record["rc"] != 0 or not matches(spec, int(word, 16)), record
            fixture.append({
                "word": word, "nvidia_sass": text, "kind": record["field"],
                "labels": [record["label"]], "role": role, "expected_key": key,
                "expected_group": "RELU" if role == "adopt" else "", "rc": record["rc"],
            })
            previous = cross_target.setdefault(word, (text, role, key, record["rc"]))
            assert previous == (text, role, key, record["rc"]), word
        path = args.cubit / "tests/fixtures" / f"{target.lower()}_viaddmnmx_reversed_ur_nvdisasm.jsonl"
        with path.open("w") as stream:
            for item in fixture:
                stream.write(json.dumps(item, sort_keys=True) + "\n")
        counts = collections.Counter(item["role"] for item in fixture)
        summary[target] = {"unique_words": len(fixture), "roles": dict(counts)}
    assert summary["SM103"] == summary["SM100"]
    assert summary["SM103"]["roles"]["adopt"] > 1000
    assert summary["SM103"]["roles"]["reject-scoped"] > 5
    result = {"source": SRC, "key": KEY, "targets": summary}
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "prepare-summary.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def apply(tables):
    for arch, path in tables.items():
        table = load_table(path)
        provenance = table["_meta"]["provenance"]
        fresh = SRC not in provenance["sources"]
        assert table["instructions"][KEY]["operand_sig"] == "R_R_UR_R_P"
        table["instructions"][KEY]["mod_groups"]["RELU"] = measured_row()
        for name, group in table["instructions"][KEY]["mod_groups"].items():
            if name == "RELU":
                continue
            block = {"shift": 76, "bits": 1, "values": [1]}
            if block not in group.setdefault("claim_forbid", []):
                group["claim_forbid"].append(block)
        if fresh:
            provenance["rows_total"] += 1
            provenance["sources"][SRC] = {
                "rows": 1, "date": "2026-11-08",
                "kind": "Controlled reversed-UR/R plain VIADDMNMX.RELU raw full128 operand lattice",
                "tool": "tools/probes/re_b300_viaddmnmx_reversed_ur.py",
                "test": "tests/hidden_b300_viaddmnmx_reversed_ur.rs",
            }
        assert provenance["sources"][SRC]["rows"] == 1
        save_table(path, table)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--isa", required=True, type=pathlib.Path)
    parser.add_argument("--cubit", required=True, type=pathlib.Path)
    parser.add_argument("--lattice", required=True, type=pathlib.Path)
    parser.add_argument("--out", required=True, type=pathlib.Path)
    parser.add_argument("--fixture-only", action="store_true")
    args = parser.parse_args()
    result = build(args)
    if not args.fixture_only:
        apply({arch: args.isa / f"{arch}.json" for arch in ("sm103a", "sm100a")})
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()

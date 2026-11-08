#!/usr/bin/env python3
"""Classify and adopt only the measured plain VIADDMNMX.RELU forms."""

import argparse
import collections
import copy
import json
import pathlib
import re
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from nvprobe import SCHEDULE, field_mask, load_table, row, save_table


SRC = "hidden-b300-viaddmnmx-relu-closure-2026-11-08"
NOTE = (
    "H production plus independent nvdisasm 13.3 V13.3.73 SM103/SM100 full-word "
    "lattices. RELU is bit76. Type[73:72] is 0=U32,1=plain,2=U16x2,3=S16x2; "
    "only plain RELU is adopted. Bit74 is a measured text-inert neighbour and stays "
    "outside this narrow row. Fields, including family-specific neg/reuse, are exactly "
    "the declared mask; schedule/control bits are not baked into the row. Vendor-text "
    "and exact encoding evidence only, not execution or arithmetic-clamp semantics."
)
ANCHORS = {
    "VIADDMNMX_R_R_R_II_P": 0x004FCA00078011030000008002087446,
    "VIADDMNMX_R_R_II_R_P": 0x000FE200038011880000000107047846,
    "VIADDMNMX_R_R_R_R_P": 0x000FC600038011050000000C0E157246,
    "VIADDMNMX_R_R_R_UR_P": 0x040FE2000B80110D000000050F1B7E46,
}
OPCODES = {0x246, 0x446, 0x846, 0xC46, 0xE46}


def tokens(text):
    if not text:
        return []
    result = text.split()
    return result[1:] if result[0].startswith("@") else result


def mnemonic(text):
    parts = tokens(text)
    return parts[0] if parts else ""


def operand_kind(token):
    token = token.strip().replace(".reuse", "").replace("-", "").strip("|")
    if token == "RZ" or re.fullmatch(r"R\d+", token):
        return "R"
    if token == "URZ" or re.fullmatch(r"UR\d+", token):
        return "UR"
    return "II"


def shape(text):
    parts = tokens(text)
    if len(parts) != 6:
        return ""
    operands = " ".join(parts[1:]).rstrip(";").split(",")
    if len(operands) != 5:
        return ""
    return f"VIADDMNMX_R_R_{operand_kind(operands[2])}_{operand_kind(operands[3])}_P"


def number(value):
    return int(value, 16) if isinstance(value, str) else int(value)


def measured_fields(template):
    assert "" in template["mod_groups"]
    fields = copy.deepcopy(template["mod_groups"][""]["fields"])
    assert fields
    for field in fields:
        field["_src"] = SRC
    field_mask(fields)
    return fields


def measured_row(template, key):
    fields = measured_fields(template)
    if key == "VIADDMNMX_R_R_R_UR_P":
        # The old harvest row put the trailing predicate at opcode bits 9..11.
        # The full operand-domain lattice measures it at [89:87], with ! at 90;
        # toggling bit9 instead selects the distinct [Ra,URb,Rc] operand order.
        predicates = [field for field in fields if field["extraction"] == "pred"]
        assert len(predicates) == 1 and predicates[0]["shift"] == 9
        predicates[0]["shift"] = 87
    base = ANCHORS[key] & ~field_mask(fields) & ~SCHEDULE
    assert base & (3 << 72) == 1 << 72
    assert base & (1 << 74) == 0
    assert base & (1 << 76)
    result = row(base, fields, SRC, NOTE)
    result["row_probe"] = True
    result["claim_forbid"] = [
        {"shift": 72, "bits": 2, "values": [0, 2, 3]},
    ]
    # The generic decoder has a sign-tolerant fallback over 62/63 and 72..75.
    # Anything there that is not an explicitly measured field must be excluded
    # on every match priority; otherwise an inert neighbour renders as plain RELU.
    for bit in (62, 63, 74, 75):
        bit_mask = 1 << bit
        if not field_mask(fields) & bit_mask:
            assert not base & bit_mask, (key, bit)
            result["claim_forbid"].append({"shift": bit, "bits": 1, "values": [1]})
    return result


def matches(row_spec, word):
    mask = (1 << 96) - 1
    variable = number(row_spec["variable_mask"])
    return (word & mask & ~variable) == (number(row_spec["and_base"]) & mask & ~variable)


def classify(record, rows):
    text = record.get("nvidia_sass")
    word = int(record["word"], 16)
    op = mnemonic(text)
    key = shape(text) if text else ""
    control_neighbour = record.get("kind") == "control-bit" or any(
            label.startswith("schedule:") for label in record.get("labels", []))
    control_neighbour |= any(
        label.startswith("bit=") and label.split("=", 1)[1].isdigit()
        and int(label.split("=", 1)[1]) >= 96
        for label in record.get("labels", []))
    if control_neighbour:
        return "auxiliary-control", ""
    if key in ANCHORS and op == "VIADDMNMX.RELU" and matches(rows[key], word):
        return "adopt", key
    if word & 0xFFF not in OPCODES:
        return "auxiliary-other-opcode", ""
    if not text or record.get("rc") or "INVALID" in text or "???" in text:
        return "reject-scoped", ""
    if op == "VIADDMNMX.RELU" or op.startswith("VIADDMNMX.") and "RELU" in op:
        return "reject-scoped", ""
    return "auxiliary-existing", ""


def read_jsonl(path):
    return [json.loads(line) for line in path.read_text().splitlines()]


def build_fixtures(tables, main_lattice, closure_lattice, cubit, out):
    row_specs = {}
    template = load_table(tables["sm103a"])
    for key in ANCHORS:
        row_specs[key] = measured_row(template["instructions"][key], key)
    summaries = {}
    merged = {}
    for target, arch in (("sm103", "sm103a"), ("sm100", "sm100a")):
        main_records = read_jsonl(main_lattice / f"{target}.jsonl")
        replay_records = [r for r in read_jsonl(closure_lattice / "results.jsonl")
                          if r["target"] == target.upper()]
        records = [(r, "main") for r in main_records]
        records.extend((r, "closure") for r in replay_records)
        fixture = {}
        for record, evidence in records:
            role, key = classify(record, row_specs)
            item = {
                "word": record["word"], "nvidia_sass": record.get("nvidia_sass"),
                "kind": record.get("kind", "closure"),
                "labels": record.get("labels", [record.get("label", "closure")]),
                "role": role, "expected_key": key,
                "expected_group": "RELU" if role == "adopt" else "",
                "rc": record["rc"],
                "evidence": evidence,
            }
            previous = fixture.get(record["word"])
            if previous is not None:
                for name in ("nvidia_sass", "role", "expected_key", "expected_group", "rc"):
                    assert previous[name] == item[name], (previous, item)
                previous["labels"] = list(dict.fromkeys(previous["labels"] + item["labels"]))
                if item["kind"] == "production":
                    previous["kind"] = "production"
                continue
            fixture[record["word"]] = item
        ordered = sorted(fixture.values(), key=lambda r: (
            r["role"] != "adopt", r["kind"] != "production", r["word"]))
        path = cubit / "tests/fixtures" / f"{target}_viaddmnmx_relu_nvdisasm.jsonl"
        with path.open("w") as stream:
            for item in ordered:
                stream.write(json.dumps(item, sort_keys=True) + "\n")
        counts = collections.Counter(item["role"] for item in ordered)
        by_key = collections.Counter(item["expected_key"] for item in ordered if item["role"] == "adopt")
        assert by_key.keys() == ANCHORS.keys(), by_key
        production = [item for item in ordered if item["kind"] == "production"]
        assert len(production) >= 442
        assert all(item["role"] == "adopt" for item in production)
        assert any(item["role"] == "reject-scoped" and item["nvidia_sass"]
                   and item["nvidia_sass"].startswith("VIADDMNMX.U32.RELU") for item in ordered)
        summaries[target] = {"unique_words": len(ordered), "roles": dict(counts),
                             "adopt_by_key": dict(by_key), "production": len(production)}
        merged[target] = {item["word"]: item for item in ordered}
    for word, left in merged["sm103"].items():
        right = merged["sm100"][word]
        assert all(left[k] == right[k] for k in
                   ("nvidia_sass", "role", "expected_key", "expected_group", "rc")), word
    production = read_jsonl(main_lattice / "production.jsonl")
    assert len(production) == 451
    assert sum(len(row["sources"]) for row in production) == 461
    for source in production:
        item = merged[source["target"].lower()][source["word"]]
        assert item["role"] == "adopt", source
    result = {"source": SRC, "targets": summaries,
              "production_word_target_pairs": len(production),
              "production_source_observations": sum(len(row["sources"]) for row in production),
              "typed_and_inert_scope": "reject-scoped"}
    out.mkdir(parents=True, exist_ok=True)
    (out / "prepare-summary.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def apply(tables):
    for arch, path in tables.items():
        table = load_table(path)
        provenance = table["_meta"]["provenance"]
        fresh = SRC not in provenance["sources"]
        for key in ANCHORS:
            entry = table["instructions"][key]
            new = measured_row(entry, key)
            if "RELU" in entry["mod_groups"]:
                assert entry["mod_groups"]["RELU"]["_src"] == SRC
            entry["mod_groups"]["RELU"] = new
        for entry in table["instructions"].values():
            if entry.get("base_op") != "VIADDMNMX":
                continue
            for name, group in entry.get("mod_groups", {}).items():
                if name == "RELU" and group.get("_src") == SRC:
                    continue
                block = {"shift": 76, "bits": 1, "values": [1]}
                groups = group.setdefault("claim_forbid", [])
                if block not in groups:
                    groups.append(block)
        if fresh:
            provenance["rows_total"] += len(ANCHORS)
            provenance["sources"][SRC] = {
                "rows": len(ANCHORS), "date": "2026-11-08",
                "kind": "H production plus controlled plain VIADDMNMX.RELU raw full128 lattice",
                "tool": "tools/probes/re_b300_viaddmnmx_relu.py",
                "test": "tests/hidden_b300_viaddmnmx_relu.rs",
            }
        assert provenance["sources"][SRC]["rows"] == len(ANCHORS)
        save_table(path, table)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--isa", type=pathlib.Path, required=True)
    parser.add_argument("--cubit", type=pathlib.Path, required=True)
    parser.add_argument("--main-lattice", type=pathlib.Path, required=True)
    parser.add_argument("--closure-lattice", type=pathlib.Path, required=True)
    parser.add_argument("--out", type=pathlib.Path, required=True)
    parser.add_argument("--fixture-only", action="store_true")
    args = parser.parse_args()
    tables = {arch: args.isa / f"{arch}.json" for arch in ("sm103a", "sm100a")}
    result = build_fixtures(tables, args.main_lattice, args.closure_lattice,
                            args.cubit, args.out)
    if not args.fixture_only:
        apply(tables)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()

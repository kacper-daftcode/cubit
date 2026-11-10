#!/usr/bin/env python3
"""Build the QMUL4 fixture from the independently rerun SM103 raw lattice."""

import argparse
import copy
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from nvprobe import SCHEDULE, field, field_mask, load_table, row, save_table


BASE = "QMUL4.E4M3x4.E2M1x4.E4M3x4"
SRC = "hidden-b300-qmul4-sm103-sm100-2026-11-07"
KEY = BASE + "_R_R_R"
SAT_KEY = BASE + ".SATFINITE_R_R_R"
ANCHOR = 0x081FE4000501B800200000040B16727C
FIELD_SPECS = [
    (12, 4, "guard", 0), (16, 8, "reg", 1),
    (24, 8, "reg", 2), (73, 1, "neg", 2), (72, 1, "abs", 2),
    (122, 1, "reuse", 2), (74, 3, "qmul4_sel", 2),
    (32, 8, "reg", 3), (63, 1, "neg", 3), (62, 1, "abs", 3),
    (123, 1, "reuse", 3), (59, 3, "qmul4_sel", 3),
]
KNOWN_VARIABLE = 0xfff | SCHEDULE | (1 << 90) | field_mask([
    field(shift, bits, extraction, token, SRC)
    for shift, bits, extraction, token in FIELD_SPECS
])
FIXED_BASE = ANCHOR & ~KNOWN_VARIABLE


def basis(text):
    if not text:
        return None
    parts = text.split(None, 1)
    if parts[0].startswith("@"):
        parts = parts[1].split(None, 1)
    return parts[0]


def build(raw, output):
    records = [json.loads(line) for line in raw.read_text().splitlines()]
    fixture = []
    for record in records:
        op = basis(record["nvidia_sass"])
        word = int(record["word"], 16)
        schedule_inert = any(label.startswith("schedule:bit=")
                             and int(label.split("=", 1)[1]) >= 125
                             for label in record.get("labels", []))
        aux = record["kind"] == "single-bit" and record["bit"] >= 96
        aux |= any(label.startswith("schedule:bit=")
                   and int(label.split("=", 1)[1]) >= 120
                   and int(label.split("=", 1)[1]) not in (122, 123)
                   for label in record.get("labels", []))
        adopt = op in (BASE, BASE + ".SATFINITE") and not aux \
            and word & ~KNOWN_VARIABLE == FIXED_BASE
        assert not adopt or (record["rc"] == 0 and op in (BASE, BASE + ".SATFINITE"))
        source = record["source"]
        if isinstance(source, list):
            source = " | ".join(dict.fromkeys(source))
        fixture.append({
            "word": record["word"],
            "nvidia_sass": record["nvidia_sass"],
            "arch": "SM103",
            "adopt": adopt,
            "schedule_inert": schedule_inert and not adopt and op in (BASE, BASE + ".SATFINITE"),
            "auxiliary_control_probe": aux,
            "kind": record["kind"],
            "rc": record["rc"],
            "stderr": record["stderr"],
            "source": source,
            "labels": record.get("labels", []),
            "evidence": "nvdisasm 13.3 rerun, complete stdout/stderr in pubwave/hidden-b300/qmul4/lattice",
        })
    # The enum crosses deliberately revisit anchors. Keep the first (production)
    # record and prove every revisit has exactly the same vendor verdict.
    unique = {}
    for record in fixture:
        previous = unique.get(record["word"])
        if previous is None:
            unique[record["word"]] = record
            continue
        assert {k: previous[k] for k in ("nvidia_sass", "adopt", "rc", "stderr")} == \
            {k: record[k] for k in ("nvidia_sass", "adopt", "rc", "stderr")}, \
            (previous, record)
    duplicates = len(fixture) - len(unique)
    fixture = list(unique.values())
    # A production witness fails first, before the broader lattice tests.
    fixture.sort(key=lambda r: (not r["adopt"], r["word"], str(r["source"])))
    with output.open("w") as fh:
        for record in fixture:
            fh.write(json.dumps(record) + "\n")
    print(json.dumps({
        "records": len(fixture),
        "adopt": sum(r["adopt"] for r in fixture),
        "rejected_or_unclaimed": sum(not r["adopt"] for r in fixture),
        "schedule_inert_not_semantic_roundtrip": sum(r["schedule_inert"] for r in fixture),
        "auxiliary_control_probes": sum(r["auxiliary_control_probe"] for r in fixture),
        "duplicates_merged": duplicates,
        "production_anchors": sum(
            r["adopt"] and r["kind"].startswith("anchor-")
            and r["kind"].endswith("raw-control") for r in fixture
        ),
    }))


def apply(tables):
    fields = [field(shift, bits, extraction, token, SRC)
              for shift, bits, extraction, token in FIELD_SPECS]
    base = (ANCHOR & ~field_mask(fields) & ~SCHEDULE & ~0xfff) | 0x27c
    groups = {
        "": row(base & ~(1 << 90), fields, SRC,
            "QMUL4 production form: full selector and field map measured on SM103 and SM100."),
        "SATFINITE": row(base, fields, SRC,
            "SATFINITE is bit 90; neighbour type codes and QADD4 are deliberately not claimed."),
    }
    entry = {
        "base_op": BASE,
        "ctrl_class": "alu_simple",
        "operand_sig": "R_R_R",
        "mod_groups": groups,
        "_src": SRC,
        "_semantic_re": "pubwave/hidden-b300/qmul4/lattice; vendor text, not silicon semantics",
        # Conservative placeholder only. No latency claim was measured in this window.
        "scheduling": {"def_latency": 4, "is_variable_latency": False,
                        "pipe_class": 0, "pipe_name": "UNKNOWN", "throughput": 1},
    }
    for path in tables:
        table = load_table(path)
        for key in [KEY, SAT_KEY]:
            previous = table["instructions"].pop(key, None)
            assert previous is None or previous["_src"] == SRC
        assert not any(key.startswith("QMUL4") for key in table["instructions"])
        sat_entry = copy.deepcopy(entry)
        sat_entry["base_op"] = BASE + ".SATFINITE"
        sat_entry["mod_groups"] = {"": copy.deepcopy(groups["SATFINITE"])}
        sat_entry["encode_only"] = True
        table["instructions"][KEY] = copy.deepcopy(entry)
        table["instructions"][SAT_KEY] = sat_entry
        provenance = table["_meta"]["provenance"]
        provenance["sources"][SRC] = {
            "rows": 2,
            "kind": "production vendor-text witnesses plus raw field/selector/type lattice",
            "date": "2026-11-07",
            "tool": "tools/probes/probe_sm103_qmul4.py + tools/probes/re_sm103_qmul4.py",
            "test": "tests/hidden_b300_qmul4.rs",
        }
        provenance["rows_total"] = sum(len(e.get("mod_groups", {}))
                                        for e in table["instructions"].values())
        provenance["rows_without_src"] = sum(1 for e in table["instructions"].values()
            for group in e.get("mod_groups", {}).values() if "_src" not in group)
        save_table(path, table)
        print(path, KEY, "installed with two measured groups")


def main():
    parser = argparse.ArgumentParser()
    command = parser.add_subparsers(dest="command", required=True)
    fixture = command.add_parser("fixture")
    fixture.add_argument("raw", type=pathlib.Path)
    fixture.add_argument("output", type=pathlib.Path)
    apply_parser = command.add_parser("apply")
    apply_parser.add_argument("tables", nargs="+", type=pathlib.Path)
    args = parser.parse_args()
    build(args.raw, args.output) if args.command == "fixture" else apply(args.tables)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Build and apply the measured scaled F2FP UNPACK_B rows on SM103a/SM100a."""

import argparse
import copy
import json
import pathlib
import re
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from nvprobe import SCHEDULE, field, field_mask, load_table, row, save_table


SRC = "f2fp-unpackb-mxfp6-mxfp8-silicon-2026-11-07"
TYPES = ["E2M1", "E2M3", "E3M2", "E4M3", "E5M2"]
FORM = re.compile(r"(?:@!?P[0-6T] )?(F2FP(?:\.[A-Z0-9_]+)+) (.+)")
SELECTOR = re.compile(r"R(?:Z|[0-9]+)\.(H0|H1|B0|B1|B2|B3)$")
SHARED_FIELDS = [
    (12, 4, "guard", 0),
    (16, 8, "reg", 1),
    (32, 8, "reg", 2),
    (123, 1, "reuse", 2),
    (64, 8, "reg", 3),
    (24, 3, "f2fp_scale_sel", 3),
    (124, 1, "reuse", 3),
]
E2M1_FIELDS = [(72, 1, "f2fp_ra_b1", 2), (88, 1, "f2fp_ra_b2", 2)]
WIDE_FIELDS = [(88, 1, "opmod:H1", 2)]
ANCHORS = [
    0x03FFCA000204120500000002020B763E,
    0x03FFCA000204140500000002020B763E,
    0x03FFCA000204160500000002020B763E,
    0x03FFCA000200160500000002020B763E,
    0x03FFCA000200140500000002020B763E,
]


def decode_name(text):
    match = FORM.fullmatch(text or "")
    if not match:
        return None
    pieces = match.group(1).split(".")
    if len(pieces) < 4 or pieces[-1] != "UNPACK_B" or pieces[-3] != "BF16":
        return None
    mods, typ = pieces[1:-3], pieces[-2]
    if typ not in TYPES or any(mod not in {"RELU", "SATFINITE"} for mod in mods):
        return None
    return typ, tuple(sorted(mods)), match.group(2)


def group_name(typ, mods):
    return ",".join(["BF16", typ, *mods, "UNPACK_B"])


def build(raw, output):
    fixture = []
    named_s26 = 0
    for line in raw.read_text().splitlines():
        record = json.loads(line)
        text = record["nvidia_sass"]
        named_s26 += ".S2_6." in (text or "")
        name = decode_name(text)
        word = int(record["word"], 16)
        adopt = False
        if name is not None and record["rc"] == 0:
            typ, mods, operands = name
            parts = operands.split(", ")
            source_pattern = (r"R(?:Z|[0-9]+)(\.B1|\.B2|\.B3)?" if typ == "E2M1"
                              else r"R(?:Z|[0-9]+)(\.H1)?")
            adopt = (
                len(parts) == 3
                and SELECTOR.fullmatch(parts[2]) is not None
                and re.fullmatch(r"R(?:Z|[0-9]+)", parts[0]) is not None
                and re.fullmatch(source_pattern, parts[1]) is not None
            )
            # Recompute against the group's measured type/modifier row; never
            # let a coincidental type-envelope encoding open its bit budget.
            base_row = row_for(typ, mods)
            mask = 0xFFFF | int(base_row["variable_mask"], 16) | SCHEDULE
            adopt = adopt and (word & 0xFFF == 0x63E
                               and word & ~mask == int(base_row["and_base"], 16) & ~mask)
        auxiliary = record["kind"] == "single-bit" and any(
            label.startswith("bit=") and int(label.split("=")[1]) >= 96
            for label in record["labels"]
        )
        adopt &= not auxiliary
        source = record["source"]
        if isinstance(source, list):
            source = " | ".join(dict.fromkeys(source))
        fixture.append({
            "word": record["word"], "nvidia_sass": text, "arch": "SM103",
            "adopt": adopt, "auxiliary_control_probe": auxiliary,
            "kind": record["kind"], "rc": record["rc"], "stderr": record["stderr"],
            "source": source, "labels": record["labels"],
            "evidence": "pubwave/hidden-b300/f2fp-unpackb/lattice; H silicon semantics retained separately",
        })
    unique = {}
    for record in fixture:
        old = unique.get(record["word"])
        if old is not None:
            assert old["adopt"] == record["adopt"] and old["nvidia_sass"] == record["nvidia_sass"]
        else:
            unique[record["word"]] = record
    fixture = sorted(unique.values(), key=lambda r: (not r["adopt"], r["word"]))
    with output.open("w") as fh:
        for record in fixture:
            fh.write(json.dumps(record) + "\n")
    print(json.dumps({
        "records": len(fixture), "adopt": sum(r["adopt"] for r in fixture),
        "unclaimed": sum(not r["adopt"] for r in fixture),
        "auxiliary": sum(r["auxiliary_control_probe"] for r in fixture),
        "named_s26_unclaimed": named_s26,
        "anchors_adopted": [r["word"] for r in fixture if int(r["word"], 16) in ANCHORS and r["adopt"]],
    }, indent=2))


def row_for(typ, mods):
    anchor = ANCHORS[list(TYPES).index(typ)]
    word = anchor
    word = (word | (1 << 75) | (1 << 77)) & ~(1 << 72) & ~(1 << 88)
    if "RELU" not in mods:
        word &= ~(1 << 75)
    if "SATFINITE" not in mods:
        word &= ~(1 << 77)
    fields = [field(*spec, SRC) for spec in
              [*SHARED_FIELDS, *(E2M1_FIELDS if typ == "E2M1" else WIDE_FIELDS)]]
    base = (word & ~(0xFFF | field_mask(fields)) & ~SCHEDULE & ~0xFFF) | 0x63E
    return row(base, fields, SRC,
        "0x63e scaled UNPACK_B: vendor text plus H B300 bit-exact E8M0 dequant semantics. "
        "Full types and source selectors measured SM103/SM100; selector INVALID6/7 and every "
        "other type/destination are unclaimed.")


def apply(tables):
    groups = {group_name(typ, mods): row_for(typ, mods)
              for typ in sorted(TYPES)
              for mods in ((), ("RELU",), ("SATFINITE",), ("RELU", "SATFINITE"))}
    for group in groups.values():
        group["claim_forbid"] = [{"shift": 24, "bits": 3, "values": [6, 7]}]
    for path in tables:
        table = load_table(path)
        entry = copy.deepcopy(table["instructions"]["F2FP_R_R_R"])
        current = entry["mod_groups"]
        # Re-applying this experiment may replace its own rows (e.g. after a
        # canonical modifier-order correction), never an unrelated donor.
        for name in list(current):
            if "UNPACK_B" in name and current[name].get("_src") == SRC:
                del current[name]
        for name in groups:
            if name in current:
                assert current[name].get("_src") == SRC, (path, name)
        current.update(groups)
        assert len(current) == len(groups) + 3
        table["instructions"]["F2FP_R_R_R"] = entry
        provenance = table["_meta"]["provenance"]
        if SRC not in provenance["sources"]:
            provenance["sources"][SRC] = {
                "rows": len(groups), "kind": "SM103/SM100 raw text and H B300 silicon semantics",
                "date": "2026-11-07",
                "tool": "tools/probes/probe_sm103_f2fp_unpackb.py + re_sm103_f2fp_unpackb.py",
                "test": "tests/hidden_b300_f2fp_unpackb.rs",
            }
        provenance["rows_total"] = sum(len(e.get("mod_groups", {}))
                                       for e in table["instructions"].values())
        provenance["rows_without_src"] = sum(1 for e in table["instructions"].values()
            for group in e.get("mod_groups", {}).values() if "_src" not in group)
        save_table(path, table)
        print(path, "added", len(groups), "measured groups to F2FP_R_R_R")


def main():
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    fixture = commands.add_parser("fixture")
    fixture.add_argument("raw", type=pathlib.Path)
    fixture.add_argument("output", type=pathlib.Path)
    apply_parser = commands.add_parser("apply")
    apply_parser.add_argument("tables", nargs="+", type=pathlib.Path)
    args = parser.parse_args()
    if args.command == "fixture":
        build(args.raw, args.output)
    else:
        apply(args.tables)


if __name__ == "__main__":
    main()

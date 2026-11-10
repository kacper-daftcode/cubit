#!/usr/bin/env python3
"""Generate and apply only the measured E3M2 PACK_AB_MERGE_C rows."""

import argparse
import copy
import json
import pathlib
import re
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from nvprobe import SCHEDULE, field, field_mask, load_table, row, save_table


SRC = "hidden-b300-f2fp-e3m2-pack-merge-2026-11-08"
KEY = "F2FP_R_R_R_R"
ANCHOR = 0x000FE2000460700A000000080908723E
FORM = re.compile(r"^(?:@!?P[0-6] |@!PT )?"
    r"F2FP\.SATFINITE\.(?:RELU\.)?E3M2\.F32\.PACK_AB_MERGE_C(?:\.RS)? ")
FIELDS = [(12, 4, "guard", 0), (16, 8, "reg", 1),
    (24, 8, "reg", 2), (122, 1, "reuse", 2),
    (32, 8, "reg", 3), (123, 1, "reuse", 3),
    (64, 8, "reg", 4), (124, 1, "reuse", 4)]
KNOWN_VARIABLE = (SCHEDULE | 0xfff | (1 << 75) | (1 << 81)
                  | sum(((1 << bits) - 1) << shift for shift, bits, _, _ in FIELDS))


def generate(raw, output):
    records = list(map(json.loads, raw.read_text().splitlines()))
    fixture = []
    for record in records:
        word = int(record["word"], 16)
        text = record["nvidia_sass"]
        aux = (record["kind"] == "single-bit" and record["labels"][0].startswith("bit=")
               and 96 <= int(record["labels"][0][4:]) not in (122, 123, 124))
        adopt = (bool(FORM.match(text or "")) and not aux
                 and word & ~KNOWN_VARIABLE == ANCHOR & ~KNOWN_VARIABLE)
        assert not adopt or record["rc"] == 0
        source = record["source"]
        if isinstance(source, list):
            source = " | ".join(dict.fromkeys(source))
        fixture.append({"word": record["word"], "nvidia_sass": text,
            "arch": "SM103", "adopt": adopt, "auxiliary_control_probe": aux,
            "kind": record["kind"], "rc": record["rc"], "stderr": record["stderr"],
            "source": source, "labels": record["labels"],
            "evidence": "independent SM103/SM100 raw-word nvdisasm 13.3.73 lattice"})
    counts = {"adopt": sum(r["adopt"] for r in fixture),
        "negative": sum(not r["adopt"] and not r["auxiliary_control_probe"] for r in fixture),
        "auxiliary_control": sum(r["auxiliary_control_probe"] for r in fixture)}
    counts["records"] = len(fixture)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w") as fh:
        for record in fixture:
            fh.write(json.dumps(record) + "\n")
    print(json.dumps(counts))


def apply_rows(tables):
    for path in tables:
        table = load_table(path)
        entry = copy.deepcopy(table["instructions"][KEY])
        existing = {name: group for name, group in entry.get("mod_groups", {}).items()
                    if group.get("_src") != SRC}
        fields = [field(shift, bits, extraction, token, SRC)
                  for shift, bits, extraction, token in FIELDS]
        mask = field_mask(fields)
        base = (ANCHOR & ~mask & ~SCHEDULE & ~0xfff & ~(1 << 75) & ~(1 << 81)) | 0x23e
        new_groups = {}
        for relu in (False, True):
            for rs in (False, True):
                mods = ["SATFINITE"] + (["RELU"] if relu else [])
                mods += ["E3M2", "F32", "PACK_AB_MERGE_C"] + (["RS"] if rs else [])
                name = ",".join(mods)
                group = row(base | ((1 << 75) if relu else 0) | ((1 << 81) if rs else 0),
                    copy.deepcopy(fields), SRC,
                    "E3M2 reached by production-E2M1 type bit 86; RELU bit 75, RS bit 81 and "
                    "all three reuse fields independently measured on both SM103 and SM100. "
                    "Only these four groups are claimed; E2M1/S2_6/text-inert and refused "
                    "neighbours stay unclaimed.")
                group["variable_mask"] = f"0x{mask | SCHEDULE:032x}"
                new_groups[name] = group
                compatibility = copy.deepcopy(group)
                compatibility["encode_only"] = True
                compatibility_name = ",".join(["E3M2", "F32", "PACK_AB_MERGE_C"]
                    + (["RELU"] if relu else []) + (["RS"] if rs else []) + ["SATFINITE"])
                new_groups[compatibility_name] = compatibility
        entry["mod_groups"] = {**existing, **new_groups}
        assert len(entry["mod_groups"]) == len(existing) + 8
        table["instructions"][KEY] = entry
        provenance = table["_meta"]["provenance"]
        provenance["sources"][SRC] = {
            "rows": 8, "kind": "controlled E3M2 type-differential text and raw-word field lattice",
            "date": "2026-11-08",
            "tool": "tools/probes/probe_hidden_b300_f2fp_e3m2_merge.py + tools/probes/re_hidden_b300_f2fp_e3m2_merge.py",
            "test": "tests/hidden_b300_f2fp_e3m2_merge.rs"}
        provenance["rows_total"] = sum(len(e.get("mod_groups", {}))
                                        for e in table["instructions"].values())
        provenance["rows_without_src"] = sum(1 for e in table["instructions"].values()
            for group in e.get("mod_groups", {}).values() if "_src" not in group)
        save_table(path, table)
        print(path, "+4 E3M2 groups and +4 encode-only key equivalents in", KEY)


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="command", required=True)
    command = sub.add_parser("fixture")
    command.add_argument("raw", type=pathlib.Path)
    command.add_argument("output", type=pathlib.Path)
    command = sub.add_parser("apply")
    command.add_argument("tables", nargs="+", type=pathlib.Path)
    args = ap.parse_args()
    if args.command == "fixture":
        generate(args.raw, args.output)
    else:
        apply_rows(args.tables)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Build a measured MOVM fixture or graft its six verified SM120 donor rows."""

import argparse
import copy
import json
import pathlib
import re
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from nvprobe import SCHEDULE, load_table, save_table


SRC = "hidden-b300-movm-2026-11-07"
LANES = {"16.MT88": 0, "U4TO8.MT88": 1, "16.M832": 8,
         "U4TO8.M832": 9, "16.M864": 16, "U4TO8.M864": 17}
VARIABLE_MASK = 0xF7FF07FFFFFFFFFFFFFFF000
FORM = re.compile(r"(?:@!?P[0-6T] )?MOVM\.([A-Za-z0-9_.]+) (R(?:Z|[0-9]+)), (R(?:Z|[0-9]+)(?:\.reuse)?)")


def decode_name(text):
    match = FORM.fullmatch(text or "")
    if not match or match.group(1) not in LANES:
        return None
    return LANES[match.group(1)]


def base_for(ns):
    return 0x23A | (ns << 75)


def build(raw, output):
    fixture = []
    for line in raw.read_text().splitlines():
        record = json.loads(line)
        word = int(record["word"], 16)
        ns = decode_name(record["nvidia_sass"]) if record["rc"] == 0 else None
        adopt = ns is not None and (word & 0xFFF) == 0x23A
        if ns is not None:
            mask = 0xFFF | VARIABLE_MASK | SCHEDULE
            adopt &= (word & ~mask) == (base_for(ns) & ~mask)
            adopt &= not (word & (1 << 91))
        bits = [int(x.split("bit=")[1].split(",")[0]) for x in record["labels"] if "bit=" in x]
        auxiliary = (record["kind"] == "control-reuse"
                     or (word & 0xFFF) != 0x23A
                     or any(bit >= 96 for bit in bits))
        adopt = bool(adopt and not auxiliary)
        source = record["source"]
        canonical = (base_for(ns) | (word & (0xF000 | (0xFF << 16) | (0xFF << 24)))
                     | (word & (~((1 << 96) - 1) & ((1 << 128) - 1)))) if ns is not None else None
        fixture.append({
            "word": record["word"], "nvidia_sass": record["nvidia_sass"], "arch": "SM103",
            "adopt": adopt, "auxiliary_control_probe": auxiliary,
            "encode_exact": bool(adopt and canonical == word),
            "kind": record["kind"], "rc": record["rc"], "stderr": record["stderr"],
            "source": " | ".join(source), "labels": record["labels"],
            "evidence": "pubwave/hidden-b300/movm/lattice; vendor text only"})
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
    by_lane = {name: 0 for name in LANES}
    for record in fixture:
        if record["adopt"]:
            match = FORM.fullmatch(record["nvidia_sass"])
            by_lane[match.group(1)] += 1
    print(json.dumps({"records": len(fixture), "adopt": sum(r["adopt"] for r in fixture),
        "unclaimed": sum(not r["adopt"] and not r["auxiliary_control_probe"] for r in fixture),
        "auxiliary": sum(r["auxiliary_control_probe"] for r in fixture),
        "encode_exact": sum(r["encode_exact"] for r in fixture),
        "adopted_by_lane": by_lane,
        "h_anchors_adopted": [r["word"] for r in fixture if r["adopt"]
            and any(x.startswith("H-") for x in r["labels"])]}, indent=2))


def apply(donor_path, tables):
    donor = load_table(donor_path)
    entries = {}
    for name in LANES:
        key = f"MOVM.{name}_R_R"
        assert key not in entries
        entry = copy.deepcopy(donor["instructions"][key])
        old = entry["mod_groups"][""]
        group = {k: copy.deepcopy(old[k]) for k in ("and_base", "count", "fields", "variable_mask")
                 if k in old}
        assert int(group["variable_mask"], 16) == VARIABLE_MASK
        assert int(group["and_base"], 16) == base_for(LANES[name])
        group["_src"] = SRC
        group["_note"] = ("Six SM103/SM100 MOVM namespace lanes measured from full 128-bit words. "
            "Only guard/Rd/Ra are operand fields. The measured text-inert low-bit envelope and "
            "schedule/reuse split match the SM120 donor; invalid and unnamed namespaces stay unclaimed.")
        for field in group["fields"]:
            field["_src"] = SRC
        entry["mod_groups"] = {"": group}
        entries[key] = entry
    for path in tables:
        table = load_table(path)
        existing = {k for k in table["instructions"] if k.startswith("MOVM")}
        assert not existing or existing == set(entries), (path, existing)
        if existing:
            assert all(table["instructions"][key] == entry for key, entry in entries.items()), path
        table["instructions"].update(copy.deepcopy(entries))
        provenance = table["_meta"]["provenance"]
        if SRC not in provenance["sources"]:
            provenance["sources"][SRC] = {
                "rows": len(entries), "kind": "SM103/SM100 raw nvdisasm text; measured SM120 donor graft",
                "date": "2026-11-07", "tool": "pubwave/hidden-b300/tools/probe_movm.py + tools/probes/re_sm103_movm.py",
                "test": "tests/hidden_b300_movm.rs"}
        provenance["rows_total"] = sum(len(e.get("mod_groups", {})) for e in table["instructions"].values())
        provenance["rows_without_src"] = sum(1 for e in table["instructions"].values()
            for group in e.get("mod_groups", {}).values() if "_src" not in group)
        save_table(path, table)
        print(path, "added", len(entries), "measured MOVM rows")


def main():
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    fixture = commands.add_parser("fixture")
    fixture.add_argument("raw", type=pathlib.Path)
    fixture.add_argument("output", type=pathlib.Path)
    apply_parser = commands.add_parser("apply")
    apply_parser.add_argument("donor", type=pathlib.Path)
    apply_parser.add_argument("tables", nargs="+", type=pathlib.Path)
    args = parser.parse_args()
    if args.command == "fixture":
        build(args.raw, args.output)
    else:
        apply(args.donor, args.tables)


if __name__ == "__main__":
    main()

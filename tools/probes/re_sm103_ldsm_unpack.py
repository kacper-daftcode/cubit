#!/usr/bin/env python3
"""Build and apply the measured SM103/SM100 compressed-matrix LDSM rows."""

import argparse
import copy
import json
import pathlib
import re
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from nvprobe import SCHEDULE, field, field_mask, load_table, save_table

SRC = "hidden-b300-ldsm-unpack-2026-11-07"
PAIRS = [(shape, addr) for shape in ("U4x16P64TO8.M816.2", "U4x16P64TO8.MT1616")
         for addr in ("ARI", "AURI", "ARURI")]
PAIRS += [(shape, "AURI") for shape in ("U6x16P32TO8.M816.2", "U6x16P32TO8.MT1616")]
KEYS = {"ARI": "LDSM_R_ARI", "AURI": "LDSM_R_AURI", "ARURI": "LDSM_R_ARURI"}
GROUPS = {"U4x16P64TO8.M816.2": "2,M816,U4x16P64TO8",
          "U4x16P64TO8.MT1616": "MT1616,U4x16P64TO8",
          "U6x16P32TO8.M816.2": "2,M816,U6x16P32TO8",
          "U6x16P32TO8.MT1616": "MT1616,U6x16P32TO8"}
FORM = re.compile(r"(?:@!?P[0-6T] )?LDSM\.(U[46]x16P(?:32|64)TO8\.[A-Za-z0-9.]+) "
                  r"(R(?:Z|[0-9]+)), \[([^]]+)\]")
ADDRESS = {
    "ARI": re.compile(r"R(?:Z|[0-9]+)(?:\+-?0x[0-9a-f]+)?"),
    "AURI": re.compile(r"UR[0-9]+(?:\+-?0x[0-9a-f]+)?"),
    "ARURI": re.compile(r"R(?:Z|[0-9]+)\+UR[0-9]+(?:\+-?0x[0-9a-f]+)?"),
}
NOTE = ("SM103/SM100 full-word nvdisasm lattice. Compressed-matrix LDSM type/shape byte and "
        "three measured addressing classes only. Guard, destination, R/UR and immediate fields "
        "are independent arithmetic operands, not matrix-layout semantics. Opcode siblings, "
        "invalid/unnamed type bytes and unmeasured fixed bits remain outside these mod_groups. "
        "Schedule/reuse probes are kept separate. No execution or silicon semantic claim.")


def parse(text):
    match = FORM.fullmatch(text or "")
    if not match or match.group(1) not in GROUPS:
        return None
    for addr, pattern in ADDRESS.items():
        if pattern.fullmatch(match.group(3)):
            return match.group(1), addr
    return None


def fields_for(addr):
    fields = [field(12, 4, "guard", 0, SRC), field(16, 8, "reg", 1, SRC)]
    if addr != "AURI":
        fields.append(field(24, 8, "sub_r0", 2, SRC))
    if addr != "ARI":
        fields.append(field(32, 8, "sub_ur0" if addr == "AURI" else "sub_ur1", 2, SRC))
    fields.append(field(40, 24, "sub_imm1", 2, SRC))
    return fields


def canonical(summary, pair):
    shape, addr = pair
    word = int(summary["canonical"][f"{shape}-{addr}"], 16)
    return word & ~SCHEDULE & ~field_mask(fields_for(addr))


def build(raw_path, summary_path, output):
    summary = json.loads(summary_path.read_text())
    assert set(summary["canonical"]) == {f"{shape}-{addr}" for shape, addr in PAIRS}
    bases = {pair: canonical(summary, pair) for pair in PAIRS}
    fixture = []
    for line in raw_path.read_text().splitlines():
        record = json.loads(line)
        word = int(record["word"], 16)
        pair = parse(record["nvidia_sass"]) if record["rc"] == 0 else None
        adopt = pair in PAIRS
        if adopt:
            fields = fields_for(pair[1])
            allowed = field_mask(fields) | SCHEDULE
            adopt = (word & ~allowed) == bases[pair]
        bit_flips = [int(match.group(1)) for label in record["labels"]
                     if (match := re.search(r"-bit([0-9]+)$", label))]
        auxiliary = (record["kind"] in ("control-reuse", "namespace") or
                     any(bit >= 96 for bit in bit_flips))
        adopt = bool(adopt and not auxiliary)
        vendor_body = re.sub(r"^@!?P[0-6T] ", "", record["nvidia_sass"] or "")
        negative = (not adopt and not auxiliary and
                    (record["rc"] != 0 or not vendor_body.startswith("LDSM.") or
                     "INVALID" in (record["nvidia_sass"] or "")))
        if pair in PAIRS and bases[pair] & ~SCHEDULE != bases[pair]:
                raise AssertionError("canonical base must not bake schedule bits")
        fixture.append({"word": record["word"], "nvidia_sass": record["nvidia_sass"],
                        "arch": "SM103", "adopt": adopt, "auxiliary_control_probe": auxiliary,
                        # Retain the measured legal control word from raw decode; do not
                        # confuse that exact roundtrip with new operand/reuse claims.
                        "core_negative": negative, "encode_exact": adopt,
                        "kind": record["kind"], "rc": record["rc"], "stderr": record["stderr"],
                        "source": " | ".join(record["source"]), "labels": record["labels"],
                        "evidence": "pubwave/hidden-b300/ldsm-unpack/lattice; vendor text only"})
    unique = {}
    for record in fixture:
        old = unique.get(record["word"])
        if old:
            assert old["adopt"] == record["adopt"] and old["nvidia_sass"] == record["nvidia_sass"]
        else:
            unique[record["word"]] = record
    fixture = sorted(unique.values(), key=lambda r: (not r["adopt"], r["word"]))
    with output.open("w") as fh:
        for record in fixture:
            fh.write(json.dumps(record) + "\n")
    by_form = {f"{shape}-{addr}": 0 for shape, addr in PAIRS}
    for record in fixture:
        if record["adopt"]:
            pair = parse(record["nvidia_sass"])
            by_form[f"{pair[0]}-{pair[1]}"] += 1
    print(json.dumps({"records": len(fixture), "adopt": sum(r["adopt"] for r in fixture),
                      "core_negative": sum(r["core_negative"] for r in fixture),
                      "auxiliary": sum(r["auxiliary_control_probe"] for r in fixture),
                      "encode_exact": sum(r["encode_exact"] for r in fixture),
                      "adopted_by_form": by_form,
                      "production_adopted": sum(r["adopt"] and any(x.startswith("H-") for x in r["labels"])
                                               for r in fixture)}, indent=2))


def apply(summary_path, tables):
    summary = json.loads(summary_path.read_text())
    updates = {}
    for shape, addr in PAIRS:
        key = KEYS[addr]
        name = GROUPS[shape]
        fields = fields_for(addr)
        base = canonical(summary, (shape, addr))
        entry = {"and_base": f"0x{base:032x}", "count": None, "fields": fields,
                 "variable_mask": f"0x{field_mask(fields):032x}", "_src": SRC, "_note": NOTE}
        updates.setdefault(key, {})[name] = entry
    for path in tables:
        table = load_table(path)
        for key, groups in updates.items():
            mod_groups = table["instructions"][key]["mod_groups"]
            for stale in {name for name, group in mod_groups.items()
                          if group.get("_src") == SRC} - set(groups):
                del mod_groups[stale]
            mod_groups.update(copy.deepcopy(groups))
        provenance = table["_meta"]["provenance"]
        if SRC not in provenance["sources"]:
            provenance["sources"][SRC] = {
                "rows": len(PAIRS), "kind": "SM103/SM100 raw nvdisasm form and field lattice",
                "date": "2026-11-07",
                "tool": "pubwave/hidden-b300/tools/probe_ldsm_unpack.py + tools/probes/re_sm103_ldsm_unpack.py",
                "test": "tests/hidden_b300_ldsm_unpack.rs"}
        provenance["rows_total"] = sum(len(e.get("mod_groups", {}))
                                       for e in table["instructions"].values())
        provenance["rows_without_src"] = sum(1 for e in table["instructions"].values()
            for group in e.get("mod_groups", {}).values() if "_src" not in group)
        save_table(path, table)
        print(path, "added", len(PAIRS), "measured LDSM mod_groups")


def main():
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    fixture = commands.add_parser("fixture")
    fixture.add_argument("raw", type=pathlib.Path)
    fixture.add_argument("summary", type=pathlib.Path)
    fixture.add_argument("output", type=pathlib.Path)
    patch = commands.add_parser("apply")
    patch.add_argument("summary", type=pathlib.Path)
    patch.add_argument("tables", nargs="+", type=pathlib.Path)
    args = parser.parse_args()
    if args.command == "fixture":
        build(args.raw, args.summary, args.output)
    else:
        apply(args.summary, args.tables)


if __name__ == "__main__":
    main()

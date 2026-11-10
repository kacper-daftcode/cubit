#!/usr/bin/env python3
"""Build and apply measured VIMNMX3 R,Ra,URb,Rc,P rows."""

import argparse
import json
import pathlib
import re
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from nvprobe import SCHEDULE, field, field_mask, load_table, row, save_table


SRC = "hidden-b300-vimnmx3-ur-2026-11-07"
BASE = 0x000FE2000F8001240000000A0B247C0F
FORM = re.compile(r"(?:@!?P[0-6T] )?VIMNMX3((?:\.[A-Za-z0-9_]+)*) (.+)")
REG = r"R(?:Z|[0-9]+)"
UREG = r"UR(?:Z|[0-9]+)"
TYPE_CODES = {
    (): 0x01,
    ("U32",): 0x00,
    ("U16x2",): 0x02,
    ("S16x2",): 0x03,
    ("RELU",): 0x11,
    ("U32", "RELU"): 0x10,
    ("U16x2", "RELU"): 0x12,
    ("S16x2", "RELU"): 0x13,
}
FIELDS = [
    (12, 4, "guard", 0),
    (16, 8, "reg", 1),
    (24, 8, "reg", 2),
    (122, 1, "reuse", 2),
    (32, 8, "ureg", 3),
    (64, 8, "reg", 4),
    (124, 1, "reuse", 4),
    (87, 3, "pred", 5),
    (90, 1, "neg", 5),
]


def group_name(mods):
    return ",".join(sorted(mods))


def put(word, shift, bits, value):
    return (word & ~(((1 << bits) - 1) << shift)) | (value << shift)


def row_for(code):
    word = put(BASE, 72, 8, code)
    fields = [field(*spec, SRC) for spec in FIELDS]
    base = (word & ~(0xFFF | field_mask(fields)) & ~SCHEDULE) | 0xC0F
    result = row(base, fields, SRC,
        "Measured SM103/SM100 VIMNMX3 UR form, opcode 0xc0f. Bit 91 is required; "
        "predicate index is [89:87], negation bit 90. Only Ra/Rc reuse are licensed; "
        "UR reuse bit 123 is forbidden. Text-inert neighbouring bits stay unclaimed.")
    result["claim_forbid"] = [{"shift": 123, "bits": 1, "values": [1]}]
    return result


def decode_name(text):
    match = FORM.fullmatch(text or "")
    if not match:
        return None
    mods = tuple(match.group(1).lstrip(".").split(".")) if match.group(1) else ()
    if mods not in TYPE_CODES:
        return None
    parts = match.group(2).split(", ")
    if len(parts) != 5:
        return None
    if not re.fullmatch(REG, parts[0]):
        return None
    if not re.fullmatch(REG + r"(\.reuse)?", parts[1]):
        return None
    if not re.fullmatch(UREG, parts[2]):
        return None
    if not re.fullmatch(REG + r"(\.reuse)?", parts[3]):
        return None
    if not re.fullmatch(r"!?P[0-6T]", parts[4]):
        return None
    return TYPE_CODES[mods]


def build(raw, output):
    fixture = []
    for line in raw.read_text().splitlines():
        record = json.loads(line)
        text = record["nvidia_sass"]
        word = int(record["word"], 16)
        code = decode_name(text) if record["rc"] == 0 else None
        adopt = False
        if code is not None:
            expected = row_for(code)
            mask = 0xFFF | int(expected["variable_mask"], 16) | SCHEDULE
            adopt = (word & 0xFFF == 0xC0F
                     and word & ~mask == int(expected["and_base"], 16) & ~mask)
        bit_labels = [int(x.split("=")[1].split(",")[0])
                      for x in record["labels"] if x.startswith("bit=")]
        auxiliary = ((word & 0xFFF) != 0xC0F or any(
            bit >= 96 and bit not in (122, 123, 124) for bit in bit_labels))
        adopt &= not auxiliary
        source = record["source"]
        if isinstance(source, list):
            source = " | ".join(dict.fromkeys(source))
        fixture.append({
            "word": record["word"], "nvidia_sass": text, "arch": "SM103",
            "adopt": adopt, "auxiliary_control_probe": auxiliary,
            "kind": record["kind"], "rc": record["rc"], "stderr": record["stderr"],
            "source": source, "labels": record["labels"],
            "evidence": "pubwave/hidden-b300/vimnmx3/lattice-extended; vendor text only",
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
    adopted_by_code = {code: 0 for code in TYPE_CODES.values()}
    for record in fixture:
        if record["adopt"]:
            adopted_by_code[decode_name(record["nvidia_sass"])] += 1
    print(json.dumps({
        "records": len(fixture), "adopt": sum(r["adopt"] for r in fixture),
        "unclaimed": sum(not r["adopt"] and not r["auxiliary_control_probe"] for r in fixture),
        "auxiliary": sum(r["auxiliary_control_probe"] for r in fixture),
        "adopted_by_type_code": adopted_by_code,
        "h_anchors_adopted": [r["word"] for r in fixture if r["adopt"]
            and any(x in ("base", "H-bit72", "H-bit73", "H-bit76", "H-bit87",
                          "H-bit88", "H-bit89", "H-bit90") for x in r["labels"])],
    }, indent=2))


def apply(tables):
    groups = {group_name(mods): row_for(code) for mods, code in TYPE_CODES.items()}
    for path in tables:
        table = load_table(path)
        entry = table["instructions"]["VIMNMX3_R_R_UR_R_P"]
        old = entry.get("mod_groups", {})
        assert set(old) == {""} or all(g.get("_src") == SRC for g in old.values()), path
        entry["mod_groups"] = groups
        provenance = table["_meta"]["provenance"]
        if SRC not in provenance["sources"]:
            provenance["sources"][SRC] = {
                "rows": len(groups), "kind": "SM103/SM100 raw nvdisasm text",
                "date": "2026-11-07",
                "tool": "pubwave/hidden-b300/tools/probe_vimnmx3.py + tools/probes/re_sm103_vimnmx3_ur.py",
                "test": "tests/hidden_b300_vimnmx3.rs",
            }
        provenance["rows_total"] = sum(len(e.get("mod_groups", {}))
                                       for e in table["instructions"].values())
        provenance["rows_without_src"] = sum(1 for e in table["instructions"].values()
            for group in e.get("mod_groups", {}).values() if "_src" not in group)
        save_table(path, table)
        print(path, "replaced one orphan row with", len(groups), "measured groups")


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

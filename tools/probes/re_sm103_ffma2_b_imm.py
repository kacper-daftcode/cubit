#!/usr/bin/env python3
"""Adopt only the measured FFMA2 R,R,F32-immediate,R encoding window."""

import argparse
import copy
import json
import pathlib
import re
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from nvprobe import SCHEDULE, field, field_mask, load_table, save_table

SRC = "hidden-b300-ffma2-b-imm-2026-11-08"
FIELDS = [
    field(12, 4, "guard", 0, SRC),
    field(16, 8, "reg", 1, SRC),
    field(24, 8, "reg", 2, SRC),
    field(72, 1, "neg", 2, SRC),
    field(73, 1, "abs", 2, SRC),
    field(81, 1, "opmod:LO_HI", 2, SRC),
    field(82, 1, "opmod:F32", 2, SRC),
    field(83, 1, "opmod:NP", 2, SRC),
    field(64, 8, "reg", 4, SRC),
    field(74, 1, "abs", 4, SRC),
    field(75, 1, "neg", 4, SRC),
    field(84, 1, "opmod:LO_HI", 4, SRC),
    field(85, 1, "opmod:F32", 4, SRC),
    field(86, 1, "opmod:NP", 4, SRC),
    field(77, 1, "", 3, SRC),
    field(87, 4, "", 3, SRC),
    field(92, 4, "", 3, SRC),
    field(32, 32, "f32", 3, SRC),
]
VM = field_mask(FIELDS)
TEXT_INERT_BITS = (77, 87, 88, 89, 90, 92, 93, 94, 95)
TEXT_INERT_MASK = sum(1 << bit for bit in TEXT_INERT_BITS)
MODIFIERS = {"": 0, "FMZ": 76, "RM": 78, "RP": 79, "FTZ": 80}
MODIFIER_MASK = sum(1 << bit for bit in MODIFIERS.values() if bit)
FORM = re.compile(
    r"(?:@!?P[0-6T] )?FFMA2(?P<mnem>(?:\.(?:FMZ|RM|RP|FTZ))?) "
    r"(?P<rd>R(?:Z|[0-9]+)), "
    r"(?P<ra>-?\|?R(?:Z|[0-9]+)\|?(?:\.reuse)?)\."
    r"(?P<ra_shape>F32x2\.HI_LO|F32x2\.LO_HI|F32)(?P<ra_np>\.NP)?, "
    r"(?P<imm>.+), "
    r"(?P<rc>-?\|?R(?:Z|[0-9]+)\|?(?:\.reuse)?)\."
    r"(?P<rc_shape>F32x2\.HI_LO|F32x2\.LO_HI|F32)(?P<rc_np>\.NP)?"
)


def classify(text):
    match = FORM.fullmatch(text or "")
    if not match or match["imm"].startswith(("R", "UR", "c[", "-R", "-UR")):
        return None
    return match


def canonical(word):
    return (
        0x849
        | (word & VM & ~TEXT_INERT_MASK)
        | (word & MODIFIER_MASK)
        | (word & ~((1 << 96) - 1))
    )


def shape_ok(match, word):
    shape = match["ra_shape"]
    ok = bool(
        (shape == "F32x2.HI_LO" and not (word & (1 << 82)) and not (word & (1 << 81)))
        or (shape == "F32x2.LO_HI" and not (word & (1 << 82)) and (word & (1 << 81)))
        or (shape == "F32" and (word & (1 << 82)) and not (word & (1 << 81)))
    )
    shape = match["rc_shape"]
    ok = ok and bool(
        (shape == "F32x2.HI_LO" and not (word & (1 << 85)) and not (word & (1 << 84)))
        or (shape == "F32x2.LO_HI" and not (word & (1 << 85)) and (word & (1 << 84)))
        or (shape == "F32" and (word & (1 << 85)) and not (word & (1 << 84)))
    )
    for token, neg, absolute, np_bit in (
        ("ra", 72, 73, 83), ("rc", 75, 74, 86)
    ):
        source = match[token]
        ok &= source.startswith("-") == bool(word & (1 << neg))
        ok &= ("|" in source) == bool(word & (1 << absolute))
        ok &= ".reuse" not in source
        ok &= bool(match[f"{token}_np"]) == bool(word & (1 << np_bit))
    bit = MODIFIERS[match["mnem"][1:]]
    expected = (1 << bit) if bit else 0
    actual = sum(word & (1 << b) for b in (76, 78, 79, 80))
    return bool(ok and actual == expected)


def measured_inert(rows):
    bases = {}
    flips = {}
    for item in rows:
        word = int(item["word"], 16)
        for label in item["labels"]:
            if label.startswith("b82="):
                bits = [(word >> bit) & 1 for bit in (82, 88, 85, 86)]
                shape = sum(bit << i for i, bit in enumerate(bits))
                bases[shape] = item
            if label.startswith("shape=") and ",bit=" in label:
                shape_text, bit = label.split(",bit=")
                flips[(int(shape_text[6:]), int(bit))] = item
    assert set(bases) == set(range(16))
    assert len(flips) == 16 * 128
    return tuple(
        bit for bit in range(96)
        if all(
            flips[(shape, bit)]["rc"] == 0
            and flips[(shape, bit)]["nvidia_sass"] == bases[shape]["nvidia_sass"]
            for shape in range(16)
        )
    )


def fixture(raw, output):
    raw_rows = [json.loads(line) for line in raw.read_text().splitlines()]
    assert measured_inert(raw_rows) == TEXT_INERT_BITS, measured_inert(raw_rows)
    records = []
    for item in raw_rows:
        word = int(item["word"], 16)
        match = classify(item["nvidia_sass"]) if item["rc"] == 0 else None
        adopt = bool(
            match
            and shape_ok(match, word)
            and (word & 0xFFF) == 0x849
            and (word & ~(VM | 0xFFF | SCHEDULE | MODIFIER_MASK)) == 0
        )
        bits = [
            int(label.split("bit=")[1].split(",")[0])
            for label in item["labels"] if "bit=" in label
        ]
        auxiliary = any("reuse124-122=" in label for label in item["labels"]) or any(
            bit >= 96 for bit in bits
        )
        adopt = adopt and not auxiliary
        record = {
            "word": item["word"],
            "nvidia_sass": item["nvidia_sass"],
            "arch": item["target"],
            "adopt": adopt,
            "auxiliary_control_probe": auxiliary,
            "encode_exact": adopt and canonical(word) == word,
            "kind": item["kind"],
            "rc": item["rc"],
            "stderr": item["stderr"],
            "source": " | ".join(item["source"]),
            "labels": item["labels"],
            "nvdisasm": item["nvdisasm"],
            "nvdisasm_sha256": item["nvdisasm_sha256"],
            "evidence": "pubwave/hidden-b300/ffma2-b-immediate/lattice; vendor text",
        }
        records.append(record)
    with output.open("w") as stream:
        for record in records:
            stream.write(json.dumps(record) + "\n")
    adopted = [record for record in records if record["adopt"]]
    shapes = {
        shape: sum(
            classify(record["nvidia_sass"])["ra_shape"]
            + "/" + classify(record["nvidia_sass"])["rc_shape"] == shape
            for record in adopted
        )
        for shape in (
            "F32x2.HI_LO/F32x2.HI_LO",
            "F32/F32",
            "F32/F32x2.HI_LO",
            "F32x2.HI_LO/F32",
            "F32x2.LO_HI/F32x2.HI_LO",
            "F32x2.HI_LO/F32x2.LO_HI",
            "F32x2.LO_HI/F32",
            "F32/F32x2.LO_HI",
        )
    }
    modifiers = {
        modifier: sum(classify(r["nvidia_sass"])["mnem"][1:] == modifier for r in adopted)
        for modifier in MODIFIERS
    }
    result = {
        "records": len(records),
        "adopt": len(adopted),
        "unclaimed": sum(not r["adopt"] and not r["auxiliary_control_probe"] for r in records),
        "auxiliary": sum(r["auxiliary_control_probe"] for r in records),
        "encode_exact": sum(r["encode_exact"] for r in adopted),
        "adopted_shapes": shapes,
        "adopted_modifier_groups": modifiers,
        "text_inert_bits": list(TEXT_INERT_BITS),
        "H_anchors_adopted": [r["word"] for r in adopted if r["kind"] == "H-production"],
    }
    assert len({r["word"] for r in records}) == len(records)
    assert all(count >= 2 for count in shapes.values()), result
    assert all(count >= 4 for count in modifiers.values()), result
    assert len(result["H_anchors_adopted"]) == 12, result
    assert any(
        any("bit=91" in label for label in r["labels"]) and not r["adopt"]
        for r in records
    )
    print(json.dumps(result, indent=2))


def apply(tables):
    groups = {}
    for modifier, bit in MODIFIERS.items():
        groups[modifier] = {
            "and_base": f"0x{0x849 | ((1 << bit) if bit else 0):032x}",
            "count": None,
            "fields": copy.deepcopy(FIELDS),
            "variable_mask": f"0x{VM:032x}",
            "_src": SRC,
            "_note": (
                "Measured SM103/SM100 FFMA2 R,R,F32-immediate,R at opcode 0x849. "
                "Ra shapes use 82/81/83 and Rc shapes use 85/84/86 for F32, LO_HI "
                "and NP; scalar LO_HI is INVALID3 and unclaimed. Guard/Rd/Ra/Rc, "
                "Ra/Rc neg+abs and FP32 immediate are measured. Plain, FMZ, RM, RP "
                "and FTZ groups. Reuse/control bits[105:127] are not operand fields. "
                "Text-inert 77,87:90,92:95 are neutral and canonicalize to zero. "
                "B91 and sibling opcodes fail closed. No silicon semantic claim."
            ),
        }
    for path in tables:
        table = load_table(path)
        if "FFMA2_R_R_FI_R" in table["instructions"]:
            assert table["instructions"]["FFMA2_R_R_FI_R"]["mod_groups"][""]["_src"] == SRC
        donor = table["instructions"]["FFMA2_R_R_R_R"]
        entry = {
            "base_op": "FFMA2",
            "mod_groups": copy.deepcopy(groups),
            "operand_sig": "R_R_FI_R",
            "scheduling": copy.deepcopy(donor.get("scheduling")),
        }
        table["instructions"]["FFMA2_R_R_FI_R"] = entry
        provenance = table["_meta"]["provenance"]
        provenance["sources"][SRC] = {
            "rows": len(groups),
            "kind": "SM103/SM100 raw production vendor text and controlled encoding lattice",
            "date": "2026-11-08",
            "tool": "tools/probes/re_sm103_ffma2_b_imm.py",
            "test": "tests/hidden_b300_ffma2_b_immediate.rs",
        }
        provenance["rows_total"] = sum(
            len(e.get("mod_groups", {})) for e in table["instructions"].values()
        )
        provenance["rows_without_src"] = sum(
            1 for e in table["instructions"].values()
            for group in e.get("mod_groups", {}).values() if "_src" not in group
        )
        save_table(path, table)
        print(path, len(groups), "measured FFMA2 immediate-B groups")


def main():
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    fixture_parser = commands.add_parser("fixture")
    fixture_parser.add_argument("raw", type=pathlib.Path)
    fixture_parser.add_argument("output", type=pathlib.Path)
    apply_parser = commands.add_parser("apply")
    apply_parser.add_argument("tables", nargs="+", type=pathlib.Path)
    args = parser.parse_args()
    if args.command == "fixture":
        fixture(args.raw, args.output)
    else:
        apply(args.tables)


if __name__ == "__main__":
    main()

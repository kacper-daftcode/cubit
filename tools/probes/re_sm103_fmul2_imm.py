#!/usr/bin/env python3
"""Adopt exactly the measured FMUL2 R,R,F32-immediate operand field window."""

import argparse
import copy
import json
import pathlib
import re
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from nvprobe import SCHEDULE, field, field_mask, load_table, save_table

SRC = "hidden-b300-fmul2-imm-2026-11-08"
H_WORD = 0x000FE20001000000BF8000002C34784A
FIELDS = [field(12, 4, "guard", 0, SRC), field(16, 8, "reg", 1, SRC),
          field(24, 8, "reg", 2, SRC), field(72, 1, "neg", 2, SRC),
          field(73, 1, "abs", 2, SRC), field(122, 1, "reuse", 2, SRC),
          field(82, 1, "opmod:F32", 2, SRC), field(81, 1, "opmod:LO_HI", 2, SRC),
          field(83, 1, "opmod:NP", 2, SRC),
          field(64, 8, "", 3, SRC), field(74, 2, "", 2, SRC),
          field(77, 1, "", 2, SRC), field(84, 4, "", 2, SRC),
          field(88, 3, "", 2, SRC), field(92, 4, "", 2, SRC),
          field(32, 32, "f32", 3, SRC)]
VM = field_mask(FIELDS)
TEXT_INERT_BITS = (64, 65, 66, 67, 68, 69, 70, 71, 74, 75, 77,
                   84, 85, 86, 87, 88, 89, 90, 92, 93, 94, 95)
TEXT_INERT_MASK = sum(1 << bit for bit in TEXT_INERT_BITS)
MODIFIERS = {"": 0, "FMZ": 76, "RM": 78, "RP": 79, "FTZ": 80}
MODIFIER_MASK = sum(1 << bit for bit in MODIFIERS.values() if bit)
FORM = re.compile(r"(?:@!?P[0-6T] )?FMUL2(?P<mnem>(?:\.(?:FMZ|RM|RP|FTZ))?) "
                  r"(?P<rd>R(?:Z|[0-9]+)), "
                  r"(?P<ra>-?\|?R(?:Z|[0-9]+)\|?(?:\.reuse)?)\."
                  r"(?P<shape>F32x2\.HI_LO|F32x2\.LO_HI|F32)"
                  r"(?P<np>\.NP)?, (?P<imm>.+)")


def classify(text):
    match = FORM.fullmatch(text or "")
    if not match or match["imm"].startswith(("R", "UR", "c[")):
        return None
    return match


def canonical(word):
    return (0x84A | (word & VM & ~TEXT_INERT_MASK) | (word & MODIFIER_MASK)
            | (word & ~((1 << 96) - 1)))


def inert_from_raw(rows):
    words = {int(item["word"], 16): item for item in rows}
    assert len(words) == len(rows)
    return tuple(bit for bit in range(96) if all(
        words[(H_WORD | shape) ^ (1 << bit)]["rc"] == 0
        and words[(H_WORD | shape) ^ (1 << bit)]["nvidia_sass"]
        == words[H_WORD | shape]["nvidia_sass"]
        for shape in (0, 1 << 82, 1 << 88, (1 << 82) | (1 << 88))))


def fixture(raw, output):
    assert H_WORD & ~(VM | SCHEDULE) == 0x84A
    raw_rows = [json.loads(line) for line in raw.read_text().splitlines()]
    assert inert_from_raw(raw_rows) == TEXT_INERT_BITS
    adopted = []
    records = []
    for item in raw_rows:
        word = int(item["word"], 16)
        match = classify(item["nvidia_sass"]) if item["rc"] == 0 else None
        shape = match["shape"] if match else None
        allowed_shape = bool(match) and (
            (shape == "F32x2.HI_LO" and not (word & (3 << 81)))
            or (shape == "F32x2.LO_HI" and (word >> 81) & 3 == 1)
            or (shape == "F32" and (word & (1 << 82)) and not (word & (1 << 81))))
        if match:
            source = match["ra"]
            allowed_shape &= (source.startswith("-") == bool(word & (1 << 72)))
            allowed_shape &= (("|" in source) == bool(word & (1 << 73)))
            allowed_shape &= ((".reuse" in source) == bool(word & (1 << 122)))
            allowed_shape &= (bool(match["np"]) == bool(word & (1 << 83)))
            bit = MODIFIERS[match["mnem"][1:]]
            expected = (1 << bit) if bit else 0
            actual = sum((word & (1 << b)) for b in (76, 78, 79, 80))
            allowed_shape &= actual == expected
        adopt = bool(allowed_shape and (word & 0xFFF) == 0x84A
                     and (word & ~(VM | 0xFFF | SCHEDULE | MODIFIER_MASK)) == 0)
        bits = [int(x.split("bit=")[1].split(",")[0]) for x in item["labels"]
                if "bit=" in x]
        auxiliary = item["kind"] == "control-reuse" or any(bit >= 96 for bit in bits)
        adopt = adopt and not auxiliary
        record = {"word": item["word"], "nvidia_sass": item["nvidia_sass"],
            "arch": item["target"], "adopt": adopt, "auxiliary_control_probe": auxiliary,
            "encode_exact": adopt and canonical(word) == word,
            "kind": item["kind"], "rc": item["rc"], "stderr": item["stderr"],
            "source": " | ".join(item["source"]), "labels": item["labels"],
            "nvdisasm": item["nvdisasm"], "nvdisasm_sha256": item["nvdisasm_sha256"],
            "evidence": "pubwave/hidden-b300/fmul2-immediate/lattice; vendor text"}
        records.append(record)
        if adopt:
            adopted.append(record)
    with output.open("w") as stream:
        for record in records:
            stream.write(json.dumps(record) + "\n")
    shapes = {shape: sum(classify(r["nvidia_sass"])["shape"] == shape for r in adopted)
              for shape in ("F32x2.HI_LO", "F32x2.LO_HI", "F32")}
    modifiers = {modifier: sum(classify(r["nvidia_sass"])["mnem"][1:] == modifier
                              for r in adopted) for modifier in MODIFIERS}
    result = {"records": len(records), "adopt": len(adopted),
              "unclaimed": sum(not r["adopt"] and not r["auxiliary_control_probe"]
                               for r in records),
              "auxiliary": sum(r["auxiliary_control_probe"] for r in records),
              "encode_exact": sum(r["encode_exact"] for r in adopted),
              "adopted_shapes": shapes,
              "adopted_modifier_groups": modifiers,
              "text_inert_bits": list(TEXT_INERT_BITS),
              "inert_rule": "all four shape cells have identical vendor text; each neutral range is provenance-bearing none field",
              "H_anchors_adopted": [r["word"] for r in adopted if r["kind"] == "H-production"]}
    assert len({r["word"] for r in records}) == len(records)
    assert shapes["F32x2.HI_LO"] >= 40 and shapes["F32"] >= 40
    assert shapes["F32x2.LO_HI"] >= 2, result
    assert len(result["H_anchors_adopted"]) > 10, result
    assert all(count >= 4 for count in modifiers.values()), result
    assert any(any("bit=91" in label for label in r["labels"]) and not r["adopt"]
               for r in records), "B91 must be an explicit unclaimed core negative"
    print(json.dumps(result, indent=2))


def apply(tables):
    groups = {}
    for modifier, bit in MODIFIERS.items():
        groups[modifier] = {
            "and_base": f"0x{0x84A | ((1 << bit) if bit else 0):032x}",
            "count": None, "fields": copy.deepcopy(FIELDS),
            "variable_mask": f"0x{VM:032x}", "_src": SRC,
            "_note": ("Measured SM103/SM100 FMUL2 R,R,F32-immediate forms: paired "
                "F32x2.HI_LO/LO_HI with optional NP and scalar F32.NP, opcode 0x84a. "
                "Plain, FMZ, RM, RP and FTZ groups. Guard/Rd/Ra/FP32 imm, Ra neg/abs/"
                "reuse and bits82/81/83 are named fields. The measured text-inert "
                "ranges are neutral fields, zero on canonical encode. Scalar LO_HI (INVALID3), B91 and "
                "unrepresented windows fail closed. Silicon semantics: only paired -1.")}
    for path in tables:
        table = load_table(path)
        if "FMUL2_R_R_FI" in table["instructions"]:
            assert table["instructions"]["FMUL2_R_R_FI"]["mod_groups"][""]["_src"] == SRC
        donor = table["instructions"]["FMUL2_R_R_R"]
        entry = {"base_op": "FMUL2", "mod_groups": copy.deepcopy(groups),
                 "operand_sig": "R_R_FI", "scheduling": copy.deepcopy(donor.get("scheduling"))}
        table["instructions"]["FMUL2_R_R_FI"] = entry
        provenance = table["_meta"]["provenance"]
        provenance["sources"][SRC] = {"rows": len(groups),
                "kind": "SM103/SM100 raw production vendor text; scoped B300 -1 execution control",
                "date": "2026-11-08", "tool": "tools/probes/re_sm103_fmul2_imm.py",
                "test": "tests/hidden_b300_fmul2_immediate.rs"}
        provenance["rows_total"] = sum(len(e.get("mod_groups", {}))
            for e in table["instructions"].values())
        provenance["rows_without_src"] = sum(1 for e in table["instructions"].values()
            for g in e.get("mod_groups", {}).values() if "_src" not in g)
        save_table(path, table)
        print(path, len(groups), "measured FMUL2 immediate groups")


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

#!/usr/bin/env python3
"""Adopt four silicon-measured FADD2 immediate rounding/FTZ groups."""

import argparse
import copy
import hashlib
import json
import pathlib
import re

from nvprobe import load_table, save_table
from re_sm103_fadd2_imm import VM

SRC = "hidden-b300-fadd2-rounding-2026-11-08"
MODES = {"RZ": (78, 79), "FTZ.RM": (78, 80),
         "FTZ.RP": (79, 80), "FTZ.RZ": (78, 79, 80)}
SHAPES = {"lohi": "F32x2.LO_HI", "hilo": "F32x2.HI_LO",
          "scalar": "F32"}
TEXT = re.compile(r"/\*0000\*/\s*(.*?)\s*;")


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def vendor_text(record):
    assert record["rc"] == 0 and not record["stderr"]
    return TEXT.search(record["stdout"]).group(1).strip()


def fixture(measurement, output):
    prepare = json.loads((measurement / "prepare.json").read_text())
    verified = json.loads((measurement / "verification-summary.json").read_text())
    assert verified["execution_verdict"] == "COMPLETE"
    assert verified["current_decoder_failing_first"] == {
        "count": 194,
        "cubit": "fbf3eb53c4e44ff0d233a7dcd0b165326cbb0995",
        "isa": "59a47d8f3d1c0d67241d61300243336e73fa26d4",
        "result": "all new-group words rejected; raw commands and errors in prepare.json",
    }
    semantic = verified["bounded_silicon_semantic"]
    assert semantic["unique_finite_variants"] == 192
    assert semantic["exact_finite_words_unique_forms"] == 1572864
    assert semantic["exact_finite_words_including_replays"] == 1589248
    assert semantic["total_finite_mismatches"] == 0
    assert semantic["new_modifier_groups"] == list(MODES)
    assert prepare["adopted_cubit_failing_first_count"] == 194
    assert prepare["factorial_coverage"]["core_variants"] == 192

    records = []
    for case, row in prepare["variants"].items():
        spec = row["spec"]
        if spec["replay_of"] is not None:
            continue
        assert vendor_text(row["raw_records"][0]) == vendor_text(row["raw_records"][1])
        records.append((case, row, spec))
    assert len(records) == 192

    result = []
    seen = set()
    for case, row, spec in records:
        raw = int(row["word"], 16)
        modifier = spec["modifier"]
        assert modifier in MODES and not spec["replay_of"]
        assert raw & 0xfff == 0x44b and not raw & (1 << 91)
        assert sum(bool(raw & (1 << bit)) for bit in (78, 79, 80)) == len(MODES[modifier])
        assert all(raw & (1 << bit) for bit in MODES[modifier])
        expected = f"FADD2.{modifier} R10, R2.{SHAPES[case.split('_')[0]]}"
        assert vendor_text(row["raw_records"][0]).startswith(expected)
        assert row["adopted_cubit_failing_first"]["rc"] != 0
        assert not row["adopted_cubit_failing_first"]["stdout"]
        canonical = raw & ~(1 << 85)  # independently measured neutral bit
        replay = [row for values in verified["replays"].values()
                  if values["original"] == case]
        for word, encode_exact, role in ((raw, False, "vendor-replay-witness"),
                                         (canonical, True, "canonical-neutral-bit-zero")):
            assert word not in seen
            seen.add(word)
            result.append({
                "word": f"{word:032x}", "nvidia_sass": vendor_text(row["raw_records"][0]),
                "arch": "SM103", "adopt": True, "auxiliary_control_probe": False,
                "encode_exact": encode_exact, "kind": "core-rounding", "role": role,
                "source_measurement_case": case, "spec": spec,
                "raw_vendor_records": [item["input_file"] for item in row["raw_records"]],
                "source_cubin": row["cubin"], "source_cubin_sha256": row["cubin_sha256"],
                "nvdisasm": prepare["nvdisasm_version"],
                "nvdisasm_sha256": prepare["nvdisasm_sha256"],
                "evidence": "pubwave/hidden-b300/fadd2-shapes-np-ftz; SASS-TEXT and bit-exact SILICON-SEMANTIC",
            })
        negative = raw | (1 << 91)
        result.append({
            "word": f"{negative:032x}", "nvidia_sass": None, "arch": "SM103",
            "adopt": False, "auxiliary_control_probe": False, "encode_exact": False,
            "kind": "mask-closure", "role": "mechanical-out-of-family-bit91",
            "source_measurement_case": case,
            "evidence": "mask closure only; no vendor-text or silicon claim for this derived word",
        })
    assert len({row["word"] for row in result}) == 576
    with output.open("w") as stream:
        for row in result:
            stream.write(json.dumps(row) + "\n")
    summary = {
        "records": len(result), "adopted": sum(r["adopt"] for r in result),
        "unique_vendor_words": len(records), "exact_encodes": sum(r["encode_exact"] for r in result),
        "core_negatives": sum(not r["adopt"] for r in result),
        "modifiers": MODES, "source_measurement_sha256": digest(measurement / "verification-summary.json"),
        "exact_finite_words_including_replays": semantic["exact_finite_words_including_replays"],
        "prepare_sha256": digest(measurement / "prepare.json"),
        "modes_x_shapes_x_immediates_x_np": "4 x 3 x 4 x 4 = 192",
        "vendor_acceptance_per_target": 192,
        "nvdisasm_sha256": prepare["nvdisasm_sha256"],
    }
    print(json.dumps(summary, indent=2))


def modified(entry, paths):
    assert entry.pop("_src") == "hidden-b300-fadd2-imm-2026-11-08"
    for name in paths:
        entry[name] = SRC


def apply(tables):
    for path in tables:
        table = load_table(path)
        key = table["instructions"]["FADD2_R_R_FI"]
        donor = key["mod_groups"][""]
        assert int(donor["variable_mask"], 16) == VM
        assert len(key["mod_groups"]) in (4, 8)
        for old in ("", "RM", "RP", "FTZ"):
            assert key["mod_groups"][old]["_src"] == "hidden-b300-fadd2-imm-2026-11-08"
        # Idempotent reapplication replaces only this source's extension rows.
        for modifier in MODES:
            for name in {modifier, modifier.replace(".", ",")}:
                if name in key["mod_groups"]:
                    assert key["mod_groups"][name]["_src"] == SRC
                    del key["mod_groups"][name]
        assert len(key["mod_groups"]) == 4
        for modifier, bits in MODES.items():
            group = copy.deepcopy(donor)
            modified(group, ["_src"])
            for field in group["fields"]:
                modified(field, ["_src"])
            group["and_base"] = f"0x{0x44b | sum(1 << bit for bit in bits):032x}"
            group["_note"] = ("SASS-TEXT and bounded bit-exact SILICON-SEMANTIC: FADD2 immediate "
                + modifier + " uses the base F32-immediate fields and 3 legal source shapes. "
                "RZ=toward zero; FTZ composes independently with RM/RP/RZ. Upper-lane NP, "
                "signed zeros, subnormals and rounding boundaries are measured. Scalar LO_HI "
                "and out-of-mask words remain unclaimed; no other-opcode or performance claim.")
            assert group["and_base"] not in {g["and_base"] for g in key["mod_groups"].values()}
            # Encoder modifiers are sorted comma-joined sets; the printer
            # renders them in measured vendor order with dots.
            key["mod_groups"][modifier.replace(".", ",")] = group
        provenance = table["_meta"]["provenance"]
        provenance["sources"][SRC] = {
            "rows": len(MODES),
            "kind": "SM103/SM100 vendor text plus bounded bit-exact measured SM103a silicon semantics",
            "date": "2026-11-08", "tool": "tools/probes/re_sm103_fadd2_rounding.py",
            "test": "tests/hidden_b300_fadd2_rounding.rs",
            "evidence": "pubwave/hidden-b300/fadd2-shapes-np-ftz",
        }
        provenance["rows_total"] = sum(
            len(entry.get("mod_groups", {})) for entry in table["instructions"].values())
        provenance["rows_without_src"] = sum(
            1 for entry in table["instructions"].values()
            for group in entry.get("mod_groups", {}).values() if "_src" not in group)
        save_table(path, table)
        print(path, len(key["mod_groups"]), "FADD2 immediate groups")


def main():
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    command = commands.add_parser("fixture")
    command.add_argument("measurement", type=pathlib.Path)
    command.add_argument("output", type=pathlib.Path)
    command = commands.add_parser("apply")
    command.add_argument("tables", nargs="+", type=pathlib.Path)
    args = parser.parse_args()
    if args.command == "fixture":
        fixture(args.measurement, args.output)
    else:
        apply(args.tables)


if __name__ == "__main__":
    main()

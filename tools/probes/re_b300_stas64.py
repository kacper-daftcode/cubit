#!/usr/bin/env python3
"""Apply measured STAS widths/address operands and produce focused fixtures."""

import argparse
import collections
import copy
import json
import pathlib
import sys


ROOT = pathlib.Path("/root/sm103a/pubwave/hidden-b300/stas64-production")
SRC = "rows-hidden-b300-stas64-production-2026-11-08"
WIDTHS = ("", "64", "128")
SCHEDULE = ((1 << 23) - 1) << 105


def field(shift, bits, extraction, token):
    return {"_src": SRC, "bits": bits, "extraction": extraction,
            "shift": shift, "token_idx": token}


def number(value):
    return int(value, 16)


def fields_for(uniform):
    fields = [field(12, 4, "guard", 0), field(24, 8, "sub_r0", 1),
              field(40, 24, "sub_imm2" if uniform else "sub_imm1", 1),
              field(32, 8, "reg", 2)]
    if uniform:
        fields.append(field(64, 8, "sub_ur1", 1))
    return fields


def mask_for(fields):
    mask = 0
    for item in fields:
        mask |= ((1 << item["bits"]) - 1) << item["shift"]
    return mask


def measured_row(base, uniform, width):
    fields = fields_for(uniform)
    mask = mask_for(fields)
    template = base & ~mask & ~SCHEDULE
    template &= ~(0x3 << 73)
    if width == "64":
        template |= 1 << 73
    elif width == "128":
        template |= 1 << 74
    claim_forbid = [{"shift": 24, "bits": 8, "values": [255]}]
    if uniform:
        claim_forbid.append({"shift": 64, "bits": 8, "values": [255]})
    return {
        "and_base": f"0x{template:032x}",
        "count": None,
        "fields": fields,
        "variable_mask": f"0x{mask:032x}",
        "claim_forbid": claim_forbid,
        "_src": SRC,
        "_note": (
            "Measured with nvdisasm 13.3 V13.3.73 on SM103 and SM100: guard[15:12], "
            "R address[31:24] excluding the ???255 glyph, source R[39:32] (255=RZ), "
            "signed immediate[63:40], "
            + ("explicit UR[71:64] range 0..254, retaining the UR63 spelling. "
               if uniform else "UR window 255 is baked and elided. ")
            + "Width is the measured 64/128 enum (plain STAS when neither bit is set). "
            "Bits 72,75..90 except the required addressing frame, 92..104 and other "
            "INVALIDn forms stay fail-closed. This is SASS text/encoding evidence, "
            "not execution, memory-operation or performance confirmation."
        ),
    }


def classify(row):
    text = row["nvidia_sass"]
    labels = row["labels"]
    word = int(row["word"], 16)
    if row["kind"] == "control-bit":
        return "omit-control"
    if row["kind"] == "existing-table-anchor":
        return "old-anchor"
    if row["rc"]:
        return "reject"
    if not text or "INVALID" in text or "???" in text:
        return "reject"
    if row["kind"] in ("production", "cross"):
        return "adopt"
    if any(label.startswith(("guard4=", "imm24=")) for label in labels):
        return "adopt"
    if any(label.startswith("reserved64=") for label in labels):
        return "adopt" if (word >> 64) & 0xff != 255 else "adopt-ari"
    if any(label.startswith(("address=", "data=", "imm-low=", "imm-high="))
           for label in labels):
        return "adopt"
    if row["kind"] == "single-bit":
        bit = int(labels[0].split("=")[1])
        if bit in (73, 74):
            return "adopt"
        if bit <= 11 or bit == 91 or int(text.split()[0].startswith("STAS")) == 0:
            return "reject"
    if row["kind"] == "modifier-cross":
        return "reject-scoped"
    return "omit-unclaimed"


def fixture_row(row):
    role = classify(row)
    if role not in ("adopt", "reject", "reject-scoped"):
        return None
    word = int(row["word"], 16)
    text = row["nvidia_sass"]
    address = (word >> 24) & 0xff
    tokens = text.split() if text else []
    mnemonic = tokens[1] if tokens and tokens[0].startswith("@") else (
        tokens[0] if tokens else "")
    return {
        "word": row["word"], "nvidia_sass": text,
        "kind": row["kind"], "labels": row["labels"], "role": role,
        "expected_key": ("STAS_ARURI_R" if role == "adopt"
                          and (word >> 64) & 0xff != 255 else "STAS_ARI_R"),
        "expected_group": {"STAS.128": "128", "STAS.64": "64"}.get(mnemonic, ""),
        "source_address": address,
        "rc": row["rc"],
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--lattice", type=pathlib.Path, default=ROOT / "raw")
    parser.add_argument("--isa", type=pathlib.Path, required=True)
    parser.add_argument("--cubit", type=pathlib.Path, required=True)
    parser.add_argument("--out", type=pathlib.Path, required=True)
    parser.add_argument("--fixture-only", action="store_true")
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    all_rows = {}
    fixtures = {}
    counts = {}
    for target in ("sm103", "sm100"):
        with (args.lattice / f"{target}.jsonl").open() as stream:
            rows = [json.loads(line) for line in stream]
        assert len(rows) == 4186
        by_word = {row["word"]: row for row in rows}
        all_rows[target] = by_word
        fixture = [fixture_row(row) for row in rows]
        fixture = [row for row in fixture if row is not None]
        fixtures[target] = fixture
        counts[target] = dict(collections.Counter(row["role"] for row in fixture))
    assert set(all_rows["sm103"]) == set(all_rows["sm100"])
    for word, left in all_rows["sm103"].items():
        right = all_rows["sm100"][word]
        assert (left["rc"], left["nvidia_sass"], left["stderr"]) == (
            right["rc"], right["nvidia_sass"], right["stderr"]), word
        assert left["stdout"].replace("SM103", "TARGET") == right["stdout"].replace(
            "SM100", "TARGET"), word
        assert fixtures_equal(left, right)
    production = [row for row in all_rows["sm103"].values() if row["kind"] == "production"]
    assert len(production) == 282
    production_observations = sum(len(row["sources"]) for row in production)
    production_pairs = {(row["word"], source["original"]["target"])
                        for row in production for source in row["sources"]}
    assert production_observations == 397
    assert len(production_pairs) == 348
    assert all(row["rc"] == 0 and not any(g in row["nvidia_sass"]
               for g in ("INVALID", "???")) for row in production)
    for width, expected in (("STAS.64", 38), ("STAS.128", 244)):
        assert sum(row["nvidia_sass"].startswith(width + " ") for row in production) == expected

    for target, fixture in fixtures.items():
        path = args.cubit / "tests/fixtures" / f"{target}_stas64_nvdisasm.jsonl"
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w") as stream:
            for row in fixture:
                stream.write(json.dumps(row, sort_keys=True) + "\n")

    if not args.fixture_only:
        base = int(next(row["word"] for row in all_rows["sm103"].values()
                        if row["kind"] == "production"), 16)
        for arch in ("sm103a", "sm100a"):
            path = args.isa / f"{arch}.json"
            table = json.loads(path.read_text())
            entry = table["instructions"]["STAS_ARI_R"]
            assert set(entry["mod_groups"]) == {""}
            old = table["_meta"]["provenance"]["rows_without_src"]
            old_total = table["_meta"]["provenance"]["rows_total"]
            for width in WIDTHS:
                new = measured_row(base, False, width)
                if width == "":
                    old_group = entry["mod_groups"][""]
                    preserved = number(old_group["and_base"]) & ~number(new["variable_mask"])
                    assert preserved == number(new["and_base"])
                    new["count"] = old_group["count"]
                entry["mod_groups"][width] = new
            uniform_entry = copy.deepcopy(entry)
            uniform_entry["operand_sig"] = "ARURI_R"
            uniform_entry["mod_groups"] = {width: measured_row(base, True, width) for width in WIDTHS}
            table["instructions"]["STAS_ARURI_R"] = uniform_entry
            provenance = table["_meta"]["provenance"]
            provenance["rows_without_src"] = old - 1
            provenance["rows_total"] = old_total + 5
            provenance["sources"][SRC] = {
                "rows": 5,
                "kind": "SM103/SM100 raw STAS.64/STAS.128 production and operand lattice",
                "date": "2026-11-08",
                "tool": "tools/probes/re_b300_stas64.py",
                "test": "tests/hidden_b300_stas64.rs",
            }
            path.write_text(json.dumps(table, indent=1, ensure_ascii=True) + "\n")
    report = {"counts_per_target": counts, "production_unique_per_target": 282,
              "production_observations": production_observations,
              "production_word_target_pairs": len(production_pairs),
              "production_groups": {"64": 38, "128": 244},
              "fixture_only": args.fixture_only, "source": SRC}
    (args.out / "prepare-summary.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


def fixtures_equal(left, right):
    return fixture_row(left) == fixture_row(right)


if __name__ == "__main__":
    main()

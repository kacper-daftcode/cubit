#!/usr/bin/env python3
"""Apply the measured production FHFMA.BF16 register family."""

import argparse
import copy
import json
import pathlib


SRC = "hidden-b300-fhfma-bf16-2026-11-08"
KEY = "FHFMA_R_R_R_R"
SCHEDULE = ((1 << 23) - 1) << 105
INERT_BITS = [*range(40, 62), 76, 80, *range(85, 91), *range(92, 96)]
INERT = sum(1 << bit for bit in INERT_BITS)
NOTE = ("FHFMA.BF16 R,R,R,R measured from production H witnesses on SM103/SM100 with nvdisasm 13.3.73. "
        "Eight SAT/RM/RP/RZ groups. Guard, Rd/Ra/Rb/Rc, signs/abs, independent Ra.H1 bit83 and Rb.H1 bit84, "
        "and reuse at 122/123/124 measured directly. Bits 76, 80, 85..90, 92..95 and [61:40] are text-inert "
        "within the validated lattice; no FMZ/FTZ semantics is assigned to them. No bare FHFMA, other opcode, "
        "uniform frame or silicon numeric behavior is claimed.")


def field(shift, bits, extraction, token):
    return {"bits": bits, "extraction": extraction, "shift": shift, "token_idx": token, "_src": SRC}


FIELDS = [
    field(12, 4, "guard", 0), field(16, 8, "reg", 1),
    field(24, 8, "reg", 2), field(72, 1, "neg", 2), field(73, 1, "abs", 2),
    field(122, 1, "reuse", 2), field(83, 1, "opmod:H1", 2),
    field(32, 8, "reg", 3), field(63, 1, "neg", 3), field(62, 1, "abs", 3),
    field(123, 1, "reuse", 3), field(84, 1, "opmod:H1", 3),
    field(64, 8, "reg", 4), field(75, 1, "neg", 4), field(74, 1, "abs", 4),
    field(124, 1, "reuse", 4),
    *[field(bit, 1, "", 2) for bit in INERT_BITS],
]


def groups():
    assert len({1 << f["shift"] for f in FIELDS}) == len(FIELDS)
    variable_mask = sum(((1 << f["bits"]) - 1) << f["shift"] for f in FIELDS)
    out = {}
    for SAT in (0, 1):
        for rnd, name in enumerate(("", "RM", "RP", "RZ")):
            mods = [part for part in ("BF16", name, "SAT" if SAT else "") if part]
            and_base = 0x223 | (1 << 81) | (1 << 82) | (SAT << 77) | (rnd << 78)
            assert and_base & variable_mask == 0 and and_base & SCHEDULE == 0
            out[",".join(sorted(mods))] = {
                "and_base": f"0x{and_base:032x}", "count": None, "fields": copy.deepcopy(FIELDS),
                "variable_mask": f"0x{variable_mask:032x}", "_src": SRC, "_note": NOTE,
            }
    return out


def fixture(raw, output):
    rows = [json.loads(line) for path in sorted(raw.glob("sm103-*.jsonl")) for line in path.open()]
    out = []
    for row in rows:
        text = row["nvidia_sass"]
        schedule_probe = row["kind"] == "single-bit" and any(
            "bit-" in label and int(label.split("bit-")[-1]) >= 96 for label in row["labels"])
        if schedule_probe:
            continue
        word = int(row["word"], 16)
        adopted = bool(text and text.startswith("FHFMA.BF16"))
        record = {"word": row["word"], "nvidia_sass": text, "nvdisasm": row["nvdisasm"],
                  "nvdisasm_sha256": row["nvdisasm_sha256"], "kind": row["kind"],
                  "labels": row["labels"], "target_pair": "SM103=SM100", "adopt": adopted}
        if adopted:
            record["encode_exact"] = word & INERT == 0 and row["kind"] != "H-production"
            if row["kind"] == "H-production":
                record["provenance"] = "H production vendor fixture"
        else:
            record["lattice"] = True
        out.append(record)
    expected_words = len(rows) - sum(1 for row in rows if row["kind"] == "single-bit" and any(
        "bit-" in label and int(label.split("bit-")[-1]) >= 96 for label in row["labels"]))
    assert len(out) == expected_words
    assert sum(row["adopt"] for row in out) >= 600
    assert sum(row["kind"] == "H-production" and row["adopt"] for row in out) == 389
    with output.open("w") as stream:
        for row in out:
            stream.write(json.dumps(row, sort_keys=True) + "\n")
    print({"fixture": str(output), "records": len(out),
           "adopt": sum(row["adopt"] for row in out),
           "exact": sum(row.get("encode_exact", False) for row in out)})


def apply(tables):
    modifications = groups()
    source = {
        "rows": len(modifications), "kind": "nvdisasm 13.3.73 production-anchored SM103/SM100 field probe",
        "date": "2026-11-08", "tool": "tools/probes/re_b300_fhfma_bf16.py",
        "test": "tests/hidden_b300_fhfma_bf16.rs",
    }
    for path in tables:
        table = json.loads(path.read_text())
        if KEY in table["instructions"]:
            assert table["instructions"][KEY].get("_src") == SRC
        else:
            donor = copy.deepcopy(table["instructions"]["FFMA_R_R_R_R"])
            entry = {key: value for key, value in donor.items()
                     if key in ("base_op", "ctrl_class", "scheduling")}
            entry["base_op"] = "FHFMA"
            entry["operand_sig"] = "R_R_R_R"
            entry["_src"] = SRC
            table["instructions"][KEY] = entry
        # Replace only this experiment's rejected first schema, never an
        # arbitrary pre-existing key or another measurement's rows.
        rejected_key = "FHFMA.BF16_R_R_R_R"
        if rejected_key in table["instructions"]:
            assert table["instructions"][rejected_key].get("_src") == SRC
            del table["instructions"][rejected_key]
        table["instructions"][KEY]["mod_groups"] = modifications
        provenance = table["_meta"]["provenance"]
        if SRC in provenance["sources"]:
            assert provenance["sources"][SRC] == source
        provenance["sources"][SRC] = source
        provenance["rows_total"] = sum(len(e.get("mod_groups", {})) for e in table["instructions"].values())
        provenance["rows_without_src"] = sum(1 for e in table["instructions"].values()
            for group in e.get("mod_groups", {}).values() if "_src" not in group)
        path.write_text(json.dumps(table, indent=1) + "\n")
        print(path, "+1 key", len(modifications), "groups", provenance["rows_total"])


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    fx = sub.add_parser("fixture")
    fx.add_argument("raw", type=pathlib.Path)
    fx.add_argument("output", type=pathlib.Path)
    ap = sub.add_parser("apply")
    ap.add_argument("tables", nargs="+", type=pathlib.Path)
    args = parser.parse_args()
    if args.command == "fixture":
        fixture(args.raw, args.output)
    else:
        apply(args.tables)


if __name__ == "__main__":
    main()

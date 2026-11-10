#!/usr/bin/env python3
"""Classify the measured .8 MT168 lattice and apply only its proven forms."""

import argparse
import collections
import copy
import json
import pathlib


SRC = "rows-hidden-b300-stsm8-mt168-2026-11-08"
SCHEDULE = ((1 << 23) - 1) << 105
GROUPS = (("8,MT168", 0), ("2,8,MT168", 1), ("4,8,MT168", 2))


def mnemonic(text):
    if not text:
        return ""
    tokens = text.split()
    return tokens[1] if tokens[0].startswith("@") else tokens[0]


def field(shift, bits, extraction, token):
    return {"_src": SRC, "bits": bits, "extraction": extraction,
            "shift": shift, "token_idx": token}


def fields_for(uniform):
    fields = [field(12, 4, "guard", 0), field(24, 8, "sub_r0", 1),
              field(40, 24, "sub_imm2" if uniform else "sub_imm1", 1),
              field(32, 8, "reg", 2)]
    if uniform:
        fields.append(field(64, 8, "sub_ur1", 1))
    return fields


def mask_of(fields):
    mask = 0
    for item in fields:
        bits = ((1 << item["bits"]) - 1) << item["shift"]
        assert not mask & bits
        mask |= bits
    return mask


def measured_row(base, uniform, count):
    fields = fields_for(uniform)
    mask = mask_of(fields)
    template = base & ~mask & ~SCHEDULE
    template = (template & ~(0b11 << 72)) | count << 72
    if uniform:
        template |= 1 << 91
    return {"and_base": f"0x{template:032x}", "count": None, "fields": fields,
            "variable_mask": f"0x{mask:032x}", "_src": SRC,
            "row_probe": True,
            "_note": ("nvdisasm 13.3 V13.3.73 raw SM103/SM100: guard[15:12], base R[31:24], "
                      "signed offset[63:40], source R[39:32], bit75=.8, shape[79:78]=MT168; "
                      "count[73:72]=plain/.2/.4. INVALID3 count, other width/shape codes and "
                      "unmeasured/inert neighbor bits stay outside the row. This is vendor-text "
                      "and exact encoding evidence, not silicon execution or stmatrix semantics. "
                      + ("Explicit UR index[71:64] in [R+UR(+imm)]." if uniform
                         else "The UR window stays fixed at the no-index value."))}


def classification(record):
    text = record["nvidia_sass"]
    kind = record["kind"]
    if kind in ("single-bit", "frame-bit") \
            and any(int(label.split("=")[1]) >= 96 for label in record["labels"]
                    if label.startswith("bit=")):
        return "control-unclaimed"
    if kind == "control-bit":
        return "control-unclaimed"
    if kind == "existing-16-ari":
        return "legacy-anchor"
    if kind == "existing-16-aruri":
        return "reject-scoped"
    if record["rc"]:
        return "reject"
    if not text or "INVALID" in text or "???" in text:
        return "reject"
    if not mnemonic(text).startswith("STSM.8.MT168"):
        if (text or "").startswith(("STSM.16.M88", "STSM.16.MT88", "STSM.16.MT168")):
            return "legacy-anchor"
        return "reject-scoped"
    if any(label == "count=3" for label in record["labels"]):
        return "reject-scoped"
    if kind == "uniform":
        return "adopt" if (int(record["word"], 16) >> 64) & 0xff == 0 else "reject-scoped"
    if any(label.startswith("ur=") and label != "ur=0" for label in record["labels"]) \
            and not (int(record["word"], 16) >> 91) & 1:
        return "reject-scoped"
    if kind in ("production", "guard", "address", "data", "immediate-low",
                "immediate-high", "immediate-top", "immediate", "operand-cross", "count", "canonical-base",
                "aruri", "aruri-base", "aruri-cross"):
        return "adopt"
    if kind in ("single-bit", "frame-bit"):
        bit = int(next(label.split("=")[1] for label in record["labels"]
                       if label.startswith("bit=")))
        if bit in (*range(12, 16), *range(24, 64), 72, 73):
            return "adopt"
        if 64 <= bit < 72:
            word = int(record["word"], 16)
            return "adopt" if (word >> 91) & 1 or (word >> 64) & 0xff == 0 else "reject-scoped"
        if bit == 91:
            return "adopt"
    if kind == "aruri-count":
        return "adopt"
    return "reject-scoped"


def fixture(record, role):
    if role not in ("adopt", "reject", "reject-scoped"):
        return None
    word = int(record["word"], 16)
    text = record["nvidia_sass"]
    key = "STSM_ARURI_R" if role == "adopt" and (word >> 91) & 1 else "STSM_ARI_R"
    group = {"STSM.8.MT168": "8,MT168", "STSM.8.MT168.2": "2,8,MT168",
             "STSM.8.MT168.4": "4,8,MT168"}.get(mnemonic(text), "UNCLAIMED")
    return {"word": record["word"], "nvidia_sass": text, "kind": record["kind"],
            "labels": record["labels"], "role": role, "expected_key": key,
            "expected_group": group, "rc": record["rc"]}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--lattice", type=pathlib.Path, required=True)
    parser.add_argument("--aruri-lattice", type=pathlib.Path, required=True)
    parser.add_argument("--isa", type=pathlib.Path, required=True)
    parser.add_argument("--cubit", type=pathlib.Path, required=True)
    parser.add_argument("--out", type=pathlib.Path, required=True)
    parser.add_argument("--fixture-only", action="store_true")
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    by_target = {}
    fixtures = {}
    counts = {}
    for target in ("sm103", "sm100"):
        rows = [json.loads(line) for line in (args.lattice / f"{target}.jsonl").open()]
        rows.extend(json.loads(line) for line in (args.aruri_lattice / f"{target}.jsonl").open())
        by_target[target] = {row["word"]: row for row in rows}
        output = [fixture(row, classification(row)) for row in rows]
        fixtures[target] = [row for row in output if row is not None]
        counts[target] = dict(collections.Counter(row["role"] for row in fixtures[target]))
    assert by_target["sm103"].keys() == by_target["sm100"].keys()
    for word, left in by_target["sm103"].items():
        right = by_target["sm100"][word]
        assert (left["rc"], left["nvidia_sass"], left["stderr"]) == (
            right["rc"], right["nvidia_sass"], right["stderr"]), word
        assert fixture(left, classification(left)) == fixture(right, classification(right)), word
    production = [row for row in by_target["sm103"].values() if row["kind"] == "production"]
    assert len(production) > 300
    assert all(row["rc"] == 0 for row in production)
    for row in production:
        word = int(row["word"], 16)
        frame, ur = (word >> 91) & 1, (word >> 64) & 0xff
        assert frame or ur == 0, row
    for target, rows in fixtures.items():
        with (args.cubit / "tests/fixtures" / f"{target}_stsm8_mt168_nvdisasm.jsonl").open("w") as stream:
            for row in rows:
                stream.write(json.dumps(row, sort_keys=True) + "\n")
    if not args.fixture_only:
        summary = json.loads((args.lattice / "summary.json").read_text())
        base = int(summary["canonical_base"], 16)
        for arch in ("sm103a", "sm100a"):
            path = args.isa / f"{arch}.json"
            table = json.loads(path.read_text())
            entry = table["instructions"]["STSM_ARI_R"]
            new_names = {"8,MT168", "2,8,MT168", "4,8,MT168"}
            for name in new_names & set(entry["mod_groups"]):
                assert entry["mod_groups"][name]["_src"] == SRC
                del entry["mod_groups"][name]
            if "STSM_ARURI_R" in table["instructions"]:
                assert all(group["_src"] == SRC for group in
                           table["instructions"]["STSM_ARURI_R"]["mod_groups"].values())
                del table["instructions"]["STSM_ARURI_R"]
            for name, count in GROUPS:
                entry["mod_groups"][name] = measured_row(base, False, count)
            uniform = copy.deepcopy(entry)
            uniform["operand_sig"] = "ARURI_R"
            uniform["mod_groups"] = {name: measured_row(base, True, count)
                                     for name, count in GROUPS}
            table["instructions"]["STSM_ARURI_R"] = uniform
            provenance = table["_meta"]["provenance"]
            if SRC not in provenance["sources"]:
                provenance["rows_total"] += 6
                provenance["sources"][SRC] = {
                    "rows": 6,
                    "kind": "SM103/SM100 production STSM.8.MT168 count/address operand lattice",
                    "date": "2026-11-08",
                    "tool": "tools/probes/re_b300_stsm8.py",
                    "test": "tests/hidden_b300_stsm8_mt168.rs",
                }
            else:
                assert provenance["sources"][SRC]["rows"] == 6
            path.write_text(json.dumps(table, indent=1, ensure_ascii=True) + "\n")
    summary = {"production_unique_words": len(production), "scope_within_all_0844": 656,
               "counts_per_target": counts, "groups_per_table": 6, "source": SRC,
               "fixture_only": args.fixture_only}
    (args.out / "prepare-summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()

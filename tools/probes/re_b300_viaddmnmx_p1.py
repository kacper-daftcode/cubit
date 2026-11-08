#!/usr/bin/env python3
"""Measure and adopt only the two VIADDMNMX P1/!P1 UR operand orders."""

import argparse
import collections
import copy
import hashlib
import json
import pathlib
import subprocess
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from nvprobe import SCHEDULE, field_mask, load_table, row, save_table

SRC = "hidden-b300-viaddmnmx-p1-2026-11-08"
NVDISASM = pathlib.Path("/usr/local/cuda/bin/nvdisasm")
KEYS = {"plain": "VIADDMNMX_R_R_R_UR_P", "reversed": "VIADDMNMX_R_R_UR_R_P"}
ANCHORS = {
    "plain": 0x003FD6000B80010300000006020A7E46,
    "reversed": 0x003FD6000B80010300000006020A7C46,
}
NOTE = (
    "SM103/SM100 nvdisasm 13.3 controlled P1/!P1 words for both UR operand "
    "orders. The plain row reads pred at [89:87], not [11:9]; low [11:9]=7 "
    "is fixed and bit90 remains inversion. No silicon semantic claim here."
)
CLAIM_FORBID = [
    {"shift": 72, "bits": 2, "values": [0, 2, 3]},
    {"shift": 62, "bits": 1, "values": [1]},
    {"shift": 63, "bits": 1, "values": [1]},
    {"shift": 74, "bits": 1, "values": [1]},
    {"shift": 76, "bits": 1, "values": [1]},
]


def sha(path):
    return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()


def candidates():
    for family, anchor in ANCHORS.items():
        assert (anchor >> 87) & 7 == 7 and (anchor >> 90) & 1 == 0
        for inverted in (0, 1):
            word = (anchor & ~(7 << 87)) | (1 << 87) | (inverted << 90)
            operands = "R2, R3, UR6" if family == "plain" else "R2, UR6, R3"
            predicate = ("!" if inverted else "") + "P1"
            yield {"label": f"{family}_{'n' if inverted else ''}p1",
                   "family": family, "role": "adopt", "word": word,
                   "expected_text": f"VIADDMNMX R10, {operands}, {predicate}",
                   "changed_fields": {"predicate": [87, 89], "negation": [90, 90]},
                   "predicate_value": 1, "inverted": inverted}
    positive = (ANCHORS["plain"] & ~(7 << 87)) | (1 << 87)
    for label, word, text in (
        ("plain_relu_neighbour", positive | (1 << 76),
         "VIADDMNMX.RELU R10, R2, R3, UR6, P1"),
        ("plain_u32_neighbour", positive & ~(1 << 72),
         "VIADDMNMX.U32 R10, R2, R3, UR6, P1"),
    ):
        yield {"label": label, "family": "negative", "role": "neighbour-not-claimed",
               "word": word, "expected_text": text,
               "changed_fields": {"out_of_scope_neighbour": "one type or RELU bit from licensed plain P1"},
               "predicate_value": 1, "inverted": 0}
    for value in (0, 1):
        word = (ANCHORS["plain"] & ~(7 << 9)) | (value << 9)
        yield {"label": f"reject_old_low_field_{value}", "family": "negative",
               "role": "reject-scoped", "word": word, "expected_text": None,
               "changed_fields": {"legacy_discriminator_must_remain_7": [9, 11]},
               "predicate_value": None, "inverted": None}


def probe(destination):
    root = destination.parent / "dynamic-probe-inputs"
    root.mkdir(parents=True, exist_ok=True)
    records = []
    for candidate in candidates():
        anchor = ANCHORS[candidate["family"] if candidate["family"] in KEYS else "plain"]
        assert not ((candidate["word"] ^ anchor) >> 105)
        for target in ("SM103", "SM100"):
            path = root / f"{candidate['label']}-{target.lower()}.bin"
            path.write_bytes(candidate["word"].to_bytes(16, "little"))
            command = [str(NVDISASM), "-b", target, "-hex", str(path)]
            proc = subprocess.run(command, capture_output=True, text=True)
            text = None
            if "/*0000*/" in proc.stdout:
                text = proc.stdout.split("/*0000*/", 1)[1].split(";", 1)[0].strip()
            record = dict(candidate)
            record.update(target=target, word=f"{candidate['word']:032x}",
                          expected_key=KEYS.get(candidate["family"], ""),
                          control_bits_preserved=True, input=str(path),
                          input_sha256=sha(path), command=command, rc=proc.returncode,
                          stdout=proc.stdout, stderr=proc.stderr, text=text)
            if candidate["role"] in {"adopt", "neighbour-not-claimed"}:
                assert proc.returncode == 0 and text == candidate["expected_text"], record
            else:
                assert proc.returncode != 0 and text is None, record
                assert "Illegal instruction" in proc.stderr, record
            records.append(record)
    document = {
        "scope": "four P1/!P1 words plus two legacy-low-field negatives per target; CPU only",
        "source": SRC, "anchors": {name: f"{word:032x}" for name, word in ANCHORS.items()},
        "nvdisasm_version": subprocess.check_output([str(NVDISASM), "--version"], text=True),
        "nvdisasm_sha256": sha(NVDISASM), "records": records,
    }
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(document, indent=2) + "\n")
    return document


def fixtures(document, cubit):
    summaries = {}
    for target in ("sm103", "sm100"):
        selected = [r for r in document["records"] if r["target"] == target.upper()]
        assert len(selected) == 8
        output = []
        for record in selected:
            output.append({"word": record["word"], "nvidia_sass": record["text"],
                           "role": record["role"], "expected_group": "",
                           "expected_key": record["expected_key"], "kind": record["label"],
                           "family": record["family"], "rc": record["rc"]})
        path = cubit / "tests/fixtures" / f"{target}_viaddmnmx_p1_nvdisasm.jsonl"
        with path.open("w") as stream:
            for item in output:
                stream.write(json.dumps(item, sort_keys=True) + "\n")
        counts = collections.Counter(item["role"] for item in output)
        assert counts == {"adopt": 4, "reject-scoped": 2, "neighbour-not-claimed": 2}
        summaries[target] = {"records": len(output), "roles": dict(counts)}
    return summaries


def apply(document, isa):
    for arch in ("sm103a", "sm100a"):
        path = isa / f"{arch}.json"
        table = load_table(path)
        entry = table["instructions"][KEYS["plain"]]
        groups = entry["mod_groups"]
        old = groups[""]
        fields = copy.deepcopy(old["fields"])
        predicates = [field for field in fields if field["extraction"] == "pred"]
        assert len(predicates) == 1
        assert predicates[0]["shift"] in ({87} if old.get("_src") == SRC else {9})
        assert predicates[0]["bits"] == 3 and predicates[0]["token_idx"] == 5
        predicates[0]["shift"] = 87
        for field in fields:
            field["_src"] = SRC
        base = (ANCHORS["plain"] & ~SCHEDULE & ~field_mask(fields)) | (7 << 9)
        replacement = row(base, fields, SRC, NOTE)
        replacement["row_probe"] = True
        replacement["claim_forbid"] = copy.deepcopy(CLAIM_FORBID)
        groups[""] = replacement
        provenance = table["_meta"]["provenance"]
        provenance["sources"][SRC] = {
            "rows": 1, "date": "2026-11-08", "kind": NOTE,
            "tool": "tools/probes/re_b300_viaddmnmx_p1.py",
            "test": "tests/hidden_b300_viaddmnmx_p1.rs",
        }
        save_table(path, table)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--probe-out", type=pathlib.Path)
    parser.add_argument("--probe-in", type=pathlib.Path)
    parser.add_argument("--cubit", type=pathlib.Path,
                        default=pathlib.Path(__file__).resolve().parents[2])
    parser.add_argument("--isa", type=pathlib.Path)
    parser.add_argument("--summary-out", type=pathlib.Path, required=True)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    assert bool(args.probe_out) != bool(args.probe_in)
    document = probe(args.probe_out) if args.probe_out else json.loads(args.probe_in.read_text())
    summary = {"source": SRC, "targets": fixtures(document, args.cubit),
               "table_change": "one plain default row per architecture" if args.apply else "fixtures only"}
    if args.apply:
        assert args.isa
        apply(document, args.isa)
    args.summary_out.parent.mkdir(parents=True, exist_ok=True)
    args.summary_out.write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()

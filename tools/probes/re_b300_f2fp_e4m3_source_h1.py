#!/usr/bin/env python3
"""Measure and adopt only the clean BF16 E4M3 UNPACK_B H0/H1 group."""

import argparse
import collections
import hashlib
import json
import pathlib
import subprocess
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from nvprobe import SCHEDULE, field, field_mask, load_table, row, save_table


ROOT = pathlib.Path(__file__).resolve().parents[2]
SRC = "hidden-b300-f2fp-e4m3-source-h1-2026-11-08"
BASE = 0x03FFCA000200160500000002020B763E
NVDISASM = pathlib.Path("/usr/local/cuda/bin/nvdisasm")
KEY = "F2FP_R_R_R"
GROUP = "BF16,E4M3,UNPACK_B"
NOTE = (
    "SM103/SM100 nvdisasm 13.3 single-field BF16 E4M3 UNPACK_B selectors, "
    "registers, guard and reuse. No execution or performance claim is "
    "inferred from nvdisasm. "
    "Only the plain group is claimed; other types, modifiers, source bit72 "
    "and INVALID6/7 remain fail-closed."
)


def sha(path):
    return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()


def candidates():
    for source_h1 in (False, True):
        for selector in range(6):
            yield "adopt", f"source{int(source_h1)}_scale{selector}", (
                (BASE & ~(7 << 24)) | (int(source_h1) << 88) | (selector << 24))
    for label, bit, token in (("ra_reuse", 123, 2), ("rb_reuse", 124, 3)):
        yield "adopt", label, BASE | (1 << bit) | (1 << 109)
    yield "adopt", "guard_nondefault", BASE ^ (1 << 12)
    yield "adopt", "registers_nondefault", BASE ^ (1 << 16) ^ (7 << 32) ^ (5 << 32) ^ (7 << 64) ^ (5 << 64)
    for source_h1, selector in ((False, 6), (True, 7)):
        yield "unclaimed", f"invalid_selector_{int(source_h1)}_{selector}", (
            (BASE & ~(7 << 24)) | (int(source_h1) << 88) | (selector << 24))
    for label, word in (
            ("e3m2_neighbour", 0x03FFCA000204160500000002020B763E),
            ("relu_not_claimed", BASE | (1 << 75)),
            ("satfinite_not_claimed", BASE | (1 << 77)),
            ("opaque_source_bit72", BASE | (1 << 72)),
            ("unclaimed_output_bit76_clear", BASE & ~(1 << 76))):
        yield "unclaimed", label, word


def probe(out):
    raw_dir = out / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)
    records = []
    assert len({word for _, _, word in candidates()}) == 23
    for role, label, word in candidates():
        for target in ("SM103", "SM100"):
            path = raw_dir / f"{label}-{target}.bin"
            path.write_bytes(word.to_bytes(16, "little"))
            command = [str(NVDISASM), "-b", target, "-hex", str(path)]
            proc = subprocess.run(command, capture_output=True, text=True)
            text = None
            if "/*0000*/" in proc.stdout:
                text = proc.stdout.split("/*0000*/", 1)[1].split(";", 1)[0].strip()
            if role == "adopt":
                assert proc.returncode == 0 and text and "F2FP.BF16.E4M3.UNPACK_B" in text, (label, text)
                if label.startswith("source"):
                    source = int(label[6])
                    selector = int(label.rsplit("scale", 1)[1])
                    suffix = ["H0", "H1", "B0", "B1", "B2", "B3"][selector]
                    expected = f"F2FP.BF16.E4M3.UNPACK_B R11, R2{'.H1' if source else ''}, R5.{suffix}"
                    assert text == expected, (label, text, expected)
                elif label.endswith("reuse"):
                    operand = "R2.reuse" if label.startswith("ra") else "R5.reuse.B0"
                    assert operand in text, (label, text)
            else:
                assert proc.returncode == 0 and text, (label, proc.stderr)
                if label == "opaque_source_bit72":
                    assert text == "F2FP.BF16.E4M3.UNPACK_B R11, R2, R5.B0", (label, text)
                else:
                    assert "F2FP.BF16.E4M3.UNPACK_B" not in text or "INVALID" in text, (label, text)
            records.append({"case": label, "role": role, "target": target,
                            "word": f"{word:032x}", "text": text, "input": str(path),
                            "input_sha256": sha(path), "command": command,
                            "rc": proc.returncode, "stdout": proc.stdout, "stderr": proc.stderr,
                            "expected_key": KEY, "expected_group": GROUP})
    version = subprocess.check_output([str(NVDISASM), "--version"], text=True)
    document = {"source": SRC, "nvdisasm_version": version,
                "nvdisasm_sha256": sha(NVDISASM), "records": records}
    (out / "probe.json").write_text(json.dumps(document, indent=2) + "\n")
    return document


def fixtures(document, cubit):
    summary = {}
    for target in ("sm103", "sm100"):
        rows = [r for r in document["records"] if r["target"] == target.upper()]
        assert len(rows) == 23
        path = cubit / "tests/fixtures" / f"{target}_f2fp_e4m3_source_h1_nvdisasm.jsonl"
        with path.open("w") as stream:
            for r in rows:
                stream.write(json.dumps({"word": r["word"], "nvidia_sass": r["text"],
                    "nvdisasm": document["nvdisasm_version"].strip().splitlines()[-1],
                    "nvdisasm_sha256": document["nvdisasm_sha256"], "rc": r["rc"],
                    "role": r["role"], "expected_key": KEY, "expected_group": GROUP,
                    "kind": r["case"]}, sort_keys=True) + "\n")
        summary[target] = dict(collections.Counter(r["role"] for r in rows))
    return summary


def apply(isa):
    for arch in ("sm103a", "sm100a"):
        path = isa / f"{arch}.json"
        table = load_table(path)
        groups = table["instructions"][KEY]["mod_groups"]
        assert GROUP not in groups
        fields = [
            field(12, 4, "guard", 0, SRC),
            field(16, 8, "reg", 1, SRC),
            field(32, 8, "reg", 2, SRC),
            field(123, 1, "reuse", 2, SRC),
            field(64, 8, "reg", 3, SRC),
            field(24, 3, "f2fp_scale_sel", 3, SRC),
            field(124, 1, "reuse", 3, SRC),
            field(88, 1, "opmod:H1", 2, SRC),
        ]
        result = row(BASE & ~field_mask(fields) & ~SCHEDULE, fields, SRC, NOTE)
        result["claim_forbid"] = [{"shift": 24, "bits": 3, "values": [6, 7]}]
        groups[GROUP] = result
        provenance = table["_meta"]["provenance"]
        provenance["sources"][SRC] = {"rows": 1, "date": "2026-11-08", "kind": NOTE,
            "tool": "tools/probes/re_b300_f2fp_e4m3_source_h1.py",
            "test": "tests/hidden_b300_f2fp_e4m3_source_h1.rs"}
        provenance["rows_total"] += 1
        save_table(path, table)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--probe-out", type=pathlib.Path, required=True)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--summary-out", type=pathlib.Path, required=True)
    args = parser.parse_args()
    document = probe(args.probe_out)
    summary = {"source": SRC, "fixtures": fixtures(document, ROOT), "applied": args.apply}
    if args.apply:
        apply(ROOT.parent / "isa")
    args.summary_out.write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()

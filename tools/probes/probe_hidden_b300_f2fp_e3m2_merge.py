#!/usr/bin/env python3
"""Measure E3M2 PACK_AB_MERGE_C from a licensed production E2M1 neighbour."""

import argparse
import concurrent.futures
import hashlib
import json
import pathlib
import re
import subprocess
import threading


ANCHOR = 0x000FE2000460700A000000080908723E
EXPECTED = "F2FP.SATFINITE.E3M2.F32.PACK_AB_MERGE_C R8, R9, R8, R10"
TEXT = re.compile(r"/\*0000\*/\s*(.*?)\s*(?:;|$)", re.MULTILINE)


def put(word, shift, bits, value):
    return (word & ~(((1 << bits) - 1) << shift)) | (value << shift)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--nvdisasm", default="/usr/local/cuda/bin/nvdisasm")
    parser.add_argument("--out", required=True, type=pathlib.Path)
    parser.add_argument("--cubit", required=True)
    parser.add_argument("--table", required=True)
    parser.add_argument("--jobs", type=int, default=12)
    parser.add_argument("--extended", action="store_true")
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    version = subprocess.check_output([args.nvdisasm, "--version"], text=True)
    digest = hashlib.sha256(pathlib.Path(args.nvdisasm).read_bytes()).hexdigest()
    cases = {}

    def add(word, kind, labels, source):
        item = cases.setdefault(word, {"kind": kind, "word": word,
                                       "labels": [], "source": []})
        item["labels"] += labels if isinstance(labels, list) else [labels]
        item["source"] += source if isinstance(source, list) else [source]

    # These real H records remain E2M1 controls, never synthetic E3M2 production witnesses.
    add(0x000FC2000420700A000000080908723E, "production-neighbour",
        "H-E2M1-R8-R9-R8-R10", "survey/fixtures/forms_undecodable_sm103a.jsonl:0x41e0")
    add(0x000FC200042070FF0000000A0B0A723E, "production-neighbour",
        "H-E2M1-R10-R11-R10-RZ", "survey/fixtures/forms_undecodable_sm103a.jsonl:0x41a0")
    add(ANCHOR, "anchor", "E3M2-type-bit86",
        "controlled E2M1 PACK_AB_MERGE_C anchor; only type bit 86 changed")
    for bit in range(128):
        add(ANCHOR ^ (1 << bit), "single-bit", f"bit={bit}",
            "one bit changed from controlled E3M2 PACK_AB_MERGE_C anchor")
    for guard in range(16):
        add(put(ANCHOR, 12, 4, guard), "guard", f"guard={guard}", "complete guard map")
    for shift, name in [(16, "rd"), (24, "ra"), (32, "rb"), (64, "rc")]:
        for value in (0, 1, 7, 42, 127, 254, 255):
            add(put(ANCHOR, shift, 8, value), "register", f"register:{name}={value}",
                f"one proposed 8-bit register window: {name}")
    for shift in (72, 73, 75, 77, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95):
        for value in (0, 1):
            add(put(ANCHOR, shift, 1, value), "field-control", f"bit={shift}:value={value}",
                "independent zero/one recheck of one proposed or negative field")
    for shift, name in [(122, "ra"), (123, "rb"), (124, "rc")]:
        for value in (0, 1):
            add(put(ANCHOR, shift, 1, value), "reuse-control", f"{name}:reuse={value}",
                "reuse separated from instruction opcode/operand field measurements")
    if args.extended:
        for value in range(32):
            add(put(ANCHOR, 83, 5, value), "type-window", f"type[87:83]={value}",
                "full five-bit neighbouring type/validity window; no type alias assumed")
        for shift, first in [(75, "relu"), (81, "rs")]:
            for bit, bits, name in [(16, 8, "rd"), (24, 8, "ra"), (32, 8, "rb"), (64, 8, "rc")]:
                for value in (0, 1, 255):
                    add(put(put(ANCHOR, shift, 1, first == "relu"), bit, bits, value),
                        "modifier-register", f"{first}:{name}={value}",
                        "modifier independently combined with all four register windows")
        for flags in range(4):
            word = put(put(ANCHOR, 75, 1, flags & 1), 81, 1, (flags >> 1) & 1)
            for guard in range(16):
                add(put(word, 12, 4, guard), "modifier-guard",
                    f"modifier-flags={flags}:guard={guard}", "all modifier pairs and guards")
            for bit in (122, 123, 124):
                add(word ^ (1 << bit), "modifier-reuse",
                    f"modifier-flags={flags}:reuse-bit={bit}",
                    "each reuse against RELU/RS without assigning semantics to reuse")

    def measure(job):
        target, case = job
        scratch = args.out / f".scratch-{target}-{threading.get_ident()}.bin"
        word = case["word"]
        scratch.write_bytes(word.to_bytes(16, "little"))
        proc = subprocess.run([args.nvdisasm, "-b", target, "-hex", str(scratch)],
                              capture_output=True, text=True)
        match = TEXT.search(proc.stdout)
        return {**case, "word": f"{word:032x}", "target": target,
                "rc": proc.returncode, "stdout": proc.stdout, "stderr": proc.stderr,
                "nvidia_sass": match.group(1).strip() if match else None,
                "nvdisasm": version, "nvdisasm_sha256": digest}

    summary = {"anchor": f"{ANCHOR:032x}", "expected": EXPECTED,
               "nvdisasm": version, "nvdisasm_sha256": digest, "targets": {}}
    for target in ("SM103", "SM100"):
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
            rows = list(pool.map(measure, [(target, case) for case in cases.values()]))
        with (args.out / f"{target.lower()}.jsonl").open("w") as fh:
            for row in rows:
                fh.write(json.dumps(row) + "\n")
        anchor = [r for r in rows if r["kind"] == "anchor"]
        assert len(anchor) == 1 and anchor[0]["rc"] == 0
        assert anchor[0]["nvidia_sass"] == EXPECTED, anchor[0]
        summary["targets"][target] = {
            "records": len(rows), "accepted": sum(r["rc"] == 0 for r in rows),
            "rejected": sum(r["rc"] != 0 for r in rows),
            "unnamed": sum(r["rc"] == 0 and not r["nvidia_sass"] for r in rows)}
    proc = subprocess.run([args.cubit, "decode", "-t", args.table, f"0x{ANCHOR:032x}"],
                          capture_output=True, text=True)
    summary["canonical_cubit"] = {"command": [args.cubit, "decode", "-t", args.table,
        f"0x{ANCHOR:032x}"], "rc": proc.returncode, "stdout": proc.stdout, "stderr": proc.stderr}
    (args.out / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()

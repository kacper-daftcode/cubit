#!/usr/bin/env python3
"""Measure QADD4 on SM103/SM100 with full raw nvdisasm evidence."""

import argparse
import concurrent.futures
import hashlib
import json
import pathlib
import re
import subprocess
import threading


SCHEDULE_MASK = ((1 << 23) - 1) << 105
CONTROL = 0x000FE200000000000000000000000000
TEXT = re.compile(r"/\*0000\*/\s*(.*?)\s*(?:;|$)", re.MULTILINE)
ORIGINAL = 0x081FE4000501B800200000040B16727D
# Rebuild the canonical residue-free anchor explicitly from measured fields.
BASE = (0x27D | (7 << 12) | (22 << 16) | (11 << 24) | (0 << 64) |
        (6 << 74) | (5 << 77) | (0 << 85) | (1 << 88) | (1 << 90) | CONTROL)
EXPECTED = "QADD4.E4M3x4.E2M1x4.SATFINITE R22, R11.N3210, R0.B3210"


def identify(nvdisasm):
    version = subprocess.check_output([nvdisasm, "--version"], text=True)
    return version, hashlib.sha256(pathlib.Path(nvdisasm).read_bytes()).hexdigest()


def put(word, shift, bits, value):
    return (word & ~(((1 << bits) - 1) << shift)) | (value << shift)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--nvdisasm", required=True)
    parser.add_argument("--cubit", required=True)
    parser.add_argument("--table", required=True)
    parser.add_argument("--out", required=True, type=pathlib.Path)
    parser.add_argument("--targets", nargs="+", default=["SM103", "SM100"])
    parser.add_argument("--jobs", type=int, default=4)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    version, digest = identify(args.nvdisasm)
    local = threading.local()

    def measure(item):
        target, case = item
        if not hasattr(local, "scratch"):
            local.scratch = args.out / f".scratch-{target}-{threading.get_ident()}.bin"
        word = case["word"]
        local.scratch.write_bytes(word.to_bytes(16, "little"))
        proc = subprocess.run([args.nvdisasm, "-b", target, "-hex", str(local.scratch)],
                              capture_output=True, text=True)
        match = TEXT.search(proc.stdout)
        return {
            **case,
            "target": target,
            "word": f"{word:032x}",
            "rc": proc.returncode,
            "stdout": proc.stdout,
            "stderr": proc.stderr,
            "nvidia_sass": match.group(1).strip() if match else None,
            "nvdisasm": version,
            "nvdisasm_sha256": digest,
        }

    cases = {}

    def add(word, kind, labels, source):
        entry = cases.setdefault(word, {
            "kind": kind,
            "labels": [],
            "word": word,
            "source": [],
        })
        entry["labels"].extend(labels if isinstance(labels, list) else [labels])
        entry["source"].extend(source if isinstance(source, list) else [source])

    source = "residue-free controlled QADD4 anchor; not a production witness"
    add(BASE, "anchor-canonical", "canonical", source)
    add((ORIGINAL & ~SCHEDULE_MASK) | CONTROL, "anchor-original-core",
        "original-core", "QMUL4 anchor A with only opcode bit zero changed; valid normalized control")
    add(ORIGINAL, "anchor-original-raw-control", "original-raw-control",
        "QMUL4 raw control retained deliberately; this is not a QADD4 production control witness")
    for bit in range(105):
        add(BASE ^ (1 << bit), "single-bit", f"bit={bit}",
            f"one instruction bit changed from the canonical QADD4 anchor: {bit}")
    for bit in range(105, 128):
        add(BASE ^ (1 << bit), "schedule-bit", f"schedule:bit={bit}",
            f"one schedule/reuse bit changed from the canonical QADD4 anchor: {bit}")

    for shift, bits, name in [(16, 8, "rd"), (24, 8, "ra"), (64, 8, "rc")]:
        for value in (0, 1, 42, 127, 254, 255):
            add(put(BASE, shift, bits, value), "register", f"register:{name}={value}",
                f"canonical QADD4; [{shift}:{shift + bits - 1}]={value}")
    for guard in range(16):
        add(put(BASE, 12, 4, guard), "guard", f"guard={guard}", "full guard map")
    for token, shift in [("ra", 72), ("rc", 83)]:
        for value in range(4):
            add(put(BASE, shift, 2, value), "sign", f"sign:{token}={value}",
                f"{token} abs/neg window [{shift + 1}:{shift}]={value}")
    for shift, name in [(74, "ra"), (85, "rc")]:
        for value in range(8):
            add(put(BASE, shift, 3, value), "selector", f"selector:{name}={value}",
                f"{name} selector window [{shift + 2}:{shift}]={value}")
    for a_selector in range(8):
        for c_selector in range(8):
            word = put(put(BASE, 74, 3, a_selector), 85, 3, c_selector)
            add(word, "selector-cross", f"selector-cross:{a_selector}:{c_selector}",
                "all Ra/Rc selector pairs")
    for source_type in range(8):
        add(put(BASE, 77, 3, source_type), "source-type", f"source-type={source_type}",
            "source type [79:77]")
        for a_selector in range(8):
            for c_selector in range(8):
                word = put(put(put(BASE, 77, 3, source_type), 74, 3, a_selector), 85, 3, c_selector)
                add(word, "source-selector-cross",
                    f"source-selector-cross:{source_type}:{a_selector}:{c_selector}",
                    "every source type against both complete selector maps")
    for dest_type in range(4):
        add(put(BASE, 88, 2, dest_type), "dest-type", f"dest-type={dest_type}",
            "destination type [89:88]")
        for source_type in range(8):
            word = put(put(BASE, 88, 2, dest_type), 77, 3, source_type)
            add(word, "type-cross", f"type-cross:{dest_type}:{source_type}",
                "all destination/source type pairs")
    for sat in range(2):
        add(put(BASE, 90, 1, sat), "satfinite", f"SATFINITE={sat}", "SATFINITE bit 90")

    summary = {
        "canonical_word": f"{BASE:032x}",
        "canonical_expected": EXPECTED,
        "nvdisasm": version,
        "nvdisasm_sha256": digest,
        "targets": {},
    }
    for target in args.targets:
        jobs = [(target, case) for case in cases.values()]
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
            rows = list(pool.map(measure, jobs))
        path = args.out / f"{target.lower()}.jsonl"
        with path.open("w") as fh:
            for row in rows:
                fh.write(json.dumps(row) + "\n")
        anchors = [row for row in rows if row["kind"] == "anchor-canonical"]
        assert len(anchors) == 1 and anchors[0]["rc"] == 0
        assert anchors[0]["nvidia_sass"] == EXPECTED, anchors[0]
        summary["targets"][target] = {
            "records": len(rows),
            "accepted": sum(row["rc"] == 0 for row in rows),
            "rejected": sum(row["rc"] != 0 for row in rows),
            "unnamed": sum(row["rc"] == 0 and not row["nvidia_sass"] for row in rows),
        }
    proc = subprocess.run([args.cubit, "decode", "-t", args.table, f"0x{BASE:032x}"],
                          capture_output=True, text=True)
    summary["canonical_cubit"] = {
        "command": [args.cubit, "decode", "-t", args.table, f"0x{BASE:032x}"],
        "rc": proc.returncode,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
    }
    (args.out / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()

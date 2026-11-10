#!/usr/bin/env python3
"""Reproduce QMUL4's SM103/SM100 vendor text, keeping schedule bits separate."""

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
SURVEY = "/root/sm103a/inbox-hgx02/2026-11-07-k31-prefill-gaps/survey/SURVEY.md"
ANCHORS = [
    ("A", 0x081FE4000501B800200000040B16727C, 396,
     "QMUL4.E4M3x4.E2M1x4.E4M3x4.SATFINITE R22, R11.N3210, R4.B0"),
    ("B", 0x080FE2000501B400200000040B17727C, 397,
     "QMUL4.E4M3x4.E2M1x4.E4M3x4.SATFINITE R23, R11.N7654, R4.B0"),
    ("C", 0x081FE2000501BC00000000542E5C727C, 398,
     "QMUL4.E4M3x4.E2M1x4.E4M3x4.SATFINITE R92, R46.N6420, R84.B3210"),
]
TEXT = re.compile(r"/\*0000\*/\s*(.*?)\s*(?:;|$)", re.MULTILINE)


def identify(nvdisasm):
    version = subprocess.check_output([nvdisasm, "--version"], text=True)
    return version, hashlib.sha256(pathlib.Path(nvdisasm).read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--nvdisasm", required=True)
    parser.add_argument("--cubit", required=True)
    parser.add_argument("--table", required=True)
    parser.add_argument("--out", required=True, type=pathlib.Path)
    parser.add_argument("--targets", nargs="+", default=["SM103", "SM100"])
    parser.add_argument("--jobs", type=int, default=4)
    parser.add_argument("--extended", action="store_true")
    args = parser.parse_args()

    args.out.mkdir(parents=True, exist_ok=True)
    version, digest = identify(args.nvdisasm)
    local = threading.local()

    def measure(item):
        target, case = item
        scratch = args.out / f".scratch-{target}-{threading.get_ident()}.bin"
        if not hasattr(local, "scratch"):
            local.scratch = scratch
        scratch = local.scratch
        word = case["word"]
        scratch.write_bytes(word.to_bytes(16, "little"))
        proc = subprocess.run([args.nvdisasm, "-b", target, "-hex", str(scratch)],
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

    cases = []
    for name, word, line, expected in ANCHORS:
        for core in (False, True):
            cases.append((f"anchor-{name}-{'core' if core else 'raw-control'}", {
                "kind": f"anchor-{name}-{'core' if core else 'raw-control'}",
                "core_word": f"{word & ~SCHEDULE_MASK:032x}",
                "word": word if not core else (word & ~SCHEDULE_MASK) | CONTROL,
                "expected": expected,
                "source": f"{SURVEY}:{line}",
                "lattice": bool(core),
            }))
    base = ANCHORS[0][1] & ~SCHEDULE_MASK
    for bit in range(105):
        word = base ^ (1 << bit)
        cases.append((f"bit-{bit}", {
            "kind": "single-bit",
            "bit": bit,
            "value": (word >> bit) & 1,
            "core_word": f"{word:032x}",
            "word": word | CONTROL,
            "lattice": True,
            "source": f"one bit changed from anchor A, schedule zeroed then {CONTROL:032x}",
        }))

    if args.extended:
        # Merge labels for the same word instead of re-measuring enum members
        # that are also present in a cross. Each word still has a complete record.
        extra = {}

        def add(word, label, source):
            entry = extra.setdefault(word, {
                "kind": "enum-lattice",
                "labels": [],
                "core_word": f"{word:032x}",
                "word": word | CONTROL,
                "lattice": True,
                "source": [],
            })
            entry["labels"].append(label)
            entry["source"].append(source)

        def put(word, shift, bits, value):
            return (word & ~(((1 << bits) - 1) << shift)) | (value << shift)

        for shift, bits, name in [(59, 3, "b-sel"), (74, 3, "a-sel"),
                                  (77, 3, "b-type"), (80, 3, "c-type"),
                                  (88, 2, "d-type"), (90, 1, "satfinite")]:
            for value in range(1 << bits):
                add(put(base, shift, bits, value), f"enum:{name}={value}",
                    f"anchor A; [{shift}:{shift + bits - 1}]={value}")
        for b_sel in range(8):
            for a_sel in range(8):
                word = put(put(base, 59, 3, b_sel), 74, 3, a_sel)
                add(word, f"cross:b-sel={b_sel},a-sel={a_sel}",
                    "anchor A; both selector windows enumerated")
        for b_type in range(8):
            for b_sel in range(8):
                for a_sel in range(8):
                    word = put(put(put(base, 77, 3, b_type), 59, 3, b_sel), 74, 3, a_sel)
                    add(word, f"cross:b-type={b_type},b-sel={b_sel},a-sel={a_sel}",
                        "anchor A; second type against both selector windows")
        for b_type in range(8):
            for c_type in range(8):
                for d_type in range(4):
                    word = put(put(put(base, 77, 3, b_type), 80, 3, c_type), 88, 2, d_type)
                    add(word, f"cross:b-type={b_type},c-type={c_type},d-type={d_type}",
                        "anchor A; all three type windows enumerated")
        for shift, bits, name in [(16, 8, "rd"), (24, 8, "ra"), (32, 8, "rb")]:
            for value in (0, 1, 42, 127, 254, 255):
                add(put(base, shift, bits, value), f"register:{name}={value}",
                    f"anchor A; [{shift}:{shift + bits - 1}] register test")
        for guard in range(16):
            add(put(base, 12, 4, guard), f"guard={guard}", "full guard-map check")
        for token, shift in [("ra", 72), ("rb", 62)]:
            for value in range(4):
                add(put(base, shift, 2, value), f"sign:{token}={value}",
                    f"anchor A; neg/abs at [{shift + 1}:{shift}]")
        for bit in range(105, 128):
            add(base ^ (1 << bit), f"schedule:bit={bit}",
                "one schedule/reuse bit on anchor A; no control normalization")
        for word, case in extra.items():
            cases.append((f"extended-{word:032x}", case))

    summary = {"nvdisasm": version, "nvdisasm_sha256": digest, "targets": {}}
    for target in args.targets:
        jobs = [(target, case) for _, case in cases]
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
            rows = list(pool.map(measure, jobs))
        path = args.out / f"{target.lower()}.jsonl"
        with path.open("w") as fh:
            for row in rows:
                fh.write(json.dumps(row) + "\n")
        anchor_rows = [r for r in rows if r["kind"].endswith("core")]
        assert len(anchor_rows) == len(ANCHORS)
        for row in anchor_rows:
            assert row["rc"] == 0, row
            assert row["nvidia_sass"] == row["expected"], row
        summary["targets"][target] = {
            "records": len(rows),
            "anchors": len(anchor_rows),
            "accepted": sum(r["rc"] == 0 for r in rows),
            "rejected": sum(r["rc"] != 0 for r in rows),
            "unnamed": sum(r["rc"] == 0 and not r["nvidia_sass"] for r in rows),
        }

    canonical_word = f"{(ANCHORS[0][1] & ~SCHEDULE_MASK) | CONTROL:032x}"
    proc = subprocess.run([args.cubit, "decode", "-t", args.table, "0x" + canonical_word],
                          capture_output=True, text=True)
    summary["canonical_cubit"] = {
        "command": [args.cubit, "decode", "-t", args.table, "0x" + canonical_word],
        "rc": proc.returncode,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
    }
    (args.out / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()

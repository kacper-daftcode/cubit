#!/usr/bin/env python3
"""Measure USETMAXREG.TRY_ALLOC.CTAPOOL with complete raw nvdisasm I/O."""

import argparse
import concurrent.futures
import hashlib
import json
import pathlib
import re
import subprocess
import threading


INBOX = pathlib.Path("/root/sm103a/inbox-hgx02/2026-11-07-k31-prefill-gaps")
BUG407 = pathlib.Path(
    "/root/sm103a/pubwave/hidden-b300/worktrees/cubit-ldsm-m816-counts/"
    "tests/bug407_data.inc"
)
TEXT_RE = re.compile(r"/\*0000\*/\s*(.*?)\s*;", re.MULTILINE)
BUG407_RE = re.compile(
    r'\(0x([0-9a-f]+)u128, "(USETMAXREG\.TRY_ALLOC\.CTAPOOL [^"]+)"\)'
)
SCHEDULE_MASK = ((1 << 23) - 1) << 105


def put(word, shift, bits, value):
    return (word & ~(((1 << bits) - 1) << shift)) | (value << shift)


def production_records():
    records = {}
    for path in sorted((INBOX / "survey/fixtures").glob("*.jsonl")):
        with path.open() as stream:
            for line_number, line in enumerate(stream, 1):
                if '"USETMAXREG.TRY_ALLOC.CTAPOOL ' not in line:
                    continue
                original = json.loads(line)
                word = int(original["word"], 16)
                target = original["target"]
                if target not in ("SM103", "SM100"):
                    continue
                key = (word, target)
                item = records.setdefault(key, [])
                item.append({
                    "path": str(path.relative_to(INBOX)),
                    "line": line_number,
                    "original": original,
                })
    return records


def historical_records():
    # These are pre-existing cubit fixtures. Re-measure, do not inherit their claim.
    text = BUG407.read_text()
    return {
        int(word, 16): {
            "path": str(BUG407),
            "text": text_for_word,
            "scope": "historical BUG407 fixture re-measured here",
        }
        for word, text_for_word in BUG407_RE.findall(text)
    }


def cases_from_sources():
    h_records = production_records()
    h_words = sorted({word for word, _ in h_records})
    if not h_words:
        raise RuntimeError("no delivered production TRY_ALLOC words")
    base = h_words[0]
    cases = {}

    def add(word, kind, labels, sources=()):
        item = cases.setdefault(word, {
            "word": f"{word:032x}",
            "core_word": f"{word & ~SCHEDULE_MASK:032x}",
            "kind": kind,
            "labels": set(),
            "sources": [],
            "expected_texts": set(),
        })
        item["labels"].update(labels)
        item["sources"].extend(sources)
        item["expected_texts"].update(
            source["original"]["text"]
            for source in sources
            if "original" in source
        )

    for (word, _target), sources in h_records.items():
        add(word, "production", ["delivered-H"], sources)
    for word, source in historical_records().items():
        add(word, "historical", ["BUG407"], [source])

    for bit in range(105):
        add(base ^ (1 << bit), "single-bit", [f"bit={bit}"])
    for bit in range(105, 128):
        add(base ^ (1 << bit), "control-bit", [f"bit={bit}"])
    for value in range(1024):
        add(put(base, 32, 10, value), "immediate", [f"imm10={value}"])
    for value in range(8):
        add(put(base, 81, 3, value), "up-destination", [f"up3={value}"])
    for value in range(16):
        add(put(base, 12, 4, value), "guard", [f"guard4={value}"])
    for shift, label in ((16, "operand16"), (24, "operand24"), (64, "operand64")):
        for value in range(256):
            add(put(base, shift, 8, value), "operand-neighborhood",
                [f"{label}={value}"])
    for up in range(8):
        for guard in range(16):
            for immediate in (0, 1, 0xa0, 0x3ff):
                word = put(put(put(base, 81, 3, up), 12, 4, guard), 32, 10, immediate)
                add(word, "cross", [f"up={up},guard={guard},imm={immediate:#x}"])

    result = []
    for item in cases.values():
        item["labels"] = sorted(item["labels"])
        item["expected_texts"] = sorted(item["expected_texts"])
        result.append(item)
    return base, result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--nvdisasm", default="/usr/local/cuda/bin/nvdisasm")
    parser.add_argument("--cubit", required=True)
    parser.add_argument("--table", required=True)
    parser.add_argument("--out", required=True, type=pathlib.Path)
    parser.add_argument("--jobs", type=int, default=8)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    version = subprocess.check_output([args.nvdisasm, "--version"], text=True)
    nv_hash = hashlib.sha256(pathlib.Path(args.nvdisasm).read_bytes()).hexdigest()
    base, cases = cases_from_sources()
    local = threading.local()

    def measure(job):
        target, case = job
        if not hasattr(local, "scratch"):
            local.scratch = args.out / f".scratch-{target}-{threading.get_ident()}.bin"
        word = int(case["word"], 16)
        local.scratch.write_bytes(word.to_bytes(16, "little"))
        proc = subprocess.run(
            [args.nvdisasm, "-b", target, "-hex", str(local.scratch)],
            text=True, capture_output=True,
        )
        match = TEXT_RE.search(proc.stdout)
        row = dict(case)
        row.update({
            "target": target,
            "rc": proc.returncode,
            "stdout": proc.stdout,
            "stderr": proc.stderr,
            "nvidia_sass": match.group(1).strip() if match else None,
            "nvdisasm": version,
            "nvdisasm_sha256": nv_hash,
        })
        local.scratch.unlink()
        return row

    summary = {
        "base_word": f"{base:032x}",
        "nvdisasm": version,
        "nvdisasm_sha256": nv_hash,
        "scope": "SASS text only; no CUDA launches",
        "targets": {},
    }
    for target in ("SM103", "SM100"):
        jobs = [(target, case) for case in cases]
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
            rows = list(pool.map(measure, jobs))
        for row in rows:
            if row["expected_texts"]:
                assert row["rc"] == 0, row
                assert row["nvidia_sass"] in row["expected_texts"], row
        path = args.out / f"{target.lower()}.jsonl"
        with path.open("w") as stream:
            for row in rows:
                stream.write(json.dumps(row, sort_keys=True) + "\n")
        summary["targets"][target] = {
            "records": len(rows),
            "accepted": sum(row["rc"] == 0 for row in rows),
            "rejected": sum(row["rc"] != 0 for row in rows),
            "accepted_unnamed": sum(row["rc"] == 0 and not row["nvidia_sass"] for row in rows),
        }
    parent_probes = []
    for word in sorted({int(case["word"], 16) for case in cases
                        if case["kind"] in ("production", "historical")}):
        proc = subprocess.run(
            [args.cubit, "decode", "-t", args.table, f"0x{word:032x}"],
            text=True, capture_output=True,
        )
        parent_probes.append({
            "word": f"{word:032x}",
            "command": proc.args,
            "rc": proc.returncode,
            "stdout": proc.stdout,
            "stderr": proc.stderr,
        })
    (args.out / "parent-decode.json").write_text(json.dumps(parent_probes, indent=2) + "\n")
    (args.out / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()

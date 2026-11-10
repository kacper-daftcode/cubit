#!/usr/bin/env python3
"""Bounded full-word nvdisasm lattice for LDSM M816 x1/x2/x4 on SM103/SM100.

The six measured ptxas donors and delivered H witnesses are read-only inputs.
Every generated crossing is explicitly marked derived, never relabelled as H.
This command is CPU-only and never loads or executes a cubin.
"""

import argparse
import collections
import concurrent.futures
import hashlib
import json
import pathlib
import re
import subprocess
import threading


ROOT = pathlib.Path("/root/sm103a")
SILICON = ROOT / "pubwave/hidden-b300/ldsm-unpack-counts-silicon"
OLD = ROOT / "pubwave/hidden-b300/ldsm-unpack/lattice"
HFIXTURES = ROOT / "inbox-hgx02/2026-11-07-k31-prefill-gaps/survey/fixtures"
TEXT = re.compile(r"/\*0000\*/\s*(.*?)\s*(?:;|$)", re.MULTILINE)
COUNTS = (None, ".2", ".4")
TYPES = ("U4x16P64TO8", "U6x16P32TO8")
KIND = {(typ, count): code
        for (typ, prefix), codes in {("U4x16P64TO8", 0xa8): range(3),
                                     ("U6x16P32TO8", 0xb0): range(3)}.items()
        for count, code in zip(COUNTS, (prefix + i for i in codes))}
ADDRESS = ("ARI", "AURI", "ARURI")
SRC = "rows-hidden-b300-ldsm-m816-counts-2026-11-08"


def put(word, shift, bits, value):
    mask = ((1 << bits) - 1) << shift
    return (word & ~mask) | (value << shift)


def shape(typ, count):
    return typ + ".M816" + (count or "")


def file_hash(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read_h_production():
    """Full selected H records, including occurrences and source offsets."""
    records = []
    matrix = collections.Counter()
    unique = collections.defaultdict(set)
    sources = set()
    files = sorted(HFIXTURES.glob("rt_fmha*.jsonl"))
    assert len(files) == 3, files
    for path in files:
        digest = file_hash(path)
        for offset, line in enumerate(path.read_text().splitlines(), 1):
            row = json.loads(line)
            text = row["text"]
            if not text.startswith(("LDSM.U4x16P64TO8.M816", "LDSM.U6x16P32TO8.M816")):
                continue
            form = text.split()[0].removeprefix("LDSM.")
            addr = ("ARURI" if "+UR" in text and "[R" in text else
                    "AURI" if "[UR" in text else "ARI")
            records.append({"fixture": str(path), "fixture_sha256": digest,
                            "line": offset, **row})
            matrix[(form, addr, row["target"])] += 1
            unique[form].add(int(row["word"], 16))
            sources.add(row["source"].split(":")[0])
    summary = {"records": len(records), "unique_words": sum(map(len, unique.values())),
               "cubin_names": len(sources), "source_files": [str(f) for f in files],
               "by_form": {key: len(unique[key]) for key in sorted(unique)},
               "weighted_occurrences": {
                    form: sum(row["occurrences"] for row in records
                              if row["text"].split()[0] == "LDSM." + form)
                    for form in sorted(unique)},
               "note": "H reports occurrences per unique-row/tensor exposure; preserved verbatim, not a new whole-cubin census.",
               "observations_by_form_address_target": {"|".join(key): count
                for key, count in sorted(matrix.items())}}
    assert summary["records"] == 213 and summary["unique_words"] == 122, summary
    assert set(unique) == {"U4x16P64TO8.M816.2"}, summary
    return records, summary


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--nvdisasm", default="/usr/local/cuda/bin/nvdisasm")
    parser.add_argument("--out", required=True, type=pathlib.Path)
    parser.add_argument("--jobs", type=int, default=8)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    version = subprocess.check_output([args.nvdisasm, "--version"], text=True)
    digest = file_hash(pathlib.Path(args.nvdisasm))
    requests = [json.loads(line) for line in (SILICON / "cubit-requests.jsonl").read_text().splitlines()]
    donors = {}
    for row in requests:
        if row["case"].endswith("_replay"):
            continue
        m = re.fullmatch(r"u([46])_m816_x(1|2|4)", row["case"])
        assert m
        typ, count = ("U4x16P64TO8" if m[1] == "4" else "U6x16P32TO8",
                      {1: None, 2: ".2", 4: ".4"}[int(m[2])])
        word = int(row["word"], 16)
        donors.setdefault((typ, count, "ARURI"), {})[row["target"]] = word
    assert len(donors) == 6
    old_summary = json.loads((OLD / "summary.json").read_text())
    canonical = {}
    cases = {}

    def add(word, kind, label, source, **extra):
        entry = cases.setdefault(word, {"word": word, "kind": kind, "labels": [], "source": []})
        if label not in entry["labels"]:
            entry["labels"].append(label)
        for item in ([source] if isinstance(source, str) else source):
            if item not in entry["source"]:
                entry["source"].append(item)
        entry.update(extra)

    # Use the three previously measured address control mappings only as
    # templates. Each type/count/address cross is newly measured below.
    templates = {addr: int(old_summary["canonical"][f"U4x16P64TO8.M816.2-{addr}"], 16)
                 for addr in ADDRESS}
    for (typ, count, addr), pair in sorted(donors.items(), key=lambda item: str(item[0])):
        assert pair["SM100"] == pair["SM103"]
        donor = pair["SM103"]
        name = shape(typ, count)
        add(donor, "ptx-donor", f"ptx-{name}-ARURI", f"/root/sm103a/pubwave/hidden-b300/ldsm-unpack-counts-silicon/prepare.json:variants.{str(typ)[0].lower()}{typ[1]}_m816_x{COUNTS.index(count) * 2 + 1}",
            evidence=SRC)
        for target_addr in ADDRESS:
            old_name = f"{name}-{target_addr}"
            if target_addr == "ARURI":
                template = donor
            elif old_name in old_summary["canonical"]:
                template = int(old_summary["canonical"][old_name], 16)
            else:
                template = templates[target_addr]
            base = put(template, 72, 9, KIND[(typ, count)])
            base = put(base, 12, 4, 0)
            base = put(base, 16, 8, 0)
            base = put(base, 24, 8, 255 if target_addr == "AURI" else 0)
            base = put(base, 32, 8, 0)
            base = put(base, 40, 24, 0)
            canonical[(typ, count, target_addr)] = base
            label = f"{name}-{target_addr}"
            add(base, "core", label + "-canonical",
                f"controlled crossing of ptxas {name} and licensed {target_addr} address template")
            for bit in range(128):
                add(base ^ (1 << bit), "single-bit", f"{label}-bit{bit}",
                    "one bit changed; instruction and schedule separated below 96")
            for guard in range(16):
                add(put(base, 12, 4, guard), "guard", f"{label}-guard{guard}",
                    "complete guard enumeration")
            for field_shift, field_name in ((16, "rd"), (24, "ra"), (32, "ur")):
                for value in (0, 1, 2, 3, 4, 8, 10, 12, 16, 31, 32, 62, 63, 64, 127, 128, 254, 255):
                    word = put(base, field_shift, 8, value)
                    add(word, "operand", f"{label}-{field_name}{value}",
                        f"independent {field_name} encoding-word probe; not hardware register-assignment evidence")
            for rd, ra, ur in ((0, 0, 0), (4, 4, 4), (12, 21, 4), (16, 8, 10),
                               (32, 23, 17), (62, 127, 63), (128, 254, 255), (255, 255, 255)):
                word = put(put(put(base, 16, 8, rd), 24, 8, ra), 32, 8, ur)
                add(word, "operands", f"{label}-regs{rd}/{ra}/{ur}",
                    "coordinated Rd/Ra/UR encoding-word binding")
            for imm in (0, 1, 4, 0x10, 0x100, 0x1000, 0x10000, 0x100000,
                        0x7ffff0, 0x800000, 0xffffff):
                add(put(base, 40, 24, imm), "immediate", f"{label}-imm{imm:x}",
                    "independent 24-bit address immediate including both signs")
            for reuse in range(8):
                word = base
                for offset, bit in enumerate((122, 123, 124)):
                    word |= ((reuse >> offset) & 1) << bit
                add(word, "control-reuse", f"{label}-reuse{reuse}",
                    "control/reuse plane, not an operand field")
            for a, b in ((62, 63), (64, 65), (68, 69), (80, 81), (82, 83),
                         (84, 85), (86, 87), (88, 89), (90, 92), (93, 94)):
                add(base | (1 << a) | (1 << b), "inert-composition", f"{label}-bits{a}+{b}",
                    "paired falsifier for modifier and address fields")
            for value in range(512):
                word = put(base, 72, 9, value)
                add(word, "namespace", f"{label}-ns{value:03x}",
                    "complete bits 72..80 type/count/shape namespace enumeration")

    h_records, census = read_h_production()
    for row in h_records:
        text = row["text"]
        addr = "ARURI" if "+UR" in text and "[R" in text else "ARI"
        add(int(row["word"], 16), "production", f"H-{row['target']}-{row['line']}:" + text.split()[0],
            f"{row['fixture']}:{row['line']} sha256={row['fixture_sha256']}",
            occurrences=row["occurrences"], production_target=row["target"], address=addr)
    summary = {"nvdisasm": version, "nvdisasm_sha256": digest, "source": SRC,
               "canonical": {f"{shape(typ, count)}-{addr}": f"{word:032x}"
                            for (typ, count, addr), word in canonical.items()}, "targets": {},
               "cases": len(cases), "production_census": census}
    json.dump(summary, (args.out / "summary.json").open("w"), indent=2)
    (args.out / "production-census.json").write_text(json.dumps({"summary": census, "records": h_records}, indent=2) + "\n")
    local = threading.local()

    def measure(job):
        target, case = job
        if not hasattr(local, "scratch"):
            local.scratch = args.out / f".scratch-{target}-{threading.get_ident()}.bin"
        local.scratch.write_bytes(case["word"].to_bytes(16, "little"))
        proc = subprocess.run([args.nvdisasm, "-b", target, "-hex", str(local.scratch)],
                              capture_output=True, text=True)
        match = TEXT.search(proc.stdout)
        return {**case, "target": target, "word": f"{case['word']:032x}",
                "rc": proc.returncode, "stdout": proc.stdout, "stderr": proc.stderr,
                "nvidia_sass": match.group(1).strip() if match else None,
                "nvdisasm": version, "nvdisasm_sha256": digest}

    for target in ("SM103", "SM100"):
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
            rows = list(pool.map(measure, [(target, c) for c in cases.values()]))
        (args.out / target.lower()).mkdir(exist_ok=True)
        with (args.out / target.lower() / "raw.jsonl").open("w") as fh:
            for record in rows:
                fh.write(json.dumps(record) + "\n")
        for (typ, count, addr), base in canonical.items():
            row = next(r for r in rows if int(r["word"], 16) == base)
            assert row["rc"] == 0, (row["word"], shape(typ, count), addr, row["stderr"])
            vendor = row["nvidia_sass"] or ""
            assert f"LDSM.{shape(typ, count)} R0, [" in vendor, vendor
            address = {"ARI": "[R0]", "AURI": "[UR0]", "ARURI": "[R0+UR0]"}[addr]
            assert vendor.endswith(" " + address), (addr, vendor)
        summary["targets"][target] = {"records": len(rows), "accepted": sum(r["rc"] == 0 for r in rows),
            "rejected": sum(r["rc"] != 0 for r in rows),
            "unnamed": sum(r["rc"] == 0 and not r["nvidia_sass"] for r in rows)}
    (args.out / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    for scratch in args.out.glob(".scratch-*.bin"):
        scratch.unlink()
    print(json.dumps({"cases": len(cases), "targets": summary["targets"]}, indent=2))


if __name__ == "__main__":
    main()

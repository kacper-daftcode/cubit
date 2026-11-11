#!/usr/bin/env python3
"""Fresh CPU-only strict decoder and whole-ELF validation of accepted images.

Requires the historical cubit build, its matching tables and CUDA display tools.
No device context is created and no image is executed.
"""

import argparse
import hashlib
import json
import pathlib
import re
import subprocess
import sys

sys.dont_write_bytecode = True

ROOT = pathlib.Path(__file__).resolve().parent


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def run(command):
    proc = subprocess.run([str(part) for part in command], capture_output=True, text=True, timeout=30)
    result = {"command": [str(part) for part in command], "rc": proc.returncode,
              "stdout": proc.stdout, "stderr": proc.stderr}
    require(proc.returncode == 0, result)
    return result


def container_checks(output, arch):
    first = next(line for line in output.splitlines() if line.startswith("64-bit ELF:"))
    require("type=ET_EXEC" in first and f"sm={arch.removeprefix('sm')}" in first, (arch, first))
    params_text = output.rsplit(".nv.info.unpack_probe", 1)[1].split(".nv.callgraph", 1)[0]
    params = re.findall(r"Attribute:\s+EIATTR_KPARAM_INFO.*?(?=\n\s*<|\Z)", params_text, re.S)
    require(len(params) == 4, f"expected four actual parameter records, got {len(params)}")
    pairs = set()
    for param in params:
        offset = re.search(r"Offset\s+:\s+(0x[0-9a-f]+)\s+Size\s+:\s+0x8", param)
        ordinal = re.search(r"Ordinal\s+:\s+(0x[0-9a-f]+)", param)
        require(offset and ordinal, param)
        pairs.add((int(ordinal.group(1), 16), int(offset.group(1), 16)))
    require(pairs == {(0, 0), (1, 8), (2, 16), (3, 24)}, "actual kernel parameter ABI")
    exit_record = re.search(r"EIATTR_EXIT_INSTR_OFFSETS\s+Format:\s+EIFMT_SVAL\s+Value:\s+([^\n]+)",
                            params_text)
    require(exit_record and exit_record.group(1).split() == ["0x100"], "EIATTR_EXIT offset")
    require(re.search(r"EIATTR_CBANK_PARAM_SIZE\s+Format:\s+EIFMT_HVAL\s+Value:\s+0x20\s", params_text),
            "32-byte parameter bank")
    return {"elf": first, "parameters": [{"ordinal": ordinal, "offset": offset, "size": 8}
                                         for ordinal, offset in sorted(pairs)],
            "exit_instruction_offset": "0x100", "parameter_bank_size": "0x20"}


def selected_images():
    from verify import ARCHES, CASES, REPLAY, HSET_CASES, read_json
    for arch in ARCHES:
        suffix = arch.replace("sm", "sm_")
        source = ROOT / "sources" / f"fhadd-{suffix}"
        prepare = read_json(source / "prepare.json")
        for case in CASES + [REPLAY]:
            yield "fhadd", arch, case, source, prepare["variants"][case]
        source = ROOT / "sources" / f"hset-{suffix}"
        prepare = read_json(source / "prepare.json")
        for case in HSET_CASES:
            yield "hset2", arch, case, source, prepare["variants"][case]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--cubit", required=True, type=pathlib.Path)
    parser.add_argument("--tables", required=True, type=pathlib.Path)
    parser.add_argument("--nvdisasm", required=True, type=pathlib.Path)
    parser.add_argument("--cuobjdump", required=True, type=pathlib.Path)
    parser.add_argument("--output", type=pathlib.Path, default=ROOT / "CPU_REPLAY.json")
    parser.add_argument("--raw-dir", type=pathlib.Path, default=ROOT / "cpu-replay")
    args = parser.parse_args()
    for tool in (args.cubit, args.nvdisasm, args.cuobjdump):
        require(tool.is_file(), f"missing CPU tool: {tool}")
    report = {"schema_version": 1, "verdict": "PASS_CPU_STRICT_AND_WHOLE_CONTAINER",
              "gpu_launches_performed": 0,
              "tool_provenance_commands": {}, "selected_cubins": []}
    for name, tool in (("cubit", args.cubit), ("nvdisasm", args.nvdisasm), ("cuobjdump", args.cuobjdump)):
        report["tool_provenance_commands"][name] = run([tool, "--version"])
    tables = {}
    for family, arch, case, source, item in selected_images():
        suffix = arch.removeprefix("sm")
        table = args.tables / f"sm{suffix}.json.gz"
        require(table.is_file(), f"missing matching table: {table}")
        tables[str(table)] = sha256(table)
        cubin = source / item["cubin"]
        strict = run([args.cubit, "roundtrip-strict", "-t", table, cubin])
        require("1 sections, 17/17 instructions match; PASS" in strict["stdout"]
                and "STRICT TOTAL: 1 sections, 17/17 complete 128-bit instructions match; PASS"
                in strict["stdout"], (family, arch, case, "strict"))
        decoded = run([args.nvdisasm, "-c", cubin])
        text = decoded["stdout"] + decoded["stderr"]
        expected_decode = "sass" / pathlib.Path(f"{case}.hset.decoded.txt" if family == "hset2"
                                                   else f"{case}.decoded.txt")
        require(text == (source / expected_decode).read_text(),
                (family, arch, case, "vendor decode differs from accepted text"))
        require(f".target\t{arch.replace('sm', 'sm_')}" in text
                and item["vendor_text"] in text and text.count("/*0") == 17,
                (family, arch, case, "target/operation/instruction count"))
        elf = run([args.cuobjdump, "-elf", cubin])
        checks = container_checks(elf["stdout"] + elf["stderr"], arch)
        raw_path = args.raw_dir / f"{family}-{arch.replace('sm', 'sm_')}" / f"{case}.container.txt"
        raw_path.parent.mkdir(parents=True, exist_ok=True)
        raw_path.write_text(elf["stdout"] + elf["stderr"])
        recorded_raw_path = (str(raw_path.relative_to(ROOT)) if raw_path.is_relative_to(ROOT)
                             else str(raw_path))
        report["selected_cubins"].append({
            "family": family, "arch": arch, "case": case,
            "path": str(cubin.relative_to(ROOT)), "cubin_sha256": sha256(cubin),
            "strict_roundtrip": strict, "whole_container": checks,
            "container_log": recorded_raw_path, "container_log_sha256": sha256(raw_path),
            "vendor_decode_matches_original": True,
        })
    require(len(report["selected_cubins"]) == 38, "exact accepted image census")
    report["image_count"] = 38
    report["unique_cubin_sha256"] = len({item["cubin_sha256"] for item in report["selected_cubins"]})
    require(report["unique_cubin_sha256"] == 36, "two explicitly duplicated replay images")
    report["strict_instruction_comparisons"] = 38 * 17
    report["matching_table_sha256"] = dict(sorted(tables.items()))
    report["note"] = ("Fresh parsing/re-encoding/disassembly/ELF checks only. No claim of new GPU execution, "
                      "new native semantics or timing is made by this replay.")
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"verdict": report["verdict"], "images": report["image_count"],
                      "unique_cubin_sha256": report["unique_cubin_sha256"],
                      "strict_instruction_comparisons": report["strict_instruction_comparisons"],
                      "whole_container_attributes": "4 parameters, EXIT=0x100, CBANK=0x20",
                      "gpu_launches_performed": 0}, indent=2))


if __name__ == "__main__":
    main()

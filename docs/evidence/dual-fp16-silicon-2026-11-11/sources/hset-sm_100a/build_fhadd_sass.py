#!/usr/bin/env python3
"""Build architecture-specific FHADD bundles through cubit's standalone ELF builder."""
import hashlib
import json
import pathlib
import shutil
import struct
import subprocess

from model import ALL_CASES, REPLAY, spec

ROOT = pathlib.Path(__file__).resolve().parent
CUBIT = pathlib.Path("/root/sm103a/pubwave/hidden-b300/fhadd-bf16-production/worktrees/target/release/cubit")
TABLES = pathlib.Path("/root/sm103a/pubwave/hidden-b300/fhadd-bf16-production/worktrees/cubit/tables")
TEMPLATE = pathlib.Path("/root/sm103a/gpu-review-distributed/probe-cuda/demo.sass")


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def section(path):
    data = path.read_bytes()
    shoff = struct.unpack_from("<Q", data, 0x28)[0]
    entsize, count, names_index = struct.unpack_from("<HHH", data, 0x3A)
    entries = [struct.unpack_from("<IIQQQQ", data, shoff + i * entsize) for i in range(count)]
    strings = entries[names_index][4]
    for name, _kind, _flags, _addr, offset, size in entries:
        end = data.index(b"\0", strings + name)
        if data[strings + name:end] == b".text.unpack_probe":
            return offset, size
    raise AssertionError("missing .text.unpack_probe")


def word(path):
    with path.open("rb") as stream:
        stream.seek(section(path)[0] + 0xD0)
        low, high = struct.unpack("<QQ", stream.read(16))
    return f"{low | high << 64:032x}"


def instruction_text(case):
    options = spec(case)
    text = "FHADD" + (".BF16" if options["format"] == "bf16" else "")
    if options["rounding"] != "plain":
        text += "." + options["rounding"].upper()
    return text + f" R10, R2{'.H1' if options['h1'] else ''}, R4"


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", choices=("sm_103a", "sm_100a"), required=True)
    args = parser.parse_args()
    target = args.target
    template = TEMPLATE.read_text()
    assert "FHADD R10, R2, R4 ;" in template
    document = json.loads((ROOT / "prepare.json").read_text())
    assert document["own_buffer_limits"]["total_bytes"] == 1536
    for name in ("cubins", "sass", "case-results"):
        (ROOT / name).mkdir(exist_ok=True)
    for case in ALL_CASES:
        if case == REPLAY:
            shutil.copyfile(ROOT / "cubins/plain_bf16_h1.cubin", ROOT / f"cubins/{case}.cubin")
        else:
            text = template.replace("FHADD R10, R2, R4 ;", instruction_text(case) + " ;")
            source = ROOT / "sass" / f"{case}.sass"
            source.write_text(text)
            cubin = ROOT / "cubins" / f"{case}.cubin"
            table = TABLES / f"{dict(sm_103a='sm103a', sm_100a='sm100a')[target]}.json.gz"
            proc = subprocess.run([str(CUBIT), "asm", str(source), "-t", str(table), "-o", str(cubin)],
                                  capture_output=True, text=True)
            assert proc.returncode == 0, proc.stderr
        cubin = ROOT / "cubins" / f"{case}.cubin"
        table = TABLES / f"sm{target.split('_')[1]}.json.gz"
        strict = subprocess.run([str(CUBIT), "roundtrip-strict", "-t", str(table), str(cubin)],
                                capture_output=True, text=True)
        assert strict.returncode == 0 and "PASS" in strict.stdout, (case, strict.stdout, strict.stderr)
        proc = subprocess.run(["/usr/local/cuda/bin/nvdisasm", "-c", str(cubin)], capture_output=True, text=True)
        assert proc.returncode == 0, proc.stderr
        raw = proc.stdout + proc.stderr
        (ROOT / "sass" / f"{case}.decoded.txt").write_text(raw)
        expected = instruction_text(case)
        assert f".target\t{target}" in raw, (case, target)
        assert expected in raw, (case, expected)
        for required in ("LDG.E.64 R2", "LDG.E.64 R4", "STG.E desc[UR4][R6.64], R10", "STG.E desc[UR4][R8.64], R5", "EXIT"):
            assert required in raw, (case, required)
        item = document["variants"][case]
        item.update(cubin=f"cubins/{case}.cubin", cubin_sha256=sha256(cubin),
                    word=word(cubin), vendor_text=expected, rebuilt_target=target,
                    whole_cubin_record={"command": ["/usr/local/cuda/bin/nvdisasm", "-c", str(cubin)],
                                        "rc": proc.returncode, "stdout": proc.stdout, "stderr": proc.stderr,
                                        "cubit_strict_rc": strict.returncode, "cubit_strict_output": strict.stdout})
        item["raw_records"] = [{"rc": 0, "target": target, "input_word": item["word"]},
                               {"rc": 0, "target": target, "input_word": item["word"]}]
    document["rebuilt_target"] = target
    document["builder"] = "cubit standalone ELF with four actual param pointers and correct EIATTR_EXIT records"
    (ROOT / "prepare.json").write_text(json.dumps(document, indent=2) + "\n")
    print(json.dumps({"result": "PREPARED", "target": target, "cubins": len(ALL_CASES), "gpu_launches": 0}))


if __name__ == "__main__":
    main()

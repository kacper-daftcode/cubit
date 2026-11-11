#!/usr/bin/env python3
"""Replace two verified FHADD images with HSET2 in the proven existing driver."""
import json
import pathlib
import shutil
import subprocess

from build_fhadd_sass import CUBIT, TABLES, TEMPLATE, word as instruction_word

ROOT = pathlib.Path(__file__).resolve().parent
VARIATIONS = {
    "plain_f16_h0": "HSET2.EQ.AND R10, R2, R4, PT",
    "plain_bf16_h0": "HSET2.BF16_V2.BF.EQ.AND R10, R2, R4, PT",
}


def sha256(path):
    import hashlib
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", choices=["sm_103a", "sm_100a"], required=True)
    target = parser.parse_args().target
    template = TEMPLATE.read_text()
    data = json.loads((ROOT / "prepare.json").read_text())
    for case, operator in VARIATIONS.items():
        source = ROOT / f"cubins/{case}.hset.sass"
        source.write_text(template.replace("FHADD R10, R2, R4 ;", operator + " ;"))
        cubin = ROOT / f"cubins/{case}.cubin"
        table = TABLES / f"sm{target.split('_')[1]}.json.gz"
        run = subprocess.run([str(CUBIT), "asm", str(source), "-t", str(table), "-o", str(cubin)],
                             capture_output=True, text=True)
        assert run.returncode == 0, run.stderr
        run = subprocess.run([str(CUBIT), "roundtrip-strict", "-t", str(table), str(cubin)],
                             capture_output=True, text=True)
        assert run.returncode == 0 and "PASS" in run.stdout, (case, run.stderr)
        result = subprocess.run(["/usr/local/cuda/bin/nvdisasm", "-c", str(cubin)],
                                capture_output=True, text=True)
        assert result.returncode == 0, result.stderr
        raw = result.stdout + result.stderr
        (ROOT / "sass" / f"{case}.hset.decoded.txt").write_text(raw)
        expected = operator.replace("R4, PT", "R4.H0_H0, PT")
        assert raw.count("LDG.E.64") == 2
        for line in (expected, "STG.E desc[UR4][R6.64], R10", "STG.E desc[UR4][R8.64], R5", "EXIT"):
            assert line in raw, (case, line)
        assert f".target\t{target}" in raw
        item = data["variants"][case]
        item.update(cubin=f"cubins/{case}.cubin", cubin_sha256=sha256(cubin),
                    vendor_text=expected, word=instruction_word(cubin),
                    hset_case=VARIATIONS[case], rebuilt_target=target)
        item["raw_records"] = [{"rc": 0, "target": target, "input_word": item["word"]},
                               {"rc": 0, "target": target, "input_word": item["word"]}]
        item["whole_cubin_record"] = {"command": ["/usr/local/cuda/bin/nvdisasm", "-c", str(cubin)],
                                      "rc": result.returncode, "stdout": result.stdout,
                                      "stderr": result.stderr}
    (ROOT / "prepare.json").write_text(json.dumps(data, indent=2) + "\n")
    print(json.dumps({"target": target, "verified_cubins": len(VARIATIONS),
                      "execution_driver": "unchanged proven fhadd driver", "model_check": "pending"}))


if __name__ == "__main__":
    main()

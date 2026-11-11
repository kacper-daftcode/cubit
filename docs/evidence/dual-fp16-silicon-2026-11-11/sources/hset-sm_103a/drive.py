#!/usr/bin/env python3
"""Execute licensed FHADD cubins in bounded subprocesses and retain raw arrays."""
import ctypes
import hashlib
import json
import os
import pathlib
import subprocess
import sys
import traceback

from model import ALL_CASES, ALLOCATE, CANARY, GUARD, HOST_WORDS, N, domain, spec

ROOT = pathlib.Path(__file__).resolve().parent
CU = ctypes.CDLL("libcuda.so.1")


def sha256(path):
    return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


def telemetry():
    records = []
    for command in (["nvidia-smi", "--query-gpu=timestamp,index,name,uuid,driver_version,memory.used,memory.total,utilization.gpu", "--format=csv,noheader"],
                    ["nvidia-smi", "--query-compute-apps=gpu_uuid,pid,process_name,used_memory", "--format=csv,noheader"]):
        proc = subprocess.run(command, capture_output=True, text=True)
        records.append({"command": command, "rc": proc.returncode, "stdout": proc.stdout, "stderr": proc.stderr})
    return records


def check(rc, operation):
    if rc:
        message = ctypes.c_char_p()
        CU.cuGetErrorString(rc, ctypes.byref(message))
        raise RuntimeError(f"{operation}: CUDA {rc}: {(message.value or b'?').decode()}")


def guard(buffer_index, index):
    return 0xA5000000 | buffer_index << 24 | index


def worker(case, destination):
    item = json.loads((ROOT / "prepare.json").read_text())["variants"][case]
    cubin = (ROOT / item["cubin"]).resolve()
    result = {"case": case, "pid": os.getpid(), "grid": [1, 1, 1], "block": [N, 1, 1],
              "allocation_bytes_each": ALLOCATE, "own_mapped_bytes": 4 * ALLOCATE,
              "cubin": str(cubin), "cubin_sha256": item["cubin_sha256"], "word": item["word"],
              "vendor_text": item["vendor_text"], "raw_observations": []}
    context, buffers = None, []
    try:
        assert cubin.is_relative_to(ROOT.resolve())
        assert os.environ.get("FHADD_OWN_LAUNCH") == "1"
        assert sha256(cubin) == item["cubin_sha256"]
        check(CU.cuInit(0), "cuInit")
        device = ctypes.c_int()
        check(CU.cuDeviceGet(ctypes.byref(device), 0), "cuDeviceGet")
        name = ctypes.create_string_buffer(128)
        check(CU.cuDeviceGetName(name, 128, device), "cuDeviceGetName")
        result["device"] = name.value.decode()
        context = ctypes.c_void_p()
        check(CU.cuCtxCreate_v2(ctypes.byref(context), 0, device), "cuCtxCreate")
        module = ctypes.c_void_p()
        check(CU.cuModuleLoadData(ctypes.byref(module), cubin.read_bytes()), "cuModuleLoadData")
        function = ctypes.c_void_p()
        check(CU.cuModuleGetFunction(ctypes.byref(function), module, b"unpack_probe"), "cuModuleGetFunction")
        pointers = {}
        for key in ("a_pairs", "b_pairs", "out", "echo"):
            pointer = ctypes.c_void_p()
            check(CU.cuMemAlloc_v2(ctypes.byref(pointer), ALLOCATE), f"cuMemAlloc {key}")
            buffers.append(pointer)
            pointers[key] = pointer
        result["allocations"] = [{"name": key, "address": f"0x{pointers[key].value:x}", "bytes": ALLOCATE,
                                  "payload_offset": GUARD * 4} for key in pointers]
        parameters = tuple(ctypes.c_void_p(pointers[key].value + GUARD * 4) for key in ("a_pairs", "b_pairs", "out", "echo"))
        arguments = (ctypes.c_void_p * 4)(*[ctypes.cast(ctypes.byref(pointer), ctypes.c_void_p) for pointer in parameters])
        for domain_name in ("finite", "special"):
            rows = domain(domain_name, spec(case)["format"])
            for launch, start in enumerate(range(0, len(rows), N)):
                batch = rows[start:start + N]
                payloads = {
                    "a_pairs": [word for row in batch for word in (row["a0"] | row["a1"] << 16, 0x13579BDF)],
                    "b_pairs": [word for row in batch for word in (row["b0"] | row["b1"] << 16, 0x2468ACE0)],
                    "out": [CANARY] * len(batch), "echo": [CANARY] * len(batch),
                }
                for buffer_index, key in enumerate(("a_pairs", "b_pairs", "out", "echo")):
                    host = (ctypes.c_uint32 * HOST_WORDS)(*[guard(buffer_index, index) for index in range(HOST_WORDS)])
                    for index, value in enumerate(payloads[key]):
                        host[GUARD + index] = value
                    check(CU.cuMemcpyHtoD_v2(pointers[key], host, ALLOCATE), f"HtoD {key}")
                check(CU.cuLaunchKernel(function, 1, 1, 1, N, 1, 1, 0, None, arguments, None), "cuLaunchKernel")
                check(CU.cuCtxSynchronize(), "cuCtxSynchronize")
                observation = {"domain": domain_name, "launch": launch, "batch_start": start,
                               "indices": [row["index"] for row in batch], "canaries": {}}
                for buffer_index, key in enumerate(("a_pairs", "b_pairs", "out", "echo")):
                    host = (ctypes.c_uint32 * HOST_WORDS)()
                    check(CU.cuMemcpyDtoH_v2(host, pointers[key], ALLOCATE), f"DtoH {key}")
                    observation[key] = [f"{word:08x}" for word in host[GUARD:GUARD + len(payloads[key])]]
                    observation["canaries"][key] = all(host[index] == guard(buffer_index, index)
                        for index in range(HOST_WORDS) if not GUARD <= index < GUARD + len(payloads[key]))
                observation["inputs_preserved"] = all(observation[key] == [f"{w:08x}" for w in payloads[key]] for key in ("a_pairs", "b_pairs"))
                observation["expected_echo"] = [f"{0x2468ACE0:08x}"] * len(batch)
                observation["echo_observed"] = observation["echo"] == observation["expected_echo"]
                observation["out_observed"] = observation["out"] != [f"{CANARY:08x}"] * len(batch)
                result["raw_observations"].append(observation)
        result["launches"] = len(result["raw_observations"])
        result["canaries_all_intact"] = all(all(row["canaries"].values()) for row in result["raw_observations"])
        result["inputs_outputs_observed"] = all(row["inputs_preserved"] and row["echo_observed"] and row["out_observed"] for row in result["raw_observations"])
        result["status"] = "completed" if result["launches"] == 11 and result["canaries_all_intact"] and result["inputs_outputs_observed"] else "integrity-failure"
    except Exception as error:
        result.update(status="error", error=str(error), traceback=traceback.format_exc())
    finally:
        for pointer in buffers:
            CU.cuMemFree_v2(pointer)
        if context is not None and context.value:
            CU.cuCtxDestroy_v2(context)
        save(destination, result)
    return result["status"] == "completed"


def self_test():
    document = json.loads((ROOT / "prepare.json").read_text())
    assert list(document["variants"]) == ALL_CASES and len(ALL_CASES) == 17
    assert document["own_buffer_limits"]["total_bytes"] == 1536
    for case, item in document["variants"].items():
        assert sha256(ROOT / item["cubin"]) == item["cubin_sha256"]
        assert len(item["raw_records"]) == 2
        assert all(row["rc"] == 0 and row["input_word"] == item["word"] for row in item["raw_records"])
        assert len(domain("finite", spec(case)["format"])) == 256
        assert len(domain("special", spec(case)["format"])) == 96
    print("CPU DRIVER SELF-TEST PASS: 17 licensed cubins, 11 launches/worker, 1536 own bytes; no CUDA call")
    return 0


def valid_existing(case, path):
    if not path.is_file():
        return False
    result = json.loads(path.read_text())
    item = json.loads((ROOT / "prepare.json").read_text())["variants"][case]
    return (result.get("status") == "completed" and result.get("word") == item["word"] and
            result.get("cubin_sha256") == item["cubin_sha256"] and result.get("canaries_all_intact") and
            result.get("inputs_outputs_observed") and result.get("launches") == 11)


def parent(cases):
    assert (ROOT / "coordination-start-proof.json").is_file(), "append coordination START before execution"
    save(ROOT / "gpu-before.json", telemetry())
    outcomes = []
    for case in cases:
        destination = ROOT / "case-results" / f"{case}.json"
        if valid_existing(case, destination):
            outcomes.append({"case": case, "resumed_existing_raw": True, "status": "completed", "returncode": 0})
            continue
        before = telemetry()
        process = subprocess.Popen(["timeout", "-k", "5", "60", sys.executable, __file__, "--worker", case,
                                    "--out", str(destination)], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   text=True, env=dict(os.environ, FHADD_OWN_LAUNCH="1"))
        stdout, stderr = process.communicate(timeout=65)
        (ROOT / "case-results" / f"{case}.stdout.log").write_text(stdout)
        (ROOT / "case-results" / f"{case}.stderr.log").write_text(stderr)
        outcome = {"case": case, "timeout_wrapper_pid": process.pid, "returncode": process.returncode,
                   "telemetry_before": before, "telemetry_after": telemetry()}
        if destination.is_file():
            result = json.loads(destination.read_text())
            outcome.update(worker_pid=result.get("pid"), status=result.get("status"), error=result.get("error"),
                           launches=result.get("launches"), canaries_all_intact=result.get("canaries_all_intact"))
        outcomes.append(outcome)
        save(ROOT / "results.json", {"phase": "running", "outcomes": outcomes, "timing_claim": "none"})
        if outcome.get("status") != "completed":
            break
    save(ROOT / "gpu-final.json", telemetry())
    all_done = all(valid_existing(case, ROOT / "case-results" / f"{case}.json") for case in ALL_CASES)
    save(ROOT / "results.json", {"execution_verdict": "COMPLETE" if all_done else "BOUNDED_PROGRESS",
                                 "selected_outcomes": outcomes, "all_cases_complete": all_done,
                                 "timeout_seconds": 60, "timeout_grace_seconds": 5, "timing_claim": "none"})
    print(json.dumps({"all_cases_complete": all_done, "selected_cases": cases,
                      "outcomes": [{"case": row["case"], "status": row.get("status"), "rc": row["returncode"],
                                    "error": row.get("error")} for row in outcomes]}, indent=2))
    return 0 if all(row.get("status") == "completed" for row in outcomes) else 1


def main():
    if "--preflight" in sys.argv:
        save(ROOT / "gpu-preflight.json", telemetry())
        print("GPU telemetry recorded without a CUDA context")
        return 0
    if "--self-test" in sys.argv:
        return self_test()
    if sys.argv[1:2] == ["--worker"]:
        return 0 if worker(sys.argv[2], pathlib.Path(sys.argv[sys.argv.index("--out") + 1])) else 1
    cases = sys.argv[sys.argv.index("--cases") + 1:] if "--cases" in sys.argv else ALL_CASES
    assert cases and all(case in ALL_CASES for case in cases)
    return parent(cases)


if __name__ == "__main__":
    sys.exit(main())

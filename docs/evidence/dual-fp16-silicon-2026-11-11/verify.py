#!/usr/bin/env python3
"""Offline, repo-local validation of the stored dual-architecture observations.

This does not load CUDA or launch a GPU. It recomputes numerical expectations,
replay identity, HSET2 model rejection, address bounds and artifact identities.
"""

import argparse
import hashlib
import json
import pathlib
import runpy
import struct

ROOT = pathlib.Path(__file__).resolve().parent
ARCHES = ("sm103a", "sm100a")
DEVICES = {"sm103a": "NVIDIA B300 SXM6 AC", "sm100a": "NVIDIA B200"}
CASES = [f"{rounding}_{fmt}_h{h1}" for rounding in ("plain", "rm", "rp", "rz")
         for fmt in ("f16", "bf16") for h1 in (0, 1)]
REPLAY = "plain_bf16_h1_replay"
HSET_CASES = ("plain_f16_h0", "plain_bf16_h0")
FHADD_RAW_SHA = "079cc0b092252439b71a51627d0c87e1861277809e0fc41d1de400a1f0d28a21"
HSET_RAW_SHA = {
    "f16": "8cced12a7cd50ea1f782d181f3bbc6f02b1bfe02f25b5c2d2261fe6422cb2943",
    "bf16": "29f6928725e23e426b6b616cd518e7fafcdaf5c1ec715b19e72a453dd1db74db",
}


def read_json(path):
    return json.loads(path.read_text())


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def model_for(directory, filename="model.py"):
    return runpy.run_path(str(directory / filename))


def text_and_word(cubin):
    """Extract the central operation from a bounded, complete ELF64 image."""
    data = cubin.read_bytes()
    require(data[:7] == b"\x7fELF\x02\x01\x01", f"not little-endian ELF64: {cubin}")
    header = struct.unpack_from("<16sHHIQQQIHHHHHH", data)
    require(header[1] == 2 and header[2] == 190, f"not an NVIDIA executable: {cubin}")
    shoff, shentsize, shnum, shstrndx = header[6], header[11], header[12], header[13]
    require(header[8] == 64 and shoff + shentsize * shnum <= len(data), "invalid ELF headers")
    require(header[5] + header[9] * header[10] <= len(data), "program headers outside ELF")
    entries = [struct.unpack_from("<IIQQQQIIQQ", data, shoff + i * shentsize)
               for i in range(shnum)]
    strings = entries[shstrndx]
    for _name, kind, _flags, _addr, offset, size, _link, _info, _align, _entsize in entries:
        require(kind == 8 or offset + size <= len(data), f"section outside ELF: {cubin}")
    sections = {}
    for entry in entries:
        name, _kind, _flags, _addr, offset, size, _link, _info, _align, _entsize = entry
        end = data.index(b"\0", strings[4] + name)
        label = data[strings[4] + name:end].decode("ascii")
        sections[label] = (offset, size)
    require(sections[".text.unpack_probe"] == (0x700, 0x110), f"unexpected text layout: {cubin}")
    offset, size = sections[".text.unpack_probe"]
    require(size == 17 * 16, "the accepted harness is exactly 17 instructions")
    low, high = struct.unpack_from("<QQ", data, offset + 0xD0)
    return f"{low | high << 64:032x}"


def validate_launch_record(record, arch, case, source, prepare):
    require(record["case"] == case and record["status"] == "completed", (arch, case, "status"))
    require(record["device"] == DEVICES[arch], (arch, case, "device"))
    require(record["grid"] == [1, 1, 1] and record["block"] == [32, 1, 1], "launch geometry")
    require(record["own_mapped_bytes"] == 1536 and record["allocation_bytes_each"] == 384, "byte limits")
    require(record["launches"] == len(record["raw_observations"]) == 11, "launch count")
    require(record["canaries_all_intact"] and record["inputs_outputs_observed"], "integrity summary")
    allocations = record["allocations"]
    require([item["name"] for item in allocations] == ["a_pairs", "b_pairs", "out", "echo"], "buffer order")
    intervals = []
    for item in allocations:
        require(item["bytes"] == 384 and item["payload_offset"] == 64, "payload geometry")
        base = int(item["address"], 16)
        require(base > 0, "null allocation")
        intervals.append((base, base + item["bytes"]))
        # Lane 31 uses an 8-byte input load and 4-byte output/echo stores.
        require(item["payload_offset"] + 31 * 8 + 8 == 320 <= item["bytes"], "input tail")
        require(item["payload_offset"] + 31 * 4 + 4 == 192 <= item["bytes"], "output tail")
    require(all(left[1] <= right[0] for left, right in zip(intervals, intervals[1:])), "buffer overlap")
    offsets = sorted(start - intervals[0][0] for start, _end in intervals)
    require(offsets == [0, 512, 1024, 1536], f"unexpected accepted allocation layout: {offsets}")
    item = prepare["variants"][case]
    expected_target = arch.replace("sm", "sm_")
    require(item["rebuilt_target"] == expected_target, "target provenance")
    cubin = source / item["cubin"]
    require(cubin.is_relative_to(source), "cubin escapes source directory")
    require(sha256(cubin) == record["cubin_sha256"] == item["cubin_sha256"], "cubin identity")
    require(record["word"] == item["word"] == text_and_word(cubin), "central 128-bit word")
    decoded_name = f"{case}.hset.decoded.txt" if "hset_case" in item else f"{case}.decoded.txt"
    decoded = (source / "sass" / decoded_name).read_text()
    require(f".target\t{expected_target}" in decoded and 'ET_EXEC' in decoded, "vendor container decode")
    require(record["vendor_text"] == item["vendor_text"] and record["vendor_text"] in decoded, "operation text")
    require(decoded.count("LDG.E.64") == 2 and "EXIT" in decoded, "load/exit skeleton")
    require("STG.E desc[UR4][R6.64], R10" in decoded and "STG.E desc[UR4][R8.64], R5" in decoded,
            "output/echo skeleton")
    require(decoded.count("/*00d0*/") == 1 and decoded.count("/*0100*/") == 1, "operation/exit offsets")
    require(decoded.count("/*0") == 17, f"not exactly 17 decoded instructions: {decoded_name}")
    whole = item["whole_cubin_record"]
    require(whole["rc"] == 0 and whole["stdout"] + whole["stderr"] == decoded, "original whole-container record")
    if "cubit_strict_rc" in whole:
        require(whole["cubit_strict_rc"] == 0 and "17/17 complete 128-bit instructions match; PASS"
                in whole["cubit_strict_output"], "original strict-roundtrip record")
    return {"raw_sha256": None, "cubin_sha256": record["cubin_sha256"],
            "word": record["word"], "vendor_text": record["vendor_text"],
            "launches": 11, "raw_outputs": 352}


def check_observation(obs, expected_domain, expected_launch, expected_start, model, fmt, mirror=False):
    require(obs["domain"] == expected_domain and obs["launch"] == expected_launch
            and obs["batch_start"] == expected_start, "batch identity")
    require(obs["canaries"] == {key: True for key in ("a_pairs", "b_pairs", "out", "echo")}, "canaries")
    require(obs["inputs_preserved"] and obs["echo_observed"] and obs["out_observed"], "observed I/O")
    require(len(obs["indices"]) == len(obs["out"]) == len(obs["echo"]) == 32, "output width")
    require(len(obs["a_pairs"]) == len(obs["b_pairs"]) == 64, "packed input width")
    require(obs["a_pairs"][1::2] == ["13579bdf"] * 32, "A unused-word control")
    require(obs["b_pairs"][1::2] == ["2468ace0"] * 32, "B unused-word control")
    require(obs["expected_echo"] == ["2468ace0"] * 32 and obs["echo"] == obs["expected_echo"], "echo")
    rows = model["domain"](expected_domain, fmt)[expected_start:expected_start + 32]
    require(len(rows) == 32 and obs["indices"] == [row["index"] for row in rows], "input indices")
    for lane, row in enumerate(rows):
        a = f"{row['a0'] | row['a1'] << 16:08x}"
        b = f"{row['b0'] | row['b1'] << 16:08x}"
        require(obs["a_pairs"][2 * lane] == a and obs["b_pairs"][2 * lane] == b, "packed input data")
        if mirror:
            require(a == b, "A=B control override")
    return rows


def check_all_observations(record, model, fmt, mirror=False):
    rows = []
    for domain, launches in (("finite", 8), ("special", 3)):
        subset = [obs for obs in record["raw_observations"] if obs["domain"] == domain]
        require(len(subset) == launches, (domain, "launch count"))
        for launch, obs in enumerate(subset):
            rows.extend(check_observation(obs, domain, launch, launch * 32, model, fmt, mirror))
    return rows


def projected_observation(obs):
    return {key: obs[key] for key in ("domain", "launch", "batch_start", "indices",
                                      "a_pairs", "b_pairs", "out", "echo")}


def check_fhadd_arch(arch):
    source = ROOT / "sources" / f"fhadd-{arch.replace('sm', 'sm_')}"
    model = model_for(source)
    prepare = read_json(source / "prepare.json")
    require(prepare["own_buffer_limits"] == {"ctas": 1, "threads": 32, "buffers": 4,
                                               "bytes_each": 384, "total_bytes": 1536}, "documented limits")
    records = {}
    case_results = []
    for case in CASES + [REPLAY]:
        path = ROOT / f"raw-{arch}" / f"{case}.json"
        record = read_json(path)
        records[case] = record
        result = validate_launch_record(record, arch, case, source, prepare)
        result["raw_sha256"] = sha256(path)
        result["path"] = str(path.relative_to(ROOT))
        case_results.append(result)
        rows = check_all_observations(record, model, model["spec"](case)["format"])
        for row, obs in zip(rows, [obs for obs in record["raw_observations"] for _ in range(32)]):
            lane = row["index"] % 32
            expected = model["model"](case, row)
            actual = int(obs["out"][lane], 16)
            expected_class = expected["class"]
            category = case_results[-1].setdefault("semantics", {"finite": 0, "nan": 0, "inf": 0})
            if expected_class == "finite":
                candidates = model["candidates"](expected)
                representations = case_results[-1].setdefault("representations", {})
                for name, value in candidates.items():
                    counts = representations.setdefault(name, {"checked": 0, "mismatches": 0})
                    counts["checked"] += 1
                    counts["mismatches"] += actual != value
                require(actual == expected["wide"], (arch, case, row["index"], "wide"))
                category["finite"] += 1
            else:
                exponent = actual >> 23 & 0xFF
                fraction = actual & 0x7FFFFF
                require(exponent == 0xFF, (arch, case, row["index"], "special exponent"))
                if expected_class == "nan":
                    require(fraction != 0, (arch, case, row["index"], "NaN class"))
                    category["nan"] += 1
                else:
                    require(expected_class == "inf" and fraction == 0
                            and actual >> 31 == expected["sign"], (arch, case, row["index"], "Inf"))
                    category["inf"] += 1
    require([path.stem for path in sorted((ROOT / f"raw-{arch}").glob("*.json"))]
            == sorted(CASES + [REPLAY]), "FHADD exact case census")
    core = records["plain_bf16_h1"]
    replay = records[REPLAY]
    require([projected_observation(obs) for obs in replay["raw_observations"]]
            == [projected_observation(obs) for obs in core["raw_observations"]], "distinct replay")
    require((source / f"cubins/{REPLAY}.cubin").read_bytes()
            == (source / "cubins/plain_bf16_h1.cubin").read_bytes(), "same replay cubin")
    archived_replay = ROOT / f"replay-{arch}.json"
    require(archived_replay.read_bytes() == (ROOT / f"raw-{arch}" / f"{REPLAY}.json").read_bytes(),
            "duplicate replay archive is explicitly labelled")
    core_semantics = {"finite": sum(result["semantics"]["finite"] for result in case_results[:-1]),
                      "nan": sum(result["semantics"]["nan"] for result in case_results[:-1]),
                      "inf": sum(result["semantics"]["inf"] for result in case_results[:-1])}
    require(sum(core_semantics.values()) == 5632, "core model census")
    representations = {}
    for name in ("wide", "low_zero", "low_ones", "replicated"):
        representations[name] = {
            "checked": sum(result["representations"][name]["checked"] for result in case_results[:-1]),
            "mismatches": sum(result["representations"][name]["mismatches"] for result in case_results[:-1]),
        }
    require(representations["wide"]["mismatches"] == 0, "wide representation rejection")
    require(all(representations[name]["mismatches"] > 0 for name in representations if name != "wide"),
            "no alternative representation was rejected")
    audit = read_json(ROOT / f"audit-{arch}.json")
    require(audit["audit_verdict"] == "SEMANTICS_PASS_SCOPED_NON_SAT"
            and audit["core_raw_outputs"] == 5632 and audit["replay_raw_outputs"] == 352
            and audit["raw_replay_exact"] and audit["shared_core_winning_representations"] == ["wide"],
            "original FHADD audit")
    return records, {"cases": case_results, "core_semantics": core_semantics,
                     "representations": representations}


def ieee_equal(model, left, right, fmt):
    first, second = model["class_of"](left, fmt), model["class_of"](right, fmt)
    if "nan" in (first, second):
        return False
    if "inf" in (first, second):
        return first == second == "inf" and (left >> 15) == (right >> 15)
    return model["exact"](left, fmt) == model["exact"](right, fmt)


def check_hset_arch(arch):
    source = ROOT / "sources" / f"hset-{arch.replace('sm', 'sm_')}"
    original_model = model_for(source, "hset_model_original.py")
    mirror_model = model_for(source)
    prepare = read_json(source / "prepare.json")
    require((source / "drive.py").read_bytes()
            == (ROOT / "sources" / f"fhadd-{arch.replace('sm', 'sm_')}" / "drive.py").read_bytes(),
            "HSET driver differs from the accepted FHADD driver")
    mirrored, nonmirrored, rejection = {}, {}, {}
    saved_evaluation = read_json(ROOT / "hset-evaluation.json")
    for case in HSET_CASES:
        fmt = "f16" if "_f16_" in case else "bf16"
        mirror_path = ROOT / "hset-eq-raw" / f"{arch}-{fmt}.json"
        original_path = ROOT / f"hset-proven-{arch}" / f"{case}.json"
        current = read_json(mirror_path)
        original = read_json(original_path)
        current_result = validate_launch_record(current, arch, case, source, prepare)
        original_result = validate_launch_record(original, arch, case, source, prepare)
        current_result["raw_sha256"] = sha256(mirror_path)
        original_result["raw_sha256"] = sha256(original_path)
        check_all_observations(current, mirror_model, fmt, mirror=True)
        original_rows = check_all_observations(original, original_model, fmt)
        original_iter = (obs for obs in original["raw_observations"] for _ in range(32))
        mismatches = []
        for row, obs in zip(original_rows, original_iter):
            expected = ((0xFFFF if ieee_equal(original_model, row["a0"], row["b0"], fmt) else 0)
                        | ((0xFFFF if ieee_equal(original_model, row["a1"], row["b1"], fmt) else 0) << 16))
            actual = obs["out"][row["index"] % 32]
            if int(actual, 16) != expected:
                mismatches.append({"domain": obs["domain"], "index": row["index"],
                                   "actual": actual, "expected": f"{expected:08x}",
                                   "input_a": [row["a0"], row["a1"]],
                                   "input_b": [row["b0"], row["b1"]]})
        expected_saved = saved_evaluation[arch][fmt]
        require(expected_saved["mismatches"] == mismatches
                and expected_saved["checked_outputs"] == 352
                and expected_saved["status_if_model_correct"] == "MODEL_MISMATCH",
                (arch, fmt, "retained expected-vs-actual rejection differs"))
        rejection[fmt] = {"checked_outputs": 352, "model_mismatches": len(mismatches),
                          "details": "hset-evaluation.json"}
        mirrored[fmt], nonmirrored[fmt] = current, original
    require(not saved_evaluation["all_model_checks_pass"], "the rejected model was relabelled PASS")
    return mirrored, nonmirrored, {"non_mirrored_naive_equality_model_rejected": rejection}


def check_gpu_final():
    result = {}
    for arch in ARCHES:
        records = read_json(ROOT / f"gpu-final-{arch}.json")
        require(len(records) == 2 and all(record["rc"] == 0 for record in records), "final telemetry rc")
        line = records[0]["stdout"].strip()
        require(DEVICES[arch] in line and ", 0 MiB," in line, "final GPU state")
        require(not records[1]["stdout"], "final compute applications")
        result[arch] = {"timestamped_final_record": f"gpu-final-{arch}.json",
                        "zero_MiB_and_no_compute_apps": True}
    return result


def build_report():
    fhadd_records, fhadd, hset_records, hset_rejection = {}, {}, {}, {}
    for arch in ARCHES:
        fhadd_records[arch], fhadd[arch] = check_fhadd_arch(arch)
        current, original, hset_rejection[arch] = check_hset_arch(arch)
        hset_records[arch] = {"mirrored": current, "non_mirrored": original}
    fhadd_cross = {}
    all_serialized = {}
    for arch in ARCHES:
        records = fhadd_records[arch]
        outputs = {}
        for case in CASES + [REPLAY]:
            other = fhadd_records[ARCHES[1 - ARCHES.index(arch)]][case]
            a, b = records[case], other
            require(len(a["raw_observations"]) == len(b["raw_observations"]) == 11, "cross launch count")
            for left, right in zip(a["raw_observations"], b["raw_observations"]):
                require(left["domain"] == right["domain"] and left["launch"] == right["launch"]
                        and left["indices"] == right["indices"], "cross batch identity")
                for kind in ("a_pairs", "b_pairs", "echo", "out"):
                    require(left[kind] == right[kind], (case, kind, "cross-architecture mismatch"))
                outputs.setdefault(case, 0)
                outputs[case] += len(left["out"])
        require(sum(outputs[case] for case in CASES) == 5632 and outputs[REPLAY] == 352, "cross counts")
        fhadd_cross[arch] = outputs
        ordered = [obs for case, record in sorted(records.items()) for obs in record["raw_observations"]]
        payload = json.dumps(ordered, sort_keys=True, separators=(",", ":")).encode()
        all_serialized[arch] = hashlib.sha256(payload).hexdigest()
        require(all_serialized[arch] == FHADD_RAW_SHA, (arch, "raw observation digest"))
    hset_cross = {}
    for family in ("f16", "bf16"):
        packed_digests, mirrored_packed_digests, old_digests = {}, {}, {}
        for arch in ARCHES:
            mirrored = hset_records[arch]["mirrored"][family]
            original = hset_records[arch]["non_mirrored"][family]
            other_mirrored = hset_records[ARCHES[1 - ARCHES.index(arch)]]["mirrored"][family]
            other_original = hset_records[ARCHES[1 - ARCHES.index(arch)]]["non_mirrored"][family]
            for left, right in ((mirrored, other_mirrored), (original, other_original)):
                for a, b in zip(left["raw_observations"], right["raw_observations"]):
                    require(a["domain"] == b["domain"] and a["indices"] == b["indices"]
                            and all(a[kind] == b[kind] for kind in ("a_pairs", "b_pairs", "out", "echo")),
                            "HSET cross inputs/outputs")
            raw_hex = [obs["out"] for obs in mirrored["raw_observations"]]
            old_digest = hashlib.sha256(json.dumps(raw_hex).encode()).hexdigest()
            require(old_digest == HSET_RAW_SHA[family], (arch, family, "HSET digest"))
            packed = b"".join(int(value, 16).to_bytes(4, "little")
                              for obs in original["raw_observations"] for value in obs["out"])
            mirrored_packed = b"".join(int(value, 16).to_bytes(4, "little")
                                       for obs in mirrored["raw_observations"] for value in obs["out"])
            packed_digests[arch], old_digests[arch] = hashlib.sha256(packed).hexdigest(), old_digest
            mirrored_packed_digests[arch] = hashlib.sha256(mirrored_packed).hexdigest()
        hset_cross[family] = {
            "mirrored_outputs_per_arch": 352, "mirrored_batches_with_A_eq_B_per_arch": 11,
            "non_mirrored_outputs_per_arch": 352, "zero_cross_architecture_value_differences": True,
            "mirrored_digest_default_json_batches": old_digests,
            "mirrored_digest_packed_u32le": mirrored_packed_digests,
            "non_mirrored_digest_packed_u32le": packed_digests,
        }
    return {
        "schema_version": 1,
        "verdict": "PASS_OFFLINE_AUDIT_OF_CACHED_GPU_OBSERVATIONS",
        "gpu_launches_performed_by_this_audit": 0,
        "fhadd": {
            "per_arch": fhadd,
            "per_arch_counts": {"core_cases": 16, "replay_cases": 1, "core_launches": 176,
                                "replay_launches": 11, "total_launches": 187,
                                "core_outputs": 5632, "replay_outputs": 352},
            "both_architecture_total_launches": 374,
            "cross_architecture_matched_values_per_arch": 5984,
            "cross_architecture_zero_value_differences": True,
            "canonical_raw_observation_sha256": all_serialized,
            "replay_is_duplicate_not_core_coverage": True,
        },
        "hset2": {
            "per_arch_rejected_model": hset_rejection,
            "cross_architecture": hset_cross,
            "mirrored_launches_per_arch": 22,
            "non_mirrored_model_falsification_launches_per_arch": 22,
            "all_model_falsification_runs_are_separate_from_accepted_A_eq_B_scope": True,
            "semantics_verdict": "OPEN_NO_EQ_SEMANTIC_CLAIM",
        },
        "final_gpu_telemetry": check_gpu_final(),
        "metadata_caveats": [
            "audit-sm100a.json retains an inherited 'SM100 execution' exclusion; raw-sm100a and hset-eq-raw contain native B200 completed execution records.",
            "The FHADD semantic claim is non-SAT and limited to measured F16/BF16 H0/H1 and FP32-wide output with exercised rounding variants.",
            "NaN payload is not universalized. SAT, unused fields, timing, cache and other forms remain unmeasured.",
            "HSET2 non-mirrored runs reject only the stated naive mask model; the A=B runs are raw SILICON-EFFECT observations, not an EQ theorem.",
            "Legacy hset-dual-execution.json sha256_outputs hashes nested JSON arrays of hex strings, not packed raw bytes; both mirrored serializations are separately reported above.",
        ],
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=pathlib.Path)
    parser.add_argument("--check", type=pathlib.Path)
    args = parser.parse_args()
    report = build_report()
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(rendered)
    if args.check:
        require(args.check.read_text() == rendered, f"stale validation artifact: {args.check}")
    if not args.check:
        print(json.dumps({"verdict": report["verdict"],
                          "fhadd": report["fhadd"]["per_arch_counts"],
                          "hset2_rejected_mismatches": {
                              arch: {family: row["model_mismatches"] for family, row
                                     in value["non_mirrored_naive_equality_model_rejected"].items()}
                              for arch, value in report["hset2"]["per_arch_rejected_model"].items()},
                          "gpu_launches_performed": 0}, indent=2))


if __name__ == "__main__":
    main()

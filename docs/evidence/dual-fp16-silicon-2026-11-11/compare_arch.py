#!/usr/bin/env python3
"""Compare exact scoped raw outputs from SM103a and SM100a."""
import hashlib
import json
import pathlib

ROOT = pathlib.Path(__file__).resolve().parent


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def main():
    records = {}
    for arch in ("sm103a", "sm100a"):
        directory = ROOT / f"raw-{arch}"
        for path in sorted(directory.glob("*.json")):
            result = json.loads(path.read_text())
            assert result["status"] == "completed", (arch, path.name)
            assert result["launches"] == 11 and result["canaries_all_intact"] \
                and result["inputs_outputs_observed"], (arch, path.name)
            records[arch, path.stem] = result
        assert len(list(directory.glob("*.json"))) == 17
    case_count = 0
    launch_count = 0
    differences = []
    for case in ("plain_bf16_h1", "plain_bf16_h1_replay"):
        assert case in {case for _, case in records}
    for case in sorted({pair[1] for pair in records}):
        case_count += 1
        b = records["sm100a", case]
        a = records["sm103a", case]
        assert len(a["raw_observations"]) == len(b["raw_observations"]) == 11
        for obs_a, obs_b in zip(a["raw_observations"], b["raw_observations"]):
            assert obs_a["domain"] == obs_b["domain"]
            assert obs_a["launch"] == obs_b["launch"]
            assert obs_a["indices"] == obs_b["indices"]
            launch_count += 1
            for index, first, second in zip(obs_a["indices"], obs_a["out"], obs_b["out"]):
                if first != second:
                    differences.append({"case": case, "domain": obs_a["domain"],
                                        "batch_start": obs_a["batch_start"], "index": index,
                                        "sm103a": first, "sm100a": second})
            for kind in ("a_pairs", "b_pairs", "echo"):
                if obs_a[kind] != obs_b[kind]:
                    raise AssertionError((case, obs_a["launch"], kind))
    result = {
        "scope": "16 core forms per arch plus one repeat of plain_bf16_h1; no performance claim",
        "core_observations_per_arch": 5632,
        "replay_observations_per_arch": 352,
        "total_observations_per_arch": 5984,
        "record_metadata_preserved_separately": True,
        "exact_value_differences": differences,
        "zero_output_differences": not differences,
        "raw_observation_sha256": {
            arch: hashlib.sha256(canonical([
                obs
                for (_, case), record in sorted(records.items()) if _ == arch
                for obs in record["raw_observations"]
            ]).encode()).hexdigest()
            for arch in ("sm103a", "sm100a")
        },
        "audit_sm103a": json.loads((ROOT / "audit-sm103a.json").read_text()),
        "audit_sm100a": json.loads((ROOT / "audit-sm100a.json").read_text()),
    }
    assert result["zero_output_differences"] or differences
    assert case_count == 17 and launch_count == 187
    assert result["raw_observation_sha256"]["sm103a"] == result["raw_observation_sha256"]["sm100a"]
    (ROOT / "cross-architecture-results.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({key: result[key] for key in (
        "core_observations_per_arch", "replay_observations_per_arch", "total_observations_per_arch",
        "zero_output_differences", "raw_observation_sha256")}, indent=2))


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Synchronize Cubit's vendored SM120 table from blackwell-isa.

The vendored file is generated data.  Its provenance is recorded in
tables/SM120_SOURCE.json and CI verifies it against the exact canonical commit.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SOURCE = ROOT.parent / "blackwell-isa" / "sm120.json"
DEFAULT_DESTINATION = ROOT / "tables" / "sm120.json"
DEFAULT_METADATA = ROOT / "tables" / "SM120_SOURCE.json"


class SyncError(RuntimeError):
    """A provenance or synchronization invariant failed."""


FIXED_EXTRACTIONS = {
    "",
    "abs",
    "barrier",
    "byte_sel",
    "cm16_off",
    "cm17_off",
    "f16",
    "f16_d",
    "f32",
    "f64hi",
    "guard",
    "guard_lo3",
    "guard_neg",
    "imm",
    "imm_dec",
    "imm_dec_u32",
    "inv",
    "neg",
    "neg_abs",
    "neg_shl1",
    "opaque_mod",
    "pred",
    "reg",
    "reg_ff",
    "reuse",
    "sub_imm0",
    "sub_imm0_s24",
    "sub_imm1",
    "sub_imm1_s24",
    "sub_imm2",
    "sub_imm2_s24",
    "sub_r0",
    "sub_r1",
    "sub_r2",
    "sub_ur0",
    "sub_ur1",
    "sysreg",
    "sysreg_hi1",
    "sysreg_hi4",
    "sysreg_lo4",
    "sysreg_lo7",
    "upred",
    "ureg",
    "ureg_ff",
}
EXTRACTION_PATTERN = re.compile(
    r"(?:reg|ureg|imm)_shr\d+|"
    r"sub_(?:r|ur|imm)\d+_shr\d+"
)
U128_MAX = (1 << 128) - 1


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise SyncError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def parse_u128(value: Any, context: str) -> int:
    if not isinstance(value, str):
        raise SyncError(f"{context} must be a hexadecimal string")
    try:
        parsed = int(value, 16)
    except ValueError as exc:
        raise SyncError(f"{context} is not valid hexadecimal: {value}") from exc
    if parsed < 0 or parsed > U128_MAX:
        raise SyncError(f"{context} does not fit in 128 bits: {value}")
    return parsed


def known_extraction(value: Any) -> bool:
    return isinstance(value, str) and (
        value in FIXED_EXTRACTIONS or EXTRACTION_PATTERN.fullmatch(value) is not None
    )


def run_git(repo: Path, *args: str, check: bool = True) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo), *args],
        check=False,
        capture_output=True,
        text=True,
    )
    if check and result.returncode:
        detail = result.stderr.strip() or result.stdout.strip()
        raise SyncError(f"git {' '.join(args)} failed: {detail}")
    return result.stdout.strip()


def canonical_repository(source: Path) -> tuple[Path, str, str]:
    source = source.resolve()
    repo_text = run_git(source.parent, "rev-parse", "--show-toplevel")
    repo = Path(repo_text).resolve()
    try:
        relative = source.relative_to(repo).as_posix()
    except ValueError as exc:
        raise SyncError(f"{source} is outside its Git repository {repo}") from exc

    run_git(repo, "ls-files", "--error-unmatch", "--", relative)
    dirty = run_git(repo, "status", "--porcelain", "--", relative)
    if dirty:
        raise SyncError(
            f"canonical source is not committed: {relative}\n{dirty}\n"
            "Commit blackwell-isa first so the vendored table has immutable provenance."
        )

    # Pin the commit that last changed the table, not an unrelated newer docs
    # commit at repository HEAD. The clean-file check above guarantees that this
    # revision still describes the bytes being synchronized.
    revision = run_git(repo, "log", "-1", "--format=%H", "--", relative)
    remote = run_git(repo, "remote", "get-url", "origin")
    if remote.startswith("git@github.com:"):
        remote = "https://github.com/" + remote.removeprefix("git@github.com:")
    if remote.endswith(".git"):
        remote = remote[:-4]
    return repo, revision, remote


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def validate_table(data: bytes) -> dict[str, int]:
    try:
        table: dict[str, Any] = json.loads(data, object_pairs_hook=unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SyncError(f"canonical table is not valid UTF-8 JSON: {exc}") from exc

    allowed_top_level = {"_meta", "instructions", "sched_only", "pipeline_config"}
    extra_top_level = sorted(set(table) - allowed_top_level)
    if extra_top_level:
        raise SyncError(f"unexpected top-level records: {', '.join(extra_top_level)}")

    meta = table.get("_meta", {})
    if meta.get("architecture") != "SM120" or meta.get("instruction_width") != 128:
        raise SyncError("canonical table is not an SM120 128-bit ISA database")

    instructions = table.get("instructions")
    if not isinstance(instructions, dict) or not instructions:
        raise SyncError("canonical table has no instruction map")

    ctrl_classes = set(meta.get("ctrl_classes", {}))
    legacy_ctrl_classes = {"none", "static_ctrl"}
    variants = 0
    high_bit_entries: list[str] = []
    for key, entry in instructions.items():
        if not isinstance(entry, dict):
            raise SyncError(f"{key} must be an object")
        ctrl_class = entry.get("ctrl_class")
        if (
            ctrl_class is not None
            and ctrl_class not in ctrl_classes
            and ctrl_class not in legacy_ctrl_classes
        ):
            raise SyncError(f"{key} references unknown ctrl_class {ctrl_class!r}")
        groups = entry.get("mod_groups", {})
        if not isinstance(groups, dict):
            raise SyncError(f"{key}.mod_groups must be an object")

        for group, variant in groups.items():
            variants += 1
            context = f"{key}::{group}"
            if not isinstance(variant, dict):
                raise SyncError(f"{context} must be an object")
            and_base = parse_u128(variant.get("and_base"), f"{context}.and_base")
            if and_base >> 105:
                high_bit_entries.append(context)

            variable_mask = variant.get("variable_mask")
            if variable_mask is not None:
                parse_u128(variable_mask, f"{context}.variable_mask")

            fields = variant.get("fields", [])
            if not isinstance(fields, list):
                raise SyncError(f"{context}.fields must be an array")
            for index, field in enumerate(fields):
                field_context = f"{context}.fields[{index}]"
                if not isinstance(field, dict):
                    raise SyncError(f"{field_context} must be an object")
                shift = field.get("shift")
                bits = field.get("bits")
                token_idx = field.get("token_idx")
                if not isinstance(shift, int) or not isinstance(bits, int):
                    raise SyncError(f"{field_context} shift/bits must be integers")
                if shift < 0 or bits <= 0 or shift + bits > 128:
                    raise SyncError(
                        f"{field_context} exceeds the 128-bit instruction: "
                        f"shift={shift}, bits={bits}"
                    )
                if not isinstance(token_idx, int) or token_idx < 0:
                    raise SyncError(f"{field_context}.token_idx must be non-negative")
                extraction = field.get("extraction", "")
                if not known_extraction(extraction):
                    raise SyncError(
                        f"{field_context} uses unknown extraction {extraction!r}"
                    )

    if high_bit_entries:
        sample = ", ".join(high_bit_entries[:5])
        raise SyncError(
            f"{len(high_bit_entries)} templates bake control/reuse bits [127:105]: {sample}"
        )

    return {
        "instruction_forms": len(instructions),
        "encoding_variants": variants,
        "sched_only_entries": len(table.get("sched_only", {})),
    }


def expected_metadata(
    source: Path,
    revision: str,
    repository: str,
    source_hash: str,
    summary: dict[str, int],
) -> dict[str, Any]:
    return {
        "schema": 1,
        "repository": repository,
        "revision": revision,
        "path": source.name,
        "sha256": source_hash,
        **summary,
    }


def check_sync(
    source_data: bytes,
    destination: Path,
    metadata_path: Path,
    expected: dict[str, Any],
) -> None:
    if not destination.is_file():
        raise SyncError(f"vendored table is missing: {destination}")
    if not metadata_path.is_file():
        raise SyncError(f"source metadata is missing: {metadata_path}")

    try:
        recorded = json.loads(metadata_path.read_text())
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SyncError(f"invalid source metadata: {metadata_path}: {exc}") from exc

    if recorded != expected:
        raise SyncError(
            "tables/SM120_SOURCE.json does not describe the supplied canonical checkout"
        )
    if destination.read_bytes() != source_data:
        raise SyncError(
            "tables/sm120.json differs from canonical blackwell-isa; "
            "run tools/sync_table.py after updating the source revision"
        )


def write_sync(
    source_data: bytes,
    destination: Path,
    metadata_path: Path,
    metadata: dict[str, Any],
) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(source_data)
    metadata_path.write_text(json.dumps(metadata, indent=2) + "\n")


def test_candidate(source: Path) -> None:
    env = os.environ.copy()
    env["CUBIT_TABLE"] = str(source)
    result = subprocess.run(["cargo", "test"], cwd=ROOT, env=env, check=False)
    if result.returncode:
        raise SyncError(f"candidate table failed cargo test: {source}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=DEFAULT_SOURCE)
    parser.add_argument("--destination", type=Path, default=DEFAULT_DESTINATION)
    parser.add_argument("--metadata", type=Path, default=DEFAULT_METADATA)
    parser.add_argument(
        "--check",
        action="store_true",
        help="verify provenance and byte equality without writing files",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    source = args.source.resolve()
    if not source.is_file():
        raise SyncError(f"canonical table is missing: {source}")

    _, revision, repository = canonical_repository(source)
    source_data = source.read_bytes()
    summary = validate_table(source_data)
    metadata = expected_metadata(
        source, revision, repository, digest(source_data), summary
    )

    if args.check:
        check_sync(source_data, args.destination, args.metadata, metadata)
        action = "verified"
    else:
        test_candidate(source)
        write_sync(source_data, args.destination, args.metadata, metadata)
        action = "synchronized"

    print(
        f"{action} {summary['instruction_forms']} forms / "
        f"{summary['encoding_variants']} variants from {revision[:12]}"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except SyncError as exc:
        print(f"sync_table.py: error: {exc}", file=sys.stderr)
        raise SystemExit(1)

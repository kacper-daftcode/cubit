#!/usr/bin/env python3
"""Synchronize Cubit's vendored SM120 table from blackwell-isa.

The vendored file is generated data.  Its provenance is recorded in
tables/SM120_SOURCE.json and CI verifies it against the exact canonical commit.
"""

from __future__ import annotations

import argparse
import hashlib
import json
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
        table: dict[str, Any] = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SyncError(f"canonical table is not valid UTF-8 JSON: {exc}") from exc

    meta = table.get("_meta", {})
    if meta.get("architecture") != "SM120" or meta.get("instruction_width") != 128:
        raise SyncError("canonical table is not an SM120 128-bit ISA database")
    if "FMUL_R_R_FI" in table:
        raise SyncError("canonical table contains the obsolete top-level FMUL_R_R_FI record")

    instructions = table.get("instructions")
    if not isinstance(instructions, dict) or not instructions:
        raise SyncError("canonical table has no instruction map")

    variants = 0
    high_bit_entries: list[str] = []
    for key, entry in instructions.items():
        for group, variant in entry.get("mod_groups", {}).items():
            variants += 1
            try:
                and_base = int(variant["and_base"], 16)
            except (KeyError, TypeError, ValueError) as exc:
                raise SyncError(f"{key}::{group} has an invalid and_base") from exc
            if and_base >> 105:
                high_bit_entries.append(f"{key}::{group}")

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

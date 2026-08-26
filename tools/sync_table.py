#!/usr/bin/env python3
"""Synchronize cubit's vendored ISA tables from blackwell-isa (O2 layout).

One table per architecture, vendored byte-exact, plus a single manifest at
tables/SOURCE.json pinning every table to the canonical revision:

  * default mode: copy tables/<arch>.json from the canonical checkout and
    rewrite the manifest (runs the test suite as a fail-closed gate),
  * --check: verify tables/*.json byte-match the manifest pins (CI byte-pin;
    with --source-repo present, also byte-compares against the canonical
    checkout at the pinned revisions),
  * --validate-only: structural validation of the vendored tables only
    (pre-check; no canonical repo needed).

The vendored files are generated data: never edit them by hand (rule R1).
Fixes go to the canonical database or to the export pipeline, then land here
through a new canonical revision.
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
DEFAULT_SOURCE_REPO = ROOT.parent / "blackwell-isa"
TABLES_DIR = ROOT / "tables"
MANIFEST = TABLES_DIR / "SOURCE.json"

# arch name -> canonical _meta.architecture value
ARCH_TABLES = {
    "sm120.json": "SM120",
    "sm103a.json": "SM103a",
    "sm100a.json": "SM100a",
    "sm121a.json": "SM121A",
}

# Top-level records a canonical table may carry. The aux sections are O2
# layout payloads (single table per arch; no cubit sidecar data files).
ALLOWED_TOP_LEVEL = {
    "_meta", "instructions", "sched_only", "pipeline_config",
    "cost_model", "stallfix", "operand_roles",
}
AUX_SECTIONS = ("cost_model", "stallfix", "operand_roles")


class SyncError(RuntimeError):
    """A provenance or synchronization invariant failed."""


# Ratchet baselines for the baked control/reuse-bit check
# (and_base bits [127:105] set). Lower only on purpose, together with a
# silicon-verified canonical hygiene wave.
BAKED_CTRL_BASELINE = {"SM120": 456, "SM103a": 1269, "SM100a": 1257,
                       "SM121A": 458}

FIXED_EXTRACTIONS = {
    "",
    "abs",
    "addr_scale",
    "barrier",
    "byte_sel",
    "cm16_off",
    "cm17_off",
    "bf16",
    "desc_ur",
    "dsel2",
    "f16",
    "f16_d",
    "f32",
    "f32cast",
    "f64hi",
    "gdesc_off",
    "gdesc_ur",
    "hsel",
    "guard",
    "guard_lo3",
    "guard_neg",
    "imm",
    "imm_dec",
    "imm_dec_u32",
    "inv",
    "neg",
    "neg_abs",
    "neg_f32",
    "neg_shl1",
    "opaque_mod",
    "pred",
    "pred_inv4",
    "upred_gate",
    "urz_expl",
    "urz_expl_inv",
    "reg",
    "reg_ff",
    "reuse",
    "sub_imm0",
    "sub_imm0_s24",
    "sub_imm1",
    "sub_imm1_s24",
    "sub_imm2",
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
    r"sub_(?:r|ur|imm)\d+(?:_m1)?(?:_shr\d+u?)?|"  # unsigned sub variants (BUG-070)
    r"opmod:[A-Za-z0-9_]+|"
    r"mnemod1:[A-Za-z0-9_]+|"
    r"t(?:desc|mem)_(?:off|ur)"
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
        check=False, capture_output=True, text=True,
    )
    if check and result.returncode:
        detail = result.stderr.strip() or result.stdout.strip()
        raise SyncError(f"git {' '.join(args)} failed: {detail}")
    return result.stdout.strip()


def run_git_bytes(repo: Path, *args: str) -> bytes:
    """Binary-safe git read (no strip/newline mangling)."""
    result = subprocess.run(
        ["git", "-C", str(repo), *args], check=False, capture_output=True,
    )
    if result.returncode:
        raise SyncError(f"git {' '.join(args)} failed: {result.stderr.decode(errors='replace').strip()}")
    return result.stdout


def canonical_revision(repo: Path, relative: str) -> str:
    repo_file = repo / relative
    run_git(repo, "ls-files", "--error-unmatch", "--", relative)
    dirty = run_git(repo, "status", "--porcelain", "--", relative)
    if dirty:
        raise SyncError(
            f"canonical source is not committed: {relative}\n{dirty}\n"
            "Commit blackwell-isa first so the vendored table has immutable provenance."
        )
    if not repo_file.is_file():
        raise SyncError(f"canonical table is missing: {repo_file}")
    # Pin the commit that last changed the table, not an unrelated newer docs
    # commit at repository HEAD. The clean-file check above guarantees that
    # this revision still describes the bytes being synchronized.
    return run_git(repo, "log", "-1", "--format=%H", "--", relative)


def canonical_repository_url(repo: Path) -> str:
    remote = run_git(repo, "remote", "get-url", "origin")
    if remote.startswith("git@github.com:"):
        remote = "https://github.com/" + remote.removeprefix("git@github.com:")
    if remote.endswith(".git"):
        remote = remote[:-4]
    return remote


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def validate_aux_sections(table: dict[str, Any], arch_meta: str) -> None:
    cost = table.get("cost_model")
    if cost is not None:
        if not isinstance(cost, dict) or not cost.get("arch") \
                or "quantum_cy" not in cost or "dep_link_latency_slots" not in cost:
            raise SyncError("cost_model section fails sanity (arch/quantum/dep_link)")
        norm = lambda s: str(s).lower().replace("_", "")
        if norm(cost["arch"]) != norm(arch_meta):
            raise SyncError(
                f"cost_model arch {cost['arch']!r} mismatches table arch {arch_meta!r}")
    stall = table.get("stallfix")
    if stall is not None:
        if not isinstance(stall, dict) or "rules_version" not in stall \
                or "floor_global" not in stall:
            raise SyncError("stallfix section fails sanity (rules_version/floor_global)")
    roles = table.get("operand_roles")
    if roles is not None:
        if not isinstance(roles, dict) or not isinstance(roles.get("base_ops"), dict) \
                or not roles["base_ops"]:
            raise SyncError("operand_roles section fails sanity (base_ops)")


def validate_table(data: bytes, arch: str) -> dict[str, Any]:
    try:
        table: dict[str, Any] = json.loads(data, object_pairs_hook=unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SyncError(f"canonical table is not valid UTF-8 JSON: {exc}") from exc

    extra_top_level = sorted(set(table) - ALLOWED_TOP_LEVEL)
    # underscore-prefixed top-level keys are the reserved annotation zone
    # (sm121a carries the 121a lane's `_errata_*` evidence notes by design)
    soft_annotations = [k for k in extra_top_level if k.startswith("_")]
    hard_junk = [k for k in extra_top_level if not k.startswith("_")]
    if hard_junk:
        raise SyncError(f"unexpected top-level records: {', '.join(hard_junk)}")
    if soft_annotations:
        print(f"note: {len(soft_annotations)} reserved top-level annotations "
              f"(^-prefixed) tolerated ({extra_top_level[0]}, …)")

    meta = table.get("_meta", {})
    if meta.get("architecture") != arch or meta.get("instruction_width") != 128:
        raise SyncError(f"canonical table is not an {arch} 128-bit ISA database")

    instructions = table.get("instructions")
    if not isinstance(instructions, dict) or not instructions:
        raise SyncError("canonical table has no instruction map")

    validate_aux_sections(table, arch)

    ctrl_classes = set(meta.get("ctrl_classes", {}))
    legacy_ctrl_classes = {"none", "static_ctrl", "unknown"}
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

    baseline = BAKED_CTRL_BASELINE[arch]
    if len(high_bit_entries) > baseline:
        sample = ", ".join(high_bit_entries[:5])
        raise SyncError(
            f"{len(high_bit_entries)} templates bake control/reuse bits "
            f"[127:105] (baseline {baseline}): {sample}"
        )
    if high_bit_entries:
        print(
            f"note: {len(high_bit_entries)}/{baseline} baked-ctrl "
            f"templates (allowed by ratchet, {arch})"
        )

    return {
        "instruction_forms": len(instructions),
        "encoding_variants": variants,
        "sched_only_entries": len(table.get("sched_only", {})),
        "sections": sorted(
            k for k in table
            if k not in ("_meta", "instructions", "sched_only", "pipeline_config")
        ),
    }


def load_manifest() -> dict[str, Any]:
    if not MANIFEST.is_file():
        raise SyncError(f"manifest is missing: {MANIFEST}")
    try:
        manifest = json.loads(MANIFEST.read_text())
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SyncError(f"invalid manifest {MANIFEST}: {exc}") from exc
    if manifest.get("schema") != 2 or not isinstance(manifest.get("tables"), dict):
        raise SyncError(f"{MANIFEST}: expected schema 2 with a 'tables' map")
    unknown = sorted(set(manifest["tables"]) - set(ARCH_TABLES))
    if unknown:
        raise SyncError(f"manifest lists unknown tables: {', '.join(unknown)}")
    return manifest


def sync_tables(source_repo: Path) -> None:
    source_repo = source_repo.resolve()
    repo_text = run_git(source_repo, "rev-parse", "--show-toplevel")
    repo = Path(repo_text).resolve()
    repository = canonical_repository_url(repo)

    staged: dict[str, tuple[bytes, dict[str, Any], str]] = {}
    for name, arch in ARCH_TABLES.items():
        data = (repo / name).read_bytes() if (repo / name).is_file() else None
        if data is None:
            raise SyncError(f"canonical table is missing: {repo / name}")
        summary = validate_table(data, arch)
        revision = canonical_revision(repo, name)
        staged[name] = (data, summary, revision)

    TABLES_DIR.mkdir(exist_ok=True)
    for name, (data, _summary, _rev) in staged.items():
        (TABLES_DIR / name).write_bytes(data)

    print("running cargo test gate on the vendored candidates...")
    result = subprocess.run(["cargo", "test", "--quiet"], cwd=ROOT, check=False)
    if result.returncode:
        raise SyncError(
            "candidate tables failed cargo test; vendored tables were written "
            "but the manifest was NOT re-pinned")

    # One canonical revision for the whole vendoring (owner layout decision
    # 2026-08-25: a single base_revision for the manifest).  All tables must
    # carry their pinned bytes at that revision; canonical updates touching a
    # single table first, so table revisions are allowed to be older than the
    # newest one as long as the bytes match at the pinned revision.
    by_date = sorted(
        {rev for _d, _s, rev in staged.values()},
        key=lambda r: int(run_git(repo, "show", "-s", "--format=%ct", r)),
    )
    base_revision = None
    for rev in reversed(by_date):  # newest first
        if all(
            digest(run_git_bytes(repo, "show", f"{rev}:{name}")) == digest(data)
            for name, (data, _s, _r) in staged.items()
        ):
            base_revision = rev
            break
    if base_revision is None:
        raise SyncError(
            "canonical tables sit at divergent revisions with no common "
            "revision carrying the pinned bytes; make one canonical cut first")

    manifest: dict[str, Any] = {
        "schema": 2,
        "repository": repository,
        "base_revision": base_revision,
        "tables": {},
    }
    for name, (data, summary, _rev) in staged.items():
        manifest["tables"][name] = {
            "arch": ARCH_TABLES[name],
            "base_sha256": digest(data),
            **summary,
        }
    MANIFEST.write_text(json.dumps(manifest, indent=2) + "\n")
    for name, (_d, summary, _rev) in staged.items():
        print(
            f"synchronized {name}: {summary['instruction_forms']} forms / "
            f"{summary['encoding_variants']} variants from {base_revision[:12]}"
        )


def check_tables(source_repo: Path | None) -> None:
    manifest = load_manifest()
    base_revision = manifest.get("base_revision")
    for name, entry in manifest["tables"].items():
        entry.setdefault("base_revision", base_revision)  # schema-2 top-level pin
        dest = TABLES_DIR / name
        if not dest.is_file():
            raise SyncError(f"vendored table is missing: {dest}")
        actual = digest(dest.read_bytes())
        if actual != entry.get("base_sha256"):
            raise SyncError(
                f"{dest} does not match the manifest pin; "
                "run tools/sync_table.py after updating the canonical revision"
            )
        validate_table(dest.read_bytes(), ARCH_TABLES[name])
        print(f"pinned {name}: sha256 {actual[:16]}… ({entry['base_revision'][:12]})")
    if source_repo is not None:
        repo = source_repo.resolve()
        for name, entry in manifest["tables"].items():
            src = repo / name
            if not src.is_file():
                raise SyncError(f"--source-repo checkout lacks {src}")
            if digest(src.read_bytes()) != entry["base_sha256"]:
                raise SyncError(
                    f"{src} differs from the pinned bytes; bump the canonical "
                    "revision or re-sync"
                )
            # Immutable provenance: the pinned revision must carry exactly
            # the pinned bytes for this table.
            try:
                raw = run_git_bytes(repo, "show", f"{entry['base_revision']}:{name}")
            except SyncError:
                raw = b""
            if digest(raw) != entry["base_sha256"]:
                raise SyncError(
                    f"canonical revision {entry['base_revision'][:12]} does not "
                    f"carry the pinned bytes for {name}"
                )
        print(f"canonical checkout {repo} matches all pins")


def validate_only() -> None:
    for name, arch in ARCH_TABLES.items():
        dest = TABLES_DIR / name
        if not dest.is_file():
            raise SyncError(f"vendored table is missing: {dest}")
        summary = validate_table(dest.read_bytes(), arch)
        print(
            f"validated {name}: {summary['instruction_forms']} forms / "
            f"{summary['encoding_variants']} variants (structure, no pin)"
        )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-repo", type=Path, default=None,
                        help="canonical blackwell-isa checkout "
                             f"(default: {DEFAULT_SOURCE_REPO} when it exists)")
    parser.add_argument("--check", action="store_true",
                        help="verify manifest byte-pins without writing files")
    parser.add_argument("--validate-only", action="store_true",
                        help="structurally validate the vendored tables "
                             "(no canonical repo needed)")
    args = parser.parse_args()

    source_repo = args.source_repo
    if source_repo is None and DEFAULT_SOURCE_REPO.is_dir():
        source_repo = DEFAULT_SOURCE_REPO

    if args.validate_only:
        validate_only()
        return 0
    if args.check:
        check_tables(source_repo)
        return 0
    if source_repo is None:
        raise SyncError("no canonical checkout found (use --source-repo)")
    sync_tables(source_repo)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except SyncError as exc:
        print(f"sync_table.py: error: {exc}", file=sys.stderr)
        raise SystemExit(1)

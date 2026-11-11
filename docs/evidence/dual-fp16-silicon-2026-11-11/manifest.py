#!/usr/bin/env python3
"""Hash every regular file in this evidence directory, excluding hash outputs."""

import argparse
import hashlib
import json
import pathlib

ROOT = pathlib.Path(__file__).resolve().parent
EXCLUDED = {"MANIFEST.json", "SHA256SUMS"}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def inventory():
    files = []
    for path in sorted(ROOT.rglob("*")):
        if path.is_dir():
            continue
        relative = path.relative_to(ROOT)
        if str(relative) in EXCLUDED:
            continue
        assert "__pycache__" not in relative.parts and path.suffix != ".pyc", relative
        assert path.is_file() and not path.is_symlink(), relative
        files.append({"path": relative.as_posix(), "bytes": path.stat().st_size,
                      "sha256": digest(path)})
    return files


def build():
    files = inventory()
    canonical = json.dumps(files, sort_keys=True, separators=(",", ":")).encode()
    return {"schema_version": 1,
            "scope": "every regular file under this evidence directory except MANIFEST.json and SHA256SUMS",
            "file_count": len(files), "total_bytes": sum(item["bytes"] for item in files),
            "aggregate_sha256_of_canonical_file_records": hashlib.sha256(canonical).hexdigest(),
            "files": files}


def check():
    expected = build()
    actual = json.loads((ROOT / "MANIFEST.json").read_text())
    assert actual == expected, "MANIFEST is stale, incomplete or has hash mismatches"
    lines = (ROOT / "SHA256SUMS").read_text().splitlines()
    expected_lines = [f"{item['sha256']}  {item['path']}" for item in expected["files"]]
    expected_lines.append(f"{digest(ROOT / 'MANIFEST.json')}  MANIFEST.json")
    assert lines == expected_lines, "SHA256SUMS is stale, incomplete or has hash mismatches"
    return expected


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    assert args.write != args.check, "choose exactly one of --write and --check"
    if args.write:
        report = build()
        (ROOT / "MANIFEST.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
        lines = [f"{item['sha256']}  {item['path']}" for item in report["files"]]
        lines.append(f"{digest(ROOT / 'MANIFEST.json')}  MANIFEST.json")
        (ROOT / "SHA256SUMS").write_text("\n".join(lines) + "\n")
    else:
        report = check()
    print(json.dumps({"verdict": "PASS", "file_count": report["file_count"],
                      "total_bytes": report["total_bytes"],
                      "aggregate_sha256": report["aggregate_sha256_of_canonical_file_records"]}, indent=2))


if __name__ == "__main__":
    main()

"""Read cubit's vendored ISA tables whether they sit on disk as plain JSON or gzip.

Since 2026-11-04 the files in git are `tables/<arch>.json.gz` (single-member gzip,
`mtime=0`, written by `tools/sync_table.py`); `tables/<arch>.json` is a generated,
git-ignored convenience (`tools/sync_table.py --unpack`). `tables/SOURCE.json` pins
the SHA-256 of the *plain* bytes, so every consumer hashes and parses the same
bytes regardless of the file it opened. The Rust loader (`cubit::table::read_table_bytes`)
applies the same rule.

    from tablefile import read_table_bytes, load_table
    table = load_table("tables/sm120.json")        # plain file or its .gz twin
"""
from __future__ import annotations

import gzip
import json
from pathlib import Path
from typing import Any


def gz_twin(path: Path) -> Path:
    return path.with_name(path.name + ".gz")


def table_file_available(path: str | Path) -> bool:
    p = Path(path)
    return p.is_file() or (p.suffix != ".gz" and gz_twin(p).is_file())


def read_table_bytes(path: str | Path) -> bytes:
    """Plain JSON bytes of a table: the plain file if it exists, else the `.gz` twin
    decompressed; a path ending in `.gz` is always decompressed."""
    p = Path(path)
    if p.suffix == ".gz":
        return gzip.decompress(p.read_bytes())
    if p.is_file():
        return p.read_bytes()
    gz = gz_twin(p)
    if gz.is_file():
        return gzip.decompress(gz.read_bytes())
    raise FileNotFoundError(
        f"table file not found: {p} (neither the plain JSON nor {gz.name} exists; "
        "the vendored tables are tables/<arch>.json.gz)")


def load_table(path: str | Path, **json_kwargs: Any) -> Any:
    return json.loads(read_table_bytes(path), **json_kwargs)


def compress_table(plain: bytes) -> bytes:
    """Deterministic gzip of a table (no filename, mtime 0, level 9) so that an
    unchanged table yields unchanged bytes in git."""
    return gzip.compress(plain, compresslevel=9, mtime=0)

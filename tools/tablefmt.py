#!/usr/bin/env python3
"""The canonical on-disk layout of the blackwell-isa tables and the provenance-hoisting normalisation.

Every tool that reads or writes a canonical table (`sm120.json`, `sm103a.json`, `sm100a.json`,
`sm121a.json`) goes through this module (`tools/probes/nvprobe.py`, the probes' `apply`,
`tools/sync_table.py --validate-only`, the HTML exporter); `cubit`'s loader itself is a plain JSON
parser and accepts any layout.

Layout (2026-11-08, session T-23; NEEDS 61 — `sm121a.json` had reached 87 MiB in the former
`json.dumps(indent=1)` layout, GitHub refuses files over 100 MiB):

* compact JSON (no indentation inside a record, `,`/`:` separators);
* **one encoding row per line** — `instructions.<key>.mod_groups.<group>` is one line, so a diff of
  the table reads row by row; a key's own attributes (`base_op`, `operand_sig`, `_src`, `_note`, …)
  open the key's line, `mod_groups` is always the key's last attribute;
* `_meta` and the other top-level sections (`sched_only`, `pipeline_config`, `operand_roles`,
  `stallfix`, `cost_model`) keep `indent=1` — they are small and read by people;
* the file ends with a newline.

Provenance hoisting (`normalize`, idempotent; the data a row carries is unchanged, only where its
provenance is written changes):

* a row's `_src` stays on the row (the per-row provenance every consumer — the decoder's `rows-`
  arm, `tools/audit_table.py`, the tests — reads). When **every** row of a key carries the same
  `_src`, the key carries it too (`instructions.<key>._src`): the lattice families' convention.
* a row's `_note` (the measurement in prose) is hoisted to the key when **every** row of the key
  carries the same note, and from the keys to `_meta.provenance.sources[<tag>].note` when every
  key tagged `<tag>` carries the same note — the family's law is written once per family;
  a row or key keeps its own `_note` whenever it differs. `row_note()` resolves the three levels.
* a field's `_src` is dropped when it equals the row's `_src` (the row's tag names the measurement
  of every field of the row); a field measured by another tag than the row keeps its own.

`load_table` refuses a file that is not in the canonical layout (run `tools/tablefmt.py --rewrite`
on it); `save_table` normalises and writes the canonical layout.

    python3 tools/tablefmt.py --check sm120.json sm103a.json sm100a.json sm121a.json
    python3 tools/tablefmt.py --rewrite <table.json>...      # normalise + canonical layout, in place
    python3 tools/tablefmt.py --stats <table.json>...        # what the hoisting would move, sizes
"""
from __future__ import annotations

import argparse
import collections
import copy
import json
import pathlib
import sys
from typing import Any

COMPACT = (",", ":")


# ---------------------------------------------------------------------------
# layout
# ---------------------------------------------------------------------------

def _compact(obj: Any) -> str:
    return json.dumps(obj, separators=COMPACT)


def dumps(table: dict) -> str:
    """The canonical text of a table (see the module docstring)."""
    out: list[str] = ["{\n"]
    sections = list(table.items())
    for i, (name, value) in enumerate(sections):
        comma = "," if i < len(sections) - 1 else ""
        if name == "instructions" and isinstance(value, dict):
            out.append('"instructions": {\n')
            keys = list(value.items())
            for j, (key, entry) in enumerate(keys):
                kcomma = "," if j < len(keys) - 1 else ""
                if isinstance(entry, dict) and isinstance(entry.get("mod_groups"), dict):
                    attrs = {a: v for a, v in entry.items() if a != "mod_groups"}
                    head = _compact(attrs)[:-1]  # drop the closing brace; the key's line stays open
                    sep = "," if attrs else ""
                    out.append(f'{json.dumps(key)}: {head}{sep}"mod_groups": {{\n')
                    groups = list(entry["mod_groups"].items())
                    for g, (group, row) in enumerate(groups):
                        gcomma = "," if g < len(groups) - 1 else ""
                        out.append(f"{json.dumps(group)}: {_compact(row)}{gcomma}\n")
                    out.append(f"}}}}{kcomma}\n")
                else:
                    out.append(f"{json.dumps(key)}: {_compact(entry)}{kcomma}\n")
            out.append(f"}}{comma}\n")
        else:
            out.append(f"{json.dumps(name)}: {json.dumps(value, indent=1)}{comma}\n")
    out.append("}\n")
    return "".join(out)


def loads(data: bytes | str) -> dict:
    return json.loads(data)


def is_canonical(data: bytes) -> bool:
    return dumps(json.loads(data)).encode() == data


def load_table(path: pathlib.Path) -> dict:
    """Parse a canonical table; refuse one that is not in the canonical layout."""
    data = pathlib.Path(path).read_bytes()
    table = json.loads(data)
    if dumps(table).encode() != data:
        raise SystemExit(
            f"{path}: not in the canonical table layout (tools/tablefmt.py: compact JSON, one encoding "
            f"row per line, indent=1 _meta) -- run `python3 tools/tablefmt.py --rewrite {path}` first")
    return table


def save_table(path: pathlib.Path, table: dict) -> None:
    """Normalise the provenance (hoisting) and write the canonical layout."""
    normalize(table)
    pathlib.Path(path).write_text(dumps(table))


# ---------------------------------------------------------------------------
# provenance resolution
# ---------------------------------------------------------------------------

def iter_entries(table: dict):
    """(key, entry) for every real instruction entry (the sm121a `_errata_*` pseudo-entries skipped)."""
    for key, entry in table.get("instructions", {}).items():
        if isinstance(entry, dict) and isinstance(entry.get("mod_groups"), dict):
            yield key, entry


def row_src(entry: dict, row: dict) -> str | None:
    """The row's provenance tag: its own `_src`, else the key's."""
    src = row.get("_src")
    return src if src is not None else entry.get("_src")


def row_note(table: dict, entry: dict, row: dict) -> str | None:
    """The row's measurement note: its own, else the key's, else its tag's `_meta.provenance.sources[tag].note`."""
    if row.get("_note") is not None:
        return row["_note"]
    if entry.get("_note") is not None:
        return entry["_note"]
    tag = row_src(entry, row)
    if tag is None:
        return None
    source = table.get("_meta", {}).get("provenance", {}).get("sources", {}).get(tag)
    return source.get("note") if isinstance(source, dict) else None


def key_note(table: dict, entry: dict) -> str | None:
    """The key's note: its own, else its tag's."""
    if entry.get("_note") is not None:
        return entry["_note"]
    tag = entry.get("_src")
    if tag is None:
        return None
    source = table.get("_meta", {}).get("provenance", {}).get("sources", {}).get(tag)
    return source.get("note") if isinstance(source, dict) else None


def provenance_counts(table: dict) -> tuple[int, int]:
    """(rows_total, rows_without_src) -- the `_meta.provenance` counters."""
    total = without = 0
    for _key, entry in iter_entries(table):
        for row in entry["mod_groups"].values():
            total += 1
            if row_src(entry, row) is None:
                without += 1
    return total, without


# ---------------------------------------------------------------------------
# normalisation (hoisting)
# ---------------------------------------------------------------------------

def normalize(table: dict) -> dict:
    """Hoist the duplicated provenance (see the module docstring). In place; returns a summary."""
    summary: collections.Counter = collections.Counter()
    sources = table.get("_meta", {}).get("provenance", {}).get("sources")
    # tag -> the set of notes its rows resolve to before the tag-level hoist (None = a row without one)
    notes_by_tag: dict[str, set[str | None]] = collections.defaultdict(set)
    key_notes_by_tag: dict[str, dict[str, str]] = collections.defaultdict(dict)  # tag -> {key: key note}
    for key, entry in iter_entries(table):
        rows = list(entry["mod_groups"].values())
        if rows:
            srcs = {row.get("_src") for row in rows}
            if len(srcs) == 1 and None not in srcs:
                tag = next(iter(srcs))
                if entry.get("_src") != tag:
                    entry["_src"] = tag
                    summary["key_src_set"] += 1
            notes = {row.get("_note") for row in rows}
            if len(notes) == 1 and None not in notes:
                note = next(iter(notes))
                if entry.get("_note") in (None, note):
                    entry["_note"] = note
                    for row in rows:
                        del row["_note"]
                    summary["row_notes_hoisted"] += len(rows)
        for row in rows:
            eff = row_src(entry, row)
            for field in row.get("fields", []):
                if isinstance(field, dict) and "_src" in field and field["_src"] == eff:
                    del field["_src"]
                    summary["field_src_dropped"] += 1
            if eff is not None:
                own = row.get("_note")
                notes_by_tag[eff].add(own if own is not None else entry.get("_note"))
        if entry.get("_note") is not None and isinstance(entry.get("_src"), str):
            key_notes_by_tag[entry["_src"]][key] = entry["_note"]
    if isinstance(sources, dict):
        # the family's law moves to its provenance entry only when EVERY row of the tag carries it
        # (a tag shared by rows with and without the note keeps the note on the keys that have it)
        for tag, by_key in key_notes_by_tag.items():
            notes = notes_by_tag.get(tag, set())
            source = sources.get(tag)
            if len(notes) != 1 or None in notes or not isinstance(source, dict):
                continue
            note = next(iter(notes))
            if source.get("note") in (None, note):
                source["note"] = note
                for key, knote in by_key.items():
                    if knote == note:  # a key's own, different note (an older graft note) stays on the key
                        del table["instructions"][key]["_note"]
                        summary["key_notes_hoisted"] += 1
    provenance = table.get("_meta", {}).get("provenance")
    if isinstance(provenance, dict):
        total, without = provenance_counts(table)
        provenance["rows_total"] = total
        provenance["rows_without_src"] = without
    return dict(summary)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _stats(path: pathlib.Path) -> None:
    data = path.read_bytes()
    table = json.loads(data)
    canonical = dumps(table).encode()
    work = copy.deepcopy(table)
    summary = normalize(work)
    after = dumps(work).encode()
    total, without = provenance_counts(work)
    print(f"{path.name}: {len(data) / 2**20:.2f} MiB on disk; canonical layout {len(canonical) / 2**20:.2f} MiB; "
          f"normalised {len(after) / 2**20:.2f} MiB; rows {total}, without _src {without}; "
          f"canonical now: {'yes' if canonical == data else 'no'}; "
          f"normalised already: {'yes' if after == canonical else 'no'}; hoisting: {summary}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true", help="exit 1 unless every table is canonical and normalised")
    mode.add_argument("--rewrite", action="store_true", help="normalise + write the canonical layout in place")
    mode.add_argument("--stats", action="store_true", help="report the sizes and what the hoisting would move")
    ap.add_argument("tables", nargs="+", type=pathlib.Path)
    args = ap.parse_args()
    rc = 0
    for path in args.tables:
        if args.stats:
            _stats(path)
        elif args.check:
            data = path.read_bytes()
            table = json.loads(data)
            work = copy.deepcopy(table)
            normalize(work)
            if dumps(table).encode() != data:
                print(f"{path}: NOT canonical (layout)"); rc = 1
            elif dumps(work).encode() != data:
                print(f"{path}: NOT normalised (provenance hoisting pending)"); rc = 1
            else:
                print(f"{path}: canonical ({len(data) / 2**20:.2f} MiB)")
        else:
            data = path.read_bytes()
            table = json.loads(data)
            summary = normalize(table)
            out = dumps(table).encode()
            path.write_bytes(out)
            print(f"{path}: {len(data) / 2**20:.2f} -> {len(out) / 2**20:.2f} MiB; hoisting: {summary}")
    return rc


if __name__ == "__main__":
    sys.exit(main())

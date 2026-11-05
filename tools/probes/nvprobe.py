#!/usr/bin/env python3
"""Shared helpers for the SM120 nvdisasm probes under tools/probes/.

Every probe measures one instruction form against NVIDIA's disassembler
(nvdisasm 13.1, one 128-bit word per call: nvdisasm aborts a whole file on one
illegal word), writes the measured words to a `tests/fixtures/sm120_<form>_nvdisasm.jsonl`
fixture (`{"word", "nvidia_sass", "nvdisasm", "nvdisasm_sha256"[, "lattice": true]}`
per line; `nvidia_sass` is null for words nvdisasm rejects) and can `apply` the
measured rows to a canonical `sm120.json` (blackwell-isa). The words of a form
must decode and re-encode bit for bit in cubit; the lattice words document the
neighbourhood and must stay unclaimed (fail-closed).
"""
from __future__ import annotations

import hashlib
import json
import pathlib
import re
import subprocess

REPO = pathlib.Path(__file__).resolve().parents[2]
FIXTURES = REPO / "tests" / "fixtures"
SCHEDULE = ((1 << 23) - 1) << 105  # control code + reuse: never part of a row

_TEXT = re.compile(r"/\*0000\*/\s*(.*?)\s*;")


def nvdisasm_text(nvdisasm: str, scratch: pathlib.Path, word: int, ctrl: int, arch: str = "SM120"):
    """NVIDIA's text for one word (the control code `ctrl` is or-ed in), or None if illegal."""
    scratch.write_bytes((word | ctrl).to_bytes(16, "little"))
    r = subprocess.run([nvdisasm, "-b", arch, "-hex", str(scratch)], capture_output=True, text=True)
    if r.returncode:
        assert "Illegal instruction" in r.stderr, f"{word:032x}: {r.stderr.strip()[:200]}"
        return None
    m = _TEXT.search(r.stdout)
    # a word nvdisasm neither rejects nor renders (no instruction line) is unnamed
    return m.group(1).strip() if m else None


def nvdisasm_identity(nvdisasm: str) -> tuple[str, str]:
    version = subprocess.check_output([nvdisasm, "--version"], text=True).strip().splitlines()[-1]
    digest = hashlib.sha256(pathlib.Path(nvdisasm).read_bytes()).hexdigest()
    return version, digest


def write_fixture(out: pathlib.Path, rows: list[dict]) -> None:
    with out.open("w") as fh:
        for r in rows:
            fh.write(json.dumps(r) + "\n")


def probe_words(nvdisasm: str, name: str, words, ctrl: int, check_form, check_lattice=None, arch: str = "SM120"):
    """Measure `(word, lattice)` pairs; returns fixture rows. `check_form(word, text)` must
    hold for every form word; `check_lattice(word, text)` (text may be None) for lattice words.
    `arch` is nvdisasm's `-b` target (`SM120`, `SM100`, `SM103`, `SM121`)."""
    scratch = pathlib.Path(f"/tmp/re_{arch.lower()}_{name}_probe.bin")
    version, digest = nvdisasm_identity(nvdisasm)
    rows = []
    for w, lattice in words:
        body = nvdisasm_text(nvdisasm, scratch, w, ctrl, arch)
        if not lattice:
            assert body is not None and check_form(w, body), f"{w:032x}: {body}"
        elif check_lattice is not None:
            assert check_lattice(w, body), f"{w:032x}: {body}"
        row = {"word": f"{w:032x}", "nvidia_sass": body, "nvdisasm": version, "nvdisasm_sha256": digest}
        if arch != "SM120":
            row["arch"] = arch
        if lattice:
            row["lattice"] = True
        rows.append(row)
    return rows


def field(shift: int, bits: int, extraction: str, token: int, src: str) -> dict:
    return {"bits": bits, "extraction": extraction, "shift": shift, "token_idx": token, "_src": src}


def field_mask(fields: list[dict]) -> int:
    mask = 0
    for f in fields:
        bits = ((1 << f["bits"]) - 1) << f["shift"]
        assert mask & bits == 0, "measured fields are disjoint"
        mask |= bits
    return mask


def load_table(path: pathlib.Path) -> dict:
    before = path.read_bytes()
    table = json.loads(before)
    # canonical formatting is `json.dumps(indent=1)` + "\n"; the wave-11 tables (2026-11-05) were
    # written without the final newline -- accepted, `save_table` restores the canonical form
    canonical = json.dumps(table, indent=1).encode()
    assert before in (canonical + b"\n", canonical), "unexpected table formatting"
    return table


def save_table(path: pathlib.Path, table: dict) -> None:
    path.write_text(json.dumps(table, indent=1) + "\n")


def row(and_base: int, fields: list[dict], src: str, note: str) -> dict:
    mask = field_mask(fields)
    assert and_base & mask == 0, "and_base must be clear in the field bits"
    assert and_base & SCHEDULE == 0, "and_base must not bake control bits"
    return {
        "and_base": f"0x{and_base:032x}",
        "count": None,
        "fields": fields,
        "variable_mask": f"0x{mask:032x}",
        "_src": src,
        "_note": note,
    }

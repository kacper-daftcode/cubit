#!/usr/bin/env python3
"""Static audit of a canonical ISA table (blackwell-isa O2 layout) for the harvest-era defect classes.

The 2026-06..08 "harvest" learned rows from compiler output; several of them carried operand bytes
in the wrong place (the `ATOMS_R_ARURI_R` row read the address UR byte as a fourth register,
`cubit-internal/docs/TASK_ISA_FIELD_AUDIT.md` describes the same class for LDG/STG). This audit
flags, per (key, mod_group) row:

  baked_operand_byte      and_base has non-zero bits in a standard operand slot ([23:16] Rd,
                          [31:24] Ra, [39:32] Rb/UR, [63:40] imm/offset, [71:64] Rc/UR, [87:80]
                          mode) that no field covers -> an operand value learned as a constant
  field_token_beyond_sig  a field addresses an operand token the key's signature does not have
                          (the fourth-register defect)
  reg_field_off_slot      a `reg`/`ureg` field that is not 8 bits at one of the standard slots
  missing_imm_field       the key promises an immediate / offset operand (II, FI, ARI, AI, AURI,
                          ARURI, dARI, cAI, cARI ...) but the row has no imm / sub_imm field
  mask_excludes_field     variable_mask does not cover every bit of a declared field (the encoder
                          then cannot vary it; the decoder widens the mask itself)
  overlapping_claims      two rows of the same opcode whose constant bits agree on every bit both
                          rows consider constant: the decoder's tiebreak, not the table, decides
  count_null              informational: rows without a harvest record count (measured rows)

Usage: tools/audit_table.py [--table tables/sm120.json] [--out findings.jsonl] [--summary]
Exit 0 always (it is an inventory, not a gate); the JSONL has one finding per line.
"""
from __future__ import annotations

import argparse
import collections
import json
import pathlib
import re
import sys as _sys, pathlib as _pathlib
_sys.path.insert(0, str(_pathlib.Path(__file__).resolve().parent))
from tablefile import load_table  # plain tables/<arch>.json or the vendored .json.gz

SLOTS = {"Rd[23:16]": (16, 8), "Ra[31:24]": (24, 8), "Rb/UR[39:32]": (32, 8),
         "imm/off[63:40]": (40, 24), "Rc/UR[71:64]": (64, 8), "mode[87:80]": (80, 8)}
REG_SLOTS = {16, 24, 32, 64}
WORD96 = (1 << 96) - 1
IMM_SIGS = ("II", "FI", "ARI", "AI", "AURI", "ARURI", "dARI", "cAI", "cARI", "cAURI", "IM")
OP_TYPES = {"ARURI", "ARURI64", "ARURR", "ARUR", "AURI", "AURR", "AUR", "cAURI", "cAI", "cARI",
            "dARI", "ARI", "AI", "UP", "UR", "SR", "FI", "II", "IM", "LO", "R", "P", "L", "B", "?"}


def operand_tokens(key: str, entry: dict) -> int:
    """Number of operand tokens of a key (token 0 is the opcode/guard)."""
    sig = entry.get("operand_sig")
    if sig is None:
        parts = key.split("_")
        sig_parts = [p for p in parts[1:] if p in OP_TYPES or p.rstrip("?") in OP_TYPES]
        return len(sig_parts)
    return 0 if sig == "" else len(sig.split("_"))


def field_bits(f: dict) -> int:
    return ((1 << f["bits"]) - 1) << f["shift"]


def audit(table: dict) -> tuple[list[dict], dict]:
    findings: list[dict] = []
    stats: collections.Counter = collections.Counter()
    by_opcode: dict[int, list[tuple[str, str, int, int]]] = collections.defaultdict(list)
    for key, entry in table["instructions"].items():
        n_tok = operand_tokens(key, entry)
        for group, row in entry.get("mod_groups", {}).items():
            stats["rows"] += 1
            # the row's provenance tag: its own `_src`, else the key's (tools/tablefmt.py, 2026-11-08)
            row = dict(row, _src=row.get("_src", entry.get("_src"))) if "_src" not in row and entry.get("_src") else row
            ab = int(row["and_base"], 16)
            vm = int(row["variable_mask"], 16) if row.get("variable_mask") else 0
            fields = row.get("fields", [])
            fmask = 0
            for f in fields:
                fmask |= field_bits(f)
            if row.get("count") is None:
                stats["count_null"] += 1
                findings.append({"check": "count_null", "key": key, "group": group, "src": row.get("_src")})
            if row.get("_src"):
                stats["with_src"] += 1
            # 1. operand bytes baked into and_base without a field
            for slot, (shift, bits) in SLOTS.items():
                m = ((1 << bits) - 1) << shift
                baked = ab & m & ~fmask & ~vm
                if baked and shift != 80:
                    findings.append({"check": "baked_operand_byte", "key": key, "group": group, "slot": slot,
                                     "value": f"0x{baked >> shift:x}", "src": row.get("_src")})
                    stats["baked_operand_byte"] += 1
            # 2./3. field placement
            for f in fields:
                ext = f["extraction"]
                if f["token_idx"] > n_tok and n_tok > 0:
                    findings.append({"check": "field_token_beyond_sig", "key": key, "group": group,
                                     "field": ext, "shift": f["shift"], "token": f["token_idx"], "tokens": n_tok,
                                     "src": row.get("_src")})
                    stats["field_token_beyond_sig"] += 1
                if ext in ("reg", "ureg") and (f["bits"] != 8 or f["shift"] not in REG_SLOTS):
                    findings.append({"check": "reg_field_off_slot", "key": key, "group": group, "field": ext,
                                     "shift": f["shift"], "bits": f["bits"], "token": f["token_idx"],
                                     "src": row.get("_src")})
                    stats["reg_field_off_slot"] += 1
            # 4. promised immediate without a field
            sig_tokens = key.split("_")[1:]
            if any(t.rstrip("?") in IMM_SIGS for t in sig_tokens) and fields:
                has_imm = any(re.match(r"(sub_)?imm|f16|bf16|f32|f64hi|imm_|sub_imm", f["extraction"]) for f in fields)
                if not has_imm:
                    findings.append({"check": "missing_imm_field", "key": key, "group": group,
                                     "fields": [f["extraction"] for f in fields], "src": row.get("_src")})
                    stats["missing_imm_field"] += 1
            # 5. mask narrower than the fields
            if vm and fmask & ~vm & WORD96:
                findings.append({"check": "mask_excludes_field", "key": key, "group": group,
                                 "bits": f"0x{fmask & ~vm & WORD96:x}", "src": row.get("_src")})
                stats["mask_excludes_field"] += 1
            by_opcode[ab & 0xfff].append((key, group, ab & WORD96, (vm | fmask) & WORD96))
    # 6. overlapping claims per opcode
    for opcode, rows in by_opcode.items():
        for i in range(len(rows)):
            k1, g1, ab1, var1 = rows[i]
            for j in range(i + 1, len(rows)):
                k2, g2, ab2, var2 = rows[j]
                both_const = ~(var1 | var2) & WORD96
                if (ab1 ^ ab2) & both_const == 0:
                    findings.append({"check": "overlapping_claims", "opcode": f"0x{opcode:03x}",
                                     "a": [k1, g1], "b": [k2, g2],
                                     "same_key": k1 == k2})
                    stats["overlapping_claims"] += 1
    return findings, stats


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--table", default="tables/sm120.json")
    parser.add_argument("--out", type=pathlib.Path)
    parser.add_argument("--summary", action="store_true")
    args = parser.parse_args()
    table = load_table(args.table)
    findings, stats = audit(table)
    if args.out:
        with args.out.open("w") as fh:
            for f in findings:
                fh.write(json.dumps(f) + "\n")
    print(f"{args.table}: {stats['rows']} rows, {stats['with_src']} with _src")
    for check in ("baked_operand_byte", "field_token_beyond_sig", "reg_field_off_slot", "missing_imm_field",
                  "mask_excludes_field", "overlapping_claims", "count_null"):
        print(f"  {check:24s} {stats[check]}")
    if args.summary:
        by_key = collections.Counter((f["check"], f.get("key", f.get("opcode"))) for f in findings)
        for (check, key), n in by_key.most_common(40):
            print(f"  {check:24s} {n:5d}  {key}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

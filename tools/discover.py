#!/usr/bin/env python3
"""Brute-force bit-level field discovery using nvdisasm -b SM120.

For each InsKey:
1. Take one known-good 128-bit encoding
2. Flip every bit (0-127) and decode with nvdisasm
3. Compare to base → classify each bit as operand/flag/opcode/scheduling/constant
4. Group contiguous bits into fields, determine type
5. Compute base encoding (all variable bits zeroed)

Output: tables/sm120.json
"""

import json
import os
import re
import struct
import subprocess
import sys
import tempfile
import time
from collections import defaultdict
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path

NVDISASM = os.environ.get("NVDISASM", "/usr/local/cuda/bin/nvdisasm")
RECORDS = Path(os.environ.get("CUBIT_RECORDS", "tables/records.jsonl"))
OUTPUT = Path(os.environ.get("CUBIT_TABLE", "tables/sm120.json"))
MAX_WORKERS = int(os.environ.get("CUBIT_DISCOVER_WORKERS", "12"))

# ---------------------------------------------------------------------------
# nvdisasm probe helpers
# ---------------------------------------------------------------------------

def nvdisasm_decode(code128: int) -> str | None:
    """Decode a 128-bit instruction via nvdisasm -b SM120. Returns ASM or None."""
    lo = code128 & ((1 << 64) - 1)
    hi = code128 >> 64
    path = f"/tmp/cubit_probe_{os.getpid()}.bin"
    with open(path, "wb") as f:
        f.write(struct.pack("<QQ", lo, hi))
    try:
        r = subprocess.run(
            [NVDISASM, "-b", "SM120", path],
            capture_output=True, text=True, timeout=5,
        )
        for line in r.stdout.splitlines():
            if "/*0000*/" in line:
                # Extract ASM between */ and optional /* (hex comment)
                after = line.split("*/", 1)[1].strip()
                # Remove trailing hex comment
                if "/*" in after:
                    after = after.split("/*")[0].strip()
                return after.rstrip(";").strip()
    except Exception:
        pass
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass
    return None


def probe_bit(args):
    """Probe one bit flip. Called in parallel. Returns (bit, asm_or_none)."""
    base_code, bit = args
    probed = base_code ^ (1 << bit)
    return (bit, nvdisasm_decode(probed))


# ---------------------------------------------------------------------------
# ASM diff analysis
# ---------------------------------------------------------------------------

def clean_asm(asm: str) -> str:
    """Strip annotations for comparison."""
    return re.sub(r"\s*[?&]\S+", "", asm).strip()


def tokenize_sass(asm: str):
    """Tokenize SASS into (guard, opcode, [operands]).
    
    Guard is None or '@P0'/'@!P1' etc.
    Opcode is 'IADD3' or 'IADD3.X' etc.
    Operands are comma-separated tokens.
    """
    text = clean_asm(asm).rstrip(";").strip()
    guard = None
    m = re.match(r"^(@!?U?P\w+)\s+", text)
    if m:
        guard = m.group(1)
        text = text[m.end():]

    parts = text.split(None, 1)
    opcode = parts[0] if parts else ""
    ops_str = parts[1].strip() if len(parts) > 1 else ""

    # Split operands by comma (respecting brackets)
    operands = []
    if ops_str:
        depth = 0
        current = ""
        for ch in ops_str:
            if ch in "([":
                depth += 1
            elif ch in ")]":
                depth -= 1
            elif ch == "," and depth == 0:
                operands.append(current.strip())
                current = ""
                continue
            current += ch
        if current.strip():
            operands.append(current.strip())

    return guard, opcode, operands


def diff_asm(base: str, probed: str):
    """Determine what changed between base and probed ASM.
    
    Returns a dict with structured diff info, or None if identical.
    """
    base_clean = clean_asm(base)
    probed_clean = clean_asm(probed)
    if base_clean == probed_clean:
        return None

    bg, bo, bops = tokenize_sass(base_clean)
    pg, po, pops = tokenize_sass(probed_clean)

    # Guard changed?
    if bg != pg:
        return {"token_idx": 0, "base": bg or "none", "probed": pg or "none",
                "change": "guard"}

    # Opcode changed?
    bo_base = bo.split(".")[0]
    po_base = po.split(".")[0]
    if bo_base != po_base:
        return {"token_idx": 0, "base": bo, "probed": po,
                "change": "opcode_identity"}

    # Opcode modifiers changed? (e.g., IADD3 -> IADD3.X)
    if bo != po:
        return {"token_idx": 0, "base": bo, "probed": po,
                "change": "modifier"}

    # Find first differing operand
    for i, (bt, pt) in enumerate(zip(bops, pops)):
        if bt != pt:
            return {"token_idx": i + 1, "base": bt, "probed": pt,
                    "change": "operand"}

    # Different number of operands
    if len(bops) != len(pops):
        return {"token_idx": min(len(bops), len(pops)) + 1,
                "base": base_clean, "probed": probed_clean,
                "change": "length_diff"}

    return {"base": base_clean, "probed": probed_clean, "change": "unknown"}


def classify_token_change(base_tok: str, probed_tok: str) -> str:
    """Classify what type of field a token change represents."""
    # Strip to base for comparison
    def strip_mods(t):
        return t.lstrip("-~!|").rstrip("|").split(".")[0]

    base_stripped = strip_mods(base_tok)
    probe_stripped = strip_mods(probed_tok)

    # Negate/abs/inv flag: only prefix differs, base token is same
    # e.g., R5 -> -R5, R5 -> ~R5, R5 -> |R5|
    if base_stripped == probe_stripped and base_stripped.startswith(("R", "UR")):
        return "negate_flag"

    # Predicate negation: P0 -> !P0
    if base_stripped == probe_stripped and base_stripped.startswith(("P", "UP")):
        return "negate_flag"

    # Register number change: R5 -> R6
    if re.match(r"^R\d+$", base_stripped) and re.match(r"^R\d+$", probe_stripped):
        return "register"
    if re.match(r"^UR\d+$", base_stripped) and re.match(r"^UR\d+$", probe_stripped):
        return "uregister"

    # Predicate number change: P0 -> P1, PT -> P0
    if re.match(r"^P\d+$|^PT$", base_stripped) and re.match(r"^P\d+$|^PT$", probe_stripped):
        return "predicate"
    if re.match(r"^UP\d+$|^UPT$", base_stripped) and re.match(r"^UP\d+$|^UPT$", probe_stripped):
        return "upredicate"

    # Immediate change: 0x100 -> 0x108, 5 -> 13
    if re.match(r"^-?0x[0-9a-f]+$", base_tok, re.I) or re.match(r"^-?\d+$", base_tok):
        return "immediate"

    # Scheduling annotations
    if base_tok.startswith(("?", "&")) or probed_tok.startswith(("?", "&")):
        return "scheduling"

    # Complex operands: addresses, descriptors, const mem
    # Extract register numbers from complex tokens and compare
    base_regs = set(re.findall(r'\bR(\d+)\b', base_tok))
    probe_regs = set(re.findall(r'\bR(\d+)\b', probed_tok))
    if base_regs != probe_regs and base_regs and probe_regs:
        return "register"

    base_uregs = set(re.findall(r'\bUR(\d+)\b', base_tok))
    probe_uregs = set(re.findall(r'\bUR(\d+)\b', probed_tok))
    if base_uregs != probe_uregs and base_uregs and probe_uregs:
        return "uregister"

    # Offset change in address: [R2+0x8] -> [R2+0x10]
    base_offsets = re.findall(r'0x[0-9a-f]+', base_tok, re.I)
    probe_offsets = re.findall(r'0x[0-9a-f]+', probed_tok, re.I)
    if base_offsets != probe_offsets:
        return "immediate"

    # System register change: SR_TID.X -> SR_TID.Y
    if base_tok.startswith("SR_") and probed_tok.startswith("SR_"):
        return "immediate"  # SR index encoded as immediate

    # Barrier change: B0 -> B1
    if re.match(r"^B\d+$", base_tok) and re.match(r"^B\d+$", probed_tok):
        return "immediate"

    return "unknown"


# ---------------------------------------------------------------------------
# Field grouping
# ---------------------------------------------------------------------------

def group_bits_into_fields(bit_info: dict) -> list:
    """Group classified bits into contiguous fields.
    
    bit_info: {bit_num: {"type": ..., "token_idx": ..., ...}}
    Returns list of field dicts.
    """
    if not bit_info:
        return []

    # Group by (token_idx, type, modifier) first
    groups = defaultdict(list)
    for bit, info in sorted(bit_info.items()):
        modifier = info.get("modifier", "")
        key = (info.get("token_idx", -1), info.get("type", "unknown"), modifier)
        groups[key].append(bit)

    fields = []
    for (tok_idx, ftype, modifier), bits in sorted(groups.items()):
        bits = sorted(bits)
        # Split into contiguous ranges
        ranges = []
        start = bits[0]
        prev = bits[0]
        for b in bits[1:]:
            if b == prev + 1:
                prev = b
            else:
                ranges.append((start, prev))
                start = b
                prev = b
        ranges.append((start, prev))

        for rstart, rend in ranges:
            entry = {
                "type": ftype,
                "token_idx": tok_idx,
                "shift": rstart,
                "bits": rend - rstart + 1,
                "mask": (1 << (rend - rstart + 1)) - 1,
                "bit_positions": list(range(rstart, rend + 1)),
            }
            if modifier:
                entry["modifier"] = modifier
            fields.append(entry)

    return fields


# ---------------------------------------------------------------------------
# Per-InsKey discovery
# ---------------------------------------------------------------------------

def inject_scheduling(code128: int) -> int:
    """Inject default scheduling bits if missing (stall=1, yield=0, barriers=7/7, wait=0)."""
    SCHED_SHIFT = 64 + 41  # bits [121:105] of 128-bit code
    SCHED_MASK = 0x1FFFF << SCHED_SHIFT
    current_sched = (code128 >> SCHED_SHIFT) & 0x1FFFF
    if current_sched == 0:
        # Default: stall=1, yield_inv=1, write_bar=7, read_bar=7, wait=0
        # = (0<<11) | (7<<8) | (7<<5) | (1<<4) | 1 = 0x7F1
        default_sched = 0x7F1
        code128 = (code128 & ~SCHED_MASK) | (default_sched << SCHED_SHIFT)
    return code128


def discover_key(key: str, records: list, pool: ProcessPoolExecutor) -> dict | None:
    """Discover bit fields for one InsKey using brute-force probing."""
    if not records:
        return None

    # Pick the first record as base, inject scheduling if missing
    addr, code128, asm = records[0]
    code128 = inject_scheduling(code128)

    # Decode base to verify
    base_asm = nvdisasm_decode(code128)
    if base_asm is None:
        print(f"  SKIP {key}: base encoding not decodable", file=sys.stderr)
        return None

    base_asm_clean = clean_asm(base_asm)

    # Probe all 128 bits in parallel
    tasks = [(code128, bit) for bit in range(128)]
    futures = {pool.submit(probe_bit, t): t[1] for t in tasks}

    bit_results = {}  # bit -> asm_or_none
    for fut in as_completed(futures):
        bit, probe_asm = fut.result()
        bit_results[bit] = probe_asm

    # Classify each bit
    active_bits = {}
    illegal_bits = []
    constant_bits = []

    for bit in range(128):
        probe_asm = bit_results.get(bit)
        if probe_asm is None:
            illegal_bits.append(bit)
            continue

        probe_clean = clean_asm(probe_asm)
        if probe_clean == base_asm_clean:
            constant_bits.append(bit)
            continue

        # Something changed — determine what
        d = diff_asm(base_asm, probe_asm)
        if d is None:
            constant_bits.append(bit)
            continue

        tok_idx = d.get("token_idx", -1)
        change_type = d.get("change", "unknown")
        base_tok = d.get("base", "")
        probed_tok = d.get("probed", "")

        # Map change type to field type + capture details
        extra = {}
        if change_type == "guard":
            ftype = "pred_guard"
            tok_idx = 0
        elif change_type == "opcode_identity":
            ftype = "opcode_change"
        elif change_type == "modifier":
            ftype = "modifier_flag"
            # Capture which modifier: diff the .split('.') lists
            base_mods = set(base_tok.split('.')[1:])
            probe_mods = set(probed_tok.split('.')[1:])
            added = probe_mods - base_mods
            removed = base_mods - probe_mods
            if added:
                extra["modifier"] = "." + list(added)[0]
            elif removed:
                extra["modifier"] = "." + list(removed)[0]
        elif change_type == "operand":
            ftype = classify_token_change(base_tok, probed_tok) if base_tok and probed_tok else "unknown"
        else:
            ftype = "unknown"

        active_bits[bit] = {
            "type": ftype,
            "token_idx": tok_idx,
            "base_tok": base_tok,
            "probed_tok": probed_tok,
            **extra,
        }

    # Group into fields
    fields = group_bits_into_fields(active_bits)

    # Compute base: zero OPERAND and FLAG fields.
    # Keep opcode_change bits (they define the instruction identity).
    # Clear scheduling bits (encoder injects them separately).
    OPERAND_TYPES = {"register", "uregister", "predicate", "upredicate", "pred_guard",
                     "immediate", "negate_flag", "modifier_flag"}
    operand_mask = 0
    for f in fields:
        if f["type"] in OPERAND_TYPES:
            for b in f["bit_positions"]:
                operand_mask |= (1 << b)

    SCHED_MASK = 0x1FFFF << (64 + 41)
    base = code128 & ~operand_mask & ~SCHED_MASK

    # Validate against all records
    pass_count = 0
    fail_count = 0
    SCHED_MASK = 0x1FFFF << (64 + 41)
    for rec_addr, rec_code_raw, rec_asm in records:
        rec_code = inject_scheduling(rec_code_raw)
        # Check if base | extracted_fields == rec_code (ignoring scheduling bits)
        reconstructed = base
        for f in fields:
            # Extract field value from the record's code
            val = (rec_code >> f["shift"]) & f["mask"]
            reconstructed |= val << f["shift"]
        # Compare (ignoring scheduling bits)
        if (reconstructed & ~SCHED_MASK) == (rec_code & ~SCHED_MASK):
            pass_count += 1
        else:
            fail_count += 1

    return {
        "key": key,
        "base": hex(base),
        "fields": [
            {k: v for k, v in {
                "type": f["type"],
                "token_idx": f["token_idx"],
                "shift": f["shift"],
                "bits": f["bits"],
                "modifier": f.get("modifier"),
            }.items() if v is not None}
            for f in fields
        ],
        "opcode_bits": illegal_bits,
        "constant_bits": constant_bits,
        "active_bits": sorted(active_bits.keys()),
        "base_asm": base_asm_clean,
        "n_records": len(records),
        "pass": pass_count,
        "fail": fail_count,
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def load_records() -> dict:
    """Load records.jsonl -> {key: [(addr, code, asm)]}."""
    records = defaultdict(list)
    with open(RECORDS) as f:
        for line in f:
            r = json.loads(line)
            code = int(r["code"], 16)
            records[r["key"]].append((r["addr"], code, r["asm"]))
    return dict(records)


def main():
    records_by_key = load_records()
    print(f"Loaded {sum(len(v) for v in records_by_key.values())} records across {len(records_by_key)} InsKeys")

    results = {}
    total_pass = 0
    total_fail = 0
    total_keys = 0

    t_start = time.time()

    with ProcessPoolExecutor(max_workers=MAX_WORKERS) as pool:
        for i, (key, records) in enumerate(sorted(records_by_key.items())):
            t0 = time.time()
            result = discover_key(key, records, pool)
            t1 = time.time()

            if result is None:
                print(f"  [{i+1}/{len(records_by_key)}] SKIP {key}")
                continue

            results[key] = result
            total_keys += 1
            total_pass += result["pass"]
            total_fail += result["fail"]

            status = "OK" if result["fail"] == 0 else f"FAIL({result['fail']}/{result['n_records']})"
            n_fields = len(result["fields"])
            print(f"  [{i+1}/{len(records_by_key)}] {key}: {n_fields} fields, {status} ({t1-t0:.1f}s)")

    t_total = time.time() - t_start

    # Summary
    perfect = sum(1 for r in results.values() if r["fail"] == 0)
    print(f"\n{'='*70}")
    print(f"Discovery complete in {t_total:.0f}s")
    print(f"  Keys: {total_keys}")
    print(f"  Perfect (0 fail): {perfect}/{total_keys}")
    print(f"  Records: {total_pass}/{total_pass + total_fail} pass")
    if total_fail > 0:
        print(f"\n  Failing keys:")
        for key, r in sorted(results.items()):
            if r["fail"] > 0:
                print(f"    {key}: {r['fail']}/{r['n_records']} fail")

    # Write output
    output = {
        "arch": 120,
        "discovery_method": "brute_force_bit_probe",
        "instructions": results,
    }
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT, "w") as f:
        json.dump(output, f, indent=2)
    print(f"\nSaved to {OUTPUT}")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Whole-cubin assembler round trip: `disassemble --frozen` -> `asm -T` -> byte comparison.

For every cubin given, the frozen text of all kernels is written, assembled back
against the original as template, and the result is compared with the original
byte for byte. A mismatch is explained per ELF section (`.text.<kernel>`
instruction words, `.nv.info*` EIATTR records, Mercury companions, string and
symbol tables) so the report says *which* metadata the assembler did not
reproduce, not only that something differs.

    tools/asm_roundtrip.py --cubit target/release/cubit --table tables/sm120.json \\
        --out /tmp/asm_rt a.cubin b.cubin ...

Exit status 0 when every cubin is byte-identical, 1 otherwise. The JSON report
(`<out>/report.json`) lists per cubin: kernels, instructions, identical flag and
the differing sections with the first differing offsets.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import struct
import subprocess
import sys
import time


def elf_sections(data: bytes) -> list[tuple[str, int, int, int]]:
    """(name, type, offset, size) for every section header of an ELF64 image."""
    if data[:4] != b"\x7fELF" or data[4] != 2:
        raise ValueError("not an ELF64 image")
    shoff = struct.unpack_from("<Q", data, 0x28)[0]
    shentsize, shnum, shstrndx = struct.unpack_from("<HHH", data, 0x3A)
    raw = []
    for i in range(shnum):
        off = shoff + i * shentsize
        name, typ, _flags, _addr, offset, size = struct.unpack_from("<IIQQQQ", data, off)
        raw.append((name, typ, offset, size))
    str_off = raw[shstrndx][2]

    def name_of(n: int) -> str:
        end = data.index(b"\0", str_off + n)
        return data[str_off + n:end].decode(errors="replace")

    return [(name_of(n), typ, offset, size) for n, typ, offset, size in raw]


def eiattr_records(payload: bytes) -> list[tuple[int, int, bytes]]:
    """(fmt, attr, data) records of an .nv.info section."""
    out = []
    pos = 0
    while pos + 4 <= len(payload):
        fmt, attr = payload[pos], payload[pos + 1]
        size = struct.unpack_from("<H", payload, pos + 2)[0]
        pos += 4
        if fmt == 4:
            out.append((fmt, attr, payload[pos:pos + size]))
            pos += size
        else:
            out.append((fmt, attr, payload[pos - 2:pos]))
    return out


def describe_difference(name: str, a: bytes, b: bytes) -> dict:
    entry: dict = {"section": name, "size_original": len(a), "size_rebuilt": len(b)}
    if name.startswith(".text."):
        words = []
        for i in range(0, min(len(a), len(b)), 16):
            if a[i:i + 16] != b[i:i + 16]:
                words.append({"offset": f"0x{i:x}", "original": a[i:i + 16][::-1].hex(),
                              "rebuilt": b[i:i + 16][::-1].hex()})
            if len(words) >= 8:
                break
        entry["differing_words"] = words
        entry["differing_word_count"] = sum(
            a[i:i + 16] != b[i:i + 16] for i in range(0, min(len(a), len(b)), 16))
    elif name.startswith(".nv.info"):
        ra, rb = eiattr_records(a), eiattr_records(b)
        diffs = []
        for i, (x, y) in enumerate(zip(ra, rb)):
            if x != y:
                diffs.append({"record": i, "original": f"fmt={x[0]:#x} attr={x[1]:#x} data={x[2].hex()}",
                              "rebuilt": f"fmt={y[0]:#x} attr={y[1]:#x} data={y[2].hex()}"})
        if len(ra) != len(rb):
            diffs.append({"record_count": [len(ra), len(rb)]})
        entry["eiattr_differences"] = diffs[:16]
    else:
        first = next((i for i, (x, y) in enumerate(zip(a, b)) if x != y), min(len(a), len(b)))
        entry["first_difference"] = f"0x{first:x}"
    return entry


def compare(original: bytes, rebuilt: bytes) -> list[dict]:
    if original == rebuilt:
        return []
    try:
        sa = {n: (o, s) for n, _t, o, s in elf_sections(original) if n}
        sb = {n: (o, s) for n, _t, o, s in elf_sections(rebuilt) if n}
    except ValueError as exc:
        return [{"section": "<elf>", "error": str(exc)}]
    out = []
    for name in sorted(set(sa) | set(sb)):
        if name not in sa or name not in sb:
            out.append({"section": name, "only_in": "original" if name in sa else "rebuilt"})
            continue
        a = original[sa[name][0]:sa[name][0] + sa[name][1]]
        b = rebuilt[sb[name][0]:sb[name][0] + sb[name][1]]
        if a != b:
            out.append(describe_difference(name, a, b))
    if not out:
        out.append({"section": "<headers>", "note": "section payloads identical; ELF/section headers differ"})
    return out


def run(cmd: list[str], log: pathlib.Path) -> int:
    with log.open("w") as fh:
        return subprocess.run(cmd, stdout=fh, stderr=subprocess.STDOUT).returncode


def roundtrip(cubit: str, table: str, cubin: pathlib.Path, out: pathlib.Path) -> dict:
    stem = cubin.name
    frozen = out / f"{stem}.frozen.sass"
    rebuilt = out / f"{stem}.rebuilt.cubin"
    result: dict = {"cubin": str(cubin), "sha256": hashlib.sha256(cubin.read_bytes()).hexdigest()}
    t0 = time.time()
    rc = run([cubit, "disassemble", "-t", table, "--frozen", str(cubin), "-o", str(frozen)],
             out / f"{stem}.disassemble.log")
    if rc:
        result.update(identical=False, stage="disassemble", exit=rc)
        return result
    text = frozen.read_text()
    result["kernels"] = sum(line.startswith(".entry ") for line in text.splitlines())
    result["instructions"] = sum(line.lstrip().startswith("[") for line in text.splitlines())
    # words the decoder could not name are frozen as `__raw__0x...` and come
    # back byte-identical by construction: they are not evidence of coverage
    result["raw_words"] = sum(line.lstrip().startswith("__raw__") for line in text.splitlines())
    if result["kernels"] == 0:
        result.update(identical=None, stage="no .text sections (nothing to round-trip)")
        return result
    rc = run([cubit, "asm", "-t", table, "-T", str(cubin), str(frozen), "-o", str(rebuilt)],
             out / f"{stem}.asm.log")
    if rc:
        tail = (out / f"{stem}.asm.log").read_text().strip().splitlines()[-3:]
        result.update(identical=False, stage="asm", exit=rc, error=tail)
        return result
    original, new = cubin.read_bytes(), rebuilt.read_bytes()
    differences = compare(original, new)
    result.update(identical=not differences, differences=differences, seconds=round(time.time() - t0, 1))
    result["strict"] = bool(result["identical"]) and result["raw_words"] == 0
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--cubit", default="target/release/cubit")
    parser.add_argument("--table", default="tables/sm120.json")
    parser.add_argument("--out", type=pathlib.Path, required=True)
    parser.add_argument("cubins", nargs="+", type=pathlib.Path)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    results = []
    for cubin in args.cubins:
        r = roundtrip(args.cubit, args.table, cubin, args.out)
        results.append(r)
        if r.get("identical") is None:
            status = "SKIPPED"
        elif r.get("identical"):
            status = "IDENTICAL" if r["raw_words"] == 0 else f"IDENTICAL ({r['raw_words']} raw)"
        else:
            status = f"DIFFERS ({r.get('stage', 'bytes')})"
        print(f"{status:>20}  {r.get('kernels', '?'):>3} kernels {r.get('instructions', '?'):>7} insns  {cubin}")
        for d in r.get("differences", [])[:6]:
            print(f"                      {json.dumps(d)[:200]}")
    (args.out / "report.json").write_text(json.dumps(results, indent=1) + "\n")
    considered = [r for r in results if r.get("identical") is not None]
    identical = sum(bool(r.get("identical")) for r in considered)
    strict = sum(bool(r.get("strict")) for r in considered)
    raw = sum(r.get("raw_words", 0) for r in considered)
    print(f"{identical}/{len(considered)} cubins byte-identical after disassemble --frozen -> asm -T "
          f"({strict} with every word decoded, {raw} __raw__ words in total, "
          f"{len(results) - len(considered)} skipped without .text)")
    return 0 if identical == len(considered) else 1


if __name__ == "__main__":
    sys.exit(main())

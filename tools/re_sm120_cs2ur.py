#!/usr/bin/env python3
"""Measure SM120 CS2UR operand fields with nvdisasm and repair the canonical rows.

CS2UR (opcode 0x8cb) reads a system register into a uniform register. The
canonical table carried one harvested word under the ".32" group with no
fields (guard, URd and SR_CLOCKLO baked into and_base) and a junk "UR_II" row
that re-read the SR number as two immediates, so `CS2UR UR4, SR_CLOCKLO`
did not encode and most CS2UR.32 words decoded as `CS2UR URd, 0x0`.

`probe` sweeps every bit the operands can take and records nvdisasm's text:
guard[15:12] (uniform predicates @UP0..@UP6, PT, @!UP0..@!UP6, !UPT),
URd[23:16] (0..254 = URn, 255 = URZ), SR[79:72] (all 256 ids) and bit 80
(1 = 64-bit/plain, 0 = .32). `apply` writes the two measured groups and
removes the immediate row. Every probe word reassembles bit for bit in
tests/sm120_cs2ur_sysreg.rs.
"""
import argparse
import hashlib
import json
import pathlib
import re
import subprocess

PROVENANCE = "cs2ur-sm120-2026-10-23"
SCHEDULE = ((1 << 17) - 1) << 105
OPCODE = 0x8cb
FIXTURE = pathlib.Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "sm120_cs2ur_nvdisasm.jsonl"


def field(shift, bits, extraction, token):
    return {"bits": bits, "extraction": extraction, "shift": shift,
            "token_idx": token, "_src": PROVENANCE}


def row(base, fields, note):
    mask = 0
    for f in fields:
        bits = ((1 << f["bits"]) - 1) << f["shift"]
        assert mask & bits == 0, "measured fields are disjoint"
        mask |= bits
    return {"and_base": f"0x{base & ~SCHEDULE & ~mask:032x}", "count": None,
            "fields": fields, "variable_mask": f"0x{mask:032x}",
            "_src": PROVENANCE, "_note": note}


def word(urd, sr, guard=7, bit80=1):
    return OPCODE | (guard << 12) | (urd << 16) | (sr << 72) | (bit80 << 80)


def sweep_words():
    words = set()
    for bit80 in (0, 1):
        words.update(word(4, sr, 7, bit80) for sr in range(256))
        words.update(word(urd, 0x50, 7, bit80)
                     for urd in list(range(64)) + [64, 100, 127, 128, 254, 255])
        words.update(word(4, 0x50, guard, bit80) for guard in range(16))
    return sorted(words)


def probe(nvdisasm, out=FIXTURE):
    words = sweep_words()
    blob = b"".join(w.to_bytes(16, "little") for w in words)
    binary = pathlib.Path("/tmp/re_sm120_cs2ur_sweep.bin")
    binary.write_bytes(blob)
    text = subprocess.check_output([nvdisasm, "-b", "SM120", "-hex", str(binary)], text=True)
    lines = [l for l in text.splitlines() if re.match(r"^\s*/\*[0-9a-f]{4,}\*/", l)]
    assert len(lines) == len(words), (len(lines), len(words))
    digest = hashlib.sha256(pathlib.Path(nvdisasm).read_bytes()).hexdigest()
    version = subprocess.check_output([nvdisasm, "--version"], text=True).strip().splitlines()[-1]
    with out.open("w") as fh:
        for w, line in zip(words, lines):
            body = line.split("*/", 1)[1].split("/*", 1)[0].strip().rstrip(";").strip()
            assert re.fullmatch(r"(@!?UP[0-6T] )?CS2UR(\.32)? UR(Z|\d+), \S+", body), body
            fh.write(json.dumps({"word": f"{w:032x}", "nvidia_sass": body,
                                 "nvdisasm": version, "nvdisasm_sha256": digest}) + "\n")
    print(f"{len(words)} CS2UR words -> {out}")


def apply(table_path):
    path = pathlib.Path(table_path)
    before = path.read_bytes()
    table = json.loads(before)
    assert (json.dumps(table, indent=1) + "\n").encode() == before, "unexpected table formatting"
    ins = table["instructions"]
    fields = [field(12, 4, "guard", 0), field(16, 8, "ureg", 1), field(72, 8, "sysreg", 2)]
    entry = ins["CS2UR_UR_L"]
    assert entry["base_op"] == "CS2UR" and entry["operand_sig"] == "UR_L"
    entry["mod_groups"] = {
        "": row(word(0, 0, 0, 1), fields,
                "nvdisasm 13.1 sweeps: uniform guard[15:12], URd[23:16] (255 = URZ), "
                "system-register id[79:72]; bit80=1 is the 64-bit/plain form."),
        "32": row(word(0, 0, 0, 0), fields,
                  "CS2UR.32: same measured fields, bit80=0."),
    }
    removed = ins.pop("CS2UR_UR_II", None)
    assert removed is not None, "junk immediate row already gone"
    path.write_text(json.dumps(table, indent=1) + "\n")
    print(f"repaired CS2UR_UR_L (2 groups), removed CS2UR_UR_II in {path}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("probe", help="sweep CS2UR words through nvdisasm into the fixture")
    p.add_argument("--nvdisasm", required=True)
    p.add_argument("--out", type=pathlib.Path, default=FIXTURE)
    a = sub.add_parser("apply", help="repair the canonical sm120.json in place")
    a.add_argument("table")
    args = parser.parse_args()
    if args.command == "probe":
        probe(args.nvdisasm, args.out)
    else:
        apply(args.table)


if __name__ == "__main__":
    main()

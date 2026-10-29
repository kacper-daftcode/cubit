#!/usr/bin/env python3
"""Measure SM120 F2FP.BF16.E8.UNPACK_B (UE8M0 -> BF16x2) with nvdisasm and add its canonical row.

F2FP (opcode 0x23e) converts packed narrow floats. The table carried the UNPACK_B rows for the F16
destination (E4M3, E5M2, E3M2, E2M1 sources) but not the UE8M0 source, whose only destination is
BF16: `F2FP.BF16.E8.UNPACK_B Rd, Rb[.H1]` is what PTX `cvt.rn.bf16x2.ue8m0x2` compiles to - the
block-scale decode of FlashInfer 0.7.2's DeepSeek-V4.1 full-BF16 sparse-MLA prefill kernel
(sparse_mla_prefill_dsv41_bf16_kernel, 48 words in the sm_120 AOT cubin of image r21), which cubit's
strict round-trip of that cubin reported as `no instruction matches ... at opcode 0x023e`
(vLLM-Moet front "cubit + prefill", Phase 0, 2026-10-28).

`probe` sweeps the fields nvdisasm 13.1 renders for this form: guard [15:12] (@P0..@P6, PT,
@!P0..@!P6, !PT), destination register [23:16], source register [39:32], .H1 = bit 88, .reuse =
bit 123. The source-format lattice around it (same sweep, kept in the fixture for the record):
bits [87:80] select the group (0x00 = 8-bit E4M3/E5M2, 0x04 = 4/6-bit E0M3/E2M1/E2M3/E3M2, 0x08 = E8),
bits [74:73] the sub-format, bit 75 = RELU, bit 76 = BF16 destination (legal only with E8; E8 is
legal only with BF16), bit 72 together with bit 88 selects the byte (.B1/.B2/.B3) of the 4-bit
sources; [87:80] = 0x01 / 0x02 print as unknown `.???2` / `.???4` and bit 79 as `.???1` - all left
outside the row (fail-closed). `apply` adds `F2FP.BF16.E8.UNPACK_B_R_R` next to the E4M3 row with the
same measured fields.
"""
import argparse
import copy
import hashlib
import json
import pathlib
import re
import subprocess

PROVENANCE = "f2fp-e8-sm120-2026-10-28"
OPCODE = 0x23e
NATIVE_CTRL = 0x000fe200 << 96
# F2FP.BF16.E8.UNPACK_B R0, R0 with guard PT (7), no .H1, no .reuse
BASE = 0x00000000020816ff00000000ff00023e | (7 << 12)
DONOR = "F2FP.F16.E4M3.UNPACK_B_R_R"
KEY = "F2FP.BF16.E8.UNPACK_B_R_R"
FIXTURE = pathlib.Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "sm120_f2fp_e8_nvdisasm.jsonl"
TEXT = re.compile(r"(@!?P[0-6T] )?F2FP\.BF16\.E8\.UNPACK_B R(Z|\d+), R(Z|\d+)(\.reuse)?(\.H1)?")


def word(guard=7, rd=0, rb=0, h1=0, reuse=0):
    w = BASE & ~((0xf << 12) | (0xff << 16) | (0xff << 32))
    return w | (guard << 12) | (rd << 16) | (rb << 32) | (h1 << 88) | (reuse << 123)


def sweep_words():
    words = {word()}
    for guard in range(16):
        words.add(word(guard=guard))
    for rd in (1, 5, 47, 100, 254, 255):
        words.add(word(rd=rd))
    for rb in (1, 9, 94, 100, 254, 255):
        words.add(word(rb=rb))
    for h1 in (0, 1):
        for reuse in (0, 1):
            words.add(word(rd=47, rb=94, h1=h1, reuse=reuse))
            words.add(word(guard=1, rd=47, rb=94, h1=h1, reuse=reuse))
    return sorted(words)


def probe(nvdisasm, out=FIXTURE):
    words = sweep_words()
    binary = pathlib.Path("/tmp/re_sm120_f2fp_e8_probe.bin")
    digest = hashlib.sha256(pathlib.Path(nvdisasm).read_bytes()).hexdigest()
    version = subprocess.check_output([nvdisasm, "--version"], text=True).strip().splitlines()[-1]
    rows = []
    for w in words:  # one word per call: nvdisasm aborts a whole file on one illegal word
        binary.write_bytes((w | NATIVE_CTRL).to_bytes(16, "little"))
        r = subprocess.run([nvdisasm, "-b", "SM120", "-hex", str(binary)], capture_output=True, text=True)
        m = re.search(r"/\*0000\*/\s*(.*?)\s*;", r.stdout)
        assert m, f"nvdisasm rejected {w:032x}: {r.stderr.strip()[:120]}"
        body = m.group(1).strip()
        assert TEXT.fullmatch(body), body
        rows.append({"word": f"{w:032x}", "nvidia_sass": body, "nvdisasm": version, "nvdisasm_sha256": digest})
    with out.open("w") as fh:
        for r in rows:
            fh.write(json.dumps(r) + "\n")
    print(f"{len(rows)} F2FP.BF16.E8.UNPACK_B words -> {out}")


def apply(table_path):
    path = pathlib.Path(table_path)
    before = path.read_bytes()
    table = json.loads(before)
    assert (json.dumps(table, indent=1) + "\n").encode() == before, "unexpected table formatting"
    ins = table["instructions"]
    if KEY in ins:
        print(f"{KEY}: already present in {path}")
        return
    donor = ins[DONOR]
    assert donor["base_op"] == "F2FP.F16.E4M3.UNPACK_B" and list(donor["mod_groups"]) == [""]
    entry = copy.deepcopy(donor)
    entry["base_op"] = "F2FP.BF16.E8.UNPACK_B"
    group = entry["mod_groups"][""]
    mask = int(group["variable_mask"], 16)
    group["and_base"] = f"0x{(word() & ~mask & ~(((1 << 23) - 1) << 105)):032x}"
    group["count"] = None
    group["_src"] = PROVENANCE
    group["_note"] = ("nvdisasm 13.1 sweeps: guard[15:12], destination[23:16], source[39:32], .H1 = bit 88, .reuse = bit 123; "
                      "bits [87:80] = 0x08 select the UE8M0 source group and bit 76 the BF16 destination (E8 has no F16 "
                      "destination, the other UNPACK_B sources no BF16 one). PTX cvt.rn.bf16x2.ue8m0x2.")
    for f in group["fields"]:
        f["_src"] = PROVENANCE
    # insert right after the donor so the file keeps its neighbourhood order
    rebuilt = {}
    for k, v in ins.items():
        rebuilt[k] = v
        if k == DONOR:
            rebuilt[KEY] = entry
    table["instructions"] = rebuilt
    path.write_text(json.dumps(table, indent=1) + "\n")
    print(f"{KEY}: added next to {DONOR} in {path} (base {group['and_base']}, mask {group['variable_mask']})")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("probe")
    p.add_argument("--nvdisasm", required=True)
    p.add_argument("--out", type=pathlib.Path, default=FIXTURE)
    a = sub.add_parser("apply")
    a.add_argument("table")
    args = parser.parse_args()
    if args.command == "probe":
        probe(args.nvdisasm, args.out)
    else:
        apply(args.table)


if __name__ == "__main__":
    main()

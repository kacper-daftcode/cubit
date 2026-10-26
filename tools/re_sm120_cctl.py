#!/usr/bin/env python3
"""Measure SM120 CCTL's register-address forms with nvdisasm and complete the canonical rows.

CCTL (opcode 0x98f) is the cache-control instruction: prefetch, write-back, invalidate and the L2
line operations PML2 / DML2 / RML2 (PTX prefetch / discard / applypriority). The canonical table
carried the register-plus-immediate form (`CCTL_ARI`) with one group, `E,PF2`, so the
`CCTL.E.RML2 [R]` words that PTX `discard.global.L2` compiles to (vLLM-Moet's moe_l2_discard
extension, five words) did not round-trip - cubit_gate.py found them on image r21.

`probe` sweeps the fields nvdisasm 13.1 renders: guard[15:12] (@P0..@P6, PT, @!P0..@!P6, !PT),
the address register [31:24] (255 = RZ), the signed 32-bit offset [63:32], the E flag (bit 72) and
the operation [90:87] (0 PF1, 1 PF2, 2 WB, 3 IV, 5 RS, 9 PML2, 10 DML2, 11 RML2; the other eight
codes are illegal). `apply` adds the seven missing E groups to `CCTL_ARI` next to the existing
`E,PF2` (keys in the table's sorted modifier order, e.g. `DML2,E`), with the same measured fields; every probe word reassembles bit for bit in
tests/sm120_cctl_register_forms.rs. The legacy `CCTL.E.PF1_AR` / `CCTL.E.PF2_AR` /
`CCTL.E.PML2_AR` rows (harvest leftovers: no E bit in their base, PML2 base set to the PF2 code)
are left in place for a later cleanup.
"""
import argparse
import hashlib
import json
import pathlib
import re
import subprocess

PROVENANCE = "cctl-sm120-2026-10-25"
SCHEDULE = ((1 << 17) - 1) << 105
OPCODE = 0x98f
# the control code of the native word (nvdisasm refuses a CCTL with an all-zero control code)
NATIVE_CTRL = 0x0001e400 << 96
OPS = {0: "PF1", 1: "PF2", 2: "WB", 3: "IV", 5: "RS", 9: "PML2", 10: "DML2", 11: "RML2"}
FIXTURE = pathlib.Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "sm120_cctl_nvdisasm.jsonl"


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


def word(op, e, reg=2, imm=0, guard=7):
    return (OPCODE | (guard << 12) | (reg << 24) | ((imm & 0xffffffff) << 32) | (e << 72) | (op << 87))


def sweep_words():
    words = set()
    for op in OPS:
        for e in (0, 1):
            words.add(word(op, e))
            for reg in (0, 1, 17, 100, 254, 255):
                words.add(word(op, e, reg=reg))
            for imm in (0x10, 0x1234, 0x7ffffff0, -0x100, -0x80000000 & 0xffffffff):
                words.add(word(op, e, imm=imm))
            for guard in range(16):
                words.add(word(op, e, guard=guard))
    return sorted(words)


def probe(nvdisasm, out=FIXTURE):
    words = sweep_words()
    binary = pathlib.Path("/tmp/re_sm120_cctl_probe.bin")
    digest = hashlib.sha256(pathlib.Path(nvdisasm).read_bytes()).hexdigest()
    version = subprocess.check_output([nvdisasm, "--version"], text=True).strip().splitlines()[-1]
    rows = []
    for w in words:  # one word per call: nvdisasm aborts a whole file on one illegal word
        binary.write_bytes((w | NATIVE_CTRL).to_bytes(16, "little"))
        r = subprocess.run([nvdisasm, "-b", "SM120", "-hex", str(binary)], capture_output=True, text=True)
        m = re.search(r"/\*0000\*/\s*(.*?)\s*;", r.stdout)
        assert m, f"nvdisasm rejected {w:032x}: {r.stderr.strip()[:120]}"
        body = m.group(1).strip()
        assert re.fullmatch(r"(@!?P[0-6T] )?CCTL(\.E)?\.(PF1|PF2|WB|IV|RS|PML2|DML2|RML2) \[R(Z|\d+)(\+-?0x[0-9a-f]+)?\]", body), body
        rows.append({"word": f"{w:032x}", "nvidia_sass": body, "nvdisasm": version, "nvdisasm_sha256": digest})
    with out.open("w") as fh:
        for r in rows:
            fh.write(json.dumps(r) + "\n")
    print(f"{len(rows)} CCTL words -> {out}")


def apply(table_path):
    path = pathlib.Path(table_path)
    before = path.read_bytes()
    table = json.loads(before)
    assert (json.dumps(table, indent=1) + "\n").encode() == before, "unexpected table formatting"
    entry = table["instructions"]["CCTL_ARI"]
    assert entry["base_op"] == "CCTL" and "E,PF2" in entry["mod_groups"]
    fields = [field(12, 4, "guard", 0), field(24, 8, "sub_r0", 1), field(32, 32, "sub_imm1", 1)]
    added = []
    for op, name in OPS.items():
        key = ",".join(sorted(["E", name]))  # the table keys modifier groups in sorted order ("DML2,E", "E,PF2")
        if key in entry["mod_groups"]:
            continue
        entry["mod_groups"][key] = row(word(op, 1, reg=0), fields,
                                       f"nvdisasm 13.1 sweeps: guard[15:12], address register[31:24] (255 = RZ), signed "
                                       f"offset[63:32], E = bit 72, operation[90:87] = {op} ({name}); bits 73-76 add a "
                                       f"trailing immediate and bit 80 an unknown modifier - both left out of the mask.")
        added.append(key)
    path.write_text(json.dumps(table, indent=1) + "\n")
    print(f"CCTL_ARI: added groups {added} in {path}")


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

#!/usr/bin/env python3
"""Measure SM120 ATOMS.MAX.S32 with a register-plus-uniform address and repair its canonical row.

ATOMS (shared-memory atomic) has two opcodes on SM120: 0x38c for the register address `[R+imm]`
and 0x98c, together with bit 91, for the uniform-indexed address `[R+UR+imm]` (`[UR+imm]` when the
base is RZ). The canonical table carried `ATOMS_R_ARURI_R` / `MAX,S32` as a harvest leftover whose
fields mistook the address UR byte [71:64] for a fourth register operand and declared neither the
UR nor the 24-bit offset (the same defect tools/re_sm120_memory_fields.py retired on
`ATOMS_R_ARI_R_R`). cubit's decoder still reached that row through its broad memory-address
fallback, printed `ATOMS.MAX.S32 RZ, [R157], R58` for the shipped word
0x0001e200090002070151003a9dff798c (`[R157+UR7+0x15100]` in nvdisasm) and the encoder rejected
the vendor text ("operand 2 (addr UR) has no field able to encode it"): 96 words of FlashInfer
0.7.2's GLM-5.3 MG prefill kernel (sparse_mla_prefill_mg_kernel<ModelType 3>, sm_120 AOT cubin of
vLLM-Moet image r21) did not round-trip (front "cubit + prefill", session L follow-up, 2026-10-28).

`probe` sweeps the fields nvdisasm 13.1 renders for the form: guard [15:12] (@P0..@P6, PT,
@!P0..@!P6, @!PT), destination [23:16] (255 = RZ), base register [31:24] (255 = RZ, printed as the
`[UR+imm]` spelling), source [39:32] (255 = RZ), the signed 24-bit offset [63:40] (elided at 0) and
the uniform register [71:64] (255 = URZ). The lattice around the form is recorded in the fixture
with `"lattice": true` and stays outside the row (fail-closed): the operation [90:87] (0 ADD,
1 MIN, 2 MAX, 3 INC, 4 DEC, 5 AND, 6 OR, 7 XOR, 8 EXCH, 9..15 INVALIDn), the type [75:73]
(1 = S32, 3 = INVALID3, 5 = INVALID5), the address scale bits 78 (.X4) / 79 (.X8), the text-inert
bits 72, 76, 77, 80..86, 92..95 and the reuse window [124:122], and the two illegal opcode mixes
(0x38c with bit 91, 0x98c without it). `apply` replaces the leftover `MAX,S32` group with the
measured fields - the geometry of the measured `ADD` group next to it.
"""
import argparse
import hashlib
import json
import pathlib
import re
import subprocess

PROVENANCE = "atoms-aruri-sm120-2026-10-29"
OPCODE = 0x98c
NATIVE_CTRL = 0x0001e200 << 96
SCHEDULE = ((1 << 23) - 1) << 105
KEY = "ATOMS_R_ARURI_R"
GROUP = "MAX,S32"
FIXTURE = pathlib.Path(__file__).resolve().parents[2] / "tests" / "fixtures" / "sm120_atoms_aruri_nvdisasm.jsonl"
TEXT = re.compile(r"(@!?P[0-6T] )?ATOMS\.MAX\.S32 R(Z|\d+), \[(R\d+\+)?UR(Z|\d+)(\+-?0x[0-9a-f]+)?\], R(Z|\d+)")
OPS = {0: "ADD", 1: "MIN", 2: "MAX", 3: "INC", 4: "DEC", 5: "AND", 6: "OR", 7: "XOR", 8: "EXCH"}


def field(shift, bits, extraction, token):
    return {"bits": bits, "extraction": extraction, "shift": shift, "token_idx": token, "_src": PROVENANCE}


def word(guard=7, rd=255, ra=157, rb=58, imm=0x15100, ur=7, op=2, s32=1, hi_extra=0, opcode=OPCODE, bit91=1):
    hi = (bit91 << 91) | (op << 87) | (s32 << 73) | hi_extra
    return opcode | (guard << 12) | (rd << 16) | (ra << 24) | (rb << 32) | ((imm & 0xffffff) << 40) | (ur << 64) | hi


def sweep_words():
    """(word, lattice) pairs: lattice words document the neighbourhood and must stay unclaimed."""
    form = {word()}
    for guard in range(16):
        form.add(word(guard=guard))
    for rd in (0, 1, 47, 100, 254, 255):
        form.add(word(rd=rd))
    for ra in (0, 1, 100, 254, 255):
        form.add(word(ra=ra))
    for rb in (0, 1, 100, 254, 255):
        form.add(word(rb=rb))
    for ur in (0, 1, 31, 62, 63, 255):
        form.add(word(ur=ur))
    for imm in (0, 1, 0x10, 0x7fffff, 0x800000, 0xffffff):
        form.add(word(imm=imm))
    for bit in range(24):
        form.add(word(imm=1 << bit))
    form.add(word(guard=8, rd=0, ra=255, rb=255, imm=0, ur=63))
    lattice = set()
    for op in range(16):
        for s32 in (0, 1):
            lattice.add(word(op=op, s32=s32))
    for bit in (72, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 92, 93, 94, 95):
        lattice.add(word(hi_extra=1 << bit))
    for bit in (122, 123, 124):
        lattice.add(word(hi_extra=1 << bit))
    lattice.add(word(opcode=0x38c))
    lattice.add(word(bit91=0))
    lattice -= form
    return [(w, False) for w in sorted(form)] + [(w, True) for w in sorted(lattice)]


def nvdisasm_text(nvdisasm, binary, w):
    binary.write_bytes((w | NATIVE_CTRL).to_bytes(16, "little"))
    r = subprocess.run([nvdisasm, "-b", "SM120", "-hex", str(binary)], capture_output=True, text=True)
    if r.returncode:
        assert "Illegal instruction" in r.stderr, f"{w:032x}: {r.stderr.strip()[:200]}"
        return None
    m = re.search(r"/\*0000\*/\s*(.*?)\s*;", r.stdout)
    assert m, f"no text for {w:032x}: {r.stdout[:200]}"
    return m.group(1).strip()


def probe(nvdisasm, out=FIXTURE):
    binary = pathlib.Path("/tmp/re_sm120_atoms_aruri_probe.bin")
    digest = hashlib.sha256(pathlib.Path(nvdisasm).read_bytes()).hexdigest()
    version = subprocess.check_output([nvdisasm, "--version"], text=True).strip().splitlines()[-1]
    rows = []
    for w, lattice in sweep_words():  # one word per call: nvdisasm aborts a whole file on one illegal word
        body = nvdisasm_text(nvdisasm, binary, w)
        if not lattice:
            assert body is not None and TEXT.fullmatch(body), f"{w:032x}: {body}"
        else:
            assert body is None or body.startswith("ATOMS."), f"{w:032x}: {body}"
        row = {"word": f"{w:032x}", "nvidia_sass": body, "nvdisasm": version, "nvdisasm_sha256": digest}
        if lattice:
            row["lattice"] = True
        rows.append(row)
    with out.open("w") as fh:
        for r in rows:
            fh.write(json.dumps(r) + "\n")
    n_form = sum(not r.get("lattice") for r in rows)
    print(f"{n_form} ATOMS.MAX.S32 [R+UR+imm] words + {len(rows) - n_form} lattice words -> {out}")


def measured_group():
    fields = [field(12, 4, "guard", 0), field(16, 8, "reg", 1), field(24, 8, "sub_r0", 2),
              field(64, 8, "sub_ur1", 2), field(40, 24, "sub_imm2", 2), field(32, 8, "reg", 3)]
    mask = 0
    for f in fields:
        bits = ((1 << f["bits"]) - 1) << f["shift"]
        assert mask & bits == 0, "measured fields are disjoint"
        mask |= bits
    return {
        "and_base": f"0x{word() & ~SCHEDULE & ~mask:032x}",
        "count": None,
        "fields": fields,
        "variable_mask": f"0x{mask:032x}",
        "_src": PROVENANCE,
        "_note": ("nvdisasm 13.1 sweeps: guard[15:12], destination[23:16], base register[31:24] (255 = RZ, "
                  "printed [UR+imm]), source[39:32], signed offset[63:40], uniform register[71:64] (255 = URZ); "
                  "opcode 0x98c with bit 91 is the uniform-indexed address (0x38c = [R+imm]; the mixes are "
                  "illegal), [90:87] = 2 MAX, bit 73 = S32. Bits 72/76/77/80-86/92-95 are text-inert, 74/75 "
                  "INVALID3/INVALID5, 78/79 the .X4/.X8 scale - all outside the row. Replaces the harvest "
                  "leftover that read the UR byte as a fourth register and had no offset field."),
    }


def apply(table_path):
    path = pathlib.Path(table_path)
    before = path.read_bytes()
    table = json.loads(before)
    assert (json.dumps(table, indent=1) + "\n").encode() == before, "unexpected table formatting"
    entry = table["instructions"][KEY]
    assert entry["base_op"] == "ATOMS" and entry["operand_sig"] == "R_ARURI_R"
    old = entry["mod_groups"][GROUP]
    new = measured_group()
    if old.get("_src") == PROVENANCE:
        print(f"{KEY} / {GROUP}: already measured in {path}")
        return
    assert int(old["and_base"], 16) & ~SCHEDULE & ~0xf000 == int(new["and_base"], 16), \
        "the leftover row's mode bits must match the measured word"
    entry["mod_groups"][GROUP] = new
    path.write_text(json.dumps(table, indent=1) + "\n")
    print(f"{KEY} / {GROUP}: replaced (base {new['and_base']}, mask {new['variable_mask']}) in {path}")


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

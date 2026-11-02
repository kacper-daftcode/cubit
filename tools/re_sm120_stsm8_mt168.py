#!/usr/bin/env python3
"""Measure SM120 STSM.8.MT168 (8-bit transposed matrix store) with nvdisasm and add its canonical rows.

STSM (opcode 0x844) stores warp-wide matrix fragments to shared memory; the canonical table carried
the 16-bit rows of `STSM_ARI_R` (M88 / MT88 / MT168 x plain / .2 / .4, BUG-433/438) but no 8-bit
datatype, so the `STSM.8.MT168.4 [R111+0x10800], R68` words that PTX `stmatrix.sync.aligned.m16n8.x4.trans.b8`
compiles to (40 words in FlashInfer 0.7.2's swapab sparse-MLA prefill kernels, sm_120 AOT cubin
of vLLM-Moet image r21) stopped cubit's strict round-trip with `no instruction matches ... at
opcode 0x0844` (front "cubit + prefill", session L follow-up, 2026-10-28).

`probe` sweeps the fields nvdisasm 13.1 renders for the form: guard [15:12] (@P0..@P6, PT,
@!P0..@!P6, @!PT), base register [31:24] (255 = RZ, printed `[imm]`), source register [39:32]
(255 = RZ), the signed 24-bit offset [63:40] (elided at 0), and the count [73:72] (0 plain, 1 = .2,
2 = .4). The lattice around the form is recorded in the fixture with `"lattice": true` and stays
outside the rows (fail-closed): count 3 = INVALID3; the datatype window [77:75] where only bit 75
selects .8 over .16 (bits 76/77 are text-inert); the shape [79:78] (0 M88, 1 MT88, 2 MT168,
3 INVALID3 - only MT168 is claimed here); the text-inert bits 16..23, 64..71, 80 (the BUG-438
alias ring), 81..90, 92..95 and the reuse window [124:122]; bit 91 switches to the unclaimed
`[R+UR+imm]` address. `apply` adds `8,MT168`, `2,8,MT168` and `4,8,MT168` to `STSM_ARI_R` next to
the 16-bit MT168 groups with the donors' measured fields (guard, sub_r0@24, sub_imm1@40, reg@32),
and_base = donor | bit 75 and a variable mask of exactly the measured fields (the donors' bit-80
alias relaxation is not inherited: the alias words are text-inert, so they stay unclaimed).
"""
import argparse
import copy
import hashlib
import json
import pathlib
import re
import subprocess

PROVENANCE = "stsm8-mt168-sm120-2026-10-29"
OPCODE = 0x844
NATIVE_CTRL = 0x000fe800 << 96
SCHEDULE = ((1 << 23) - 1) << 105
KEY = "STSM_ARI_R"
GROUPS = {0: ("8,MT168", "16,MT168"), 1: ("2,8,MT168", "16,2,MT168"), 2: ("4,8,MT168", "16,4,MT168")}
FIXTURE = pathlib.Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "sm120_stsm8_mt168_nvdisasm.jsonl"
TEXT = re.compile(r"(@!?P[0-6T] )?STSM\.8\.MT168(\.2|\.4)? \[(R(Z|\d+))?(\+?-?0x[0-9a-f]+)?\], R(Z|\d+)")


def word(guard=7, ra=111, rb=68, imm=0x10800, count=2, dtype=1, shape=2, hi_extra=0):
    hi = count | (dtype << 3) | (shape << 6) | hi_extra  # [73:72] count, [77:75] datatype, [79:78] shape
    return OPCODE | (guard << 12) | (ra << 24) | (rb << 32) | ((imm & 0xffffff) << 40) | (hi << 72)


def sweep_words():
    """(word, lattice) pairs: lattice words document the neighbourhood and must stay unclaimed."""
    form = set()
    for count in (0, 1, 2):
        form.add(word(count=count))
        for guard in range(16):
            form.add(word(count=count, guard=guard))
        for ra in (0, 1, 254, 255):
            form.add(word(count=count, ra=ra))
        for rb in (0, 1, 64, 254, 255):
            form.add(word(count=count, rb=rb))
        for imm in (0, 1, 0x10a00, 0x7fffff, 0x800000, 0xffffff):
            form.add(word(count=count, imm=imm))
        form.add(word(count=count, guard=8, ra=255, rb=255, imm=0))
    for bit in range(24):
        form.add(word(imm=1 << bit))
    lattice = set()
    lattice.add(word(count=3))
    for dtype in range(8):
        lattice.add(word(dtype=dtype))
    for shape in range(4):
        lattice.add(word(shape=shape))
    for bit in (16, 23, 64, 71):
        lattice.add(word() | (1 << bit))
    for bit in range(80, 96):
        lattice.add(word(hi_extra=1 << (bit - 72)))
    for bit in (122, 123, 124):
        lattice.add(word(hi_extra=1 << (bit - 72)))
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
    binary = pathlib.Path("/tmp/re_sm120_stsm8_mt168_probe.bin")
    digest = hashlib.sha256(pathlib.Path(nvdisasm).read_bytes()).hexdigest()
    version = subprocess.check_output([nvdisasm, "--version"], text=True).strip().splitlines()[-1]
    rows = []
    for w, lattice in sweep_words():  # one word per call: nvdisasm aborts a whole file on one illegal word
        body = nvdisasm_text(nvdisasm, binary, w)
        if not lattice:
            assert body is not None and TEXT.fullmatch(body), f"{w:032x}: {body}"
        else:
            assert body is None or body.startswith("STSM."), f"{w:032x}: {body}"
        row = {"word": f"{w:032x}", "nvidia_sass": body, "nvdisasm": version, "nvdisasm_sha256": digest}
        if lattice:
            row["lattice"] = True
        rows.append(row)
    with out.open("w") as fh:
        for r in rows:
            fh.write(json.dumps(r) + "\n")
    n_form = sum(not r.get("lattice") for r in rows)
    print(f"{n_form} STSM.8.MT168[.2/.4] words + {len(rows) - n_form} lattice words -> {out}")


def apply(table_path):
    path = pathlib.Path(table_path)
    before = path.read_bytes()
    table = json.loads(before)
    assert (json.dumps(table, indent=1) + "\n").encode() == before, "unexpected table formatting"
    entry = table["instructions"][KEY]
    assert entry["base_op"] == "STSM" and entry["operand_sig"] == "ARI_R"
    groups = entry["mod_groups"]
    added = []
    for count, (name, donor_name) in GROUPS.items():
        if name in groups:
            continue
        donor = groups[donor_name]
        fields = copy.deepcopy(donor["fields"])
        assert [(f["extraction"], f["shift"], f["bits"], f["token_idx"]) for f in fields] == [
            ("guard", 12, 4, 0), ("sub_r0", 24, 8, 1), ("sub_imm1", 40, 24, 1), ("reg", 32, 8, 2)], donor_name
        mask = 0
        for f in fields:
            f["_src"] = PROVENANCE
            mask |= ((1 << f["bits"]) - 1) << f["shift"]
        base = word(count=count, ra=0, rb=0, imm=0) & ~SCHEDULE & ~mask
        assert base == (int(donor["and_base"], 16) & ~SCHEDULE & ~mask) | (1 << 75), donor_name
        group = {
            "and_base": f"0x{base:032x}",
            "count": None,
            "fields": fields,
            "variable_mask": f"0x{mask:032x}",
            "_src": PROVENANCE,
            "_note": ("nvdisasm 13.1 sweeps: guard[15:12], base register[31:24] (255 = RZ, printed [imm]), source "
                      "register[39:32], signed offset[63:40], count[73:72] (0 plain, 1 .2, 2 .4; 3 INVALID3), bit 75 = "
                      ".8 (bits 76/77 text-inert), shape[79:78] = 2 MT168 (0 M88, 1 MT88, 3 INVALID3 unclaimed). "
                      f"Fields of the {donor_name} donor; the variable mask is exactly the measured fields (the donors' "
                      "text-inert bit-80 alias is not inherited). PTX stmatrix.sync.aligned.m16n8.x1/x2/x4.trans.b8."),
        }
        # insert right after the 16-bit MT168 sibling so the file keeps its neighbourhood order
        rebuilt = {}
        for k, v in groups.items():
            rebuilt[k] = v
            if k == donor_name:
                rebuilt[name] = group
        groups = rebuilt
        added.append(name)
    entry["mod_groups"] = groups
    path.write_text(json.dumps(table, indent=1) + "\n")
    print(f"{KEY}: added groups {added} in {path}")


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

#!/usr/bin/env python3
"""Measure SM120 UBLKPF.L2 (bulk L2 prefetch, PTX cp.async.bulk.prefetch.L2) with nvdisasm and add its canonical rows.

UBLKPF (opcode 0x3bc, uniform datapath) prefetches a bulk region into L2: `UBLKPF.L2 [URa], URsize`
and, with a tensor-map/descriptor, `UBLKPF.L2 [URa], URsize, desc[URd]`. The canonical table carried
only a harvest-era key `UBLKPF.L2_AUR_UR` whose `AUR` address signature cubit's printer renders in
the descriptor spelling (`desc[UR24][R24.64]`) and whose key the encoder never selects for the
vendor text (`[UR24]` is an `AURI` address), so the 28 UBLKPF words of FlashInfer 0.7.2's
sparse-MLA prefill kernels (sm_120 AOT cubin of vLLM-Moet image r21: 16 plain words incl. `@!UP0`,
12 descriptor words under `@UP0` / `@!UP0`) did not round-trip (front "cubit + prefill", session L
follow-up, 2026-10-28). The sibling UBLKCP has the measured keys `UBLKCP_AURI_AURI_UR` /
`UBLKCP_AURI_AURI_UR_II` (`G,S`, native capture 2026-10-22) - the model for these rows.

`probe` sweeps the fields nvdisasm 13.1 renders: the uniform guard [15:12] (@UP0..@UP6, UPT,
@!UP0..@!UP6, @!UPT), the address register [31:24] (255 = URZ), the size register [71:64]
(255 = URZ) and, when bit 76 is set, the descriptor register [47:40] (255 = URZ). The lattice is
recorded in the fixture with `"lattice": true` and stays outside the rows (fail-closed): the
descriptor byte without bit 76 and the bits 16..23, 32..39, 48..63, 72..75, 77..90, 92..95 are
text-inert, bit 91 is required (clearing it is illegal), `.L2` is the opcode's fixed text (no bit
toggles it) and the reuse window [124:122] prints nothing. `apply` adds `UBLKPF_AURI_UR` / `L2`
(guard, sub_ur0@24, ureg@64) and `UBLKPF_AURI_UR_II` / `L2` (+ desc_ur@40, bit 76 fixed) next to
the harvest key, cloning its entry metadata with the ctrl_class of the measured UBLKCP siblings.
"""
import argparse
import copy
import hashlib
import json
import pathlib
import re
import subprocess
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import tablefmt  # noqa: E402  -- the canonical table layout (NEEDS 61, 2026-11-08)

PROVENANCE = "ublkpf-l2-sm120-2026-10-29"
OPCODE = 0x3bc
NATIVE_CTRL = 0x0003f000 << 96
SCHEDULE = ((1 << 23) - 1) << 105
LEGACY_KEY = "UBLKPF.L2_AUR_UR"
SIBLING_KEY = "UBLKCP_AURI_AURI_UR_II"
KEYS = {"UBLKPF_AURI_UR": "AURI_UR", "UBLKPF_AURI_UR_II": "AURI_UR_II"}
GROUP = "L2"
FIXTURE = pathlib.Path(__file__).resolve().parents[2] / "tests" / "fixtures" / "sm120_ublkpf_nvdisasm.jsonl"
TEXT = re.compile(r"(@!?UP[0-6T] )?UBLKPF\.L2 \[UR(Z|\d+)\], UR(Z|\d+)(, desc\[UR(Z|\d+)\])?")


def field(shift, bits, extraction, token):
    return {"bits": bits, "extraction": extraction, "shift": shift, "token_idx": token, "_src": PROVENANCE}


def word(guard=7, ura=24, urs=4, desc=None, lo_extra=0, hi_extra=0, bit91=1):
    hi = (bit91 << 91) | hi_extra
    if desc is not None:
        hi |= (1 << 76) | (desc << 40)
    return OPCODE | (guard << 12) | (ura << 24) | (urs << 64) | hi | lo_extra


def sweep_words():
    """(word, lattice) pairs: lattice words document the neighbourhood and must stay unclaimed."""
    form = {word(), word(desc=4)}
    for guard in range(16):
        form.add(word(guard=guard))
        form.add(word(guard=guard, ura=16, urs=6, desc=4))
    for ura in (0, 1, 10, 31, 62, 63, 255):
        form.add(word(ura=ura))
        form.add(word(ura=ura, desc=4))
    for urs in (0, 1, 7, 31, 62, 63, 255):
        form.add(word(urs=urs))
        form.add(word(urs=urs, desc=4))
    for desc in (0, 1, 8, 31, 62, 63, 255):
        form.add(word(desc=desc))
    form.add(word(guard=0, ura=6, urs=5, desc=8))
    form.add(word(guard=8, ura=10, urs=7))
    lattice = set()
    for desc in (1, 4, 255):
        lattice.add(word(lo_extra=desc << 40))
    for bit in (16, 23, 32, 39, 48, 55, 63):
        lattice.add(word(lo_extra=1 << bit))
    for bit in range(72, 96):
        if bit in (76, 91):
            continue
        lattice.add(word(hi_extra=1 << bit))
    for bit in (122, 123, 124):
        lattice.add(word(hi_extra=1 << bit))
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
    binary = pathlib.Path("/tmp/re_sm120_ublkpf_probe.bin")
    digest = hashlib.sha256(pathlib.Path(nvdisasm).read_bytes()).hexdigest()
    version = subprocess.check_output([nvdisasm, "--version"], text=True).strip().splitlines()[-1]
    rows = []
    for w, lattice in sweep_words():  # one word per call: nvdisasm aborts a whole file on one illegal word
        body = nvdisasm_text(nvdisasm, binary, w)
        if not lattice:
            assert body is not None and TEXT.fullmatch(body), f"{w:032x}: {body}"
        else:
            assert body is None or body.startswith("UBLKPF."), f"{w:032x}: {body}"
        row = {"word": f"{w:032x}", "nvidia_sass": body, "nvdisasm": version, "nvdisasm_sha256": digest}
        if lattice:
            row["lattice"] = True
        rows.append(row)
    with out.open("w") as fh:
        for r in rows:
            fh.write(json.dumps(r) + "\n")
    n_form = sum(not r.get("lattice") for r in rows)
    print(f"{n_form} UBLKPF.L2 words + {len(rows) - n_form} lattice words -> {out}")


def group(fields, base, note):
    mask = 0
    for f in fields:
        bits = ((1 << f["bits"]) - 1) << f["shift"]
        assert mask & bits == 0, "measured fields are disjoint"
        mask |= bits
    return {"and_base": f"0x{base & ~SCHEDULE & ~mask:032x}", "count": None, "fields": fields,
            "variable_mask": f"0x{mask:032x}", "_src": PROVENANCE, "_note": note}


def apply(table_path):
    path = pathlib.Path(table_path)
    table = tablefmt.load_table(path)  # refused unless in the canonical layout
    ins = table["instructions"]
    if all(k in ins for k in KEYS):
        print(f"{', '.join(KEYS)}: already present in {path}")
        return
    legacy = ins[LEGACY_KEY]
    assert legacy["base_op"] == "UBLKPF.L2" and legacy["operand_sig"] == "AUR_UR"
    sibling = ins[SIBLING_KEY]
    assert sibling["base_op"] == "UBLKCP" and list(sibling["mod_groups"]) == ["G,S"]
    guard = field(12, 4, "guard", 0)
    plain = group([guard, field(24, 8, "sub_ur0", 1), field(64, 8, "ureg", 2)], word(ura=0, urs=0),
                  "nvdisasm 13.1 sweeps: uniform guard[15:12], address UR[31:24] (255 = URZ), size UR[71:64] "
                  "(255 = URZ); opcode 0x3bc with bit 91 (required) is UBLKPF.L2 - no bit toggles the .L2 text. "
                  "Bits 16-23, 32-47, 48-63, 72-75, 77-90, 92-95 are text-inert and bit 76 adds the descriptor "
                  "operand (the _II key) - all outside this row. PTX cp.async.bulk.prefetch.L2.global.")
    desc = group([guard, field(24, 8, "sub_ur0", 1), field(64, 8, "ureg", 2), field(40, 8, "desc_ur", 3)],
                 word(ura=0, urs=0, desc=0),
                 "nvdisasm 13.1 sweeps: uniform guard[15:12], address UR[31:24] (255 = URZ), size UR[71:64] "
                 "(255 = URZ), descriptor UR[47:40] (255 = URZ) with the descriptor-present bit 76 fixed; "
                 "opcode 0x3bc with bit 91 (required). Same text-inert neighbourhood as the plain row. "
                 "PTX cp.async.bulk.prefetch.L2.global with an L2 cache hint.")
    rebuilt = {}
    for k, v in ins.items():
        rebuilt[k] = v
        if k == LEGACY_KEY:
            for key, (sig, row) in zip(KEYS, [("AURI_UR", plain), ("AURI_UR_II", desc)]):
                entry = copy.deepcopy(legacy)
                entry.pop("encode_only", None)
                entry["base_op"] = "UBLKPF"
                entry["operand_sig"] = sig
                # the uniform bulk family is scheduled like its measured UBLKCP siblings (it carries a read
                # barrier in the vendor schedule, so it is not a fully static control word)
                entry["ctrl_class"] = sibling["ctrl_class"]
                entry["mod_groups"] = {GROUP: row}
                rebuilt[key] = entry
    table["instructions"] = rebuilt
    tablefmt.save_table(path, table)
    print(f"{', '.join(KEYS)}: added next to {LEGACY_KEY} in {path} (plain base {plain['and_base']}, desc base {desc['and_base']})")


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

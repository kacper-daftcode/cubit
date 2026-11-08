#!/usr/bin/env python3
"""Measure the SM120 UBLKCP direction code with nvdisasm 13.1 and add the bulk-copy rows the sorted
modifier group cannot name: `UBLKCP.G.S` (the TMA bulk *store*, shared -> global:
PTX `cp.async.bulk.global.shared::cta.bulk_group`) and `UBLKCP.S.S` (shared -> shared).

UBLKCP (opcode 0x3ba, the uniform datapath, bit 91 required) copies a bulk region between the
address spaces its two letters name -- destination space first, then source space, the vendor's
spelling (`UBLKCP.S.G [URdst], [URsrc], URsize` = global -> shared, the load every TMA pipeline
issues). The direction is the two-bit code [74:73]:

    0 = .G.G (global -> global)      1 = .S.G (global -> shared: the load, `UBLKCP_AURI_AURI_UR` / `G,S`)
    2 = .G.S (shared -> global: the store)      3 = .S.S (shared -> shared)

The canonical table carried the codes 0 and 1 as the groups `G,G` / `G,S` of the plain key
`UBLKCP_AURI_AURI_UR` (and `G,S` of the descriptor key `_II`, bit 76 + desc UR [47:40]). A mod-group
name is the *sorted* modifier set, so `.G.S` and `.S.G` spell the same name `G,S`: the store had no
row (nvcc's store word printed as `/* ? */`) and the text `UBLKCP.G.S [UR4], [UR36], UR6` assembled
to the load word -- a silent wrong-direction encode (found by the megakernel work of 2026-11-08
compiling `cp.async.bulk.global.shared::cta` with nvcc 13.0 for sm_120a; nvdisasm 13.1 / 13.4 name
the minted word `UBLKCP.S.G`). Like the conversions (`F2F.BF16.F32_R_R` next to `F2F.F32.F64_R_R`),
an ordered modifier pair lives on a dotted key: this probe adds `UBLKCP.G.S_AURI_AURI_UR[_II]` and
`UBLKCP.S.S_AURI_AURI_UR[_II]` with the empty group, and the encoder (src/encoder.rs) refuses to
serve a `.G.S` / `.S.S` text from the plain key's sorted group.

`probe` sweeps, for the codes 2 and 3 with and without the descriptor: the uniform guard [15:12],
the destination address UR [39:32], the source address UR [31:24], the size UR [71:64] and the
descriptor UR [47:40] (255 = URZ everywhere). The lattice (recorded with `"lattice": true`, outside
the rows, fail-closed): bit 75 = `.MULTICAST`, 81 = `.LTC64B`, 82 = `.LTC128B`, 83 = `.SEQUENCED`,
84 = `.DST_G_BYTE_MASK` (modifier bits of groups this probe does not claim), bits 72, 85-90 and the
upper 16-23 / 48-63 / 92-104 text-inert, bits 77-80 illegal, bit 91 required (clearing it is
illegal), the descriptor byte without bit 76 text-inert. `apply` writes the four keys next to
`UBLKCP_AURI_AURI_UR_II`, cloning that family's scheduling and ctrl_class.
"""
from __future__ import annotations

import argparse
import copy
import pathlib
import re
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import nvprobe  # noqa: E402

PROVENANCE = "ublkcp-dir-sm120-2026-11-08"
OPCODE = 0x3ba
NATIVE_CTRL = 0x0003f000 << 96  # the control code the sibling UBLKPF probe measured under (never part of a row)
FIXTURE = nvprobe.FIXTURES / "sm120_ublkcp_dir_nvdisasm.jsonl"
PLAIN_KEY = "UBLKCP_AURI_AURI_UR"
DESC_KEY = "UBLKCP_AURI_AURI_UR_II"
DIRECTIONS = {2: "G.S", 3: "S.S"}
TEXT = re.compile(r"(@!?UP[0-6T] )?UBLKCP\.(G|S)\.(G|S) \[UR(Z|\d+)\], \[UR(Z|\d+)\], UR(Z|\d+)(, desc\[UR(Z|\d+)\])?")


def word(code: int, guard: int = 7, dst: int = 32, src: int = 48, size: int = 64, desc: int | None = None,
         extra: int = 0, bit91: int = 1) -> int:
    w = OPCODE | (guard << 12) | (src << 24) | (dst << 32) | (size << 64) | (code << 73) | (bit91 << 91) | extra
    if desc is not None:
        w |= (1 << 76) | (desc << 40)
    return w


def sweep_words():
    """(word, lattice) pairs for the two directions the sorted group cannot name."""
    form = set()
    for code in DIRECTIONS:
        for desc in (None, 8):
            form.add(word(code, desc=desc))
            for guard in range(16):
                form.add(word(code, guard=guard, desc=desc))
            for v in (0, 1, 10, 31, 62, 63, 255):
                form.add(word(code, dst=v, desc=desc))
                form.add(word(code, src=v, desc=desc))
                form.add(word(code, size=v, desc=desc))
                if desc is not None:
                    form.add(word(code, desc=v))
        form.add(word(code, guard=0, dst=6, src=5, size=4, desc=1))
        form.add(word(code, guard=8, dst=10, src=7, size=9))
    # nvcc 13.0's own store word (`cp.async.bulk.global.shared::cta.bulk_group [UR4], [UR36], UR6`)
    form.add(word(2, dst=4, src=36, size=6))
    lattice = set()
    base = word(2)
    for bit in range(16, 24):
        lattice.add(base | (1 << bit))
    for bit in (40, 47, 48, 55, 56, 63):
        lattice.add(base | (1 << bit))
    for bit in range(72, 105):
        if bit in (73, 74, 76, 91):
            continue
        lattice.add(base | (1 << bit))
    for bit in (122, 123, 124):
        lattice.add(base | (1 << bit))
    lattice.add(word(2, bit91=0))
    lattice.add(word(2, desc=8) | (1 << 75))
    lattice -= form
    return [(w, False) for w in sorted(form)] + [(w, True) for w in sorted(lattice)]


def expected_text(w: int) -> str:
    code = (w >> 73) & 3
    guard = (w >> 12) & 0xf
    ur = lambda v: "URZ" if v == 255 else f"UR{v}"  # noqa: E731
    g = "" if guard == 7 else (f"@UP{guard} " if guard < 7 else ("@!UPT " if guard == 15 else f"@!UP{guard - 8} "))
    text = f"{g}UBLKCP.{DIRECTIONS[code]} [{ur((w >> 32) & 0xff)}], [{ur((w >> 24) & 0xff)}], {ur((w >> 64) & 0xff)}"
    if (w >> 76) & 1:
        text += f", desc[{ur((w >> 40) & 0xff)}]"
    return text


def probe(nvdisasm: str, out: pathlib.Path = FIXTURE, jobs: int = 8) -> None:
    rows = nvprobe.probe_words(
        nvdisasm, "ublkcp_dir", sweep_words(), NATIVE_CTRL,
        check_form=lambda w, text: TEXT.fullmatch(text) is not None and text == expected_text(w),
        check_lattice=lambda w, text: text is None or text.startswith("UBLKCP."),
        jobs=jobs)
    nvprobe.write_fixture(out, rows)
    n_form = sum(not r.get("lattice") for r in rows)
    print(f"{n_form} UBLKCP.G.S / UBLKCP.S.S words + {len(rows) - n_form} lattice words -> {out}")


def apply(table_path: str) -> None:
    path = pathlib.Path(table_path)
    table = nvprobe.load_table(path)
    ins = table["instructions"]
    plain, desc = ins[PLAIN_KEY], ins[DESC_KEY]
    assert plain["base_op"] == "UBLKCP" and set(plain["mod_groups"]) == {"G,S", "G,G"}, PLAIN_KEY
    assert desc["base_op"] == "UBLKCP" and list(desc["mod_groups"]) == ["G,S"], DESC_KEY
    guard = nvprobe.field(12, 4, "guard", 0, PROVENANCE)
    fields_plain = [guard, nvprobe.field(32, 8, "sub_ur0", 1, PROVENANCE), nvprobe.field(24, 8, "sub_ur0", 2, PROVENANCE),
                    nvprobe.field(64, 8, "ureg", 3, PROVENANCE)]
    fields_desc = fields_plain + [nvprobe.field(40, 8, "desc_ur", 4, PROVENANCE)]
    new = {}
    for code, direction in DIRECTIONS.items():
        what = {"G.S": "shared -> global, the TMA bulk store (PTX cp.async.bulk.global.shared::cta.bulk_group)",
                "S.S": "shared -> shared"}[direction]
        for sig, fields, template, model in (("AURI_AURI_UR", fields_plain, word(code, guard=0, dst=0, src=0, size=0), plain),
                                             ("AURI_AURI_UR_II", fields_desc, word(code, guard=0, dst=0, src=0, size=0, desc=0), desc)):
            key = f"UBLKCP.{direction}_{sig}"
            note = (f"Measured with nvdisasm 13.1 (-b SM120; tools/probes/re_sm120_ublkcp_dir.py): direction code [74:73] = {code} "
                    f"prints `UBLKCP.{direction}` ({what}; 0 = .G.G, 1 = .S.G are the plain key's groups). Fields: uniform guard "
                    f"[15:12], destination address UR [39:32], source address UR [31:24], size UR [71:64]"
                    + (", descriptor UR [47:40] with the descriptor-present bit 76 fixed" if "II" in sig else "")
                    + " (255 = URZ). Outside the row: bit 75 `.MULTICAST`, 81 `.LTC64B`, 82 `.LTC128B`, 83 `.SEQUENCED`, "
                    "84 `.DST_G_BYTE_MASK` (unclaimed modifier groups), bits 72, 85-90, 16-23, 48-63, 92-104 text-inert, 77-80 "
                    "illegal, bit 91 required. The two letters are an ordered pair (destination, source): the sorted mod-group "
                    "name cannot tell .G.S from .S.G, hence the dotted key; the encoder refuses to serve this text from the "
                    "plain key's `G,S` group (the load).")
            entry = copy.deepcopy(model)
            entry.pop("_note", None)
            entry.pop("encode_only", None)
            entry["base_op"] = f"UBLKCP.{direction}"
            entry["operand_sig"] = sig
            entry["_src"] = PROVENANCE
            entry["mod_groups"] = {"": nvprobe.row(template, fields, PROVENANCE, note)}
            new[key] = entry
    present = [k for k in new if k in ins]
    if present:
        print(f"{', '.join(present)}: already present in {path}")
        return
    rebuilt = {}
    for k, v in ins.items():
        rebuilt[k] = v
        if k == DESC_KEY:
            rebuilt.update(new)
    table["instructions"] = rebuilt
    prov = table["_meta"]["provenance"]
    rows = [g for e in rebuilt.values() if isinstance(e, dict) and isinstance(e.get("mod_groups"), dict)
            for g in e["mod_groups"].values()]
    prov["rows_total"] = len(rows)
    prov["rows_without_src"] = sum(1 for g in rows if g.get("_src") is None)
    prov["sources"][PROVENANCE] = {
        "rows": len(new),
        "kind": "nvdisasm 13.1 field probe (-b SM120): the UBLKCP direction code [74:73], the .G.S / .S.S forms",
        "date": "2026-11-08",
        "tool": "tools/probes/re_sm120_ublkcp_dir.py",
        "test": "tests/sm120_ublkcp_dir.rs",
    }
    nvprobe.save_table(path, table)
    print(f"{path}: added {', '.join(new)} after {DESC_KEY}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("probe")
    p.add_argument("--nvdisasm", default="/usr/local/lib/python3.12/dist-packages/triton/backends/nvidia/bin/nvdisasm")
    p.add_argument("--out", type=pathlib.Path, default=FIXTURE)
    p.add_argument("--jobs", type=int, default=8)
    a = sub.add_parser("apply")
    a.add_argument("table")
    args = parser.parse_args()
    if args.command == "probe":
        probe(args.nvdisasm, args.out, args.jobs)
    else:
        apply(args.table)


if __name__ == "__main__":
    main()

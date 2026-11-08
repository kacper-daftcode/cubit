#!/usr/bin/env python3
"""Measure SM120 FENCE.VIEW.ASYNC (the async-proxy fence, PTX `fence.proxy.async[.shared::cta|.global]`)
with nvdisasm 13.1 and rewrite the `FENCE` key's rows from the measurement.

FENCE (opcode 0x3c6) orders the generic proxy against the async proxy (TMA / bulk copies). nvcc 13.0
for sm_120a emits `MEMBAR.ALL.CTA; FENCE.VIEW.ASYNC.S` for `fence.proxy.async.shared::cta`,
`MEMBAR.ALL.GPU; FENCE.VIEW.ASYNC.S` for the generic `fence.proxy.async`, and `FENCE.VIEW.ASYNC.G`
for `fence.proxy.async.global` -- the fence a kernel needs between generic stores to global memory
and a TMA / bulk copy that reads them (or the other way round), on this GPU or a peer's.

The canonical table carried the key from a 2026-08 donor census (`bug226e`): two rows without
fields, `ASYNC,S,VIEW` (0x73c6) and `ASYNC,T,VIEW` (bit 73), both with a variable mask made of
control-code bits. nvdisasm 13.1 on SM120 says: bit 72 is the scope -- clear = `.S`, set = `.G`
(the `.G` word had no row: it printed as `.S` with a reserved-bit residue and the text did not
assemble); the predicate guard [15:12] is live (`@P0 FENCE.VIEW.ASYNC.S` ... `@!PT`); bit 73 (`.T`,
the tensor-memory scope of sm_100 / sm_103) is ILLEGAL on SM120 -- with bit 72 or without it -- so
the `.T` row leaves the SM120 table; bits 74-75 and every other bit of the word are text-inert
(outside the rows, fail-closed), bit 91 is illegal. The control code matters for this opcode: a word
whose read-barrier field [115:113] names a barrier (anything but 7) is illegal -- FENCE has no
register source to track, so it may carry a write barrier and no read barrier (the probe measures
under nvcc's own control code, wrtbar 7 / readbar 7 / stall 4 / yield).

`probe` sweeps the scope bit, the guard and the lattice into `tests/fixtures/sm120_fence_view_async_nvdisasm.jsonl`;
`apply` rewrites `FENCE`: `ASYNC,S,VIEW` and `ASYNC,G,VIEW` with the guard field, the donor rows gone.
"""
from __future__ import annotations

import argparse
import pathlib
import re
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import nvprobe  # noqa: E402

PROVENANCE = "fence-view-async-sm120-2026-11-08"
OPCODE = 0x73c6  # 0x3c6 + the guard PT (7) in [14:12]
NVCC_CTRL = 0x000fe800 << 96  # nvcc 13.0's control code on the fence: stall 4, yield, wrtbar 7, readbar 7
FIXTURE = nvprobe.FIXTURES / "sm120_fence_view_async_nvdisasm.jsonl"
KEY = "FENCE"
DONOR_SRC = "bug226e-2026-08-28"
TEXT = re.compile(r"(@!?P[0-6T] )?FENCE\.VIEW\.ASYNC\.(S|G)")


def word(scope: int = 0, guard: int = 7, extra: int = 0) -> int:
    return 0x3c6 | (guard << 12) | (scope << 72) | extra


def expected_text(w: int) -> str:
    guard = (w >> 12) & 0xf
    g = "" if guard == 7 else (f"@P{guard} " if guard < 7 else ("@!PT " if guard == 15 else f"@!P{guard - 8} "))
    return f"{g}FENCE.VIEW.ASYNC.{'G' if (w >> 72) & 1 else 'S'}"


def sweep_words():
    form = set()
    for scope in (0, 1):
        for guard in range(16):
            form.add(word(scope, guard))
    lattice = set()
    for scope in (0, 1):
        lattice.add(word(scope) | (1 << 73))  # .T: illegal on SM120
    for bit in list(range(16, 72)) + list(range(73, 105)):
        lattice.add(word() | (1 << bit))
    for bit in (122, 123, 124):
        lattice.add(word() | (1 << bit))
    lattice -= form
    return [(w, False) for w in sorted(form)] + [(w, True) for w in sorted(lattice)]


def probe(nvdisasm: str, out: pathlib.Path = FIXTURE, jobs: int = 8) -> None:
    rows = nvprobe.probe_words(
        nvdisasm, "fence_view_async", sweep_words(), NVCC_CTRL,
        check_form=lambda w, text: TEXT.fullmatch(text) is not None and text == expected_text(w),
        check_lattice=lambda w, text: text is None or text == "FENCE.VIEW.ASYNC.S",
        jobs=jobs)
    # the control-code law, recorded as lattice words under their own control code: a read barrier makes the word illegal
    scratch = pathlib.Path("/tmp/re_sm120_fence_ctrl_probe.bin")
    version, digest = nvprobe.nvdisasm_identity(nvdisasm)
    for readbar in range(7):
        ctrl = (0x4 << 105) | (1 << 109) | (0x7 << 110) | (readbar << 113)
        text = nvprobe.nvdisasm_text(nvdisasm, scratch, word(), ctrl)
        assert text is None, f"readbar {readbar}: {text}"
        rows.append({"word": f"{word() | ctrl:032x}", "nvidia_sass": None, "nvdisasm": version, "nvdisasm_sha256": digest,
                     "lattice": True, "control": f"readbar {readbar}"})
    for wrtbar in range(8):
        ctrl = (0x4 << 105) | (1 << 109) | (wrtbar << 110) | (0x7 << 113)
        text = nvprobe.nvdisasm_text(nvdisasm, scratch, word(), ctrl)
        assert text == "FENCE.VIEW.ASYNC.S", f"wrtbar {wrtbar}: {text}"
    nvprobe.write_fixture(out, rows)
    n_form = sum(not r.get("lattice") for r in rows)
    print(f"{n_form} FENCE.VIEW.ASYNC.{{S,G}} words + {len(rows) - n_form} lattice words -> {out}")


def apply(table_path: str) -> None:
    path = pathlib.Path(table_path)
    table = nvprobe.load_table(path)
    ins = table["instructions"]
    entry = ins[KEY]
    assert entry["base_op"] == "FENCE" and entry["operand_sig"] == "", KEY
    old = entry["mod_groups"]
    if set(old) == {"ASYNC,S,VIEW", "ASYNC,G,VIEW"} and all(g.get("_src") == PROVENANCE for g in old.values()):
        print(f"{KEY}: already measured in {path}")
        return
    assert set(old) == {"ASYNC,S,VIEW", "ASYNC,T,VIEW"}, sorted(old)
    guard = [nvprobe.field(12, 4, "guard", 0, PROVENANCE)]
    common = ("Measured with nvdisasm 13.1 (-b SM120; tools/probes/re_sm120_fence_view_async.py): opcode 0x3c6, the "
              "predicate guard [15:12] live, bit 72 = the scope (clear `.S` = PTX fence.proxy.async.shared::cta, also "
              "nvcc's lowering of the generic fence.proxy.async behind MEMBAR.ALL.GPU; set `.G` = fence.proxy.async.global). "
              "Bit 73 (`.T`, the sm_100 / sm_103 tensor-memory scope of the donor row) is ILLEGAL on SM120, bit 91 illegal, "
              "every other bit of the word text-inert (outside the row, fail-closed). Control law: a read barrier on this "
              "word ([115:113] != 7) makes it illegal -- FENCE carries a write barrier at most (nvcc: wrtbar, stall 4).")
    groups = {
        "ASYNC,S,VIEW": nvprobe.row(word(0, guard=0), guard, PROVENANCE, common),
        "ASYNC,G,VIEW": nvprobe.row(word(1, guard=0), guard, PROVENANCE, common),
    }
    entry["mod_groups"] = groups
    entry["_src"] = PROVENANCE
    entry.pop("_bug226e", None)
    prov = table["_meta"]["provenance"]
    rows = [g for e in ins.values() if isinstance(e, dict) and isinstance(e.get("mod_groups"), dict)
            for g in e["mod_groups"].values()]
    prov["rows_total"] = len(rows)
    prov["rows_without_src"] = sum(1 for g in rows if g.get("_src") is None)
    prov["sources"][PROVENANCE] = {
        "rows": 2,
        "kind": "nvdisasm 13.1 field probe (-b SM120): the async-proxy fence's scope bit, guard and control law",
        "date": "2026-11-08",
        "tool": "tools/probes/re_sm120_fence_view_async.py",
        "test": "tests/sm120_fence_view_async.rs",
    }
    donor = prov["sources"].get(DONOR_SRC)
    if donor is not None and isinstance(donor.get("rows"), int):
        donor["rows"] = sum(1 for g in rows if g.get("_src") == DONOR_SRC)
    nvprobe.save_table(path, table)
    print(f"{path}: {KEY} rewritten -- ASYNC,S,VIEW + ASYNC,G,VIEW measured, the donor ASYNC,T,VIEW row (illegal on SM120) gone")


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

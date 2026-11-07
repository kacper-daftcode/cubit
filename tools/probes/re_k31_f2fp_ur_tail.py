#!/usr/bin/env python3
"""Restore the F2FP.BF16.F32.PACK_AB inert third-source default byte."""
import argparse, json, pathlib, sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from nvprobe import field_mask, load_table, probe_words, save_table, write_fixture

SRC = "k31-f2fp-pack-ur-inert-rc-2026-11-07"
ROOT = pathlib.Path(__file__).resolve().parents[3]
VENDOR = ROOT.parent / "inbox-hgx02/2026-11-07-k31-prefill-gaps/vendor/fixture_flashkda_sm100.jsonl"
FIXTURE = pathlib.Path(__file__).resolve().parents[2] / "tests/fixtures/k31_f2fp_ur_tail_nvdisasm.jsonl"
OP = "F2FP.BF16.F32.PACK_AB"


def put(word, shift, bits, value):
    return (word & ~(((1 << bits) - 1) << shift)) | (value << shift)


def production():
    out = []
    with VENDOR.open() as fh:
        for line in fh:
            r = json.loads(line)
            if r["text"].startswith(OP + " "):
                assert (int(r["word"], 0) >> 64) & 0xff == 0xff
                out.append({"word": r["word"][2:], "nvidia_sass": r["text"], "arch": "SM100", "op": OP,
                            "nvdisasm": r["nvdisasm"], "source": r["source"], "occurrences": r["occurrences"],
                            "evidence": "H production witness; RC=0xff confirmed in both words"})
    assert len(out) == 2
    assert sum(r["occurrences"] for r in out) == 4
    return out


def probe(args):
    out = []
    records = production()
    for arch in ("SM103", "SM100"):
        if arch == "SM100":
            out.extend(records)
        base = int(records[0]["word"], 16)
        words = {put(base, 12, 4, guard) for guard in range(16)}
        for shift in (16, 24, 32):
            for value in (0, 5, 63, 100, 255):
                words.add(put(base, shift, 8, value))
        words = sorted(words)
        measured = probe_words(args.nvdisasm, "k31_f2fp_ur_tail", [(w, False) for w in words], 0,
                               lambda _w, text: OP + " " in text, arch=arch, jobs=args.jobs)
        for rec, word in zip(measured, words):
            rec.update({"word": f"{word:032x}", "arch": arch, "op": OP, "occurrences": 0,
                        "evidence": "independent guard/Rd/Ra/UR probe with measured RC=0xff retained"})
            out.append(rec)
    write_fixture(args.out, out)
    print(len(out), "records ->", args.out)


def apply(tables):
    for path in tables:
        table = load_table(path)
        group = table["instructions"]["F2FP_R_R_UR"]["mod_groups"]["BF16,F32,PACK_AB"]
        and_base = int(group["and_base"], 0)
        variable_mask = int(group["variable_mask"], 0)
        assert and_base & (0xff << 64) == 0
        assert variable_mask & (0xff << 64) == 0xff << 64
        group["and_base"] = f"0x{and_base | (0xff << 64):032x}"
        group["variable_mask"] = f"0x{variable_mask & ~(0xff << 64):032x}"
        for field in group["fields"]:
            field["_src"] = SRC
        group["_src"] = SRC
        group["_note"] = "Measure FlashKDA RC=0xff at [71:64], matching the working SM120 donor. The third operand remains UR at [39:32]; the inert RC byte must survive lossless encoding. Existing claim_forbid rules retained."
        provenance = table["_meta"]["provenance"]
        provenance["sources"][SRC] = {"rows": 1, "kind": "production RC residue + SM103/SM100 guard/register probes",
            "date": "2026-11-07", "tool": "tools/probes/re_k31_f2fp_ur_tail.py", "test": "tests/k31_f2fp_ur_tail.rs"}
        provenance["rows_total"] = sum(len(e.get("mod_groups", {})) for e in table["instructions"].values())
        provenance["rows_without_src"] = sum(1 for e in table["instructions"].values()
                                             for g in e.get("mod_groups", {}).values() if "_src" not in g)
        save_table(path, table)
        print(path, "F2FP BF16 PACK_AB RC=0xff baked into and_base")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest="command", required=True)
    p = sub.add_parser("probe")
    p.add_argument("--nvdisasm", default="/usr/local/cuda/bin/nvdisasm")
    p.add_argument("--out", type=pathlib.Path, default=FIXTURE)
    p.add_argument("--jobs", type=int, default=8)
    a = sub.add_parser("apply")
    a.add_argument("tables", nargs="+", type=pathlib.Path)
    args = ap.parse_args()
    probe(args) if args.command == "probe" else apply(args.tables)


if __name__ == "__main__":
    main()

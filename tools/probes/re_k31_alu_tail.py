#!/usr/bin/env python3
"""Measure FlashKDA FMUL.FTZ.D2 and predicated FFMA.FTZ tail forms."""
import argparse, copy, json, pathlib, sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from nvprobe import SCHEDULE, field_mask, load_table, probe_words, row, save_table, write_fixture

SRC = "k31-flashkda-alu-tail-2026-11-07"
ROOT = pathlib.Path(__file__).resolve().parents[3]
VENDOR = ROOT.parent / "inbox-hgx02/2026-11-07-k31-prefill-gaps/vendor/fixture_flashkda_sm100.jsonl"
STRICT = ROOT / "k31-work/utma1d/release-kda.fail.jsonl"
FIXTURE = pathlib.Path(__file__).resolve().parents[2] / "tests/fixtures/k31_alu_tail_nvdisasm.jsonl"


def put(word, shift, bits, value):
    return (word & ~(((1 << bits) - 1) << shift)) | (value << shift)


def production():
    out = {"FMUL": [], "FFMA": []}
    with VENDOR.open() as fh:
        for line in fh:
            r = json.loads(line)
            if r["text"].startswith("FMUL.FTZ.D2 "):
                out["FMUL"].append({"word": r["word"][2:], "nvidia_sass": r["text"], "arch": "SM100", "op": "FMUL",
                                    "nvdisasm": r["nvdisasm"], "source": r["source"], "occurrences": r["occurrences"],
                                    "evidence": "H production witness"})
    # These FFMA words were hidden behind the original MOVM failures. They are
    # now directly measured from the post-MOVM strict stream and nvdisasm.
    from nvprobe import nvdisasm_text
    scratch = pathlib.Path("/tmp/re_k31_alu_tail_production.bin")
    with STRICT.open() as fh:
        for line in fh:
            outer = json.loads(line)
            f = outer["failure"]
            if f["stage"] != "decode" or (int(f["expected"], 0) & 0xfff) != 0x223:
                continue
            word = int(f["expected"], 0)
            text = nvdisasm_text("/usr/local/cuda/bin/nvdisasm", scratch, word, 0, "SM100")
            assert text is not None and "FFMA.FTZ " in text
            section = f["section"]
            out["FFMA"].append({"word": f"{word:032x}", "nvidia_sass": text, "arch": "SM100", "op": "FFMA",
                                "source": f"{pathlib.Path(outer.get('input', 'flashkda')).name}:{section}:{f['addr']:#x}",
                                "occurrences": 1, "evidence": "post-MOVM production strict witness + direct nvdisasm"})
    assert len(out["FMUL"]) == 4
    assert sum(r["occurrences"] for r in out["FMUL"]) == 64
    assert len(out["FFMA"]) == 164
    return out


def probe(args):
    rows = production()
    out = []
    for arch in ("SM103", "SM100"):
        for op, records in rows.items():
            if arch == "SM100":
                for r in records:
                    r.setdefault("nvdisasm", "Build cuda_13.3.r13.3/compiler.38244171_0")
                out.extend(records)
            base = int(records[0]["word"], 16)
            words = {put(base, 12, 4, guard) for guard in range(16)}
            shifts = (16, 24, 32) if op == "FMUL" else (16, 24, 32, 64)
            for shift in shifts:
                for value in (0, 5, 63, 100, 255):
                    words.add(put(base, shift, 8, value))
            bits = (72, 73, 62, 63, 122, 123) if op == "FMUL" else (72, 73, 62, 63, 74, 75, 122, 123, 124)
            for bit in bits:
                words.add(base ^ (1 << bit))
            words = sorted(words)
            mnemonic = "FMUL.FTZ.D2 " if op == "FMUL" else "FFMA.FTZ "
            measured = probe_words(args.nvdisasm, "k31_alu_tail", [(w, False) for w in words], 0,
                                   lambda _w, text, mnemonic=mnemonic: mnemonic in text, arch=arch, jobs=args.jobs)
            for rec, word in zip(measured, words):
                rec.update({"word": f"{word:032x}", "arch": arch, "op": op, "occurrences": 0,
                            "evidence": "independent guard/register/sign/reuse nvdisasm field probe"})
                out.append(rec)
    write_fixture(args.out, out)
    print(len(out), "records ->", args.out)


def apply(tables):
    sm120 = load_table(ROOT / "isa-k31/sm120.json")["instructions"]
    donors = {"FMUL": sm120["FMUL_R_R_R"]["mod_groups"]["D2,FTZ"],
              "FFMA": sm120["FFMA_R_R_R_R"]["mod_groups"]["FTZ"]}
    keys = {"FMUL": "FMUL_R_R_R", "FFMA": "FFMA_R_R_R_R"}
    groups = {"FMUL": "D2,FTZ", "FFMA": "FTZ"}
    records = production()
    for path in tables:
        table = load_table(path)
        for op in ("FMUL", "FFMA"):
            fields = copy.deepcopy(donors[op]["fields"])
            for f in fields:
                f["_src"] = SRC
            word = int(records[op][0]["word"], 16)
            base = (word & ~field_mask(fields) & ~SCHEDULE & ~0xfff) | (0x220 if op == "FMUL" else 0x223)
            table["instructions"][keys[op]]["mod_groups"][groups[op]] = row(base, fields, SRC,
                "FlashKDA production plus SM103/SM100 guard, full registers, signs, absolute values and reuse probes.")
        provenance = table["_meta"]["provenance"]
        provenance["sources"][SRC] = {"rows": 2, "kind": "measured FMUL/FFMA target fields from production and local probes",
            "date": "2026-11-07", "tool": "tools/probes/re_k31_alu_tail.py", "test": "tests/k31_alu_tail.rs"}
        provenance["rows_total"] = sum(len(e.get("mod_groups", {})) for e in table["instructions"].values())
        provenance["rows_without_src"] = sum(1 for e in table["instructions"].values()
                                             for g in e.get("mod_groups", {}).values() if "_src" not in g)
        save_table(path, table)
        print(path, "FMUL D2,FTZ and full FFMA FTZ rows installed")


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

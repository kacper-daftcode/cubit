#!/usr/bin/env python3
"""Measure single-result LDG.NA[.64].CONSTANT descriptor forms."""
import argparse, copy, json, pathlib, sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from nvprobe import field_mask, load_table, probe_words, row, save_table, write_fixture

SRC = "k31-ldg-small-constants-2026-11-07"
ROOT = pathlib.Path(__file__).resolve().parents[3]
VENDOR = ROOT.parent / "inbox-hgx02/2026-11-07-k31-prefill-gaps/vendor/fixture_flashmla_sm100.jsonl"
FIXTURE = pathlib.Path(__file__).resolve().parents[2] / "tests/fixtures/k31_ldg_constants_nvdisasm.jsonl"
FORMS = {"LDG.E.NA.CONSTANT": (10, 18), "LDG.E.NA.64.CONSTANT": (6, 12)}


def put(word, shift, bits, value):
    return (word & ~(((1 << bits) - 1) << shift)) | (value << shift)


def production():
    out = {op: [] for op in FORMS}
    with VENDOR.open() as fh:
        for line in fh:
            r = json.loads(line)
            op = next((key for key in FORMS if r["text"].startswith(key + " ")), None)
            if op is not None:
                out[op].append({"word": r["word"][2:], "nvidia_sass": r["text"], "arch": "SM100", "op": op,
                                "nvdisasm": r["nvdisasm"], "source": r["source"], "occurrences": r["occurrences"],
                                "evidence": "H production witness"})
    for op, (count, occ) in FORMS.items():
        assert len(out[op]) == count
        assert sum(r["occurrences"] for r in out[op]) == occ
    return out


def probe(args):
    out = []
    for arch in ("SM103", "SM100"):
        for op, records in production().items():
            if arch == "SM100": out.extend(records)
            base = int(records[0]["word"], 16)
            words = {put(base, 12, 4, guard) for guard in range(16)}
            for shift in (16, 32):
                for value in (0, 5, 63, 64, 100):
                    words.add(put(base, shift, 8, value))
            for raw in (0, 4, 64, 32767, 32768, 65535, 65536, 131071):
                words.add(put(base, 40, 17, raw))
            words = sorted(words)
            measured = probe_words(args.nvdisasm, "k31_ldg", [(w, False) for w in words], 0,
                                   lambda _w, text, op=op: op in text, arch=arch, jobs=args.jobs)
            for rec, word in zip(measured, words):
                rec.update({"word": f"{word:032x}", "arch": arch, "op": op, "occurrences": 0,
                            "evidence": "independent nvdisasm field probe"})
                out.append(rec)
    write_fixture(args.out, out)
    print(len(out), "records ->", args.out)


def apply(tables):
    donor = load_table(ROOT / "isa-k31/sm120.json")["instructions"]["LDG.E.ENL2.256_R_R_dARI"]
    for path in tables:
        table = load_table(path)
        for op, records in production().items():
            entry = copy.deepcopy(donor)
            fields = copy.deepcopy(entry["mod_groups"][""]["fields"])
            fields = [f for f in fields if not (f["token_idx"] == 1 and f["shift"] == 64)]
            for f in fields:
                f["_src"] = SRC
                if f["token_idx"] >= 2:
                    f["token_idx"] -= 1
                if f["extraction"] == "sub_imm2_shr5":
                    f["extraction"] = "sub_imm2_shr0u"
            word = int(records[0]["word"], 16)
            base = (word & ~field_mask(fields) & ~(((1 << 23) - 1) << 105) & ~0xfff) | 0x981
            entry["base_op"] = op
            entry["operand_sig"] = "R_dARI"
            entry["mod_groups"] = {"": row(base, fields, SRC, "Single destination and desc[UR][R.64] with unsigned 17-bit byte offset; actual small-constant production and exact target field probes.")}
            entry["_src"] = SRC
            table["instructions"][op + "_R_dARI"] = entry
        pro = table["_meta"]["provenance"]
        pro["sources"][SRC] = {"rows": 2, "kind": "measured descriptor fields + SM103/SM100 probes", "date": "2026-11-07",
                              "tool": "tools/probes/re_k31_ldg_constants.py", "test": "tests/k31_ldg_constants.rs"}
        pro["rows_total"] = sum(len(e.get("mod_groups", {})) for e in table["instructions"].values())
        pro["rows_without_src"] = sum(1 for e in table["instructions"].values() for g in e.get("mod_groups", {}).values() if "_src" not in g)
        save_table(path, table)
        print(path, "two single-result constants rows installed")


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


if __name__ == "__main__": main()

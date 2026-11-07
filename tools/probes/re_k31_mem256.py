#!/usr/bin/env python3
"""Measure the exact FlashMLA LDG/STG 256-bit descriptor forms."""
import argparse, copy, json, pathlib, sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from nvprobe import field, field_mask, load_table, probe_words, row, save_table, write_fixture

SRC = "k31-memory256-flashmla-2026-11-07"
ROOT = pathlib.Path(__file__).resolve().parents[3]
VENDOR = ROOT.parent / "inbox-hgx02/2026-11-07-k31-prefill-gaps/vendor/fixture_flashmla_sm100.jsonl"
FIXTURE = pathlib.Path(__file__).resolve().parents[2] / "tests/fixtures/k31_memory256_nvdisasm.jsonl"
FORMS = [
    ("LDG.E.NA.EFL2.LTC256B.256.CONSTANT", "R_R_dARI", 457, 514),
    ("LDG.E.NA.ENL2.LTC256B.256.CONSTANT", "R_R_dARI", 5, 8),
    ("LDG.E.NA.ENL2.LTC256B.256.CONSTANT", "R_R_dARI_II", 27, 45),
    ("LDG.E.EF.ENL2.LTC256B.256.CONSTANT", "R_R_dARI", 2, 3),
    ("LDG.E.ENL2.LTC256B.256.CONSTANT", "R_R_dARI", 1, 2),
    ("STG.E.NA.EFL2.256", "dARI_R_R", 44, 72),
]
KEY_FIELD = 2


def put(word, shift, bits, value):
    return (word & ~(((1 << bits) - 1) << shift)) | (value << shift)


def key(base, sig):
    return f"{base}_{sig}"


def production():
    out = {(base, sig): [] for base, sig, _, _ in FORMS}
    with VENDOR.open() as fh:
        for line in fh:
            r = json.loads(line)
            base = next((b for b, _, _, _ in FORMS if r["text"].startswith(b + " ")), None)
            if not base:
                continue
            sig = "R_R_dARI_II" if base.startswith("LDG") and r["text"].rsplit(", ", 1)[-1].startswith("0x") else "R_R_dARI"
            if base.startswith("STG"):
                sig = "dARI_R_R"
            rec = (base, sig)
            assert rec in out, (base, sig, r["text"])
            out[rec].append({"word": r["word"][2:], "nvidia_sass": r["text"], "arch": "SM100", "form": key(base, sig),
                             "nvdisasm": r["nvdisasm"], "source": r["source"], "occurrences": r["occurrences"],
                             "evidence": "H production witness (not re-probed)"})
    for base, sig, count, occurrences in FORMS:
        assert len(out[(base, sig)]) == count, (base, sig, len(out[(base, sig)]), count)
        assert sum(r["occurrences"] for r in out[(base, sig)]) == occurrences, (base, sig)
    return out


def probe(args):
    rows = production()
    out = []
    for arch in ("SM103", "SM100"):
        for (base, sig), records in rows.items():
            if arch == "SM100":
                out.extend(records)
            word = int(records[0]["word"], 16)
            words = {put(word, 12, 4, guard) for guard in range(16)}
            for shift in (16, 24, 32, 64):
                for value in (0, 5, 63, 64, 100):
                    words.add(put(word, shift, 8, value))
            for raw in (0, 4, 64, 32767, 32768, 65535, 65536, 131071):
                if base.startswith("STG"):
                    words.add(put(word, 40, 19, raw))
                else:
                    words.add(put(word, 40, 17, raw))
            if sig.endswith("_II"):
                for value in (0, 1, 3, 0xf, 0x3f, 0x7f):
                    words.add(put(word, 57, 7, value))
                words.add(put(word, 72, 1, 1))
            words = sorted(words)
            measured = probe_words(args.nvdisasm, "k31_mem256", [(w, False) for w in words], 0,
                                   lambda _w, text, base=base: base in text, arch=arch, jobs=args.jobs)
            for rec, value in zip(measured, words):
                rec.update({"word": f"{value:032x}", "arch": arch, "form": key(base, sig), "occurrences": 0,
                            "evidence": "independent raw nvdisasm field probe"})
                out.append(rec)
    write_fixture(args.out, out)
    print(len(out), "records ->", args.out)


def apply(tables):
    donor = load_table(ROOT / "isa-k31/sm120.json")["instructions"]
    anchors = production()
    for path in tables:
        table = load_table(path)
        ins = table["instructions"]
        for (base, sig), records in anchors.items():
            ldg = base.startswith("LDG")
            donor_key = "STG.E.EFL2.256_dARI_R_R" if not ldg else "LDG.E.ENL2.256_R_R_dARI" + ("_II" if sig.endswith("_II") else "")
            entry = copy.deepcopy(donor[donor_key])
            fields = copy.deepcopy(entry["mod_groups"][""]["fields"])
            for f in fields:
                f["_src"] = SRC
            word = int(records[0]["word"], 16)
            base_word = (word & ~field_mask(fields) & ~(((1 << 23) - 1) << 105) & ~0xfff) | (word & 0xfff)
            group = row(base_word, fields, SRC,
                        "Production witnesses and independent SM103/SM100 guard/register/offset/policy probes for this exact "
                        f"{base} form. Signed scaled address offset and, where present, the trailing policy immediate are explicit.")
            entry["base_op"] = base
            entry["operand_sig"] = sig
            entry["mod_groups"] = {"": group}
            entry["_src"] = SRC
            ins[key(base, sig)] = entry
        pro = table["_meta"]["provenance"]
        pro["sources"][SRC] = {"rows": 6, "kind": "measured descriptor field transfer + nvdisasm 13.3.73 exact-form target probes",
                              "date": "2026-11-07", "tool": "tools/probes/re_k31_mem256.py", "test": "tests/k31_memory256.rs"}
        pro["rows_total"] = sum(len(e.get("mod_groups", {})) for e in ins.values())
        pro["rows_without_src"] = sum(1 for e in ins.values() for g in e.get("mod_groups", {}).values() if "_src" not in g)
        save_table(path, table)
        print(path, "6 exact descriptor forms installed")


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
    if args.command == "probe":
        probe(args)
    else:
        apply(args.tables)


if __name__ == "__main__":
    main()

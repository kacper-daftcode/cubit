#!/usr/bin/env python3
"""Add measured FlashMLA UTMALDG GATHER4/2CTA/5D variants."""
import argparse, copy, json, pathlib, sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from nvprobe import field_mask, load_table, probe_words, row, save_table, write_fixture

SRC = "k31-utma-flashmla-2026-11-07"
ROOT = pathlib.Path(__file__).resolve().parents[3]
VENDOR = ROOT.parent / "inbox-hgx02/2026-11-07-k31-prefill-gaps/vendor/fixture_flashmla_sm100.jsonl"
FIXTURE = pathlib.Path(__file__).resolve().parents[2] / "tests/fixtures/k31_utma_forms_nvdisasm.jsonl"
FORMS = {
    "UTMALDG.2D.GATHER4 ": ("2D,GATHER4", 263, 884),
    "UTMALDG.2D.GATHER4.2CTA ": ("2CTA,2D,GATHER4", 94, 264),
    "UTMALDG.5D.2CTA ": ("2CTA,5D", 3, 7),
}
KEY = "UTMALDG_AURI_AURI_II"


def put(word, shift, bits, value):
    return (word & ~(((1 << bits) - 1) << shift)) | (value << shift)


def production():
    out = {name: [] for name in FORMS}
    with VENDOR.open() as fh:
        for line in fh:
            r = json.loads(line)
            name = next((n for n in FORMS if r["text"].startswith(n)), None)
            if name is not None:
                out[name].append({"word": r["word"][2:], "nvidia_sass": r["text"], "arch": "SM100",
                                  "op": name.strip(), "nvdisasm": r["nvdisasm"], "source": r["source"],
                                  "occurrences": r["occurrences"], "evidence": "H production witness (not re-probed)"})
    for name, (_, count, occurrences) in FORMS.items():
        assert len(out[name]) == count
        assert sum(r["occurrences"] for r in out[name]) == occurrences
    return out


def probe(args):
    rows = production()
    out = []
    for arch in ("SM103", "SM100"):
        for name, records in rows.items():
            if arch == "SM100":
                out.extend(records)
            base = int(records[0]["word"], 16)
            words = {put(base, 12, 4, guard) for guard in range(16)}
            for shift in (24, 32, 40):
                for value in (0, 8, 63, 64, 255):
                    words.add(put(base, shift, 8, value))
            words = sorted(words)
            measured = probe_words(args.nvdisasm, "k31_utma_forms", [(w, False) for w in words], 0,
                                   lambda _w, text, name=name: name.strip() in text, arch=arch, jobs=args.jobs)
            for rec, word in zip(measured, words):
                rec.update({"word": f"{word:032x}", "arch": arch, "op": name.strip(), "occurrences": 0,
                            "evidence": "independent raw nvdisasm field probe"})
                out.append(rec)
    write_fixture(args.out, out)
    print(len(out), "records ->", args.out)


def apply(tables):
    donor = load_table(ROOT / "isa-k31/sm120.json")["instructions"][KEY]
    anchors = production()
    for path in tables:
        table = load_table(path)
        ins = table["instructions"]
        entry = copy.deepcopy(ins[KEY])
        assert len(entry["mod_groups"]) == 7
        for name, (group_name, _, _) in FORMS.items():
            fields = copy.deepcopy(donor["mod_groups"]["2D"]["fields"])
            for f in fields:
                f["_src"] = SRC
            word = int(anchors[name][0]["word"], 16)
            base = (word & ~field_mask(fields) & ~(((1 << 23) - 1) << 105) & ~0xfff) | 0x5b4
            entry["mod_groups"][group_name] = row(
                base, fields, SRC,
                "FlashMLA production witnesses and local SM103/SM100 probes: UR operands at 32/24 and the "
                "explicit third desc[UR] at 40; exact dimensional/GATHER4/2CTA fixed bits, existing variants retained.")
        ins[KEY] = entry
        pro = table["_meta"]["provenance"]
        pro["sources"][SRC] = {"rows": 3, "kind": "measured UTMALDG dimensional donor + nvdisasm 13.3.73 target field probes",
                              "date": "2026-11-07", "tool": "tools/probes/re_k31_utma_forms.py", "test": "tests/k31_utma_forms.rs"}
        pro["rows_total"] = sum(len(e.get("mod_groups", {})) for e in ins.values())
        pro["rows_without_src"] = sum(1 for e in ins.values() for g in e.get("mod_groups", {}).values() if "_src" not in g)
        save_table(path, table)
        print(path, "3 UTMALDG groups installed; 7 earlier groups retained")


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

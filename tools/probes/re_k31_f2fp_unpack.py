#!/usr/bin/env python3
"""Transfer measured F16/E4M3, F16/E2M1 and BF16/E8 UNPACK_B forms."""
import argparse, copy, json, pathlib, sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from nvprobe import field, load_table, probe_words, row, save_table, write_fixture

SRC = "k31-f2fp-unpack-flashmla-2026-11-07"
ROOT = pathlib.Path(__file__).resolve().parents[3]
VENDOR = ROOT.parent / "inbox-hgx02/2026-11-07-k31-prefill-gaps/vendor/fixture_flashmla_sm100.jsonl"
FIXTURE = pathlib.Path(__file__).resolve().parents[2] / "tests/fixtures/k31_f2fp_unpack_nvdisasm.jsonl"
FORMS = {
    "F2FP.F16.E4M3.UNPACK_B": ("F2FP.F16.E4M3.UNPACK_B_R_R", (1264, 301)),
    "F2FP.F16.E2M1.UNPACK_B": ("F2FP.F16.E2M1.UNPACK_B_R_R", (1280, 597)),
    "F2FP.BF16.E8.UNPACK_B": ("F2FP.BF16.E8.UNPACK_B_R_R", (568, 177)),
    "F2FP.E8.F32.PACK_AB_MERGE_C.RZ": ("F2FP.E8.F32.PACK_AB_MERGE_C.RZ_R_R_R_R", (16, 6)),
}


def put(word, shift, bits, value):
    return (word & ~(((1 << bits) - 1) << shift)) | (value << shift)


def production():
    out = {name: [] for name in FORMS}
    with VENDOR.open() as fh:
        for line in fh:
            r = json.loads(line)
            parts = r["text"].split()
            name = next((n for n in FORMS if r["text"].startswith(n + " ")), None)
            if name is None:
                continue
            if parts[0].startswith("@"):
                assert parts[1].startswith(name + " ")
            out[name].append({"word": r["word"][2:], "nvidia_sass": r["text"], "arch": "SM100",
                              "op": name, "nvdisasm": r["nvdisasm"], "source": r["source"],
                              "occurrences": r["occurrences"], "evidence": "H production witness (not re-probed)"})
    for name, (_, (occ, count)) in FORMS.items():
        assert len(out[name]) == count
        assert sum(r["occurrences"] for r in out[name]) == occ
    return out


def probe(args):
    production_rows = production()
    out = []
    for arch in ("SM103", "SM100"):
        for name, rows in production_rows.items():
            if arch == "SM100":
                out.extend(rows)
            base = int(rows[0]["word"], 16)
            words = set()
            for guard in range(16):
                words.add(put(base, 12, 4, guard))
            for shift in ((16, 24, 32, 64) if "PACK_AB" in name else (16, 32)):
                for value in (0, 5, 47, 100, 255):
                    words.add(put(base, shift, 8, value))
            for reuse in (0, 1):
                words.add(put(base, 123, 1, reuse))
            if "E2M1" in name:
                for low in (0, 1):
                    for high in (0, 1):
                        word = put(put(base, 72, 1, low), 88, 1, high)
                        words.add(word)
            elif "PACK_AB" not in name:
                words.add(put(base, 88, 1, 0))
                words.add(put(base, 88, 1, 1))
            words = sorted(words)
            measured = probe_words(args.nvdisasm, "k31_f2fp_unpack", [(w, False) for w in words], 0,
                                   lambda _w, text, name=name: name in text, arch=arch, jobs=args.jobs)
            for rec, word in zip(measured, words):
                rec.update({"word": f"{word:032x}", "arch": arch, "op": name,
                            "occurrences": 0, "evidence": "independent raw nvdisasm field probe"})
                out.append(rec)
    write_fixture(args.out, out)
    print(len(out), "records ->", args.out)


def apply(tables):
    donor_ins = load_table(ROOT / "isa-k31/sm120.json")["instructions"]
    anchors = production()
    for path in tables:
        table = load_table(path)
        ins = table["instructions"]
        for name, (key, _) in FORMS.items():
            if name == "F2FP.E8.F32.PACK_AB_MERGE_C.RZ":
                entry = copy.deepcopy(donor_ins["F2FP.F16.E4M3.UNPACK_B_R_R"])
                entry["base_op"] = name
                entry["operand_sig"] = "R_R_R_R"
                fields = [field(12, 4, "guard", 0, SRC), field(16, 8, "reg", 1, SRC),
                          field(24, 8, "reg", 2, SRC), field(32, 8, "reg", 3, SRC),
                          field(64, 8, "reg", 4, SRC)]
                mask = sum(((1 << f["bits"]) - 1) << f["shift"] for f in fields)
                word = int(anchors[name][0]["word"], 16)
                base = (word & ~mask & ~(((1 << 23) - 1) << 105) & ~0xfff) | 0x23e
                group = row(base, fields, SRC,
                            "Six production FlashMLA words plus nvdisasm 13.3.73 field sweeps: four explicit register operands, "
                            "including the fourth RZ; mnemonic keeps the measured .PACK_AB_MERGE_C.RZ spelling.")
                entry["mod_groups"] = {"": group}
            else:
                entry = copy.deepcopy(donor_ins[key])
                group = entry["mod_groups"][""]
            if name == "F2FP.F16.E2M1.UNPACK_B":
                group["fields"].extend([
                    {"bits": 1, "extraction": "e2m1_ra", "shift": 72, "token_idx": 2, "_src": SRC},
                    {"bits": 1, "extraction": "e2m1_ra", "shift": 88, "token_idx": 2, "_src": SRC},
                ])
                mask = 0
                for f in group["fields"]:
                    m = ((1 << f["bits"]) - 1) << f["shift"]
                    assert not mask & m
                    mask |= m
                word = int(anchors[name][0]["word"], 16)
                group["and_base"] = f"0x{(word & ~mask & ~(((1 << 23) - 1) << 105) & ~0xfff) | 0x23e:032x}"
                group["variable_mask"] = f"0x{mask:032x}"
            for f in group["fields"]:
                f["_src"] = SRC
            group["_src"] = SRC
            group["_measurement"] = "SM120 measured donor transferred to SM103a/SM100a; all production words and local field probes revalidated."
            entry["_src"] = SRC
            ins[key] = entry
        # The old generic E4M3 group lacks H1/reuse and wins the lookup before
        # the measured typed key. Retire only this covered group; sibling
        # harvest forms and the already encode-only spelling-alias stay live.
        retired = ins["F2FP_R_R"]["mod_groups"].pop("F16,E4M3,UNPACK_B", None)
        assert retired is not None or "F2FP.F16.E4M3.UNPACK_B_R_R" in ins
        alias = ins["F2FP_R_R"]["mod_groups"].pop("E4M3,F16,UNPACK_B", None)
        assert alias is not None and alias.get("encode_only")
        assert "TF32,F32,PACK_B" in ins["F2FP_R_R"]["mod_groups"]
        pro = table["_meta"]["provenance"]
        pro["sources"][SRC] = {"rows": 4, "kind": "measured SM120 donor + nvdisasm 13.3.73 target field probes + production witnesses",
                              "date": "2026-11-07", "tool": "tools/probes/re_k31_f2fp_unpack.py", "test": "tests/k31_f2fp_unpack.rs"}
        pro["rows_total"] = sum(len(e.get("mod_groups", {})) for e in ins.values())
        pro["rows_without_src"] = sum(1 for e in ins.values() for g in e.get("mod_groups", {}).values() if "_src" not in g)
        save_table(path, table)
        print(path, "4 F2FP conversion forms installed")


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

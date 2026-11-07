#!/usr/bin/env python3
"""Measure packed-FP32 scalar-source geometry missing after the first MoE pass."""
import argparse, copy, collections, json, pathlib, sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from nvprobe import field, field_mask, load_table, probe_words, row, save_table, write_fixture

SRC = "k31-packed-scalar-fp32-2026-11-07"
ROOT = pathlib.Path(__file__).resolve().parents[3]
VENDOR = ROOT.parent / "inbox-hgx02/2026-11-07-k31-prefill-gaps/vendor"
WORK = ROOT / "k31-work"
FIXTURE = pathlib.Path(__file__).resolve().parents[2] / "tests/fixtures/k31_fp32_scalar_nvdisasm.jsonl"
NVDISASM = "/usr/local/cuda/bin/nvdisasm"


def put(word, shift, bits, value):
    return (word & ~(((1 << bits) - 1) << shift)) | (value << shift)


def fmul2_words():
    out = []
    for target, stem in [("SM103", "release103"), ("SM100", "release100f")]:
        seen = {}
        with (WORK / "sync-forms" / f"{stem}.fail.jsonl").open() as fh:
            for line in fh:
                row = json.loads(line)
                failure = row["failure"]
                if (failure.get("expected") or "").endswith("24a"):
                    word = failure["expected"][2:]
                    seen.setdefault(word, [0, row["input"]])
                    seen[word][0] += 1
        for word, (occurrences, source) in sorted(seen.items()):
            out.append((int(word, 16), {"arch": target, "op": "FMUL2", "occurrences": occurrences,
                                       "source": source, "evidence": "actual trtllm residual, locally disassembled"}))
    assert len(out) == 884
    assert sum(meta["occurrences"] for _, meta in out) == 1432
    return out


def h_ffma2_words():
    rows = []
    for filename in ["fixture_trtllm_moe_sm100f.jsonl", "fixture_flashmla_sm100.jsonl"]:
        with (VENDOR / filename).open() as fh:
            for line in fh:
                r = json.loads(line)
                if not r["text"].startswith("FFMA2"):
                    continue
                opcode = int(r["word"], 16) & 0xfff
                assert opcode in (0x249, 0xc49)
                rows.append({"word": r["word"][2:], "nvidia_sass": r["text"],
                             "arch": r["target"].replace("F", ""), "op": "FFMA2",
                             "kind": "UR" if opcode == 0xc49 else "R",
                             "nvdisasm": r["nvdisasm"], "source": r["source"],
                             "occurrences": r["occurrences"], "evidence": "H production witness (not re-probed)"})
    assert len(rows) == 1221
    assert sum(r["occurrences"] for r in rows) == 1856
    return rows


def probe(args):
    out = []
    fmul = fmul2_words()
    for arch in ("SM103", "SM100"):
        pairs = [(w, False) for w, meta in fmul if meta["arch"] == arch]
        metadata = [meta for w, meta in fmul if meta["arch"] == arch]
        texts = probe_words(args.nvdisasm, "k31_fmul2_production", pairs, 0,
                            lambda _w, text: text.startswith("FMUL2") and text.rsplit(", ", 1)[1].endswith(".F32"),
                            arch=arch, jobs=args.jobs)
        for rec, meta in zip(texts, metadata):
            rec.update(meta)
            rec["kind"] = "R32"
            out.append(rec)

        base = next(w for w, meta in fmul if meta["arch"] == arch)
        synthetic = []
        for guard in range(16):
            synthetic.append(put(base, 12, 4, guard))
        for shift in (16, 24, 32):
            for value in (0, 4, 35, 127, 255):
                synthetic.append(put(base, shift, 8, value))
        synthetic = sorted(set(synthetic))
        measured = probe_words(args.nvdisasm, "k31_fmul2_fields", [(w, False) for w in synthetic], 0,
                               lambda _w, text: text.startswith(("FMUL2", "@")) and ".F32" in text,
                               arch=arch, jobs=args.jobs)
        for rec, word in zip(measured, synthetic):
            rec.update({"word": f"{word:032x}", "arch": arch, "op": "FMUL2", "kind": "R32",
                        "occurrences": 0, "evidence": "independent raw nvdisasm field probe"})
            out.append(rec)
    out.extend(h_ffma2_words())
    write_fixture(args.out, out)
    print(len(out), "records ->", args.out)


def stamp(group):
    group["_src"] = SRC
    for f in group["fields"]:
        f["_src"] = SRC


def apply(tables):
    sm120 = load_table(ROOT / "isa-k31/sm120.json")["instructions"]
    fmul_anchor = fmul2_words()[0][0]
    for path in tables:
        table = load_table(path)
        ins = table["instructions"]
        key = "FMUL2_R_R_R"
        entry = copy.deepcopy(ins[key])
        fields = []
        for f in entry["mod_groups"][""]["fields"]:
            if f["token_idx"] == 3 and ((f["shift"] in (32, 64) and f["extraction"] == "reg") or f["shift"] in (85, 88)):
                continue
            fields.append(copy.deepcopy(f))
        assert not any(f["token_idx"] == 3 and f["extraction"] == "reg" for f in fields)
        fields.append(field(32, 8, "reg", 3, SRC))
        fields.append(field(88, 1, "opmod:F32", 3, SRC))
        base = (fmul_anchor & ~field_mask(fields) & ~(((1 << 23) - 1) << 105) & ~0xfff) | 0x24a
        g = row(base, fields, SRC,
                "nvdisasm 13.3.73 on 884 production words: scalar third Rb lives in the 8-bit slot at 32; "
                "its .F32 form requires bit 88. Ra keeps its measured modifiers; Rd/Ra/Rc guards and reuse stay exact.")
        stamp(g)
        entry["mod_groups"] = {"": g}
        entry["_src"] = SRC
        ins[key] = entry

        for key, opcode in [("FFMA2_R_R_R_R", 0x249), ("FFMA2_R_R_UR_R", 0xc49)]:
            entry = copy.deepcopy(ins[key])
            if key == "FFMA2_R_R_R_R":
                fields = copy.deepcopy(sm120[key]["mod_groups"][""]["fields"])
                fields = [f for f in fields if not (f["token_idx"] == 2 and f["shift"] == 88)]
                fields.append(field(88, 1, "opmod:F32", 3, SRC))
            else:
                fields = copy.deepcopy(entry["mod_groups"][""]["fields"])
            for shift, extraction in [(74, "abs"), (75, "neg"), (85, "opmod:F32"), (124, "reuse")]:
                if not any(f["token_idx"] == 4 and f["shift"] == shift for f in fields):
                    fields.append(field(shift, 1, extraction, 4, SRC))
            for f in fields:
                f["_src"] = SRC
            anchor = next(r for r in h_ffma2_words() if (int(r["word"], 16) & 0xfff) == opcode)
            base = (int(anchor["word"], 16) & ~field_mask(fields) & ~(((1 << 23) - 1) << 105) & ~0xfff) | opcode
            g = row(base, fields, SRC,
                    "FlashMLA/trtllm production witnesses plus nvdisasm bit probes: FFMA2 token 4 uses .F32 when bit 85 is set, "
                    "otherwise .F32x2.HI_LO. Negation, absolute value and reuse are explicit token-4 fields; no text suffix is silently dropped.")
            stamp(g)
            entry["mod_groups"] = {"": g}
            entry["_src"] = SRC
            ins[key] = entry

        pro = table["_meta"]["provenance"]
        pro["sources"][SRC] = {"rows": 3, "kind": "nvdisasm 13.3.73 production residual disassembly and per-field probes",
                              "date": "2026-11-07", "tool": "tools/probes/re_k31_fp32_scalar.py", "test": "tests/k31_fp32_scalar.rs"}
        pro["rows_total"] = sum(len(e.get("mod_groups", {})) for e in ins.values())
        pro["rows_without_src"] = sum(1 for e in ins.values() for g in e.get("mod_groups", {}).values() if "_src" not in g)
        save_table(path, table)
        print(path, "3 scalar packed-FP32 rows repaired")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest="command", required=True)
    p = sub.add_parser("probe")
    p.add_argument("--nvdisasm", default=NVDISASM)
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

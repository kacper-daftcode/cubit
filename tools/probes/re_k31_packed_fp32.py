#!/usr/bin/env python3
"""Measure the K3.1 packed-FP32 immediate/UR forms and FADD2's third register.

FADD2/FMUL2 place Rd@16, Ra@24 and their third operand at 32 (with f32@32 for
immediate forms).  FFMA2 has a different four-operand geometry and is not
silently treated as the same form.  H supplies the production witness text;
raw probes independently cover guard, registers, URs, and float immediates.
"""
import argparse, copy, json, pathlib, sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from nvprobe import field, field_mask, load_table, nvdisasm_identity, probe_words, row, save_table

SRC = "k31-packed-fp32-2026-11-07"
INBOX = pathlib.Path("/root/sm103a/inbox-hgx02/2026-11-07-k31-prefill-gaps/vendor")
ISA = pathlib.Path(__file__).resolve().parents[3] / "isa-k31"
FIXTURE = pathlib.Path(__file__).resolve().parents[2] / "tests/fixtures/k31_packed_fp32_nvdisasm.jsonl"
FAMILIES = [("FADD2", "R", "FADD2_R_R_R"), ("FADD2", "FI", "FADD2_R_R_FI"),
            ("FADD2", "UR", "FADD2_R_R_UR"), ("FMUL2", "FI", "FMUL2_R_R_FI"),
            ("FMUL2", "UR", "FMUL2_R_R_UR")]


def put(w, shift, bits, value):
    return (w & ~(((1 << bits) - 1) << shift)) | (value << shift)


def samples():
    tables = {"R": {}, "FI": {}, "UR": {}}
    out = []
    for filename in ["fixture_trtllm_moe_sm103a.jsonl", "fixture_trtllm_moe_sm100f.jsonl"]:
        with (INBOX / filename).open() as fh:
            for line in fh:
                r = json.loads(line)
                if not r["text"].startswith(("FADD2", "FMUL2")):
                    continue
                kind = "FI" if r["text"].endswith(", -1") or r["text"].endswith(", 1") else "UR" if ", UR" in r["text"] else "R"
                op = r["text"].split()[0]
                arch = r["target"].replace("F", "")
                out.append({"word": r["word"][2:], "nvidia_sass": r["text"], "arch": arch,
                            "target_file": filename, "nvdisasm": r["nvdisasm"], "source": r["source"],
                            "occurrences": r["occurrences"], "kind": kind, "op": op,
                            "evidence": "H production witness (not re-probed)"})
                tables[kind].setdefault(op, r)
    tables["R"].setdefault("FMUL2", {"word": f"{(0x000fe200 << 96) | 0x24a | (7 << 12) | (52 << 16) | (4 << 24) | (5 << 64):032x}", "synthetic_probe": True})
    for kind in ("R", "FI", "UR"):
        assert set(tables[kind]) == {"FADD2", "FMUL2"}, (kind, set(tables[kind]))
    print("production records", len(out), "words", sum(r["occurrences"] for r in out))
    return out, tables


def probe(args):
    out, tables = samples()
    for arch in ("SM103", "SM100"):
        words = []
        for kind in ("R", "FI", "UR"):
            for op in ("FADD2", "FMUL2"):
                base = int(tables[kind][op]["word"], 16)
                for guard in range(16):
                    words.append((put(base, 12, 4, guard), False))
                for rd in (0, 4, 47, 100, 255):
                    words.append((put(base, 16, 8, rd), False))
                for ra in (0, 5, 44, 100, 255):
                    words.append((put(base, 24, 8, ra), False))
                if kind != "FI":
                    for rc in (0, 5, 12, 47, 100):
                        words.append((put(base, 32, 8, rc), False))
                else:
                    for imm in (0, 0x3f800000, 0xbf800000, 0x7f800000, 0x7fc00001, 0xffffffff):
                        words.append((put(base, 32, 32, imm), False))
        words = list(dict.fromkeys(words))
        expected = lambda _w, text: text.startswith(("FADD2", "FMUL2", "@"))
        rows = probe_words(args.nvdisasm, "k31_packed_fp32", words, 0, expected, arch=arch, jobs=args.jobs)
        for rec, (word, _) in zip(rows, words):
            rec["word"] = f"{word:032x}"
            rec["evidence"] = "independent raw nvdisasm probe"
            rec["op"] = op
            rec["kind"] = kind
            rec["synthetic_probe"] = bool(tables[kind][op].get("synthetic_probe"))
        out.extend(rows)
    # Concrete slower remainder of the failed trtllm corpus. These are not
    # synthetic data: this is why a third F32x2.HI_LO must not print as F32.
    for arch in ("SM103", "SM100"):
        word = 0x020fc600000000000000006a9494724b
        from nvprobe import nvdisasm_text
        text = nvdisasm_text(args.nvdisasm, pathlib.Path(f"/tmp/k31_residual_{arch}.bin"), word, 0, arch)
        assert text == "FADD2 R148, R148.F32x2.HI_LO, R106.F32x2.HI_LO", text
        out.append({"word": f"{word:032x}", "nvidia_sass": text, "arch": arch,
                    "source": "trtllm-103a.fail.jsonl, stage=decode", "op": "FADD2", "kind": "R",
                    "evidence": "actual trtllm residual, independently disassembled"})
    with args.out.open("w") as fh:
        for rec in out:
            fh.write(json.dumps(rec) + "\n")
    print(len(out), "records", "->", args.out)


def apply(tables):
    anchors, arities = samples()
    op_n = {"FADD2": (0x44b, 0x24b, 0xe4b), "FMUL2": (0x84a, None, 0xc4a)}
    for path in tables:
        table = load_table(path)
        ins = table["instructions"]
        for op, kind, key in FAMILIES:
            arch = arities[kind][op]
            base = int(arch["word"], 16)
            donor = "FMUL2_R_R_R" if op == "FMUL2" else "FADD2_R_R_R"
            entry = copy.deepcopy(ins[donor])
            entry["_src"] = SRC
            fields = [field(12, 4, "guard", 0, SRC), field(16, 8, "reg", 1, SRC),
                      field(24, 8, "reg", 2, SRC)]
            if op == "FMUL2":
                fields.append(field(122, 1, "reuse", 2, SRC))
            fields.append(field(82, 1, "opmod:F32", 2, SRC))
            if kind == "FI":
                fields.append(field(32, 32, "f32", 3, SRC))
                opcode = op_n[op][0]
            else:
                fields.append(field(32, 8, "reg" if kind == "R" else "ureg", 3, SRC))
                if kind == "R" and op == "FADD2":
                    fields.append(field(85, 1, "opmod:F32", 3, SRC))
                if kind == "R":
                    fields.append(field(124, 1, "reuse", 3, SRC))
                opcode = op_n[op][1 if kind == "R" else 2]
            mask = field_mask(fields)
            base_const = (base & ~mask & ~(((1 << 23) - 1) << 105) & ~0xfff) | opcode
            g = row(base_const, fields, SRC,
                "Measured trtllm-gen packed-FP32 operand geometry on nvdisasm 13.3.73: Rd@16, Ra@24, "
                "or the third register/UR at 32. The F32x2.HI_LO // F32 donor modifiers are preserved; "
                "FFMA2's different four-operand row is not changed. All supplied witnesses of this exact form.")
            entry["base_op"] = op
            if key.endswith("_R_FI"):
                entry["operand_sig"] = "R_R_FI"
            elif key.endswith("_R_UR"):
                entry["operand_sig"] = "R_R_UR"
            else:
                entry["operand_sig"] = "R_R_R"
            entry["mod_groups"] = {"": g}
            ins[key] = entry
        # The ordinary FMUL R/R/R row has the same measured type bit at 85,
        # but HI_LO at 88 is vendor-text-inert here (every failing witness has 0).
        g = ins["FMUL2_R_R_R"]["mod_groups"][""]
        g["fields"] = [f for f in g["fields"] if not (f["shift"] == 88 and f["token_idx"] == 2)]
        if not any(f["shift"] == 85 and f["token_idx"] == 3 for f in g["fields"]):
            g["fields"].append(field(85, 1, "opmod:F32", 3, SRC))
        g["variable_mask"] = f"0x{field_mask(g['fields']):032x}"
        for f in g["fields"]:
            f["_src"] = SRC
        g["_src"] = SRC
        ins["FMUL2_R_R_R"]["_src"] = SRC
        pro = table["_meta"]["provenance"]
        pro["sources"][SRC] = {"rows": 6, "kind": "nvdisasm 13.3.73 per-field and per-operand probes; H production witnesses",
                              "date": "2026-11-07", "tool": "tools/probes/re_k31_packed_fp32.py", "test": "tests/k31_packed_fp32.rs"}
        pro["rows_total"] = sum(len(e.get("mod_groups", {})) for e in ins.values())
        pro["rows_without_src"] = sum(1 for e in ins.values() for g in e.get("mod_groups", {}).values() if "_src" not in g)
        save_table(path, table)
        print(path, "packed-FP32 rows measured: 5")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest="command", required=True)
    p = sub.add_parser("probe")
    p.add_argument("--nvdisasm", default="/usr/local/cuda/bin/nvdisasm")
    p.add_argument("--out", type=pathlib.Path, default=FIXTURE)
    p.add_argument("--jobs", type=int, default=4)
    a = sub.add_parser("apply")
    a.add_argument("tables", nargs="+", type=pathlib.Path)
    args = ap.parse_args()
    if args.command == "probe":
        nvdisasm_identity(args.nvdisasm)
        probe(args)
    else:
        apply(args.tables)


if __name__ == "__main__":
    main()

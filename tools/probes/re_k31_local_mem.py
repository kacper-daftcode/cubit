#!/usr/bin/env python3
"""Measure LDL.U8 and UBLKCP.G.S helper memory forms."""
import argparse, copy, json, pathlib, sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from nvprobe import field_mask, load_table, probe_words, row, save_table, write_fixture

SRC = "k31-local-memory-flashmla-2026-11-07"
ROOT = pathlib.Path(__file__).resolve().parents[3]
VENDOR = ROOT.parent / "inbox-hgx02/2026-11-07-k31-prefill-gaps/vendor/fixture_flashmla_sm100.jsonl"
FIXTURE = pathlib.Path(__file__).resolve().parents[2] / "tests/fixtures/k31_local_mem_nvdisasm.jsonl"
FORMS = {"LDL.U8": (81, 192), "UBLKCP.G.S": (49, 82), "UBLKCP.S.G": (2, 2)}
SG_WORDS = [("0001e4000800021400000012060073ba", "SM100"), ("0007e2000800020e0000000c040073ba", "SM100")]


def put(word, shift, bits, value):
    return (word & ~(((1 << bits) - 1) << shift)) | (value << shift)


def production():
    out = {op: [] for op in FORMS}
    with VENDOR.open() as fh:
        for line in fh:
            r = json.loads(line)
            op = next((op for op in FORMS if r["text"].startswith(op + " ")), None)
            if op is not None:
                out[op].append({"word": r["word"][2:], "nvidia_sass": r["text"], "arch": "SM100", "op": op,
                                "nvdisasm": r["nvdisasm"], "source": r["source"], "occurrences": r["occurrences"],
                                "evidence": "H production witness (not re-probed)"})
    for word, arch in SG_WORDS:
        from nvprobe import nvdisasm_text
        text = nvdisasm_text("/usr/local/cuda/bin/nvdisasm", pathlib.Path(f"/tmp/k31_ublkcp_{arch.lower()}_sg.bin"), int(word, 16), 0, arch)
        assert text is not None
        assert text.startswith("UBLKCP.S.G ")
        out["UBLKCP.S.G"].append({"word": word, "nvidia_sass": text, "arch": arch, "op": "UBLKCP.S.G",
                                  "occurrences": 1, "source": "residual strict stream", "evidence": "locally disassembled residual"})
    for op, (n, occ) in FORMS.items():
        assert len(out[op]) == n, (op, len(out[op]))
        assert sum(r["occurrences"] for r in out[op]) == occ, op
    return out


def probe(args):
    out = []
    for arch in ("SM103", "SM100"):
        for op, records in production().items():
            if arch == "SM100":
                out.extend(records)
            base = int(records[0]["word"], 16)
            words = {put(base, 12, 4, guard) for guard in range(16)}
            if op == "LDL.U8":
                for shift in (16, 24):
                    for value in (0, 5, 63, 64, 100):
                        words.add(put(base, shift, 8, value))
                for raw in (0, 1, 0x10, 0x400, 0x7fffff, 0x800000, 0xffffff):
                    words.add(put(base, 40, 24, raw))
            else:
                for shift in (24, 32, 64):
                    for value in (0, 8, 63, 64, 255):
                        words.add(put(base, shift, 8, value))
            words = sorted(words)
            measured = probe_words(args.nvdisasm, "k31_local_mem", [(w, False) for w in words], 0,
                                   lambda _w, text, op=op: op in text, arch=arch, jobs=args.jobs)
            for rec, word in zip(measured, words):
                rec.update({"word": f"{word:032x}", "arch": arch, "op": op, "occurrences": 0,
                            "evidence": "independent raw nvdisasm field probe"})
                out.append(rec)
    write_fixture(args.out, out)
    print(len(out), "records ->", args.out)


def apply(tables):
    sm120 = load_table(ROOT / "isa-k31/sm120.json")["instructions"]
    anchors = production()
    for path in tables:
        table = load_table(path)
        ins = table["instructions"]
        for op in FORMS:
            key = {"LDL.U8": "LDL.U8_R_ARI", "UBLKCP.G.S": "UBLKCP.G.S_AURI_AURI_UR", "UBLKCP.S.G": "UBLKCP.S.G_AURI_AURI_UR"}[op]
            donor_key = {"LDL.U8": "LDL_R_ARI", "UBLKCP.G.S": "UBLKCP_AURI_AURI_UR", "UBLKCP.S.G": "UBLKCP.S.G_AUR_AUR_UR"}[op]
            entry = copy.deepcopy(sm120[donor_key])
            group = entry["mod_groups"]["" if op in ("LDL.U8", "UBLKCP.S.G") else "G,S"]
            fields = copy.deepcopy(group["fields"])
            for f in fields:
                f["_src"] = SRC
            word = int(anchors[op][0]["word"], 16)
            base = (word & ~field_mask(fields) & ~(((1 << 23) - 1) << 105) & ~0xfff) | (word & 0xfff)
            g = row(base, fields, SRC, "FlashMLA " + op + " production plus independent guard/register/offset target probes; exact type and UR geometry, no blanket reuse of a field-less donor.")
            group.clear()
            group.update(g)
            if op == "LDL.U8":
                entry["base_op"] = "LDL.U8"
            elif op == "UBLKCP.S.G":
                entry["base_op"] = "UBLKCP.S.G"
                entry["operand_sig"] = "AURI_AURI_UR"
                entry["mod_groups"] = {"": group}
                previous = ins.get("UBLKCP.S.G_AUR_AUR_UR")
                if previous is not None and previous.get("_src") == SRC:
                    del ins["UBLKCP.S.G_AUR_AUR_UR"]
            else:
                entry["base_op"] = "UBLKCP.G.S"
                entry["mod_groups"] = {"": group}
                previous = ins.get("UBLKCP_AURI_AURI_UR")
                if previous is not None and previous.get("_src") == SRC:
                    del ins["UBLKCP_AURI_AURI_UR"]
            entry["_src"] = SRC
            ins[key] = entry
        pro = table["_meta"]["provenance"]
        pro["sources"][SRC] = {"rows": 3, "kind": "measured local-memory fields + nvdisasm 13.3.73 target probes", "date": "2026-11-07",
                              "tool": "tools/probes/re_k31_local_mem.py", "test": "tests/k31_local_mem.rs"}
        pro["rows_total"] = sum(len(e.get("mod_groups", {})) for e in ins.values())
        pro["rows_without_src"] = sum(1 for e in ins.values() for g in e.get("mod_groups", {}).values() if "_src" not in g)
        save_table(path, table)
        print(path, "LDL.U8 and UBLKCP.G.S rows installed")


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
    if args.command == "probe": probe(args)
    else: apply(args.tables)


if __name__ == "__main__": main()

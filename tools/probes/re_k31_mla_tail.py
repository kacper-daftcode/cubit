#!/usr/bin/env python3
"""Measure the five remaining FlashMLA instruction forms."""
import argparse, copy, json, pathlib, sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from nvprobe import SCHEDULE, field_mask, load_table, probe_words, row, save_table, write_fixture

SRC = "k31-flashmla-tail-2026-11-07"
ROOT = pathlib.Path(__file__).resolve().parents[3]
VENDOR = ROOT.parent / "inbox-hgx02/2026-11-07-k31-prefill-gaps/vendor/fixture_flashmla_sm100.jsonl"
STRICT = ROOT / "k31-work/mla-tail/baseline.fail.jsonl"
FIXTURE = pathlib.Path(__file__).resolve().parents[2] / "tests/fixtures/k31_mla_tail_nvdisasm.jsonl"
OPS = ("FADD", "FMUL", "FMNMX", "UPLOP3", "BREAK")


def put(word, shift, bits, value):
    return (word & ~(((1 << bits) - 1) << shift)) | (value << shift)


def h_record(r, op, evidence):
    return {"word": r["word"][2:], "nvidia_sass": r["text"], "arch": "SM100", "op": op,
            "nvdisasm": r["nvdisasm"], "source": r["source"], "occurrences": r["occurrences"],
            "evidence": evidence}


def production():
    out = {op: [] for op in OPS}
    with VENDOR.open() as fh:
        for line in fh:
            r = json.loads(line)
            text = r["text"]
            if text.startswith("FADD.FTZ ") and text.endswith(", 448"):
                out["FADD"].append(h_record(r, "FADD", "H production FADD immediate-448 witness"))
            elif text.startswith("UPLOP3.LUT "):
                out["UPLOP3"].append(h_record(r, "UPLOP3", "H production UPLOP3 witness"))
            elif text.startswith("FMNMX.FTZ "):
                out["FMNMX"].append(h_record(r, "FMNMX", "H production FMNMX -INF !PT witness"))
            elif "BREAK.RELIABLE " in text:
                out["BREAK"].append(h_record(r, "BREAK", "H production BREAK.RELIABLE witness"))
    from nvprobe import nvdisasm_text
    scratch = pathlib.Path("/tmp/re_k31_mla_tail_production.bin")
    with STRICT.open() as fh:
        for line in fh:
            outer = json.loads(line)
            f = outer["failure"]
            if f["stage"] != "decode" or (int(f["expected"], 0) & 0xfff) != 0xc20:
                continue
            word = int(f["expected"], 0)
            text = nvdisasm_text("/usr/local/cuda/bin/nvdisasm", scratch, word, 0, "SM100")
            assert text and text.startswith("FMUL ")
            out["FMUL"].append({"word": f"{word:032x}", "nvidia_sass": text, "arch": "SM100", "op": "FMUL",
                "source": f"{pathlib.Path(outer['input']).name}:{f['section']}:{f['addr']:#x}", "occurrences": 1,
                "evidence": "post-LDG production strict witness + direct nvdisasm"})
    expected = {"FADD": (5, 8), "FMUL": (14, 14), "FMNMX": (1, 1), "UPLOP3": (1, 16), "BREAK": (1, 1)}
    for op, (count, occurrences) in expected.items():
        assert len(out[op]) == count, (op, len(out[op]))
        assert sum(r["occurrences"] for r in out[op]) == occurrences
    return out


def probe(args):
    rows = production()
    out = []
    for arch in ("SM103", "SM100"):
        for op, records in rows.items():
            if arch == "SM100":
                out.extend(records)
            base = int(records[0]["word"], 16)
            words = {put(base, 12, 4, guard) for guard in range(16)}
            if op == "BREAK":
                for barrier in (0, 1, 3, 5, 15):
                    words.add(put(base, 16, 4, barrier))
                for pred in (0, 2, 6, 7):
                    words.add(put(base, 87, 3, pred))
                words.add(base ^ (1 << 90))
                mnemonic = "BREAK.RELIABLE "
            elif op == "UPLOP3":
                for shift in (81, 84, 87, 77, 68):
                    for pred in (0, 1, 2, 7):
                        words.add(put(base, shift, 3, pred))
                for bit in (90, 80, 71):
                    words.add(base ^ (1 << bit))
                for value in (0, 1, 0x1f, 0x20, 0x7f, 0xfe, 0xff):
                    words.add(put(put(base, 64, 3, value & 7), 72, 5, value >> 3))
                for value in (0, 1, 0x55, 0xff):
                    words.add(put(base, 16, 8, value))
                mnemonic = "UPLOP3.LUT "
            else:
                for shift in (16, 24):
                    for value in (0, 5, 63, 100, 255):
                        words.add(put(base, shift, 8, value))
                if op == "FMUL":
                    for value in (0, 5, 63, 100, 255):
                        words.add(put(base, 32, 8, value))
                    bits = (72, 73, 62, 63, 122)
                    mnemonic = "FMUL "
                else:
                    for value in (0, 0x3f000000, 0x3f800000, 0x43e00000, 0xbf800000, 0x7f800000, 0xff800000):
                        words.add(put(base, 32, 32, value))
                    if op == "FMNMX":
                        for pred in (0, 2, 6, 7):
                            words.add(put(base, 87, 3, pred))
                        words.add(base ^ (1 << 90))
                    bits = (72, 73, 122)
                    mnemonic = "FADD.FTZ " if op == "FADD" else "FMNMX.FTZ "
                for bit in bits:
                    words.add(base ^ (1 << bit))
            words = sorted(words)
            measured = probe_words(args.nvdisasm, "k31_mla_tail", [(w, False) for w in words], 0,
                                   lambda _w, text, mnemonic=mnemonic: mnemonic in text, arch=arch, jobs=args.jobs)
            for rec, word in zip(measured, words):
                rec.update({"word": f"{word:032x}", "arch": arch, "op": op, "occurrences": 0,
                            "evidence": "independent full-field nvdisasm probe"})
                out.append(rec)
    write_fixture(args.out, out)
    print(len(out), "records ->", args.out)


def new_row(donor, word, opcode):
    fields = copy.deepcopy(donor["fields"])
    for f in fields:
        f["_src"] = SRC
    base = (word & ~field_mask(fields) & ~SCHEDULE & ~0xfff) | opcode
    return row(base, fields, SRC, "FlashMLA production and local SM103/SM100 full-field probes." )


def apply(tables):
    sm120 = load_table(ROOT / "isa-k31/sm120.json")["instructions"]
    records = production()
    for path in tables:
        table = load_table(path)
        ins = table["instructions"]
        ins["FADD_R_R_FI"]["mod_groups"]["FTZ"] = new_row(
            sm120["FADD_R_R_FI"]["mod_groups"]["FTZ"], int(records["FADD"][0]["word"], 16), 0x421)
        ins["FMUL_R_R_UR"]["mod_groups"][""] = new_row(
            sm120["FMUL_R_R_UR"]["mod_groups"][""], int(records["FMUL"][0]["word"], 16), 0xc20)
        ins["FMNMX_R_R_FI_P"]["mod_groups"]["FTZ"] = new_row(
            sm120["FMNMX_R_R_FI_P"]["mod_groups"]["FTZ"], int(records["FMNMX"][0]["word"], 16), 0x809)
        ins["BREAK_P_B"]["mod_groups"]["RELIABLE"] = new_row(
            sm120["BREAK_P_B"]["mod_groups"]["RELIABLE"], int(records["BREAK"][0]["word"], 16), 0x942)
        old = "UPLOP3_UP_UP_UP_UP_UP_II_II"
        new = "UPLOP3.LUT_UP_UP_UP_UP_UP_II_II"
        donor = copy.deepcopy(sm120[new])
        donor["_src"] = SRC
        donor["mod_groups"] = {"": new_row(sm120[new]["mod_groups"][""], int(records["UPLOP3"][0]["word"], 16), 0x89c)}
        assert old in ins and new not in ins
        del ins[old]
        ins[new] = donor
        table["_meta"].setdefault("key_aliases", {})[old] = new
        provenance = table["_meta"]["provenance"]
        provenance["sources"][SRC] = {"rows": 5, "kind": "production residues + local full-field probes + UPLOP3 alias retirement",
            "date": "2026-11-07", "tool": "tools/probes/re_k31_mla_tail.py", "test": "tests/k31_mla_tail.rs"}
        provenance["rows_total"] = sum(len(e.get("mod_groups", {})) for e in ins.values())
        provenance["rows_without_src"] = sum(1 for e in ins.values() for g in e.get("mod_groups", {}).values() if "_src" not in g)
        save_table(path, table)
        print(path, "five FlashMLA tail rows installed; UPLOP3 old key retired by alias")


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

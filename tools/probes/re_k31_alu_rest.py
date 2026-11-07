#!/usr/bin/env python3
"""Measured tail of FlashMLA scalar ALU and synchronisation forms."""
import argparse, copy, json, pathlib, subprocess, sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from nvprobe import field, field_mask, load_table, probe_words, row, save_table, write_fixture

SRC = "k31-alu-tail-flashmla-2026-11-07"
ROOT = pathlib.Path(__file__).resolve().parents[3]
VENDOR = ROOT.parent / "inbox-hgx02/2026-11-07-k31-prefill-gaps/vendor/fixture_flashmla_sm100.jsonl"
FIXTURE = pathlib.Path(__file__).resolve().parents[2] / "tests/fixtures/k31_alu_rest_nvdisasm.jsonl"
FORMS = {
    "FADD": (0xe21, "FADD_R_R_UR", "FTZ"),
    "FFMA": (0xc23, "FFMA_R_R_UR_R", "FTZ"),
    "FSETP": (0x80b, "FSETP_P_P_R_FI_P", "AND,EQ"),
    "ARRIVES": (0x9b0, "ARRIVES_ARURI", "64,ARVCNT,LDGSTSBAR"),
    "SYNCS": (0x9a7, "SYNCS.ARRIVE.TRANS64.RED.A0TX_R_ARURI_R", ""),
    "VIMNMX3": (0xc0f, "VIMNMX3_R_R_UR_R_P", ""),
}


def put(word, shift, bits, value):
    return (word & ~(((1 << bits) - 1) << shift)) | (value << shift)


def production():
    out = {op: [] for op in FORMS}
    with VENDOR.open() as fh:
        for line in fh:
            r = json.loads(line)
            op = next((op for op, (opcode, _, _) in FORMS.items()
                       if (int(r["word"], 16) & 0xfff) == opcode and r["text"].startswith(op)), None)
            if op is not None:
                out[op].append({"word": r["word"][2:], "nvidia_sass": r["text"], "arch": "SM100", "op": op,
                                "nvdisasm": r["nvdisasm"], "source": r["source"], "occurrences": r["occurrences"],
                                "evidence": "H production witness (not re-probed)"})
    for op, rows in out.items():
        assert rows, op
    return out


def donor_for(op, sm120):
    if op == "FSETP":
        return sm120["FSETP_P_P_R_FI_P"], "AND,EQ"
    if op == "ARRIVES":
        return sm120["ARRIVES_ARURI"], "64,ARVCNT,LDGSTSBAR"
    if op == "SYNCS":
        return sm120["SYNCS_R_ARURI_R"], "A1T0,ARRIVE,TRANS64"
    return sm120[FORMS[op][1]], "FTZ"


def probe(args):
    out = []
    for arch in ("SM103", "SM100"):
        for op, records in production().items():
            if arch == "SM100":
                out.extend(records)
            base = int(records[0]["word"], 16)
            words = {put(base, 12, 4, guard) for guard in range(16)}
            shifts = {"FSETP": (24,), "ARRIVES": (24, 40, 64)}.get(op, (16, 24, 32, 64))
            if op == "FADD":
                shifts = (16, 24, 32)
            for shift in shifts:
                for value in (0, 5, 63, 64, 255):
                    words.add(put(base, shift, 8, value))
            if op == "VIMNMX3":
                for value in range(8):
                    words.add(put(base, 87, 3, value))
                for shift in (122,):
                    words.add(put(base, shift, 1, 1))
            words = sorted(words)
            measured = probe_words(args.nvdisasm, "k31_alu_rest", [(w, False) for w in words], 0,
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
        original_ins = json.loads(subprocess.check_output(
            ["git", "-C", str(ROOT / "isa-k31"), "show", f"fa1f9f4ef68d23cfef8b352c0c08174bc7500843:{path.name}"],
            text=True))["instructions"]
        table = load_table(path)
        ins = table["instructions"]
        for op, (_, key, _) in FORMS.items():
            if op == "VIMNMX3":
                entry = copy.deepcopy(sm120["FFMA_R_R_UR_R"])
                fields = copy.deepcopy(entry["mod_groups"]["FTZ"]["fields"])
                fields = [f for f in fields if f["extraction"] not in ("neg", "abs")]
                fields.extend([field(87, 3, "pred", 5, SRC), field(90, 1, "neg", 5, SRC)])
                group_name = ""
                sig = "R_R_UR_R_P"
            else:
                donor, group_name = donor_for(op, sm120)
                if key in original_ins:
                    entry = copy.deepcopy(original_ins[key])
                else:
                    entry = copy.deepcopy(donor)
                    entry["mod_groups"] = {}
                fields = copy.deepcopy(donor["mod_groups"][group_name]["fields"])
                sig = entry["operand_sig"]
            for f in fields:
                f["_src"] = SRC
            word = int(anchors[op][0]["word"], 16)
            base = (word & ~field_mask(fields) & ~(((1 << 23) - 1) << 105) & ~0xfff) | (word & 0xfff)
            group = row(base, fields, SRC, "Exact FlashMLA production witnesses and local SM103/SM100 field probes; preserved operand and policy geometry.")
            if op == "SYNCS":
                entry["base_op"] = "SYNCS.ARRIVE.TRANS64.RED.A0TX"
                group_name = ""
            if op == "VIMNMX3":
                entry["base_op"] = "VIMNMX3"
            entry["operand_sig"] = sig
            if op in ("SYNCS", "VIMNMX3"):
                entry["mod_groups"] = {group_name: group}
            else:
                entry["mod_groups"][group_name] = group
            if key not in original_ins:
                entry["_src"] = SRC
            ins[key] = entry
        pro = table["_meta"]["provenance"]
        pro["sources"][SRC] = {"rows": 6, "kind": "measured ALU/sync donor fields + nvdisasm 13.3.73 target probes", "date": "2026-11-07",
                              "tool": "tools/probes/re_k31_alu_rest.py", "test": "tests/k31_alu_rest.rs"}
        pro["rows_total"] = sum(len(e.get("mod_groups", {})) for e in ins.values())
        pro["rows_without_src"] = sum(1 for e in ins.values() for g in e.get("mod_groups", {}).values() if "_src" not in g)
        save_table(path, table)
        print(path, "6 ALU/sync forms installed")


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

#!/usr/bin/env python3
"""Measured UIADD3.64 register and immediate forms for FlashMLA."""
import argparse, copy, json, pathlib, sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from nvprobe import field, field_mask, load_table, probe_words, row, save_table, write_fixture

SRC = "k31-uiadd64-flashmla-2026-11-07"
ROOT = pathlib.Path(__file__).resolve().parents[3]
VENDOR = ROOT.parent / "inbox-hgx02/2026-11-07-k31-prefill-gaps/vendor/fixture_flashmla_sm100.jsonl"
FIXTURE = pathlib.Path(__file__).resolve().parents[2] / "tests/fixtures/k31_uiadd64_nvdisasm.jsonl"
KINDS = {0x297: ("R", "UIADD3.64_UR_UP_UP_UR_UR_UR", 112, 247),
         0x897: ("II", "UIADD3.64_UR_UP_UP_UR_II_UR", 100, 174)}


def put(word, shift, bits, value):
    return (word & ~(((1 << bits) - 1) << shift)) | (value << shift)


def production():
    out = {op: [] for op in KINDS}
    with VENDOR.open() as fh:
        for line in fh:
            r = json.loads(line)
            if not r["text"].startswith("UIADD3.64 "):
                continue
            opcode = int(r["word"], 16) & 0xfff
            assert opcode in KINDS
            kind = KINDS[opcode][0]
            out[opcode].append({"word": r["word"][2:], "nvidia_sass": r["text"], "arch": "SM100",
                                "op": "UIADD3.64", "kind": kind, "nvdisasm": r["nvdisasm"], "source": r["source"],
                                "occurrences": r["occurrences"], "evidence": "H production witness (not re-probed)"})
    for opcode, (_, _, count, occurrences) in KINDS.items():
        assert len(out[opcode]) == count
        assert sum(r["occurrences"] for r in out[opcode]) == occurrences
    return out


def probe(args):
    rows = production()
    out = []
    for arch in ("SM103", "SM100"):
        for opcode, records in rows.items():
            if arch == "SM100":
                out.extend(records)
            base = int(records[0]["word"], 16)
            words = {put(base, 12, 4, guard) for guard in range(16)}
            for shift in (16, 24, 64) + ((32,) if opcode == 0x297 else ()):
                for value in (0, 5, 63, 64, 255):
                    words.add(put(base, shift, 8, value))
            for shift in (81, 84):
                for value in range(8):
                    words.add(put(base, shift, 3, value))
            for shift in (72, 75):
                words.add(put(base, shift, 1, 1))
            if opcode == 0x297:
                words.add(put(base, 63, 1, 1))
            else:
                for value in (0, 1, 0x400, 0xc04, 0x7fffffff, 0x80000000, 0xffffffff):
                    words.add(put(base, 32, 32, value))
            words = sorted(words)
            measured = probe_words(args.nvdisasm, "k31_uiadd64", [(w, False) for w in words], 0,
                                   lambda _w, text: "UIADD3.64" in text, arch=arch, jobs=args.jobs)
            for rec, word in zip(measured, words):
                rec.update({"word": f"{word:032x}", "arch": arch, "op": "UIADD3.64", "kind": KINDS[opcode][0],
                            "occurrences": 0, "evidence": "independent raw nvdisasm field probe"})
                out.append(rec)
    write_fixture(args.out, out)
    print(len(out), "records ->", args.out)


def apply(tables):
    donor = load_table(ROOT / "isa-k31/sm120.json")["instructions"]["UIADD3.64_UR_UP_UP_UR_UR_UR"]
    anchors = production()
    for path in tables:
        table = load_table(path)
        ins = table["instructions"]
        for opcode, (kind, key, _, _) in KINDS.items():
            entry = copy.deepcopy(donor)
            fields = copy.deepcopy(donor["mod_groups"][""]["fields"])
            if opcode == 0x897:
                fields = [f for f in fields if not (f["token_idx"] == 5 and f["shift"] in (32, 63))]
                fields.append(field(32, 32, "imm", 5, SRC))
                entry["operand_sig"] = "UR_UP_UP_UR_II_UR"
            for f in fields:
                f["_src"] = SRC
            word = int(anchors[opcode][0]["word"], 16)
            base = (word & ~field_mask(fields) & ~(((1 << 23) - 1) << 105) & ~0xfff) | opcode
            group = row(base, fields, SRC,
                        "FlashMLA production witnesses + SM103/SM100 probes: full 8-bit UR fields at 16/24/32/64, UP fields at 81/84, "
                        "guard and measured negation fields. The immediate form differs only in imm@32 and opcode 0x897.")
            entry["base_op"] = "UIADD3.64"
            entry["mod_groups"] = {"": group}
            entry["_src"] = SRC
            ins[key] = entry
        # The generic 64 group preempts the exact typed key during assembly
        # and encodes a different opcode/register geometry. Keep its 32-bit "" sibling.
        old64 = ins["UIADD3_UR_UP_UP_UR_UR_UR"]["mod_groups"].pop("64", None)
        assert old64 is not None or "UIADD3.64_UR_UP_UP_UR_UR_UR" in ins
        assert "" in ins["UIADD3_UR_UP_UP_UR_UR_UR"]["mod_groups"]
        pro = table["_meta"]["provenance"]
        pro["sources"][SRC] = {"rows": 2, "kind": "measured full-byte UIADD3.64 donor + nvdisasm 13.3.73 target field probes",
                              "date": "2026-11-07", "tool": "tools/probes/re_k31_uiadd64.py", "test": "tests/k31_uiadd64.rs"}
        pro["rows_total"] = sum(len(e.get("mod_groups", {})) for e in ins.values())
        pro["rows_without_src"] = sum(1 for e in ins.values() for g in e.get("mod_groups", {}).values() if "_src" not in g)
        save_table(path, table)
        print(path, "2 UIADD3.64 forms installed")


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

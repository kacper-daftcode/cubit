#!/usr/bin/env python3
"""K3.1 SATFINITE.BF16.F32.PACK_AB: measured donor plus local field probes."""
import argparse, copy, json, pathlib, sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from nvprobe import load_table, nvdisasm_identity, probe_words, save_table

SRC = "k31-f2fp-satfinite-bf16-pack-2026-11-07"
KEY = "F2FP.SATFINITE.BF16.F32.PACK_AB_R_R_R"
LOCAL = "F2FP_R_R_R"
VENDOR = pathlib.Path("/root/sm103a/inbox-hgx02/2026-11-07-k31-prefill-gaps/vendor/fixture_trtllm_moe_sm103a.jsonl")
FIXTURE = pathlib.Path(__file__).resolve().parents[2] / "tests/fixtures/k31_f2fp_pack_nvdisasm.jsonl"
ISA = pathlib.Path(__file__).resolve().parents[3] / "isa-k31"


def put(w, shift, bits, value):
    return (w & ~(((1 << bits) - 1) << shift)) | (value << shift)


def witnesses():
    out = []
    with VENDOR.open() as fh:
        for line in fh:
            r = json.loads(line)
            if not r["text"].startswith("F2FP.SATFINITE.BF16.F32.PACK_AB"):
                continue
            out.append({"word": r["word"][2:], "nvidia_sass": r["text"], "arch": "SM103",
                        "nvdisasm": r["nvdisasm"], "source": r["source"], "occurrences": r["occurrences"],
                        "evidence": "H production witness (not re-probed)"})
    assert len(out) == 383, len(out)
    assert sum(r["occurrences"] for r in out) == 1184
    return out


def probe(args):
    base = int(witnesses()[0]["word"], 16)
    words = [(base, False)]
    for guard in range(16):
        words.append((put(base, 12, 4, guard), False))
    for shift in (16, 24, 32):
        for value in (0, 1, 47, 100, 254, 255):
            words.append((put(base, shift, 8, value), False))
    words.append((base ^ (1 << 73), True))
    words.append((base ^ (1 << 74), True))
    out = witnesses()
    for arch in ("SM103", "SM100"):
        for row, (word, _lattice) in zip(probe_words(args.nvdisasm, "k31_f2fp_pack", words, 0,
            lambda _w, text: "F2FP.SATFINITE.BF16.F32.PACK_AB" in text, arch=arch, jobs=args.jobs), words):
            row["word"] = f"{word:032x}"
            row["evidence"] = "independent raw nvdisasm probe"
            out.append(row)
    with args.out.open("w") as fh:
        for row in out:
            fh.write(json.dumps(row) + "\n")
    print(len(out), "records ->", args.out)


def apply(src, tables):
    donor = src["instructions"][KEY]
    for path in tables:
        table = load_table(path)
        ins = table["instructions"]
        local = copy.deepcopy(ins[LOCAL])
        local["base_op"] = donor["base_op"]
        local["operand_sig"] = donor["operand_sig"]
        g = copy.deepcopy(donor["mod_groups"][""])
        g["_src"] = SRC
        g.pop("_note_wave11_canon", None)
        for f in g["fields"]:
            f["_src"] = SRC
        local["mod_groups"] = {"": g}
        local["_src"] = SRC
        ins[KEY] = local
        pro = table["_meta"]["provenance"]
        pro["sources"][SRC] = {"rows": 1, "kind": "nvdisasm 13.3.73 field probes on SM103/SM100; production witnesses and measured donor transfer",
            "date": "2026-11-07", "tool": "tools/probes/re_k31_f2fp_pack.py", "test": "tests/k31_f2fp_pack.rs"}
        pro["rows_total"] = sum(len(e.get("mod_groups", {})) for e in ins.values())
        pro["rows_without_src"] = sum(1 for e in ins.values() for g in e.get("mod_groups", {}).values() if "_src" not in g)
        save_table(path, table)
        print(path, "+", KEY)


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
        apply(load_table(ISA / "sm120.json"), args.tables)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Port measured FSETP R_R/R_FI rows to K3.1 SM103/SM100.

G measured all 96 groups per form on SM120 during T1.  Here we replace the
26+19 sm103a/sm100a harvest groups with those 96+96 measured groups, without
touching DSETP or the uniform FSETP family.  The probe covers H's exact
production modifiers and operand windows independently on SM103 and SM100.
"""
import argparse
import copy
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from nvprobe import (load_table, nvdisasm_identity, probe_words, save_table)

SRC = "k31-fsetp-trtllm-2026-11-07"
KEYS = ["FSETP_P_P_R_R_P", "FSETP_P_P_R_FI_P"]
VENDOR = pathlib.Path("/root/sm103a/inbox-hgx02/2026-11-07-k31-prefill-gaps/vendor/fixture_trtllm_moe_sm103a.jsonl")
FIXTURE = pathlib.Path(__file__).resolve().parents[2] / "tests/fixtures/k31_fsetp_nvdisasm.jsonl"
ISA = pathlib.Path(__file__).resolve().parents[3] / "isa-k31"
DONORS = {key: ["AND,FTZ,GT", "AND,FTZ,GEU"] for key in KEYS}
ALIASES = {
    "FSETP.GE.FTZ.AND_P_P_R_R_R": KEYS[0],
    "FSETP.NAN.FTZ.AND_P_P_R_R_R": KEYS[0],
    "FSETP.NE.FTZ.AND_P_P_R_R_?": KEYS[1],
    "FSETP.NEU.AND_P_P_R_R_P_?": KEYS[0],
    "FSETP.NEU.OR_P_P_R_R_P_?": KEYS[0],
    "FSETP_P_P_II_II_P": KEYS[1],
    "FSETP_P_P_II_R_P": KEYS[0],
    "FSETP_P_P_R_II_P": KEYS[1],
}


def put(w, shift, bits, value):
    return (w & ~(((1 << bits) - 1) << shift)) | (value << shift)


def witnesses():
    out = []
    with VENDOR.open() as fh:
        for line in fh:
            r = json.loads(line)
            if not r["text"].startswith("FSETP"):
                continue
            out.append({"word": r["word"][2:], "nvidia_sass": r["text"], "arch": "SM103",
                        "nvdisasm": r["nvdisasm"], "source": r["source"], "cubit_error": r["cubit_error"],
                        "occurrences": r["occurrences"], "evidence": "H production witness (not re-probed)"})
    assert len(out) == 2331, len(out)
    assert sum(r["occurrences"] for r in out) == 4736
    assert len({r["word"] for r in out}) == len(out)
    return out


def bases():
    rr = next(int(r["word"], 16) for r in witnesses() if int(r["word"], 16) & 0xfff == 0x20b)
    fi = next(int(r["word"], 16) for r in witnesses() if int(r["word"], 16) & 0xfff == 0x80b)
    return rr, fi


def probe_words_local():
    rr, fi = bases()
    words = [(rr, False), (fi, False)]
    for base in (rr, fi):
        for guard in range(16):
            words.append((put(base, 12, 4, guard), False))
        for shift in (24, 81, 84, 87):
            for value in (0, 1, 6, 7):
                words.append((put(base, shift, 8 if shift == 24 else 3, value), False))
        for bit in (72, 73, 90, 122) + ((62, 63, 123) if base == rr else ()):
            words.append((base ^ (1 << bit), False))
        for value in (0, 0x3f800000, 0xbf800000, 0x7f800000, 0x7fc00001, 0xffffffff):
            if base == fi:
                words.append((put(base, 32, 32, value), False))
            else:
                words.append((put(base, 32, 8, value & 0xff), False))
    return list(dict.fromkeys(words))


def probe(args):
    words = probe_words_local()
    out = witnesses()
    for arch in ("SM103", "SM100"):
        rows = probe_words(args.nvdisasm, "k31_fsetp", words, 0,
            lambda _w, text: text.startswith(("FSETP.GT.FTZ.AND", "FSETP.GEU.FTZ.AND", "@")),
            arch=arch, jobs=args.jobs)
        for row, (word, _) in zip(rows, words):
            row["evidence"] = "independent raw nvdisasm probe"
            row["word"] = f"{word:032x}"
        out.extend(rows)
    with args.out.open("w") as fh:
        for row in out:
            fh.write(json.dumps(row) + "\n")
    print(f"{len(out)} FSETP witness/probe records -> {args.out}")


def apply(src, tables):
    donors = {}
    for p in tables:
        t = load_table(p)
        ins = t["instructions"]
        for key in KEYS:
            meta = copy.deepcopy(ins[key])
            if key not in donors:
                donors[key] = copy.deepcopy(src["instructions"][key])
            donor = donors[key]
            assert len(donor["mod_groups"]) == 96 and donor["_src"] == "fsetp-dsetp-family-2026-11-06"
            groups = copy.deepcopy(donor["mod_groups"])
            for g in groups.values():
                g["_src"] = SRC
                for f in g["fields"]:
                    for tag in list(f):
                        if tag.startswith("_src"):
                            del f[tag]
                    f["_src"] = SRC
            meta["base_op"] = "FSETP"
            meta["operand_sig"] = "P_P_R_R_P" if key == KEYS[0] else "P_P_R_FI_P"
            meta["mod_groups"] = groups
            meta["_src"] = SRC
            ins[key] = meta
        t["_meta"].setdefault("key_aliases", {}).update(ALIASES)
        prov = t["_meta"]["provenance"]
        prov["sources"][SRC] = {"rows": 192, "kind": "nvdisasm 13.3.73 probes (SM103/SM100) plus measured SM120 family row transfer",
            "date": "2026-11-07", "tool": "tools/probes/re_k31_fsetp.py", "test": "tests/k31_fsetp.rs"}
        prov["rows_total"] = sum(len(e.get("mod_groups", {})) for e in ins.values())
        prov["rows_without_src"] = sum(1 for e in ins.values() for g in e.get("mod_groups", {}).values() if "_src" not in g)
        save_table(p, t)
        print(p, "FSETP 26+19 harvest groups -> 96+96 measured groups; aliases", len(ALIASES))


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
        src = load_table(ISA / "sm120.json")
        apply(src, args.tables)


if __name__ == "__main__":
    main()

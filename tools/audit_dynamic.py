#!/usr/bin/env python3
"""Dynamic table audit: canonical words of selected rows vs nvdisasm vs cubit's decode + re-encode.

For every selected (key, mod_group) row the script builds the row's canonical word (and_base with
each field at a neutral value) and a bounded set of variants (one field at a time at a few boundary
values: registers 0/255, uniform registers 0/63/255, immediates 0/1/sign/max, predicates 0/7, the
guard at 7 and 0). nvdisasm 13.1 renders every word (one call per word, the row's control code
or-ed in); `examples/audit_words.rs` decodes, prints and re-encodes the same words in one cubit
process. Each word is then classified:

  ok                    nvdisasm and cubit print the same text and the text re-encodes bit-exact
  text_mismatch         both name the word but differently (modulo spacing / `.reuse`)
  reencode_mismatch     same text, but cubit's re-encode of its own text differs from the word
  decode_miss           nvdisasm names the word, cubit decodes nothing (the row cannot own its
                        own canonical word -> wrong fields / mask)
  cubit_decodes_illegal nvdisasm rejects the word, cubit decodes it (the row claims an illegal word)
  both_reject           nvdisasm rejects and cubit decodes nothing (fine: an illegal variant)
  other_row             cubit decodes the word through a different row than the one it was built
                        from (recorded, not a defect by itself)
  reuse_inert           same text, re-encode differs only in control-code / reuse bits [127:105]
                        (text-inert for both oracles; not a row defect)
  --replay words_in.jsonl re-runs cubit and the classification on an earlier run's words and
  nvdisasm texts (words of rows that left the table are skipped).

Selection: `--flagged findings.jsonl` (rows named by tools/audit_table.py) and/or `--family REGEX`
(base opcode families). Output: `<out>/words.jsonl` (all words with both texts and classes),
`<out>/dynamic_findings.jsonl` (non-ok words), a per-row summary on stdout.

    tools/audit_dynamic.py --table tables/sm120.json --cubit-example target/release/examples/audit_words \\
        --nvdisasm /path/to/nvdisasm --flagged T/audit/static_findings.jsonl \\
        --family 'QMMA|HMMA|LDSM|STSM|LDS|STS|LDG|STG|LDGSTS' --max-rows 4000 --jobs 16 --out T/audit/dyn
"""
from __future__ import annotations

import argparse
import collections
import concurrent.futures
import json
import pathlib
import re
import subprocess
import tempfile

SCHEDULE_MASK = ((1 << 23) - 1) << 105
DEFAULT_CTRL = 0x000fe200 << 96  # stall 1, yield, no barriers - legal for every class
TEXT_RE = re.compile(r"/\*0000\*/\s*(.*?)\s*;")


def field_mask(f):
    return ((1 << f["bits"]) - 1) << f["shift"]


def neutral_value(f, token):
    e = f["extraction"]
    if e == "guard":
        return 7
    if e in ("reg", "sub_r0", "sub_r1", "sub_r2"):
        return (2 * token + 2) % 254 + (1 if e != "reg" else 0)
    if e in ("ureg", "sub_ur0", "sub_ur1"):
        return (token + 4) % 63
    if e.startswith("imm") or e.startswith("sub_imm") or e in ("f16", "bf16", "f32"):
        return 0x10 if f["bits"] > 5 else 1
    if e in ("pred", "upred"):
        return 7
    return 0  # modifier-like fields: keep the group's own constant


def variants(f, token):
    e = f["extraction"]
    full = (1 << f["bits"]) - 1
    if e == "guard":
        return [0, 15]
    if e in ("reg", "sub_r0", "sub_r1", "sub_r2"):
        return [0, min(255, full)]
    if e in ("ureg", "sub_ur0", "sub_ur1"):
        return [0, min(63, full), min(255, full)]
    if e.startswith("imm") or e.startswith("sub_imm") or e in ("f16", "bf16", "f32"):
        return sorted({0, 1, 1 << (f["bits"] - 1), full})
    if e in ("pred", "upred"):
        return [0, 6]
    if e in ("neg", "abs", "reuse", "inv") or f["bits"] == 1:
        return [1]
    return [full]


def words_for_row(key, group, row):
    fields = row.get("fields", [])
    base = int(row["and_base"], 16) & ~SCHEDULE_MASK
    for f in fields:
        base &= ~field_mask(f)
    canonical = base
    for f in fields:
        canonical |= (neutral_value(f, f["token_idx"]) & ((1 << f["bits"]) - 1)) << f["shift"]
    out = [("canonical", canonical)]
    for i, f in enumerate(fields):
        for v in variants(f, f["token_idx"]):
            w = (canonical & ~field_mask(f)) | ((v & ((1 << f["bits"]) - 1)) << f["shift"])
            if w != canonical:
                out.append((f"{f['extraction']}@{f['shift']}={v}", w))
    seen = set()
    uniq = []
    for label, w in out:
        if w not in seen:
            seen.add(w)
            uniq.append((label, w))
    return uniq[:16]


def nvdisasm_one(nvdisasm, word, ctrl, scratch_dir):
    path = pathlib.Path(scratch_dir) / f"{word:032x}.bin"
    path.write_bytes((word | ctrl).to_bytes(16, "little"))
    r = subprocess.run([nvdisasm, "-b", "SM120", "-hex", str(path)], capture_output=True, text=True)
    path.unlink(missing_ok=True)
    if r.returncode:
        return None
    m = TEXT_RE.search(r.stdout)
    return m.group(1).strip() if m else None


def normalise(text):
    return re.sub(r"\s+", " ", text.replace(".reuse", "")).strip().rstrip(";").strip()


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--table", default="tables/sm120.json")
    ap.add_argument("--cubit-example", default="target/release/examples/audit_words")
    ap.add_argument("--nvdisasm", required=True)
    ap.add_argument("--flagged", type=pathlib.Path, help="static_findings.jsonl: audit the rows it names")
    ap.add_argument("--family", help="regex over the key's base opcode (first key token before '_')")
    ap.add_argument("--max-rows", type=int, default=4000)
    ap.add_argument("--jobs", type=int, default=8)
    ap.add_argument("--out", type=pathlib.Path, required=True)
    ap.add_argument("--replay", type=pathlib.Path,
                    help="words_in.jsonl of an earlier run: reuse its words and nvdisasm texts, only re-run cubit "
                         "and the classification (the state of the current table / binary against the same oracle)")
    args = ap.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    table = json.load(open(args.table))
    ins = table["instructions"]
    if args.replay:
        words_in = args.out / "words_in.jsonl"
        kept, dropped = [], 0
        for line in args.replay.read_text().splitlines():
            it = json.loads(line)
            if it["key"] in ins and it["group"] in ins[it["key"]]["mod_groups"]:
                kept.append(line)
            else:
                dropped += 1  # the row no longer exists: its probe words are not a finding against it
        print(f"replaying {len(kept)} words ({dropped} of rows that left the table skipped)")
        words_in.write_text("".join(l + "\n" for l in kept))
        words_out = args.out / "words.jsonl"
        subprocess.run([args.cubit_example, str(words_in), args.table, str(words_out)], check=True)
        classify(args, words_out)
        return
    selected = collections.OrderedDict()
    if args.flagged:
        for line in open(args.flagged):
            f = json.loads(line)
            if f["check"] in ("count_null", "overlapping_claims"):
                continue
            k, g = f.get("key"), f.get("group")
            if k in ins and g in ins[k]["mod_groups"]:
                selected[(k, g)] = "flagged:" + f["check"]
    if args.family:
        fam = re.compile(args.family)
        for k, e in ins.items():
            base = k.split("_")[0].split(".")[0]
            if fam.fullmatch(base):
                for g in e["mod_groups"]:
                    selected.setdefault((k, g), "family")
    rows = list(selected.items())[: args.max_rows]
    print(f"{len(rows)} rows selected ({sum(1 for _, why in rows if why.startswith('flagged'))} flagged)")
    words = []
    for (k, g), why in rows:
        row = ins[k]["mod_groups"][g]
        if not row.get("fields"):
            continue
        for label, w in words_for_row(k, g, row):
            words.append({"word": f"{w:032x}", "key": k, "group": g, "why": why, "label": label})
    print(f"{len(words)} probe words")
    scratch = tempfile.mkdtemp(prefix="audit_dyn_")
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as ex:
        texts = list(ex.map(lambda it: nvdisasm_one(args.nvdisasm, int(it["word"], 16), DEFAULT_CTRL, scratch), words))
    for it, t in zip(words, texts):
        it["nvidia_sass"] = t
        it["word"] = f"{int(it['word'], 16) | DEFAULT_CTRL:032x}"
    words_in = args.out / "words_in.jsonl"
    words_in.write_text("".join(json.dumps(it) + "\n" for it in words))
    words_out = args.out / "words.jsonl"
    subprocess.run([args.cubit_example, str(words_in), args.table, str(words_out)], check=True)
    classify(args, words_out)


def classify(args, words_out):
    classes = collections.Counter()
    per_row = collections.defaultdict(collections.Counter)
    findings = []
    for line in open(words_out):
        it = json.loads(line)
        nv, ct = it.get("nvidia_sass"), it.get("cubit_text")
        if nv is None and ct is None:
            cls = "both_reject"
        elif nv is None:
            cls = "cubit_decodes_illegal"
        elif ct is None:
            cls = "decode_miss"
        elif normalise(nv) != normalise(ct):
            cls = "text_mismatch"
        elif it.get("reencode") != "ok":
            cls = "reencode_mismatch"
            re = it["reencode"]
            if re.startswith("mismatch:") and (int(re[9:], 16) ^ int(it["word"], 16)) & ~SCHEDULE_MASK == 0:
                # only control-code / reuse bits differ: both oracles print the same text for
                # them (the decoder matches [104:0]; the strict round trip carries them in the
                # control code or an `!rsd` overlay) - a text-inert bit, not a row defect
                cls = "reuse_inert"
        else:
            cls = "ok"
        if cls == "ok" and (it.get("cubit_key"), it.get("cubit_group")) != (it["key"], it["group"]):
            cls = "other_row"
        it["class"] = cls
        classes[cls] += 1
        per_row[(it["key"], it["group"])][cls] += 1
        if cls not in ("ok", "both_reject", "other_row", "reuse_inert"):
            findings.append(it)
    (args.out / "dynamic_findings.jsonl").write_text("".join(json.dumps(f) + "\n" for f in findings))
    print("classes:", dict(classes))
    bad_rows = {r: c for r, c in per_row.items() if any(k in c for k in ("text_mismatch", "decode_miss", "cubit_decodes_illegal", "reencode_mismatch"))}
    print(f"{len(bad_rows)} of {len(per_row)} rows with at least one non-ok word")
    by_key = collections.Counter()
    for (k, g), c in bad_rows.items():
        by_key[k.split("_")[0]] += 1
    for k, n in by_key.most_common(30):
        print(f"  {n:5d} rows  {k}")
    summary = {"rows": len(per_row), "bad_rows": len(bad_rows), "classes": dict(classes),
               "bad_rows_by_base": dict(by_key)}
    (args.out / "summary.json").write_text(json.dumps(summary, indent=1) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

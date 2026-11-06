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
  vendor_unknown        nvdisasm has no text for the word and the row that decodes it is a measured
                        undocumented form (its `_src` provenance entry carries `nvdisasm_sm120:
                        "no text"`: E3M4 block-scaled MMA, the tcgen05 kinds the SM120 silicon runs,
                        FFMA2) - "nvdisasm does not know the word", never a defect (owner 2026-11-03)
  both_reject           nvdisasm rejects and cubit decodes nothing (fine: an illegal variant)
  other_row             cubit decodes the word through a different row than the one it was built
                        from (recorded, not a defect by itself)
  reuse_inert           same text, re-encode differs only in control-code / reuse bits [127:105]
                        (text-inert for both oracles; not a row defect)
  reuse_rejected        nvdisasm rejects the word because a reuse bit [124:122] sits on a slot that
                        holds no register; with the reuse bits cleared nvdisasm names the word with
                        the text cubit prints for it. The BUG-362a / KNOWN_ISSUES A12 class: on silicon
                        the bit is inert (F2I measured 2026-11-03), nvdisasm is a text oracle only
                        (owner 2026-11-03) -- not a row defect. Measured per word (one nvdisasm call
                        on the stripped word; the verdicts are kept in words.jsonl as `nvidia_sass_noreuse`).
  inert_failclosed      nvdisasm names the word, cubit decodes nothing for it, and cubit ASSEMBLES the
                        vendor's text to a different word that nvdisasm names with the same text
                        (`vendor_encode` from examples/audit_words.rs, one nvdisasm call on the
                        assembled word, kept as `nvidia_sass_of_vendor_encode`). The bits in which the
                        two words differ are text-inert for the vendor; the measured rows fail closed
                        on them -- the convention of every measured family (LEA, SHF, BRA, ...;
                        KNOWN_ISSUES T1), not a defect.
  inert_bits            both texts agree; cubit's re-encode of the text differs from the probe word in
                        bits below the control code that nvdisasm's text does not express -- measured:
                        nvdisasm names the re-encoded word with the same text (one call, kept as
                        `nvidia_sass_of_reencode`). The probe word carries text-inert bits the row
                        tolerates on decode and the canonical encoding does not reproduce (the
                        harvest's junk byte of `WARPSYNC.ALL`, bit 34 of `UBMSK.W`, ...) -- not a defect
                        (no census word carries them: the strict census is 100 %).
  nan_glyph             both texts agree and carry the vendor's `+/-QNAN` / `SNAN` glyph, which drops
                        the NaN payload; the glyph is not re-encodable by design (KNOWN_ISSUES A8: the
                        parser parks QNAN -- bimodal payload lanes; the owner's 2026-11-04 print
                        policy keeps it) -- documented, not counted
  vendor_invalid        nvdisasm's text carries an `INVALIDn` / `???n` glyph: the vendor marks the
                        encoding invalid (an undefined enum value). cubit decoding NOTHING for it is
                        the fail-closed answer (counted here, not a defect); cubit printing the SAME
                        text (the harvest keys that carry the glyph in their mnemonic, e.g.
                        `QMMA.SP.INVALID0.F16.E2M3.E2M3`) is `ok` -- a faithful rendering of what the
                        vendor prints; cubit printing a valid-looking text for it stays
                        `cubit_decodes_illegal` (the row claims an invalid word).
  silicon_illegal       both texts agree; cubit refuses to assemble the text because a silicon-measured
                        law forbids the word (BUG-037: a multi-register MMA operand off its alignment is
                        ILLEGAL_INSTRUCTION on the RTX 5090 -- the encoder's documented refusal, which
                        nvdisasm's text-only view does not make); counted, not a defect
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
import itertools
import tempfile
import threading
import sys as _sys, pathlib as _pathlib
_sys.path.insert(0, str(_pathlib.Path(__file__).resolve().parent))
from tablefile import load_table  # plain tables/<arch>.json or the vendored .json.gz

SCHEDULE_MASK = ((1 << 23) - 1) << 105
_SCRATCH_SEQ = itertools.count()
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
    # One scratch file per CALL (2026-11-06): the same word is probed once per row that generates it,
    # and two threads sharing `<word>.bin` raced (one unlinked the file the other was about to pass to
    # nvdisasm) -- the 2026-11-04 run recorded 386 legal words as "rejected" that way (the records were
    # corrected by re-measurement, `T/audit/dyn/words_in_fixed.jsonl`). A failure that is not nvdisasm's
    # own "Illegal instruction" verdict is an error, never a verdict.
    path = pathlib.Path(scratch_dir) / f"{word:032x}-{threading.get_ident()}-{next(_SCRATCH_SEQ)}.bin"
    path.write_bytes((word | ctrl).to_bytes(16, "little"))
    r = subprocess.run([nvdisasm, "-b", "SM120", "-hex", str(path)], capture_output=True, text=True)
    path.unlink(missing_ok=True)
    if r.returncode:
        if "Illegal instruction" not in r.stderr and "Invalid instruction" not in r.stderr and "undefined value" not in r.stderr:
            raise RuntimeError(f"nvdisasm failed on {word:032x}: {r.stderr.strip()[:200]}")
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
    table = load_table(args.table)
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
        classify(args, words_out, table)
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
    classify(args, words_out, table)


def vendor_unknown_rows(table):
    """Rows whose provenance says nvdisasm has no text for their words on SM120 (undocumented forms
    measured on silicon): (key, group) pairs."""
    sources = table.get("_meta", {}).get("provenance", {}).get("sources", {})
    tags = {t for t, e in sources.items() if isinstance(e, dict) and e.get("nvdisasm_sm120") == "no text"}
    rows = set()
    for k, e in table["instructions"].items():
        for g, v in e.get("mod_groups", {}).items():
            if v.get("_src") in tags:
                rows.add((k, g))
    return rows


REUSE_MASK = 7 << 122


def vendor_invalid_text(text):
    return text is not None and ("INVALID" in text or "???" in text)


def classify(args, words_out, table):
    classes = collections.Counter()
    per_row = collections.defaultdict(collections.Counter)
    findings = []
    unknown_rows = vendor_unknown_rows(table)
    items = [json.loads(line) for line in open(words_out)]
    # `reuse_rejected`: nvdisasm's verdict on the reuse-stripped word, measured once and kept;
    # `inert_failclosed`: nvdisasm's verdict on cubit's assembly of the vendor text, likewise
    scratch = None
    for it in items:
        nv, ct = it.get("nvidia_sass"), it.get("cubit_text")
        if nv is None and ct is not None and (int(it["word"], 16) & REUSE_MASK) and "nvidia_sass_noreuse" not in it:
            if scratch is None:
                scratch = tempfile.mkdtemp(prefix="audit_dyn_noreuse_")
            stripped = int(it["word"], 16) & ~REUSE_MASK
            it["nvidia_sass_noreuse"] = nvdisasm_one(args.nvdisasm, stripped & ~SCHEDULE_MASK, stripped & SCHEDULE_MASK, scratch)
        re_ = it.get("reencode", "")
        if nv is not None and ct is not None and normalise(nv) == normalise(ct) and re_.startswith("mismatch:") \
                and "nvidia_sass_of_reencode" not in it:
            w2 = int(re_[9:], 16)
            if (w2 ^ int(it["word"], 16)) & ~SCHEDULE_MASK:
                if scratch is None:
                    scratch = tempfile.mkdtemp(prefix="audit_dyn_noreuse_")
                it["nvidia_sass_of_reencode"] = nvdisasm_one(args.nvdisasm, w2 & ~SCHEDULE_MASK, w2 & SCHEDULE_MASK, scratch)
        ve = it.get("vendor_encode")
        if nv is not None and ct is None and ve and not ve.startswith("error") and "nvidia_sass_of_vendor_encode" not in it:
            if scratch is None:
                scratch = tempfile.mkdtemp(prefix="audit_dyn_noreuse_")
            w2 = int(ve, 16)
            if w2 == int(it["word"], 16):
                it["nvidia_sass_of_vendor_encode"] = nv  # same word: not a miss of inert bits (kept as decode_miss below)
            else:
                it["nvidia_sass_of_vendor_encode"] = nvdisasm_one(args.nvdisasm, w2 & ~SCHEDULE_MASK, w2 & SCHEDULE_MASK, scratch)
    for it in items:
        nv, ct = it.get("nvidia_sass"), it.get("cubit_text")
        if nv is None and ct is None:
            cls = "both_reject"
        elif nv is None:
            decoded_by = (it.get("cubit_key"), it.get("cubit_group"))
            stripped_text = it.get("nvidia_sass_noreuse")
            if decoded_by in unknown_rows:
                cls = "vendor_unknown"
            elif stripped_text is not None and normalise(stripped_text) == normalise(ct):
                cls = "reuse_rejected"
            else:
                cls = "cubit_decodes_illegal"
        elif ct is None:
            ve = it.get("vendor_encode", "")
            ve_text = it.get("nvidia_sass_of_vendor_encode")
            if vendor_invalid_text(nv):
                cls = "vendor_invalid"
            elif ve and not ve.startswith("error") and int(ve, 16) != int(it["word"], 16) \
                    and ve_text is not None and normalise(ve_text) == normalise(nv):
                cls = "inert_failclosed"
            else:
                cls = "decode_miss"
        elif vendor_invalid_text(nv) and normalise(nv) != normalise(ct):
            cls = "cubit_decodes_illegal"  # a valid-looking text for a word the vendor marks invalid
        elif normalise(nv) != normalise(ct):
            cls = "text_mismatch"
        elif it.get("reencode") != "ok" and ("QNAN" in nv or "SNAN" in nv):
            # the texts agree and carry the vendor's NaN glyph, which drops the payload: the owner's
            # print policy (2026-11-04, KNOWN_ISSUES A8) keeps the glyph on these lanes; the glyph is
            # not re-encodable by design (the parser parks QNAN: bimodal payload lanes) -- documented,
            # not counted
            cls = "nan_glyph"
        elif it.get("reencode") != "ok":
            cls = "reencode_mismatch"
            re = it["reencode"]
            if re.startswith("mismatch:") and (int(re[9:], 16) ^ int(it["word"], 16)) & ~SCHEDULE_MASK == 0:
                # only control-code / reuse bits differ: both oracles print the same text for
                # them (the decoder matches [104:0]; the strict round trip carries them in the
                # control code or an `!rsd` overlay) - a text-inert bit, not a row defect
                cls = "reuse_inert"
            elif re.startswith("mismatch:") and it.get("nvidia_sass_of_reencode") is not None \
                    and normalise(it["nvidia_sass_of_reencode"]) == normalise(nv):
                cls = "inert_bits"
            elif re.startswith("error:") and "ILLEGAL on silicon" in re:
                # the texts agree; cubit refuses to assemble the text because a silicon-measured
                # law forbids the word (BUG-037: a multi-register MMA operand off its alignment --
                # ILLEGAL_INSTRUCTION on the RTX 5090, tests/bug037_mma_align.rs); nvdisasm prints
                # the text without that check. The refusal is the encoder's documented behaviour,
                # not a row defect -- counted, named, never a finding
                cls = "silicon_illegal"
        else:
            cls = "ok"
        if cls == "ok" and (it.get("cubit_key"), it.get("cubit_group")) != (it["key"], it["group"]):
            cls = "other_row"
        it["class"] = cls
        classes[cls] += 1
        per_row[(it["key"], it["group"])][cls] += 1
        if cls not in ("ok", "both_reject", "other_row", "reuse_inert", "vendor_unknown", "reuse_rejected", "inert_failclosed", "vendor_invalid", "nan_glyph", "inert_bits", "silicon_illegal"):
            findings.append(it)
    words_out.write_text("".join(json.dumps(it) + "\n" for it in items))
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

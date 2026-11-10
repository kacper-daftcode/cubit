#!/usr/bin/env python3
"""Measured SM103/SM100 HMNMX2 register and two-f16-immediate families."""

import argparse
import concurrent.futures
import copy
import hashlib
import json
import pathlib
import re
import subprocess
import threading


H_ROOT = pathlib.Path(
    "/root/sm103a/inbox-hgx02/2026-11-07-k31-prefill-gaps/survey/fixtures"
)
TEXT = re.compile(r"/\*0000\*/\s*(.*?)\s*(?:;|$)", re.MULTILINE)
CTRL = 0x000FE200 << 96
SRC = "hidden-b300-hmnmx2-2026-11-08"
REG_KEY = "HMNMX2_R_R_R_P"
IMM_KEY = "HMNMX2_R_R_FI_FI_P"
MOD_BITS = {"FTZ": 80, "NAN": 81, "XORSIGN": 82, "BF16_V2": 85}
MOD_NAMES = tuple(MOD_BITS)
REG_BASE = 0x240 | (7 << 12) | (8 << 16) | (18 << 24) | (19 << 32) | (7 << 87)
IMM_BASE = (
    0x840 | (7 << 12) | (8 << 16) | (18 << 24)
    | (0x3C00 << 32) | (0x4000 << 48) | (7 << 87)
)


def put(word, shift, bits, value):
    return (word & ~(((1 << bits) - 1) << shift)) | (value << shift)


def modifiers(word, names):
    for name in names:
        word |= 1 << MOD_BITS[name]
    return word


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def production():
    anchors = []
    malformed = []
    seen = set()
    for path in sorted(H_ROOT.glob("*.jsonl")):
        for line_number, line in enumerate(path.read_text().splitlines(), 1):
            if not line.strip():
                continue
            record = json.loads(line)
            text = record.get("text", "")
            raw = record.get("word", "")
            if not text.startswith("HMNMX2"):
                continue
            if not (raw.startswith("0x") and len(raw) == 34):
                malformed.append({"source": f"{path}:{line_number}", "word": raw, "text": text})
                continue
            word = int(raw, 16)
            if word & 0xFFF not in (0x240, 0x840):
                continue
            if word in seen:
                continue
            seen.add(word)
            anchors.append({
                "word": word,
                "source": f"{path}:{line_number}",
                "nvidia_sass": text,
                "target": record.get("target"),
                "cubin": record.get("source"),
                "occurrences": record.get("occurrences"),
            })
    return anchors, malformed


def sweep():
    cases = {}

    def add(word, kind, label, production_word=False):
        # Controlled reuse bits also live in the upper word, so a nonzero upper
        # word cannot identify a production record. Only H inputs preserve their
        # schedule; every controlled case gets the complete control word.
        if not production_word:
            word |= CTRL
        entry = cases.setdefault(word, {"word": word, "kind": kind, "labels": []})
        if label not in entry["labels"]:
            entry["labels"].append(label)

    anchors, malformed = production()
    for index, anchor in enumerate(anchors):
        add(anchor["word"], "H-production", f"H:{index}", production_word=True)

    bases = {"reg": REG_BASE, "imm": IMM_BASE}
    for form, base in bases.items():
        add(base, "anchor", f"{form}:plain-base")
        loaded = modifiers(base, MOD_NAMES)
        add(loaded, "anchor", f"{form}:loaded-base")
        for bit in range(105):
            add(base ^ (1 << bit), "single-bit", f"{form}:plain:bit-{bit}")
            add(loaded ^ (1 << bit), "single-bit-loaded", f"{form}:loaded:bit-{bit}")

        for mod_mask in range(16):
            names = [name for i, name in enumerate(MOD_NAMES) if mod_mask & (1 << i)]
            mod_base = modifiers(base, names)
            add(mod_base, "modifiers", f"{form}:mods-{mod_mask}")
            ra_range = range(4)
            rb_range = range(4) if form == "reg" else range(1)
            for ra_sel in ra_range:
                for rb_sel in rb_range:
                    word = put(mod_base, 74, 2, ra_sel)
                    if form == "reg":
                        word = put(word, 60, 2, rb_sel)
                    add(word, "hsel-cross", f"{form}:mods-{mod_mask}:ra-{ra_sel}:rb-{rb_sel}")
            for sign_mask in range(16 if form == "reg" else 4):
                word = mod_base | ((sign_mask & 3) << 72)
                if form == "reg":
                    word |= ((sign_mask >> 2) & 3) << 62
                add(word, "sign-cross", f"{form}:mods-{mod_mask}:signs-{sign_mask}")
            for reuse in range(8):
                word = mod_base
                for offset, bit in enumerate((122, 123, 124)):
                    word |= ((reuse >> offset) & 1) << bit
                add(word, "reuse", f"{form}:mods-{mod_mask}:reuse-{reuse}")

        competition_bits = (60, 61, 62, 63, 64, 65, 72, 73, 74, 75, 76, 77,
                            78, 79, 83, 84, 86, 87, 88, 89, 90, 91, 92, 95)
        for bit in competition_bits:
            for mod_bit in MOD_BITS.values():
                add(base ^ (1 << bit) ^ (1 << mod_bit), "competition",
                    f"{form}:bits-{bit}+{mod_bit}")

        for guard in range(16):
            add(put(base, 12, 4, guard), "guard", f"{form}:guard-{guard}")
        for token, shift in (("Rd", 16), ("Ra", 24)):
            for value in (0, 1, 63, 127, 128, 254, 255):
                add(put(base, shift, 8, value), "register", f"{form}:{token}-{value}")
        if form == "reg":
            for value in (0, 1, 63, 127, 128, 254, 255):
                add(put(base, 32, 8, value), "register", f"reg:Rb-{value}")
        for pred in range(16):
            word = put(base, 87, 3, pred & 7)
            word = put(word, 90, 1, (pred >> 3) & 1)
            add(word, "predicate", f"{form}:pred-{pred}")

        add(base & ~0xFFF, "wrong-opcode", f"{form}:wrong-opcode-zero")
        add(base ^ (1 << 10), "form-neighbour", f"{form}:bit10")
        add(base ^ (1 << 11), "form-neighbour", f"{form}:bit11")

    immediate_values = (
        0x0000, 0x0001, 0x0002, 0x03FF, 0x0400, 0x07FF, 0x0800, 0x3C00,
        0x4000, 0x7BFF, 0x7C00, 0x7C01, 0x7E00, 0x8000, 0xC3E0, 0xFBFF,
    )
    for low in immediate_values:
        for high in immediate_values:
            word = put(IMM_BASE, 32, 16, low)
            word = put(word, 48, 16, high)
            add(word, "immediate-cross", f"imm:{low:04x}:{high:04x}")
    for mod_mask in range(16):
        names = [name for i, name in enumerate(MOD_NAMES) if mod_mask & (1 << i)]
        for low, high in ((0x3C00, 0x4000), (0x0000, 0x8000), (0x7BFF, 0xC3E0),
                          (0x7C00, 0x7E00), (0x0001, 0x03FF), (0xFBFF, 0x7BFF)):
            word = modifiers(put(put(IMM_BASE, 32, 16, low), 48, 16, high), names)
            add(word, "immediate-modifiers", f"imm:mods-{mod_mask}:{low:04x}:{high:04x}")

    return list(cases.values()), anchors, malformed


def probe(args):
    args.out.mkdir(parents=True, exist_ok=True)
    version = subprocess.check_output([args.nvdisasm, "--version"], text=True)
    digest = sha256(pathlib.Path(args.nvdisasm))
    cases, anchors, malformed = sweep()
    local = threading.local()

    def measure(job):
        target, case = job
        if not hasattr(local, "scratch"):
            local.scratch = args.out / f".word-{target}-{threading.get_ident()}.bin"
        word = case["word"]
        local.scratch.write_bytes(word.to_bytes(16, "little"))
        command = [args.nvdisasm, "-b", target, "-hex", str(local.scratch)]
        proc = subprocess.run(command, capture_output=True, text=True)
        match = TEXT.search(proc.stdout)
        return {"target": target, "word": f"{word:032x}", "kind": case["kind"],
                "labels": case["labels"], "command": command, "rc": proc.returncode,
                "stdout": proc.stdout, "stderr": proc.stderr,
                "nvidia_sass": match.group(1).strip() if match else None,
                "nvdisasm": version, "nvdisasm_sha256": digest}

    summary = {
        "scope": "HMNMX2 R,R,R,P and R,R,f16,f16,P plus bounded neighbours",
        "sources": [{"path": str(path), "sha256": sha256(path)} for path in sorted(H_ROOT.glob("*.jsonl"))],
        "nvdisasm": version, "nvdisasm_sha256": digest,
        "control_hex": f"{CTRL:032x}", "unique_words_including_schedule": len(cases),
        "h_anchor_count": len(anchors), "malformed_hmnmx2_records": malformed,
        "h_anchors": [{**a, "word": f"{a['word']:032x}"} for a in anchors],
        "targets": {},
    }
    by_target = {}
    for target in ("SM103", "SM100"):
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
            rows = list(pool.map(measure, ((target, case) for case in cases)))
        by_target[target] = rows
        for start in range(0, len(rows), 256):
            with (args.out / f"{target.lower()}-{start // 256:03d}.jsonl").open("w") as stream:
                for row in rows[start:start + 256]:
                    stream.write(json.dumps(row, sort_keys=True) + "\n")
        summary["targets"][target] = {
            "records": len(rows), "accepted": sum(row["rc"] == 0 for row in rows),
            "rejected": sum(row["rc"] != 0 for row in rows),
            "accepted_unnamed": sum(row["rc"] == 0 and not row["nvidia_sass"] for row in rows),
        }
    summary["cross_target_same_word_rc_text"] = sum(
        a["word"] == b["word"] and a["rc"] == b["rc"] and a["nvidia_sass"] == b["nvidia_sass"]
        for a, b in zip(by_target["SM103"], by_target["SM100"])
    )
    (args.out / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    print(json.dumps({k: v for k, v in summary.items() if k not in ("h_anchors", "sources")}, indent=2))


def raw_rows(raw):
    return [json.loads(line) for path in sorted(raw.glob("sm103-*.jsonl")) for line in path.open()]


def text_shape(text):
    """Return the measured operand frame, never accepting an INVALID glyph."""
    if not text or "INVALID" in text or "???" in text:
        return None
    body = text.split(" ", 1)[1] if text.startswith("@") else text
    if " " not in body:
        return None
    head, operands = body.split(" ", 1)
    if not head.startswith("HMNMX2"):
        return None
    mods = head.split(".")[1:]
    if any(mod not in MOD_BITS for mod in mods):
        return None
    ops = [op.strip() for op in operands.split(",")]
    if len(ops) == 4 and "R" in ops[2] and "UR" not in ops[2]:
        return "reg"
    if len(ops) == 5 and all("R" not in op and "|" not in op for op in ops[2:4]):
        return "imm"
    return None


def field(shift, bits, extraction, token):
    return {"bits": bits, "extraction": extraction, "shift": shift,
            "token_idx": token, "_src": SRC}


def base_fields(form):
    fields = [
        field(12, 4, "guard", 0), field(16, 8, "reg", 1),
        field(24, 8, "reg", 2), field(72, 1, "neg", 2), field(73, 1, "abs", 2),
        field(74, 2, "hsel", 2), field(122, 1, "reuse", 2),
        field(87, 3, "pred", 4 if form == "reg" else 5),
        field(90, 1, "neg", 4 if form == "reg" else 5),
    ]
    if form == "reg":
        fields += [field(32, 8, "reg", 3), field(62, 1, "abs", 3),
                   field(63, 1, "neg", 3), field(60, 2, "hsel", 3),
                   field(123, 1, "reuse", 3)]
    else:
        fields += [field(48, 16, "f16", 3), field(32, 16, "f16", 4)]
    return fields


def neutral_masks(rows):
    """Neutral requires the same text at plain AND fully-loaded anchors."""
    by_label = {label: row for row in rows for label in row["labels"]}
    result = {}
    evidence = {}
    for form in ("reg", "imm"):
        plain = by_label[f"{form}:plain-base"]
        loaded = by_label[f"{form}:loaded-base"]
        bits = []
        for bit in range(96):
            p = by_label.get(f"{form}:plain:bit-{bit}")
            l = by_label.get(f"{form}:loaded:bit-{bit}")
            if (p and l and p["rc"] == 0 and l["rc"] == 0
                    and p["nvidia_sass"] == plain["nvidia_sass"]
                    and l["nvidia_sass"] == loaded["nvidia_sass"]):
                bits.append(bit)
        result[form] = sum(1 << bit for bit in bits)
        evidence[form] = bits
    return result, evidence


def groups(neutral):
    output = {}
    for form in ("reg", "imm"):
        fields = base_fields(form) + [field(bit, 1, "", 2) for bit in range(96)
                                      if neutral[form] & (1 << bit)]
        assert len({(f["shift"], f["bits"]) for f in fields}) == len(fields)
        variable_mask = sum(((1 << f["bits"]) - 1) << f["shift"] for f in fields)
        for mod_mask in range(16):
            names = [name for i, name in enumerate(MOD_NAMES) if mod_mask & (1 << i)]
            group_fields = copy.deepcopy(fields)
            if form == "imm" and "BF16_V2" in names:
                for immediate_field in group_fields:
                    if immediate_field["extraction"] == "f16":
                        immediate_field["extraction"] = "bf16"
            and_base = (0x240 if form == "reg" else 0x840) | modifiers(0, names)
            assert and_base & variable_mask == 0
            claim_forbid = []
            if form == "reg":
                claim_forbid.append({"shift": 124, "bits": 1, "values": [1]})
            else:
                claim_forbid.extend({"shift": bit, "bits": 1, "values": [1]}
                                    for bit in (123, 124))
            output.setdefault(form, {})[",".join(sorted(names))] = {
                "and_base": f"0x{and_base:032x}", "count": None,
                "fields": group_fields,
                "claim_forbid": claim_forbid,
                "variable_mask": f"0x{variable_mask:032x}", "_src": SRC,
                "_note": ("Measured HMNMX2 on real 128-bit words with nvdisasm 13.3.73 on SM103/SM100. "
                          "Sixteen independent BF16_V2/FTZ/NAN/XORSIGN groups. Guard, registers, signs, "
                          "legal half selectors, predicate and reuse are measured; the immediate frame has "
                          "two independent f16 fields, or bf16 fields under BF16_V2. Neutral bits require identical text at both plain "
                          "and fully-loaded anchors. Illegal third-operand/immediate reuse is explicitly "
                          "claim_forbid. UR, INVALID/unnamed words and other opcodes are not claimed."),
            }
    return output


def fixture(raw, output):
    rows = raw_rows(raw)
    neutral, evidence = neutral_masks(rows)
    out = []
    counts = {"reg": 0, "imm": 0, "production_reg": 0, "production_imm": 0,
              "exact_reg": 0, "exact_imm": 0, "negatives": 0}
    for row in rows:
        text = row["nvidia_sass"]
        form = text_shape(text)
        word = int(row["word"], 16)
        schedule_probe = row["kind"] in ("single-bit", "single-bit-loaded") and any(
            ":bit-" in label and int(label.rsplit("-", 1)[1]) >= 96 for label in row["labels"])
        adopted = form is not None and not schedule_probe
        record = {"word": row["word"], "nvidia_sass": text, "nvdisasm": row["nvdisasm"],
                  "nvdisasm_sha256": row["nvdisasm_sha256"], "kind": row["kind"],
                  "labels": row["labels"], "target_pair": "SM103=SM100", "adopt": adopted}
        if schedule_probe:
            record["auxiliary"] = "control/schedule-plane probe"
        if adopted:
            record["form"] = form
            record["encode_exact"] = (word & ((1 << 96) - 1) & neutral[form] == 0
                                      and row["kind"] != "H-production")
            counts[form] += 1
            counts[f"exact_{form}"] += int(record["encode_exact"])
            if row["kind"] == "H-production":
                record["provenance"] = "H survey production vendor fixture"
                counts[f"production_{form}"] += 1
        elif not schedule_probe:
            record["lattice"] = True
            if text is None or text.startswith("HMNMX2") or " HMNMX2" in text:
                counts["negatives"] += 1
        out.append(record)
    assert counts["production_reg"] == 310, counts
    assert counts["production_imm"] == 319, counts
    assert counts["reg"] > 500 and counts["imm"] > 500, counts
    with output.open("w") as stream:
        for record in out:
            stream.write(json.dumps(record, sort_keys=True) + "\n")
    summary = {"counts": counts, "neutral_bits": evidence,
               "fixture_sha256": sha256(output), "records": len(out)}
    (output.parent / "hmnmx2-fixture-summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n")
    print(json.dumps(summary, indent=2, sort_keys=True))


def apply(raw, tables):
    rows = raw_rows(raw)
    neutral, _ = neutral_masks(rows)
    modifications = groups(neutral)
    source = {"rows": 32, "kind": "nvdisasm 13.3.73 production-anchored SM103/SM100 HMNMX2 probe",
              "date": "2026-11-08", "tool": "tools/probes/re_b300_hmnmx2.py",
              "test": "tests/hidden_b300_hmnmx2.rs"}
    for path in tables:
        table = json.loads(path.read_text())
        for form, key in (("reg", REG_KEY), ("imm", IMM_KEY)):
            if key in table["instructions"]:
                assert table["instructions"][key].get("_src") == SRC
            else:
                donor = copy.deepcopy(table["instructions"]["FMNMX_R_R_R_P"])
                entry = {k: v for k, v in donor.items() if k in ("ctrl_class", "scheduling")}
                entry.update({"base_op": "HMNMX2", "operand_sig": "R_R_R_P" if form == "reg" else "R_R_FI_FI_P",
                              "_src": SRC})
                table["instructions"][key] = entry
            table["instructions"][key]["mod_groups"] = modifications[form]
        provenance = table["_meta"]["provenance"]
        if SRC in provenance["sources"]:
            assert provenance["sources"][SRC] == source
        provenance["sources"][SRC] = source
        provenance["rows_total"] = sum(len(e.get("mod_groups", {}))
                                      for e in table["instructions"].values())
        provenance["rows_without_src"] = sum(1 for e in table["instructions"].values()
            for group in e.get("mod_groups", {}).values() if "_src" not in group)
        path.write_text(json.dumps(table, indent=1) + "\n")
        print(path, "+2 keys", 32, "groups", provenance["rows_total"])


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    pr = sub.add_parser("probe")
    pr.add_argument("--nvdisasm", default="/usr/local/cuda/bin/nvdisasm")
    pr.add_argument("--out", type=pathlib.Path, required=True)
    pr.add_argument("--jobs", type=int, default=8)
    fx = sub.add_parser("fixture")
    fx.add_argument("raw", type=pathlib.Path)
    fx.add_argument("output", type=pathlib.Path)
    ap = sub.add_parser("apply")
    ap.add_argument("raw", type=pathlib.Path)
    ap.add_argument("tables", nargs="+", type=pathlib.Path)
    args = parser.parse_args()
    if args.command == "probe":
        probe(args)
    elif args.command == "fixture":
        fixture(args.raw, args.output)
    else:
        apply(args.raw, args.tables)


if __name__ == "__main__":
    main()

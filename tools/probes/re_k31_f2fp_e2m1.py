#!/usr/bin/env python3
"""Measure the K3.1 BF16/E2M1 UNPACK_B register and immediate scale forms.

The production witnesses are not re-enumerated here.  H supplied all 861
distinct register-scale words with nvdisasm 13.3 text in the K3.1 inbox;
`probe` adds independently measured field/selector/lattice words on SM103 and
SM100, keeps both classes of evidence in one JSONL, and `apply` installs one
measured row per form on sm103a/sm100a.

H's silicon run (inbox .../silicon/) established the semantics: the two BF16
outputs are the E2M1 nibbles of the selected Ra byte multiplied by the
selected E8M0 scale byte.  The register form is opcode 0x63e; the immediate
form is 0xe3e.  The corpus and the raw probes give the complete field map:
guard@12, Rd@16, scale selector@24 (H0/H1/B0..B3 = 0..5), Ra.byte = 72|88,
Ra.reuse=123 and Rb.reuse=124 on 0x63e.  The immediate form moves Ra to 64
and uses f32@32 for the packed scale; its bits 123/124 are text-inert, not
reuse flags, and are deliberately excluded from its row.
"""
import argparse
import copy
import concurrent.futures
import json
import pathlib
import re
import subprocess
import sys
import threading

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from nvprobe import field, field_mask, load_table, nvdisasm_identity, row, save_table

PROVENANCE = "k31-f2fp-e2m1-sm103-sm100-2026-11-07"
REG_KEY = "F2FP.BF16.E2M1.UNPACK_B_R_R_R"
IMM_KEY = "F2FP.BF16.E2M1.UNPACK_B_R_R_FI"
DONOR = "F2FP_R_R_R"  # local metadata donor; it remains for the other F2FP forms
CTRL = 0x000fe200 << 96
REG_BASE = 0x000fe2000204120200000010020b763e
IMM_BASE = 0x004fca000204120200007f7f000b7e3e
INBOX = pathlib.Path("/root/sm103a/inbox-hgx02/2026-11-07-k31-prefill-gaps")
VENDOR = INBOX / "vendor/fixture_trtllm_moe_sm103a.jsonl"
FIXTURE = HERE.parents[1] / "tests/fixtures/k31_f2fp_e2m1_nvdisasm.jsonl"


def put(w, shift, bits, value):
    return (w & ~(((1 << bits) - 1) << shift)) | (value << shift)


def synthetic_words():
    """One word per field arm, then the bit-lattice outside the declarations."""
    forms = []
    for base, form in [(REG_BASE, "register"), (IMM_BASE, "immediate")]:
        forms.append((base, {"probe": "anchor", "form": form}))
        for guard in range(16):
            forms.append((put(base, 12, 4, guard), {"probe": "guard", "form": form}))
        for rd in (0, 1, 47, 100, 254, 255):
            forms.append((put(base, 16, 8, rd), {"probe": "rd", "form": form}))
        for selector in range(8):
            forms.append((put(base, 24, 3, selector), {"probe": "scale-selector", "form": form}))
        for ra_byte in range(4):
            w = put(put(base, 72, 1, ra_byte & 1), 88, 1, ra_byte >> 1)
            forms.append((w, {"probe": "ra-byte", "form": form}))
        for ra in (0, 1, 47, 100, 254, 255):
            shift = 32 if form == "register" else 64
            forms.append((put(base, shift, 8, ra), {"probe": "ra", "form": form}))
        if form == "register":
            for ra_byte in range(4):
                for ra_reuse in (0, 1):
                    for rb_reuse in (0, 1):
                        w = put(put(base, 72, 1, ra_byte & 1), 88, 1, ra_byte >> 1)
                        w = put(put(w, 124, 1, ra_reuse), 123, 1, rb_reuse)
                        forms.append((w, {"probe": "full-ra-rb-reuse-cross", "form": form}))
            for rb in (0, 1, 47, 100, 254, 255):
                forms.append((put(base, 64, 8, rb), {"probe": "rb", "form": form}))
            for bit in (122, 123, 124):
                forms.append((base ^ (1 << bit), {"probe": "reuse", "form": form}))
        else:
            for bit in (123, 124):
                forms.append((base ^ (1 << bit), {"probe": "text-inert-reuse-window", "lattice": True, "form": form}))
            for imm in (0, 1, 0x7f, 0x7f7f, 0x7e7e, 0x7fff7fff, 0x12345678, 0xffffffff):
                forms.append((put(base, 32, 32, imm), {"probe": "f32-scale", "form": form}))
        forms.append((base & ~(7 << 122), {"probe": "reuse-none", "form": form}))

    # Do not infer legality from the anchors: every undeclared payload bit is
    # probed separately.  Text-inert bits are not silently appended to fields.
    declared = {12, 13, 14, 15, *range(16, 27), *range(32, 40),
                *range(64, 72), 72, 73, 76, 80, 82, 88, 89}
    for base, form in [(REG_BASE, "register"), (IMM_BASE, "immediate")]:
        for bit in range(16, 105):
            if bit in declared or (form == "immediate" and 32 <= bit < 64):
                continue
            w = base ^ (1 << bit)
            forms.append((w, {"probe": "lattice-bit", "lattice": True, "form": form, "bit": bit}))
    return list({w: (w, meta) for w, meta in forms}.values())


def vendor_rows():
    rows = []
    with VENDOR.open() as fh:
        for line in fh:
            record = json.loads(line)
            if "F2FP.BF16.E2M1.UNPACK_B" not in record["text"]:
                continue
            rows.append({
                "word": record["word"][2:],
                "nvidia_sass": record["text"],
                "arch": "SM103",
                "nvdisasm": record["nvdisasm"],
                "source": record["source"],
                "occurrences": record["occurrences"],
                "evidence": "H production witness (not re-probed)",
                "form": "register",
            })
    assert len(rows) == 861, len(rows)
    assert sum(r["occurrences"] for r in rows) == 11520
    assert len({r["word"] for r in rows}) == len(rows)
    return rows


def probe(args):
    rows = vendor_rows()
    words = synthetic_words()
    for arch in ("SM103", "SM100"):
        version, digest = nvdisasm_identity(args.nvdisasm)
        local = threading.local()
        def one(w):
            if not hasattr(local, "scratch"):
                local.scratch = pathlib.Path(f"/tmp/k31_f2fp_e2m1_{arch}_{threading.get_ident()}.bin")
            local.scratch.write_bytes(w.to_bytes(16, "little"))
            r = subprocess.run([args.nvdisasm, "-b", arch, "-hex", str(local.scratch)],
                                capture_output=True, text=True)
            match = re.search(r"/\*0000\*/\s*(.*?)\s*;", r.stdout)
            text = match.group(1).strip() if r.returncode == 0 and match else None
            error = None if text is not None else r.stderr.strip()
            return {"word": f"{w:032x}", "nvidia_sass": text, "arch": arch,
                    "nvdisasm": version, "nvdisasm_sha256": digest, "vendor_error": error}
        with concurrent.futures.ThreadPoolExecutor(args.jobs) as pool:
            measured = list(pool.map(one, [w for w, _ in words]))
        for rec, (w, meta) in zip(measured, words):
            rec.update(meta)
            rec["word"] = f"{w:032x}"
            rec["evidence"] = "independent raw nvdisasm probe"
            # The immediate value is a raw f32 plus a lane selector, not an
            # integer scale; keep the exact spelling chosen by this nvdisasm.
            if not meta.get("lattice"):
                assert rec["nvidia_sass"] is None or rec["nvidia_sass"].startswith(
                    ("@P", "@!P", "F2FP.BF16.E2M1.UNPACK_B")), rec
            if meta.get("probe") == "scale-selector" and ((w >> 24) & 7) < 6:
                assert rec["nvidia_sass"] is not None, rec
            rows.append(rec)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w") as fh:
        for rec in rows:
            fh.write(json.dumps(rec) + "\n")
    print(f"{len(rows)} rows ({len(vendor_rows())} supplied production witnesses) -> {args.out}")


def fields_for(form):
    f = [field(12, 4, "guard", 0, PROVENANCE), field(16, 8, "reg", 1, PROVENANCE),
         field(24, 3, "e2m1_scale", 3, PROVENANCE)]
    ra_shift = 32 if form == "register" else 64
    f += [field(ra_shift, 8, "reg", 2, PROVENANCE),
          field(72, 1, "e2m1_ra", 2, PROVENANCE),
          field(88, 1, "e2m1_ra", 2, PROVENANCE)]
    if form == "register":
        f += [field(64, 8, "reg", 3, PROVENANCE), field(123, 1, "reuse", 2, PROVENANCE),
              field(124, 1, "reuse", 3, PROVENANCE)]
    else:
        f += [field(32, 32, "f32", 3, PROVENANCE)]
    return f


def apply(path):
    path = pathlib.Path(path)
    table = load_table(path)
    ins = table["instructions"]
    assert (REG_KEY in ins) == (IMM_KEY in ins), "partial K3.1 row set"
    assert DONOR in ins
    additions = {}
    for key, form, base, operand_sig in [
        (REG_KEY, "register", REG_BASE, "R_R_R"),
        (IMM_KEY, "immediate", IMM_BASE, "R_R_FI"),
    ]:
        fields = fields_for(form)
        mask = field_mask(fields)
        and_base = base & ~mask & ~(((1 << 23) - 1) << 105)
        entry = copy.deepcopy(ins[DONOR])
        entry["base_op"] = "F2FP.BF16.E2M1.UNPACK_B"
        entry["operand_sig"] = operand_sig
        g = row(and_base, fields, PROVENANCE,
            "K3.1 MoE: MXFP4 nibble pair * E8M0 -> BF16x2.  nvdisasm 13.3.73 field probes on SM103/SM100; "
            "all 861 distinct (11,520-word) register-scale production witnesses supplied by H.  "
            "Bits 73/76/82/89 select BF16/E2M1/UNPACK_B; scale selector values 6/7 stay unclaimed.  "
            "H's B300 silicon sweep covers all 256 E2M1 bytes x 13 scale bytes, including subnormals/inf/NaN; "
            "see k31-work/f2fp-e2m1 and inbox-hgx02/2026-11-07-k31-prefill-gaps/silicon.")
        g["claim_forbid"] = [{"shift": 24, "bits": 3, "values": [6, 7]}]
        g["claim_forbid"] += [{"shift": bit, "bits": 1, "values": [1]} for bit in range(96, 105)]
        if form == "immediate":
            # decode strips the upper 32 bits before the ordinary mask match;
            # these text-inert bits therefore need explicit exclusion guards.
            g["claim_forbid"] += [{"shift": bit, "bits": 1, "values": [1]} for bit in (123, 124)]
        entry["mod_groups"] = {"": g}
        entry["_src"] = PROVENANCE
        additions[key] = entry
    rebuilt = {}
    for k, v in ins.items():
        if k == DONOR:
            rebuilt.update(additions)
        rebuilt[k] = v
    ins.clear()
    ins.update(rebuilt)
    p = table["_meta"]["provenance"]
    p["sources"][PROVENANCE] = {
        "rows": 2,
        "kind": "nvdisasm 13.3.73 field probe on SM103/SM100 + production-witness census + B300 silicon (H)",
        "date": "2026-11-07",
        "tool": "tools/probes/re_k31_f2fp_e2m1.py",
        "test": "tests/k31_f2fp_e2m1.rs",
        "silicon": "H, B300 GPU 7 with owner permission: exact E2M1*E8M0 -> BF16x2 for all 256 input bytes x 13 scales",
    }
    p["rows_total"] = sum(len(e.get("mod_groups", {})) for e in ins.values())
    p["rows_without_src"] = sum(1 for e in ins.values() for g in e.get("mod_groups", {}).values() if "_src" not in g)
    save_table(path, table)
    print(f"{path}: +{REG_KEY}, +{IMM_KEY}")


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
        for path in args.tables:
            apply(path)


if __name__ == "__main__":
    main()

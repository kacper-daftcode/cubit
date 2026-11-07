#!/usr/bin/env python3
"""Install measured K3.1 SYNCS/ARRIVES/UTMALDG/U? helper forms.

Every row has either a measured donor in blackwell-isa or a donor's exact
field map adapted to the new named form.  Nothing is copied from nvdisasm
output strings in isolation.  H's production fixtures remain the witnesses;
`apply` binds each field and the complete canonical group to a registered tag.
"""
import argparse, copy, json, pathlib, sys
import subprocess
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from nvprobe import field, field_mask, load_table, nvdisasm_text, save_table, write_fixture
import nvprobe

SRC = "k31-synchronisation-forms-2026-11-07"
VENDOR = pathlib.Path("/root/sm103a/inbox-hgx02/2026-11-07-k31-prefill-gaps/vendor")
ISA = pathlib.Path(__file__).resolve().parents[3] / "isa-k31"
FIXTURE = pathlib.Path(__file__).resolve().parents[2] / "tests/fixtures/k31_sync_forms_nvdisasm.jsonl"
NVDISASM = "/usr/local/cuda/bin/nvdisasm"
PREFIXES = ("SYNCS", "ARRIVES", "USETMAXREG", "UTMALDG", "UGETNEXTWORKID", "BAR.SYNC")
FORM_PREFIXES = {
    "SYNCS": "SYNCS.ARRIVE.TRANS64.RED.A0T1 ",
    "ARRIVES": "ARRIVES.LDGSTSBAR.64.TRANSCNT ",
    "USETMAXREG": "USETMAXREG.TRY_ALLOC.CTAPOOL ",
    "UTMALDG": "UTMALDG.4D.MULTICAST.2CTA ",
    "UGETNEXTWORKID": "UGETNEXTWORKID.SELFCAST ",
    "BAR.SYNC": "BAR.SYNC.DEFER_BLOCKING ",
}
EXPECTED = {"SYNCS": (103, 174), "ARRIVES": (103, 174), "USETMAXREG": (2, 30),
            "UTMALDG": (9, 56), "UGETNEXTWORKID": (26, 328), "BAR.SYNC": (1, 48)}


def witnesses_preview(out=None):
    rows = []
    for filename in ("fixture_trtllm_moe_sm103a.jsonl", "fixture_trtllm_moe_sm100f.jsonl"):
        with (VENDOR / filename).open() as fh:
            for line in fh:
                r = json.loads(line)
                op = r["text"].split()[0].split('.')[0]
                if op == "BAR":
                    op = "BAR.SYNC"
                if op not in FORM_PREFIXES or not r["text"].startswith(FORM_PREFIXES[op]):
                    continue
                r2 = {"word": r["word"][2:], "nvidia_sass": r["text"], "arch": r["target"].replace("F", ""),
                        "op": op, "nvdisasm": r["nvdisasm"], "source": r["source"], "occurrences": r["occurrences"],
                        "evidence": "H production witness (not re-probed), donor validated per family"}
                rows.append(r2)
    for op, (n, occ) in EXPECTED.items():
        got = [r for r in rows if r["op"] == op]
        assert len(got) == n, (op, len(got), n)
        assert sum(r["occurrences"] for r in got) == occ, op
    assert sum(EXPECTED[x][0] for x in EXPECTED) == len(rows)
    if out:
        with out.open("w") as fh:
            for r in rows:
                fh.write(json.dumps(r) + "\n")
        print(len(rows), "records ->", out)
    return rows


def preserved_broadcast_witnesses():
    rows = []
    for arch, target, word, occurrences in [
        ("sm103a", "SM103", "000fec0008000100000000001a0073ca", 42),
        ("sm100a", "SM100", "000fec0008000100000000001a0073ca", 40),
    ]:
        text = nvdisasm_text(NVDISASM, pathlib.Path(f"/tmp/k31_ugetnext_{target}.bin"), int(word, 16), 0, target)
        assert text == "UGETNEXTWORKID.BROADCAST [UR26], [UR27]", (arch, text)
        rows.append({"word": word, "nvidia_sass": text, "arch": target, "op": "UGETNEXTWORKID.BROADCAST",
                     "nvdisasm": nvprobe.nvdisasm_identity(NVDISASM)[0], "source": "preserved production stream witness",
                     "occurrences": occurrences, "evidence": "pre-existing BROADCAST row retained; local nvdisasm 13.3.73 text"})
    return rows


def stamp(record, src=SRC):
    record["_src"] = src
    for f in record["fields"]:
        for key in list(f):
            if key.startswith("_src") or key.startswith("_evidence"):
                f.pop(key, None)
        f["_src"] = src


def metadata_from(donor, local, base_op, sig):
    entry = copy.deepcopy(local if local is not None else donor)
    entry["base_op"] = base_op
    entry["operand_sig"] = sig
    entry["_src"] = SRC
    return entry


def apply(tables):
    sm120 = load_table(ISA / "sm120.json")["instructions"]
    samples = witnesses_preview()
    for path in tables:
        original = json.loads(subprocess.check_output(
            ["git", "-C", str(ISA), "show", f"3103829f20eeb56d9ece67b5ade3d2a2a8cbcfe1:{path.name}"],
            text=True))
        table = load_table(path)
        ins = table["instructions"]
        # Two whole, measured ARRIVES variants, not the older no-row gap.
        donor = sm120["ARRIVES_ARURI"]
        entry = metadata_from(donor, ins.get("ARRIVES_ARURI"), "ARRIVES", "ARURI")
        g = copy.deepcopy(donor["mod_groups"]["64,LDGSTSBAR"])
        for r in samples:
            if r["op"] == "ARRIVES":
                w = int(r["word"], 16)
                assert (w >> 77) & 1 == 1 and (w >> 76) & 1 == 0
        g["and_base"] = f"0x{int(g['and_base'], 16) | (1 << 77):032x}"
        stamp(g)
        entry["mod_groups"] = {"64,LDGSTSBAR,TRANSCNT": g}
        ins["ARRIVES_ARURI"] = entry

        # USETMAXREG's uniform-predicate destination and immediate pool count.
        donor = sm120["USETMAXREG_UP_II"]
        key = "USETMAXREG_UP_II"
        entry = metadata_from(donor, ins.get(key), "USETMAXREG", "UP_II")
        entry["mod_groups"] = copy.deepcopy(donor["mod_groups"])
        for g in entry["mod_groups"].values():
            stamp(g)
        ins[key] = entry
        table["_meta"].setdefault("key_aliases", {})["USETMAXREG_U_UP_II"] = key

        # UGETNEXTWORKID self-casts share URn, URn+1 at [31:24].
        donor = sm120["UGETNEXTWORKID_AURI_AURI"]
        key = "UGETNEXTWORKID_AURI_AURI"
        entry = metadata_from(donor, ins.get(key), "UGETNEXTWORKID", "AURI_AURI")
        broadcast = ins.get(key, {}).get("mod_groups", {}).get("BROADCAST")
        if broadcast is None:
            broadcast = original["instructions"][key]["mod_groups"]["BROADCAST"]
        entry["mod_groups"] = {"BROADCAST": copy.deepcopy(broadcast),
                               "SELFCAST": copy.deepcopy(donor["mod_groups"]["SELFCAST"])}
        stamp(entry["mod_groups"]["SELFCAST"])
        ins[key] = entry

        # `imm=0` is the elided count in BAR.SYNC.DEFER_BLOCKING.
        donor = sm120["BAR.SYNC.DEFER_BLOCKING_II_R"]
        key = "BAR.SYNC.DEFER_BLOCKING_II"
        entry = metadata_from(donor, ins.get(key), "BAR.SYNC.DEFER_BLOCKING", "II")
        # One immediate token, with the RZ count implicit in and_base.
        if ins.get("BAR.SYNC.DEFER_BLOCKING_II_R", {}).get("_src") == SRC:
            del ins["BAR.SYNC.DEFER_BLOCKING_II_R"]
        exact = {"bits": 4, "extraction": "guard", "shift": 12, "token_idx": 0, "_src": SRC}
        immediate = {"bits": 4, "extraction": "imm", "shift": 54, "token_idx": 1, "_src": SRC}
        register = {"bits": 8, "extraction": "reg", "shift": 32, "token_idx": 2, "_src": SRC}
        g = {"count": None, "fields": [exact, immediate, register],
             "_note": "T1 measured BAR defer blocker: one immediate; implicit RZ at [39:32]."}
        g["variable_mask"] = f"0x{field_mask(g['fields']):032x}"
        sample = next(int(r["word"], 16) for r in samples if r["op"] == "BAR.SYNC")
        g["and_base"] = f"0x{sample & ~(((1 << 23) - 1) << 105) & ~(int(g['variable_mask'], 16) | 0xfff) | (sample & 0xfff):032x}"
        g["_src"] = SRC
        entry["mod_groups"] = {"DEFER_BLOCKING,SYNC": g}
        ins[key] = entry
        table["_meta"].get("key_aliases", {}).pop("BAR.SYNC.DEFER_BLOCKING_II", None)
        if ins.get("BAR.SYNC.DEFER_BLOCKING_II_R", {}).get("_src") == SRC:
            del ins["BAR.SYNC.DEFER_BLOCKING_II_R"]

        # The new multicast + 2CTA variant retains the 4D donor's ARURI fields.
        donor = sm120["UTMALDG_AURI_AURI_II"]
        # Preserve the seven earlier target-specific measured dimensional
        # variants. Earlier prototypes accidentally replaced this donor with
        # the one new form; recover it from the last pre-sync commit if needed.
        legacy_key = "UTMALDG_AURI_AURI_II"
        if len(ins.get(legacy_key, {}).get("mod_groups", {})) != 7:
            ins[legacy_key] = original["instructions"][legacy_key]
        assert len(ins[legacy_key]["mod_groups"]) == 7
        key = "UTMALDG.4D.MULTICAST.2CTA_AURI_AURI_UR"
        entry = metadata_from(donor, ins.get(key), "UTMALDG.4D.MULTICAST.2CTA", "AURI_AURI_UR")
        assert "4D" in donor["mod_groups"]
        g = copy.deepcopy(donor["mod_groups"]["4D"])
        stamp(g)
        g["fields"] = [field(12, 4, "guard", 0, SRC), field(32, 8, "sub_ur0", 1, SRC),
                       field(24, 8, "sub_ur0", 2, SRC), field(64, 8, "ureg", 3, SRC)]
        g["variable_mask"] = f"0x{field_mask(g['fields']):032x}"
        sample = next(int(r["word"], 16) for r in samples if r["op"] == "UTMALDG")
        opcode = sample & 0xfff
        control = ((1 << 23) - 1) << 105
        base = sample & ~control & ~(int(g["variable_mask"], 16) | 0xfff) | opcode
        g["and_base"] = f"0x{base:032x}"
        entry["mod_groups"] = {"2CTA,4D,MULTICAST": g}
        ins[key] = entry
        # Only our earlier, rejected prototype is removed, never an existing donor.
        if ins.get("UTMALDG_AURI_AURI_II", {}).get("_src") == SRC:
            del ins["UTMALDG_AURI_AURI_II"]

        # The actual target says A0T1. Reuse the already measured descriptor,
        # immediate and sink operands of the sibling A1T0 ARRIVE form, but let
        # this own the A0T1 mnemonic and its observed geometric modifiers.
        donor = sm120["SYNCS_R_ARURI_R"]
        key = "SYNCS.ARRIVE.TRANS64.RED.A0T1_R_ARURI_R"
        entry = metadata_from(donor, ins.get(key), "SYNCS.ARRIVE.TRANS64.RED.A0T1", "R_ARURI_R")
        assert "A1T0,ARRIVE,TRANS64" in donor["mod_groups"]
        g = copy.deepcopy(donor["mod_groups"]["A1T0,ARRIVE,TRANS64"])
        stamp(g)
        mask = int(g["variable_mask"], 16)
        samples_sync = [int(r["word"], 16) for r in samples if r["op"] == "SYNCS"]
        # Remove control/reuse bits at >=105, never harvest them into a row.
        fixed = ((1 << 128) - 1) & ~(((1 << 23) - 1) << 105)
        for w in samples_sync:
            fixed &= w
        fixed &= ~0xfff
        fixed |= 0x9a7
        fixed &= ~mask
        g["and_base"] = f"0x{fixed:032x}"
        entry["mod_groups"] = {"A0T1,ARRIVE,RED,TRANS64": g}
        ins[key] = entry

        prov = table["_meta"]["provenance"]
        prov["sources"][SRC] = {"rows": 6, "kind": "measured-donor transfer + nvdisasm 13.3.73 production witnesses per form",
            "date": "2026-11-07", "tool": "tools/probes/re_k31_sync_forms.py", "test": "tests/k31_sync_forms.rs"}
        prov["rows_total"] = sum(len(e.get("mod_groups", {})) for e in ins.values())
        prov["rows_without_src"] = sum(1 for e in ins.values() for g in e.get("mod_groups", {}).values() if "_src" not in g)
        save_table(path, table)
        print(path, "6 measured synchronisation rows installed")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest="command", required=True)
    p = sub.add_parser("probe")
    p.add_argument("--out", type=pathlib.Path, default=FIXTURE)
    a = sub.add_parser("apply")
    a.add_argument("tables", nargs="+", type=pathlib.Path)
    args = ap.parse_args()
    if args.command == "probe":
        rows = witnesses_preview()
        rows.extend(preserved_broadcast_witnesses())
        write_fixture(args.out, rows)
        print(len(rows), "records ->", args.out)
    else:
        apply(args.tables)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Close the three exact FlashKDA S1 residue encodings with nvdisasm evidence."""
import argparse
import copy
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from nvprobe import (  # noqa: E402
    SCHEDULE, field_mask, load_table, probe_words, row, save_table, write_fixture,
)

ROOT = pathlib.Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "tests/fixtures/k31_flashkda_residue_nvdisasm.jsonl"
SOURCES = {
    "utmaldg": "k31-utma1d-flashkda-2026-11-07",
    "ublkcp": "k31-ublkcp-gs-flashkda-2026-11-11",
    "f2fp": "k31-f2fp-pack-ur-inert-rc-2026-11-07",
}
OCCURRENCES = {"utmaldg": 388, "ublkcp": 24, "f2fp": 4}


def put(word, shift, bits, value):
    return (word & ~(((1 << bits) - 1) << shift)) | (value << shift)


def classify(failure):
    if failure.get("stage") == "decode":
        error = failure.get("error", "")
        if "opcode 0x05b4" in error:
            return "utmaldg"
        if "opcode 0x03ba" in error:
            return "ublkcp"
    if failure.get("stage") == "mismatch" and failure.get("decoded_key") == "F2FP_R_R_UR":
        assert failure.get("decoded_mod_group") == "BF16,F32,PACK_AB"
        assert failure.get("xor") == "0x00000000000000ff0000000000000000"
        return "f2fp"
    return None


def production_records(failures):
    """Reduce one strict JSONL report to distinct production words and census counts."""
    counts = {}
    for line in failures.open():
        wrapper = json.loads(line)
        failure = wrapper["failure"]
        kind = classify(failure)
        if kind is None:
            continue
        word = int(failure["expected"], 16) & ~SCHEDULE
        counts.setdefault(word, [kind, 0])[1] += 1
    grouped = {kind: [] for kind in SOURCES}
    for word, (kind, occurrences) in sorted(counts.items()):
        grouped[kind].append((word, occurrences))
    assert {kind: sum(n for _w, n in rows) for kind, rows in grouped.items()} == OCCURRENCES
    return grouped


def checked(kind, text):
    if kind == "utmaldg":
        return text is not None and "UTMALDG.1D [" in text and ", desc[UR" in text
    if kind == "ublkcp":
        return text is not None and "UBLKCP.G.S [" in text
    return text is not None and "F2FP.BF16.F32.PACK_AB " in text


def add_metadata(records, kind, occurrences, evidence, arch):
    for record, (word, count) in zip(records, occurrences):
        assert int(record["word"], 16) == word
        record.update({
            "arch": arch, "kind": kind, "occurrences": count, "evidence": evidence,
        })


def probe(args):
    out = []
    production = production_records(args.failures)
    for kind, rows in production.items():
        words = [(word, False) for word, _count in rows]
        measured = probe_words(args.nvdisasm, f"k31_{kind}_production", words, 0,
                               lambda _w, text, k=kind: checked(k, text), arch="SM100", jobs=args.jobs)
        add_metadata(measured, kind, rows, "FlashKDA production word replayed through nvdisasm", "SM100")
        out.extend(measured)

    field_shifts = {"utmaldg": (24, 32, 40), "ublkcp": (24, 32, 64), "f2fp": (16, 24, 32)}
    for kind, rows in production.items():
        for arch in ("SM103", "SM100"):
            base = rows[0][0]
            words = {put(base, 12, 4, guard) for guard in range(16)}
            for shift in field_shifts[kind]:
                for value in (0, 5, 63, 64, 100, 127, 128, 255):
                    words.add(put(base, shift, 8, value))
            words = sorted(words)
            measured = probe_words(args.nvdisasm, f"k31_{kind}_fields", [(w, False) for w in words], 0,
                                   lambda _w, text, k=kind: checked(k, text), arch=arch, jobs=args.jobs)
            add_metadata(measured, kind, [(w, 0) for w in words], "independent guard/register field probe", arch)
            out.extend(measured)
    write_fixture(args.out, out)
    print(len(out), "records ->", args.out)


def fixture_production(kind):
    with FIXTURE.open() as fh:
        rows = [json.loads(line) for line in fh]
    rows = [r for r in rows if r["kind"] == kind and r["arch"] == "SM100" and r["occurrences"]]
    assert sum(r["occurrences"] for r in rows) == OCCURRENCES[kind]
    return rows


def sourced_fields(group, src):
    fields = copy.deepcopy(group["fields"])
    for field in fields:
        field["_src"] = src
    return fields


def base_fromWitness(witness, fields, opcode):
    return (witness & ~field_mask(fields) & ~SCHEDULE & ~0xfff) | opcode


def note_source(table, src, kind):
    provenance = table["_meta"]["provenance"]
    provenance["sources"][src] = {
        "rows": 1,
        "kind": f"FlashKDA {kind} production witnesses + independent nvdisasm field probes",
        "date": "2026-11-11",
        "tool": "tools/probes/re_k31_flashkda_residue.py",
        "test": "tests/k31_flashkda_residue.rs",
    }


def install_utmaldg(table):
    src = SOURCES["utmaldg"]
    form = table["instructions"]["UTMALDG_AURI_AURI_II"]
    assert "1D" not in form["mod_groups"]
    fields = sourced_fields(form["mod_groups"]["2D"], src)
    assert [(f["shift"], f["bits"], f["extraction"], f["token_idx"]) for f in fields] == [
        (12, 4, "guard", 0), (32, 8, "sub_ur0", 1),
        (24, 8, "sub_ur0", 2), (40, 8, "desc_ur", 3)]
    witness = int(fixture_production("utmaldg")[0]["word"], 16)
    base = base_fromWitness(witness, fields, 0x5b4)
    form["mod_groups"]["1D"] = row(base, fields, src,
        "FlashKDA descriptor-form UTMALDG.1D with guard and three exact 8-bit uniform registers.")
    note_source(table, src, "UTMALDG.1D descriptor")


def install_ublkcp(table):
    src = SOURCES["ublkcp"]
    key = "UBLKCP.G.S_AURI_AURI_UR"
    assert key not in table["instructions"]
    donor = load_table(ROOT.parent / "blackwell-isa/sm120.json")["instructions"][key]
    fields = sourced_fields(donor["mod_groups"][""], src)
    assert [(f["shift"], f["bits"], f["extraction"], f["token_idx"]) for f in fields] == [
        (12, 4, "guard", 0), (32, 8, "sub_ur0", 1),
        (24, 8, "sub_ur0", 2), (64, 8, "ureg", 3)]
    witness = int(fixture_production("ublkcp")[0]["word"], 16)
    entry = copy.deepcopy(donor)
    entry["_src"] = src
    entry["mod_groups"] = {"": row(base_fromWitness(witness, fields, 0x3ba), fields, src,
        "FlashKDA UBLKCP.G.S with guard and three exact 8-bit uniform registers; no open immediate byte band.")}
    table["instructions"][key] = entry
    note_source(table, src, "UBLKCP.G.S")


def install_f2fp(table):
    src = SOURCES["f2fp"]
    group = table["instructions"]["F2FP_R_R_UR"]["mod_groups"]["BF16,F32,PACK_AB"]
    assert int(group["and_base"], 16) & (0xff << 64) == 0
    group["and_base"] = f"0x{int(group['and_base'], 16) | (0xff << 64):032x}"
    group["_src_k31"] = src
    group["_note"] = (
        "FlashKDA production F2FP.BF16.F32.PACK_AB R,R,UR carries the vendor's inert RC byte "
        "0xff at [71:64]. Preserve it verbatim; all existing fields, variable_mask and "
        "claim_forbid safety rules are unchanged. " + group.get("_note", ""))
    note_source(table, src, "F2FP.BF16.F32.PACK_AB inert RC byte")


def apply(tables):
    for path in tables:
        table = load_table(path)
        install_utmaldg(table)
        install_ublkcp(table)
        install_f2fp(table)
        provenance = table["_meta"]["provenance"]
        provenance["rows_total"] = sum(len(e.get("mod_groups", {})) for e in table["instructions"].values())
        provenance["rows_without_src"] = sum(1 for e in table["instructions"].values()
                                             for g in e.get("mod_groups", {}).values() if "_src" not in g)
        save_table(path, table)
        print(path, "FlashKDA residue installed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("probe")
    p.add_argument("--failures", required=True, type=pathlib.Path)
    p.add_argument("--nvdisasm", default="nvdisasm")
    p.add_argument("--out", type=pathlib.Path, default=FIXTURE)
    p.add_argument("--jobs", type=int, default=8)
    a = sub.add_parser("apply")
    a.add_argument("tables", nargs="+", type=pathlib.Path)
    args = parser.parse_args()
    probe(args) if args.command == "probe" else apply(args.tables)


if __name__ == "__main__":
    main()

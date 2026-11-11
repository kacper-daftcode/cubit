#!/usr/bin/env python3
"""Measure the four missing ExpertsKernel forms on SM103/SM100 and write their rows.

K1 production has nine DEPBAR brace masks, nine uniform deep-CCTL addresses,
18 descriptor UBLKCP loads, and 14 plain UBLKPF prefetches. Eight distinct words
cover those sites. This probe replays them with nvdisasm 13.3 and sweeps their
live fields with no GPU. One-bit neighbours outside the adopted fields stay
negative even when nvdisasm renders unchanged text.
"""

import argparse
import copy
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import nvprobe  # noqa: E402


SRC = "rows-k1-experts-forms-2026-11-10"
CTRL = {
    "depbar": 0x000FC800 << 96,
    "cctl": 0x004EA400 << 96,
    "ublkcp": 0x0003E400 << 96,
    "ublkpf": 0x0003F000 << 96,
}
ARCH = {
    "SM103": "k1_experts_sm103a_nvdisasm.jsonl",
    "SM100": "k1_experts_sm100a_nvdisasm.jsonl",
}

DEPBAR = 0x791A | (7 << 12) | (0x3F << 32)
LOW96 = (1 << 96) - 1
CCTL = 0x004EA40009C080000000000012007540 & LOW96
UBLKCP = 0x0001E4000800120400000C08060073BA & LOW96
UBLKPF = 0x0003F0000800000400000000180073BC & LOW96
BASE = {"depbar": DEPBAR, "cctl": CCTL, "ublkcp": UBLKCP, "ublkpf": UBLKPF}
META = {
    "depbar": ("DEPBAR_II", ""),
    "cctl": ("CCTL_AURI", "C,DEEP,E,IV,LDCU"),
    "ublkcp": ("UBLKCP_AURI_AURI_UR_II", "G,S"),
    "ublkpf": ("UBLKPF_AURI_UR", "L2"),
}
FIELDS = {
    "depbar": (12, 4, 32, 6),
    "cctl": (12, 4, 24, 8, 32, 32),
    "ublkcp": (12, 4, 24, 8, 32, 8, 40, 8, 64, 8),
    "ublkpf": (12, 4, 24, 8, 64, 8),
}
PRODUCTION = {
    "depbar": [
        (0x000FC800000000000000003F0000791A, "DEPBAR {5,4,3,2,1,0}"),
    ],
    "cctl": [
        (0x000EA40009C080000000000010007540, "CCTL.E.C.LDCU.IV.DEEP [UR16]"),
        (0x004EA40009C080000000000012007540, "CCTL.E.C.LDCU.IV.DEEP [UR18]"),
        (0x000EA40009C080000000000040007540, "CCTL.E.C.LDCU.IV.DEEP [UR64]"),
    ],
    "ublkcp": [
        (0x0003E4000800120400000C0A080073BA, "UBLKCP.S.G [UR10], [UR8], UR4, desc[UR12]"),
        (0x0003E400080012040000100A080073BA, "UBLKCP.S.G [UR10], [UR8], UR4, desc[UR16]"),
        (0x0023E2000800120400000E080A0073BA, "UBLKCP.S.G [UR8], [UR10], UR4, desc[UR14]"),
    ],
    "ublkpf": [
        (0x0003F0000800000400000000080073BC, "UBLKPF.L2 [UR8], UR4"),
    ],
}


def put(word, shift, bits, value):
    mask = ((1 << bits) - 1) << shift
    return (word & ~mask) | ((value << shift) & mask)


def add(cases, family, case, word, role="adopt", kind="controlled"):
    key, group = META[family]
    cases.setdefault(word, {
        "word": word, "family": family, "case": case, "role": role, "kind": kind,
        "expected_key": key, "expected_group": group,
    })


def cases_for(family):
    cases = {}
    base = BASE[family]
    for word, text in PRODUCTION[family]:
        add(cases, family, "production", word, kind="production")
        assert text
    for guard in range(16):
        add(cases, family, f"guard-{guard}", put(base, 12, 4, guard))
    fields = FIELDS[family]
    for start in range(0, len(fields), 2):
        shift, bits = fields[start:start + 2]
        for bit in range(bits):
            add(cases, family, f"field-{shift + bit}", base ^ (1 << (shift + bit)))
    if family == "depbar":
        add(cases, family, "empty-mask", put(base, 32, 6, 0), role="reject")
        for mask in (1, 2, 4, 8, 16, 32, 21, 63):
            add(cases, family, f"mask-{mask}", put(base, 32, 6, mask))
    elif family == "cctl":
        for reg in (0, 1, 16, 18, 63, 64, 100, 254, 255):
            add(cases, family, f"address-{reg}", put(base, 24, 8, reg))
        for offset in (0, 1, 16, 0x10, 0x7FFFFFFF, -1, -16, -0x80000000):
            add(cases, family, f"offset-{offset}", put(base, 32, 32, offset & 0xFFFFFFFF))
    elif family == "ublkcp":
        for shift, name in ((32, "dst"), (24, "src"), (40, "desc"), (64, "size")):
            for reg in (0, 1, 8, 16, 63, 64, 100, 254, 255):
                add(cases, family, f"{name}-{reg}", put(base, shift, 8, reg))
    else:
        for shift, name in ((24, "address"), (64, "size")):
            for reg in (0, 1, 8, 16, 63, 64, 100, 254, 255):
                add(cases, family, f"{name}-{reg}", put(base, shift, 8, reg))
    field_bits = set()
    for start in range(0, len(fields), 2):
        shift, bits = fields[start:start + 2]
        field_bits.update(range(shift, shift + bits))
    # Bits 96..104 belong to the scheduling/control plane and are not encoding-row neighbours.
    for bit in range(96):
        if bit not in field_bits:
            add(cases, family, f"neighbour-{bit}", base ^ (1 << bit), role="reject")
    return list(cases.values())


def expected_shape(family, text):
    if not text or "?" in text or "INVALID" in text:
        return False
    head = text.split(" ", 2)[1] if text.startswith("@") else text.split(" ", 1)[0]
    return {
        "depbar": lambda: head == "DEPBAR" and "{" in text and ".LE" not in text,
        "cctl": lambda: head == "CCTL.E.C.LDCU.IV.DEEP",
        "ublkcp": lambda: head == "UBLKCP.S.G" and "desc[" in text,
        "ublkpf": lambda: head == "UBLKPF.L2" and "desc[" not in text,
    }[family]()


def probe(args):
    args.out.mkdir(parents=True, exist_ok=True)
    all_cases = {family: cases_for(family) for family in META}
    expected_production = sum(len(v) for v in PRODUCTION.values())
    assert expected_production == 8
    previous = None
    for arch, filename in ARCH.items():
        rows = []
        for family, cases in all_cases.items():
            words = cases
            inputs = [(case["word"], case["role"] == "reject") for case in words]
            result = nvprobe.probe_words(
                args.nvdisasm, f"k1_experts_{family}", inputs, CTRL[family],
                lambda _w, text, f=family: expected_shape(f, text),
                arch=arch, jobs=args.jobs)
            for case, record in zip(words, result):
                word = case["word"]
                record.update({key: value for key, value in case.items() if key != "word"})
                record["word"] = f"{word:032x}"
                if case["role"] == "reject":
                    record.pop("expected_key")
                    record.pop("expected_group")
                rows.append(record)
        rows.sort(key=lambda row: (row["family"], row["case"], row["word"]))
        signature = [(row["word"], row["case"], row["role"], row["nvidia_sass"]) for row in rows]
        if previous is not None:
            assert signature == previous, "SM103 and SM100 disagree"
        previous = signature
        output = args.out / filename
        nvprobe.write_fixture(output, rows)
        print(arch, len(rows), "records", sum(r["kind"] == "production" for r in rows),
              "production", sum(r["role"] == "reject" for r in rows), "rejected", "->", output)


def field(shift, bits, extraction, token):
    return nvprobe.field(shift, bits, extraction, token, SRC)


def make_row(family):
    guard = field(12, 4, "guard", 0)
    if family == "depbar":
        fields = [guard, field(32, 6, "imm", 1)]
        base = DEPBAR & ~(0xF << 12) & ~(0x3F << 32)
    elif family == "cctl":
        fields = [guard, field(24, 8, "sub_ur0", 1), field(32, 32, "sub_imm1", 1)]
        base = CCTL & ~(0xF << 12) & ~(0xFF << 24) & ~(0xFFFFFFFF << 32)
    elif family == "ublkcp":
        fields = [guard, field(32, 8, "sub_ur0", 1), field(24, 8, "sub_ur0", 2),
                  field(64, 8, "ureg", 3), field(40, 8, "desc_ur", 4)]
        base = UBLKCP & ~(0xF << 12) & ~(0xFF << 24) & ~(0xFF << 32)
        base &= ~(0xFF << 40) & ~(0xFF << 64)
    else:
        fields = [guard, field(24, 8, "sub_ur0", 1), field(64, 8, "ureg", 2)]
        base = UBLKPF & ~(0xF << 12) & ~(0xFF << 24) & ~(0xFF << 64)
    mask = nvprobe.field_mask(fields)
    assert base & mask == 0
    result = nvprobe.row(base, fields, SRC,
        "K1 ExpertsKernel production anchors plus nvdisasm 13.3.73 SM103/SM100 guard/operand sweeps. "
        "Only the measured fields are in the mask; all neighbouring one-bit cases outside them remain "
        "unclaimed. The DEPBAR row is the brace-list mask, not DEPBAR.LE. The CCTL row is the uniform "
        "opcode with signed offset, not opcode 0x98f. Encoding evidence only: no GPU execution.")
    if family == "depbar":
        result["claim_forbid"] = [{"shift": 32, "bits": 6, "values": [0]}]
    return result


def donor_entry(table, donor, sig, base_op, row, group):
    entry = copy.deepcopy(table["instructions"][donor])
    entry.pop("encode_only", None)
    entry.pop("_note", None)
    entry["base_op"] = base_op
    entry["operand_sig"] = sig
    entry["mod_groups"] = {group: row}
    return entry


def insert_after(table, donor, additions):
    rebuilt = {}
    for key, value in table["instructions"].items():
        rebuilt[key] = value
        if key == donor:
            rebuilt.update(additions)
    assert len(rebuilt) == len(table["instructions"]) + len(additions)
    table["instructions"] = rebuilt


def apply(tables):
    source = {
        "rows": 4,
        "kind": "nvdisasm 13.3.73 K1 production anchors and SM103/SM100 field/neighbour probes",
        "date": "2026-11-10",
        "tool": "tools/probes/re_k1_experts_forms.py",
        "test": "tests/k1_experts_forms.rs",
        "note": ("K1 ExpertsKernel forms measured by editable text and exact words on SM103 and SM100. "
                 "Four new rows whose masks are exactly the measured fields; neighbouring one-bit cases fail closed. "
                 "No instruction was executed on a GPU."),
    }
    for path in tables:
        table = nvprobe.load_table(path)
        insert_after(table, "DEPBAR_II_II", {
            "DEPBAR_II": donor_entry(table, "DEPBAR_II_II", "II", "DEPBAR", make_row("depbar"), ""),
        })
        insert_after(table, "CCTL_ARI", {
            "CCTL_AURI": donor_entry(table, "CCTL_ARI", "AURI", "CCTL", make_row("cctl"), META["cctl"][1]),
        })
        insert_after(table, "UBLKCP_AURI_AURI_UR", {
            "UBLKCP_AURI_AURI_UR_II": donor_entry(table, "UBLKCP_AURI_AURI_UR", "AURI_AURI_UR_II",
                                                  "UBLKCP", make_row("ublkcp"), "G,S"),
        })
        insert_after(table, "UBLKCP_AURI_AURI_UR_II", {
            "UBLKPF_AURI_UR": donor_entry(table, "UBLKCP_AURI_AURI_UR", "AURI_UR",
                                          "UBLKPF", make_row("ublkpf"), "L2"),
        })
        provenance = table["_meta"]["provenance"]
        if SRC in provenance["sources"]:
            assert provenance["sources"][SRC] == source
        provenance["sources"][SRC] = source
        nvprobe.save_table(path, table)
        print(path, "+4 rows", provenance["rows_total"])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    pr = sub.add_parser("probe")
    pr.add_argument("--nvdisasm", default="/usr/local/cuda/bin/nvdisasm")
    pr.add_argument("--out", type=pathlib.Path, required=True)
    pr.add_argument("--jobs", type=int, default=16)
    ap = sub.add_parser("apply")
    ap.add_argument("tables", nargs="+", type=pathlib.Path)
    args = parser.parse_args()
    if args.command == "probe":
        probe(args)
    else:
        apply(args.tables)


if __name__ == "__main__":
    main()

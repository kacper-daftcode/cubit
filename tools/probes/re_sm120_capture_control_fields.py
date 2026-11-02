#!/usr/bin/env python3
"""Measured SM120 control/copy fields from native DS4.1 CUPTI captures.

No instruction overlays: each row declares editable NVIDIA operands. Use
--apply --table PATH to update a table; otherwise this script does not write it.
--probe-output saves independent NVIDIA bit/field witnesses for replay.
"""
import argparse
import concurrent.futures
import copy
import json
import os
from pathlib import Path
import subprocess
import tempfile

PROVENANCE = "sm120-native-capture-control-2026-10-22"
SCHEDULE = ((1 << 17) - 1) << 105
ANCHORS = {
    "UBLKCP": 0x0001e4000800120400000c08060073ba,
    "QSPC": 0x000ee400000003000000000008ff73aa,
    "USETMAXREG": 0x000e240008020600000000b0000079c8,
    "SYNCS": 0x000e64000802110900000003ff0075a7,
    "BRA_UP_ANY": 0x000fec000b93ffffffffffe9004c7547,
    "LDGSTS_0DAE": 0x0001c0000b980a0000000010ff800dae,
    "LDGSTS_MEMBER": 0x000fe200081a021800000010ffbc7dae,
}


def field(shift, bits, extraction, token):
    return dict(shift=shift, bits=bits, extraction=extraction,
                token_idx=token, _src=PROVENANCE)


def row(anchor, fields, note):
    mask = 0
    for f in fields:
        part = ((1 << f["bits"]) - 1) << f["shift"]
        assert not mask & part
        mask |= part
    return dict(and_base=f"0x{anchor & ~SCHEDULE & ~mask:032x}",
                variable_mask=f"0x{mask:032x}", fields=fields,
                count=None, _src=PROVENANCE, _note=note)


def apply(path):
    db = json.loads(path.read_bytes())
    ins = db["instructions"]
    guard = field(12, 4, "guard", 0)
    bulk = copy.deepcopy(ins["UBLKCP_AURI_AURI_UR"])
    bulk.pop("encode_only", None)
    bulk["operand_sig"] = "AURI_AURI_UR_II"
    bulk["mod_groups"] = {"G,S": row(ANCHORS["UBLKCP"], [guard,
        field(32, 8, "sub_ur0", 1), field(24, 8, "sub_ur0", 2),
        field(64, 8, "ureg", 3), field(40, 8, "desc_ur", 4)],
        "NVIDIA13.1 native UBLKCP.S.G with explicit descriptor: full UR bytes32/24/64/40; descriptor-present bit76 fixed. Five-value sweeps on each UR include literalUR63 and URZ255.")}
    ins["UBLKCP_AURI_AURI_UR_II"] = bulk

    ins["QSPC_P_R_ARI"]["mod_groups"]["E,L"] = row(ANCHORS["QSPC"], [guard,
        field(81, 3, "pred", 1), field(16, 8, "reg", 2),
        field(24, 8, "sub_r0", 3), field(40, 24, "sub_imm1", 3)],
        "NVIDIA13.1 QSPC.E.L predicate81, resultR16, localbaseR24 and signedoffset24@40; full predicate/register/signedoffset probes.")
    ins["USETMAXREG_UP_II"]["mod_groups"]["CTAPOOL,TRY_ALLOC"] = row(ANCHORS["USETMAXREG"], [guard,
        field(81, 3, "upred", 1), field(32, 10, "imm", 2)],
        "NVIDIA13.1 USETMAXREG.TRY_ALLOC.CTAPOOL uniform resultpredicate81 (not guard15), immediate10bits@32; isolated bit32..47 walk shows only32..41 contribute to the count. Uniform executionguard12 is independently measured.")

    sync_proto = copy.deepcopy(ins["SYNCS_P_ARURI_R"])
    for signature, with_base in [("P_ARURI_R", True), ("P_AURI_R", False)]:
        fixed = copy.deepcopy(sync_proto)
        fixed.pop("encode_only", None)
        fixed["operand_sig"] = signature
        fixed["mod_groups"] = {}
        for trywait in [False, True]:
            anchor = (ANCHORS["SYNCS"] & ~(1 << 72)) | (int(trywait) << 72)
            fields = [guard, field(81, 3, "pred", 1), field(64, 8, "sub_ur1", 2),
                      field(40, 24, "sub_imm1", 2), field(32, 8, "reg", 3)]
            if with_base:
                fields.append(field(24, 8, "sub_r0", 2))
            modifiers = "PHASECHK,TRANS64" + (",TRYWAIT" if trywait else "")
            fixed["mod_groups"][modifiers] = row(anchor, fields,
                "NVIDIA13.1 SYNCS.PHASECHK.TRANS64[.TRYWAIT]: P81 is3bits, addressR24/UR64/signedoffset24@40, dataR32. AURI has fixed RZbase and must retain predicate81 rather than writing an unrelated R16 byte.")
        ins[f"SYNCS_{signature}"] = fixed

    ins["BRA_UP_II"]["mod_groups"]["ANY,U"] = row(ANCHORS["BRA_UP_ANY"], [guard,
        field(24, 3, "upred", 1), field(27, 1, "inv", 1),
        field(16, 8, "imm_shr2", 2), field(34, 48, "imm_shr10", 2)],
        "NVIDIA13.1 BRA.U.ANY uniformpredicate24/inversion27, ANYbit84, opcode547, Umodebit32; complete signedq56 dwordtarget. Raw oracle must use its logical PC when comparing absolute branch targets.")

    # A real native bootstrap witness also exposed a ninth destination
    # register bit accidentally borrowed from the global-address base.
    for member in [False, True]:
        suffix = "_P" if member else ""
        prototype = copy.deepcopy(ins[f"LDGSTS_ARURI_ARI{suffix}"])
        for has_base in [True, False]:
            fixed = copy.deepcopy(prototype)
            fixed["operand_sig"] = ("ARURI" if has_base else "AURI") + "_ARI" + suffix
            fixed["mod_groups"] = {}
            for modifiers, old in prototype["mod_groups"].items():
                anchor = int(old["and_base"], 16)
                if not has_base:
                    anchor = (anchor & ~(255 << 16)) | (255 << 16)
                fields = [guard, field(44, 20, "sub_imm1", 1), field(64, 8, "sub_ur1", 1),
                          field(24, 8, "sub_r0", 2), field(32, 12, "sub_imm1", 2)]
                if has_base:
                    fields.append(field(16, 8, "sub_r0", 1))
                if member:
                    fields.extend([field(87, 3, "pred", 3), field(90, 1, "inv", 3)])
                group = row(anchor, fields,
                    "NVIDIA13.1 native0xdae: sharedR8@16 (not9), sharedUR8@64, signedsharedoffset20@44; globalR8@24 and signedglobaloffset12@32; optional P87/inversion90. Full field sweeps cover registers and both offset sign boundaries. AURI fixes sharedbaseRZ rather than borrowing the globalbasebit24.")
                if member:
                    group["claim_forbid"] = [dict(shift=87, bits=4, values=[7])]
                fixed["mod_groups"][modifiers] = group
            ins[f"LDGSTS_{fixed['operand_sig']}"] = fixed
    temp = path.with_name(path.name + ".native-control.tmp")
    temp.write_text(json.dumps(db, indent=1, ensure_ascii=True) + "\n")
    os.replace(temp, path)


def probes():
    result = [(name, "anchor", word) for name, word in ANCHORS.items()]
    specs = [("UBLKCP", shift, 8, [0, 1, 31, 63, 255]) for shift in [24, 32, 40, 64]]
    specs += [("QSPC",81,3,[0,1,7]), ("QSPC",16,8,[0,17,255]),
              ("QSPC",24,8,[0,17,255]), ("QSPC",40,24,[1,16,0xffffff]),
              ("USETMAXREG",81,3,[0,1,7]), ("USETMAXREG",12,4,[0,8,7]),
              ("USETMAXREG",32,32,[0,1,255,256,65535]),
              ("SYNCS",81,3,[0,1,7]), ("SYNCS",24,8,[0,17,255]),
              ("SYNCS",64,8,[0,17,255]), ("SYNCS",32,8,[0,17,255]),
              ("SYNCS",40,24,[1,16,0xffffff]), ("SYNCS",72,1,[0,1]),
              ("LDGSTS_MEMBER",87,4,[0,3,7,8,15]),
              ("BRA_UP_ANY",24,3,[0,1,7]), ("BRA_UP_ANY",27,1,[0,1])]
    for shift, bits, values in [(16,8,[0,1,127,128,254,255]), (24,8,[0,1,127,128,254,255]),
                                (64,8,[0,1,127,128,254,255]), (32,12,[0,1,16,2047,2048,4095]),
                                (44,20,[0,1,16,524287,524288,1048575])]:
        specs.append(("LDGSTS_0DAE", shift, bits, values))
    for name, shift, bits, values in specs:
        for value in values:
            word = (ANCHORS[name] & ~(((1 << bits) - 1) << shift)) | (value << shift)
            result.append((name, f"field{shift}_{value}", word))
    for bit in range(32,48):
        result.append(("USETMAXREG", f"imm_bit{bit}",
                       (ANCHORS["USETMAXREG"] & ~(0xffffffff << 32)) | (1 << bit)))
    return result


def probe_all(binary, output, jobs):
    def one(item):
        family, name, word = item
        with tempfile.NamedTemporaryFile(suffix=".bin") as temp:
            temp.write(word.to_bytes(16, "little")); temp.flush()
            proc = subprocess.run([str(binary), "-raw", "-ndf", "-b", "SM120", temp.name],
                                  capture_output=True, text=True)
        return dict(family=family, probe=name, word=f"{word:032x}",
                    returncode=proc.returncode, stdout=proc.stdout, stderr=proc.stderr)
    with concurrent.futures.ThreadPoolExecutor(max_workers=jobs) as pool:
        records = list(pool.map(one, probes()))
    output.write_text(json.dumps(records, indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--table", type=Path)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--probe-output", type=Path)
    parser.add_argument("--nvdisasm", type=Path, default=Path("/usr/local/lib/python3.12/dist-packages/triton/backends/nvidia/bin/nvdisasm"))
    parser.add_argument("--jobs", type=int, default=2)
    args = parser.parse_args()
    if args.probe_output:
        probe_all(args.nvdisasm, args.probe_output, args.jobs)
    if args.apply:
        parser.error("--apply requires --table") if args.table is None else apply(args.table)


if __name__ == "__main__":
    main()

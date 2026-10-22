#!/usr/bin/env python3
"""Reproduce DSv4.1 SM120 field probes and apply measured canonical row repairs.

The probe oracle is NVIDIA nvdisasm. All variants are independently constructed
from fixed corpus witnesses plus one changed bit or one replaced operand field;
no original instruction bits are overlaid onto assembled output.
"""
import argparse
import concurrent.futures
import copy
import json
import hashlib
import pathlib
import re
import subprocess
import tempfile

ANCHORS = {
    "CS2R": "000fe2000001ff000000000000107805",
    "P2R": "000fe2000000000000000040ff567803",
    "BREAK": "001fea0003800000000000000000791b",
    "CCTL_IVALL": "000fe2000200000000000000ff00798f",
    "F2FP_UNPACK_B": "080fe400020006ff00000016ff43723e",
    "F2FP_UNPACK_A": "000fe200030006ff00000018ff18723e",
    "LDG_NEW_POLICY": "000168000c5e9d00000000080610a981",
    "UIADD3_64": "000fe2000fffe0ff0000000406067297",
    "LEA_HI_X": "040fe200008f140f000000ff161b7211",
    "BREAK_RELIABLE": "000fea00038001000000000000007942",
    "SEL64": "000fc600048000000000000814147407",
    "SEL": "000fe4000c8000000000000a18187c07",
    "ISETP_U64": "002fdc00087144700000000c10007c0c",
    "SHF_U64": "0c0fe4000001021d00000014171d7219",
    "UFFMA_RR_RI": "000fc600080000073b12492506067455",
    "UFFMA_RR_RF": "000fe200080008063f80000007067455",
    "USEL64": "000fe2000c0000000000000c06187c87",
    "UVIMNMX": "000fc4000bfe01000000000c140c724a",
    "VIMNMX": "000fe20003fe11000000000207027248",
    "UFADD": "000fe20008010100bfe00000ff0a7454",
    "WARPSYNC_COLLECTIVE": "001fea0003c00000000000000a087348",
    "CALL_ABS_REG": "00afea0003c000000000000002007343",
    "LEPC": "000fce0000000000000000001014794e",
    "BAR_II_II": "000fe2000001000000c1000000007b1d",
    "BAR_II_R": "0009ec000001000003c000030000791d",
    "BAR_R_R": "0001e40000010000000000200000731d",
    "WARPSYNC_ALL": "03afea0003c000000000000000187948",
    "BRA_CONV": "000fea000b8000000000000304307947",
    "ISETP_RR64": "000fdc0003f560700000001a2000720c",
    "ISETP_RI64": "000fe40006fd4270ffffffff2e00780c",
    "ISETP_RU64": "000fc8000bf112700000000402007c0c",
    "F2FP_E2M1_PACK": "000fe200042070ff000000070000723e",
    "MEMBAR_CTA": "000fec00000080000000000000007992",
    "MEMBAR_GPU": "000fec000000a0000000000000007992",
    "EXIT_P": "001fea0001000000000000000000994d",
    "BAR_RED_R_R": "0001e400030148000000000d0000731d",
    "BAR_RED_II_R": "0001ec000001480003c000210000791d",
    "BAR_RED_II_II": "000fec00030148000343800000007b1d",
    "BMOV_355": "000e2a00001000000000000009007355",
    "BMOV_356": "0081ea00000000000000000506007356",
    "B2R_RESULT": "000e2400000c40000000000000ff731c",
    "R2P": "000fc60000000000000000240c007804",
    "CALL_ABS_IMM": "000fea0003c000000000000000007943",
    "CALL_REL_IMM": "000fea0003c000000000000000007944",
    "F2FP_BF16_PACK": "000fc600000030ff0000001c2323723e",
    "F2FP_F16_PACK": "000fc600000020ff0000001c2323723e",
    "BRA_PRED_NEG": "000fea000500000000000004002c9947",
    "RET_ABS_REG": "000fec0003e000000000000014007950",
    "SEL64_UR": "000fc8000c0000000000000404047e07",
    "F2FP_F16_MERGE": "000fe400048032ff00000005ff05723e",
    "WARPSYNC_REG": "000fea00038000000000000008007348",
    "MEMBAR_SC": "000fec00000030000000000000007992",
    "BRA_U_ANY": "002fea000393fffffffffffd00ec0947",
    "BRX_REG": "000fea000383ffffffffffd8225c7949",
    "BRXU_UREG": "001fea000b83fffffffffff404a47958",
    "NANOSLEEP": "000fea0003800000000001180000795d",
    "F2FP_E2M1_UNPACK_B": "000fe400020402ff00000011ff11723e",
    "ISETP32_RUR": "020fe2000c725a700000000710007c0c",
    "RPCMOV_READ": "000fda00000000000000000000027353",
    "RPCMOV_WRITE": "000fcc00000000000000000200007352",
    "BREAK_PLAIN": "000fea00038000000000000000030942",
    "BAR_ARV_II_II": "000ff0000000200001c6000000000b1d",
    "BAR_ARV_R_R": "0003ec00000020000000001a0000731d",
    "UGETNEXTWORKID": "000fec000800010000000000040073ca",
    "UVIMNMX_RELU": "000fe2000ffe1100000000050412724a",
}

PROVENANCE = "dsv41-sm120-2026-10-22"
SCHEDULE = ((1 << 17) - 1) << 105


def field(shift, bits, extraction, token):
    return {"bits": bits, "extraction": extraction, "shift": shift,
            "token_idx": token, "_src": PROVENANCE}


def row(anchor, fields, note, allow_alias=False):
    mask = sum((((1 << f["bits"]) - 1) << f["shift"]) for f in fields)
    # The listed independently verified fields are disjoint.
    union = 0
    for f in fields:
        union |= ((1 << f["bits"]) - 1) << f["shift"]
    assert allow_alias or mask == union
    mask = union
    return {"and_base": f"0x{int(anchor, 16) & ~SCHEDULE & ~mask:032x}",
            "count": None, "fields": fields, "variable_mask": f"0x{mask:032x}",
            "_src": PROVENANCE, "_note": note}


def apply(table_path):
    path = pathlib.Path(table_path)
    before = path.read_bytes()
    table = json.loads(before)
    ins = table["instructions"]
    guard = field(12, 4, "guard", 0)
    csfields = [guard, field(16, 8, "reg", 1), field(72, 8, "sysreg", 2)]
    ins["CS2R_R_L"]["mod_groups"][""] = row(ANCHORS["CS2R"], csfields,
        "NVIDIA 13.1 bit/field sweeps: Rd[23:16], system-register ID[79:72]; bit80 selects 64-bit/plain vs .32.")
    ins["CS2R_R_L"]["mod_groups"]["32"] = row(
        f"{int(ANCHORS['CS2R'], 16) & ~(1 << 80):032x}", csfields,
        "CS2R.32: same measured register fields, bit80=0.")

    p2r = copy.deepcopy(ins["P2R_R_L_R_II"])
    p2r.pop("encode_only", None)
    p2r["operand_sig"] = "R_II_R_II"
    p2r["mod_groups"] = {"": row(ANCHORS["P2R"], [guard,
        field(16, 8, "reg", 1), field(24, 8, "reg", 3),
        field(32, 8, "imm", 4), field(122, 1, "reuse", 3)],
        "PR is the fixed predicate-file source token; Rd[23:16], source R[31:24], maskimm8[39:32]. Both register and mask sweeps cover 0..255.")}
    for byte in range(1, 4):
        selected = copy.deepcopy(p2r["mod_groups"][""])
        selected["and_base"] = f"0x{int(selected['and_base'], 16) | (byte << 76):032x}"
        selected["_note"] += " Opcode .B1/.B2/.B3 selects byte via bits[77:76], independently bit-probed."
        p2r["mod_groups"][f"B{byte}"] = selected
    ins["P2R_R_II_R_II"] = p2r
    for key, entry in ins.items():
        if key.startswith("P2R") and key != "P2R_R_II_R_II":
            entry["encode_only"] = True

    f2fields = [guard, field(16, 8, "reg", 1), field(32, 8, "reg", 2),
                field(123, 1, "reuse", 2), field(88, 1, "opmod:H1", 2)]
    for datatype, type_delta in [("E4M3", 0), ("E5M2", 1 << 73),
                                 ("E3M2", 1 << 82), ("E2M1", (1 << 82) | (1 << 74))]:
        anchor = f"{int(ANCHORS['F2FP_UNPACK_B'], 16) ^ type_delta:032x}"
        unpack_fields = f2fields if datatype != "E2M1" else [f for f in f2fields if f["extraction"] != "opmod:H1"]
        fixed = row(anchor, unpack_fields,
            "NVIDIA 13.1: UNPACK_B has two operands; source[39:32], .reuse=bit123, source.H1=bit88. Bits24..31/64..71 are not extra register operands.")
        group = f"F16,{datatype},UNPACK_B"
        ins["F2FP_R_R"]["mod_groups"][group] = copy.deepcopy(fixed)
        dotted_key = f"F2FP.F16.{datatype}.UNPACK_B_R_R"
        dotted = copy.deepcopy(ins.get(dotted_key, ins["F2FP_R_R"]))
        dotted.pop("encode_only", None)
        dotted["base_op"] = f"F2FP.F16.{datatype}.UNPACK_B"
        dotted["operand_sig"] = "R_R"
        dotted["mod_groups"] = {"": copy.deepcopy(fixed)}
        ins[dotted_key] = dotted
        for old_group in [group, f"{datatype},F16,UNPACK_B"]:
            if old_group in ins["F2FP_R_R_R_R"]["mod_groups"]:
                ins["F2FP_R_R_R_R"]["mod_groups"][old_group]["encode_only"] = True

    cctl = row(ANCHORS["CCTL_IVALL"], [guard],
        "NVIDIA 13.1: CCTL.IVALL has opcode0x98f, cache operationbit89=1, no operands. The old 0x98e row decoded to REDG.DEC.")
    ins["CCTL"]["mod_groups"]["IVALL"] = copy.deepcopy(cctl)
    ins["CCTL.IVALL"]["mod_groups"][""] = copy.deepcopy(cctl)
    for key in ["CCTL.IVALL_?_?", "CCTL.IVALL_P"]:
        ins[key]["encode_only"] = True

    # Two old bootstrap names were wrong even though their payloads could
    # round-trip. NVIDIA distinguishes MATCH.ALL's predicate destination
    # from MATCH.ANY (modebit79), and 0x98e is REDG, never CCTL.IVALL.
    match_any = row("000fea00000e800000000000000073a1", [guard,
        field(16, 8, "reg", 1), field(24, 8, "reg", 2), field(122, 1, "reuse", 2)],
        "NVIDIA13.1 MATCH.ANY uses modebit79=1 and fixed PT resultpredicate81; fullRd16/Rsrc24 fields. Legacy dotted ANY alias carried ALL's modebit79=0.")
    ins["MATCH_R_R"]["mod_groups"]["ANY"] = copy.deepcopy(match_any)
    ins["MATCH.ANY_R_R"]["mod_groups"] = {"": copy.deepcopy(match_any)}
    match_all = copy.deepcopy(ins["MATCH_R_R"])
    match_all["operand_sig"] = "P_R_R"
    match_all["mod_groups"] = {"ALL": row("000fea00000e000000000000000073a1", [guard,
        field(81, 3, "pred", 1), field(16, 8, "reg", 2), field(24, 8, "reg", 3),
        field(122, 1, "reuse", 3)],
        "NVIDIA13.1 MATCH.ALL modebit79=0, destinationpredicate81 (full P0..PT sweep), fullRd16/Rsrc24. PT remains an explicit output operand.")}
    ins["MATCH_P_R_R"] = match_all
    ins["REDG_ARI_R"]["mod_groups"]["ADD,EF"] = row("000fea000000000000000000ff00798e", [guard,
        field(24, 8, "sub_r0", 1), field(40, 24, "sub_imm1", 1), field(32, 8, "reg", 2)],
        "NVIDIA13.1 REDG.ADD.EF packet0x98e with plain addressR8@24, signedoffset24@40, dataR8@32; sixbase/data/offset probes. The old CCTL.IVALL bootstrap word is exactly this semantic instruction.")

    end = ins["ENDCOLLECTIVE"]
    end["mod_groups"] = {"": row(ANCHORS["BREAK"], [guard],
        "NVIDIA 13.1: opcode0x91b is ENDCOLLECTIVE; default predicatePT at[89:87], no barrier operand.")}
    endpred = copy.deepcopy(end)
    endpred["operand_sig"] = "P"
    endpred["mod_groups"] = {"": row(ANCHORS["BREAK"], [guard,
        field(87, 3, "pred", 1), field(90, 1, "neg", 1)],
        "ENDCOLLECTIVE explicit member predicate: P[89:87], negationbit90. Predicate sweep0..7 and bit90 verified with NVIDIA13.1.")}
    ins["ENDCOLLECTIVE_P"] = endpred
    # This old broad row claimed ENDCOLLECTIVE via variable opcode bits.
    # BREAK.RELIABLE uses the separately measured 0x942 form instead.
    reliable = ins["BREAK_P_B"]["mod_groups"]["RELIABLE"]
    reliable.update(row("000fea00038001000000000000007942", [guard,
        field(87, 3, "pred", 1), field(90, 1, "neg", 1), field(16, 4, "barrier", 2)],
        "Replace broad opcode0x902 alias that absorbed ENDCOLLECTIVE with BREAK.RELIABLE0x942 geometry."))

    ldg = ins["LDG_R_dARI"]["mod_groups"]
    for group, donor in list(ldg.items()):
        mods = group.split(",")
        if "CONSTANT" in mods and "NA" not in mods:
            fixed = copy.deepcopy(donor)
            fixed["and_base"] = f"0x{int(donor['and_base'], 16) | (1 << 86):032x}"
            fixed["variable_mask"] = f"0x{int(donor['variable_mask'], 16) & ~(1 << 86):032x}"
            fixed["_src"] = PROVENANCE
            fixed["_note"] = "NVIDIA13.1: descriptor LDG.CONSTANT + bit86 selects .NA. Fields clone same-width .CONSTANT sibling; bit86 toggle removes .NA only."
            ldg[",".join(sorted(mods + ["NA"]))] = fixed

    ui = ins["UIADD3.64_UR_UP_UP_UR_UR_UR"]
    ui["mod_groups"][""] = row(ANCHORS["UIADD3_64"], [guard,
        field(16, 8, "ureg", 1), field(81, 3, "upred", 2), field(84, 3, "upred", 3),
        field(24, 8, "ureg", 4), field(32, 8, "ureg", 5), field(64, 8, "ureg", 6),
        field(72, 1, "neg", 4), field(63, 1, "neg", 5), field(75, 1, "neg", 6)],
        "NVIDIA13.1 full-byte register sweeps: UR[23:16]/[31:24]/[39:32]/[71:64]; odd register values are printed verbatim. Old shifted narrow fields doubled authored register indices.")

    for f in ins["LEA_R_R_R_R_II_P"]["mod_groups"]["HI,X"]["fields"]:
        if f["extraction"] == "reuse" and f["shift"] == 124:
            f["token_idx"] = 4
            f["_src"] = PROVENANCE

    select_fields = [guard, field(16, 8, "reg", 1), field(24, 8, "reg", 2),
                     field(32, 8, "ureg", 3), field(87, 3, "pred", 4),
                     field(90, 1, "neg", 4), field(122, 1, "reuse", 2)]
    ins["SEL_R_R_UR_P"]["mod_groups"][""] = row(ANCHORS["SEL"], select_fields,
        "NVIDIA13.1: uniform source occupies fullbyte32; selector is predicate[89:87] and negate90, not a two-bit integer field.")
    select_imm = [guard, field(16, 8, "reg", 1), field(24, 8, "reg", 2),
                  field(32, 33, "imm", 3), field(87, 3, "pred", 4), field(90, 1, "neg", 4)]
    ins["SEL_R_R_II_P"]["mod_groups"]["64"] = row(ANCHORS["SEL64"], select_imm,
        "NVIDIA13.1: SEL.64 opcode0x407 has signed33-bit immediate[64:32], not a uniform source; bit64 is sign/bit32, not imm>>3.")
    ins["SEL_R_R_UR_P"]["mod_groups"]["64"] = row(ANCHORS["SEL64_UR"], select_fields,
        "NVIDIA13.1 SEL.64 uniform-source opcode0xe07 retains fullRd/Ra/URb fields16/24/32 and predicate87,neg90; distinct fromimmediateopcode0x407.")

    compare = row(ANCHORS["ISETP_U64"], [guard, field(81, 3, "pred", 1),
        field(84, 3, "pred", 2), field(24, 8, "reg", 3), field(32, 8, "ureg", 4),
        field(87, 3, "pred", 5), field(90, 1, "neg", 5), field(122, 1, "reuse", 3)],
        "NVIDIA13.1: ISETP.GT.U64.OR includes booleanOR bit74; clearbit74 selectsAND. Fullpredicateandregister field sweeps verified.")
    ins["ISETP_P_P_R_UR_P"]["mod_groups"]["GT,OR,U64"] = compare
    compare_and = copy.deepcopy(compare)
    compare_and["and_base"] = f"0x{int(compare_and['and_base'], 16) & ~(1 << 74):032x}"
    ins["ISETP_P_P_R_UR_P"]["mod_groups"]["AND,GT,U64"] = compare_and

    for f in ins["SHF_R_R_R_R"]["mod_groups"]["HI,L,U64"]["fields"]:
        if f["extraction"] == "reuse" and f["shift"] == 124:
            f["token_idx"] = 4
            f["_src"] = PROVENANCE

    ins["UFFMA_UR_UR_UR_FI"]["mod_groups"][""] = row(ANCHORS["UFFMA_RR_RI"], [guard,
        field(16, 8, "ureg", 1), field(24, 8, "ureg", 2), field(72, 1, "neg", 2),
        field(73, 1, "abs", 2), field(64, 8, "ureg", 3), field(75, 1, "neg", 3),
        field(74, 1, "abs", 3), field(32, 32, "f32", 4)],
        "NVIDIA13.1: immediate is f32[63:32], Ra negate72/abs73 and Rb negate75/abs74; UR sourcefield64 is distinct from floatingaddend32.")
    for key in ["UFFMA_UR_UR_UR_L", "UFFMA_UR_UR_UR_II"]:
        ins[key]["encode_only"] = True

    uselect_fields = [guard, field(16, 8, "ureg", 1), field(24, 8, "ureg", 2),
                      field(32, 8, "ureg", 3), field(87, 3, "upred", 4), field(90, 1, "neg", 4)]
    uselect = row(ANCHORS["USEL64"], uselect_fields,
        "NVIDIA13.1: USEL.64 uses three fullbyte uniformregister fields and trailing uniformpredicate[89:87]/neg90. No register doubling or fourthUR operand.")
    ins["USEL_UR_UR_UR_UP"]["mod_groups"]["64"] = copy.deepcopy(uselect)
    ins["USEL.64_UR_UR_UR_UP"]["mod_groups"][""] = copy.deepcopy(uselect)
    ins["USEL.64_UR_UR_UR_UR"]["encode_only"] = True

    uniform_min_fields = [guard, field(16, 8, "ureg", 1), field(24, 8, "ureg", 2),
                          field(32, 8, "ureg", 3), field(87, 3, "upred", 4), field(90, 1, "neg", 4)]
    for datatype, selector in [("U32", 0), ("S32", 1), ("U16x2", 2), ("S16x2", 3), ("U8x4", 4), ("S8x4", 5)]:
        for relu in [False, True]:
            anchor = replace(int(ANCHORS["UVIMNMX"], 16), 72, 3, selector)
            anchor = replace(anchor, 76, 1, int(relu))
            uniform = row(f"{anchor:032x}", uniform_min_fields,
                "NVIDIA13.1 UVIMNMX fullbyteUR16/24/32,uniformpredicate87/neg90; typeenum[74:72]=U32,S32,U16x2,S16x2,U8x4,S8x4; RELU76.")
            modifiers = [datatype] + (["RELU"] if relu else [])
            ins["UVIMNMX_UR_UR_UR_UP"]["mod_groups"][",".join(sorted(modifiers))] = copy.deepcopy(uniform)
            dotted_uniform = ins.get(f"UVIMNMX.{datatype}_UR_UR_UR_UP")
            if dotted_uniform is not None and not relu:
                dotted_uniform["mod_groups"][""] = copy.deepcopy(uniform)
    ins["UVIMNMX_UR_UR_UR_P"]["encode_only"] = True
    uniform_imm = copy.deepcopy(ins["UVIMNMX_UR_UR_II_UP"])
    uniform_imm.pop("encode_only", None)
    uniform_imm["mod_groups"] = {}
    uniform_imm_fields = [guard, field(16, 8, "ureg", 1), field(24, 8, "ureg", 2),
        field(32, 32, "imm", 3), field(87, 3, "upred", 4), field(90, 1, "inv", 4),
        field(122, 1, "reuse", 2)]
    for datatype, selector in [("U32", 0), ("S32", 1), ("U16x2", 2), ("S16x2", 3), ("U8x4", 4), ("S8x4", 5)]:
        for relu in [False, True]:
            anchor = 0x000fc6000bfe0000000000010607784a | (selector << 72) | (int(relu) << 76)
            fixed = row(f"{anchor:032x}", uniform_imm_fields,
                "NVIDIA13.1 UVIMNMX immediate packet0x84a: fullUR16/24, literal32@32, UP87/inversion90, typeenum72..74 and RELU76 independently swept. Legacy P-signature mislabeled U32 as S32 and lost uniform predicate inversion.")
            modifiers = [datatype] + (["RELU"] if relu else [])
            uniform_imm["mod_groups"][",".join(sorted(modifiers))] = fixed
            dotted = ins.get(f"UVIMNMX.{datatype}_UR_UR_II_UP")
            if dotted is not None and not relu:
                dotted.pop("encode_only", None)
                dotted["mod_groups"] = {"": copy.deepcopy(fixed)}
    ins["UVIMNMX_UR_UR_II_UP"] = uniform_imm
    for key, legacy in ins.items():
        if key.startswith("UVIMNMX") and ("_II_P" in key or "_II_?" in key):
            legacy["encode_only"] = True
    # Non-uniform VIMNMX's complete six-type family is owned by
    # re_sm120_tensor_fields.py, including these S32/U32 witnesses.

    ufadd = copy.deepcopy(ins["UFADD_UR_UR_II"])
    ufadd.pop("encode_only", None)
    ufadd["operand_sig"] = "UR_UR_FI"
    ufadd["mod_groups"] = {}
    for ftz in [False, True]:
        anchor = int(ANCHORS["UFADD"], 16)
        if not ftz:
            anchor &= ~(1 << 80)
        ufadd["mod_groups"]["FTZ" if ftz else ""] = row(f"{anchor:032x}", [guard,
            field(16, 8, "ureg", 1), field(24, 8, "ureg", 2), field(72, 1, "neg", 2),
            field(73, 1, "abs", 2), field(32, 32, "f32", 3)],
            "NVIDIA13.1: UFADD immediatef32@[63:32], Ra neg72/abs73, FTZbit80; full8-bit URdest/source.")
    ins["UFADD_UR_UR_FI"] = ufadd
    ins["UFADD_UR_UR_II"]["encode_only"] = True

    collective_fields = [guard, field(24, 8, "reg", 1), field(16, 8, "imm_shr2", 2),
                         field(34, 48, "imm_shr10", 2)]
    collective = row(ANCHORS["WARPSYNC_COLLECTIVE"], collective_fields,
        "NVIDIA13.1: membermaskR@[31:24], signed56-bit dwordoffset low8@[23:16]/high48@[81:34]; branch encoder owns absolute-to-relative targetconversion. Bit16 adds4, bit64 adds2^40, bit81 is sign.")
    ins["WARPSYNC_R_II"]["mod_groups"]["COLLECTIVE"] = copy.deepcopy(collective)
    ins["WARPSYNC.COLLECTIVE_R_II"]["mod_groups"][""] = copy.deepcopy(collective)
    ins["WARPSYNC"]["mod_groups"]["COLLECTIVE"]["encode_only"] = True
    ins["WARPSYNC_R"]["mod_groups"][""] = row(ANCHORS["WARPSYNC_REG"],
        [guard, field(24, 8, "reg", 1), field(122, 1, "reuse", 1)],
        "NVIDIA13.1 plain WARPSYNC has one full8-bit registermembermaskat24, with no branchtarget.")
    ins["WARPSYNC"]["mod_groups"][""]["encode_only"] = True
    for group in ["", "ALL"]:
        ins["WARPSYNC_R_II"]["mod_groups"][group]["encode_only"] = True
    for group in ["ALL", "COLLECTIVE"]:
        ins["WARPSYNC_R"]["mod_groups"][group]["encode_only"] = True

    call = copy.deepcopy(ins["CALL.ABS.NOINC_II"])
    call.pop("encode_only", None)
    call["base_op"] = "CALL"
    call["operand_sig"] = "R"
    call["mod_groups"] = {"ABS,NOINC": row(ANCHORS["CALL_ABS_REG"], [guard,
        field(24, 8, "reg", 1)],
        "NVIDIA13.1: CALL.ABS.NOINC registerindirectopcode0x343, targetregister fullbyte@[31:24]; fixeddefaultpredicatePT.")}
    ins["CALL_R"] = call

    lepc = copy.deepcopy(ins["CALL.ABS.NOINC_II"])
    lepc.pop("encode_only", None)
    lepc["base_op"] = "LEPC"
    lepc["operand_sig"] = "R_II"
    lepc["mod_groups"] = {"": row(ANCHORS["LEPC"], [guard, field(16, 8, "reg", 1),
        field(24, 58, "imm", 2)],
        "NVIDIA13.1: LEPC Rd8@[23:16], target=pc+16+sext58(payload@[81:24]); bytegranularfield confirmed by individualbitflips24..81.")}
    ins["LEPC_R_II"] = lepc

    barrier_fields = {
        "II": [guard, field(54, 4, "imm", 1)],
        "II_II": [guard, field(54, 4, "imm", 1), field(42, 12, "imm", 2)],
        "II_R": [guard, field(54, 4, "imm", 1), field(32, 8, "reg", 2)],
        "R_R": [guard, field(32, 8, "reg", 1), field(32, 8, "reg", 2)],
    }
    for signature, fs in barrier_fields.items():
        anchor = ANCHORS["BAR_II_II" if signature == "II" else f"BAR_{signature}"]
        if signature == "II":
            anchor = f"{int(anchor, 16) & ~(((1 << 12) - 1) << 42):032x}"
        barrier = copy.deepcopy(ins["BAR.SYNC.DEFER_BLOCKING_II"])
        barrier["base_op"] = "BAR.SYNC.DEFER_BLOCKING"
        barrier["operand_sig"] = signature
        barrier["mod_groups"] = {"": row(anchor, fs,
            "NVIDIA13.1 BAR.SYNC.DEFER_BLOCKING: barrierID4@[57:54], immediatecount12@[53:42], registercount8@[39:32]. R,R operands alias onephysicalregisterfield; encoder must require equality.",
            allow_alias=signature == "R_R")}
        if signature == "II_II":
            # A zero count is the one-operand default form, as printed by
            # NVIDIA. Its dedicated II row owns that decoder surface.
            barrier["mod_groups"][""]["claim_forbid"] = [{"shift": 42, "bits": 12, "values": [0]}]
        ins[f"BAR.SYNC.DEFER_BLOCKING_{signature}"] = barrier
    ins["BAR.SYNC.DEFER_BLOCKING_P_II"]["encode_only"] = True
    # The old B2R.RESULT artifact claims BAR's zero-register form via
    # variable opcode bits, and has no independent vendor mnemonic support.
    if "B2R_R_P" in ins and "RESULT" in ins["B2R_R_P"]["mod_groups"]:
        ins["B2R_R_P"]["mod_groups"]["RESULT"]["encode_only"] = True

    all_collective = copy.deepcopy(ins["WARPSYNC_R_II"])
    all_collective["operand_sig"] = "II"
    all_collective["mod_groups"] = {"ALL,COLLECTIVE": row(ANCHORS["WARPSYNC_ALL"], [guard,
        field(16, 8, "imm_shr2", 1), field(34, 48, "imm_shr10", 1)],
        "NVIDIA13.1: WARPSYNC.COLLECTIVE.ALL has no registermask and resolves same signed56-bit dwordoffset as registercollective, opcode0x948.")}
    ins["WARPSYNC_II"] = all_collective

    conv = copy.deepcopy(ins["BRA.DIV_UR_II"])
    conv["base_op"] = "BRA"
    conv["operand_sig"] = "UR_II"
    conv["mod_groups"] = {"CONV": row(ANCHORS["BRA_CONV"], [guard,
        field(24, 8, "ureg", 1), field(16, 8, "imm_shr2", 2), field(34, 48, "imm_shr10", 2)],
        "NVIDIA13.1: BRA.CONV UR,target uses same fullsigned56-bit dwordoffset asDIV; bit32 togglesCONV(1)/DIV(0), bit33=1.")}
    ins["BRA_UR_II"]["mod_groups"]["CONV"] = conv["mod_groups"]["CONV"]

    # Complete 64-bit integer predicate families. Every selector combination
    # below was directly passed through NVIDIA's disassembler (288 grid cells).
    cmp_names = ["F", "LT", "EQ", "LE", "GT", "NE", "GE", "T"]
    bool_names = ["AND", "OR", "XOR"]
    for source, family in [("R", "ISETP_RR64"), ("II", "ISETP_RI64"), ("UR", "ISETP_RU64")]:
        for extended in [False, True]:
            key = f"ISETP_P_P_R_{source}_P" + ("_P" if extended else "")
            for compare, compare_name in enumerate(cmp_names):
                for combine, bool_name in enumerate(bool_names):
                    for signed, datatype in [(False, "U64"), (True, "S64")]:
                        anchor = int(ANCHORS[family], 16)
                        anchor = replace(anchor, 76, 3, compare)
                        anchor = replace(anchor, 74, 2, combine)
                        anchor = replace(anchor, 73, 1, int(signed))
                        anchor = replace(anchor, 72, 1, int(extended))
                        source_field = field(32, 32 if source == "II" else 8,
                                             {"R": "reg", "UR": "ureg", "II": "imm"}[source], 4)
                        fields = [guard, field(81, 3, "pred", 1), field(84, 3, "pred", 2),
                            field(24, 8, "reg", 3), source_field, field(87, 3, "pred", 5),
                            field(90, 1, "neg", 5), field(122, 1, "reuse", 3)]
                        if source == "R":
                            fields.append(field(123, 1, "reuse", 4))
                        if extended:
                            fields += [field(68, 3, "pred", 6), field(71, 1, "neg", 6)]
                        modifiers = [compare_name, bool_name, datatype] + (["EX"] if extended else [])
                        ins[key]["mod_groups"][",".join(sorted(modifiers))] = row(f"{anchor:032x}", fields,
                            "NVIDIA13.1 288cell ISETP64 matrix: cmp[78:76], bool[75:74], S64bit73/U64clear, EXbit72; 64bittypebit80set. RR/RI/RUR sourcegeometryandpredicatefields independently bit-probed.")

    # The independent 96-cell 32-bit R/UR matrix has the same operand fields;
    # Clear bit80 selects32-bit width; signed32-bit mode elides its type modifier.
    for extended in [False, True]:
        groups = ins["ISETP_P_P_R_UR_P" + ("_P" if extended else "")]["mod_groups"]
        measured64 = [(name, copy.deepcopy(group)) for name, group in groups.items()
                      if "S64" in name.split(',') or "U64" in name.split(',')]
        for name, group in groups.items():
            if not ({"S64", "U64"} & set(name.split(','))):
                group["encode_only"] = True
        for name, group in measured64:
            modifiers = [part for part in name.split(',') if part != "S64"]
            modifiers = ["U32" if part == "U64" else part for part in modifiers]
            anchor = int(group["and_base"], 16) & ~(1 << 80)
            groups[",".join(sorted(modifiers))] = row(f"{anchor:032x}", group["fields"],
                "NVIDIA13.1 96-cell ISETP32 R/UR matrix: identicalpredicate/registergeometryto64-bit; widthbit80clear, signed32modeomitsS32. BooleanXOR=2at74,OR=1.")

    packing_fields = [guard, field(16, 8, "reg", 1), field(24, 8, "reg", 2),
        field(32, 8, "reg", 3), field(64, 8, "reg", 4), field(122, 1, "reuse", 2),
        field(123, 1, "reuse", 3), field(124, 1, "reuse", 4)]
    for relu in [False, True]:
        anchor = int(ANCHORS["F2FP_E2M1_PACK"], 16) | ((1 << 75) if relu else 0)
        modifiers = ["SATFINITE", "E2M1", "F32", "PACK_AB_MERGE_C"] + (["RELU"] if relu else [])
        ins["F2FP_R_R_R_R"]["mod_groups"][",".join(sorted(modifiers))] = row(f"{anchor:032x}", packing_fields,
            "NVIDIA13.1: SATFINITE.E2M1.F32.PACK_AB_MERGE_C has Rd16/Ra24/Rb32/Rc64 bytefields and source reuse122/123/124; RELUbit75 independently verified.")

    membar_template = copy.deepcopy(ins["MEMBAR"])
    for semantic, all_threads in [("ALL", True), ("SC", False)]:
        for scope, bits in [("CTA", 0), ("SM", 1), ("GPU", 2), ("SYS", 3)]:
            anchor = replace(int(ANCHORS["MEMBAR_CTA"], 16), 76, 3, bits)
            anchor = replace(anchor, 79, 1, int(all_threads))
            fixed = row(f"{anchor:032x}", [guard],
                "NVIDIA13.1 MEMBAR opcode0x992, scope[78:76]=CTA0/SM1/GPU2/SYS3; ALLbit79/SCclear; nooperands, guard4@12.")
            canonical_group = ",".join(sorted([semantic, scope]))
            legacy_group = f"{semantic},{scope}"
            if legacy_group != canonical_group:
                ins["MEMBAR"]["mod_groups"].pop(legacy_group, None)
            ins["MEMBAR"]["mod_groups"][canonical_group] = copy.deepcopy(fixed)
            dotted = copy.deepcopy(membar_template)
            dotted["base_op"] = f"MEMBAR.{semantic}.{scope}"
            dotted["operand_sig"] = ""
            dotted["mod_groups"] = {"": copy.deepcopy(fixed)}
            ins[f"MEMBAR.{semantic}.{scope}"] = dotted
    if "MEMBAR.ALL.GPU_?" in ins:
        ins["MEMBAR.ALL.GPU_?"]["encode_only"] = True

    ins["EXIT_P"]["mod_groups"][""] = row(ANCHORS["EXIT_P"], [guard,
        field(87, 3, "pred", 1), field(90, 1, "neg", 1)],
        "NVIDIA13.1 EXIT has independent guard@[15:12] and optional executionpredicate[89:87]/neg90; PTmayelide.")
    ins["EXIT"]["mod_groups"][""] = row("000fea0003800000000000000000794d", [guard],
        "EXIT withoutoperand has fixedPTexecutionpredicate@[89:87]; variablepayloadwildcardremoved.")

    for signature, family in [("II_R_P", "BAR_RED_II_R"), ("R_R_P", "BAR_RED_R_R"), ("II_II_P", "BAR_RED_II_II")]:
        base_signature = signature.rsplit("_P", 1)[0]
        fs = copy.deepcopy(barrier_fields[base_signature])
        fs += [field(87, 3, "pred", 3), field(90, 1, "neg", 3)]
        red = copy.deepcopy(ins["BAR.SYNC.DEFER_BLOCKING_II"])
        red["base_op"] = "BAR.RED.OR.DEFER_BLOCKING"
        red["operand_sig"] = signature
        red["mod_groups"] = {"": row(ANCHORS[family], fs,
            "NVIDIA13.1 BAR.RED.OR.DEFER_BLOCKING uses sameID/countfieldselectionasSYNC pluspredicate[89:87]/neg90; R,Rcountoperandsaliasonephysicalfield.",
            allow_alias=signature == "R_R_P")}
        ins[f"BAR.RED.OR.DEFER_BLOCKING_{signature}"] = red
    ins["BAR.RED.OR.DEFER_BLOCKING_II_P"]["encode_only"] = True

    bmov_template = copy.deepcopy(ins["BMOV.32_R_II"])
    for signature, family, fields in [
        ("R_B", "BMOV_355", [guard, field(16, 8, "reg", 1), field(24, 4, "barrier", 2)]),
        ("B_R", "BMOV_356", [guard, field(24, 4, "barrier", 1), field(32, 8, "reg", 2)]),
    ]:
        bmov = copy.deepcopy(bmov_template)
        bmov.pop("encode_only", None)
        bmov["base_op"] = "BMOV"
        bmov["operand_sig"] = signature
        bmov["mod_groups"] = {}
        for flagged in [False, True]:
            anchor = replace(int(ANCHORS[family], 16), 84, 1, int(flagged))
            group = "32" + (",CLEAR" if signature == "R_B" and flagged else ",PQUAD" if flagged else "")
            bmov["mod_groups"][group] = row(f"{anchor:032x}", fields,
                "NVIDIA13.1 BMOV.32 R,B usesRd16/barrier4@24; B,Rusesbarrier4@24/Rsrc32; bit84meansCLEARforreadorPQUADforwrite.")
        ins[f"BMOV_{signature}"] = bmov

    result_fields = [guard, field(16, 8, "reg", 1), field(81, 3, "pred", 2)]
    result = row(ANCHORS["B2R_RESULT"], result_fields,
        "NVIDIA13.1 B2R.RESULT opcode0x31c withresultflag78, Rd8@16, sourcepredicate3@81; legacyonebitfieldcouldonlyrepresentP0/P1.")
    ins["B2R_R_P"]["mod_groups"]["RESULT"] = copy.deepcopy(result)
    ins["B2R.RESULT_R_P"]["mod_groups"][""] = copy.deepcopy(result)
    implicit_result = row(f"{replace(int(ANCHORS['B2R_RESULT'], 16), 81, 3, 7):032x}", [guard, field(16, 8, "reg", 1)],
        "B2R.RESULT implicitPTpredicatecase; predicate7elidesintheNVIDIAsurface.")
    ins["B2R.RESULT_R"]["mod_groups"][""] = implicit_result

    r2p = copy.deepcopy(ins["R2P_L_R_II"])
    r2p.pop("encode_only", None)
    r2p["operand_sig"] = "II_R_II"
    r2p["mod_groups"] = {"": row(ANCHORS["R2P"], [guard, field(24, 8, "reg", 2),
        field(32, 32, "imm", 3), field(76, 2, "byte_sel", 2), field(122, 1, "reuse", 2)],
        "NVIDIA13.1 R2PfirstoperandisliteralPR; sourceR8@24/mask32@32/sourcebyte_selector2@76.")}
    ins["R2P_II_R_II"] = r2p
    ins["R2P_L_R_II"]["encode_only"] = True

    absolute_call = row(ANCHORS["CALL_ABS_IMM"], [guard, field(16, 8, "imm_shr2", 1),
        field(34, 48, "imm_shr10", 1)],
        "NVIDIA13.1 CALL.ABS.NOINC0x943takesabsoluteimmediateq56*4; opcode0x343isthedistinctregisterindirectform. Nopc+16adjustmentforABS.")
    ins["CALL_II"]["mod_groups"]["ABS,NOINC"] = absolute_call
    ins["CALL_II"]["mod_groups"]["NOINC,REL"] = row(ANCHORS["CALL_REL_IMM"], [guard,
        field(16, 8, "imm_shr2", 1), field(34, 48, "imm_shr10", 1)],
        "NVIDIA13.1 CALL.REL.NOINC0x944resolvespc+16+signedq56*4; samephysicalsplitasABSimmediatebutdifferentaddressinterpretation.")
    for key in ["CALL.ABS.NOINC_II", "CALL.ABS.NOINC_II_?"]:
        if key in ins:
            ins[key]["encode_only"] = True

    three_pack = copy.deepcopy(ins["F2FP_R_R_R_R"])
    three_pack["operand_sig"] = "R_R_R"
    three_pack["mod_groups"] = {}
    fields = [guard, field(16, 8, "reg", 1), field(24, 8, "reg", 2), field(32, 8, "reg", 3),
        field(122, 1, "reuse", 2), field(123, 1, "reuse", 3)]
    for datatype, family in [("BF16", "F2FP_BF16_PACK"), ("F16", "F2FP_F16_PACK")]:
        for saturated in [False, True]:
            for relu in [False, True]:
                anchor = replace(int(ANCHORS[family], 16), 77, 1, int(saturated))
                anchor = replace(anchor, 75, 1, int(relu))
                modifiers = [datatype, "F32", "PACK_AB"] + (["SATFINITE"] if saturated else []) + (["RELU"] if relu else [])
                three_pack["mod_groups"][",".join(sorted(modifiers))] = row(f"{anchor:032x}", fields,
                    "NVIDIA13.1 BF16/F16.F32.PACK_ABhasthreefullregisteroperands16/24/32; SATFINITEbit77, RELUbit75, typeBF16bit76/F16clear.")
    ins["F2FP_R_R_R"] = three_pack
    for target_type, e4m3 in [("E4M3", True), ("E5M2", False)]:
        for source_type, bf16 in [("F16", False), ("BF16", True)]:
            for saturated in [False, True]:
                for relu in [False, True]:
                    anchor = int(ANCHORS["F2FP_F16_MERGE"], 16)
                    for shift, value in [(76, e4m3), (83, bf16), (77, saturated), (75, relu)]:
                        anchor = replace(anchor, shift, 1, int(value))
                    modifiers = [target_type, source_type, "UNPACK_B_MERGE_C"]
                    if saturated:
                        modifiers.append("SATFINITE")
                    if relu:
                        modifiers.append("RELU")
                    ins["F2FP_R_R_R"]["mod_groups"][",".join(sorted(modifiers))] = row(f"{anchor:032x}",
                        [guard, field(16, 8, "reg", 1), field(32, 8, "reg", 2),
                         field(64, 8, "reg", 3), field(72, 1, "opmod:H1", 3),
                         field(123, 1, "reuse", 2), field(124, 1, "reuse", 3)],
                        "NVIDIA13.1 UNPACK_B_MERGE_C has Rd16,source32,merge64; merge.H1=72,reuse123/124. TargetE4/E5bit76,sourceF16/BF16bit83,SATFINITE77,RELU75. Independentlyverified128-cellmatrix.")
    for entry in ins.values():
        if entry.get("base_op", "").split(".")[0] != "F2FP":
            continue
        for group in entry["mod_groups"].values():
            for f in group.get("fields", []):
                if f["extraction"] == "guard" and f["shift"] == 12 and f["bits"] == 3:
                    f["bits"] = 4
                    f["_src"] = PROVENANCE
                    group["variable_mask"] = f"0x{int(group['variable_mask'], 16) | (1 << 15):032x}"

    predicate_branch = row(ANCHORS["BRA_PRED_NEG"], [guard,
        field(87, 3, "pred", 1), field(90, 1, "neg", 1),
        field(16, 8, "imm_shr2", 2), field(34, 48, "imm_shr10", 2)],
        "NVIDIA13.1 BRA predicateoperandindependentfromguard: P[89:87], negatebit90; branchaddressfullsignedq56*4.")
    ins["BRA_P_II"]["mod_groups"][""] = predicate_branch
    ins["BRA_P_P_II"]["encode_only"] = True

    ret = ins["RET_R_II"]
    ret.setdefault("base_op", "RET")
    ret.setdefault("operand_sig", "R_II")
    ret.setdefault("ctrl_class", "ctrl_flow")
    ret["mod_groups"]["ABS,NODEC"] = row(ANCHORS["RET_ABS_REG"], [guard,
        field(24, 8, "reg", 1), field(16, 8, "imm_shr2", 2), field(34, 48, "imm_shr10", 2)],
        "NVIDIA13.1 RET.ABS.NODEC takes register8@24 plusabsoluteq56*4target low8@16/high48@34; no pc+16additionforABS. bit85distinguishesABSfromREL.")
    ins["RET.ABS.NODEC_?"]["encode_only"] = True
    ins["RET_L"]["mod_groups"]["ABS,NODEC"]["encode_only"] = True

    ins["BRA_II"]["mod_groups"]["ANY,U"] = row(ANCHORS["BRA_U_ANY"], [guard,
        field(16, 8, "imm_shr2", 1), field(34, 48, "imm_shr10", 1)],
        "NVIDIA13.1 BRA.U.ANY has guard4 and one direct target in signedq56 dword layout, with no predicateoperand.")
    ins["BRA_II"]["mod_groups"]["U"] = row("000fec00038000000000000500740947", [guard,
        field(16, 8, "imm_shr2", 1), field(34, 48, "imm_shr10", 1)],
        "NVIDIA13.1 BRA.U directtarget: modebit32=1 distinct from plainBRA; same signedq56 dwordtarget low8@16/high48@34. Actual captured native payload distinguishes BRA.U from BRA with exactly bit32.")
    ins["BRA_P_II"]["mod_groups"]["U"] = row("000fec00000000000000000500740947", [guard,
        field(87, 3, "pred", 1), field(90, 1, "inv", 1),
        field(16, 8, "imm_shr2", 2), field(34, 48, "imm_shr10", 2)],
        "NVIDIA13.1 BRA.U optional memberpredicate87/inversion90, same directtarget fields; implicit PT is elided.")
    for mode in ["", "U"]:
        ins["BRA_P_II"]["mod_groups"][mode]["claim_forbid"] = [{"shift": 87, "bits": 4, "values": [7]}]
    trap = copy.deepcopy(ins["BPT.TRAP_II"])
    trap["mod_groups"] = {"": row("000fea0000300000000000040000795c", [guard,
        field(34, 3, "imm", 1)],
        "NVIDIA13.1 BPT.TRAP immediate is3bits@34, not2bits@35. Bitwalk34/35/36 prints1/2/4; immediatezero uses nooperand spelling.")}
    ins["BPT.TRAP_II"] = trap
    implicit_trap = copy.deepcopy(trap)
    implicit_trap["operand_sig"] = ""
    implicit_trap["mod_groups"] = {"": row("000fea0000300000000000000000795c", [guard],
        "NVIDIA13.1 BPT.TRAP omits the immediate operand when its3-bit value iszero.")}
    ins["BPT.TRAP"] = implicit_trap
    trap["mod_groups"][""]["claim_forbid"] = [{"shift": 34, "bits": 3, "values": [0]}]
    for key, source, signature, extraction in [("BRX_R_II", "BRX_REG", "R_II", "reg"),
                                               ("BRXU_UR_II", "BRXU_UREG", "UR_II", "ureg")]:
        base = "BRX" if source == "BRX_REG" else "BRXU"
        indirect = copy.deepcopy(ins[f"{base}_L"])
        indirect.pop("encode_only", None)
        indirect["base_op"] = base
        indirect["operand_sig"] = signature
        indirect["mod_groups"] = {"": row(ANCHORS[source], [guard,
            field(24, 8, extraction, 1), field(16, 8, "imm_shr2", 2),
            field(34, 48, "imm_shr10", 2), field(122, 1, "reuse", 1)],
            "NVIDIA13.1 indirectbranch takes register8@24 and raw signedq56*4 byteoffset; target is relative toregister, not instructionPC.")}
        ins[key] = indirect
        ins[f"{base}_L"]["encode_only"] = True
    ins["NANOSLEEP_II"]["mod_groups"][""] = row(ANCHORS["NANOSLEEP"], [guard,
        field(32, 32, "imm", 1)],
        "NVIDIA13.1 NANOSLEEP delayimmediate32@32 with fixedPTpredicate87; old dummy token0 field erasedPTbits.")
    # The default one-operand spelling elides PT. Non-PT/negated member
    # predicates are real operands, independent of the execution guard.
    for signature, packet, source_extraction, source_bits in [
            ("P_II", 0x95d, "imm", 32), ("P_R", 0x35d, "reg", 8)]:
        member = copy.deepcopy(ins["NANOSLEEP_II" if source_bits == 32 else "NANOSLEEP_R"])
        member.pop("encode_only", None)
        member["operand_sig"] = signature
        member["mod_groups"] = {"": row(f"{packet:032x}", [guard,
            field(87, 3, "pred", 1), field(90, 1, "inv", 1),
            field(32, source_bits, source_extraction, 2)] +
            ([field(123, 1, "reuse", 2)] if source_bits == 8 else []),
            "NVIDIA13.1 full P0..PT/negation sweep: NANOSLEEP memberpredicate87/inversion90, delayimmediate32 or register8 at32. ImplicitPT form remains more specific.")}
        member["mod_groups"][""]["claim_forbid"] = [{"shift": 87, "bits": 4, "values": [7]}]
        ins[f"NANOSLEEP_{signature}"] = member
    ins["NANOSLEEP_R"]["mod_groups"][""] = row(f"{((7 << 87) | 0x35d):032x}", [guard,
        field(32, 8, "reg", 1), field(123, 1, "reuse", 1)],
        "NVIDIA13.1 NANOSLEEP registerdelay8@32; implicit memberPT is fixed at87..90, independent guard12.")

    for signature, family, register_shift, register_token in [("R_II", "RPCMOV_READ", 16, 1),
                                                             ("II_R", "RPCMOV_WRITE", 32, 2)]:
        ins[f"RPCMOV_{signature}"] = {"base_op": "RPCMOV", "ctrl_class": "ctrl_flow", "operand_sig": signature,
            "mercury": [], "mod_groups": {"32": row(ANCHORS[family], [guard,
                field(register_shift, 8, "reg", register_token)],
                "NVIDIA13.1 RPCMOV.32 readsRpc.LOtoRd16(opcode353)orwritesRsrc32toRpc.LO(opcode352); literalRpc.LOselector31isfixedzero.")},
            "scheduling": {"def_latency": 0, "is_variable_latency": False, "pipe_class": 0,
                "pipe_name": "UNKNOWN", "throughput": 1, "confidence": "synthetic", "latency_source": "unmeasured"}}
    ins["BREAK_B"]["mod_groups"][""] = row(ANCHORS["BREAK_PLAIN"], [guard,
        field(16, 4, "barrier", 1)], "NVIDIA13.1 plainBREAK has barrier4@16; bit72clear/plainversusset/RELIABLE; defaultmemberpredicatePT.")
    ins["BREAK_P_B"]["mod_groups"][""] = row(ANCHORS["BREAK_PLAIN"], [guard,
        field(87, 3, "pred", 1), field(90, 1, "neg", 1), field(16, 4, "barrier", 2)],
        "NVIDIA13.1 BREAKoptionalpredicate87/neg90 isindependentofguard12; barrier4@16.")
    for signature, family in [("II_II", "BAR_ARV_II_II"), ("R_R", "BAR_ARV_R_R")]:
        arv = copy.deepcopy(ins[f"BAR.SYNC.DEFER_BLOCKING_{signature}"])
        arv["base_op"] = "BAR.ARV"
        arv["mod_groups"] = {"": row(ANCHORS[family], barrier_fields[signature],
            "NVIDIA13.1 BAR.ARV usesID4@54,count12@42oraliasedR8@32; bit77selectsARV, bit80clear(nodeferredblocking).",
            allow_alias=signature == "R_R")}
        ins[f"BAR.ARV_{signature}"] = arv
    work = {"base_op": "UGETNEXTWORKID", "ctrl_class": "alu_simple", "operand_sig": "AURI_AURI", "mercury": [],
        "scheduling": {"def_latency": 0, "is_variable_latency": False, "pipe_class": 0,
            "pipe_name": "UNKNOWN", "throughput": 1, "confidence": "synthetic", "latency_source": "unmeasured"}, "mod_groups": {}}
    for modifier, broadcast in [("BROADCAST", True), ("SELFCAST", False)]:
        anchor = replace(int(ANCHORS["UGETNEXTWORKID"], 16), 72, 1, int(broadcast))
        group = row(f"{anchor:032x}", [guard, field(24, 8, "sub_ur0", 1), field(24, 8, "sub_ur0_m1", 2)],
            "NVIDIA13.1 UGETNEXTWORKIDaddresspair[URn],[URn+1]sharesfull8-bitfield24; modesBROADCASTbit72/SELFCASTclear; nooffsetbits.", allow_alias=True)
        group["claim_forbid"] = [{"shift": 24, "bits": 8, "values": [254, 255]}]
        work["mod_groups"][modifier] = group
    ins["UGETNEXTWORKID_AURI_AURI"] = work
    output = (json.dumps(table, indent=1, ensure_ascii=True) + "\n").encode()
    temporary = path.with_name(path.name + ".dsv41.tmp")
    temporary.write_bytes(output)
    temporary.replace(path)
    print(f"Updated {path}: {hashlib.sha256(before).hexdigest()} -> {hashlib.sha256(output).hexdigest()}")


def replace(word, shift, bits, value):
    mask = ((1 << bits) - 1) << shift
    return (word & ~mask) | ((value << shift) & mask)


def probe(nvdisasm, out, only=None):
    variants = []
    for name, code in ANCHORS.items():
        if only is not None and name not in only:
            continue
        word = int(code, 16)
        variants.append((name, "anchor", word))
        variants.extend((name, f"xor_bit_{bit}", word ^ (1 << bit)) for bit in range(128))
        if name == "F2FP_F16_MERGE":
            for shift, bits in [(72, 8), (80, 9)]:
                variants.extend((name, f"selector_{shift}_{bits}_{value}", replace(word, shift, bits, value))
                                for value in range(1 << bits))
            for e4m3 in range(2):
                for bf16 in range(2):
                    for saturated in range(2):
                        for relu in range(2):
                            for h1 in range(2):
                                for reuse in range(4):
                                    variant = word
                                    for shift, bits, value in [(76, 1, e4m3), (83, 1, bf16), (77, 1, saturated),
                                                               (75, 1, relu), (72, 1, h1), (123, 2, reuse)]:
                                        variant = replace(variant, shift, bits, value)
                                    variants.append((name, f"grid_e4{e4m3}_bf{bf16}_sat{saturated}_relu{relu}_h{h1}_reuse{reuse}", variant))
        if name in {"ISETP_RR64", "ISETP_RI64", "ISETP_RU64"}:
            for compare in range(8):
                for combine in range(3):
                    for signed in range(2):
                        for extended in range(2):
                            variant = replace(word, 76, 3, compare)
                            variant = replace(variant, 74, 2, combine)
                            variant = replace(variant, 73, 1, signed)
                            variant = replace(variant, 72, 1, extended)
                            variants.append((name, f"grid_cmp{compare}_bool{combine}_signed{signed}_ex{extended}", variant))
        if name == "ISETP32_RUR":
            for compare in range(8):
                for combine in range(3):
                    for signed in range(2):
                        for extended in range(2):
                            variant = replace(word, 76, 3, compare)
                            variant = replace(variant, 74, 2, combine)
                            variant = replace(variant, 73, 1, signed)
                            variant = replace(variant, 72, 1, extended)
                            variants.append((name, f"grid_cmp{compare}_bool{combine}_signed{signed}_ex{extended}", variant))
        if name == "UVIMNMX_RELU":
            for dtype in range(6):
                for relu in range(2):
                    variants.append((name, f"grid_type{dtype}_relu{relu}",
                        replace(replace(word, 72, 3, dtype), 76, 1, relu)))
        if name == "MEMBAR_SC":
            for scope in range(4):
                for all_threads in range(2):
                    variants.append((name, f"grid_scope{scope}_all{all_threads}",
                        replace(replace(word, 76, 3, scope), 79, 1, all_threads)))
        fields = {
            "CS2R": [(72, 8)],
            "P2R": [(24, 8), (32, 8)],
            "BREAK": [(16, 4), (87, 4)],
            "F2FP_UNPACK_A": [(16, 8), (24, 8), (32, 8), (64, 8)],
            "F2FP_UNPACK_B": [(16, 8), (24, 8), (32, 8), (64, 8)],
            "UIADD3_64": [(16, 8), (24, 8), (32, 8), (64, 8)],
            "SEL64": [(16, 8), (24, 8), (32, 8), (87, 4)],
            "USEL64": [(16, 8), (24, 8), (32, 8), (87, 4)],
            "UVIMNMX": [(16, 8), (24, 8), (32, 8), (87, 4)],
            "VIMNMX": [(16, 8), (24, 8), (32, 8), (87, 4)],
            "CALL_ABS_REG": [(24, 8)],
            "LEPC": [(24, 8), (32, 8)],
            "BAR_II_II": [(32, 8), (40, 8), (48, 8), (54, 4)],
            "BAR_II_R": [(32, 8), (54, 4)],
            "BAR_R_R": [(32, 8)],
            "BMOV_355": [(16, 8), (24, 8)],
            "BMOV_356": [(16, 8), (24, 8), (32, 8)],
            "B2R_RESULT": [(16, 8), (81, 4)],
            "R2P": [(24, 8), (32, 8)],
            "RET_ABS_REG": [(24, 8)],
            "SEL64_UR": [(16, 8), (24, 8), (32, 8), (87, 3)],
            "F2FP_F16_MERGE": [(16, 8), (24, 8), (32, 8), (64, 8)],
            "WARPSYNC_REG": [(24, 8)],
            "BRX_REG": [(24, 8)],
            "BRXU_UREG": [(24, 8)],
            "NANOSLEEP": [(32, 8), (87, 3)],
            "F2FP_E2M1_UNPACK_B": [(16, 8), (32, 8)],
            "RPCMOV_READ": [(16, 8), (24, 8)],
            "RPCMOV_WRITE": [(24, 8), (32, 8)],
            "BREAK_PLAIN": [(16, 4)],
            "BAR_ARV_II_II": [(54, 4), (42, 12)],
            "BAR_ARV_R_R": [(32, 8)],
            "UGETNEXTWORKID": [(24, 8)],
        }.get(name, [])
        for shift, bits in fields:
            for value in [0, 1, 2, 3, 4, 6, 7, 8, 16, 31, 32, 63, 64, 127, 128, 254, 255]:
                if value < 1 << bits:
                    variants.append((name, f"field_{shift}_{bits}_{value}", replace(word, shift, bits, value)))
    with tempfile.TemporaryDirectory(prefix="cubit-re-sm120-") as temp:
        def one(item):
            i, (family, change, word) = item
            binary = pathlib.Path(temp) / f"{i}.bin"
            binary.write_bytes(word.to_bytes(16, "little"))
            process = subprocess.run([nvdisasm, "-raw", "-ndf", "-b", "SM120", str(binary)],
                                     text=True, capture_output=True)
            decoded = None
            for line in process.stdout.splitlines():
                match = re.match(r"\s*/\*0+\*/\s*(.*)", line)
                if match:
                    decoded = match[1].split("/*", 1)[0].rstrip().rstrip(";").strip()
            if change == "anchor" and (process.returncode != 0 or decoded is None):
                raise RuntimeError(f"nvdisasm rejected anchor {family}: {process.stderr}")
            return {"family": family, "change": change, "code": f"{word:032x}",
                    "nvdisasm": decoded, "returncode": process.returncode,
                    "stderr": process.stderr,
                    "unparsed_stdout": process.stdout if decoded is None and process.returncode == 0 else None}
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            rows = list(executor.map(one, enumerate(variants)))
        version = subprocess.run([nvdisasm, "-V"], text=True, capture_output=True, check=True)
    pathlib.Path(out).write_text(json.dumps({"oracle": version.stdout + version.stderr,
        "command": [nvdisasm, "-raw", "-ndf", "-b", "SM120", "variants.bin"],
        "rows": rows}, indent=2) + "\n")
    print(f"Wrote {len(rows)} independently constructed probes to {out}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--nvdisasm", default="/usr/local/lib/python3.12/dist-packages/triton/backends/nvidia/bin/nvdisasm")
    parser.add_argument("--probe-out")
    parser.add_argument("--apply", metavar="CANONICAL_SM120_JSON")
    parser.add_argument("--only", help="comma-separated probe family names")
    args = parser.parse_args()
    if args.probe_out:
        probe(args.nvdisasm, args.probe_out, set(args.only.split(",")) if args.only else None)
    if args.apply:
        apply(args.apply)
    if not args.probe_out and not args.apply:
        parser.error("specify --probe-out and/or --apply")


if __name__ == "__main__":
    main()

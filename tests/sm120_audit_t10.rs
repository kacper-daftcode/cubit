//! Dynamic-audit batches of session T-10 (2026-11-06; blackwell-isa `1e562ad` + `71ff64f`, tools
//! `blackwell-isa-internal/tools/audit_fix_20261106_t10.py` + `_t10b.py`): the harvest-row field repairs the
//! replay of the 2026-11-04 word set still named after the family rebuilds, each verified against nvdisasm 13.1
//! `-b SM120` before the table was written, and the junk keys retired under the census-witness rule (0 witnesses
//! among the 249 929 distinct words of the production census + our kernels, no alias target, every probe word
//! vendor-invalid / illegal or decoded by the remaining rows). Pins: the repaired rows print and re-encode the
//! measured vendor texts; the retired keys are gone and their shapes decode through the remaining rows or fail
//! closed; the provenance entry counts the repaired rows.

use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;
use std::{path::Path, sync::OnceLock};

const SOURCE: &str = "audit-fix-2026-11-06-t10";
const CTRL: u128 = 0x000f_e200u128 << 96;

fn loaded() -> &'static (IsaTable, DecodeIndex) {
    static T: OnceLock<(IsaTable, DecodeIndex)> = OnceLock::new();
    T.get_or_init(|| {
        let table = IsaTable::load(Path::new("tables/sm120.json")).unwrap();
        let index = DecodeIndex::build(&table);
        (table, index)
    })
}

fn decode(word: u128) -> Option<(String, String)> {
    let (table, index) = loaded();
    index.decode(word | CTRL, 0, table).ok().map(|d| (d.key.clone(), cubit::printer::to_sass(&d)))
}

fn reencode(word: u128, text: &str) -> u128 {
    let (table, _) = loaded();
    let control = cubit::scheduling::format_control_code(&cubit::scheduling::decode_sched_upper32(((word | CTRL) >> 96) as u32));
    let source = format!("[{control}] {text} ;");
    let parsed = cubit::parse_cuasm_line(&source, 0).unwrap();
    cubit::encoder::encode_instruction(&parsed, table).unwrap_or_else(|e| panic!("{source}: {e}"))
}

/// (word without control code, nvdisasm 13.1 text, the key that must own it)
const MEASURED: &[(u128, &str, &str)] = &[
    // batch 1 -- field repairs
    (0x000000001ea10c0000100a090673a9, "ATOMG.E.CAS.STRONG.SM PT, R6, [R9+0x10], R10, R12", "ATOMG_P_R_ARI_R_R"),
    (0x000000000010a10c0000100a090673a9, "ATOMG.E.CAS.STRONG.SM P0, R6, [R9+0x10], R10, R12", "ATOMG_P_R_ARI_R_R"),
    (0x0000000000000a000000100605007388, "STS.64 [R5+0x10], R6", "STS_ARI_R"),
    (0x0000000000000f000000000600047202, "MOV R4, R6", "MOV_R_R"),
    (0x0000000000010f000000000600047202, "MOV.64 R4, R6", "MOV_R_R"),
    (0x00000000038000000000000000007948, "WARPSYNC.ALL", "WARPSYNC"),
    (0x00000000084000000000000006057256, "UFMUL UR5, UR6, UR0", "UFMUL_UR_UR_UR"),
    (0x00000000080100000000000c020073b6, "UTMAREDG.3D.ADD [UR12], [UR2]", "UTMAREDG_AURI_AURI"),
    (0x00000000080e050000000000000079c8 | (0x3ff << 32), "USETMAXREG.DEALLOC.CTAPOOL 0x3ff", "USETMAXREG_II"),
    (0x00000000048148000000000000007b1d, "BAR.RED.OR.DEFER_BLOCKING 0x0, !P1", "BAR.RED.OR.DEFER_BLOCKING_II_P"),
    (0x00000000048148000000040000007b1d, "BAR.RED.OR.DEFER_BLOCKING 0x0, 0x1, !P1", "BAR.RED.OR.DEFER_BLOCKING_II_II_P"),
    (0x0000000008000c0000000000ff0577ac, "LDCU.128 UR5, c[0x0][URZ]", "LDCU_UR_cAI"),
    (0x000000000800000000000000070577ac, "LDCU.U8 UR5, c[0x0][UR7]", "LDCU_UR_cAI"),
    (0x00000000038e060e00000010ff047424, "IMAD.X R4, RZ, R14, 0x10, PT", "IMAD_R_R_R_II_P"),
    // batch 2
    (0x00000000081004ff0000100c07ff79a7, "SYNCS.ARRIVE.TRANS64.RED.A1T0 RZ, [R7+URZ+0x10], R12", "SYNCS_R_ARI_R"),
    (0x00000000081004ff0000100c070479a7, "SYNCS.ARRIVE.TRANS64.RED.A1T0 R4, [R7+URZ+0x10], R12", "SYNCS_R_ARI_R"),
    (0x00000000082031000000000600017d05, "F2I.NTZ R1, UR6", "F2I_R_UR"),
    (0x00000000082031000000003f00c87d05, "F2I.NTZ R200, UR63", "F2I_R_UR"),
];

#[test]
fn the_repaired_rows_print_and_reencode_the_measured_vendor_texts() {
    for &(word, vendor, key) in MEASURED {
        let (k, text) = decode(word).unwrap_or_else(|| panic!("{word:032x} ({vendor}) does not decode"));
        assert_eq!(k, key, "{word:032x}");
        assert_eq!(text, vendor, "{word:032x}");
        assert_eq!(reencode(word, vendor) & !(0x7fffffu128 << 105), word, "{vendor}");
    }
}

/// Words the retired or repaired rows used to claim: the illegal ones fail closed, the shifted-field twins'
/// words decode through the measured rows, the text-inert junk bytes fail closed (cubit assembles the vendor
/// text to the canonical word instead -- the audit's `inert_failclosed` class).
#[test]
fn the_retired_shapes_fail_closed_or_decode_through_the_remaining_rows() {
    // STS.64 with opcode bit 9 clear (0x188): illegal for nvdisasm, claimed by the old row
    assert!(decode(0x0000000000000a000000100605007188).is_none(), "the 0x188 STS word stays unclaimed");
    // ATOMG CAS with the opcode bits [10:7] carved out by the old pred@7 field
    assert!(decode(0x00000000001ea10c0000100a09067029).is_none());
    // MOV with the text-inert junk byte 0x22 at [31:24]: fails closed; the vendor text assembles to the canonical word
    assert!(decode(0x0000000000000f000000000622047202).is_none());
    assert_eq!(reencode(0x0000000000000f000000000600047202, "MOV R4, R6") & !(0x7fffffu128 << 105), 0x0000000000000f000000000600047202);
    // the vendor-invalid SULD words: unclaimed; the FSETP junk rows' canonical word (every predicate bit set,
    // nvdisasm `FSETP.T.FTZ.INVALID3`) is no longer theirs
    assert!(decode(0x00000000080e000000ff070006047f98).is_none());
    assert_ne!(decode(0x000000000fffff00c000000108007c0b).map(|(k, _)| k), Some("FSETP_P_P_L_FI_P".to_string()));
    // a shifted-field QMMA `_P_R_R_R_R` twin's word: decodes through the measured row with the vendor's registers
    let (k, t) = decode(0x0000000000002c28000000201bfcf27a).unwrap();
    assert!(!k.contains("_P_R_R_R_R"), "{k}");
    assert_eq!(t, "@!PT QMMA.16832.F32.E4M3.E4M3 R252, R27, R32, R40");
}

#[test]
fn the_rows_carry_the_provenance_and_the_junk_keys_are_gone() {
    let raw: Value = serde_json::from_slice(&cubit::table::read_table_bytes(Path::new("tables/sm120.json")).unwrap()).unwrap();
    let ins = raw["instructions"].as_object().unwrap();
    for gone in [
        "CS2R_R_R_?", "DADD_R_R_R_II_?", "DMUL_R_R_R_II_II_?", "FSETP_P_P_L_FI_P", "FSEL_R_R_L_P", "SULD.D.BA.2D.STRONG.SM.TRAP_R_AR_UR",
        "HMMA.16816.F32_P_R_R_R_R", "QMMA.16832.F32.E4M3.E4M3_P_R_R_R_R", "MOV_P_R_R", "MOV_R_R_II_II_?", "MOV_R_R_II_II_II_?",
        "IADD_R_R_R_II", "IADD.X_R_R_R_P", "UIADD3.64_UR_UP_UP_UR_II_II", "PLOP3.LUT_P_P_P_P_UP_II_II",
    ] {
        assert!(!ins.contains_key(gone), "{gone} should be retired");
    }
    assert!(!ins["MUFU_R_II"]["mod_groups"].as_object().unwrap().contains_key("RCP64H"));
    // batch 3: two batch-1 retirements undone with the measurement -- BUG-097's plain U32+UR LD.E form and
    // BUG-089's canonical IADD3_R_P_P_R_II_R [X] row are back (their own pins hold them)
    assert_eq!(ins["LD_R_ARURI"]["mod_groups"]["E"]["_src"], SOURCE);
    assert!(ins["IADD3_R_P_P_R_II_R"]["mod_groups"].as_object().unwrap().contains_key("X"));
    assert!(!ins["F2I_R_UR"]["mod_groups"].as_object().unwrap().contains_key("NTZ,U32"));
    let mut n = 0;
    for (key, e) in ins {
        for (name, g) in e["mod_groups"].as_object().unwrap() {
            if g["_src"] == SOURCE {
                n += 1;
                let mut field_mask = 0u128;
                for f in g["fields"].as_array().unwrap() {
                    field_mask |= ((1u128 << f["bits"].as_u64().unwrap()) - 1) << f["shift"].as_u64().unwrap();
                }
                let ab = u128::from_str_radix(g["and_base"].as_str().unwrap().trim_start_matches("0x"), 16).unwrap();
                assert_eq!(ab & field_mask, 0, "{key} [{name}]");
                assert_eq!(ab >> 105, 0, "{key} [{name}]: no control bits baked");
            }
        }
    }
    assert_eq!(raw["_meta"]["provenance"]["sources"][SOURCE]["rows"], n);
    assert!(n >= 20, "{n} repaired rows");
}

/// The audit's `silicon_illegal` class (dyn21, 2026-11-06): the three words of the old `IMMA.16832.S8.S8.SAT` harvest
/// probe whose registers, read through the measured fields, sit off the MMA operand alignment. nvdisasm names them
/// (its view is text-only); cubit prints the same text and refuses to assemble it under BUG-037 (a multi-register MMA
/// operand off its alignment is ILLEGAL_INSTRUCTION on the RTX 5090, `tests/bug037_mma_align.rs`). The refusal is the
/// encoder's documented behaviour, not a row defect -- the class is counted and named, never a finding.
#[test]
fn the_silicon_illegal_words_print_the_vendor_text_and_the_encoder_refuses_them_under_bug037() {
    let (table, _) = loaded();
    for (word, text) in [
        (0x0000_0000_0044_5c28_0000_0008_1bfc_0237u128, "@P0 IMMA.16832.S8.S8.SAT R252, R27.ROW, R8.COL, R40"),
        (0x0000_0000_0044_5c28_0000_000b_fc10_0237u128, "@P0 IMMA.16832.S8.S8.SAT R16, R252.ROW, R11.COL, R40"),
        (0x0000_0000_0044_5c28_0000_00ff_1810_0237u128, "@P0 IMMA.16832.S8.S8.SAT R16, R24.ROW, RZ.COL, R40"),
    ] {
        let (key, printed) = decode(word).unwrap_or_else(|| panic!("{word:032x} must decode"));
        assert_eq!(key, "IMMA.16832.S8.S8.SAT_R_R_R_R");
        assert_eq!(printed, text);
        let parsed = cubit::parse_cuasm_line(&format!("[B------:R-:W-:Y:S02] {text} ;"), 0).unwrap();
        let err = cubit::encoder::encode_instruction(&parsed, table).err().unwrap_or_else(|| panic!("{text}: BUG-037 must refuse"));
        let msg = err.to_string();
        assert!(msg.contains("ILLEGAL on silicon") && msg.contains("BUG-037"), "{text}: {msg}");
    }
}

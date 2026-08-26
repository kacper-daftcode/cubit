//! BUG-147 (b4-forward-4, follow-up of BUG-143 section 5): 115 decoder rows
//! of tables/sm103a.json carried sub_r{0,1}@24 with bits==9 (harvest era 2aE).
//! The window [24:33) bleeds bit32 (LSB of the sibling field at shift 32:
//! sub_ur0 desc-UR or the second data register of 256-bit forms) into the
//! base-R numeral -> render hallucination R+256 and an encode-side clobber
//! hazard (field-write collision, see BUG-143 report "zombie" discussion).
//!
//! Live corpus witnesses (hexdb 32.2M lines, F2-iter67 build; sm_100 cublasLt
//! 197): pre-fix decode rendered
//!   STG.E.ENL2.256 desc[UR20][R264.64], RZ, RZ
//! where the vendor truth (and post-fix render) is
//!   STG.E.ENL2.256 desc[UR20][R8.64], RZ, RZ      (reg@32 == RZ sentinel 255)
//!
//! Census (work/i69/census147.json): 132 total sub_r*@24/9 rows = 17 BUG-143
//! E1 (ATOM family, parked on branch a6049c1) + 115 patched here:
//! Decoder match semantics (decoder.rs): match_mask = !variable_mask &
//! !field_mask, so declared field windows are variable regardless of vmask.
//! Under that rule: 96 rows have a sibling field covering bit32 (sub_ur0/1
//! 8/5/4-bit desc-UR or second data reg) = match-invariant, render fixed on
//! bit32=1 words; 19 no-cover rows (LDS_R_ARI, LDL, QSPC, LDSM, LDG_R_ARI,
//! LDC_R_cARI) make bit32 fail-closed post-fix (zero corpus witnesses, A/B
//! 2014 cubins clean outside the two repaired classes).
//! Match-sets invariant: extraction fields do not participate in the
//! and_base/variable_mask match, so narrowing cannot change which words match.
//! Encode side verified invariant (battery pre==fix, work/i69/battery*).

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::table::{Extraction, IsaTable};

const SCHED: u128 = 0xFFFF_FFFFu128 << 96;

fn t103a() -> IsaTable {
    IsaTable::load(std::path::Path::new("tables/sm103a.json")).unwrap()
}

fn enc(t: &IsaTable, text: &str) -> u128 {
    let insn = parse_sass(text, 0).expect("parse");
    encode_instruction(&insn, t).expect("encode") & !SCHED
}

fn dec(t: &IsaTable, idx: &DecodeIndex, w: u128) -> String {
    idx.decode(w, 0, t).map(|d| cubit::printer::to_sass(&d)).expect("decode")
}

fn parts(lo: u64, hi32: u32) -> u128 { (lo as u128) | ((hi32 as u128) << 64) }

// Vendor witnesses of the live defect (sm_100 libcublasLt.so.197):
const WITNESS: &[(u64, u32, &str)] = &[
    // STG.256 +RZ data: reg@32 = RZ sentinel 255 bleeds into addr-R (sm_100 cublasLt197)
    (0xf80000ff08ff797f, 0x0f121814, "STG.E.ENL2.256 desc[UR20][R8.64], RZ, RZ"),
    (0xf80001ff08ff797f, 0x0f121814, "STG.E.ENL2.256 desc[UR20][R8.64+0x20], RZ, RZ"),
    // LDS.S8 odd-UR: sub_ur1@32/5 LSB bleeds into addr-R (sm_100 cublasLt468,
    // 1472 corpus lines, UR hist 5:726/13:439/15:200/11:66/7:37/9:3/17:1)
    (0x0000000b275f7984, 0x08000200, "LDS.S8 R95, [R39+UR11]"),
];

// Ordinary desc-form anchors, sm_103 corpus (even-UR control):
const CONTROL: &[(&str, u64, u32)] = &[
    ("LDG.E R0, desc[UR10][R10.64]", 0x0000000a0a007981, 0x0c1e1900),
    ("LD.E R0, desc[UR10][R2.64]",   0x0000000a02007980, 0x0c101900),
];

#[test]
fn t147_1_witness_decode_vendor_exact() {
    let t = t103a();
    let idx = DecodeIndex::build(&t);
    for (lo, hi32, want) in WITNESS {
        let got = dec(&t, &idx, parts(*lo, *hi32));
        assert_eq!(&got, want, "witness decode must match vendor (no R+256)");
        assert!(!got.contains("R264"), "R264 hallucination regressed: {got}");
    }
}

#[test]
fn t147_2_witness_encode_byte_exact() {
    let t = t103a();
    for (lo, hi32, text) in WITNESS {
        assert_eq!(enc(&t, text), parts(*lo, *hi32), "encode parity: {text}");
    }
}

#[test]
fn t147_3_control_encode_decode_roundtrip() {
    let t = t103a();
    let idx = DecodeIndex::build(&t);
    for (text, lo, hi32) in CONTROL {
        assert_eq!(enc(&t, text), parts(*lo, *hi32), "encode parity: {text}");
        assert_eq!(&dec(&t, &idx, parts(*lo, *hi32)), text, "decode parity: {text}");
    }
}

#[test]
fn t147_4_table_class_normalized() {
    // All 115 non-ATOM SubR@24/9 rows are narrowed; exactly the 17 parked
    // BUG-143 E1 ATOM-family rows may keep bits==9 at shift 24.
    let t = t103a();
    let mut n9 = 0usize;
    let mut n9_atom = 0usize;
    for (key, ins) in &t.entries {
        for g in ins.mod_groups.values() {
            for f in &g.fields {
                if f.shift == 24 && f.bits == 9
                    && matches!(f.extraction, Extraction::SubR(0) | Extraction::SubR(1))
                {
                    n9 += 1;
                    let base = key.split('_').next().unwrap_or("");
                    if base.starts_with("ATOM") || base == "REDG" {
                        n9_atom += 1;
                    }
                }
            }
        }
    }
    assert_eq!(
        (n9, n9_atom),
        (17, 17),
        "only the 17 parked BUG-143 E1 rows may stay width-9 @24 (got {n9}, of which {n9_atom} ATOM)"
    );
}

#[test]
fn t147_5_no_width9_in_targeted_families() {
    // Hard class pin: none of the census families may regress to bits==9@24.
    let t = t103a();
    for key in [
        "LDG_R_dARI", "LDG_R_ARI", "LDG_R_ARURI", "LDG_R_R_dARI",
        "STG_dARI_R", "STG_ARI_R", "STG_ARURI_R", "STG_dARI_R_R",
        "LDS_R_ARI", "LDS_R_ARURI", "ST_dARI_R", "ST_ARURI_R",
        "LD_R_dARI", "LDL_R_ARI", "LDSM_R_ARI", "LDC_R_cARI",
        "QSPC_P_R_ARI", "STSM_ARI_R",
    ] {
        let ins = t.entries.get(key).unwrap_or_else(|| panic!("key {key}"));
        for (gn, g) in &ins.mod_groups {
            for f in &g.fields {
                assert!(
                    !(f.shift == 24 && f.bits == 9
                        && matches!(f.extraction, Extraction::SubR(0) | Extraction::SubR(1))),
                    "{key}[{gn:?}] regressed to width-9 @24"
                );
            }
        }
    }
}

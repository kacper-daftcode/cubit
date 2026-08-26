//! BUG-156 (F2-iter75, front2/blind; adoption of spark LATENT note
//! 156_signmodel_ari + own census): ARI (plain [R+imm]) address-immediate
//! window model was wrong in both tables:
//!   A) LD/ST E-family (LD_R_ARI E/64,E/128,E, ST_ARI_R 64,E/128,E):
//!      window modeled s24@32, vendor truth = s32@32 (nvdisasm-13.3 bit-walk,
//!      work/bug156/probe/walk156*.log): bits [32:64) all participate, bit63
//!      prints "+-0x80000000". Effect pre-fix: decode rendered values
//!      0x800000..0xFFFFFFFF sign-flipped ("+-0x10" for raw 0xfffff0 vs
//!      vendor "+0xfffff0"); encode dropped bits >= 2^24 (fit_soft mask 24).
//!   B) LDG_R_ARI E + E,GPU,STRONG / LDS_R_ARI S8 / STG_ARI_R E,GPU,STRONG
//!      / REDG_ARI_R ADD,E,GPU,S32,STRONG / ST_ARI_R E: vendor window =
//!      s24@[40:64) (bit-walk: bit40 -> +0x1 .. bit62 -> +0x400000, bit63 ->
//!      "+-0x800000"). Fleet modeled s24@32 (LDG), s24@31+base 7b (LDS.S8,
//!      ST.E), s24@35 (STG/REDG, OVERLAPPING the payload-reg field
//!      reg@[32:40) -> decode fabricated offsets from high data-reg numerals).
//! Latency proof (hexdb 32.2M, work/bug156/probe/census156*.json):
//!   all six classes: bits[40:64) == 0 on 100% of vendor anchors; [32:40)
//!   nonzero only as STG/REDG data-reg numerals (never offset bits) =>
//!   tightening is corpus-lossless, widening is corpus-invariant.
//! nvdisasm-13.3 arbitration (SM103a ELF injection): every pin pair below
//! == nvdisasm render of the same word, and every encode pin's produced
//! word re-renders to the authored text.

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::table::IsaTable;

const SCHED: u128 = 0xFFFF_FFFFu128 << 96;

fn t103a() -> IsaTable {
    IsaTable::load(std::path::Path::new("tables/sm103a.json")).unwrap()
}
fn t120() -> IsaTable {
    IsaTable::load(std::path::Path::new("tables/sm120.json")).unwrap()
}

fn enc(t: &IsaTable, text: &str) -> u128 {
    let insn = parse_sass(text, 0).expect("parse");
    encode_instruction(&insn, t).expect("encode") & !SCHED
}

fn dec(idx: &DecodeIndex, w: u128, t: &IsaTable) -> String {
    idx.decode(w, 0, t).map(|d| cubit::printer::to_sass(&d)).expect("decode")
}

fn row<'a>(j: &'a serde_json::Value, key: &str, mg: &str) -> Option<&'a serde_json::Value> {
    j.pointer(&format!("/instructions/{key}/mod_groups/{mg}"))
}

/// t156_1 (invariant): window geometry of all patched rows, both tables.
#[test]
fn t156_1_geometry_polygon() {
    for path in ["tables/sm103a.json", "tables/sm120.json"] {
        let j: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        let a_rows = [
            ("LD_R_ARI", "E"),
            ("LD_R_ARI", "64,E"),
            ("LD_R_ARI", "128,E"),
            ("ST_ARI_R", "E"),
            ("ST_ARI_R", "64,E"),
            ("ST_ARI_R", "128,E"),
        ];
        for (k, mg) in a_rows {
            let r = row(&j, k, mg).unwrap_or_else(|| panic!("{path} {k}[{mg}]"));
            let imm: Vec<_> = r["fields"].as_array().unwrap().iter()
                .filter(|f| f["extraction"] == "sub_imm1").collect();
            assert_eq!(imm.len(), 1, "{k}[{mg}] imm count");
            assert_eq!(imm[0]["shift"], 32, "{k}[{mg}] imm shift");
            assert_eq!(imm[0]["bits"], 32, "{k}[{mg}] imm bits");
        }
        let b_rows = [
            ("LDG_R_ARI", "E"),
            ("LDG_R_ARI", "E,GPU,STRONG"),
            ("LDS_R_ARI", "S8"),
            ("STG_ARI_R", "E,GPU,STRONG"),
        ];
        for (k, mg) in b_rows {
            let r = row(&j, k, mg).unwrap_or_else(|| panic!("{path} {k}[{mg}]"));
            let imm: Vec<_> = r["fields"].as_array().unwrap().iter()
                .filter(|f| f["extraction"] == "sub_imm1").collect();
            assert_eq!(imm.len(), 1, "{k}[{mg}] imm count");
            assert_eq!(imm[0]["shift"], 40, "{k}[{mg}] imm shift");
            assert_eq!(imm[0]["bits"], 24, "{k}[{mg}] imm bits");
        }
        for (k, mg) in [("ST_ARI_R", "E"), ("LDS_R_ARI", "S8")] {
            let r = row(&j, k, mg).unwrap();
            let b: Vec<_> = r["fields"].as_array().unwrap().iter()
                .filter(|f| f["extraction"].as_str().unwrap().starts_with("sub_r"))
                .collect();
            assert_eq!(b.len(), 1, "{k}[{mg}] base count");
            assert_eq!(b[0]["bits"], 8, "{k}[{mg}] base bits");
        }
        if let Some(r) = row(&j, "REDG_ARI_R", "ADD,E,GPU,S32,STRONG") {
            let fs = r["fields"].as_array().unwrap();
            let imm: Vec<_> = fs.iter().filter(|f| f["extraction"] == "sub_imm1").collect();
            assert_eq!(imm.len(), 1);
            assert_eq!(imm[0]["shift"], 40);
            assert_eq!(imm[0]["bits"], 24);
            let regwin: std::collections::HashSet<u32> = fs.iter()
                .filter(|f| f["extraction"] == "reg")
                .flat_map(|f| {
                    let s = f["shift"].as_u64().unwrap() as u32;
                    let b = f["bits"].as_u64().unwrap() as u32;
                    s..s + b
                })
                .collect();
            assert!((40..64).all(|b| !regwin.contains(&b)), "REDG imm/reg overlap");
        }
    }
}

/// t156_2 (A-family s32@32): corpus anchor + vendor bit-walk pairs.
#[test]
fn t156_2_ld_st_s32_window() {
    let t = t103a();
    let idx = DecodeIndex::build(&t);
    let a = 0x000ea400001009000000000402047980u128; // LD.E R4, [R2+0x4]
    assert_eq!(dec(&idx, a, &t), "LD.E R4, [R2+0x4]");
    assert_eq!(dec(&idx, a ^ (1u128 << 56), &t), "LD.E R4, [R2+0x1000004]");
    assert_eq!(dec(&idx, a ^ (1u128 << 62), &t), "LD.E R4, [R2+0x40000004]");
    let neg = (a & !(((1u128 << 32) - 1) << 32)) | (0x8000_0000u128 << 32);
    assert_eq!(dec(&idx, neg, &t), "LD.E R4, [R2+-0x80000000]");
    let raw24 = (a & !(((1u128 << 32) - 1) << 32)) | (0xfffff0u128 << 32);
    assert_eq!(dec(&idx, raw24, &t), "LD.E R4, [R2+0xfffff0]");
    let t2 = t120();
    assert_eq!(dec(&idx, raw24, &t2), "LD.E R4, [R2+0xfffff0]");
}

/// t156_3 (B-family s24@40): window at [40:64); dead [32:40) on LDG/LDS.
#[test]
fn t156_3_ldg_lds_stg_redg_s24_at_40() {
    let t = t103a();
    let idx = DecodeIndex::build(&t);
    let ldg = 0x00032200001e09000000000084847381u128; // LDG.E R132, [R132]
    assert_eq!(dec(&idx, ldg ^ (1u128 << 40), &t), "LDG.E R132, [R132+0x1]");
    assert_eq!(dec(&idx, ldg ^ (1u128 << 63), &t), "LDG.E R132, [R132+-0x800000]");
    let lds = 0x000fe80000000200000000000a5b7984u128; // LDS.S8 R91, [R10]
    assert_eq!(dec(&idx, lds ^ (1u128 << 40), &t), "LDS.S8 R91, [R10+0x1]");
    assert_eq!(dec(&idx, lds ^ (1u128 << 31), &t), "LDS.S8 R91, [R138]");
    let stg = 0x0003e2000010e9000000000396007386u128; // STG.E.STRONG.GPU [R150], R3
    assert_eq!(dec(&idx, stg ^ (1u128 << 40), &t), "STG.E.STRONG.GPU [R150+0x1], R3");
    let red = 0x0003e2000010e300000000030400798eu128; // REDG.E.ADD.S32.STRONG.GPU [R4], R3
    assert_eq!(dec(&idx, red ^ (1u128 << 40), &t), "REDG.E.ADD.S32.STRONG.GPU [R4+0x1], R3");
    let t2 = t120();
    let idx2 = DecodeIndex::build(&t2);
    assert_eq!(dec(&idx2, stg ^ (1u128 << 40), &t2), "STG.E.STRONG.GPU [R150+0x1], R3");
}

/// t156_4 (fabrication kill): high data-reg numerals no longer spill ghost
/// offsets (pre-fix @35 window overlapped reg@[32:40): R9 fabricated +0x1);
/// ST.E base-R192 word was base-7b + ghost imm pre-fix.
#[test]
fn t156_4_no_ghost_offsets() {
    let t = t103a();
    let idx = DecodeIndex::build(&t);
    let red = 0x0003e2000010e300000000030400798eu128;
    let r9 = (red & !(0xFFu128 << 32)) | (0x9u128 << 32);
    assert_eq!(dec(&idx, r9, &t), "REDG.E.ADD.S32.STRONG.GPU [R4], R9");
    let stg = 0x0003e2000010e9000000000396007386u128;
    let stg_r9 = (stg & !(0xFFu128 << 32)) | (0x9u128 << 32);
    assert_eq!(dec(&idx, stg_r9, &t), "STG.E.STRONG.GPU [R150], R9");
    let st = 0x0201e400001009060000000040007385u128; // ST.E [R64], R6
    assert_eq!(dec(&idx, st ^ (1u128 << 31), &t), "ST.E [R192], R6");
}

/// t156_5 (encode byte-parity): authored texts encode to words whose
/// nvdisasm-13.3 render equals the authored text (arbitrated pre-commit).
#[test]
fn t156_5_encode_window_placement() {
    let t = t103a();
    let w = enc(&t, "LDG.E R5, [R7+0x10]");
    assert_eq!((w >> 40) & 0xFF_FFFF, 0x10);
    assert_eq!((w >> 32) & 0xFF, 0);
    assert_eq!((w >> 24) & 0xFF, 7);
    for (v, raw) in [(-0x10i64, 0xfffff0u64), (-0x800000, 0x800000u64), (0x7fffff, 0x7fffffu64)] {
        let sv = if v < 0 { format!("+-0x{:x}", -v) } else { format!("+0x{v:x}") };
        let w = enc(&t, &format!("LDG.E R5, [R7{sv}]"));
        assert_eq!((w >> 40) & 0xFF_FFFF, u128::from(raw & 0xFF_FFFF), "LDG imm {v}");
    }
    let w = enc(&t, "ST.E [R192+0x1000000], R6");
    assert_eq!((w >> 24) & 0xFF, 192);
    assert_eq!((w >> 32) & 0xFFFF_FFFF, 0x1000000);
    let w = enc(&t, "STG.E.STRONG.GPU [R6+0x20], R9");
    assert_eq!((w >> 40) & 0xFF_FFFF, 0x20);
    assert_eq!((w >> 32) & 0xFF, 9);
    let w = enc(&t, "REDG.E.ADD.S32.STRONG.GPU [R4+0x40], R5");
    assert_eq!((w >> 40) & 0xFF_FFFF, 0x40);
    assert_eq!((w >> 32) & 0xFF, 5);
    let w = enc(&t, "LD.E R4, [R2+0x1000000]");
    assert_eq!((w >> 32) & 0xFFFF_FFFF, 0x1000000);
    let w = enc(&t, "LD.E R4, [R2+-0x80000000]");
    assert_eq!((w >> 32) & 0xFFFF_FFFF, 0x8000_0000);
}

/// t156_6 (roundtrip): decode -> print -> encode byte-exact on pin classes.
#[test]
fn t156_6_roundtrip_byte_exact() {
    for (t, words) in [
        (t103a(), vec![
            0x000ea400001009000000000402047980u128,
            0x000ea400001009000000000402047980u128 ^ (1u128 << 56),
            0x00032200001e09000000000084847381u128 ^ (0x123u128 << 40),
            0x000fe80000000200000000000a5b7984u128 ^ (0x55u128 << 40),
            0x0003e2000010e9000000000396007386u128 ^ (0x77u128 << 40),
            0x0003e2000010e300000000030400798eu128 ^ (0x11u128 << 40), // REDG sm103a-only row
        ]),
        (t120(), vec![
            0x000ea400001009000000000402047980u128,
            0x000ea400001009000000000402047980u128 ^ (1u128 << 56),
            0x00032200001e09000000000084847381u128 ^ (0x123u128 << 40),
            0x000fe80000000200000000000a5b7984u128 ^ (0x55u128 << 40),
            0x0003e2000010e9000000000396007386u128 ^ (0x77u128 << 40),
        ]),
    ] {
        let idx = DecodeIndex::build(&t);
        for w in words {
            let sass = dec(&idx, w, &t);
            let w2 = enc(&t, &sass);
            assert_eq!(w & !SCHED, w2 & !SCHED, "roundtrip {sass}");
        }
    }
}

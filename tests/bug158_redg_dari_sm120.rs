//! BUG-158 (F2, front2/blind): sm120 REDG non-EL int-op dARI/ARI rows missed
//! the immediato/descriptor geometry entirely.
//!   pre: REDG_ARI_R / REDG_dARI_R groups {ADD,AND},E,GPU,STRONG carried only
//!        sub_r1@24/8 + reg@32/8 — no imm field ([40:48) variable-mask-no-field
//!        => render-drop of small offsets; [48:64) match-fixed => fail-closed
//!        for +large/negative), no UR field (desc UR silently BAKED to the
//!        harvest value: ctl encoded `desc[UR10][R10.64]` to bytes nvdisasm
//!        renders as `desc[UR8][R10.64]`), junk full-op siblings mis-slotted
//!        (data reg @34 / base @25) competed for the same words.
//!   arb: nvdisasm 13.3.73, .target sm_120a, 16 raw-word probes
//!        (work/bug158/p158raw): imm = s24@[40:64) (sign=bit63, +/-0x800000
//!        round-trip), base R@[24:32) 8-bit (R130), data R@[32:40), desc
//!        UR@[64:72) (UR0..UR62 regular; 255=URZ). Plain `[R+imm]` ARI form
//!        for ADD/AND.GPU is a PHANTOM (UR=0 renders desc[UR0]); vendor-form
//!        census (30,406 paired anchors, work/bug142/hexdb): int GPU REDG
//!        non-EL emits desc-form ONLY. Donor = sm103a harvest row == AND-mask
//!        envelope of 1,947 sm_100 ADD anchors byte-for-byte.
//!   census (work/bug158/census158.json): zero strict/relaxed/broad anchors
//!        for all 4 defect rows on the current sm120 corpus (392 cubins /
//!        2,744,311 words); meta count=3/1/32/20 is stale-harvest.
//! fix: REDG_dARI_R {ADD,AND} rebuilt with donor geometry
//!      (guard@12/4, sub_ur0@64/8, sub_r1@24/8, sub_imm2@40/24, reg@32/8);
//!      REDG_ARI_R key + junk full-op keys removed (158b).

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::table::IsaTable;

const SCHED: u128 = 0xFFFF_FFFFu128 << 96;

fn t120() -> IsaTable {
    IsaTable::load(std::path::Path::new("tables/sm120.json")).unwrap()
}

fn enc(t: &IsaTable, text: &str) -> u128 {
    let insn = parse_sass(text, 0).expect("parse");
    encode_instruction(&insn, t).expect("encode") & !SCHED
}

fn enc_res(t: &IsaTable, text: &str) -> anyhow::Result<u128> {
    parse_sass(text, 0)
        .and_then(|insn| encode_instruction(&insn, t))
        .map(|w| w & !SCHED)
}

fn dec(idx: &DecodeIndex, w: u128, t: &IsaTable) -> String {
    idx.decode(w, 0, t)
        .map(|d| cubit::printer::to_sass(&d))
        .expect("decode")
}

fn imm_s24(w: u128) -> i64 {
    let v = ((w >> 40) & 0xFF_FFFF) as i64;
    if v & 0x80_0000 != 0 { v - 0x100_0000 } else { v }
}

/// t158_1 (invariant): table polygons of the two rebuilt rows — sub_imm2
/// exactly s24@[40:64) on tok1, sub_ur0@64/8, no field overlaps; phantom key
/// and junk keys are gone.
#[test]
fn t158_1_table_geometry() {
    let j: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string("tables/sm120.json").unwrap()).unwrap();
    for mg in ["ADD,E,GPU,STRONG", "AND,E,GPU,STRONG"] {
        let row = j.pointer(&format!("/instructions/REDG_dARI_R/mod_groups/{mg}"))
            .unwrap_or_else(|| panic!("row REDG_dARI_R[{mg}] missing"));
        let fields = row["fields"].as_array().unwrap();
        let imm: Vec<_> = fields.iter().filter(|f| f["extraction"] == "sub_imm2").collect();
        assert_eq!(imm.len(), 1, "{mg} imm count");
        assert_eq!(imm[0]["shift"].as_u64().unwrap(), 40, "{mg} imm shift");
        assert_eq!(imm[0]["bits"].as_u64().unwrap(), 24, "{mg} imm bits");
        assert_eq!(imm[0]["token_idx"].as_u64().unwrap(), 1, "{mg} imm token");
        let ur: Vec<_> = fields.iter().filter(|f| f["extraction"] == "sub_ur0").collect();
        assert_eq!(ur.len(), 1, "{mg} ur count");
        assert_eq!(ur[0]["shift"].as_u64().unwrap(), 64, "{mg} ur shift");
        let mut seen = 0u128;
        for f in fields {
            let (s, b) = (f["shift"].as_u64().unwrap(), f["bits"].as_u64().unwrap());
            let m = ((1u128 << b) - 1) << s;
            assert!(seen & m == 0, "{mg} overlapping field {:?}", f);
            seen |= m;
        }
    }
    // 2026-08-26 compose: REDG_ARI_R was RESTORED with the corrected BUG-156
    // geometry (imm @40/24-overlap-free) because the BUG-142 vendor battery
    // has a live witness for it ("REDG.E.ADD.S32.STRONG.GPU [R134], R3");
    // the phantom-shape version is what may not come back. Keep a geometry
    // guard instead of an absence guard.
    if let Some(r) = j.pointer("/instructions/REDG_ARI_R/mod_groups/ADD,E,GPU,S32,STRONG") {
        let fs = r["fields"].as_array().unwrap();
        let im: Vec<_> = fs.iter().filter(|f| f["extraction"] == "sub_imm1").collect();
        assert_eq!(im.len(), 1, "REDG_ARI_R S32 imm count");
        assert_eq!(im[0]["shift"].as_u64().unwrap(), 40, "REDG_ARI_R S32 imm shift");
        let regwin: std::collections::HashSet<u32> = fs.iter()
            .filter(|f| f["extraction"] == "reg")
            .flat_map(|f| {
                let (s, b) = (f["shift"].as_u64().unwrap() as u32, f["bits"].as_u64().unwrap() as u32);
                s..s + b
            }).collect();
        assert!((40..64).all(|b| !regwin.contains(&b)), "REDG_ARI_R imm/reg overlap");
    }
    assert!(j.pointer("/instructions/REDG.E.ADD.STRONG.GPU_dARI_R").is_none(), "junk ADD gone");
    assert!(j.pointer("/instructions/REDG.E.AND.STRONG.GPU_dARI_R").is_none(), "junk AND gone");
}

/// t158_2: decode of the nvdisasm-arbitrated raw words yields the vendor
/// text byte-exact (sans control annotation).
#[test]
fn t158_2_decode_vendor_words() {
    let t = t120();
    let idx = DecodeIndex::build(&t);
    let cases: &[(&str, &str)] = &[
        ("000fe2000c12e108000000050200098e", "@P0 REDG.E.ADD.STRONG.GPU desc[UR8][R2.64], R5"),
        ("0001e8000c12e10a0000100d0a00798e", "REDG.E.ADD.STRONG.GPU desc[UR10][R10.64+0x10], R13"),
        ("0001e8000c12e10afffffc0d0a00798e", "REDG.E.ADD.STRONG.GPU desc[UR10][R10.64+-0x4], R13"),
        ("0001e8000c12e10a8000000d0a00798e", "REDG.E.ADD.STRONG.GPU desc[UR10][R10.64+-0x800000], R13"),
        ("0001e8000c12e10a7fffff0d0a00798e", "REDG.E.ADD.STRONG.GPU desc[UR10][R10.64+0x7fffff], R13"),
        ("008fe2000e92e108000000050200098e", "@P0 REDG.E.AND.STRONG.GPU desc[UR8][R2.64], R5"),
        ("008fe2000e92e108fffff0050200098e", "@P0 REDG.E.AND.STRONG.GPU desc[UR8][R2.64+-0x10], R5"),
        ("000fe2000c12e108000000820200098e", "@P0 REDG.E.ADD.STRONG.GPU desc[UR8][R2.64], R130"),
        ("000fe2000c12e13e000000050200098e", "@P0 REDG.E.ADD.STRONG.GPU desc[UR62][R2.64], R5"),
    ];
    for (hexw, want) in cases {
        let w = u128::from_str_radix(hexw, 16).unwrap();
        let got = dec(&idx, w, &t);
        assert_eq!(&got, want, "decode {hexw}");
    }
}

/// t158_3: authored vendor forms encode to the arbitrated payload bytes
/// (payload == vendor word low96) and decode->re-encode is a fixed point.
/// Includes the pre-fix silent-corruption control: desc UR10 must NOT bake 8.
#[test]
fn t158_3_encode_vendor_bytes() {
    let t = t120();
    let idx = DecodeIndex::build(&t);
    let cases: &[(&str, u128)] = &[
        ("@P0 REDG.E.ADD.STRONG.GPU desc[UR8][R2.64], R5",
         u128::from_str_radix("000fe2000c12e108000000050200098e", 16).unwrap()),
        ("REDG.E.ADD.STRONG.GPU desc[UR10][R10.64+0x10], R13",
         u128::from_str_radix("0001e8000c12e10a0000100d0a00798e", 16).unwrap()),
        ("REDG.E.ADD.STRONG.GPU desc[UR10][R10.64+-0x4], R13",
         u128::from_str_radix("0001e8000c12e10afffffc0d0a00798e", 16).unwrap()),
        ("@P0 REDG.E.AND.STRONG.GPU desc[UR8][R2.64+-0x10], R5",
         u128::from_str_radix("008fe2000e92e108fffff0050200098e", 16).unwrap()),
        // UR10 no-imm: pre-fix silently baked UR=8; vendor payload has byte8=10
        ("REDG.E.ADD.STRONG.GPU desc[UR10][R10.64], R13",
         u128::from_str_radix("0001e8000c12e10a0000000d0a00798e", 16).unwrap()),
    ];
    for (text, want_low) in cases {
        let w = enc(&t, text);
        assert_eq!(w & !(SCHED >> 96 << 96 | 0), w, "mask noop"); // clarity: w already masked
        let want_masked = want_low & !SCHED;
        // vendor sched bytes are not authoritative here: compare payload+idle-ctrl bits only
        let cmp_mask: u128 = !SCHED;
        assert_eq!(w & cmp_mask, want_masked & cmp_mask, "{text}: payload bytes");
        assert_eq!(((w >> 64) & 0xFF), ((want_low >> 64) & 0xFF), "{text}: UR byte not baked");
        let d = dec(&idx, w, &t);
        let re = enc(&t, &d);
        assert_eq!(re & cmp_mask, w & cmp_mask, "{text}: decode->re-encode fixed point");
    }
}

/// t158_4 (invariant): the phantom plain-ARI form stays fail-closed in both
/// pre and post tables (vendor never emits it for ADD/AND.GPU non-EL).
#[test]
fn t158_4_phantom_ari_fail_closed() {
    let t = t120();
    assert!(enc_res(&t, "REDG.E.ADD.STRONG.GPU [R2+0x10], R5").is_err());
    assert!(enc_res(&t, "REDG.E.AND.STRONG.GPU [R2+0x10], R5").is_err());
}

/// t158_5: harvest-stale junk-shape word (UR6 / base R44 / imm0) decodes
/// through the rebuilt short key with the data reg taken from the vendor
/// window [32:40) — pre-fix the junk full-op row read it at shift 34 (=> R0).
#[test]
fn t158_5_junk_shape_word_correct_reg() {
    let t = t120();
    let idx = DecodeIndex::build(&t);
    // ADD base, UR6, base R44, imm 0, data R1 at [32:40)
    let w: u128 = u128::from_str_radix("0000e2000c12e106000000012c00798e", 16).unwrap();
    let got = dec(&idx, w, &t);
    assert!(
        got.contains("desc[UR6][R44.64], R1"),
        "junk-shape must decode via rebuilt row, got: {got}"
    );
}

/// t158_6: imm sign-window arithmetic on encode (s24 two's complement at
/// [40:64)) for both ADD and AND rows.
#[test]
fn t158_6_imm_sign_window() {
    let t = t120();
    let cases: &[(&str, i64)] = &[
        ("REDG.E.ADD.STRONG.GPU desc[UR10][R10.64+0x1], R13", 0x1),
        ("REDG.E.ADD.STRONG.GPU desc[UR10][R10.64+0x7fffff], R13", 0x7fffff),
        ("REDG.E.ADD.STRONG.GPU desc[UR10][R10.64+-0x800000], R13", -0x800000),
        ("REDG.E.AND.STRONG.GPU desc[UR8][R2.64+0x20], R5", 0x20),
        ("REDG.E.AND.STRONG.GPU desc[UR8][R2.64+-0x800000], R5", -0x800000),
    ];
    for (text, imm) in cases {
        let w = enc(&t, text);
        assert_eq!(imm_s24(w), *imm, "{text}: s24@[40:64)");
        assert_eq!(((w >> 63) & 1) as i64, (*imm < 0) as i64, "{text}: sign bit63");
    }
}

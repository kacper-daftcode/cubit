//! BUG-148 (F2-iter71): 94 decoder rows of tables/sm120.json carried
//! sub_r{0,1}@24 with bits==9 (harvest era 2aE). Window [24:33) bleeds bit32
//! (LSB of the sibling field at shift 32: sub_ur0/1 desc-UR or the second
//! data register of 256-bit forms) into the base-R numeral -> render
//! hallucination R+256, e.g. (pre-fix ctl-table decode of the arb words):
//!   LDG.E.64 R76, desc[UR9][R260.64]              (vendor/fixed: [R4.64])
//!   STG.E.ENL2.256 desc[UR20][R264.64], RZ, RZ    (vendor/fixed: [R8.64])
//!   ATOMG.E.CAS.64.STRONG.SYS PT, R10, [R268], ... (vendor/fixed: [R12])
//!   LDS R2, [R295]  (synthetic bit32=1; vendor ignores the residual bit)
//!
//! sm120-side port of BUG-147 (sm103a, 115 rows) / BUG-143 E1 (ATOM family).
//! LATENT on the vendor corpus (392 sm120 cubins, all_120.sass: zero odd-UR
//! [R+URn] / odd desc[URn] / LDS.S8; machine-verified in work/bug148) but the
//! geometry is identical to sm103a where live witnesses existed (cublasLt197
//! STG.256 +RZ, cublasLt468 LDS.S8), so the rows are normalized data-only:
//! census (work/bug148/census148.json): 94 rows = LDG 50/STG 16/LD 11/LDS 6/
//! LDL 3/ST 3/LDSM 3/ATOMG 2; 78/94 sibling-covered (match-set invariant,
//! render fixed on bit32=1 words); 16 no-cover rows surface bit32 as an
//! explicit `!rsd` residual instead of folding it into the R numeral.
//! All witness words below arbitrated byte-exact by nvdisasm 13.3 (sm_120a)
//! via the __raw__ graft in work/bug148/probe/arb.sass.

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::table::{Extraction, IsaTable};

const SCHED: u128 = 0xFFFF_FFFFu128 << 96;

fn t120() -> IsaTable {
    IsaTable::load(std::path::Path::new("tables/sm120.json")).unwrap()
}
fn enc(t: &IsaTable, text: &str) -> u128 {
    let insn = parse_sass(&format!("{text} ;"), 0).expect("parse");
    encode_instruction(&insn, t).expect("encode") & !SCHED
}
fn dec(t: &IsaTable, idx: &DecodeIndex, w: u128) -> String {
    idx.decode(w, 0, t).map(|d| cubit::printer::to_sass(&d)).expect("decode")
}

/// Synthesized probes (work/bug148/probe), nvdisasm-13.3 arbitrated:
/// (word incl. sched stripe, vendor text)
const WITNESS: &[(u128, &str)] = &[
    // sibling sub_ur0@32/8 (desc-UR) odd: bit32=1 bled into addr-R pre-fix
    (0x000fe8000c1e1b00_00000009_044c7981, "LDG.E.64 R76, desc[UR9][R4.64]"),
    // sibling reg@32/8 = RZ sentinel 255 (data reg of the 256-bit store)
    (0x000fc8000f121814_f80000ff_08ff797f, "STG.E.ENL2.256 desc[UR20][R8.64], RZ, RZ"),
    // ATOM-family CAS (BUG-143 E1 analog): sibling reg@32/8 = odd compare reg
    (0x000fe800001f450a_00000009_0c0a73a9, "ATOMG.E.CAS.64.STRONG.SYS PT, R10, [R12], R9, R10"),
];

/// Even-UR / even-reg controls (clean pre and post):
const CONTROL: &[(u128, &str)] = &[
    (0x000fe8000c1e1b00_00000008_044c7981, "LDG.E.64 R76, desc[UR8][R4.64]"),
    (0x000fc8000f121814_f800000a_080b797f, "STG.E.ENL2.256 desc[UR20][R8.64], R10, R11"),
    (0x000fe800001f450a_00000008_0c0a73a9, "ATOMG.E.CAS.64.STRONG.SYS PT, R10, [R12], R8, R10"),
];

/// Synthetic no-cover probe: LDS_R_ARI '' with bit32 poked to 1.
const LDS_BIT32: u128 = 0x000fe80000000800_00000001_27027984;

#[test]
fn t148_1_witness_decode_vendor_exact() {
    let t = t120();
    let idx = DecodeIndex::build(&t);
    for (w, want) in WITNESS {
        let got = dec(&t, &idx, *w);
        assert_eq!(&got, want, "witness decode must match vendor (no R+256)");
        for bad in ["R260", "R264", "R268", "R295"] {
            assert!(!got.contains(bad), "R+256 hallucination regressed: {got}");
        }
    }
}

#[test]
fn t148_2_witness_encode_byte_exact() {
    let t = t120();
    for (w, text) in WITNESS {
        assert_eq!(enc(&t, text), w & !SCHED, "encode parity: {text}");
    }
}

#[test]
fn t148_3_control_encode_decode_roundtrip() {
    let t = t120();
    let idx = DecodeIndex::build(&t);
    for (w, text) in CONTROL {
        assert_eq!(enc(&t, text), w & !SCHED, "encode parity: {text}");
        assert_eq!(&dec(&t, &idx, *w), text, "decode parity: {text}");
    }
}

#[test]
fn t148_4_table_class_normalized() {
    // All 94 sub_r{0,1}@24/9 rows are narrowed (incl. the 2 ATOMG CAS groups —
    // sm120 has no parked E1 side-channel; BUG-142 kept bits==9 there).
    let t = t120();
    let mut offenders = vec![];
    for (key, ins) in &t.entries {
        for (gn, g) in &ins.mod_groups {
            for f in &g.fields {
                if f.shift == 24 && f.bits == 9
                    && matches!(f.extraction, Extraction::SubR(0) | Extraction::SubR(1))
                {
                    offenders.push(format!("{key}[{gn:?}]"));
                }
            }
        }
    }
    // 2026-08-26 wave-2: BUG-189 (arb189 ptxas-corroborated) keeps the ATOMS
    // 32,INC,POPC groups genuinely 9-bit @24 (the hoover dest window moved
    // [7:15) sink side); the E1-class exemption narrowed to exactly these two
    // arb189-proven rows. Everything else stays 8-bit.
    const ALLOW: &[&str] = &[r#"ATOMS_R_ARURI["32,INC,POPC"]"#, r#"ATOMS_R_ARI["32,INC,POPC"]"#];
    let bad: Vec<_> = offenders.iter().filter(|o| !ALLOW.contains(&o.as_str())).collect();
    assert!(bad.is_empty(),
        "sm120.json sub_r@24/9 outside the arb189-proven pair: {bad:?}");
}

#[test]
fn t148_5_no_cover_residual_not_folded() {
    // bit32=1 on a no-cover row must NOT fold into the R numeral: decode
    // yields the base address, and the re-encode diff isolates exactly the
    // unexplained residual bit32 (what `cubit disassemble` renders as the
    // `!rsd[32:1]` overlay).
    let t = t120();
    let idx = DecodeIndex::build(&t);
    let got = dec(&t, &idx, LDS_BIT32);
    assert_eq!(got, "LDS R2, [R39]", "no R+256 hallucination; text is the base form");
    let reenc = enc(&t, &got);
    let delta = (LDS_BIT32 ^ reenc) & !SCHED;
    assert_eq!(delta, 1u128 << 32,
        "only bit32 may be unexplained (CLI !rsd[32:1]); delta={delta:#036x}");
    // a fabricated wide numeral is fail-closed at the parser boundary
    // ("every bracket component must classify once"), before encode
    assert!(parse_sass("LDS R2, [R295] ;", 0).is_err(),
        "R295 must be unparseable/unencodable through the 8-bit window");
}

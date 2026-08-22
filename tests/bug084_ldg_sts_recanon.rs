//! BUG-084 (F2Q, 2026-08-22): memory-family key re-canonicalization in
//! sm120.json (LDG/STS/STG/LDGSTS/DEPBAR/LDGDEPBAR: 158 legacy harvest keys
//! -> 21 keys at sm103a geometry) + ERRBAR shadow-fix (junk bit2-field removed, bit2 pinned;ERRBAR itself is vendor-real).
//!
//! Symptom classes fixed (all proven word-level against cuobjdump 13.3 on
//! the 2049-cubin corpus, 678,608 LDG/STS/STG-family records; report
//! results/cubitfix/084.md):
//!   * LDG.E.{64,128,S8}.CONSTANT decoded with halved regs/UR + phantom imm
//!     (e.g. `R12, desc[UR10][R12.64]` -> `R6, desc[UR1][R6.64], 0x0`);
//!   * LDG.E.EF[.{64,128,U16,S8}] mis-routed to LDG.E.LTC128B.128 rows;
//!   * LDG.E.*.STRONG.{SM,SYS,GPU} UR/desc halving ([UR8][R2.64] ->
//!     [UR4][R1.64]);
//!   * STS.64 addr<->data operand swap (`STS.64 [R7], R4` -> `STS.64_AR
//!     R3, R2`) and sm120-only `*_AR_R`/`_ARUR_R` phantom sigs;
//!   * LDGSTS/LDGDEPBAR/DEPBAR dotted-key harvest junk (LDGDEPBAR was
//!     shadow-decoded as ERRBAR by the ERRBAR row: junk bit2-field pulled
//!     bit2 out of match_mask, while its variable mask covered bits 12-15;
//!     zero-content field removed + bit2 pinned -- ERRBAR (0x79ab) itself
//!     is vendor-real: 2,254 corpus anchors across p_fence/k31/k33c1..);
//!   * LDG.E.ENL2.256 pair-form missing entirely (LDG_R_R_dARI key absent).
//! Parity: (False,True)=119,865 records 100% fixed, (True,True)=557,047
//! unchanged, residual (False,False)=1,680 = text-parity classes only
//! (LDGSTS `.BYPASS.E` render order = printer RP-class, STS `[R+URZ]`
//! UR255 alias print, `[URn+-0x..]` sign format, LDG.E [Rn.64+UR+imm]
//! geometry gap = b4 coverage). ok->BAD: 16 records, all the cosmetic
//! `+-` sign-format class (now rendering like sm103a's print).

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::table::IsaTable;

fn t120() -> IsaTable { IsaTable::load(std::path::Path::new("tables/sm120.json")).unwrap() }
const M96: u128 = (1u128 << 96) - 1;

/// (full 128-bit instruction word, vendor canonical text) — anchors
/// section-aligned from the vendor census (cuobjdump 13.3).
const GOLD: &[(u128, &str)] = &[
    (0x000ea2000c1e9b000000000a0c0c7981, "LDG.E.64.CONSTANT R12, desc[UR10][R12.64]"),
    (0x000ea2000c0e1b00000000180a0a7981, "LDG.E.EF.64 R10, desc[UR24][R10.64]"),
    (0x000fea0000000a000000000407007388, "STS.64 [R7], R4"),
    (0x000ea4000c1f590000000008022f7981, "LDG.E.STRONG.SYS R47, desc[UR8][R2.64]"),
    (0x002ee2000c1e9d000000000404047981, "LDG.E.128.CONSTANT R4, desc[UR4][R4.64]"),
    (0x000ea8000c1e93000000801c06247981, "LDG.E.S8.CONSTANT R36, desc[UR28][R6.64+0x80]"),
    (0x002ea6000c0e19000000040406077981, "LDG.E.EF R7, desc[UR4][R6.64+0x4]"),
    (0x0004e2000c0e1500000000101a297981, "LDG.E.EF.U16 R41, desc[UR16][R26.64]"),
    (0x0005e8000b9a1414000000002873afae, "@!P2 LDGSTS.E.64 [R115], desc[UR20][R40.64]"),
    (0x010fe8000b9a10060000000004077fae, "LDGSTS.E [R7], desc[UR6][R4.64]"),
    (0x0004e2000c1e15200000001a16111981, "@P1 LDG.E.LTC128B.U16 R17, desc[UR26][R22.64]"),
    (0x0003e4000c10bb08000000061c001986, "@P1 STG.E.64.STRONG.SM desc[UR8][R28.64], R6"),
    (0x001fe2000c1011040000000002007986, "STG.E.U8 desc[UR4][R2.64], R0"),
    (0x000e22000000000000000000000079af, "LDGDEPBAR"),
    (0x0041e80000000c00000000040f00c388, "@!P4 STS.128 [R15], R4"),
    (0x000162000812190cfe0000161204097e, "@P0 LDG.E.ENL2.256 R12, R4, desc[UR22][R18.64]"),
    (0x000f22000c1eb500000000101c287981, "LDG.E.U16.STRONG.SM R40, desc[UR16][R28.64]"),
    (0x0005e2000c115b0c000000ff0e009986, "@!P1 STG.E.64.STRONG.SYS desc[UR12][R14.64], RZ"),
    (0x000ea2000c0e1d000000001808087981, "LDG.E.EF.128 R8, desc[UR24][R8.64]"),
    (0x0001e200000004000000000809007388, "STS.U16 [R9], R8"),
    (0x000ea2000c1ebb000000000a5e5e7981, "LDG.E.64.STRONG.SM R94, desc[UR10][R94.64]"),
    (0x0007e2000b9a16180000000006097fae, "LDGSTS.E.LTC128B.64 [R9], desc[UR24][R6.64]"),
];

#[test]
fn bug084_decode_vendor_exact_sm120() {
    let t = t120();
    let idx = DecodeIndex::build(&t);
    for &(w, golden) in GOLD {
        let d = idx.decode(w, 0, &t).unwrap();
        let text = cubit::printer::to_sass(&d);
        assert_eq!(text, golden, "word {w:032x}");
    }
}

#[test]
fn bug084_roundtrip_word_exact_sm120() {
    // encode(decode(w)) == w on the payload 96 bits for every anchor
    let t = t120();
    let idx = DecodeIndex::build(&t);
    for &(w, golden) in GOLD {
        let d = idx.decode(w, 0, &t).unwrap();
        let text = cubit::printer::to_sass(&d);
        let insn = parse_sass(&format!("{text} ;"), 0).unwrap();
        let w2 = encode_instruction(&insn, &t)
            .unwrap_or_else(|e| panic!("encode failed for {text}: {e}"));
        assert_eq!(w2 & M96, w & M96, "loop {golden}");
    }
}

#[test]
fn bug084_errbar_shadow_broken() {
    // ERRBAR is a REAL vendor op (2,254 corpus anchors, always 0x79ab) but
    // pre-084 its row shadow-decoded every LDGDEPBAR (0x79af, bit2=1) via a
    // junk bit2 field + variable bits 12-15. Pin the boundary: ERRBAR
    // anchors decode as ERRBAR, LDGDEPBAR anchors as LDGDEPBAR.
    let t = t120();
    let idx = DecodeIndex::build(&t);
    let w_err: u128 = 0x000fc0000000000000000000000079ab; // ERRBAR (k31.cubin)
    let w_dep: u128 = 0x000e22000000000000000000000079af; // LDGDEPBAR (b_cpasync)
    let d1 = idx.decode(w_err, 0, &t).unwrap();
    assert_eq!(cubit::printer::to_sass(&d1), "ERRBAR");
    let d2 = idx.decode(w_dep, 0, &t).unwrap();
    assert_eq!(cubit::printer::to_sass(&d2), "LDGDEPBAR");
    assert_eq!(d2.key, "LDGDEPBAR");
}

#[test]
fn bug084_sts64_no_operand_swap() {
    // The addr<->data swap bug: `STS.64 [R7], R4` used to decode to
    // `STS.64_AR R3, R2`. Pin both halves of the address form family.
    let t = t120();
    let idx = DecodeIndex::build(&t);
    let w: u128 = 0x000fea0000000a000000000407007388; // STS.64 [R7], R4
    let d = idx.decode(w, 0, &t).unwrap();
    assert_eq!(d.key, "STS_ARI_R");
    assert_eq!(d.mod_group, "64");
    assert_eq!(cubit::printer::to_sass(&d), "STS.64 [R7], R4");
}

#[test]
fn bug084_dropped_speculative_keys_fail_closed() {
    // Dotted harvest-junk keys without any corpus anchor were removed;
    // their text forms must fail closed instead of silently encoding junk.
    let t = t120();
    assert!(t.get_key("LDG.E.NA.128_R_dARI").is_none());
    assert!(t.get_key("STG.E_P_dARI_R").is_none());
    assert!(t.get_key("STS.64_P0_AR_R").is_none());
}

#[test]
fn bug084_raw_addr_plain_roundtrip_word_exact() {
    // The legacy SM120 raw-address template rebuild (0x0c101900/0x986 baked
    // paths) used to clobber plain raw-address LDG/STG encode even when the
    // selected entry fully owned the Addr operand. Post-084 the canon
    // entries own the geometry; encode must emit the vendor-exact word.
    let t = t120();
    const TRIPLES: &[(u128, &str)] = &[
        (0x001009000000000a02007386, "STG.E [R2], R10"),
        (0x001009000000040b02007386, "STG.E [R2+0x4], R11"),
        (0x00000a000000000407007388, "STS.64 [R7], R4"),
    ];
    let idx = DecodeIndex::build(&t);
    for &(w, text) in TRIPLES {
        let insn = parse_sass(&format!("{text} ;"), 0).unwrap();
        let enc = encode_instruction(&insn, &t)
            .unwrap_or_else(|e| panic!("encode {text}: {e}"));
        assert_eq!(enc & M96, w & M96, "encode exact {text}");
        let d = idx.decode(enc, 0, &t).unwrap();
        assert_eq!(cubit::printer::to_sass(&d), text, "re-decode echo {text}");
    }
}

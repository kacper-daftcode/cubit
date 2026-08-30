//! BUG-253 (F2-iter129, loop5/blind front2, 2026-08-28): decoder.rs
//! `extraction_name()` had no `NegShl1` arm -- Debug-lowercase catch-all
//! emitted "negshl1", which the printer's "neg_shl1" arm never matches, so
//! the DFMA sign windows were silently dropped from sm121a decoded text
//! (inventory: exactly 12 NegShl1 field slots over 4 sm121a DFMA keys;
//! zero on sm100a/sm103a/sm120). Encoder made exact printer-inverse +
//! raw-abs preservation ((neg<<1)|abs) so the vendor-legal both-set window
//! ('-|R|', value 3) round-trips.
//!
//! Evidence: law251 census (2,406-cubin battery, nvdisasm 13.3.73): DFMA
//! 465,175 uniq / 1,134,688 occ; sm121a pre-fix pure_sign class 61,436 uniq
//! (58,385 R_R_R_R + 2,093 R_R_UR_R + 958 R_R_II_R) -> post-fix MATCH.
//! arb251b/arb253 (raw -b SM121a + SM103a, identical models): tok3 window
//! @62: b63=neg '-R64', b62=abs '|R64|', both '-|R64|'; tok4 window @74:
//! b75=neg '-R28', b74=abs '|R28|', both '-|R28|'.
//!
//! Poswitium: reuse_drop class (340 uniq, DFMA_R_R_R_II imm-tail) is
//! ARCH-DIVERGENT (arb253: vendor prints '.reuse' for b123 under SM100a/
//! SM103a raw models but NOT under SM121a) -> registered 256-kand, parked
//! for owner (policy: law-glyph parity vs raw-121a fidelity); sentinel
//! t253_5 pins status quo until decided.
use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::{Extraction, IsaTable};

const M96: u128 = (1u128 << 96) - 1;
fn tab(arch: &str) -> IsaTable {
    IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap()
}
fn dec(t: &IsaTable, w: u128) -> Option<String> {
    let idx = DecodeIndex::build(t);
    idx.decode(w, 0, t).map(|d| to_sass(&d)).ok()
}
fn enc(t: &IsaTable, text: &str) -> u128 {
    let insn = parse_sass(&format!("{text};"), 0).unwrap_or_else(|e| panic!("parse {text}: {e}"));
    encode_instruction(&insn, t).unwrap_or_else(|e| panic!("encode {text}: {e}"))
}

// arb251b/arb253 witnesses (full 128-bit; engine matches 96-bit payload).
const W_DF_BASE: u128 = 0x4fc6000000001c000000402020722b; // DFMA R32, R32, R64, R28
const W_DF_T3_NEG: u128 = W_DF_BASE ^ (1u128 << 63); //      vend: -R64
const W_DF_T3_ABS: u128 = W_DF_BASE ^ (1u128 << 62); //      vend: |R64|
const W_DF_T3_BOTH: u128 = W_DF_BASE ^ (3u128 << 62); //     vend: -|R64|
const W_DF_T4_NEG: u128 = W_DF_BASE ^ (1u128 << 75); //      vend: -R28
const W_DF_T4_ABS: u128 = W_DF_BASE ^ (1u128 << 74); //      vend: |R28|
const W_DF_T4_BOTH: u128 = W_DF_BASE ^ (3u128 << 74); //     vend: -|R28|
                                                      // law251 corpus witnesses (post-fix sm121a decode == vendor glyph).
const W_CORP_IIR: u128 = 0xfd4000000080e400000002020782b; // DFMA R32, R32, 2, -R14
const W_CORP_URR: u128 = 0xfca0008000806000000100c067c2b; // DFMA R6, R12, UR16, -R6
const W_CORP_RRRR: u128 = 0x4fd000000000088000003c1e08722b; // DFMA R8, R30, -R60, R8
                                                            // 256-kand sentinel: imm-tail reuse word (vendor sm100-model prints
                                                            // '-R46.reuse'; vendor raw SM121a prints no reuse).
const W_II_REUSE: u128 = 0x81e24000000082e3ff000004630742b; // DFMA R48, R70, -R46(.reuse), 1

#[test]
fn t253_1_structure() {
    // NegShl1 field slots: exactly 12, all sm121a DFMA keys; shapes:
    //   R_R_R_R  x3 mgs x{tok3 2b@62, tok4 2b@74} = 6
    //   R_R_II_R x3 mgs x tok4 2b@74            = 3
    //   R_R_R_FI RM/RP x tok3 2b@74             = 2
    //   R_R_UR_R '' x tok4 2b@74                = 1
    let t = tab("sm121a");
    let mut shapes: Vec<(String, String, i32, u32, u32)> = Vec::new();
    for (k, row) in &t.entries {
        for (mg, g) in &row.mod_groups {
            for f in &g.fields {
                if f.extraction == Extraction::NegShl1 {
                    assert!(k.starts_with("DFMA"), "NegShl1 outside DFMA: {k}");
                    shapes.push((k.clone(), mg.clone(), f.token_idx, f.shift, f.bits));
                }
            }
        }
    }
    assert_eq!(shapes.len(), 12, "sm121a NegShl1 inventory drifted");
    for (_, _, tok, shift, bits) in &shapes {
        assert_eq!(*bits, 2, "NegShl1 must be a 2-bit window");
        assert!(
            (*tok, *shift) == (3, 62) || (*tok, *shift) == (3, 74) || (*tok, *shift) == (4, 74),
            "unexpected NegShl1 placement tok={tok} @{shift}"
        );
    }
    for arch in ["sm100a", "sm103a", "sm120"] {
        let t = tab(arch);
        for (k, row) in &t.entries {
            for (_mg, g) in &row.mod_groups {
                for f in &g.fields {
                    assert!(
                        f.extraction != Extraction::NegShl1,
                        "{arch} {k}: NegShl1 must stay sm121a-scoped"
                    );
                }
            }
        }
    }
    // BUG-253 table graft (canon 14cb404): DFMA_R_R_R_R[''] tok2 must carry
    // the donor-parallel split neg 1b@72 + abs 1b@73 (era 2-bit neg@72
    // conflated the abs-only window into a spurious '-' ghost, 170 uniq
    // corpus words). Global 2-bit 'neg' census = 258-kand. BUG-258
    // (canon 741f3a1) split the 4 corpus-exposed rows (DFMA RM/RP tok2 +
    // UFADD tok2/tok3 on sm120+sm121a; arb258 law), residuum = 261-kand:
    // 51 sm120 + 66 sm121a (donors stay 0).
    let t = tab("sm121a");
    let g = t.entries["DFMA_R_R_R_R"]
        .mod_groups
        .get("")
        .expect("DFMA_R_R_R_R/''");
    let tok2: Vec<(u32, u32, &str)> = g
        .fields
        .iter()
        .filter(|f| f.token_idx == 2 && (f.shift == 72 || f.shift == 73))
        .map(|f| {
            (
                f.shift,
                f.bits,
                match f.extraction {
                    Extraction::Neg => "neg",
                    Extraction::Abs => "abs",
                    _ => "other",
                },
            )
        })
        .collect();
    assert_eq!(
        tok2,
        vec![(72u32, 1u32, "neg"), (73u32, 1u32, "abs")],
        "DFMA_R_R_R_R/'' tok2 split drifted"
    );
    let neg2b = |arch: &str| -> usize {
        tab(arch)
            .entries
            .values()
            .flat_map(|r| r.mod_groups.values())
            .flat_map(|g| g.fields.iter())
            .filter(|f| f.extraction == Extraction::Neg && f.bits == 2)
            .count()
    };
    // post-261 (F2-iter134, canonical dac676b): full residuum closed by
    // patch261 grafts; the 7 registry rows remained (I2I x2, I2IP x4,
    // FMNMX II-'?' = 265-kand b3-line; see tests/bug261_neg2b_resid.rs).
    // FLIPPED 2026-08-29 (BUG-265 closure): 5 phantom/poison rows DELETED,
    // I2IP '' retyped to opmod:H1, FMNMX-'?' DELETED => census ZERO.
    assert_eq!(
        neg2b("sm121a"),
        0,
        "sm121a 2-bit neg census (post-265 closure) drifted"
    );
    assert_eq!(
        neg2b("sm120"),
        0,
        "sm120 2-bit neg census (post-265 closure) drifted"
    );
    assert_eq!(neg2b("sm100a"), 0, "donor sm100a must stay 2-bit-neg free");
    assert_eq!(neg2b("sm103a"), 0, "donor sm103a must stay 2-bit-neg free");
}

#[test]
fn t253_2_decode_vendor_true() {
    let cases: &[(u128, &str)] = &[
        (W_DF_BASE, "DFMA R32, R32, R64, R28"),
        (W_DF_T3_NEG, "DFMA R32, R32, -R64, R28"),
        (W_DF_T3_ABS, "DFMA R32, R32, |R64|, R28"),
        (W_DF_T3_BOTH, "DFMA R32, R32, -|R64|, R28"),
        (W_DF_T4_NEG, "DFMA R32, R32, R64, -R28"),
        (W_DF_T4_ABS, "DFMA R32, R32, R64, |R28|"),
        (W_DF_T4_BOTH, "DFMA R32, R32, R64, -|R28|"),
    ];
    for arch in ["sm100a", "sm103a", "sm120", "sm121a"] {
        let t = tab(arch);
        for (i, (w, want)) in cases.iter().enumerate() {
            let got = dec(&t, *w).unwrap_or_else(|| panic!("{arch} case{i} HOLE"));
            assert_eq!(
                got, *want,
                "{arch} case{i} decode != vendor (arb251b/arb253)"
            );
        }
    }
    // Corpus witnesses on the fixing leg (sm121a).
    let t = tab("sm121a");
    for (i, (w, want)) in [
        (W_CORP_IIR, "DFMA R32, R32, 2, -R14"),
        (W_CORP_URR, "DFMA R6, R12, UR16, -R6"),
        (W_CORP_RRRR, "DFMA R8, R30, -R60, R8"),
    ]
    .iter()
    .enumerate()
    {
        let got = dec(&t, *w).unwrap_or_else(|| panic!("sm121a corp{i} HOLE"));
        assert_eq!(got, *want, "sm121a corp{i} decode != law251 glyph");
    }
}

#[test]
fn t253_3_encode_payload_exact() {
    let t = tab("sm121a");
    let cases: &[(&str, u128)] = &[
        ("DFMA R32, R32, R64, R28", W_DF_BASE),
        ("DFMA R32, R32, -R64, R28", W_DF_T3_NEG),
        ("DFMA R32, R32, |R64|, R28", W_DF_T3_ABS),
        ("DFMA R32, R32, -|R64|, R28", W_DF_T3_BOTH),
        ("DFMA R32, R32, R64, -R28", W_DF_T4_NEG),
        ("DFMA R32, R32, R64, -|R28|", W_DF_T4_BOTH),
    ];
    for (i, (text, w)) in cases.iter().enumerate() {
        let got = enc(&t, text);
        assert_eq!(got & M96, w & M96, "case{i} encode payload drift ({text})");
    }
}

#[test]
fn t253_4_roundtrip() {
    for arch in ["sm100a", "sm103a", "sm120", "sm121a"] {
        let t = tab(arch);
        for (i, w) in [
            W_DF_BASE,
            W_DF_T3_NEG,
            W_DF_T3_ABS,
            W_DF_T3_BOTH,
            W_DF_T4_NEG,
            W_DF_T4_ABS,
            W_DF_T4_BOTH,
        ]
        .iter()
        .enumerate()
        {
            let txt = dec(&t, *w).unwrap_or_else(|| panic!("{arch} w{i} decode"));
            let back = enc(&t, &txt);
            assert_eq!(back & M96, w & M96, "{arch} w{i} roundtrip drift: {txt}");
        }
    }
    let t = tab("sm121a");
    for (i, w) in [W_CORP_IIR, W_CORP_URR, W_CORP_RRRR].iter().enumerate() {
        let txt = dec(&t, *w).unwrap_or_else(|| panic!("sm121a corp{i} decode"));
        let back = enc(&t, &txt);
        assert_eq!(back & M96, w & M96, "sm121a corp{i} roundtrip drift: {txt}");
    }
}

#[test]
fn t253_5_sentinel_256_reuse_parked() {
    // 256-kand sentinel (parked owner class, see file header): the imm-tail
    // reuse bit stays vendor-121a-faithful = NOT printed on sm121a until the
    // owner picks the policy (law glyph = sm100 model prints '-R46.reuse').
    // Donor control: sm100a prints '.reuse' (its R_R_R_FI row carries the
    // tok3 reuse field) -- keeps the donor-parity observation gate alive.
    let s121a = tab("sm121a");
    let s100a = tab("sm100a");
    assert_eq!(
        dec(&s100a, W_II_REUSE).as_deref(),
        Some("DFMA R48, R70, -R46.reuse, 1"),
        "donor leg lost imm-tail reuse (raw model parity changed?)"
    );
    assert_eq!(
        dec(&s121a, W_II_REUSE).as_deref(),
        Some("DFMA R48, R70, -R46, 1"),
        "256 sentinel: sm121a now prints imm-tail reuse -- retire this pin into the 256 fix"
    );
}

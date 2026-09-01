//! BUG-330 (F2-iter176, loop5/blind front2, 2026-09-01): dense-leg II_FI
//! tok4 f16@48 field-closure -- +tok4 16b@48 on HFMA2_R_R_R_II_FI x36 mgs
//! + 12 RELU _P era keys, legs sm120+sm121a (canonical 4a46e95,
//!
//! ride-after 65a6aab/BUG-329). Registered 330-kand LOW at F2-iter165
//! (312 report sec.6).
//!
//! MEASUREMENT (publish f77bb8e, canonical 2761da4; work/bug329/
//! measure_pre329{,b}.json): behavioral parity PRE-EXISTED on documented
//! paths (FI_FI shadow owns g7/imm words via its armed f16@48; guard-
//! generic match). REAL zarodek closed: vendor-legal junk/inert-pred
//! words b87[b88,b89,b90] (no RELU b79) + imm48!=0 were LOUD HOLES
//! dense-side; post-graft II_FI wins with tok4 armed = vendor-equal
//! text. RELU-b79+imm already decoded via FI_FI_RELU_P era keys (312-B)
//! = parity pins here. Election: FI_FI match_mask keeps strictly more
//! checks ({87..90,122..127}); g7 imm words keep FI_FI ownership.
//!
//! LAW: arb329 71 probes nvdisasm 13.3.73 raw -b, x4 models agree on
//! EVERY probe; work/bug329/arb329_verdicts.json.
use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::{Extraction, IsaTable};

const M96: u128 = (1u128 << 96) - 1;
const B78: u128 = 1 << 78;
const B79: u128 = 1 << 79;
const B85: u128 = 1 << 85;
const B86: u128 = 1 << 86;
const B87: u128 = 1 << 87;
const B90: u128 = 1 << 90;
const H1: u128 = 0x3c00u128 << 48;
const H15: u128 = 0x3e00u128 << 48;
const H1P: u128 = 0x3c01u128 << 48;
const HN2: u128 = 0xc000u128 << 48;
const BF1: u128 = 0x3f80u128 << 48;
const II0: u128 = 0x0431 | (2 << 16) | (3 << 24) | (4 << 64);

fn tab(arch: &str) -> IsaTable {
    IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap()
}
fn dec(t: &IsaTable, w: u128) -> Option<String> {
    let idx = DecodeIndex::build(t);
    idx.decode(w & M96, 0, t)
        .map(|d| to_sass(&d))
        .ok()
        .map(|s| s.trim_end().trim_end_matches(';').to_string())
}
fn enc(t: &IsaTable, text: &str) -> Result<u128, String> {
    let insn = parse_sass(&format!("{text};"), 0).map_err(|e| format!("parse: {e}"))?;
    encode_instruction(&insn, t).map_err(|e| format!("encode: {e}"))
}

#[test]
fn t330_1_structure_graft_and_siblings() {
    for leg in ["sm120", "sm121a"] {
        let t = tab(leg);
        let iifi = &t.entries["HFMA2_R_R_R_II_FI"];
        assert_eq!(iifi.mod_groups.len(), 36, "{leg}: II_FI mg count drift");
        let tok4 = |mg: &cubit::table::ModGroupEntry| {
            mg.fields
                .iter()
                .filter(|f| {
                    f.shift == 48
                        && f.bits == 16
                        && f.token_idx == 4
                        && matches!(f.extraction, Extraction::F16d)
                })
                .count()
        };
        let tok4b = |mg: &cubit::table::ModGroupEntry| {
            mg.fields
                .iter()
                .filter(|f| {
                    f.shift == 48
                        && f.bits == 16
                        && f.token_idx == 4
                        && matches!(f.extraction, Extraction::BF16)
                })
                .count()
        };
        for (mn, mg) in &iifi.mod_groups {
            let isbf = mn.contains("BF16_V2");
            assert_eq!(tok4(mg), (!isbf) as usize, "{leg}[{mn}]: f16_d@48 count");
            assert_eq!(tok4b(mg), isbf as usize, "{leg}[{mn}]: bf16@48 count");
            assert_eq!(
                mg.and_base & (0xffffu128 << 48),
                0,
                "{leg}[{mn}]: ab carries tok4"
            );
        }
        for k in t.entries.keys() {
            if k.starts_with("HFMA2.") && k.ends_with("_R_R_R_II_FI_P") {
                let mg = &t.entries[k].mod_groups[""];
                let isbf = k.contains("BF16_V2");
                assert_eq!(tok4(mg), (!isbf) as usize, "{leg}: era {k}: f16_d@48 count");
                assert_eq!(tok4b(mg), isbf as usize, "{leg}: era {k}: bf16@48 count");
            }
        }
        // II_II siblings untouched (era-288 geometry)
        let iiii = &t.entries["HFMA2_R_R_R_II_II"].mod_groups[""];
        assert_eq!(tok4(iiii), 1, "{leg}: II_II '' lost its tok4 field");
    }
    // sparse legs: no II_FI/II_II keys at all (329/330 sparse-NEGATYW line)
    for leg in ["sm100a", "sm103a"] {
        let t = tab(leg);
        assert!(
            !t.entries.contains_key("HFMA2_R_R_R_II_FI"),
            "{leg}: II_FI key!"
        );
        assert!(
            !t.entries.contains_key("HFMA2_R_R_R_II_II"),
            "{leg}: II_II key!"
        );
    }
}

#[test]
fn t330_2_decode_law_vendor_equal_dense() {
    let cases: &[(u128, &str)] = &[
        (0, "@P0 HFMA2 R2, R3, R4, 0, 0"),
        (H1, "@P0 HFMA2 R2, R3, R4, 1, 0"),
        (0x3c00u128 << 32, "@P0 HFMA2 R2, R3, R4, 0, 1"),
        (H1 | (0x3c00u128 << 32), "@P0 HFMA2 R2, R3, R4, 1, 1"),
        (H15, "@P0 HFMA2 R2, R3, R4, 1.5, 0"),
        (H1P, "@P0 HFMA2 R2, R3, R4, 1.0009765625, 0"),
        (HN2, "@P0 HFMA2 R2, R3, R4, -2, 0"),
        (B85 | BF1, "@P0 HFMA2.BF16_V2 R2, R3, R4, 1, 0"),
        (
            B85 | BF1 | (0x3f80u128 << 32),
            "@P0 HFMA2.BF16_V2 R2, R3, R4, 1, 1",
        ),
        // zarodek: junk/inert pred bits, no RELU -> HOLE pre, armed post
        (H1 | B87, "@P0 HFMA2 R2, R3, R4, 1, 0"),
        (B78 | H1 | B87, "@P0 HFMA2.F32 R2, R3, R4, 1, 0"),
        // RELU era parity (decoded pre via FI_FI_RELU_P, 312-B)
        (B79 | H1, "@P0 HFMA2.RELU R2, R3, R4, 1, 0, P0"),
        (B79 | B87 | H1, "@P0 HFMA2.RELU R2, R3, R4, 1, 0, P1"),
        (B79 | B90 | H1, "@P0 HFMA2.RELU R2, R3, R4, 1, 0, !P0"),
    ];
    let g7w: u128 = 0x7431 | (2 << 16) | (3 << 24) | (4 << 64) | H1;
    for leg in ["sm120", "sm121a"] {
        let t = tab(leg);
        for (extra, want) in cases {
            let got =
                dec(&t, II0 | extra).unwrap_or_else(|| panic!("{leg}: HOLE on extra={extra:#x}"));
            assert_eq!(&got, want, "{leg}: decode law drift extra={extra:#x}");
        }
        assert_eq!(
            &dec(&t, g7w).unwrap(),
            "HFMA2 R2, R3, R4, 1, 0",
            "{leg}: g7 drift"
        );
        // guard sweep x4 archetypes with imm
        for (g, want) in [
            (0u128 << 12, "@P0 HFMA2 R2, R3, R4, 1, 0"),
            (7u128 << 12, "HFMA2 R2, R3, R4, 1, 0"),
            (8u128 << 12, "@!P0 HFMA2 R2, R3, R4, 1, 0"),
            (0xfu128 << 12, "@!PT HFMA2 R2, R3, R4, 1, 0"),
        ] {
            assert_eq!(
                &dec(&t, (II0 & !(0xfu128 << 12)) | g | H1).unwrap(),
                want,
                "{leg}: guard {g:#x} imm drift"
            );
        }
    }
}

#[test]
fn t330_3_encode_word_exact_and_roundtrip_dense() {
    for leg in ["sm120", "sm121a"] {
        let t = tab(leg);
        for (want_w, text) in [
            (
                0xfc200000000040000000003020431u128,
                "@P0 HFMA2 R2, R3, R4, 0, 0",
            ),
            (
                0xfc200000000043c00000003020431u128,
                "@P0 HFMA2 R2, R3, R4, 1, 0",
            ),
            (
                0xfc200000000043e00c00003020431u128,
                "@P0 HFMA2 R2, R3, R4, 1.5, -2",
            ),
        ] {
            let w = enc(&t, text).unwrap_or_else(|e| panic!("{leg}: REFUSE on {text:?}: {e}"));
            assert_eq!(w & M96, want_w & M96, "{leg}: mint drift on {text:?}");
            assert_eq!(
                &dec(&t, w).unwrap(),
                text,
                "{leg}: roundtrip drift on {text:?}"
            );
        }
    }
}

#[test]
fn t330_4_fail_closed_edges_and_sparse_stayhole() {
    // INVALID3 (285 doctrine) + INVALID5 (271 doctrine) + kill b91 = HOLE
    for leg in ["sm100a", "sm103a", "sm120", "sm121a"] {
        let t = tab(leg);
        assert!(
            dec(&t, II0 | B78 | B85 | H1).is_none(),
            "{leg}: INVALID3 decoded"
        );
        assert!(
            dec(&t, II0 | B86 | (1u128 << 81)).is_none(),
            "{leg}: INVALID5 decoded"
        );
        assert!(
            dec(&t, II0 | (1u128 << 91) | H1).is_none(),
            "{leg}: b91 kill decoded"
        );
    }
    // sparse legs keep fail-closed on the whole 330 surface (no II keys)
    for leg in ["sm100a", "sm103a"] {
        let t = tab(leg);
        assert!(
            dec(&t, II0 | B79 | H1).is_none(),
            "{leg}: RELU era decoded sparse"
        );
        assert!(
            dec(&t, II0 | H1 | B87).is_none(),
            "{leg}: zarodek decoded sparse"
        );
        assert!(
            enc(&t, "@P0 HFMA2.RELU R2, R3, R4, 1, 0, P0").is_err(),
            "{leg}: era mint accepted sparse"
        );
    }
}

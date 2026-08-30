//! BUG-270 (F2-iter137, loop5/blind front2, 2026-08-29): multi-bit (>=3)
//! era 'neg' residuum closure, legs sm120+sm121a (canonical 9984a9e).
//! census270 (post-264 inventory): 12 sm120 + 17 sm121a fields, donors 0.
//! routex264 FULL 2,406-cubin battery exposure: ONLY HFMA2_R_R_R_II_FI routes
//! (94,630 words, ALL value=1 = pure neg@72 => post-graft text IDENT); every
//! other graft row zero-routed; era misbehavior on II_FI values !=1 provable
//! (ghost '-' for hsel/abs/op-suffix values) but corpus-absent.
//!
//! arb270 + arb270b (nvdisasm 13.3.73 raw -b, x4 models SM100a/103a/120/121a
//! all agree) per-window laws:
//!   [63:60] UR token (arb D/E; 264-law transfer):
//!     hsel pair @{60(INVALID1 lo),61(.H0_H0 hi); v3 .H1_H1} + abs@62 + neg@63.
//!   [63:60] FRND.F16 src-R (arb F): b60 '.H1' => opmod:H1; b61 '.INVALID2'
//!     (payload-gap); b62 abs; b63 neg; combos '-R0.H1'/ '|R0.H1|'.
//!   [75:72] R token (arb A corpus witness HFMA2 R3,-RZ,RZ,0,0 + B FI_II host
//!     + G/G2 donor hosts): neg@72 + abs@73 + hsel pair @{74(INVALID1),75
//!     (.H0_H0); v3 .H1_H1}.
//!   [84:81] R token (arb B + G/G2): hsel pair @{81(.F32/INVALID1),82(.H0_H0);
//!     v3 .H1_H1} + abs@83 + neg@84.
//!   b86 on HFMA2-family rows = '.H0_NH1' (3-bit window hi bit, 271-class);
//!     era neg@86 1-bit mislabel deleted with the graft (264 doctrine).
//!   HFMA2_R_R_R_II_FI 8b@72: operand law [75:72] grafted; bits 76..79 =
//!     .FMZ/.SAT/.F32/.RELU op-suffixes (arb264 D-set), no engine arm on this
//!     row today => payload-gap = 274-kand (was: ghost '-' for any !=0).
//! SKIP + junk-register (and_base vendor rc=1 x4 models, zero routing):
//!   HFMA2_R_R_R_R_? '' x2 legs, HFMA2_R_R_R_FI_FI|BF16_V2, HFMA2_R_R_R_II_II|
//!   BF16_V2 x2 legs (8 residuum mb-neg fields, 265-line).
//! FRND.F16{,.CEIL,.FLOOR,.TRUNC}_R_R = identical quadruplets (ab/vm/fields);
//! arb270c: no rounding discrimination bits 0..119 => phantom-variant rows,
//! registered; the same field law applied to all four (pre/post matcher
//! behavior unchanged).
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
fn mb_neg(t: &IsaTable) -> usize {
    t.entries
        .values()
        .flat_map(|e| e.mod_groups.values())
        .flat_map(|g| g.fields.iter())
        .filter(|f| {
            matches!(
                f.extraction,
                Extraction::Neg | Extraction::Abs | Extraction::NegAbs | Extraction::NegShl1
            ) && f.bits >= 3
        })
        .count()
}

// arb270 host words (payload part; ctl mask convention of the harness).
const W_IIFI_V1: u128 = 0x000fc600000001ff00000000ff037431; // 'HFMA2 R3, -RZ, RZ, 0, 0'
const W_FIII_BASE: u128 = 0x00000000000000ff3f800000ff000431; // 'HFMA2 R0, RZ, RZ, 1.875, 0'
const W_RRUR_BASE: u128 = 0x00000000080000000000000000000e31; // 'HFMA2 R0, R0, R0, UR0'
const W_HSETP_BASE: u128 = 0x00000000080000000000000000000e34; // 'HSETP2 P0, P0, R0, UR0, P0'
const W_FRND_BASE: u128 = 0x00000000001008000000000000000307; // 'FRND.F16 R0, R0'

#[test]
fn t270_1_structure_and_skip_registry() {
    for arch in ["sm120", "sm121a"] {
        let t = tab(arch);
        // era fields deleted everywhere in the graft set.
        // FLIPPED 2026-08-29 (BUG-265): FRND.F16.{CEIL,FLOOR,TRUNC}_R_R
        // phantom-variant rows DELETED outright (identical quadruplets,
        // arb270c no-rounding-discrimination; encode was already fail-closed
        // BUG-132); only the plain row remains and keeps the 270 field law.
        for (key, mg) in [
            ("FRND.F16_R_R", ""),
            ("HFMA2_R_R_R_UR", ""),
            ("HFMA2_R_R_R_FI_II", ""),
            ("HFMA2_R_R_R_II_FI", ""),
        ] {
            let g = &t.entries[key].mod_groups[mg];
            assert!(
                !g.fields
                    .iter()
                    .any(|f| f.extraction == Extraction::Neg && f.bits >= 3),
                "{arch} {key}: multi-bit neg survived"
            );
        }
        // new-law spot checks
        let g = &t.entries["HFMA2_R_R_R_UR"].mod_groups[""];
        for (sh, b, ex) in [
            (60u32, 2u32, Extraction::HalfSel),
            (62, 1, Extraction::Abs),
            (63, 1, Extraction::Neg),
        ] {
            assert!(
                g.fields.iter().any(|f| f.token_idx == 4
                    && f.shift == sh
                    && f.bits == b
                    && f.extraction == ex),
                "{arch} RRUR tok4 @{sh} {b}b {ex:?} missing"
            );
        }
        assert!(
            !g.fields.iter().any(|f| f.shift == 86),
            "{arch} RRUR neg@86 survived"
        );
        let g = &t.entries["FRND.F16_R_R"].mod_groups[""];
        assert!(
            g.fields.iter().any(|f| f.token_idx == 2
                && f.shift == 60
                && f.bits == 1
                && f.extraction == Extraction::OpModFlag("H1".into())),
            "{arch} FRND opmod:H1 graft missing"
        );
        let g = &t.entries["HFMA2_R_R_R_II_FI"].mod_groups[""];
        for (sh, b, ex) in [
            (72u32, 1u32, Extraction::Neg),
            (73, 1, Extraction::Abs),
            (74, 2, Extraction::HalfSel),
        ] {
            assert!(
                g.fields.iter().any(|f| f.token_idx == 2
                    && f.shift == sh
                    && f.bits == b
                    && f.extraction == ex),
                "{arch} II_FI tok2 @{sh} {b}b {ex:?} missing"
            );
        }
        assert!(
            !g.fields
                .iter()
                .any(|f| f.bits >= 3 && f.extraction == Extraction::Neg),
            "{arch} II_FI 8b-neg survived"
        );
        // FLIPPED 2026-08-29 (BUG-265): the SKIP-register junk rows are
        // DELETED outright (arb265 re-measured: bases vendor rc=1 x4 models,
        // zero battery routing) -- the residuum fields die with the rows.
        assert!(!t.entries.contains_key("HFMA2_R_R_R_R_?"));
        assert!(!t.entries["HFMA2_R_R_R_II_II"]
            .mod_groups
            .contains_key("BF16_V2"));
    }
    // sm121a-only legs
    let t = tab("sm121a");
    for mg in ["", "BF16_V2"] {
        let g = &t.entries["HFMA2_R_R_FI_FI_R"].mod_groups[mg];
        assert!(!g
            .fields
            .iter()
            .any(|f| f.extraction == Extraction::Neg && f.bits >= 3));
        assert!(
            g.fields.iter().any(|f| f.token_idx == 5
                && f.shift == 84
                && f.bits == 1
                && f.extraction == Extraction::Neg),
            "FIFIR tok5 neg@84 missing ({mg})"
        );
    }
    // sm121a FI_FI BF16_V2 junk mg: DELETED by BUG-265 (same closure).
    assert!(!t.entries["HFMA2_R_R_R_FI_FI"]
        .mod_groups
        .contains_key("BF16_V2"));
    // mb-neg residuum counts FLIPPED 2026-08-29 (BUG-265): the SKIP-register
    // junk set carried the entire residuum -> deletion closes it to ZERO.
    assert_eq!(
        mb_neg(&tab("sm120")),
        0,
        "sm120 mb-sign residuum drift (post-265 zero)"
    );
    assert_eq!(
        mb_neg(&t),
        0,
        "sm121a mb-sign residuum drift (post-265 zero)"
    );
    // donors: keys absent (byte-untouched proxy)
    for arch in ["sm100a", "sm103a"] {
        let t = tab(arch);
        for k in ["FRND.F16_R_R", "HFMA2_R_R_R_II_FI", "HFMA2_R_R_R_UR"] {
            assert!(!t.entries.contains_key(k), "donor {arch} grew {k}");
        }
    }
}

#[test]
fn t270_2_decode_law_72_iifi() {
    for arch in ["sm120", "sm121a"] {
        let t = tab(arch);
        // corpus witness anchor (value=1: pre == post, byte-stable)
        assert_eq!(
            dec(&t, W_IIFI_V1 & M96).as_deref(),
            Some("HFMA2 R3, -RZ, RZ, 0, 0")
        );
        // arb A window laws (era: ghost '-' for ANY nonzero; post: vendor-equal)
        assert_eq!(
            dec(&t, 0x000fc600000002ff00000000ff037431 & M96).as_deref(),
            Some("HFMA2 R3, |RZ|, RZ, 0, 0")
        );
        assert_eq!(
            dec(&t, 0x000fc600000008ff00000000ff037431 & M96).as_deref(),
            Some("HFMA2 R3, RZ.H0_H0, RZ, 0, 0")
        );
        assert_eq!(
            dec(&t, 0x000fc60000000cff00000000ff037431 & M96).as_deref(),
            Some("HFMA2 R3, RZ.H1_H1, RZ, 0, 0")
        );
        assert_eq!(
            dec(&t, 0x000fc600000003ff00000000ff037431 & M96).as_deref(),
            Some("HFMA2 R3, -|RZ|, RZ, 0, 0")
        );
    }
    // FLIPPED 2026-08-29 (BUG-274): the op-suffix window is ARMED — b78 is
    // now the .F32 arm (arb274 x4 models); ghost stays gone and the suffix
    // prints. Full lattice + RELU pred laws pinned in tests/bug274_opsuffix.rs.
    let t = tab("sm121a");
    let got =
        dec(&t, (W_IIFI_V1 & !(1u128 << 72) | (1u128 << 78)) & M96).expect("row still matches");
    assert!(!got.contains('-'), "274 ghost survived: {got}");
    assert_eq!(got, "HFMA2.F32 R3, RZ, RZ, 0, 0", "274 .F32 arm: {got}");
}

#[test]
fn t270_3_decode_law_60_and_81() {
    // Engine-verified post-graft texts (probed on the grafted tables, both
    // legs identical); arb270 vendor-side: hsel v1 '.F32'/'.INVALID1' spellings
    // are engine-law '.H0_H1' (owner-scope note from 264); FRND '.H1' and all
    // sign glyphs vendor-equal; immediate print cosmetics on the FI_II host
    // ('0, 0x0' vs vendor '1.875, 0' for the b81-window words) = pre-existing
    // FI-region payload-gap (tok4 f16@[63:48] field absent on the era row),
    // registered.
    for arch in ["sm120", "sm121a"] {
        let t = tab(arch);
        // @60 UR token (arb D): era ghost for hsel values; post vendor-equal
        assert_eq!(
            dec(&t, 0x80000002000000000000e31 & M96).as_deref(),
            Some("@P0 HFMA2 R0, R0, R0, UR0.H0_H0")
        );
        assert_eq!(
            dec(&t, 0x80000004000000000000e31 & M96).as_deref(),
            Some("@P0 HFMA2 R0, R0, R0, |UR0|")
        );
        assert_eq!(
            dec(&t, 0x80000008000000000000e31 & M96).as_deref(),
            Some("@P0 HFMA2 R0, R0, R0, -UR0")
        );
        assert_eq!(
            dec(&t, 0x80000003000000000000e31 & M96).as_deref(),
            Some("@P0 HFMA2 R0, R0, R0, UR0.H1_H1")
        );
        assert_eq!(
            dec(&t, 0x8000000c000000000000e31 & M96).as_deref(),
            Some("@P0 HFMA2 R0, R0, R0, -|UR0|")
        );
        // @81 R token (arb B host): hsel pair + abs + neg.
        // FLIPPED 2026-08-29 (BUG-279): on sm120 the grafted family rows now
        // win and print VENDOR-EXACT (re-verified nvdisasm 13.3.73 raw -b x4
        // models during F2-iter142): tok3 hsel v1 = '.F32', tok4 imm field
        // armed ('1.875' heals the documented '0, 0x0' FI-region cosmetics).
        // sm121a: the era FI_II host row still shadows the family on
        // [82:81]-set words with nonzero tok4 (its vm claims the window);
        // pin the era texts as tripwire — closing the shadowing = registered
        // follow-up (FI_II demote/narrow), corpus exposure ZERO (routex279:
        // [86:80]==0 on all 97,337 battery words).
        let (w_f32, w_h00, w_abs, w_neg) = (
            0x200ff3f800000ff000431 & M96,
            0x400ff3f800000ff000431 & M96,
            0x800ff3f800000ff000431 & M96,
            0x1000ff3f800000ff000431 & M96,
        );
        if arch == "sm120" {
            assert_eq!(
                dec(&t, w_f32).as_deref(),
                Some("@P0 HFMA2 R0, RZ, RZ.F32, 1.875, 0")
            );
            assert_eq!(
                dec(&t, w_h00).as_deref(),
                Some("@P0 HFMA2 R0, RZ, RZ.H0_H0, 1.875, 0")
            );
            assert_eq!(
                dec(&t, w_abs).as_deref(),
                Some("@P0 HFMA2 R0, RZ, |RZ|, 1.875, 0")
            );
            assert_eq!(
                dec(&t, w_neg).as_deref(),
                Some("@P0 HFMA2 R0, RZ, -RZ, 1.875, 0")
            );
        } else {
            // FLIPPED F2-iter154 (BUG-306 armed): the hsel v1 suffix now
            // prints the vendor law '.F32' on the era-shadowed FI_II row
            // too (arb306 tok3/window census x4 models); the '0, 0x0'
            // imm-tail shadowing itself is NOT touched by 306 and stays
            // pinned below as the registered follow-up.
            assert_eq!(
                dec(&t, w_f32).as_deref(),
                Some("@P0 HFMA2 R0, RZ, RZ.F32, 0, 0x0")
            );
            assert_eq!(
                dec(&t, w_h00).as_deref(),
                Some("@P0 HFMA2 R0, RZ, RZ.H0_H0, 0, 0x0")
            );
            assert_eq!(
                dec(&t, w_abs).as_deref(),
                Some("@P0 HFMA2 R0, RZ, |RZ|, 0, 0x0")
            );
            assert_eq!(
                dec(&t, w_neg).as_deref(),
                Some("@P0 HFMA2 R0, RZ, -RZ, 0, 0x0")
            );
        }
        // b86 no longer a ghost '-' (271-class window: suffix dropped = gap)
        let got = dec(&t, 0x4000ff3f800000ff000431 & M96).expect("FI_II b86 matches");
        assert!(!got.contains('-'), "b86 neg-ghost survived: {got}");
        // FRND.F16 @60 src-R (arb F): opmod:H1 + abs + neg, vendor-equal
        assert_eq!(
            dec(&t, 0x1008001000000000000307 & M96).as_deref(),
            Some("@P0 FRND.F16 R0, R0.H1")
        );
        assert_eq!(
            dec(&t, 0x1008004000000000000307 & M96).as_deref(),
            Some("@P0 FRND.F16 R0, |R0|")
        );
        assert_eq!(
            dec(&t, 0x1008008000000000000307 & M96).as_deref(),
            Some("@P0 FRND.F16 R0, -R0")
        );
        assert_eq!(
            dec(&t, 0x1008009000000000000307 & M96).as_deref(),
            Some("@P0 FRND.F16 R0, -R0.H1")
        );
    }
    // HSETP2 (arb E): era ghost killed, field glyph present. FLIPPED
    // 2026-08-29 (BUG-265): the sm120 mg-name drift 'GEU.AND' is CLOSED by
    // rename to 'AND,F' -- decode now prints the vendor-equal '.F.AND' on
    // the cmp-F base (arb265 B, x4 models; grammar parity with sm121a).
    let t = tab("sm120");
    assert_eq!(
        dec(&t, 0x80000004000000000000e34 & M96).as_deref(),
        Some("@P0 HSETP2.F.AND P0, P0, R0, |UR0|, P0")
    );
    assert_eq!(
        dec(&t, 0x80000002000000000000e34 & M96).as_deref(),
        Some("@P0 HSETP2.F.AND P0, P0, R0, UR0.H0_H0, P0")
    );
    let t = tab("sm121a");
    assert_eq!(
        dec(&t, 0x80000004000000000000e34 & M96).as_deref(),
        Some("@P0 HSETP2.F.AND P0, P0, R0, |UR0|, P0")
    );
}

#[test]
fn t270_4_encode_inverse() {
    // Base-relative bit deltas on row-unambiguous texts (pred guard/f16-imm
    // cosmetics of the and_base hosts do not belong to the window laws).
    for arch in ["sm120", "sm121a"] {
        let t = tab(arch);
        let b = enc(&t, "@P0 HFMA2 R0, R0, R0, UR0") & M96;
        assert_eq!(
            enc(&t, "@P0 HFMA2 R0, R0, R0, UR0.H0_H0") & M96,
            b | (1 << 61)
        );
        assert_eq!(
            enc(&t, "@P0 HFMA2 R0, R0, R0, UR0.H1_H1") & M96,
            b | (3 << 60)
        );
        assert_eq!(enc(&t, "@P0 HFMA2 R0, R0, R0, |UR0|") & M96, b | (1 << 62));
        assert_eq!(enc(&t, "@P0 HFMA2 R0, R0, R0, -UR0") & M96, b | (1 << 63));
        assert_eq!(enc(&t, "@P0 HFMA2 R0, R0, R0, -|UR0|") & M96, b | (3 << 62));
        let f = enc(&t, "@P0 FRND.F16 R0, R0") & M96;
        assert_eq!(enc(&t, "@P0 FRND.F16 R0, R0.H1") & M96, f | (1 << 60));
        assert_eq!(enc(&t, "@P0 FRND.F16 R0, |R0|") & M96, f | (1 << 62));
        assert_eq!(enc(&t, "@P0 FRND.F16 R0, -R0") & M96, f | (1 << 63));
        assert_eq!(
            enc(&t, "@P0 FRND.F16 R0, -R0.H1") & M96,
            f | (1 << 60) | (1 << 63)
        );
    }
    // HSETP2 sm120 encode of 'GEU.AND' text stays fail-closed post-265:
    // pre-265 the mg-name order mismatched the parser query; post-265 the
    // renamed lattice carries only 'AND,F' (sm121a has the full 16-mg cmp
    // lattice; sm120 GEU-word coverage = b4-forward/277-kand).
    let t = tab("sm120");
    let r = parse_sass("@P0 HSETP2.GEU.AND P0, P0, R0, UR0, P0;", 0)
        .map(|i| encode_instruction(&i, &t));
    assert!(
        matches!(r, Ok(Err(_))),
        "HSETP2 sm120 mg-name drift must stay fail-closed"
    );
    // Encode-route limitation (pre-existing, registered): FI/II text typing
    // makes R_R_R_FI_II unreachable for plain float texts (is_float typing =>
    // '0'/'1.875' = FloatImm => R_R_R_FI_FI key, hsel payload-gap there), and
    // the hex-imm route lands on R_R_R_FI_II but its era-typed 'imm' field
    // cannot take the float immediate (fail-closed, 265-adjacent row hygiene).
    let r = parse_sass("HFMA2 R0, RZ, -RZ, 1.875, 0x0;", 0).map(|i| encode_instruction(&i, &t));
    assert!(
        matches!(r, Ok(Err(_))),
        "FI_II hex-imm route should stay fail-closed"
    );
}

#[test]
fn t270_5_anchors_registrations() {
    // 264 anchors stay vendor-equal (sm121a BF16 window law untouched here)
    let t = tab("sm121a");
    assert_eq!(
        dec(&t, 0x4fe20008000000300000080c037c32 & M96).as_deref(),
        Some("HMUL2.BF16_V2 R3, R12, UR8.H1_H1")
    );
    assert_eq!(
        dec(&t, 0x4fca00080408052000000602057c31 & M96).as_deref(),
        Some("HFMA2.BF16_V2 R5, R2.H0_H0, UR6.H0_H0, R5.H0_H0")
    );
    // 265-line anchors: HADD2-'?' bucket KEPT (265 measured: only mask
    // covering 112 vendor-decodable 'HFMA2 4R+reuse' words; removal=holes,
    // synthesis = 278-kand). FRND.CEIL anchor RETIRED by the 265 phantom
    // deletion (see t265_1).
    assert!(t.entries.contains_key("HADD2_R_R_II_II_II_II_?"));
    assert!(!t.entries.contains_key("FRND.F16.CEIL_R_R"));
    // 271-sentinel (updated F2-iter143): BUG-271 armed the imm family +
    // BF16_V2 hosts only; THIS row (HFMA2_R_R_R_UR) keeps b86 extractionless
    // (routex271 corpus-zero) — 289-kand. '.H0_NH1' law battery =
    // tests/bug271_h0nh1.rs.
    let got = dec(&t, (W_RRUR_BASE | (1u128 << 86)) & M96).expect("RRUR b86 matches");
    assert!(!got.contains(".H0_NH1"), "269/289 scope leak: {got}");
    assert!(!got.contains('-'), "271 neg-ghost survived: {got}");
}

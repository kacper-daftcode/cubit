//! BUG-413(ii)/(iii) pins (F2-iter231, loop5/blind front2, 2026-09-08):
//! encode-side closure of the RZ-elided shared-bracket mints
//! (canonical e4f0915 -> 487757b; tables-only graft patch413ii.py
//! replayable+idempotent; ENGINE ZERO changes).
//!
//! 413(ii): LDSM_R_AURI was absent x4 -> 'LDSM.16.M88 R16, [UR4+-0x800000]'
//! refused loud ("no operand-compatible table entry"). 413(iii): LDS_R_AURI
//! lacked the S8 mod-group x4 ('',64,128,U8,U16 siblings rowed) -> 'LDS.S8
//! R93, [UR4+-0x800000]' refused under the BUG-132 silent-mod cordon. Both
//! words decode vendor-exact pre (ARURI twins, sub_r0=0xff RZ-elided print)
//! -- pure encode-side holes.
//!
//! Vendor law arb413+arb413b (204 probes x4 models AGREE EVERY, DIVERGENT=0;
//! work/bug413ii/): LDSM AURI frame = guard 4b@12 / reg 8b@16 / UR 8b@32 /
//! imm 24b@40 (BUG-399v2 sign-window); mod-enum [80:78] {0:M88,1:MT88,
//! 2:M816,3:M832,4:MT1616,5..7:INVALIDn}; numbered b72='.2'/b73='.4'/
//! both=INVALID3; guard g0..g15 legal; dst R0..R255 (R255 prints RZ);
//! b75/76/77 not-LDSM-space; bare '16,MT88' and '.2' variants legal x4.
//! S8 AURI: width-enum [75:73]=001 legal x4 same axes.
//!
//! Graft: LDS_R_AURI|S8 := U16-sibling clone (b74->b73, vm verbatim);
//! LDSM_R_AURI := AURI-ized LDSM_R_ARURI|16,M88 clone x 6 measured mgs.
//! Post: 530 same-ok + 234 same-hole + 52 healed, 0 regressions, 0 claim
//! migrations (text-stable); mints x4-identical, low96==law; regression
//! window (U16/U8/'',64,128 RZ-elided mints) 20/20 byte-identical pre==post.
//!
//! Registered-not-grafted: 421-kand (LDSM M816/M832/MT1616 mods vs address
//! forms), 422-kand (LDS S16 absent on R_* forms), 423-kand (sm121a era
//! LDSM.16.M88_R_AUR fabricates [R0+UR4] on junk-band singles -- pre-existing
//! on publish e33f4fc9, UNTOUCHED pin t413ii_7), 420-kand (.X4/.X8 b78/b79
//! scale-rows), parser '[URZ...]' posture refuse (pre-existing, t413ii_5).
//!
//! Witness data: tests/bug413ii_data.inc (machine-built by
//! work/bug413ii/gen413iipins.py; no hand hex; self-checks abort).

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::IsaTable;

include!("bug413ii_data.inc");

const LEGS: [&str; 4] = ["sm100a", "sm103a", "sm120", "sm121a"];

fn tab(arch: &str) -> IsaTable {
    IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap()
}
fn dec(t: &IsaTable, idx: &DecodeIndex, w: u128) -> Option<String> {
    idx.decode(w, 0, t)
        .map(|d| to_sass(&d).trim().trim_end_matches(';').to_string())
        .ok()
}
fn enc(t: &IsaTable, text: &str) -> Option<u128> {
    let ins = parse_sass(text, 0).ok()?;
    encode_instruction(&ins, t).ok()
}

/// t413ii_1: every unanimous law cell decodes exactly as measured (vendor
/// text for legal cells, HOLE for doctrine/posture classes) x4.
#[test]
fn t413ii_1_law_grid_vendor_exact_x4() {
    for (li, leg) in LEGS.iter().enumerate() {
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        for (w, tag, exp) in LAW413_DECODE {
            let got = dec(&t, &idx, *w);
            match &exp[li] {
                Some(vt) => assert_eq!(got.as_deref(), Some(*vt), "[{leg}] {tag}"),
                None => assert!(got.is_none(), "[{leg}] {tag} posture drift: {got:?}"),
            }
        }
    }
    let (legal, hole) = LAW413_COUNTS;
    assert_eq!(LAW413_DECODE.len(), legal + hole);
    // FLIP (BUG-421+422, F2-iter233, canonical 13e13b6): the enum-closure
    // class registered below closed -- 8 uniq words / 11 tags (44 leg-cells)
    // decode vendor-exact via the mod-enum [80:78) + S16 width graft.
    // Machine evidence work/bug421422/measure413_post421422.json;
    // was (142, 51) at 0eddad5 (= 420; before that (136, 57)). Counts per-TAG:
    // 11 healed tags => (142+11, 51-11), machine-measured not predicted.
    assert_eq!((legal, hole), (153, 40));
}

/// t413ii_2: mint witnesses close byte-exact circles x4 (cross-leg
/// word-identical asserted at gen time; reprint == vendor text).
#[test]
fn t413ii_2_mint_circles_x4() {
    const M96: u128 = (1u128 << 96) - 1;
    for leg in LEGS {
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        for (text, word, reprint) in MINT413II {
            let got = enc(&t, text).unwrap_or_else(|| panic!("[{leg}] mint refuse: {text}"));
            assert_eq!(got & M96, word & M96, "[{leg}] low96 drift: {text}");
            let back = dec(&t, &idx, got).unwrap_or_else(|| panic!("[{leg}] circle hole: {text}"));
            assert_eq!(&back, reprint, "[{leg}] second render drift: {text}");
        }
    }
    // FLIP (BUG-421+422, F2-iter233): += the four healed class mints
    // (S16 + M816/M832/MT1616 -- refuse class closed); was 29 at 0eddad5.
    assert_eq!(MINT413II.len(), 33);
}

/// t413ii_3: the two registered defect texts mint on every leg, landing on
/// the vendor law words (low96) -- 'LDS.S8 R93, [UR4+-0x800000]' (132 cordon
/// closed) and 'LDSM.16.M88 R16, [UR4+-0x800000]' (row added).
#[test]
fn t413ii_3_defect_texts_mint() {
    const M96: u128 = (1u128 << 96) - 1;
    for leg in LEGS {
        let t = tab(leg);
        let w1 = enc(&t, "LDS.S8 R93, [UR4+-0x800000] ;")
            .unwrap_or_else(|| panic!("[{leg}] S8 AURI mint refuse"));
        assert_eq!(
            w1 & M96,
            0x0800020080000004ff5d7984u128 & !0u128 | 0x0800020080000004ff5d7984u128
        );
        let w2 = enc(&t, "LDSM.16.M88 R16, [UR4+-0x800000] ;")
            .unwrap_or_else(|| panic!("[{leg}] LDSM AURI mint refuse"));
        assert_eq!(
            w2 & M96,
            0x0800000080000004ff10783bu128 & !0u128 | 0x0800000080000004ff10783bu128
        );
        // the BUG-132 anti-silent-drop contract: both sign spellings mint
        // one word and reprint as the vendor '+-' glyph (399-style).
        let w3 = enc(&t, "LDS.S8 R93, [UR4-0x800000] ;").unwrap();
        assert_eq!(w3, w1, "[{leg}] -/+- spellings must mint one word");
        let idx = DecodeIndex::build(&t);
        assert_eq!(
            dec(&t, &idx, w3).unwrap(),
            "LDS.S8 R93, [UR4+-0x800000]",
            "[{leg}] reprint must be the vendor glyph"
        );
    }
}

/// t413ii_4: refuse postures stand x4 (INVALID3/parser-URZ): every authored
/// text must still fail loudly -- no silent accepts. (FLIP BUG-421+422:
/// the S16/mods-not-rowed classes closed -- those texts mint now, pinned in
/// MINT413II + REFUSE421422 adds the surviving refuses INVALID5/6/7,
/// M832.2/.4 and the S16-scale cordon.)
#[test]
fn t413ii_4_refuse_postures_stand() {
    // BUG-421+422: shed 4 closed classes (S16/M816/M832/MT1616 mint now)
    for leg in LEGS {
        let t = tab(leg);
        for text in REFUSE413II {
            assert!(enc(&t, text).is_none(), "[{leg}] minted through: {text}");
        }
    }
    // FLIP (BUG-421+422, F2-iter233): S16 + M816/M832/MT1616 refuse classes
    // closed by the graft; 10 -> 6.
    assert_eq!(REFUSE413II.len(), 6);
}

/// t413ii_5: '[URZ...]' authored-bracket parser posture (pre-existing on
/// publish e33f4fc9 -- the already-rowing LDS.U16 class refused identically):
/// URZ-alone stays unauthorable on every leg while numeral URZ-sinks mint.
#[test]
fn t413ii_5_urz_parser_posture() {
    for leg in LEGS {
        let t = tab(leg);
        for text in [
            "LDS.S8 R93, [URZ] ;",
            "LDS.S8 R93, [URZ+-0x800000] ;",
            "LDSM.16.M88 R16, [URZ] ;",
            "LDSM.16.MT88.4 R16, [URZ+0x1] ;",
            "LDS.128 R96, [URZ] ;",
        ] {
            assert!(
                enc(&t, text).is_none(),
                "[{leg}] URZ-bracket minted: {text}"
            );
        }
        // the URZ sink as the UR-addend DOES mint (0xff window, 412 law):
        let t1 = tab(leg);
        let idx = DecodeIndex::build(&t1);
        let w = enc(&t1, "LDS.S8 R93, [R10+URZ+-0x1] ;").unwrap();
        assert_eq!(dec(&t1, &idx, w).unwrap(), "LDS.S8 R93, [R10+URZ+-0x1]");
    }
}

/// t413ii_6: claim-attribution anchors -- the RZ-elided canonical words keep
/// their ARURI-twin claims (zero text-stable migrations measured); new-space
/// cells (no ARURI sibling) claim via the new AURI rows.
#[test]
fn t413ii_6_claim_attribution_anchors() {
    let lds8rz: u128 = 0x000fe2000800020000000004ff5d7984; // lds8rz.ur004.z0
    let ldsmrz: u128 = 0x000000000800000000000004ff10783b; // ldsmrz.ur004.z0
    let b72: u128 = ldsmrz ^ (1u128 << 72); // .2 (no sibling on 100a/103a/120)
    let b78: u128 = ldsmrz ^ (1u128 << 78); // MT88 (no sibling x4)
    for leg in LEGS {
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        let d1 = idx.decode(lds8rz, 0, &t).unwrap();
        assert_eq!(
            format!("{}|{}", d1.key, d1.mod_group),
            "LDS_R_ARURI|S8",
            "[{leg}]"
        );
        let d2 = idx.decode(ldsmrz, 0, &t).unwrap();
        assert_eq!(
            format!("{}|{}", d2.key, d2.mod_group),
            "LDSM_R_ARURI|16,M88",
            "[{leg}]"
        );
        let d4 = idx.decode(b78, 0, &t).unwrap();
        // FLIP (BUG-424 F2-iter234, canonical 291ed59b): ARURI|16,MT88 rowed
        // x4 now -> the RZ-elided canonical word claims via the ARURI row on
        // every leg (doctrine: canonical words claim ARURI; uniform x4,
        // machine-measured measure413_post424 km-flip 52 = 13 tags x4 text-
        // stable AURI->ARURI specific-row migrations).
        assert_eq!(
            format!("{}|{}", d4.key, d4.mod_group),
            "LDSM_R_ARURI|16,MT88",
            "[{leg}]"
        );
        let d3 = idx.decode(b72, 0, &t).unwrap();
        let km3 = format!("{}|{}", d3.key, d3.mod_group);
        assert_eq!(km3, "LDSM_R_ARURI|16,2,M88", "[{leg}] uniform x4 post-424");
        // printed text vendor-exact regardless of which twin claims:
        assert_eq!(
            to_sass(&d1).trim().trim_end_matches(';'),
            "LDS.S8 R93, [UR4]"
        );
        assert_eq!(
            to_sass(&d4).trim().trim_end_matches(';'),
            "LDSM.16.MT88 R16, [UR4]"
        );
    }
}

/// t413ii_7: 423-kand posture UNTOUCHED -- the sm121a era row
/// LDSM.16.M88_R_AUR fabricates "[R0+UR4]" on the 11 junk-band singles
/// (vendor prints "[UR4]"; pre-existing on publish e33f4fc9, registered).
/// Sibling legs keep their own measured states verbatim (broad-pass vendor-
/// exact claims on b64-71 singles; HOLE on b84-86) -- the era posture is a
/// sm121a-only decode artifact, NOT propagated by this graft.
#[test]
fn t413ii_7_423_era_fabrication_posture() {
    assert_eq!(POSTURE423.len(), 11);
    for (w, tag, engine, others) in POSTURE423 {
        assert!(tag.ends_with(".sm121a"), "{tag} not an sm121a era cell");
        let t = tab("sm121a");
        let idx = DecodeIndex::build(&t);
        let got = dec(&t, &idx, *w).unwrap_or_else(|| panic!("{tag} posture hole"));
        assert_eq!(&got, engine, "{tag} era fabrication drift");
        for (li, leg) in ["sm100a", "sm103a", "sm120"].iter().enumerate() {
            let tl = tab(leg);
            let idxl = DecodeIndex::build(&tl);
            let gotl = dec(&tl, &idxl, *w);
            match &others[li] {
                Some(v) => assert_eq!(gotl.as_deref(), Some(*v), "[{leg}] {tag} sibling drift"),
                None => assert!(gotl.is_none(), "[{leg}] {tag} sibling posture drift"),
            }
        }
    }
}

//! BUG-452 pins (F2-iter260, loop5/blind front2, 2026-09-13): donor-first
//! claim-narrowing -- claim_forbid {shift:24, bits:8, values:[255]} na:
//! L1 EFL2.256 desc (dARI): 3 klucze/noga. Vendor rc=1 gated x4 na base=255
//!    (arb452 g2 + sondy _P; 0..254 legal). Pre: engine drukowal 'RZ.64'.
//! L2 REDG *_ARURI64_R a64: 3072 kluczy/noga. Vendor rc=0 ale drukuje glif
//!    '???255.64' (arb452 g3; U32-form KEEP 'RZ.U32' = 451-law, nietkniety).
//!    Unclaim (HOLE-parity doktryna) zamiast nowego glifu -- rejestr
//!    towarzyszacy: text-parity '???255.64' = opcjonalny printer-arm.
//! Era-klasy z fuzz evidence (CLONE-ILLEG-447 x7 / CLONE-ILLEG-454 x32)
//! REKLASYFIKOWANE do 449-standing: canonical-era siblings gated-legal x4
//! (arb452 g4 32/32 + sondy c447), zaden nie nalezy do przestrzeni L1/L2;
//! ich decode ma byc NIETKNIETE (pin t452_6).
//! Mechanizm: opcjonalne pole mg 'claim_forbid' (doktryna BUG-099); ENGINE
//! guardi: decoder drop-kandydata na wszystkich priorytetach + encoder
//! fail-closed przy mincie (symetria). Canonical 4ee8431 -> e03e034.
//! Witness: tests/bug452_data.inc (maszynowe gen452pins.py rc=2).

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::IsaTable;

include!("bug452_data.inc");

fn tab(arch: &str) -> IsaTable {
    IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap()
}
fn dec(t: &IsaTable, idx: &DecodeIndex, w: u128) -> Option<String> {
    idx.decode(w, 0, t)
        .ok()
        .map(|d| to_sass(&d).trim().trim_end_matches(';').to_string())
}
fn enc(t: &IsaTable, text: &str) -> Result<u128, String> {
    let full = format!(" {text} ;");
    let parsed = parse_sass(&full, 0).map_err(|e| e.to_string())?;
    encode_instruction(&parsed, t).map_err(|e| e.to_string())
}

/// t452_1: L1 refuse -- slowa base=255 EFL2.256 desc dekoduja sie jako
/// HOLE na wszystkich nogach po fixie (pre drukowaly 'RZ.64'; dowody
/// pre-claim w gen452pins, rc=2 sprawdzone o cold engine).
#[test]
fn t452_1_l1_desc_ra255_hole() {
    for (w, leg) in REFUSE452_L1 {
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        assert_eq!(dec(&t, &idx, *w), None, "[{leg}] L1 claimed {w:#034x}");
    }
}

/// t452_2: L2 -- slowa base=255 ARURI64 (klatki x4 + 5 fuzz-wordow
/// STAND454) [ride 461: 2026-09-14, canonical f58ed16] HOLE zastapione
/// vendorskim glifem '???255.64' (wtedy HOLE-parity; 461 = text-parity).
/// Werdyktowanie glifu: t461_1 (nvdisasm-sourced); tu sanity: kazde slowo
/// dekoduje sie i zawiera glif.
#[test]
fn t452_2_l2_a64_ra255_hole() {
    for (w, leg) in REFUSE452_L2 {
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        let got =
            dec(&t, &idx, *w).unwrap_or_else(|| panic!("[{leg}] L2 HOLE after 461 {w:#034x}"));
        assert!(
            got.contains("???255.64"),
            "[{leg}] L2 glyph {w:#034x}: {got}"
        );
    }
}

/// t452_3: kill-preserve -- base in {0,28,253,254} na rodzinach L1/L2
/// dekoduje dokladnie tak samo jak przed fixem (teksty z cold engine).
#[test]
fn t452_3_kill_preserve() {
    for (w, leg, want) in KEEP452_MATCH {
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        let got = dec(&t, &idx, *w);
        assert_eq!(got.as_deref(), Some(*want), "[{leg}] kill drift {w:#034x}");
    }
}

/// t452_4: U32 keeper -- REDG plain U32-form base=255 dekoduje 'RZ.U32'
/// (451-law; guard NIE dotyka b90=0).
#[test]
fn t452_4_u32_keeper() {
    for (w, leg, want) in U32KEEP452 {
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        let got = dec(&t, &idx, *w);
        assert_eq!(got.as_deref(), Some(*want), "[{leg}] U32 drift {w:#034x}");
        assert!(want.contains("RZ.U32"), "expected RZ.U32 glyph: {want}");
    }
}

/// t452_5: mint-refuse -- teksty desc z baza RZ odmawiaja z cytowaniem
/// BUG-452 (fail-closed symetria encodera).
#[test]
fn t452_5_mint_refuse() {
    let t = tab("sm103a");
    for text in MINTREF452 {
        let e = enc(&t, text).expect_err("mint must refuse");
        assert!(format!("{e}").contains("BUG-452"), "guard msg: {e}");
    }
}

/// t452_6: era-stability -- slowa klas ery z fuzz evidence (39) dekoduje
/// dokladnie tak samo po fixie (atrybucja: guard dziala WYLACZNIE w
/// przestrzeni L1/L2).
#[test]
fn t452_6_era_unchanged() {
    let t = tab("sm103a");
    let idx = DecodeIndex::build(&t);
    for (w, want) in ERA452_UNCHANGED {
        let got = dec(&t, &idx, *w);
        assert_eq!(got.as_deref(), Some(*want), "era drift {w:#034x}");
    }
}

/// t452_7: data-attribution -- kazda zaanotowana instrukcja nosi _src452
/// i forbid 255@24 na wszystkich nogach; liczniki dokladnie 3+3072.
#[test]
fn t452_7_data_attribution() {
    for leg in ["sm100a", "sm103a", "sm120", "sm121a"] {
        let v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(format!("tables/{leg}.json")).unwrap())
                .unwrap();
        let ins = v["instructions"].as_object().unwrap();
        let mut l1 = 0;
        let mut l2 = 0;
        for (k, rec) in ins {
            let hit = k.ends_with("_ARURI64_R")
                || k == "LDG.E.EFL2.256_R_R_dARI"
                || k == "LDG.E.EFL2.256_R_R_dARI_P"
                || k == "STG.E.EFL2.256_dARI_R_R";
            if !hit {
                continue;
            }
            if k.ends_with("_ARURI64_R") {
                l2 += 1;
            } else {
                l1 += 1;
            }
            assert_eq!(rec["_src452"], "bug452-2026-09-13", "[{leg}] {k} src");
            let mgs = rec["mod_groups"].as_object().unwrap();
            if k.ends_with("_ARURI64_R") {
                // [ride 461] L2 zdjete data-side (glif drukarski); claim_forbid
                // ma NIE istniec, a rekord nosi _src461.
                assert_eq!(
                    rec["_src461"], "bug461-2026-09-14",
                    "[{leg}] {k} src461 po L2-UNCLAIM"
                );
                for (mg, g) in mgs {
                    assert!(
                        g.get("claim_forbid").is_none(),
                        "[{leg}] {k}::{mg} forbid po 461"
                    );
                }
                continue;
            }
            for (mg, g) in mgs {
                let cf = &g["claim_forbid"];
                assert_eq!(
                    *cf,
                    serde_json::json!([{"shift":24,"bits":8,"values":[255]}]),
                    "[{leg}] {k}::{mg} forbid"
                );
            }
        }
        assert_eq!((l1, l2), (3, 3072), "[{leg}] inventory drift");
    }
}

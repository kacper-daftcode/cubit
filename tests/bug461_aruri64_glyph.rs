//! BUG-461 pins (F2-iter265, loop5/blind front2, 2026-09-14): text-parity
//! glif '???255.64' dla L2 REDG *_ARURI64_R zamiast HOLE (452 swiadomie
//! wybral HOLE-parity; rejestr 452_claim_narrow_donor_first_103a.md sec.5).
//! Vendor law (arb452 g3 + triage461 fresh nvdisasm 13.3.73 era-gated x4
//! AGREE EVERY/DIVERGENT=0): base[24:32)==255 -> rc=0, glif
//! '[???255.64+UR..(+off)]'; 0..254 -> 'R{n}.64' (kill-preserve);
//! U32-form (b90=0) 255 -> 'RZ.U32' KEEPER (451-law, nietkniety).
//! Fix: data-side L2-UNCLAIM (canonical f376558 -> f58ed16, patch461.py
//! replayable+idempotent, 12,288 adnotacji zdjetych z 3072 kluczy x4;
//! L1 EFL2.256 desc + 462 ENL2/ELL2 + legacy 099 ZOSTAJA) + printer-arm
//! (format_plain_u32_ur glyph255=true wylacznie na galezce REDG.E ARURI64)
//! + encoder refuse mint-side (cytat BUG-461; kontynuacja polisy BUG-452:
//! tekst '.64' z baza R255/RZ nie mintuje; fallback U32 niedozwolony).
//! Witness: tests/bug461_data.inc (maszynowe gen461pins.py rc=2).

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::IsaTable;

include!("bug461_data.inc");

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

/// t461_1: glif-decode -- 13 slow base=255 ARURI64 (klatki x4 + 5 fuzz
/// STAND454) dekoduje DOKLADNIE tekst vendora '???255.64' (pre-fix: HOLE;
/// werdykt glifu z nvdisasm, nie z hot-silnika -- gen461pins rc=2).
#[test]
fn t461_1_glyph_decode() {
    for (w, leg, want) in GLYPH461 {
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        let got = dec(&t, &idx, *w);
        assert_eq!(got.as_deref(), Some(*want), "[{leg}] glyph {w:#034x}");
        assert!(want.contains("???255.64"), "glyph shape: {want}");
    }
}

/// t461_2: kill-preserve -- bazay {0,28,127,253,254} na 2 klatkach x4 nogi
/// dekoduja dokladnie jak przed fixem (teksty z cold publish 79aebc2b).
#[test]
fn t461_2_kill_preserve() {
    for (w, leg, want) in KEEP461_PREPOST {
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        let got = dec(&t, &idx, *w);
        assert_eq!(got.as_deref(), Some(*want), "[{leg}] kill drift {w:#034x}");
    }
}

/// t461_3: mint-refuse -- teksty '.64' z baza R255/RZ odmawiaja z cytatem
/// BUG-461 na wszystkich nogach (mint-side kontynuacja polisy BUG-452).
#[test]
fn t461_3_mint_refuse() {
    for (leg, text) in MINTREF461 {
        let t = tab(leg);
        let e = enc(&t, text).expect_err("mint must refuse");
        assert!(e.contains("BUG-461"), "[{leg}] cite: {e}");
    }
}

/// t461_4: data-attribution -- claim_forbid census per noga PO zdjeciu L2
/// (21/21/13/17; L1 3/noga + 462 + legacy 099 stoja), zero cf na ARURI64,
/// markery _src461 na wszystkich 3072 kluczach/noga.
#[test]
fn t461_4_census_attribution() {
    // ride 463: +12 cf/noga (LTC klucze); canonical a64b82b = 33/33/25/29.
    // RIDE469 (F2-iter285): graft 469 sm121a +17 cf (9 mg R/R_P/P_R/P_R_P z
    // CF_RA + 4 klucze EF-band z cf + 4 LTC-mg G2/G4 z CF_RA); canonical bd48e63
    // = 33/33/25/46.
    let want = [
        ("sm100a", 33u32),
        ("sm103a", 33),
        ("sm120", 25),
        ("sm121a", 46),
    ];
    for (leg, want_cf) in want {
        let v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(format!("tables/{leg}.json")).unwrap())
                .unwrap();
        let ins = v["instructions"].as_object().unwrap();
        let mut n_cf = 0u32;
        let mut n_a64 = 0u32;
        let mut n_a64cf = 0u32;
        let mut n_src461 = 0u32;
        for (k, rec) in ins {
            // pseudo-rekordy _errata_* (reserved top-level annotations) nie
            // nosza mod_groups -- pomijane, jak w gen461pins.
            let mgs = match rec["mod_groups"].as_object() {
                Some(m) => m,
                None => continue,
            };
            for (_, g) in mgs {
                if g.get("claim_forbid").is_some() {
                    n_cf += 1;
                }
            }
            if k.ends_with("_ARURI64_R") {
                n_a64 += 1;
                if rec["_src461"] == "bug461-2026-09-14" {
                    n_src461 += 1;
                }
                for (_, g) in mgs {
                    if g.get("claim_forbid").is_some() {
                        n_a64cf += 1;
                    }
                }
            }
        }
        assert_eq!(
            (n_cf, n_a64, n_a64cf, n_src461),
            (want_cf, 3072, 0, 3072),
            "[{leg}] census drift"
        );
    }
}

/// t461_5: U32 keeper -- REDG plain U32-form base=255 dekoduje 'RZ.U32'
/// (451-law; arm glifu NIE dotyka b90=0 po stronie decode ani mint).
#[test]
fn t461_5_u32_keeper() {
    for (w, leg, want) in U32KEEP461 {
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        let got = dec(&t, &idx, *w);
        assert_eq!(got.as_deref(), Some(*want), "[{leg}] U32 drift {w:#034x}");
        assert!(want.contains("RZ.U32"), "expected RZ.U32 glyph: {want}");
    }
}

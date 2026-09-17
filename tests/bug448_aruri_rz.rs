//! BUG-448 pins (F2-iter253, loop5/blind front2, 2026-09-12): vendor base-RZ
//! elision on the EFL2.256 NA ARURI family -- ra=255 in the plain-u32-ur
//! address prints bare `[URm(+off)]`, not `[RZ.U32+URm]` (arb448 34 probes,
//! nvdisasm 13.3.73 raw -b x4 models AGREE EVERY/DIVERGENT=0: invariant under
//! policy byte 0x00/0xfe/0xbf/0xff, signed<<5 offset +/-, pred_inv4=8,
//! LTC64B.CONSTANT ride, URZ/UR0 sweeps; `[URZ]` / `[URZ+0x20]` / `[UR0]`
//! render bare too). Every measured LEGACY plain family KEEPS
//! `[RZ.U32+URm]` x4 (arb448 K: bug149/bug099/038a/arb444 carriers --
//! LDG.E/.64/.128, LD.E, STG.E/.64, .EL x2, ATOMG.E.64, even
//! `[RZ.U32+URZ]`); the elide is gated on the efl2_na arm only, NA-width
//! plain (.128/U16) unmeasured-untouched.
//! ENGINE-only: canonical blackwell-isa 099faa0 STOI (tables byte-untouched).
//! Engine arms: (1) printer format_plain_u32_ur elide
//! (efl2_na && base==Some(255) && ur.is_some()); (2) parser bare-URZ
//! admission (BUG-073 clause lifted by arb448 vendor-attest); (3) encoder
//! ARURI fallback candidates for Addr{base:None, ur:Some} (BUG-398
//! pattern; AURI primary keeps priority -- ATOMS sm120 BUG-181 untouched);
//! (4) op_sub_ureg idx==1 arm relaxed for elided base (donor rows key UR
//! as sub_ur1 regardless of the textual prefix). BUG-060 keeper parity
//! intact: elided base == RZ(255) odd, guard outcome unchanged.
//! Defect pre->post (measure448; post-447 lineage a3245079 + 099faa0 ->
//! work; 33 cells x4): E-family 17 WRONG/leg -> all MATCH; K-family all
//! MATCH pre->post; standing pre==post: coverage holes (atomg x3 rows
//! 121a-only, bug149 carrier 120/121a) + k.ldg_corpus_rz sm121a raw-rebuild
//! form (121a-coverage class, NOT 448).
//! Witness data: tests/bug448_data.inc (machine-built by
//! work/bug448/gen448pins.py; rc=2 fail-closed; no hand hex; mints
//! nvdisasm-crossed x4 at generation time).

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::IsaTable;

include!("bug448_data.inc");

fn tab(arch: &str) -> IsaTable {
    IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap()
}
fn dec(t: &IsaTable, idx: &DecodeIndex, w: u128) -> Option<String> {
    idx.decode(w, 0, t)
        .ok()
        .map(|d| to_sass(&d).trim().trim_end_matches(';').to_string())
}
const LEGS448: [&str; 4] = ["sm100a", "sm103a", "sm120", "sm121a"];
fn enc(t: &IsaTable, text: &str) -> Result<u128, String> {
    let full = format!(" {text} ;");
    let parsed = parse_sass(&full, 0).map_err(|e| e.to_string())?;
    encode_instruction(&parsed, t).map_err(|e| e.to_string())
}

/// t448_1: heal grid -- decode == vendor elided text on every EFL2.256 NA
/// ARURI base-RZ cell, all four legs (68 = 17 words x 4).
#[test]
fn t448_1_heal_grid() {
    for (w, leg, vendor) in LAW448_HEAL {
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        let got = dec(&t, &idx, *w);
        assert_eq!(
            got.as_deref(),
            Some(*vendor),
            "[{leg}] heal drift {w:#034x}"
        );
    }
}

/// t448_2: keep grid -- legacy plain families keep `[RZ.U32+URm]` text x4;
/// elision must not leak past the efl2_na arm (overreach tripwire).
#[test]
fn t448_2_keep_grid() {
    for (w, leg, vendor) in LAW448_KEEP {
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        let got = dec(&t, &idx, *w);
        assert_eq!(
            got.as_deref(),
            Some(*vendor),
            "[{leg}] keep drift {w:#034x}"
        );
    }
}

/// t448_3: standing snap -- pre==post cells outside 448 scope stay
/// machine-snapped (121a-coverage class; zero silent heals/losses).
#[test]
fn t448_3_standing_snap() {
    for (w, leg, snap) in STAND448 {
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        let got = dec(&t, &idx, *w);
        // "HOLE" in the machine data pins a decode hole (decode error).
        let exp = if *snap == "HOLE" { None } else { Some(*snap) };
        assert_eq!(got.as_deref(), exp, "[{leg}] standing drift {w:#034x}");
    }
}

/// t448_4: elided mints -- encode(vendor bare-UR text) == machine mint on
/// every leg; decode circle returns the vendor text (parser admission +
/// ARURI fallback + sub_ur1 fill live).
#[test]
fn t448_4_elided_mints() {
    for leg in LEGS448 {
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        for (mw, vendor) in MASKMINT448 {
            let got = enc(&t, vendor)
                .unwrap_or_else(|e| panic!("[{leg}] elided mint refuse {vendor}: {e}"));
            assert_eq!(got, *mw, "[{leg}] elided mint drift {vendor}");
            let back =
                dec(&t, &idx, got).unwrap_or_else(|| panic!("[{leg}] elided circle HOLE {vendor}"));
            assert_eq!(
                back, *vendor,
                "[{leg}] elided circle drift {vendor} -> {back}"
            );
        }
    }
}

/// t448_5: alias mints -- the explicit `[RZ.U32+URm..]` spelling encodes the
/// SAME word as the vendor elided spelling on all four legs (back-compat).
#[test]
fn t448_5_alias_mints() {
    for leg in LEGS448 {
        let t = tab(leg);
        for (mw, elided, rz) in ALIAS448 {
            let w_el = enc(&t, elided)
                .unwrap_or_else(|e| panic!("[{leg}] alias elided refuse {elided}: {e}"));
            let w_rz = enc(&t, rz).unwrap_or_else(|e| panic!("[{leg}] alias rz refuse {rz}: {e}"));
            assert_eq!(w_el, *mw, "[{leg}] elided != mint {elided}");
            assert_eq!(w_rz, *mw, "[{leg}] rz-spelling != mint {rz}");
        }
    }
}

/// t448_6: keep-mint -- bare `[UR36]` admission on legacy STG.E yields the
/// very same word as explicit `[RZ.U32+UR36]` (semantic-equality doc pin;
/// word nvdisasm-crossed x4 at generation).
#[test]
fn t448_6_keep_mint() {
    for (mw, elided) in KEEPMINT448 {
        for leg in LEGS448 {
            let t = tab(leg);
            let rz = elided.replace("[UR36]", "[RZ.U32+UR36]");
            let w_el =
                enc(&t, elided).unwrap_or_else(|e| panic!("[{leg}] keep-mint elided refuse: {e}"));
            let w_rz = enc(&t, &rz).unwrap_or_else(|e| panic!("[{leg}] keep-mint rz refuse: {e}"));
            assert_eq!(w_el, *mw, "[{leg}] keep-mint elided drift");
            assert_eq!(w_rz, *mw, "[{leg}] keep-mint rz drift");
        }
    }
}

/// t448_7: refuse clauses -- shapes staying fail-closed post-admission
/// (double-URZ, suffixed bare URZ, UR-address on non-address op).
#[test]
fn t448_7_refuse() {
    let t = tab("sm103a");
    for bad in REFUSE448 {
        let full = format!(" {bad} ;");
        let refused = match parse_sass(&full, 0) {
            Err(_) => true,
            Ok(p) => encode_instruction(&p, &t).is_err(),
        };
        assert!(refused, "not fail-closed: {bad}");
    }
}

/// t448_8: canonical pin -- ENGINE-only bug; canonical HEAD rides (450: 589be87).
/// (Ratchet itself carries no 448 row; pin asserts the documented state.)
#[test]
fn t448_8_canonical_pin() {
    assert_eq!(CANON448, "bd2e254"); // ride F2-iter275 (BUG-466 ELL2.256 rekanon); was 23976eb; old:  ride F2-iter267 (BUG-432 ari-cavity); was a64b82b (BUG-463 ltc-widths); // ride F2-iter266 (BUG-463 ltc-widths); was f58ed16 (BUG-461 glyph); // ride F2-iter265 (BUG-461 glyph); was f376558 (BUG-462 narrow); // ride F2-iter264 (BUG-462 narrow); was 700524e (BUG-453 graft); // ride F2-iter263 (BUG-453 graft); was e03e034 (BUG-452 narrow); // ride F2-iter258 (BUG-454 graft) [flip-ride 467: pin 67b54f4 -> 668f842]
}

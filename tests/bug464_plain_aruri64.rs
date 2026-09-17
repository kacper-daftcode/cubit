//! BUG-464 pins (F2-iter270, loop5/blind front2, 2026-09-15): plain (nNA)
//! ARURI64 EFL2.256 lattice graft (canonical +6 kluczy/noga x4: LDG
//! *_R_R_ARURI64{,_P,_II,_II_P} + STG *_ARURI64_R_R{,_II}) + ENGINE army
//! (printer format_plain_u32_ur plain64; encoder `_ARURI64` fallback dla
//! elizji bazy '[URm(+off)]'). Rodzina byla absent x4 (engine HOLE, vendor
//! rc=0 -- fz nosniki klasy STANDING z 453): flz frame {b75,b84,b91} + lo
//! 0x97e/0x97f. Vendor law: arb464/464b/464c/464d 508 sond nvdisasm 13.3.73
//! raw -b x4 AGREE EVERY/DIVERGENT=0 -- pol 8-bit pelny zakres (trailer
//! ', 0xNN' PRZED pred-out), 0xff = ELIDED (baza strict len-tie jak NA/dARI),
//! imm17/19 signed<<5 '+-', UR 0xff=URZ, pred_inv4 [90:87], rzedy era
//! [118:126) inert, band [92:96) inert, STG 72/73/74/87 inert (463-paritet,
//! flagi None-mirror), KILL tylko b91=0, baza 255 -> czysta elizja
//! '[UR38]'/'[URZ]'/'[UR38+0x40020]' (448-law-side, NIE glif 461-REDG --
//! mintowalna przez encoder fallback ARURI64). Standing nieclaimowane
//! (post==pre snap): modsub 465 (b77/78/79/80/81/82/84off/85), LTC ARURI LDG
//! [74:73] (468-family), U32 sibling b75=0 (474-kand), b83 inert pinned
//! (HOLE-parity lustro dARI; vm celowo bez b83). reuse-klasa b124 ->
//! '.reuse' parity z rodzina EFL2.256 (jak dARI/NA); era-kill '[0:96) core'
//! = 449-era-shadow. Witness data: tests/bug464_data.inc (machine-built by
//! work/bug464/gen464pins.py; rc=2 fail-closed; no hand hex; mints
//! nvdisasm-crossed x4 at generation time).

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::IsaTable;

include!("bug464_data.inc");

fn tab(arch: &str) -> IsaTable {
    IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap()
}
fn dec(t: &IsaTable, idx: &DecodeIndex, w: u128) -> Option<String> {
    idx.decode(w, 0, t)
        .ok()
        .map(|d| to_sass(&d).trim().trim_end_matches(';').to_string())
}
const LEGS464: [&str; 4] = ["sm100a", "sm103a", "sm120", "sm121a"];
fn enc(t: &IsaTable, text: &str) -> Result<u128, String> {
    let full = format!(" {text} ;");
    let parsed = parse_sass(&full, 0).map_err(|e| e.to_string())?;
    encode_instruction(&parsed, t).map_err(|e| e.to_string())
}

/// t464_1: heal grid -- decode == vendor text na slowach frame z trailerem
/// (pol != 0xff), wszystkie cztery nogi (pre-state = HOLE, dowiedzione w
/// sesji generowania pinow).
#[test]
fn t464_1_heal_grid() {
    for (w, tag, vendor) in LAW464_HEAL {
        for leg in LEGS464 {
            let t = tab(leg);
            let idx = DecodeIndex::build(&t);
            let got = dec(&t, &idx, *w);
            assert_eq!(
                got.as_deref(),
                Some(*vendor),
                "[{leg}] {tag} heal drift {w:#034x}"
            );
        }
    }
}

/// t464_2: elide grid -- pol == 0xff elided przez baze/_P (tie-break
/// krotszym kluczem, paritet NA/dARI), decode == vendor x4.
#[test]
fn t464_2_elide_grid() {
    for (w, tag, vendor) in LAW464_ELIDE {
        for leg in LEGS464 {
            let t = tab(leg);
            let idx = DecodeIndex::build(&t);
            let got = dec(&t, &idx, *w);
            assert_eq!(
                got.as_deref(),
                Some(*vendor),
                "[{leg}] {tag} elide drift {w:#034x}"
            );
        }
    }
}

/// t464_3: standing snap -- vendor-legalne slowa POZA frame (modsub/LTC/
/// U32/b83/desc76/NA) pozostaja nieruszone (pre==post machine snap).
#[test]
fn t464_3_standing_snap() {
    for (w, tag, snap) in STAND464 {
        for leg in LEGS464 {
            let t = tab(leg);
            let idx = DecodeIndex::build(&t);
            let got = dec(&t, &idx, *w);
            let exp = if *snap == "HOLE" { None } else { Some(*snap) };
            assert_eq!(
                got.as_deref(),
                exp,
                "[{leg}] {tag} standing drift {w:#034x}"
            );
        }
    }
}

/// t464_4: kill snap -- b91=0 pozostaje HOLE x4 (jedyne vendor-kille na
/// frame; NEW row nic nie claimguje tam).
#[test]
fn t464_4_kill_snap() {
    for (w, tag) in KILL464 {
        for leg in LEGS464 {
            let t = tab(leg);
            let idx = DecodeIndex::build(&t);
            assert!(
                dec(&t, &idx, *w).is_none(),
                "[{leg}] {tag} kill claimed {w:#034x}"
            );
        }
    }
}

/// t464_5: reuse-parity snap -- nosnik b124 drukowany jak rodzina EFL2.256
/// (dARI/NA): '.reuse' przy dst (vendor eliduje; klasa parity-standing,
/// pre==post z zachowaniem siblings). Snap = engine text z dowodem vendor.
#[test]
fn t464_5_reuse_parity() {
    for (w, tag, _vendor, snap) in REUSE464 {
        for leg in LEGS464 {
            let t = tab(leg);
            let idx = DecodeIndex::build(&t);
            let got = dec(&t, &idx, *w);
            assert_eq!(
                got.as_deref(),
                Some(*snap),
                "[{leg}] {tag} reuse-snap drift {w:#034x}"
            );
        }
    }
}

/// t464_6: era-shadow -- slowo vendor-kill w warstwie era [96:128) ma rdzen
/// [0:96) w frame; engine (era-blind, 449-doktryna) claimguje rdzen jak w
/// kazdej rodzinie dARI/NA. Snap = engine text.
#[test]
fn t464_6_era_shadow() {
    for (w, tag, snap) in SHADOW464 {
        for leg in LEGS464 {
            let t = tab(leg);
            let idx = DecodeIndex::build(&t);
            let got = dec(&t, &idx, *w);
            assert_eq!(
                got.as_deref(),
                Some(*snap),
                "[{leg}] {tag} shadow drift {w:#034x}"
            );
        }
    }
}

/// t464_7: mint circle -- encode(vendor text) -> decode -> ten sam tekst
/// x4 (mints z gen464pins, nvdisasm-crossed at generation time; slowo
/// mintu jest dowodem -- core [0:96) frame).
#[test]
fn t464_7_mint_circle() {
    for (w, vendor) in MINT464 {
        for leg in LEGS464 {
            let t = tab(leg);
            let idx = DecodeIndex::build(&t);
            let got = dec(&t, &idx, *w);
            assert_eq!(
                got.as_deref(),
                Some(*vendor),
                "[{leg}] mint-word decode drift {w:#034x}"
            );
            // encode odzyskuje core-slowo (era-mnemosina encodera vs dowod:
            // porownanie przez decode circle powyzej + nvdisasm w genetorze)
            let re = enc(&t, vendor);
            if let Ok(rw) = re {
                let g2 = dec(&t, &idx, rw);
                assert_eq!(g2.as_deref(), Some(*vendor), "[{leg}] re-mint circle drift");
            }
            // refuse (BUG-060 guard na sm103a even-base) jest prawidlowa
            // odpowiedzia fail-closed; nie wymusza formatu slowa.
        }
    }
}

/// t464_8: elide-mint circle -- elizja bazy '[URm(+off)]' mintowalna przez
/// encoder fallback `_ARURI64` (base:None -> 255 fill), decode kolo x4.
#[test]
fn t464_8_elide_mint_circle() {
    for (w, vendor) in MINT464_ELIDE {
        for leg in LEGS464 {
            let t = tab(leg);
            let idx = DecodeIndex::build(&t);
            let got = dec(&t, &idx, *w);
            assert_eq!(
                got.as_deref(),
                Some(*vendor),
                "[{leg}] elide-word decode drift {w:#034x}"
            );
            let rw =
                enc(&t, vendor).unwrap_or_else(|e| panic!("[{leg}] elide-mint FAIL {vendor}: {e}"));
            let g2 = dec(&t, &idx, rw);
            assert_eq!(g2.as_deref(), Some(*vendor), "[{leg}] elide re-mint drift");
        }
    }
}

/// t464_9: refuse 461 -- tekst '[RZ.64+URm]' (jawna baza 255 z .64) jest
/// refuse'owany globalnym armem encodera BUG-461 (rodzina 464 dzieli arm
/// z reszta ARURI64); '[URm]' bare elide NIE jest refuse'owany (t464_8).
#[test]
fn t464_9_refuse461() {
    for leg in LEGS464 {
        let t = tab(leg);
        for txt in [
            "LDG.E.EFL2.256 R44, R48, [RZ.64+UR38], 0x99",
            "STG.E.EFL2.256 [RZ.64+UR38], R44, R48, 0xa0",
        ] {
            let e = enc(&t, txt);
            assert!(e.is_err(), "[{leg}] RZ.64 plain ARURI64 nie refused: {txt}");
            assert!(
                e.unwrap_err().contains("461"),
                "[{leg}] refuse bez cytatu 461"
            );
        }
    }
}

/// t464_10: canonical pin -- catena graftu (tabele vendored by sync;
/// tripwire dla ride-flipow: zfcpatowane hashe przez flip464).
#[test]
fn t464_10_canonical_pin() {
    let src = std::fs::read_to_string("tables/SOURCE.json").unwrap();
    assert!(
        src.contains(CANON464),
        "SOURCE.json nie pina canonical 464-graftu ({}): {}",
        &CANON464[..8],
        src.lines().nth(3).unwrap_or("")
    );
}

//! BUG-464 pins (F2-iter270, loop5/blind front2, 2026-09-15): the plain (nNA)
//! ARURI64 EFL2.256 lattice graft (canonical: +6 keys per leg x4: LDG
//! *_R_R_ARURI64{,_P,_II,_II_P} + STG *_ARURI64_R_R{,_II}) + the ENGINE arm (printer
//! format_plain_u32_ur plain64; encoder `_ARURI64` fallback for the elided base
//! '[URm(+off)]'). The family was absent on all four legs (an engine HOLE, vendor
//! rc=0 -- the fz carriers of the STANDING class from 453): the flz frame
//! {b75,b84,b91} + low 0x97e / 0x97f. Vendor law: arb464 / 464b / 464c / 464d, 508
//! probes, nvdisasm 13.3.73 raw -b x4 AGREE EVERY / DIVERGENT = 0 -- the 8-bit field
//! over its full range (the trailer ', 0xNN' BEFORE the pred-out), 0xff = ELIDED (the
//! strict length-tie base as on NA / dARI), imm17/19 signed<<5 '+-', UR 0xff = URZ,
//! pred_inv4 [90:87], the era rows [118:126) inert, the band [92:96) inert, STG
//! 72/73/74/87 inert (463 parity, None-mirror flags), KILL only at b91 = 0, base 255 ->
//! a clean elision '[UR38]' / '[URZ]' / '[UR38+0x40020]' (the 448 law side, NOT the
//! 461-REDG glyph -- mintable through the encoder's ARURI64 fallback). Standing,
//! unclaimed (post == pre snapshot): the 465 modsub (b77/78/79/80/81/82/84off/85), the
//! LTC ARURI LDG [74:73] (the 468 family), the U32 sibling b75 = 0 (candidate 474),
//! b83 inert pinned (HOLE parity, a mirror of dARI; vm deliberately without b83). The
//! reuse class b124 -> '.reuse' parity with the EFL2.256 family (as dARI / NA); the
//! era kill '[0:96) core' = the 449 era shadow. Witness data: tests/bug464_data.inc
//! (machine-built by work/bug464/gen464pins.py; rc=2 fail-closed; no hand hex; the
//! mints nvdisasm-crossed x4 at generation time).

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::IsaTable;

include!("bug464_data.inc");

// Immutable fixtures only: every word still runs through decode/encode.
fn pool() -> &'static std::collections::HashMap<&'static str, (IsaTable, DecodeIndex)> {
    static POOL: std::sync::OnceLock<std::collections::HashMap<&'static str, (IsaTable, DecodeIndex)>> = std::sync::OnceLock::new();
    POOL.get_or_init(|| {
        ["sm100a", "sm103a", "sm120", "sm121a"].into_iter().map(|arch| {
            let table = IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap();
            let index = DecodeIndex::build(&table);
            (arch, (table, index))
        }).collect()
    })
}
fn tab(arch: &str) -> &'static IsaTable {
    &pool().get(arch).unwrap().0
}
fn cached_index(table: &IsaTable) -> &'static DecodeIndex {
    pool().values().find(|(fixture, _)| std::ptr::eq(fixture, table))
        .map(|(_, index)| index).expect("table must come from the immutable fixture pool")
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
/// The legs whose 256-bit LDG / STG family is measured (one row per modifier group, fail-closed on the text-inert
/// bits): sm120 since G's batches 10-13 (2026-11-07); sm103a / sm100a since T-20 / T-21 batch 4 (2026-11-08,
/// `tools/probes/re_sm120_ldg256.py --arch SM103 / SM100` x 3 forms + `re_sm120_stg256.py --arch SM103 / SM100`,
/// nvdisasm 13.1 -- every form word prints the SM120 text on both targets; fixtures
/// `tests/fixtures/sm103a_*256*_nvdisasm.jsonl` / `sm100a_*`, tests `tests/sm103a_sm100a_*256*.rs`).
/// sm121a since T-21 batch 5 (2026-11-08): the same five probes with `--arch SM121 --witnesses` (the GB10 census words
/// of the forms) -- every form word prints the SM120 text; `tests/sm121a_{ldg256_dari,ldg256_aruri64,ldg256_aruri,stg256,redg_aruri}.rs`.
fn measured256(leg: &str) -> bool {
    matches!(leg, "sm120" | "sm103a" | "sm100a" | "sm121a")
}

/// t464_1: heal grid -- decode == vendor text na slowach frame z trailerem
/// (pol != 0xff), wszystkie cztery nogi (pre-state = HOLE, dowiedzione w
/// sesji generowania pinow).
#[test]
fn t464_1_heal_grid() {
    for (w, tag, vendor) in LAW464_HEAL {
        for leg in LEGS464 {
            let t = tab(leg);
            let idx = cached_index(t);
            let got = dec(t, idx, *w);
            // 2026-11-07 (session G, batch 11, tools/probes/re_sm120_ldg256.py): the measured sm120 rows of the
            // 256-bit load (`LDG_R_R_ARURI64[_II][_P]`) fail closed on the text-inert bits 83 / 92-95 (T-10's
            // convention for measured rows); the `_b9x` cells of this grid carry one of them.
            // T-21 batch 4 (2026-11-08): the same measured rows on sm103a / sm100a (`measured256`); sm121a is untouched.
            if measured256(leg) && (*w & 0xfff) == 0x97e && (*w & ((1u128 << 83) | (0xfu128 << 92))) != 0 {
                assert_eq!(got, None, "[{leg}] {tag} {w:#034x}: inert bits fail closed (G batch 11 / T-21 batch 4)");
                continue;
            }
            // Batch 13 (tools/probes/re_sm120_stg256.py): the store's measured `STG_ARURI64_R_R[_II]` rows the same way
            // ([74:72] / 83 / 87 / [95:92] text-inert on the 256-bit store; the `.Cg.stg685` cell carries bit 94).
            if measured256(leg) && (*w & 0xfff) == 0x97f && (*w & ((7u128 << 72) | (1u128 << 83) | (1u128 << 87) | (0xfu128 << 92))) != 0 {
                assert_eq!(got, None, "[{leg}] {tag} {w:#034x}: inert bits fail closed (G batch 13 / T-21 batch 4)");
                continue;
            }
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
            let idx = cached_index(t);
            let got = dec(t, idx, *w);
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
            let idx = cached_index(t);
            let got = dec(t, idx, *w);
            let exp = if *snap == "HOLE" { None } else { Some(*snap) };
            // 2026-11-07 (session G, batch 11): the `.C3.ldg_b86` cell (cache code 5 = NA, no scope) is a legal word
            // nvdisasm 13.1 names on SM120 / SM103 / SM100 -- the 2026-09 HOLE stood on the harvest's silence; the
            // measured `LDG_R_R_ARURI64_II` row claims it on sm120 -- and on sm103a / sm100a since T-21 batch 4
            // (`re_sm120_ldg256.py --form ARURI64 --arch SM103 / SM100`: the same text on both targets).
            if measured256(leg) && *tag == "arb464c_.C3.ldg_b86" {
                assert_eq!(got.as_deref(), Some("@P1 LDG.E.NA.EFL2.256 R44, R48, [R28.64+UR38], 0x99"), "[{leg}] {tag} (measured legal, G batch 11 / T-21 batch 4)");
                continue;
            }
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
            let idx = cached_index(t);
            assert!(
                dec(t, idx, *w).is_none(),
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
            let idx = cached_index(t);
            let got = dec(t, idx, *w);
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
            let idx = cached_index(t);
            let got = dec(t, idx, *w);
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
            let idx = cached_index(t);
            let got = dec(t, idx, *w);
            assert_eq!(
                got.as_deref(),
                Some(*vendor),
                "[{leg}] mint-word decode drift {w:#034x}"
            );
            // encode odzyskuje core-slowo (era-mnemosina encodera vs dowod:
            // porownanie przez decode circle powyzej + nvdisasm w genetorze)
            let re = enc(t, vendor);
            if let Ok(rw) = re {
                let g2 = dec(t, idx, rw);
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
            let idx = cached_index(t);
            let got = dec(t, idx, *w);
            assert_eq!(
                got.as_deref(),
                Some(*vendor),
                "[{leg}] elide-word decode drift {w:#034x}"
            );
            let rw =
                enc(t, vendor).unwrap_or_else(|e| panic!("[{leg}] elide-mint FAIL {vendor}: {e}"));
            let g2 = dec(t, idx, rw);
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
            let e = enc(t, txt);
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
    // Current byte-pinned cut; historical fixture provenance remains unchanged.
    const CURRENT_VENDORED_CANON: &str = "6bb25fa2c4b303253a66a304c2f86c36a4b2e46c" /* 2026-11-06 T-11 (was c258f8a, T-10) */ /* 2026-11-06 T-10 (was b75cc20, T-9) */;
    assert_eq!(CANON464, "9c0e4cec355119065444f59d0710de372b9d0577", "historical fixture revision drift");

    let src = std::fs::read_to_string("tables/SOURCE.json").unwrap();
    assert!(
        src.contains(CURRENT_VENDORED_CANON),
        "SOURCE.json nie pina canonical 464-graftu ({}): {}",
        &CANON464[..8],
        src.lines().nth(3).unwrap_or("")
    );
}

//! BUG-467 pins (F2-iter278, loop5/blind front2, 2026-09-16): DELETE x8
//! degenerate era-rows (canonical 67b54f4 -> 668f842). Registry 467-kand
//! (residuum 462): sm120 x3 klucze _P_P ATOM/ATOMG dARI + sm121a x4 klucze
//! STG.E{,_P,64,128} dARI nobracket-mangle; audiencja poszerzyla o sm121a
//! STG.E_II_R (ta sama zdegenerowana ramka era; po usunieciu x4 przejalby
//! mangle na siebie).
//!
//! Defekt pre (publish e13567b3): silnik claimowal slowa z ramka era
//! [ab=0x08001000@64:96 (sm120) / 0x0c001000@64:96 (sm121a)] i drukowal
//! mangle: ATOMG.E.ADD renderowane jako 'ATOMG.E.OR.STRONG.GPU' (oba klucze
//! ADD i OR mialy IDENTYCZNE ab=0x80010008000000000ff09a8), ekstra token
//! '0x0', 'PT' vs vendor 'RZ', 'E' vs vendor 'EF'; sm121a x4: nobracket
//! 'STG.E 0x0, R0' (brak adresu w ogole). Vendor (nvdisasm 13.3.73 raw -b)
//! drukuje dla CALEGO claim-space'u glif degenerate: ATOM.???0.ADD.EF /
//! ATOMG.???0.ADD.EF / STG.???0.EF.U8 -- arb467b+arb467c 216/216 sond
//! (27 mutacji x 8 klas: ureg [64:72), reuse b122/123/124, pred [81:84),
//! guard [12:16), imm/regs, combo) rc=0 I WSZYSTKIE '???0'. Rodzenstwo
//! legalne (P_R dARI sm120; STG.E.EL/SM/EU/NA, STG_dARI_R mgs na sm121a)
//! renderuje poprawnie => degeneracja siedzi w ramce era, nie w low12.
//!
//! Fix = DELETE calej klasy x8 (doktryna fail-closed dla glifow vendor-
//! invalid: decoder.rs F2I.???6/???7 + 285 INVALID-enum HOLE-parity; 452
//! HOLE-posture). Encode-side pre i post: no-entry fail-closed dla tekstow
//! mangle'owanych i dla glifu '???0'. Claim-space post-delete pusta
//! (A0b-post), trzecich claimantow brak (A0b). Census ekspozycji ab240
//! (34.0M slow x4 nogi) = 0 nosnikow (LATENT). Zero ENGINE src. Witness
//! data: tests/bug467_data.inc (machine-built by work/bug467/gen467pins.py
//! rc=0; anchors/keeps minted live nvdisasm; no hand hex).

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::IsaTable;

include!("bug467_data.inc");

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

/// t467_1: 8 anchors era-wordow = decode fail-closed HOLE (post-delete);
/// kazdy anchor jest z claim-space'i usunietej klasy i ma glif vendor
/// '???0' (law pin w inc; doktryna HOLE dla vendor-degenerate).
#[test]
fn t467_1_decode_fail_closed_anchors() {
    let mut n = 0;
    for (w, leg, tag, vendor) in DEGEN467_LAW {
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        let got = dec(&t, &idx, *w);
        assert!(
            got.is_none(),
            "[{leg}] {tag}: era-word musi byc HOLE, decode dal {got:?} (vendor: {vendor})"
        );
        assert!(
            vendor.contains("???0"),
            "[{leg}] {tag}: law expected ???0 glyph"
        );
        n += 1;
    }
    assert_eq!(n, 8, "8 anchors expected");
}

/// t467_2: caly probe-space (99 mutacji 8 klas; ureg/reuse/pred/guard/imm/
/// regs/combo) = decode HOLE; zero trzecich claimantow post-delete.
#[test]
fn t467_2_probe_space_all_hole() {
    let mut by_leg = std::collections::HashMap::new();
    for (_, leg, _) in DEGEN467_PROBES {
        *by_leg.entry(*leg).or_insert(0usize) += 1;
    }
    let mut n = 0;
    for (w, leg, tag) in DEGEN467_PROBES {
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        let got = dec(&t, &idx, *w);
        assert!(
            got.is_none(),
            "[{leg}] {tag}: probe {w:#034x} musi byc HOLE, decode dal {got:?}"
        );
        n += 1;
    }
    assert_eq!(n, 99, "probe census 99");
    assert_eq!(by_leg.len(), 2, "probes only on sm120+sm121a");
}

/// t467_3: encode fail-closed: teksty mangle'owane (pre-engine) i glify
/// vendora '???0' MUSZA odmawiac (postawa pre==post; LOCK fail-closed).
#[test]
fn t467_3_encode_refuse_fail_closed() {
    let mut n = 0;
    for (leg, text) in REFUSE467 {
        let t = tab(leg);
        let r = enc(&t, text);
        assert!(
            r.is_err(),
            "[{leg}] encode '{text}' musi odmawiac, dal {r:034x?}"
        );
        n += 1;
    }
    assert_eq!(n, 11);
}

/// t467_4: legalne rodzenstwo nietkniete: decode == vendor text-exact +
/// encode keep-alive dziala (plain-STG na sm121a koderuje jak przed fixem).
#[test]
fn t467_4_keep_alive_siblings() {
    for (w, leg, tag, vendor) in KEEP467 {
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        let got = dec(&t, &idx, *w);
        assert_eq!(
            got.as_deref(),
            Some(*vendor),
            "[{leg}] {tag}: legal sibling drift {w:#034x}"
        );
    }
    for (leg, text) in KEEP467_ENC {
        let t = tab(leg);
        let w = enc(&t, text).unwrap_or_else(|e| panic!("[{leg}] keep-enc '{text}' odmowil: {e}"));
        let idx = DecodeIndex::build(&t);
        assert!(
            dec(&t, &idx, w).is_some(),
            "[{leg}] keep-enc word of '{text}' musi dekodowac (circle)"
        );
    }
    // pin byte-exact: mint == slowo-z-witness + decode == tekst vendora
    // (zdeponowane po naprawie prestudy iter277 B.2: mincowane slowa sa
    // vendor-LEGALNE na sm121a; hazard-hipoteza obalona).
    for (w, leg, text, vendor) in KEEP467_ENC_WORD {
        let t = tab(leg);
        let got = enc(&t, text).unwrap();
        assert_eq!(&got, w, "[{leg}] keep-enc mint geometry drift for '{text}'");
        let idx = DecodeIndex::build(&t);
        assert_eq!(
            dec(&t, &idx, got).as_deref(),
            Some(*vendor),
            "[{leg}] keep-enc circle text drift '{text}'"
        );
    }
}

/// t467_5: census kluczy post-delete + SOURCE pin == canonical graft
/// (raw counts: sm120 9088-3=9085, sm121a 16912-5=16907; 100a/103a stoi).
/// ride F2-iter280 BUG-468: +2320 keys (LTC-sel [74:73] lattice closure plain ARURI64 + NA LTC128B/256B; canonical 08a6145) -> 10267/10267/11405/19227.
/// ride F2-iter282 BUG-469: +6 sm121a keys (widthless ARURI graft: 2x ELL2.256 R_R_ARURI donor-103a verbatim-era0 + mg R/R_P/P_R/P_R_P plain-band + 4x EF-band P_R_ARURI_P; canonical bd48e63) -> 10267/10267/11405/19233.
/// RIDE474 (F2-iter285 BUG-474, canonical PENDING-474): +3454/+3454/+3454/+3455 twins _ARURI U32 (b75=0 sib calej rodziny plain ARURI64 464/465/468) -> 13721/13721/14859/22688.
/// RIDE474 (F2-iter285 BUG-474, canonical PENDING-474): +3454/+3454/+3454/+3455 twins _ARURI U32 (b75=0 sib calej rodziny plain ARURI64 464/465/468) -> 13721/13721/14859/22688.
/// RIDE474 (F2-iter285 BUG-474, canonical PENDING-474): +3454/+3454/+3454/+3455 twins _ARURI U32 (b75=0 sib calej rodziny plain ARURI64 464/465/468) -> 13721/13721/14859/22688.
/// RIDE474 (F2-iter285 BUG-474, canonical PENDING-474): +3454/+3454/+3454/+3455 twins _ARURI U32 (b75=0 sib calej rodziny plain ARURI64 464/465/468) -> 13721/13721/14859/22688.
/// RIDE474 (F2-iter285 BUG-474, canonical PENDING-474): +3454/+3454/+3454/+3455 twins _ARURI U32 (b75=0 sib calej rodziny plain ARURI64 464/465/468) -> 13721/13721/14859/22688.
/// ride F2-iter280 BUG-468: +2320 keys (LTC-sel [74:73] lattice closure plain ARURI64 + NA LTC128B/256B; canonical 08a6145) -> 10267/10267/11405/19227.
/// ride F2-iter282 BUG-469: +6 sm121a keys (widthless ARURI graft: 2x ELL2.256 R_R_ARURI donor-103a verbatim-era0 + mg R/R_P/P_R/P_R_P plain-band + 4x EF-band P_R_ARURI_P; canonical bd48e63) -> 10267/10267/11405/19233.
/// RIDE474 (F2-iter285 BUG-474, canonical PENDING-474): +3454/+3454/+3454/+3455 twins _ARURI U32 (b75=0 sib calej rodziny plain ARURI64 464/465/468) -> 13721/13721/14859/22688.
/// RIDE474 (F2-iter285 BUG-474, canonical PENDING-474): +3454/+3454/+3454/+3455 twins _ARURI U32 (b75=0 sib calej rodziny plain ARURI64 464/465/468) -> 13721/13721/14859/22688.
/// RIDE474 (F2-iter285 BUG-474, canonical PENDING-474): +3454/+3454/+3454/+3455 twins _ARURI U32 (b75=0 sib calej rodziny plain ARURI64 464/465/468) -> 13721/13721/14859/22688.
/// RIDE474 (F2-iter285 BUG-474, canonical PENDING-474): +3454/+3454/+3454/+3455 twins _ARURI U32 (b75=0 sib calej rodziny plain ARURI64 464/465/468) -> 13721/13721/14859/22688.
/// RIDE474 (F2-iter285 BUG-474, canonical PENDING-474): +3454/+3454/+3454/+3455 twins _ARURI U32 (b75=0 sib calej rodziny plain ARURI64 464/465/468) -> 13721/13721/14859/22688.
/// RIDE475R3 (F2-iter289): +3/+3/+2/+2 (NA/EU restore + alias + 121a R3b anomalie) -> 14868/14868/16005/23825; cf 1169/1169/1166/1183 // RIDE475 (F2-iter288 BUG-475, canonical PENDING-475): +1146 graft x4 nogi (dARI modsub lattice E*L2.256 frame b76=1: klon 6 donorow *_dARI EFL2.256/noga, fields/vm PARITY) + rekanon 462-mgs ENL2 [489-absorb: DELETE 13/13/7 mgs + 2 anomalie 121a; REPLACE 9 heritage _src462] -> raw 14865/14865/16003/23823; loader 121a 23821 (offset -2 _errata stoi); cf 1166/1166/1164/1181 -> 14865/14865/16003/23823 (loader-121a 23821).
#[test]
fn t467_5_census_and_source_pin() {
    for (leg, want) in [
        ("sm100a", 14879usize), // RIDE476 (F2-iter299, canonical c88778e): +11 -> 14879 // RIDE475R3 (F2-iter289): +3/+3/+2/+2 (NA/EU restore + alias + 121a R3b anomalie) -> 14868/14868/16005/23825; cf 1169/1169/1166/1183 // RIDE475 (F2-iter288 BUG-475, canonical PENDING-475): +1146 graft x4 nogi (dARI modsub lattice E*L2.256 frame b76=1: klon 6 donorow *_dARI EFL2.256/noga, fields/vm PARITY) + rekanon 462-mgs ENL2 [489-absorb: DELETE 13/13/7 mgs + 2 anomalie 121a; REPLACE 9 heritage _src462] -> raw 14865/14865/16003/23823; loader 121a 23821 (offset -2 _errata stoi); cf 1166/1166/1164/1181 // was: 13721usize // RIDE474 (F2-iter285 BUG-474, canonical PENDING-474): +3454/+3454/+3454/+3455 twins _ARURI U32 (b75=0 sib calej rodziny plain ARURI64 464/465/468) // was: 10267 ride F2-iter280 BUG-468: +2320 keys (LTC-sel [74:73] lattice closure plain ARURI64 + NA LTC128B/256B; canonical 08a6145),
        ("sm103a", 14879usize), // RIDE476 (F2-iter299, canonical c88778e): +11 -> 14879 // RIDE475R3 (F2-iter289): +3/+3/+2/+2 (NA/EU restore + alias + 121a R3b anomalie) -> 14868/14868/16005/23825; cf 1169/1169/1166/1183 // RIDE475 (F2-iter288 BUG-475, canonical PENDING-475): +1146 graft x4 nogi (dARI modsub lattice E*L2.256 frame b76=1: klon 6 donorow *_dARI EFL2.256/noga, fields/vm PARITY) + rekanon 462-mgs ENL2 [489-absorb: DELETE 13/13/7 mgs + 2 anomalie 121a; REPLACE 9 heritage _src462] -> raw 14865/14865/16003/23823; loader 121a 23821 (offset -2 _errata stoi); cf 1166/1166/1164/1181 // was: 13721usize // RIDE474 (F2-iter285 BUG-474, canonical PENDING-474): +3454/+3454/+3454/+3455 twins _ARURI U32 (b75=0 sib calej rodziny plain ARURI64 464/465/468) // was: 10267 ride F2-iter280 BUG-468: +2320 keys (LTC-sel [74:73] lattice closure plain ARURI64 + NA LTC128B/256B; canonical 08a6145),
        ("sm120", 16015usize), // RIDE459a (F2-iter301, canonical 96372cb): -1 sm120 key (459a junk-mg "" / 64 DELETE -> key-del UR_II_..._UP_UP) -> forms 16015, variants -4=17631; sm121a variants -4=26385; cf stoi // RIDE476 (F2-iter299, canonical c88778e): +11 -> 16016 // RIDE475R3 (F2-iter289): +3/+3/+2/+2 (NA/EU restore + alias + 121a R3b anomalie) -> 14868/14868/16005/23825; cf 1169/1169/1166/1183 // RIDE475 (F2-iter288 BUG-475, canonical PENDING-475): +1146 graft x4 nogi (dARI modsub lattice E*L2.256 frame b76=1: klon 6 donorow *_dARI EFL2.256/noga, fields/vm PARITY) + rekanon 462-mgs ENL2 [489-absorb: DELETE 13/13/7 mgs + 2 anomalie 121a; REPLACE 9 heritage _src462] -> raw 14865/14865/16003/23823; loader 121a 23821 (offset -2 _errata stoi); cf 1166/1166/1164/1181 // was: 14859usize // RIDE474 (F2-iter285 BUG-474, canonical PENDING-474): +3454/+3454/+3454/+3455 twins _ARURI U32 (b75=0 sib calej rodziny plain ARURI64 464/465/468) // was: 11405 ride F2-iter280 BUG-468: +2320 keys (LTC-sel [74:73] lattice closure plain ARURI64 + NA LTC128B/256B; canonical 08a6145),
        ("sm121a", 23833usize), // RIDE476 (F2-iter299, canonical c88778e): +8 -> raw 23833 // RIDE475R3 (F2-iter289): +3/+3/+2/+2 (NA/EU restore + alias + 121a R3b anomalie) -> 14868/14868/16005/23825; cf 1169/1169/1166/1183 // RIDE475 (F2-iter288 BUG-475, canonical PENDING-475): +1146 graft x4 nogi (dARI modsub lattice E*L2.256 frame b76=1: klon 6 donorow *_dARI EFL2.256/noga, fields/vm PARITY) + rekanon 462-mgs ENL2 [489-absorb: DELETE 13/13/7 mgs + 2 anomalie 121a; REPLACE 9 heritage _src462] -> raw 14865/14865/16003/23823; loader 121a 23821 (offset -2 _errata stoi); cf 1166/1166/1164/1181 // was: 22688usize // RIDE474 (F2-iter285 BUG-474, canonical PENDING-474): +3454/+3454/+3454/+3455 twins _ARURI U32 (b75=0 sib calej rodziny plain ARURI64 464/465/468) // was: 19233 ride F2-iter282 BUG-469: +6 sm121a keys (widthless ARURI graft: 2x ELL2.256 R_R_ARURI donor-103a verbatim-era0 + mg R/R_P/P_R/P_R_P plain-band + 4x EF-band P_R_ARURI_P; canonical bd48e63),  // ride F2-iter280 BUG-468: +2320 keys (LTC-sel [74:73] lattice closure plain ARURI64 + NA LTC128B/256B; canonical 08a6145),
    ] {
        let raw: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(format!("tables/{leg}.json")).unwrap())
                .unwrap();
        let got = raw["instructions"].as_object().unwrap().len();
        assert_eq!(got, want, "[{leg}] key census post-467");
    }
    let src: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string("tables/SOURCE.json").unwrap()).unwrap();
    assert_eq!(
        src["base_revision"].as_str().unwrap(),
        CANON467,
        "SOURCE.json base_revision == canonical graft 668f842"
    );
    // usuniete klucze nie wstana
    for (leg, keys) in [
        (
            "sm120",
            &[
                "ATOM.E.ADD.S32.STRONG.GPU_P_P_R_dARI_R",
                "ATOMG.E.ADD.STRONG.GPU_P_P_R_dARI_R",
                "ATOMG.E.OR.STRONG.GPU_P_P_R_dARI_R",
            ][..],
        ),
        (
            "sm121a",
            &[
                "STG.E_dARI_R",
                "STG.E_P_dARI_R",
                "STG.E.64_dARI_R",
                "STG.E.128_dARI_R",
                "STG.E_II_R",
            ][..],
        ),
    ] {
        let raw: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(format!("tables/{leg}.json")).unwrap())
                .unwrap();
        let i = raw["instructions"].as_object().unwrap();
        for k in keys {
            assert!(!i.contains_key(*k), "[{leg}] deleted key resurrected: {k}");
        }
    }
}

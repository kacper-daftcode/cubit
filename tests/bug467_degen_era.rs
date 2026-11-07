//! BUG-467 pins (F2-iter278, loop5/blind front2, 2026-09-16): DELETE x8 degenerate
//! era rows (canonical 67b54f4 -> 668f842). Registry candidate 467 (the residue of
//! 462): sm120 x3 keys _P_P ATOM / ATOMG dARI + sm121a x4 keys STG.E{,_P,64,128} dARI
//! with the no-bracket mangle; the audience widened by sm121a STG.E_II_R (the same
//! degenerate era frame; after the x4 deletion it would have taken the mangle over).
//!
//! The defect before (publish e13567b3): the engine claimed words with the era frame
//! [ab = 0x08001000@64:96 (sm120) / 0x0c001000@64:96 (sm121a)] and printed a mangle:
//! ATOMG.E.ADD rendered as 'ATOMG.E.OR.STRONG.GPU' (the ADD and OR keys had an
//! IDENTICAL ab = 0x80010008000000000ff09a8), an extra token '0x0', 'PT' vs the
//! vendor's 'RZ', 'E' vs the vendor's 'EF'; sm121a x4: the no-bracket 'STG.E 0x0, R0'
//! (no address at all). The vendor (nvdisasm 13.3.73 raw -b) prints the degenerate
//! glyph for the WHOLE claim space: ATOM.???0.ADD.EF / ATOMG.???0.ADD.EF /
//! STG.???0.EF.U8 -- arb467b + arb467c 216/216 probes (27 mutations x 8 classes: ureg
//! [64:72), reuse b122/123/124, pred [81:84), guard [12:16), imm/regs, combo) rc=0 AND
//! ALL '???0'. The legal siblings (P_R dARI on sm120; STG.E.EL/SM/EU/NA, the STG_dARI_R
//! mgs on sm121a) render correctly => the degeneracy sits in the era frame, not in
//! low12.
//!
//! Fix = DELETE the whole class x8 (the fail-closed doctrine for vendor-invalid
//! glyphs: decoder.rs F2I.???6/???7 + the 285 INVALID-enum HOLE parity; the 452 HOLE
//! posture). Encode side pre and post: no-entry fail-closed for the mangled texts and
//! for the '???0' glyph. The claim space after the deletion is empty (A0b-post), no
//! third claimants (A0b). Exposure census ab240 (34.0M words x 4 legs) = 0 carriers
//! (LATENT). Zero ENGINE source changes. Witness data: tests/bug467_data.inc
//! (machine-built by work/bug467/gen467pins.py rc=0; anchors / keeps minted live with
//! nvdisasm; no hand hex).

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::IsaTable;

include!("bug467_data.inc");

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
        let idx = cached_index(t);
        let got = dec(t, idx, *w);
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
        let idx = cached_index(t);
        let got = dec(t, idx, *w);
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
        let r = enc(t, text);
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
        let idx = cached_index(t);
        let got = dec(t, idx, *w);
        assert_eq!(
            got.as_deref(),
            Some(*vendor),
            "[{leg}] {tag}: legal sibling drift {w:#034x}"
        );
    }
    for (leg, text) in KEEP467_ENC {
        let t = tab(leg);
        let w = enc(t, text).unwrap_or_else(|e| panic!("[{leg}] keep-enc '{text}' odmowil: {e}"));
        let idx = cached_index(t);
        assert!(
            dec(t, idx, w).is_some(),
            "[{leg}] keep-enc word of '{text}' musi dekodowac (circle)"
        );
    }
    // pin byte-exact: mint == slowo-z-witness + decode == tekst vendora
    // (zdeponowane po naprawie prestudy iter277 B.2: mincowane slowa sa
    // vendor-LEGALNE na sm121a; hazard-hipoteza obalona).
    for (w, leg, text, vendor) in KEEP467_ENC_WORD {
        let t = tab(leg);
        let got = enc(t, text).unwrap();
        assert_eq!(&got, w, "[{leg}] keep-enc mint geometry drift for '{text}'");
        let idx = cached_index(t);
        assert_eq!(
            dec(t, idx, got).as_deref(),
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
    // Current byte-pinned cut; historical fixture provenance remains unchanged.
    const CURRENT_VENDORED_CANON: &str = "3dde6e176ff5f7273ccd86d4f3e29913db353ca0" /* 2026-11-06 T-11 (was c258f8a, T-10) */ /* 2026-11-06 T-10 (was b75cc20, T-9) */;
    assert_eq!(CANON467, "9c0e4cec355119065444f59d0710de372b9d0577", "historical fixture revision drift");

    for (leg, want) in [
        ("sm100a", 14925usize), // 2026-11-06 T-11 (canonical 3dde6e1): the IDP family measured whole (sm120 15953 -> 15964 forms, 26580 -> 26598 variants; sm103a / sm100a 14913 -> 14925, 22420 -> 22439; sm121a 23850 -> 23860, 26406 -> 26421) + the audit exceptions (FADD.SAT_R_R_R retired, DEPBAR claim_forbid) // 2026-11-06 T-10 (canonical 315bffa): BRA sm103a/sm100a 14912 -> 14913 forms, 22363 -> 22420 variants; sm120 BRX/BRXU/RET + the audit batches 16045 -> 15935 forms, 26646 -> 26562 variants // 2026-11-06 T-8 (LEA family rebuilt from measurement, tools/probes/re_sm120_lea.py: sm120 56 keys / 100 rows -> 24 keys / 36 rows, sm103a / sm100a 18 keys / 21 rows -> 24 / 36): sm120 16097 -> 16065 forms, 26663 -> 26599 variants; sm103a / sm100a 14906 -> 14912, 22348 -> 22363 // 2026-11-06 T-7 (coldface's B300-1/2/3/4 rows taken + the UTMALDG plain dims + the IADD3.X carry repair, provenance re-stamp, canonical 135068e): sm120 keys 16098 -> 16097 (-2 UTMALDG dotted era keys), variants 26660 -> 26663, loader 16117; sm103a / sm100a keys 14904 -> 14906 (+IADD.XOR, +LEA.HI.X), variants 22342 -> 22348 // 2026-11-06 T-7 (ATOMG .EL 64-bit-base rows ATOMG.E.{ADD,OR}.EL.STRONG.GPU_P_R_ARURI64_R on sm120 / sm103a / sm100a, canonical 582dfd8): sm120 keys 16096 -> 16098, variants 26658 -> 26660, loader 16118; sm103a / sm100a keys 14902 -> 14904, variants 22340 -> 22342 // RIDE476 (F2-iter299, canonical c88778e): +11 -> 14879 // RIDE475R3 (F2-iter289): +3/+3/+2/+2 (NA/EU restore + alias + 121a R3b anomalie) -> 14868/14868/16005/23825; cf 1169/1169/1166/1183 // RIDE475 (F2-iter288 BUG-475, canonical PENDING-475): +1146 graft x4 nogi (dARI modsub lattice E*L2.256 frame b76=1: klon 6 donorow *_dARI EFL2.256/noga, fields/vm PARITY) + rekanon 462-mgs ENL2 [489-absorb: DELETE 13/13/7 mgs + 2 anomalie 121a; REPLACE 9 heritage _src462] -> raw 14865/14865/16003/23823; loader 121a 23821 (offset -2 _errata stoi); cf 1166/1166/1164/1181 // was: 13721usize // RIDE474 (F2-iter285 BUG-474, canonical PENDING-474): +3454/+3454/+3454/+3455 twins _ARURI U32 (b75=0 sib calej rodziny plain ARURI64 464/465/468) // was: 10267 ride F2-iter280 BUG-468: +2320 keys (LTC-sel [74:73] lattice closure plain ARURI64 + NA LTC128B/256B; canonical 08a6145),
        ("sm103a", 14926usize), // 2026-11-07 T-14 (canonical 3dde6e1: the sm103a MUFU packed-half lanes measured, MUFU_R_FI_FI new): sm103a forms 14925 -> 14926, variants 22439 -> 22445 // 2026-11-06 T-11 (canonical 3dde6e1): the IDP family measured whole (sm120 15953 -> 15964 forms, 26580 -> 26598 variants; sm103a / sm100a 14913 -> 14925, 22420 -> 22439; sm121a 23850 -> 23860, 26406 -> 26421) + the audit exceptions (FADD.SAT_R_R_R retired, DEPBAR claim_forbid) // 2026-11-06 T-10 (canonical 315bffa): BRA sm103a/sm100a 14912 -> 14913 forms, 22363 -> 22420 variants; sm120 BRX/BRXU/RET + the audit batches 16045 -> 15935 forms, 26646 -> 26562 variants // 2026-11-06 T-8 (LEA family rebuilt from measurement, tools/probes/re_sm120_lea.py: sm120 56 keys / 100 rows -> 24 keys / 36 rows, sm103a / sm100a 18 keys / 21 rows -> 24 / 36): sm120 16097 -> 16065 forms, 26663 -> 26599 variants; sm103a / sm100a 14906 -> 14912, 22348 -> 22363 // 2026-11-06 T-7 (coldface's B300-1/2/3/4 rows taken + the UTMALDG plain dims + the IADD3.X carry repair, provenance re-stamp, canonical 135068e): sm120 keys 16098 -> 16097 (-2 UTMALDG dotted era keys), variants 26660 -> 26663, loader 16117; sm103a / sm100a keys 14904 -> 14906 (+IADD.XOR, +LEA.HI.X), variants 22342 -> 22348 // 2026-11-06 T-7 (ATOMG .EL 64-bit-base rows ATOMG.E.{ADD,OR}.EL.STRONG.GPU_P_R_ARURI64_R on sm120 / sm103a / sm100a, canonical 582dfd8): sm120 keys 16096 -> 16098, variants 26658 -> 26660, loader 16118; sm103a / sm100a keys 14902 -> 14904, variants 22340 -> 22342 // RIDE476 (F2-iter299, canonical c88778e): +11 -> 14879 // RIDE475R3 (F2-iter289): +3/+3/+2/+2 (NA/EU restore + alias + 121a R3b anomalie) -> 14868/14868/16005/23825; cf 1169/1169/1166/1183 // RIDE475 (F2-iter288 BUG-475, canonical PENDING-475): +1146 graft x4 nogi (dARI modsub lattice E*L2.256 frame b76=1: klon 6 donorow *_dARI EFL2.256/noga, fields/vm PARITY) + rekanon 462-mgs ENL2 [489-absorb: DELETE 13/13/7 mgs + 2 anomalie 121a; REPLACE 9 heritage _src462] -> raw 14865/14865/16003/23823; loader 121a 23821 (offset -2 _errata stoi); cf 1166/1166/1164/1181 // was: 13721usize // RIDE474 (F2-iter285 BUG-474, canonical PENDING-474): +3454/+3454/+3454/+3455 twins _ARURI U32 (b75=0 sib calej rodziny plain ARURI64 464/465/468) // was: 10267 ride F2-iter280 BUG-468: +2320 keys (LTC-sel [74:73] lattice closure plain ARURI64 + NA LTC128B/256B; canonical 08a6145),
        ("sm120", 1231usize), // re-pinned 2026-11-07 (T-16: G run 5 batch 15 — the tensor-core long tail verified row by row — on the batches 12-14 base) // re-pinned 2026-11-07 (G batch 14: REDG uniform-indexed forms measured whole) // re-pinned 2026-11-07 (G batch 13: STG.256 measured whole) // re-pinned 2026-11-07 (G batch 12: LDG.256 ARURI measured whole) // re-pinned 2026-11-07 (G batch 11: LDG.256 ARURI64 measured whole) // re-pinned 2026-11-07 (G batch 10: LDG.256 dARI measured whole) // G batch 9 FSET / FSEL / FCHK 2026-11-07 // G batch 8 conversions 2026-11-07 // G batch 7 uniform FP32 ALU 2026-11-07 // G batch 6 FP32 ALU 2026-11-07 // 2026-11-06 G (canonical 3dde6e1): UFSETP measured, 6 junk keys retired as aliases: sm120 15840 -> 15834 forms, 26442 -> 26341 variants // 2026-11-06 G (canonical 3dde6e1): PLOP3 / P2R / R2P measured, 10 junk keys retired as aliases, R2P_II_R added: sm120 15849 -> 15840 forms, 26451 -> 26442 variants // 2026-11-06 G (canonical 3dde6e1): FSETP / DSETP measured, 112 keys retired (11 aliases): sm120 15961 -> 15849 forms, 26662 -> 26451 variants // 2026-11-06 G (canonical 3dde6e1): HSETP2 measured, 3 dotted keys retired: sm120 15964 -> 15961 forms, 26598 -> 26595 variants // 2026-11-06 T-11 (canonical 3dde6e1): the IDP family measured whole (sm120 15953 -> 15964 forms, 26580 -> 26598 variants; sm103a / sm100a 14913 -> 14925, 22420 -> 22439; sm121a 23850 -> 23860, 26406 -> 26421) + the audit exceptions (FADD.SAT_R_R_R retired, DEPBAR claim_forbid) // 2026-11-06 T-10 IMMA family (canonical c258f8a): sm120 15935 -> 15953 forms, 26562 -> 26580 variants // 2026-11-06 T-10 (canonical 315bffa): BRA sm103a/sm100a 14912 -> 14913 forms, 22363 -> 22420 variants; sm120 BRX/BRXU/RET + the audit batches 16045 -> 15935 forms, 26646 -> 26562 variants // 2026-11-06 T-9 (BRA family rebuilt from measurement, tools/probes/re_sm120_bra.py: sm120 15 keys / 31 rows -> 6 keys / 66 rows, canonical b75cc20): sm120 keys 16054 -> 16045, variants 26611 -> 26646, loader 16074 -> 16068 (+3 key aliases) // 2026-11-06 T-8 ATOMS_R_ARURI_R rebuilt (36 groups) + 9 junk keys retired (canonical 5222c58): sm120 keys 16063 -> 16054, variants 26596 -> 26612 // 2026-11-06 T-8 F2FP twins retired (canonical 09a7141): sm120 keys 16065 -> 16063, variants 26599 -> 26596, claim_forbid rows 7016 -> 7013 // 2026-11-06 T-8 (LEA family rebuilt from measurement, tools/probes/re_sm120_lea.py: sm120 56 keys / 100 rows -> 24 keys / 36 rows, sm103a / sm100a 18 keys / 21 rows -> 24 / 36): sm120 16097 -> 16065 forms, 26663 -> 26599 variants; sm103a / sm100a 14906 -> 14912, 22348 -> 22363 // 2026-11-06 T-7 (coldface's B300-1/2/3/4 rows taken + the UTMALDG plain dims + the IADD3.X carry repair, provenance re-stamp, canonical 135068e): sm120 keys 16098 -> 16097 (-2 UTMALDG dotted era keys), variants 26660 -> 26663, loader 16117; sm103a / sm100a keys 14904 -> 14906 (+IADD.XOR, +LEA.HI.X), variants 22342 -> 22348 // 2026-11-06 T-7 (ATOMG .EL 64-bit-base rows ATOMG.E.{ADD,OR}.EL.STRONG.GPU_P_R_ARURI64_R on sm120 / sm103a / sm100a, canonical 582dfd8): sm120 keys 16096 -> 16098, variants 26658 -> 26660, loader 16118; sm103a / sm100a keys 14902 -> 14904, variants 22340 -> 22342 // 2026-11-06 T-7 (HADD2 register form rebuilt from measurement, canonical ac04a77): sm120 keys 16103 -> 16096 (-7: HADD2.F32_R_R_R, HADD2.BF16_V2_R_R_R and 5 register-opcode junk rows), variants 26656 -> 26658 (12 measured groups replace 3 + the 7 keys' 11 groups); loader sm120 16116 // 2026-11-05 T-6 item 2 (T-5's SHF + LDTM/STTM rows on the wave-11 tables, canonical 377b507): sm120 keys 16143 -> 16103 (-40 dotted SHF), variants 26612 -> 26656; sm100a/sm103a variants 22199 -> 22340; loader sm120 16123 // 2026-11-04 (canonical T-3 batches b063d43/15caf70/6f11f6b): -20 era keys (now _meta.key_aliases), +1 LDL_R_ARURI = 16107 forms; variants 20883 -> 20894 (LDL +14, MUFU_R_UR 4 -> 26, IMAD -7 alias groups +4 U32 twins, F2F_R_R F32,F64 removed); sm121a -10 era keys = 23823 raw / 23821 loader-visible, variants 26380. // 2026-11-03 dynamic-audit batch 1 (canonical 6619782): -12 sm120 keys (rows whose words are other instructions for nvdisasm) = 16126 // 2026-11-02 HMUL2 imm / LDSM FP4-FP6 / PRMT UR / ARRIVES.LDGSTSBAR / UTMASTG dims (canonical 77a3dfa): +3 sm120 keys (HMUL2_R_R_FI_FI, PRMT_R_R_UR_R, ARRIVES_ARURI; +30 LDSM_R_ARI and +4 UTMASTG groups, variants 20850 -> 20905) = 16138. // 2026-10-29 UBLKPF_AURI_UR + UBLKPF_AURI_UR_II (canonical 137cd34): +2 sm120 keys (ATOMS ARURI row replaced in place, STSM 8,MT168 groups join STSM_ARI_R; variants 20845 -> 20850) = 16135. // 2026-10-28 F2FP.BF16.E8.UNPACK_B_R_R (canonical f1e02b3): +1 sm120 key (UE8M0 -> BF16x2 unpack, variants 20844 -> 20845) = 16133. // 2026-10-23 CS2UR (canonical 59561b2): -1 sm120 key (junk CS2UR_UR_II immediate row removed; CS2UR_UR_L gains the plain group, variants unchanged 20837) = 16132 // RIDE459a (F2-iter301, canonical 96372cb): -1 sm120 key (459a junk-mg "" / 64 DELETE -> key-del UR_II_..._UP_UP) -> forms 16015, variants -4=17631; sm121a variants -4=26385; cf stoi // RIDE476 (F2-iter299, canonical c88778e): +11 -> 16016 // RIDE475R3 (F2-iter289): +3/+3/+2/+2 (NA/EU restore + alias + 121a R3b anomalie) -> 14868/14868/16005/23825; cf 1169/1169/1166/1183 // RIDE475 (F2-iter288 BUG-475, canonical PENDING-475): +1146 graft x4 nogi (dARI modsub lattice E*L2.256 frame b76=1: klon 6 donorow *_dARI EFL2.256/noga, fields/vm PARITY) + rekanon 462-mgs ENL2 [489-absorb: DELETE 13/13/7 mgs + 2 anomalie 121a; REPLACE 9 heritage _src462] -> raw 14865/14865/16003/23823; loader 121a 23821 (offset -2 _errata stoi); cf 1166/1166/1164/1181 // was: 14859usize // RIDE474 (F2-iter285 BUG-474, canonical PENDING-474): +3454/+3454/+3454/+3455 twins _ARURI U32 (b75=0 sib calej rodziny plain ARURI64 464/465/468) // was: 11405 ride F2-iter280 BUG-468: +2320 keys (LTC-sel [74:73] lattice closure plain ARURI64 + NA LTC128B/256B; canonical 08a6145),
        ("sm121a", 23860usize), // 2026-11-06 T-11 (canonical 3dde6e1): the IDP family measured whole (sm120 15953 -> 15964 forms, 26580 -> 26598 variants; sm103a / sm100a 14913 -> 14925, 22420 -> 22439; sm121a 23850 -> 23860, 26406 -> 26421) + the audit exceptions (FADD.SAT_R_R_R retired, DEPBAR claim_forbid) // 2026-11-04 (canonical T-3 batches b063d43/15caf70/6f11f6b): -20 era keys (now _meta.key_aliases), +1 LDL_R_ARURI = 16107 forms; variants 20883 -> 20894 (LDL +14, MUFU_R_UR 4 -> 26, IMAD -7 alias groups +4 U32 twins, F2F_R_R F32,F64 removed); sm121a -10 era keys = 23823 raw / 23821 loader-visible, variants 26380. // RIDE476 (F2-iter299, canonical c88778e): +8 -> raw 23833 // RIDE475R3 (F2-iter289): +3/+3/+2/+2 (NA/EU restore + alias + 121a R3b anomalie) -> 14868/14868/16005/23825; cf 1169/1169/1166/1183 // RIDE475 (F2-iter288 BUG-475, canonical PENDING-475): +1146 graft x4 nogi (dARI modsub lattice E*L2.256 frame b76=1: klon 6 donorow *_dARI EFL2.256/noga, fields/vm PARITY) + rekanon 462-mgs ENL2 [489-absorb: DELETE 13/13/7 mgs + 2 anomalie 121a; REPLACE 9 heritage _src462] -> raw 14865/14865/16003/23823; loader 121a 23821 (offset -2 _errata stoi); cf 1166/1166/1164/1181 // was: 22688usize // RIDE474 (F2-iter285 BUG-474, canonical PENDING-474): +3454/+3454/+3454/+3455 twins _ARURI U32 (b75=0 sib calej rodziny plain ARURI64 464/465/468) // was: 19233 ride F2-iter282 BUG-469: +6 sm121a keys (widthless ARURI graft: 2x ELL2.256 R_R_ARURI donor-103a verbatim-era0 + mg R/R_P/P_R/P_R_P plain-band + 4x EF-band P_R_ARURI_P; canonical bd48e63),  // ride F2-iter280 BUG-468: +2320 keys (LTC-sel [74:73] lattice closure plain ARURI64 + NA LTC128B/256B; canonical 08a6145),
    ] {
        let raw: serde_json::Value =
            serde_json::from_str(&cubit::table::read_table_text(format!("tables/{leg}.json")).unwrap())
                .unwrap();
        let got = raw["instructions"].as_object().unwrap().len();
        assert_eq!(got, want, "[{leg}] key census post-467");
    }
    let src: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string("tables/SOURCE.json").unwrap()).unwrap();
    assert_eq!(
        src["base_revision"].as_str().unwrap(),
        CURRENT_VENDORED_CANON,
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
            serde_json::from_str(&cubit::table::read_table_text(format!("tables/{leg}.json")).unwrap())
                .unwrap();
        let i = raw["instructions"].as_object().unwrap();
        for k in keys {
            assert!(!i.contains_key(*k), "[{leg}] deleted key resurrected: {k}");
        }
    }
}

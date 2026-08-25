//! BUG-067 (F2Q-055-kand -> FIXED, F2-iter17): wiersz-fantom
//! `VOTEU_UP_P::ANY` w tables/sm120.json (count=10, provenance: harvest-era
//! zanieczyszczenie slowami UMOV) cieniowal dekoder przestrzeni UMOV.imm==0:
//! zlote slowa `UMOV URn, 0x0` (nvcc korpus 738 cubinow sm_103 + 12 uniq
//! slotow rt98_pub) dekodowaly sie jako `VOTEU.ANY UP0, P0 !rsd[...]`
//! (semantyczne smieci do RE/renderu; roundtrip bajtowy ratowal rsd).
//! Prawda vendor (nvdisasm 13.3): opcode UMOV = [11:0]==0x882, VOTEU = 0x886;
//! the ANY phantom had fields/mask too wide (incl. reg 8b) and matched
//! words with [63:32]==0.
//! TRUE-MODEL 2-token (cuobjdump/cuobjmap gold corpus cusparse/cutlass):
//! mode ANY = bit72=1, ALL = bit72=0 (like the VOTE P form, BUG-054); dest UP
//! 3b@[83:81], src P @[89:87] (guard  as everywhere); the 3-token UR form
//! `VOTEU.ANY URx, UPT, PT` = a separate signature (hi payload 0x038e0100).
//! Fix: remove ONLY the structural phantom `VOTEU_UP_P::ANY`
//! (61 lines); the plain `VOTEU.ANY_UP_P` row (count=32) STAYS — it is
//! supported by thousands of golden corpus words (libcusparse/cutlass/cusolver);
//! sm103a.json was clean from the start (the row mask does not cover [23:16]).
//! Evidence: the internal fix archive (words_882_886.json, census_067_delta.json).
use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::table::IsaTable;

fn t120() -> IsaTable {
    IsaTable::load(std::path::Path::new("tables/sm120.json")).unwrap()
}
const SCHED: u128 = 0x1_FFFFu128 << 105;
fn enc_clean(t: &IsaTable, s: &str) -> Result<u128, String> {
    let insn = cubit::parse_cuasm_line(s, 0).map_err(|e| format!("parse {s:?}: {e}"))?;
    encode_instruction(&insn, t)
        .map(|w| w & !SCHED)
        .map_err(|e| format!("encode {s:?}: {e}"))
}
fn dec(t: &IsaTable, word: u128) -> String {
    let idx = DecodeIndex::build(t);
    format!("{}", idx.decode(word, 0, t).expect("decode"))
        .trim_end_matches([' ', ';']).trim().to_string()
}
fn w(hi: u64, lo: u64) -> u128 { ((hi as u128) << 64) | lo as u128 }

/// nvcc korpus sm_103 (738 cubinow, i95-lineage) + rt98_pub: (hi<96, lo, vendor tekst).
const GOLD: [(u64, u64, &str); 11] = [
    // prawdziwe VOTEU (5 uniq)
    (0x00000000, 0x0000000000ff7886, "VOTEU.ALL UP0, P0"),
    (0x038e0100, 0x0000000000047886, "VOTEU.ANY UR4, UPT, PT"),
    (0x038e0100, 0x0000000000057886, "VOTEU.ANY UR5, UPT, PT"),
    (0x038e0100, 0x0000000000067886, "VOTEU.ANY UR6, UPT, PT"),
    (0x038e0100, 0x0000000000087886, "VOTEU.ANY UR8, UPT, PT"),
    // UMOV imm=0 from the corpus (4 uniq)
    (0x00000000, 0x0000000000077882, "UMOV UR7, 0x0"),
    (0x00000000, 0x0000000000097882, "UMOV UR9, 0x0"),
    (0x00000000, 0x00000000000a7882, "UMOV UR10, 0x0"),
    (0x00000000, 0x0000000000107882, "UMOV UR16, 0x0"),
    // UMOV imm!=0 (control: not shadowed)
    (0x00000000, 0x0000000100047882, "UMOV UR4, 0x1"),
    (0x00000000, 0x0000000800067882, "UMOV UR6, 0x8"),
];
/// 2-token VOTEU from the cusparse/cutlass corpus (cuobjdump gold): ANY=bit72.
/// hi = payload&0xFFFFFFFF (bity 64-95), lo = bity 0-63.
const GOLD_UP2: [(u64, u64, &str); 7] = [
    (0x01000100, 0x0000000000ff7886, "VOTEU.ANY UP0, P2"),   // libcusparse.311
    (0x00020100, 0x0000000000ff7886, "VOTEU.ANY UP1, P0"),
    (0x01820100, 0x0000000000ff7886, "VOTEU.ANY UP1, P3"),   // libcusparse.183
    (0x00840100, 0x0000000000ff8886, "@!P0 VOTEU.ANY UP2, P1"), // cutlass 70_fp8
    (0x01000000, 0x0000000000ff7886, "VOTEU.ALL UP0, P2"),   // libcusparse.183
    (0x00000000, 0x0000000000ff7886, "VOTEU.ALL UP0, P0"),
    (0x00000100, 0x0000000000ff7886, "VOTEU.ANY UP0, P0"),   // libcusparse.311
];

/// rt98_pub sloty cieniowane (12 uniq slow; vendor nvdisasm: UMOV URn, 0x0).
const RT98_SHADOW: [(u64, u64, &str); 4] = [
    (0x00000000, 0x00000000003f7882, "UMOV UR63, 0x0"),
    (0x00000000, 0x0000000000167882, "UMOV UR22, 0x0"),
    (0x00000000, 0x00000000001f7882, "UMOV UR31, 0x0"),
    (0x00000000, 0x0000000000137882, "UMOV UR19, 0x0"),
];

#[test]
fn bug067_decode_goldens_eq_vendor_after_shadow_removal() {
    let t = t120();
    for (hi, lo, sass) in GOLD.iter().chain(RT98_SHADOW.iter()) {
        assert_eq!(dec(&t, w(*hi, *lo)), *sass, "decode hi={hi:#x} lo={lo:#x}");
    }
}

#[test]
fn bug067_encode_real_forms_payload_exact() {
    let t = t120();
    for (hi, lo, sass) in GOLD.iter().take(6).chain(GOLD_UP2.iter()) {
        let got = enc_clean(&t, &format!("{sass} ;")).expect("encode real form");
        assert_eq!(got, w(*hi, *lo) & !SCHED, "encode {sass}");
    }
}

#[test]
fn bug067_decode_up2token_goldens_eq_vendor() {
    let t = t120();
    for (hi, lo, sass) in GOLD_UP2.iter() {
        assert_eq!(dec(&t, w(*hi, *lo)), *sass, "decode {sass}");
    }
}

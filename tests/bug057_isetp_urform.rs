//! BUG-057 (F2Q follow-up 049, F2-iter11): wiersze rodziny ISETP P_P_R_UR_P
//! (forma R+UR) mialy okna operandow obciete do fitu korpusu / wypieczone bity
//! operandowe (klasa narrow-fit BUG-049, "itp." = OR/LE/LT/NE/S64+):
//!  * przyklady (identyczne w repo sm120.json i legacy tb_i82p2):
//!    LE.U32.AND: ureg 5b@32 (prawda 8b); NE.U32.AND: BRAK pola tok3
//!    (R operand znikal z renderu/match w oknie); LT.U32.AND: ureg 2b@32
//!    + wypieck b36; GT.U32.OR: dest-pred 1b@81 (P>=2 zawalalo match).
//! Prawda (sondy per-bit nvdisasm 13.3 na slocie rt98 + goldeny vendor
//! mm.sass z s6: GE.AND S32 0x004fda000bf06270|0x0000000500007c0c,
//! GE.U64 0x000fe4000bf16070|0x0000000414007c0c):
//!  * dest P 3b@81, src P 3b@84, R 8b@24, UR 8b@32, tok5 P 3b@87, inv@90
//!    niezaleznie od cmp/bool/type (F5..I2 sweep); cmp=3b@[78:76]
//!    (F=000,LT=001,EQ=010,T?=011,GT=100,NE=101,GE=110,LE=111),
//!    bool=[75:74], type=(80,73): S32=01/U32=00/S64=11/U64=10 (R+UR FORM).
//! Fix: 21 wierszy repo sm120.json + 24 wiersze tb_i82p2 -> tb_i82p3:
//! pola=TEMPLATE wyzej, vm |= okna, and_base: zero wylacznie pod oknami
//! (region mod [72:80] nietkniety - migracja semantyki .U32->era-drift
//! = odrebna decyzja, F2Q-058-kand). Frozen chain rt98: v3 == v2 tekstowo
//! (md5 3f9be6e4), final cubin == 3d15ab6a bajtowo (GATE byte-exact).
//! Wartość fixa: sciezka IR/decode (barracuda lift, liveness, sched) nie
//! widzi juz ucinanych operandow; encode+detail-decode produkuja slowa
//! bajtowo zgodne z nvdisasm dla UR>=32 / P>=2 (ponizej piny 2-stronne).
use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::table::IsaTable;

fn t120() -> IsaTable {
    IsaTable::load(std::path::Path::new("tables/sm120.json")).unwrap()
}
const SCHED: u128 = 0x1_FFFFu128 << 105;
fn enc_clean(t: &IsaTable, s: &str) -> u128 {
    let insn = cubit::parse_cuasm_line(s, 0).unwrap_or_else(|e| panic!("parse {s:?}: {e}"));
    encode_instruction(&insn, t).unwrap_or_else(|e| panic!("encode {s:?}: {e}")) & !SCHED
}
fn dec(t: &IsaTable, word: u128) -> String {
    let idx = DecodeIndex::build(t);
    let r = format!("{}", idx.decode(word, 0, t).expect("decode"));
    assert!(!r.contains("__raw__"), "raw-hole for {word:032x}");
    r.trim_end_matches([' ', ';']).trim().to_string()
}

/// Goldeny nvdisasm-verified: (slowo po masce sched, tekst).
/// 4 pozytywne: enc na hoscie + nvdisasm -c render (wysokie UR/P).
/// 2 vendor z s6/iter62/mm.sass (nvdisasm render + hex w pliku).
const BOTH: [(u128, &str); 6] = [
    (0x0000_0000_0bf6_4470_0000_0037_2800_7c0c, "ISETP.GT.U32.OR P3, PT, R40, UR55, PT"),
    (0x0000_0000_0b74_1070_0000_000f_0a00_7c0c, "ISETP.LT.U32.AND P2, PT, R10, UR15, P6"),
    (0x0000_0000_0bfa_5070_0000_002c_1700_7c0c, "ISETP.NE.U32.AND P5, PT, R23, UR44, PT"),
    (0x0000_0000_0bf2_3270_0000_0037_ff00_7c0c, "ISETP.LE.AND P1, PT, RZ, UR55, PT"),
    (0x0000_0000_0bf0_6270_0000_0005_0000_7c0c, "ISETP.GE.AND P0, PT, R0, UR5, PT"),
    (0x0000_0000_0bf1_6070_0000_0004_1400_7c0c, "ISETP.GE.U64.AND P0, PT, R20, UR4, PT"),
];

#[test]
fn bug057_encode_goldens_byte_exact() {
    let t = t120();
    for (word, sass) in BOTH {
        let want = word & !SCHED;
        let want = want & !0xFFFF_FFFF_0000_0000_0000_0000_0000_0000 | (word & 0xFFFF_FFFF_0000_0000_0000_0000_0000_0000);
        assert_eq!(enc_clean(&t, &format!("{sass} ;")), want, "encode {sass:?}");
    }
}

#[test]
fn bug057_decode_goldens_text_truth() {
    let t = t120();
    for (word, sass) in BOTH {
        assert_eq!(dec(&t, word), sass, "decode {sass:?}");
    }
}

/// Korpus rt98 (sm120-silicon era): decode dokladny bez rsd dla wczesniej
/// okaleczonych wierszy (slot lt/le/ne/ge) - fix konsumuje pelne okna.
const CORPUS_RT: [(u128, &str); 9] = [
    (0x0000_0000_0bf0_6270_0000_0003_0b00_7c0c, "ISETP.GE.AND P0, PT, R11, UR3, PT"),
    (0x0000_0000_0bfa_5270_0000_000f_1700_7c0c, "ISETP.NE.AND P5, PT, R23, UR15, PT"),
    (0x0000_0000_0f78_5270_0000_000f_1700_7c0c, "ISETP.NE.AND P4, PT, R23, UR15, !P6"),
    (0x0000_0000_0b76_5270_0000_000f_1700_7c0c, "ISETP.NE.AND P3, PT, R23, UR15, P6"),
    (0x0000_0000_0bfa_3270_0000_000f_ff00_7c0c, "ISETP.LE.AND P5, PT, RZ, UR15, PT"),
    (0x0000_0000_0f78_3270_0000_000f_ff00_7c0c, "ISETP.LE.AND P4, PT, RZ, UR15, !P6"),
    (0x0000_0000_0b76_3270_0000_000f_ff00_7c0c, "ISETP.LE.AND P3, PT, RZ, UR15, P6"),
    (0x0000_0000_0bf4_1270_0000_000f_ff00_7c0c, "ISETP.LT.AND P2, PT, RZ, UR15, PT"),
    (0x0000_0000_0bf2_3270_0000_0037_ff00_7c0c, "ISETP.LE.AND P1, PT, RZ, UR55, PT"),
];

#[test]
fn bug057_decode_rt98_corpus_no_rsd() {
    let t = t120();
    let idx = DecodeIndex::build(&t);
    for (word, sass) in CORPUS_RT {
        let r = format!("{}", idx.decode(word, 0, &t).expect("decode"));
        let r = r.trim_end_matches([' ', ';']).trim();
        assert!( !r.contains("!rsd"), "rsd residue for {sass:?}: {r}");
        assert_eq!(r, sass, "decode {sass:?}");
    }
}

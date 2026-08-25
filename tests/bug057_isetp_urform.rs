//! BUG-057 (F2Q follow-up 049, F2-iter11): rows of the ISETP P_P_R_UR_P family
//! (R+UR form) had operand windows clipped to the corpus fit / baked
//! operand bits (the BUG-049 narrow-fit class, "etc." = OR/LE/LT/NE/S64+):
//!  * examples (identical in repo sm120.json and legacy tb_i82p2):
//!    LE.U32.AND: ureg 5b (truth 8b); NE.U32.AND: NO tok3 field
//!    (the R operand vanished from the render/match within the window); LT.U32.AND: ureg 2b
//!    + baked b36; GT.U32.OR: dest-pred 1b (P>=2 broke the match).
//! Truth (nvdisasm 13.3 per-bit probes on the rt98 slot + vendor goldens
//! mm.sass from s6: GE.AND S32 0x004fda000bf06270|0x0000000500007c0c,
//! GE.U64 0x000fe4000bf16070|0x0000000414007c0c):
//!  * dest P 3b, src P 3b, R 8b, UR 8b, tok5 P 3b, inv
//!    regardless of cmp/bool/type (F5..I2 sweep); cmp=3b@[78:76]
//!    (F=000,LT=001,EQ=010,T?=011,GT=100,NE=101,GE=110,LE=111),
//!    bool=[75:74], type=(80,73): S32=01/U32=00/S64=11/U64=10 (R+UR FORM).
//! Fix: 21 rows in repo sm120.json + 24 rows in tb_i82p2 -> tb_i82p3:
//! fields=TEMPLATE above, vm |= windows, and_base: zero only under windows
//! (the mod region [72:80] untouched - the .U32->era-drift semantics migration
//! is a separate decision, F2Q-058-kand). Frozen chain rt98: v3 == v2 textually
//! (md5 3f9be6e4), final cubin == 3d15ab6a byte-wise (GATE byte-exact).
//! Value of the fix: the IR/decode path (barracuda lift, liveness, sched) no
//! longer sees truncated operands; encode+detail-decode produce words
//! byte-consistent with nvdisasm for UR>=32 / P>=2 (two-sided pins below).
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

/// nvdisasm-verified goldens: (word after the sched mask, text).
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

/// The rt98 corpus (sm120-silicon era): exact decode without rsd for the previously
/// crippled rows (lt/le/ne/ge slots) - the fix consumes full windows.
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

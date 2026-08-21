//! BUG-054 (rejestr sm120: 054_vote_any_all_alias.md, F2-iter10):
//! dwustronny alias VOTE.ANY <-> VOTE.ALL na formie P-dest:
//!  * encode: `VOTE.ANY Pd, Ps` kodowal slowo z bitem trybu 72=0 -> krzem
//!    wykonywal ALL (cicha zmiana semantyki votingu; `syncwarp`-legal bug
//!    klasy wrong-code), oba teksty dawaly identyczne slowo;
//!  * decode: slowa ALL renderowalo jako `VOTE.ANY` (tie-break na wierszach
//!    bez pola trybu); slowo ANY.P parzalo sie nawet z wierszem VOTEU.
//! Prawda (nvcc 13.3 -arch=sm_120 goldeny na tym hoscie, vote.cu/v.ptx):
//!  * formy P-dest: ALL/ANY rozni bit 72 (ALL=0, ANY=1); w pozostalych
//!    bitach operandow identyczne (dest P @[83:81], src P @[89:87],
//!    src-neg @90)! Wszystkie 6 goldenow ponizej pochodzi z nvcc/ptxas.
//! Fix (tabela): `VOTE.ANY_P_P` and_base |= 1<<72; oba wiersze P-dest maja
//! variable_mask z bitem 72 (deterministyczny rozdzial ALL/ANY, R-forma
//! (VOTE.ANY R0, PT, PT) byla juz zdrowa i to ona wystawila dowod bit-72).
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
    format!("{}", idx.decode(word, 0, t).expect("decode"))
        .trim_end_matches([' ', ';']).trim().to_string()
}

/// nvcc/ptxas gold (hi64, lo64, nvdisasm text) — ex `vote.cu`/`v.ptx` sm_120.
const G: [(&str, u64, u64, &str); 6] = [
    ("ALL P0,!P0", 0x000f_ca00_0400_0000, 0x0000_0000_00ff_7806, "VOTE.ALL P0, !P0"),
    ("ANY P0,!P0", 0x000f_ca00_0400_0100, 0x0000_0000_00ff_7806, "VOTE.ANY P0, !P0"),
    ("ALL P1,!P1", 0x000f_e200_0482_0000, 0x0000_0000_00ff_7806, "VOTE.ALL P1, !P1"),
    ("ANY P2,P2",  0x000f_c800_0104_0100, 0x0000_0000_00ff_7806, "VOTE.ANY P2, P2"),
    ("ALL P0,P0",  0x000f_e200_0000_0000, 0x0000_0000_00ff_7806, "VOTE.ALL P0, P0"),
    ("ANY R0",     0x000f_e200_038e_0100, 0x0000_0000_0000_7806, "VOTE.ANY R0, PT, PT"),
];

#[test]
fn bug054_encode_all_six_goldens_exact() {
    let t = t120();
    for (name, hi, lo, sass) in G {
        let gold = ((hi as u128) << 64) | lo as u128;
        assert_eq!(enc_clean(&t, &format!("{sass} ;")), gold & !SCHED, "encode {name}");
    }
}

#[test]
fn bug054_decode_words_render_mode_truth() {
    let t = t120();
    for (name, hi, lo, sass) in G {
        let gold = ((hi as u128) << 64) | lo as u128;
        assert_eq!(dec(&t, gold), sass, "decode {name}");
    }
}

#[test]
fn bug054_any_all_differ_exactly_at_bit72() {
    let t = t120();
    let a = enc_clean(&t, "VOTE.ALL P0, !P0 ;");
    let n = enc_clean(&t, "VOTE.ANY P0, !P0 ;");
    assert_eq!(a ^ n, 1u128 << 72, "ANY vs ALL = exactly bit 72");
}

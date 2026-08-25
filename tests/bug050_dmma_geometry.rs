//! BUG-050 (sm120 registry: 050_dmma8x8x4_geometry.md, SPARK q2 gx4, GB10
//! silicon 5/5 EXACT + execution): sm120.json carried the DMMA.8x8x4 family
//! with the geometry shifted by +1 bit (Rd/Ra/Rb instead of //),
//! without an Rc field in the hi word, plus `DMMA_R_R_R_R` phantoms (mangled mg '8x8x4')
//! and `DMMA.8x8x4_{,P_}R_R_R_R_UP` (decode ambiguity ", UP0").
//! Pre-fix effects: encoding with off-by-one fields, the Rc!=RZ form = ENC-FAIL,
//! decoding goldens rendered `DMMA.INVALID2 R8, -R2, R4, R0`.
//! Fix: geometry from the ptxas goldens (identical for -arch=sm_120 and sm_121a)
//! + phantom removal + a decoder-shadow co-fix: the `DFMA_R_R_FI_R` row
//! (and_base 0x803, 1-bit guard@12) cieniowal decode goldenow DMMA;
//! zastapiony wierszem z corpus-regression spark (1476 instancji).
use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
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
    let d = idx.decode(word, 0, t).expect("decode failed");
    format!("{d}").trim_end_matches([' ', ';']).trim_start().to_string()
}

/// 5 par golden ptxas (results/q2/dmma_goldens.jsonl na landing spark);
/// nvdisasm 13.3 SM120/SM121a renderuje je identycznie (sprawdzone lokalnie).
const GOLDENS: [(&str, u128); 5] = [
    ("DMMA.8x8x4 R8, R2, R4, RZ ;", 0x004e_1e00_0000_00ff_0000_0004_0208_723f),
    ("DMMA.8x8x4 R8, R2, R4, R8 ;", 0x004e_2400_0000_0008_0000_0004_0208_723f),
    ("@P0 DMMA.8x8x4 R8, R2, R4, RZ ;", 0x008e_1e00_0000_00ff_0000_0004_0208_023f),
    ("DMMA.8x8x4 R12, R16, R6, R8 ;", 0x001e_1e00_0000_0008_0000_0006_100c_723f),
    ("DMMA.8x8x4 R4, R12, R16, R4 ;", 0x000e_5e00_0000_0004_0000_0010_0c04_723f),
];

#[test]
fn bug050_encode_5_goldens_exact() {
    let t = t120();
    for (sass, gold) in GOLDENS {
        assert_eq!(enc_clean(&t, sass), gold & !SCHED, "encode {sass}");
    }
}

#[test]
fn bug050_decode_goldens_render_truth() {
    let t = t120();
    for (sass, gold) in GOLDENS {
        let want = sass.trim_end_matches(';').trim().to_string();
        assert_eq!(dec(&t, gold), want, "decode golden {sass} — DMMA.8x8x4 must win, not DFMA/*INVALID*");
    }
}

#[test]
fn bug050_rc_field_lives_in_hi_word() {
    let t = t120();
    // Rc=RZ vs Rc=R8: jedyna roznica to bity [71:64] (hi-word), lo64 identyczne.
    let rz = enc_clean(&t, GOLDENS[0].0);
    let r8 = enc_clean(&t, GOLDENS[1].0);
    assert_eq!(rz as u64, r8 as u64, "lo64 does not depend on Rc");
    assert_eq!(((rz >> 64) as u64) & 0xFF, 0xFF);
    assert_eq!(((r8 >> 64) as u64) & 0xFF, 0x08);
}

#[test]
fn bug050_phantoms_gone() {
    let t = t120();
    // bare `DMMA` (without the 8x8x4 mod group) previously matched the glitched
    // DMMA_R_R_R_R row; now an honest ENCFAIL.
    let insn = parse_sass("DMMA R8, R2, R4, RZ ;", 0).unwrap();
    let e = encode_instruction(&insn, &t).unwrap_err().to_string();
    assert!(e.contains("no operand-compatible table entry"), "{e}");
}

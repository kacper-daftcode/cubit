//! BUG-052 (rejestr sm120: 052_qmma_f8f6f4_type_matrix.md, SPARK q2 gx4):
//! ptxas 13.0 emituje QMMA.16832.F32.A.B dla wszystkich 25 par A,B z
//! {e4m3,e5m2,e3m2,e2m3,e2m1} (mma.sync...kind::f8f6f4), a tabela sm120.json
//! miala tylko 9 par z {e2m3,e4m3,e5m2} => ENC-FAIL dla 16 legalnych par
//! (kodowanie nvcc -arch=sm_120 i -arch=sm_121a identyczne; krzem GB10:
//! fp8 i fp4 wykonuja sie, 25/25 EXACT lokalnie + nvdisasm crosscheck 25/25).
//! Fix: port 32 wpisow (16 nowych par x {plain, _P}) z tabeli spark.
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

/// 25 goldenow ptxas (results/q2/qmma_matrix25.json, landing spark; slowa
/// 128-bit, sched-bits maskowane przez !SCHED przy porownaniu).
const G: [(&str, u128); 25] = [
    ("QMMA.16832.F32.E4M3.E4M3 R4, R4, R8, R12 ;", 0x000fe20000002c0c000000080404727a),
    ("QMMA.16832.F32.E4M3.E5M2 R4, R4, R8, R12 ;", 0x000fe2000000ac0c000000080404727a),
    ("QMMA.16832.F32.E4M3.E3M2 R4, R4, R8, R12 ;", 0x000fe2000010ac0c000000080404727a),
    ("QMMA.16832.F32.E4M3.E2M3 R4, R4, R8, R12 ;", 0x000fe20000202c0c000000080404727a),
    ("QMMA.16832.F32.E4M3.E2M1 R4, R4, R8, R12 ;", 0x000fe2000020ac0c000000080404727a),
    ("QMMA.16832.F32.E5M2.E4M3 R4, R4, R8, R12 ;", 0x000fe20000006c0c000000080404727a),
    ("QMMA.16832.F32.E5M2.E5M2 R4, R4, R8, R12 ;", 0x000fe2000000ec0c000000080404727a),
    ("QMMA.16832.F32.E5M2.E3M2 R4, R4, R8, R12 ;", 0x000fe2000010ec0c000000080404727a),
    ("QMMA.16832.F32.E5M2.E2M3 R4, R4, R8, R12 ;", 0x000fe20000206c0c000000080404727a),
    ("QMMA.16832.F32.E5M2.E2M1 R4, R4, R8, R12 ;", 0x000fe2000020ec0c000000080404727a),
    ("QMMA.16832.F32.E3M2.E4M3 R4, R4, R8, R12 ;", 0x000fe20000046c0c000000080404727a),
    ("QMMA.16832.F32.E3M2.E5M2 R4, R4, R8, R12 ;", 0x000fe2000004ec0c000000080404727a),
    ("QMMA.16832.F32.E3M2.E3M2 R4, R4, R8, R12 ;", 0x000fe2000014ec0c000000080404727a),
    ("QMMA.16832.F32.E3M2.E2M3 R4, R4, R8, R12 ;", 0x000fe20000246c0c000000080404727a),
    ("QMMA.16832.F32.E3M2.E2M1 R4, R4, R8, R12 ;", 0x000fe2000024ec0c000000080404727a),
    ("QMMA.16832.F32.E2M3.E4M3 R4, R4, R8, R12 ;", 0x000fe20000082c0c000000080404727a),
    ("QMMA.16832.F32.E2M3.E5M2 R4, R4, R8, R12 ;", 0x000fe2000008ac0c000000080404727a),
    ("QMMA.16832.F32.E2M3.E3M2 R4, R4, R8, R12 ;", 0x000fe2000018ac0c000000080404727a),
    ("QMMA.16832.F32.E2M3.E2M3 R4, R4, R8, R12 ;", 0x000fe20000282c0c000000080404727a),
    ("QMMA.16832.F32.E2M3.E2M1 R4, R4, R8, R12 ;", 0x000fe2000028ac0c000000080404727a),
    ("QMMA.16832.F32.E2M1.E4M3 R4, R4, R8, R12 ;", 0x000fe20000086c0c000000080404727a),
    ("QMMA.16832.F32.E2M1.E5M2 R4, R4, R8, R12 ;", 0x000fe2000008ec0c000000080404727a),
    ("QMMA.16832.F32.E2M1.E3M2 R4, R4, R8, R12 ;", 0x000fe2000018ec0c000000080404727a),
    ("QMMA.16832.F32.E2M1.E2M3 R4, R4, R8, R12 ;", 0x000fe20000286c0c000000080404727a),
    ("QMMA.16832.F32.E2M1.E2M1 R4, R4, R8, R12 ;", 0x000fe2000028ec0c000000080404727a),
];

#[test]
fn bug052_encode_25_pairs_exact() {
    let t = t120();
    for (sass, gold) in G {
        assert_eq!(enc_clean(&t, sass), gold & !SCHED, "encode {sass}");
    }
}

#[test]
fn bug052_new_pairs_decode_roundtrip() {
    // Para E2M1.E2M1 (fp4) byla niekodowalna pre-fix; teraz word <-> text.
    let t = t120();
    let (sass, gold) = G[24];
    assert_eq!(sass.trim_end_matches(';').trim(), "QMMA.16832.F32.E2M1.E2M1 R4, R4, R8, R12");
    let idx = DecodeIndex::build(&t);
    let d = format!("{}", idx.decode(gold, 0, &t).expect("decode"));
    assert_eq!(d.trim_end_matches([' ', ';']).trim(), "QMMA.16832.F32.E2M1.E2M1 R4, R4, R8, R12");
    // re-encode znanego dekodowu == golden (maska sched)
    assert_eq!(enc_clean(&t, d.trim()), gold & !SCHED);
}

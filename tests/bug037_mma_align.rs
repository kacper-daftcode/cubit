//! BUG-037 (rejestr sm120: 037/ / iter46+iter47): enkoder akceptowal
//! niewyrownane operandy wielo-rejestrowe MMA, ktore na krzemiu daja
//! ILLEGAL_INSTRUCTION (`IMMA.16832.S8.S8 R8, R42, R44, R8` z A=R42:
//! asm OK bez WARN, run = FAIL 27 ILLEGAL; A=R40 dziala).
//! Fix: encoder-side legality check na KRZEMIEM ZMIERZONYCH (op, shape,
//! accum) kombinacjach (iter46/47 tabele):
//!   IMMA.16832.* (acc S32):  D%4 A%4 B%2 C%4
//!   QMMA.16832.F32.*:        D%4 A%4 B%2 C%4
//!   HMMA.16816.F32:          D%4 A%4 B%2 C%4
//!   HMMA.1688.F32:           D%4 A%4 Bany C%4 (B jedno-rejestrowe)
//! Reszta przestrzeni (SP/SF, F16-acc, IMMA/QMMA.16816, HMMA.1684, UTC*/DMMA)
//! NIE jest krzemiowo zmapowana i zachowuje dotychczasowe accept — arytmetyka
//! szerokosci z nazwy ksztaltu zostala sfalsyfikowana przez krzem
//! (HMMA.1688.F32 A jest quad-align mimo wezszej nominalnie macierzy).

use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::table::IsaTable;

fn t120() -> IsaTable {
    IsaTable::load(std::path::Path::new("tables/sm120.json")).unwrap()
}

const SCHED: u128 = 0xFFFF_FFFFu128 << 96;

fn enc(text: &str) -> Result<u128, String> {
    let insn = parse_sass(text, 0).unwrap_or_else(|e| panic!("parse {text:?}: {e}"));
    encode_instruction(&insn, &t120()).map_err(|e| format!("{e}"))
}

fn must_reject(text: &str) {
    let err = enc(text).expect_err(&format!("{text:?} must be refused"));
    assert!(
        err.contains("BUG-037"),
        "{text:?}: error must name BUG-037, got: {err}"
    );
}

#[test]
fn bug037_repro_misaligned_a_rejected() {
    // minimalny repro z karty buga (a_bad.sass): A-quad @R42, 42%4=2
    must_reject("IMMA.16832.S8.S8 R8, R42, R44, R8");
    // pozostale sloty: D quad, C quad
    must_reject("IMMA.16832.S8.S8 R9, R40, R44, R9");
    must_reject("IMMA.16832.S8.S8 R8, R40, R44, R9");
    // B-para na nieparzystym
    must_reject("IMMA.16832.S8.S8 R8, R40, R45, R8");
    must_reject("IMMA.16832.U8.U8 R8, R41, R44, R8");
    must_reject("IMMA.16832.S8.S8.SAT R6, R40, R44, R6");
}

#[test]
fn bug037_aligned_encodes_byte_exact_vs_silicon_ok_cubin() {
    // slowo wyciagniete z rejestrowego b_ok.cubin (krzem-OK; .text @0xa0)
    const B_OK_IMMA: u128 = 0x000ff60000405c080000002c28087237;
    let code = enc("IMMA.16832.S8.S8 R8, R40, R44, R8").expect("aligned form must encode");
    assert_eq!(code & !SCHED, B_OK_IMMA & !SCHED, "IMMA word changed");
    // B-para: obie parzyste bazy legalne
    enc("IMMA.16832.S8.S8 R8, R40, R46, R8").expect("B@R46 legal");
}

#[test]
fn bug037_qmma_hmma_measured_shapes() {
    // iter47: QMMA.16832.F32.E4M3 — A %4 (41,42,43 ILL), B %2 (45,47 ILL),
    // acc %4 (9,10,11,30,33 ILL)
    must_reject("QMMA.16832.F32.E4M3.E4M3 R8, R41, R44, R8");
    must_reject("QMMA.16832.F32.E4M3.E4M3 R8, R40, R45, R8");
    must_reject("QMMA.16832.F32.E4M3.E4M3 R9, R40, R44, R9");
    enc("QMMA.16832.F32.E4M3.E4M3 R8, R40, R44, R8").expect("aligned legal");
    // iter47: HMMA.16816.F32 — A %4 (41,42 ILL), B %2 (45 ILL), acc %4
    must_reject("HMMA.16816.F32 R8, R41, R44, R8");
    must_reject("HMMA.16816.F32 R8, R40, R45, R8");
    enc("HMMA.16816.F32 R8, R40, R44, R8").expect("aligned legal");
    // iter47: HMMA.1688.F32 — A %4 (41 ILL), acc %4 (9,10 ILL),
    // B DOWOLNE (B jedno-rejestrowe; 45 OK na krzemiu)
    must_reject("HMMA.1688.F32 R8, R41, R44, R8");
    must_reject("HMMA.1688.F32 R9, R40, R44, R9");
    enc("HMMA.1688.F32 R8, R40, R45, R8").expect("1688 odd B legal");
}

#[test]
fn bug037_unmeasured_space_stays_open() {
    // Scope-dokument: niekrzemiowo-zweryfikowane kombinacje NIE sa odrzucane
    // (encoding jak dotychczas) — zglaszanie twardego bledu wymaga pomiaru.
    enc("QMMA.16832.F16.E4M3.E4M3 R8, R42, R44, R8").expect("F16-acc out of scope");
    enc("IMMA.SP.16832.S8.S8 R8, R42, R44, R8, R12, 0x0, 0x0").expect("SP form out of scope");
}

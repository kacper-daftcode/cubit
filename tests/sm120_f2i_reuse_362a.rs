//! BUG-362a, the two-oracle record (2026-11-03): the 30 reuse-armed F2I TRUNC lattice words of
//! `tests/bug362_f2i_trunc_lattice_closure.rs::t362_4_reuse_window_fail_closed` measured on two
//! nvdisasm builds (13.1 locally, 13.3 on cold-face-bounces-fin-02 for SM120/SM100/SM103), fixture
//! `tests/fixtures/sm120_f2i_reuse_362a_nvdisasm.jsonl`. Both builds refuse every word
//! (`Opclass 'f2i_...', undefined value 0xNN for table 'TABLES_opex_0'`: the opex value is the
//! reuse/yield byte, no reuse value is defined for the F2I opclasses) and the plain word (reuse
//! bits cleared) prints normally. nvdisasm is a *text* oracle: it says the bytes have no text, not
//! that the silicon rejects them. cubit stays fail-closed (HOLE with the BUG-362 attribution) until
//! the silicon arm answers (T/gpu/kernels/f2i_reuse_362a_b{122,123,124}: a cubit-assembled kernel
//! that executes `F2I.U64.F64.TRUNC` with each reuse bit set; docs/KNOWN_ISSUES.md T7).
use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;
use std::{path::PathBuf, sync::OnceLock};

fn table_path() -> PathBuf {
    std::env::var_os("CUBIT_TABLE").map(PathBuf::from).unwrap_or_else(|| "tables/sm120.json".into())
}

fn table_and_index() -> &'static (IsaTable, DecodeIndex) {
    static TABLE: OnceLock<(IsaTable, DecodeIndex)> = OnceLock::new();
    TABLE.get_or_init(|| {
        let table = IsaTable::load(&table_path()).unwrap();
        let index = DecodeIndex::build(&table);
        (table, index)
    })
}

fn fixture() -> Vec<Value> {
    include_str!("fixtures/sm120_f2i_reuse_362a_nvdisasm.jsonl").lines()
        .map(|l| serde_json::from_str(l).unwrap()).collect()
}

#[test]
fn both_nvdisasm_builds_refuse_every_reuse_armed_word() {
    let rows = fixture();
    assert_eq!(rows.len(), 30, "the arb362 R-group + arb362b battery");
    for r in &rows {
        let word = r["word"].as_str().unwrap();
        let reuse = r["reuse_bits"].as_u64().unwrap();
        assert!(reuse != 0, "{word}: not reuse-armed");
        let v131 = &r["nvdisasm_13_1"];
        assert_eq!(v131["rc"].as_u64(), Some(1), "{word}: nvdisasm 13.1 accepted the word");
        assert!(v131["err"].as_str().unwrap().contains("TABLES_opex_0"), "{word}: unexpected 13.1 error");
        let v133 = &r["nvdisasm_13_3"];
        for arch in ["SM120", "SM100", "SM103"] {
            assert_eq!(v133["rc"][arch].as_u64(), Some(1), "{word}: nvdisasm 13.3 -b {arch} accepted the word");
        }
        assert!(v133["err"].as_str().unwrap().contains("TABLES_opex_0"), "{word}: unexpected 13.3 error");
        // the opex value nvdisasm names is the reuse/yield byte of the word
        let opex = u64::from_str_radix(
            v133["err"].as_str().unwrap().split("undefined value 0x").nth(1).unwrap().split(' ').next().unwrap(), 16).unwrap();
        let yield_bit = r["yield"].as_u64().unwrap();
        assert_eq!(opex, (reuse << 5) | (yield_bit << 4), "{word}: opex value is not the reuse/yield byte");
    }
}

#[test]
fn cubit_stays_fail_closed_until_the_silicon_arm_answers() {
    let (table, index) = table_and_index();
    for r in fixture() {
        let word = u128::from_str_radix(r["word"].as_str().unwrap(), 16).unwrap();
        let err = match index.decode(word, 0, table) {
            Ok(d) => panic!("{word:032x} decoded as {d}: the reuse window must stay a HOLE until silicon says yes"),
            Err(e) => e.to_string(),
        };
        assert!(err.contains("BUG-362"), "{word:032x}: {err}");
        assert!(r["silicon"].as_str().unwrap().starts_with("pending"), "{word:032x}: update this test with the silicon verdict");
    }
}

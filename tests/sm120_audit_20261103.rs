//! Dynamic-audit batch 1 (2026-11-03): the rows `tools/audit_dynamic.py` flagged and the fixes
//! that answer them, pinned on nvdisasm 13.1 words (`tests/fixtures/sm120_audit_20261103_nvdisasm.jsonl`,
//! one word per nvdisasm call; written by the audit, trimmed to the words that carry the evidence).
//!
//! - `ldgsts` (210 words, 70 LDGSTS rows): the shared-address base field was 9 bits wide and
//!   swallowed bit 24 - the low bit of the global base register - so `[R5+0x10]` printed as
//!   `[R261+0x10]`. Canonical sm120.json (blackwell-isa 2026-11-03) carries 8-bit fields.
//! - `aruri_u32_twin` (577 words, the LDG/STG `_ARURI` U32 rows with base RZ): the vendor text
//!   `[URm(+off)]` is shared with the `_ARURI64` twin and the assembler mints the .64 word for
//!   it (BUG-464); the display print follows the vendor, the lossless print spells the U32 twin
//!   `[RZ.U32+URm(+off)]` and re-encodes bit for bit.
//! - `bra_u_any` (19 words): the uniform branch prints `BRA.U.ANY`, not `BRA.ANY.U`.
//! - `deleted_row` (17 canonical words of the 22 rows removed): harvest rows whose probe words
//!   nvdisasm names as another instruction or rejects (FSETP -> P2R.B3, F2FP <-> HMMA, LOP3.LUT ->
//!   SEL, QMMA -> MOVM, the HMMA `_P0_` mnemonics) left the table; their words now decode to the
//!   vendor's text through the proper row or not at all (`cubit_now`). The 5 words not in the
//!   fixture still decode through the `F2FP.F16.F32.PACK_AB_P2` / `HMMA.SP.1688.F16` era rows with
//!   texts the vendor does not print - the era-key question in T/NEEDS_OWNER.md and
//!   docs/KNOWN_ISSUES.md T1.
//! The production census (1 811 600 words, 166 cubins) decodes identically before and after.
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

fn fixture(family: &str) -> Vec<Value> {
    include_str!("fixtures/sm120_audit_20261103_nvdisasm.jsonl").lines()
        .map(|l| serde_json::from_str::<Value>(l).unwrap())
        .filter(|r| r["family"] == family)
        .collect()
}

fn normalise(s: &str) -> String {
    s.replace(".reuse", "").split_whitespace().collect::<Vec<_>>().join(" ").trim_end_matches(';').trim().to_string()
}

fn reencode_lossless(table: &IsaTable, word: u128, text: &str) -> u128 {
    let control = cubit::scheduling::format_control_code(
        &cubit::scheduling::decode_sched_upper32((word >> 96) as u32));
    let source = format!("[{control}] {text} ;");
    cubit::roundtrip_audit::check_semantic_source(&source).unwrap();
    let parsed = cubit::parse_cuasm_line(&source, 0).unwrap();
    assert!(parsed.hand_sched && parsed.rsd.is_none(), "{source}");
    cubit::encoder::encode_instruction(&parsed, table).unwrap_or_else(|e| panic!("{source}: {e}"))
}

/// Display print = vendor text; lossless print re-encodes to the word.
fn check_family(family: &str, expect_rows: usize) {
    let (table, index) = table_and_index();
    let rows = fixture(family);
    assert_eq!(rows.len(), expect_rows, "{family}: fixture size");
    for r in &rows {
        let word = u128::from_str_radix(r["word"].as_str().unwrap(), 16).unwrap();
        let vendor = r["nvidia_sass"].as_str().unwrap();
        let decoded = index.decode(word, 0, table).unwrap_or_else(|e| panic!("{family} {word:032x}: {e}"));
        let display = cubit::printer::to_sass(&decoded);
        assert_eq!(normalise(&display), normalise(vendor), "{family} {word:032x}: display print");
        let lossless = cubit::printer::to_sass_lossless(&decoded);
        assert_eq!(reencode_lossless(table, word, &lossless), word, "{family} {word:032x}: lossless re-encode of {lossless}");
    }
}

#[test]
fn ldgsts_shared_base_is_eight_bits() {
    check_family("ldgsts", 210);
    let (table, _) = table_and_index();
    let _ = table; // the field shape itself is pinned in the canonical table (blackwell-isa-internal/tools/audit_fix_20261103.py)
}

#[test]
fn aruri_u32_twin_prints_like_the_vendor_and_re_encodes_losslessly() {
    check_family("aruri_u32_twin", 577);
    let (table, index) = table_and_index();
    for r in fixture("aruri_u32_twin") {
        let word = u128::from_str_radix(r["word"].as_str().unwrap(), 16).unwrap();
        let decoded = index.decode(word, 0, table).unwrap();
        let lossless = cubit::printer::to_sass_lossless(&decoded);
        // the NA family has no .64 twin (no width bit in its address frame): `[URm]` is unambiguous there
        if !r["key"].as_str().unwrap().contains(".NA.") {
            assert!(lossless.contains("[RZ.U32+UR"), "{word:032x}: the U32 twin must stay distinguishable: {lossless}");
        }
        assert_eq!((word >> 75) & 1, 0, "{word:032x}: not a U32 twin");
    }
}

#[test]
fn bra_u_any_order() {
    check_family("bra_u_any", 19);
}

#[test]
fn deleted_rows_never_claim_their_words_again() {
    let (table, index) = table_and_index();
    let rows = fixture("deleted_row");
    assert_eq!(rows.len(), 17);
    for r in &rows {
        let key = r["key"].as_str().unwrap();
        let group = r["group"].as_str().unwrap();
        assert!(
            table.entries.get(key).is_none_or(|e| !e.mod_groups.contains_key(group)),
            "{key} / {group} is back in the table"
        );
        let word = u128::from_str_radix(r["word"].as_str().unwrap(), 16).unwrap();
        match index.decode(word, 0, table) {
            Ok(d) => {
                assert_eq!(r["cubit_now"], "vendor_text", "{word:032x}: decoded as {}", d.key);
                let vendor = r["nvidia_sass"].as_str().unwrap();
                assert_eq!(normalise(&cubit::printer::to_sass(&d)), normalise(vendor), "{word:032x}");
            }
            Err(_) => assert_eq!(r["cubit_now"], "hole", "{word:032x}"),
        }
    }
}

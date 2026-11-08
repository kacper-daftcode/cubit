//! SM120 FENCE.VIEW.ASYNC.S / .G (the async-proxy fence, PTX fence.proxy.async[.shared::cta|.global]), measured with
//! nvdisasm 13.1 (tools/probes/re_sm120_fence_view_async.py, fixture tests/fixtures/sm120_fence_view_async_nvdisasm.jsonl):
//! bit 72 is the scope, the predicate guard [15:12] is live, bit 73 (the donor row's `.T`) is illegal on SM120, every
//! other bit of the word is text-inert and stays outside the rows. Every probed form word decodes to the `FENCE` key,
//! prints NVIDIA's text and reassembles all 128 bits; the lattice never renders as another text. The control law the
//! probe recorded -- a read barrier on the word makes it illegal, a write barrier is fine -- is checked against the
//! scheduler's own control code for the fence.
use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;
use std::{path::PathBuf, sync::OnceLock};

const SOURCE: &str = "fence-view-async-sm120-2026-11-08";
const KEY: &str = "FENCE";
const CTRL: u128 = 0x000f_e800u128 << 96; // nvcc 13.0's control code on the fence: stall 4, yield, wrtbar 7, readbar 7
/// nvcc 13.0 (`-arch=sm_120a`): `fence.proxy.async.global` and `fence.proxy.async.shared::cta`.
const NVCC_G: u128 = 0x000fe8000000010000000000000073c6;
const NVCC_S: u128 = 0x000fe8000000000000000000000073c6;

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
    include_str!("fixtures/sm120_fence_view_async_nvdisasm.jsonl").lines().map(|l| serde_json::from_str(l).unwrap()).collect()
}

fn reencode(table: &IsaTable, word: u128, text: &str) -> u128 {
    let control = cubit::scheduling::format_control_code(&cubit::scheduling::decode_sched_upper32((word >> 96) as u32));
    let source = format!("[{control}] {text} ;");
    cubit::roundtrip_audit::check_semantic_source(&source).unwrap();
    let parsed = cubit::parse_cuasm_line(&source, 0).unwrap();
    assert!(parsed.hand_sched && parsed.rsd.is_none(), "{source}");
    cubit::encoder::encode_instruction(&parsed, table).unwrap_or_else(|e| panic!("{source}: {e}"))
}

fn check(word: u128, vendor: &str) {
    let (table, index) = table_and_index();
    let decoded = index.decode(word, 0, table).unwrap_or_else(|e| panic!("{word:032x}: {e}"));
    assert_eq!(decoded.key.as_str(), KEY, "{word:032x}");
    let scope = if vendor.ends_with(".G") { "ASYNC,G,VIEW" } else { "ASYNC,S,VIEW" };
    assert_eq!(decoded.mod_group, scope, "{word:032x}");
    assert_eq!(cubit::printer::to_sass_lossless(&decoded), vendor, "{word:032x}");
    assert_eq!(reencode(table, word, vendor), word, "{vendor}");
}

#[test]
fn every_probed_word_matches_nvidia_and_reassembles_all_128_bits() {
    let mut n = 0;
    let mut groups = std::collections::BTreeSet::new();
    let (table, index) = table_and_index();
    for row in fixture() {
        if row.get("lattice").is_some() {
            continue;
        }
        let vendor = row["nvidia_sass"].as_str().unwrap();
        let word = u128::from_str_radix(row["word"].as_str().unwrap(), 16).unwrap() | CTRL;
        check(word, vendor);
        groups.insert(index.decode(word, 0, table).unwrap().mod_group.clone());
        n += 1;
    }
    assert_eq!(n, 32, "form words in the fixture: 2 scopes x 16 guards");
    assert_eq!(groups.len(), 2, "{groups:?}");
}

#[test]
fn nvcc_words_decode_and_both_scopes_assemble_without_a_read_barrier() {
    let (table, index) = table_and_index();
    for (word, vendor) in [(NVCC_G, "FENCE.VIEW.ASYNC.G"), (NVCC_S, "FENCE.VIEW.ASYNC.S")] {
        check(word, vendor);
    }
    // the scheduler's own control code: a write barrier at most, never a read barrier (the measured law)
    for text in ["FENCE.VIEW.ASYNC.G ;", "FENCE.VIEW.ASYNC.S ;", "@P0 FENCE.VIEW.ASYNC.G ;"] {
        let (bytes, count) = cubit::assemble(text, 0, table).unwrap_or_else(|e| panic!("{text}: {e}"));
        assert_eq!(count, 1);
        let word = u128::from_le_bytes(bytes[..16].try_into().unwrap());
        let cc = cubit::scheduling::decode_sched_upper32((word >> 96) as u32);
        assert_eq!(cc.read_bar, 7, "{text}: read barrier {} on a fence (illegal for nvdisasm)", cc.read_bar);
        let decoded = index.decode(word, 0, table).unwrap();
        assert_eq!(cubit::printer::to_sass_lossless(&decoded), text.trim_end_matches(" ;"));
        assert_eq!((word >> 72) & 1, text.contains(".G") as u128, "{text}: the scope bit");
    }
}

#[test]
fn the_measured_rows_carry_the_provenance_and_a_fail_closed_mask() {
    let raw: Value = serde_json::from_slice(&cubit::table::read_table_bytes(table_path()).unwrap()).unwrap();
    let entry = &raw["instructions"][KEY];
    let groups = entry["mod_groups"].as_object().unwrap();
    assert_eq!(groups.keys().cloned().collect::<Vec<_>>(), vec!["ASYNC,G,VIEW", "ASYNC,S,VIEW"], "the donor `.T` row is gone");
    let number = |v: &Value| u128::from_str_radix(v.as_str().unwrap().trim_start_matches("0x"), 16).unwrap();
    for (name, g) in groups {
        assert_eq!(g.get("_src").unwrap_or(&entry["_src"]), SOURCE, "{name}");
        let fields = g["fields"].as_array().unwrap();
        assert_eq!(fields.len(), 1, "{name}: the guard is the only field");
        assert_eq!((fields[0]["shift"].as_u64(), fields[0]["bits"].as_u64(), fields[0]["extraction"].as_str()), (Some(12), Some(4), Some("guard")), "{name}");
        let base = number(&g["and_base"]);
        assert_eq!(number(&g["variable_mask"]), 0xf000, "{name}");
        assert_eq!(base >> 105, 0, "{name}: no control bits baked into the template");
        assert_eq!(base & 0xf000, 0, "{name}");
        assert_eq!((base >> 72) & 1, name.contains(",G,") as u128, "{name}: the scope bit");
        assert_eq!(base & !(1 << 72), 0x3c6, "{name}");
        assert!(g["count"].is_null(), "{name}");
    }
    assert_eq!(raw["_meta"]["provenance"]["sources"][SOURCE]["rows"], 2);
}

#[test]
fn the_lattice_around_the_form_is_never_rendered_as_another_text() {
    let (table, index) = table_and_index();
    let (mut n, mut undecoded, mut control_word, mut control_law) = (0, 0, 0, 0);
    for row in fixture() {
        if row.get("lattice").is_none() {
            continue;
        }
        n += 1;
        let probed = u128::from_str_radix(row["word"].as_str().unwrap(), 16).unwrap();
        if let Some(control) = row.get("control") {
            let word = probed; // recorded with its own control code: the read barrier is the point
            // the control-law words: the instruction bits are the plain `.S` word, the control code names a read
            // barrier -- illegal for nvdisasm; cubit's decoder reads the instruction bits only, so the law is
            // enforced on the way out (the scheduler test above), not here
            assert!(row["nvidia_sass"].is_null(), "{word:032x}");
            let cc = cubit::scheduling::decode_sched_upper32((word >> 96) as u32);
            assert_eq!(control.as_str().unwrap(), format!("readbar {}", cc.read_bar), "{word:032x}");
            assert_ne!(cc.read_bar, 7, "{word:032x}");
            assert_eq!(word & ((1u128 << 105) - 1), 0x73c6, "{word:032x}");
            control_law += 1;
            continue;
        }
        let word = probed | CTRL;
        match (index.decode(word, 0, table), row["nvidia_sass"].as_str()) {
            (Err(_), _) => {
                assert_eq!(probed >> 96, 0, "{word:032x}: a control-word bit must not fail the decode");
                undecoded += 1;
            }
            (Ok(d), Some(vendor)) => {
                // bits 96-127 are the control word (scheduling, reuse): text-inert for nvdisasm and stripped by
                // the decoder by design -- the only neighbours a measured row renders, and with NVIDIA's text
                assert_ne!(probed >> 96, 0, "{word:032x}: an instruction-bit neighbour decoded");
                assert_eq!(cubit::printer::to_sass_lossless(&d).replace(".reuse", ""), vendor, "{word:032x}");
                control_word += 1;
            }
            (Ok(d), None) => panic!("{word:032x} is illegal for nvdisasm but decodes as {}", cubit::printer::to_sass_lossless(&d)),
        }
    }
    assert_eq!(n, 99, "lattice words in the fixture");
    assert_eq!((undecoded, control_word, control_law), (80, 12, 7), "fail-closed instruction-bit neighbours / control-word bits / the read-barrier words");
    // the donor spelling and the other illegal spellings are refused by the encoder
    for source in ["FENCE.VIEW.ASYNC.T ;", "FENCE.VIEW.ASYNC ;", "FENCE.VIEW.ASYNC.S.G ;", "FENCE ;"] {
        if let Ok(parsed) = cubit::parse_sass(source, 0) {
            assert!(cubit::encoder::encode_instruction(&parsed, table).is_err(), "{source}");
        }
    }
}

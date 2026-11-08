//! SM120 warp votes -- `VOTE.{ALL,ANY,EQ} [Rd,] Pd, [!]Ps` (0x806) and `VOTEU.{ALL,ANY,EQ} [URd,] UPd, [!]Ps` (0x886) -- measured
//! with nvdisasm 13.1 (tools/probes/re_sm120_vote.py, fixture tests/fixtures/sm120_vote_nvdisasm.jsonl): the guard [15:12], the
//! ballot destination [23:16] (255 = RZ / URZ, elided -- the two-operand keys), the mode [73:72] (3 = INVALID3), the predicate
//! destination [83:81], the source predicate [89:87] with its negation bit 90. Every probed word decodes to its key, prints
//! NVIDIA's text and reassembles all 128 bits; the lattice (INVALID3, bit 91, the text-inert bits) never renders as another
//! text. Before these rows `VOTEU.ALL UR4, UPT, PT` -- the "every lane ready" test of a comm warp -- and `VOTEU.ANY UR4, UPT,
//! P1` did not assemble (the harvest rows baked a predicate at PT and carried `.ANY` only; megakernel item 11, 2026-11-08).
use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;
use std::{path::PathBuf, sync::OnceLock};

const SOURCE: &str = "vote-sm120-2026-11-08";
const KEYS: [&str; 4] = ["VOTE_R_P_P", "VOTE_P_P", "VOTEU_UR_UP_P", "VOTEU_UP_P"];
const CTRL: u128 = 0x000f_ca00u128 << 96; // the probe's control code
const LOW: u128 = (1u128 << 105) - 1;

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
    include_str!("fixtures/sm120_vote_nvdisasm.jsonl").lines().map(|l| serde_json::from_str(l).unwrap()).collect()
}

fn expected_key(vendor: &str) -> &'static str {
    let uniform = vendor.contains("VOTEU.");
    let with_dst = vendor.contains(", ") && vendor.split(", ").count() == 3;
    match (uniform, with_dst) {
        (false, true) => "VOTE_R_P_P",
        (false, false) => "VOTE_P_P",
        (true, true) => "VOTEU_UR_UP_P",
        (true, false) => "VOTEU_UP_P",
    }
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
    assert_eq!(decoded.key.as_str(), expected_key(vendor), "{word:032x}");
    let mode = vendor.split('.').nth(1).unwrap().split(' ').next().unwrap();
    assert_eq!(decoded.mod_group, mode, "{word:032x}");
    assert_eq!(cubit::printer::to_sass_lossless(&decoded), vendor, "{word:032x}");
    assert_eq!(reencode(table, word, vendor), word, "{vendor}");
}

fn mint(table: &IsaTable, text: &str) -> anyhow::Result<u128> {
    let parsed = cubit::parse_sass(text, 0)?;
    Ok(cubit::encoder::encode_instruction(&parsed, table)? & LOW)
}

#[test]
fn every_probed_word_matches_nvidia_and_reassembles_all_128_bits() {
    let mut n = 0;
    let mut rows = std::collections::BTreeSet::new();
    let (table, index) = table_and_index();
    for row in fixture() {
        if row.get("lattice").is_some() {
            continue;
        }
        let vendor = row["nvidia_sass"].as_str().unwrap();
        let word = u128::from_str_radix(row["word"].as_str().unwrap(), 16).unwrap() | CTRL;
        check(word, vendor);
        let d = index.decode(word, 0, table).unwrap();
        rows.insert((d.key.clone(), d.mod_group.clone()));
        n += 1;
    }
    assert_eq!(n, 516, "form words in the fixture");
    assert_eq!(rows.len(), 12, "4 keys x ALL / ANY / EQ: {rows:?}");
}

#[test]
fn the_comm_warp_votes_assemble() {
    let (table, _) = table_and_index();
    // the texts the harvest rows refused (a predicate baked at PT, `.ANY` only) and their neighbours
    assert_eq!(mint(table, "VOTEU.ALL UR4, UPT, PT ;").unwrap(), 0x038e00000000000000047886);
    assert_eq!(mint(table, "VOTEU.ANY UR4, UPT, PT ;").unwrap(), 0x038e01000000000000047886);
    assert_eq!(mint(table, "VOTEU.ANY UR4, UPT, P1 ;").unwrap(), 0x008e01000000000000047886);
    assert_eq!(mint(table, "VOTEU.EQ UR4, UP2, !P1 ;").unwrap(), 0x048402000000000000047886);
    assert_eq!(mint(table, "VOTEU.ALL UP0, P0 ;").unwrap(), 0x0000000000000000ff7886);
    assert_eq!(mint(table, "VOTE.ALL R4, PT, PT ;").unwrap(), 0x038e00000000000000047806);
    assert_eq!(mint(table, "VOTE.ANY R4, P2, !P1 ;").unwrap(), 0x048401000000000000047806);
    assert_eq!(mint(table, "VOTE.EQ P0, P0 ;").unwrap(), 0x000002000000000000ff7806);
    assert_eq!(mint(table, "@!P0 VOTEU.ANY UR6, UPT, PT ;").unwrap(), 0x038e01000000000000068886);
    for refused in ["VOTEU.INVALID3 UR4, UPT, PT ;", "VOTEU.UNI UR4, UPT, PT ;", "VOTE.ALL R4, UPT, PT ;", "VOTEU.ALL UR4, PT, PT ;"] {
        if let Ok(parsed) = cubit::parse_sass(refused, 0) {
            assert!(cubit::encoder::encode_instruction(&parsed, table).is_err(), "{refused}");
        }
    }
}

#[test]
fn the_measured_rows_carry_the_provenance_and_a_fail_closed_mask() {
    let raw: Value = serde_json::from_slice(&cubit::table::read_table_bytes(table_path()).unwrap()).unwrap();
    let number = |v: &Value| u128::from_str_radix(v.as_str().unwrap().trim_start_matches("0x"), 16).unwrap();
    for key in KEYS {
        let entry = &raw["instructions"][key];
        assert_eq!(entry["_src"], SOURCE, "{key}");
        let groups = entry["mod_groups"].as_object().unwrap();
        assert_eq!(groups.keys().cloned().collect::<Vec<_>>(), vec!["ALL", "ANY", "EQ"], "{key}");
        let elided = !key.contains("_R_") && !key.contains("_UR_");
        for (name, g) in groups {
            assert_eq!(g.get("_src").unwrap_or(&entry["_src"]), SOURCE, "{key} {name}");
            let fields = g["fields"].as_array().unwrap();
            assert_eq!(fields.len(), if elided { 4 } else { 5 }, "{key} {name}: guard, [destination,] pdst, psrc, neg");
            let mut field_mask = 0u128;
            for f in fields {
                let bits = ((1u128 << f["bits"].as_u64().unwrap()) - 1) << f["shift"].as_u64().unwrap();
                assert_eq!(field_mask & bits, 0, "{key} {name}: overlapping fields");
                field_mask |= bits;
            }
            let base = number(&g["and_base"]);
            assert_eq!(number(&g["variable_mask"]), field_mask, "{key} {name}");
            assert_eq!(base >> 105, 0, "{key} {name}");
            assert_eq!(base & field_mask, 0, "{key} {name}");
            assert_eq!((base >> 72) & 3, match name.as_str() { "ALL" => 0, "ANY" => 1, _ => 2 }, "{key} {name}: the mode code");
            assert_eq!((base >> 16) & 0xff, if elided { 255 } else { 0 }, "{key} {name}: the destination byte");
            assert!(g["count"].is_null(), "{key} {name}");
        }
    }
    assert_eq!(raw["_meta"]["provenance"]["sources"][SOURCE]["rows"], 12);
}

#[test]
fn the_lattice_around_the_form_is_never_rendered_as_another_text() {
    let (table, index) = table_and_index();
    let (mut n, mut undecoded, mut control_word) = (0, 0, 0);
    for row in fixture() {
        if row.get("lattice").is_none() {
            continue;
        }
        n += 1;
        let probed = u128::from_str_radix(row["word"].as_str().unwrap(), 16).unwrap();
        let word = probed | CTRL;
        match (index.decode(word, 0, table), row["nvidia_sass"].as_str()) {
            (Err(_), _) => {
                assert_eq!(probed >> 96, 0, "{word:032x}: a control-word bit must not fail the decode");
                undecoded += 1;
            }
            (Ok(d), Some(vendor)) => {
                // bits 96-127 are the control word: text-inert for nvdisasm, stripped by the decoder by design
                assert_ne!(probed >> 96, 0, "{word:032x}: an instruction-bit neighbour decoded");
                assert_eq!(cubit::printer::to_sass_lossless(&d).replace(".reuse", ""), vendor, "{word:032x}");
                control_word += 1;
            }
            (Ok(d), None) => panic!("{word:032x} is illegal for nvdisasm but decodes as {}", cubit::printer::to_sass_lossless(&d)),
        }
    }
    assert_eq!(n, 154, "lattice words in the fixture");
    assert_eq!((undecoded, control_word), (130, 24), "fail-closed instruction-bit neighbours / control-word bits");
}

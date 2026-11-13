//! Served-control FP32x2 reuse witnesses and lossless-boundary checks.
include!("hb300_fixture.inc");

use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;

const ARCHES: [&str; 2] = ["sm103a", "sm100a"];
const FAMILIES: [&str; 13] = [
    "fadd2_lo_hi",
    "fadd2_hi_lo_rb_reuse",
    "fadd2_rur",
    "fmul2_rur",
    "fmul2_paired_ur",
    "fmul2_paired_order",
    "fmul2_rz_production",
    "ffma2_addend_ur",
    "ffma2_all_paired_b88",
    "ffma2_packed_b",
    "ffma2_r_scalar",
    "ffma2_scalar_a",
    "engine_l1_ffma2_legacy",
];

fn word(row: &Value) -> u128 {
    u128::from_str_radix(row["word"].as_str().unwrap(), 16).unwrap()
}

fn reencode(table: &IsaTable, decoded: &cubit::decoder::DecodedInst, raw: u128) -> u128 {
    let control = cubit::scheduling::format_control_code(&cubit::scheduling::decode_sched_upper32(
        (raw >> 96) as u32,
    ));
    let text = cubit::printer::to_sass_lossless(decoded);
    let parsed = cubit::parse_cuasm_line(&format!("[{control}] {text} ;"), 0).unwrap();
    cubit::encoder::encode_instruction(&parsed, table).unwrap()
}

#[test]
fn served_reuse_words_are_vendor_exact_and_lossless() {
    for arch in ARCHES {
        let table = IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap();
        let index = DecodeIndex::build(&table);
        let fixture = hb300_fixture(&format!("{arch}_engine_l1_served_reuse_nvdisasm.jsonl"));
        let mut records = 0;
        let mut occurrences = 0;
        for line in fixture.lines() {
            let row: Value = serde_json::from_str(line).unwrap();
            let raw = word(&row);
            let text = row["nvidia_sass"].as_str().unwrap();
            let decoded = index
                .decode(raw, 0, &table)
                .unwrap_or_else(|error| panic!("{arch} {raw:032x}: served reuse refused: {error}"));
            assert_eq!(decoded.key, "FMUL2_R_R_R", "{arch} {raw:032x}");
            assert_eq!(decoded.mod_group, "", "{arch} {raw:032x}");
            assert_eq!(cubit::printer::to_sass_lossless(&decoded), text);
            assert_eq!(reencode(&table, &decoded, raw), raw & !(7u128 << 125));
            records += 1;
            occurrences += row["occurrences"].as_u64().unwrap();
            assert_eq!(row["corpus"], "FlashMLA");
        }
        assert_eq!((records, occurrences), (532, 2_510), "{arch}");
    }
}

#[test]
fn reuse_shape_matrix_follows_every_vendor_answer() {
    for arch in ARCHES {
        let table = IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap();
        let index = DecodeIndex::build(&table);
        let fixture = hb300_fixture(&format!("{arch}_engine_l1_reuse_shape_nvdisasm.jsonl"));
        let rows: Vec<Value> = fixture
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        let mut refused = 0;
        let mut exact_pairs = 0;
        let mut inherited_incomplete = 0;
        let mut baseline_refused = 0;
        for pair in rows.chunks_exact(2) {
            let (clear, set) = (&pair[0], &pair[1]);
            assert_eq!(clear["reuse_bit"], set["reuse_bit"]);
            assert_eq!(
                (
                    clear["reuse_present"].as_u64(),
                    set["reuse_present"].as_u64()
                ),
                (Some(0), Some(1))
            );
            let (clear_raw, set_raw) = (word(clear), word(set));
            let clear_result = index.decode(clear_raw, 0, &table);
            let set_result = index.decode(set_raw, 0, &table);
            let set_text = set["nvidia_sass"].as_str();
            if set_text.is_none() || set_text.is_some_and(|sass| sass.contains("INVALID")) {
                assert!(
                    set_result.is_err(),
                    "{arch} {set_raw:032x}: expected refusal"
                );
                refused += 1;
                continue;
            }
            let clear_decoded = match clear_result {
                Ok(decoded) => decoded,
                Err(_) => {
                    // Some source witnesses carry unrelated unowned bits. The
                    // control pair must not turn that baseline into a match.
                    assert!(
                        set_result.is_err(),
                        "{arch} {set_raw:032x}: reuse opened an unowned baseline"
                    );
                    baseline_refused += 1;
                    continue;
                }
            };
            assert_eq!(
                cubit::printer::to_sass_lossless(&clear_decoded),
                clear["nvidia_sass"]
            );
            let set_decoded = set_result.unwrap_or_else(|error| {
                panic!("{arch} {set_raw:032x} {}: {error}", set_text.unwrap())
            });
            assert_eq!(
                cubit::printer::to_sass_lossless(&set_decoded),
                set_text.unwrap()
            );
            if reencode(&table, &clear_decoded, clear_raw) == clear_raw & !(7u128 << 125) {
                assert_eq!(
                    reencode(&table, &set_decoded, set_raw),
                    set_raw & !(7u128 << 125)
                );
                exact_pairs += 1;
            } else {
                // Retained pre-existing loss in scheduling/control or an
                // unrelated modifier is census evidence, not reuse adoption.
                inherited_incomplete += 1;
            }
        }
        assert_eq!(rows.len(), 156, "{arch}");
        assert_eq!(refused, 15, "{arch}");
        assert!(exact_pairs > 0, "{arch}");
        assert_eq!(
            exact_pairs + inherited_incomplete + baseline_refused + refused,
            78,
            "{arch}"
        );
        eprintln!("{arch}: exact pairs {exact_pairs}, inherited incomplete {inherited_incomplete}, baseline refused {baseline_refused}");
    }
}

#[test]
fn addend_ur_reuse_has_an_isolated_production_pair() {
    for arch in ARCHES {
        let table = IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap();
        let index = DecodeIndex::build(&table);
        let fixture = hb300_fixture(&format!("{arch}_engine_l1_addend_ur_reuse_nvdisasm.jsonl"));
        let mut clear = None;
        let mut set = None;
        for line in fixture.lines() {
            let row: Value = serde_json::from_str(line).unwrap();
            let raw = word(&row);
            let decoded = index.decode(raw, 0, &table).unwrap();
            assert_eq!(decoded.key, "FFMA2_R_R_R_UR");
            assert_eq!(
                cubit::printer::to_sass_lossless(&decoded),
                row["nvidia_sass"]
            );
            assert_eq!(reencode(&table, &decoded, raw), raw & !(7u128 << 125));
            if row["reuse_present"] == 0 {
                clear = Some(row);
            } else {
                set = Some(row);
            }
        }
        let (clear, set) = (clear.unwrap(), set.unwrap());
        assert_eq!(int_text(&clear), int_text(&set));
        assert!(!clear["nvidia_sass"].as_str().unwrap().contains(".reuse"));
        assert!(set["nvidia_sass"].as_str().unwrap().contains(".reuse"));
    }
}

fn int_text(row: &Value) -> String {
    row["nvidia_sass"].as_str().unwrap().replace(".reuse", "")
}

#[test]
fn three_token_rows_refuse_unowned_bits_74_and_75() {
    for arch in ARCHES {
        let table = IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap();
        let index = DecodeIndex::build(&table);
        let mut candidates = 0;
        for family in FAMILIES {
            let fixture = hb300_fixture(&format!("{arch}_{family}_nvdisasm.jsonl"));
            for line in fixture.lines() {
                let row: Value = serde_json::from_str(line).unwrap();
                let Some(text) = row["nvidia_sass"].as_str() else {
                    continue;
                };
                if !(text.starts_with("FADD2 ") || text.starts_with("FMUL2")) {
                    continue;
                }
                let raw = word(&row);
                if raw & (3u128 << 74) == 0 {
                    continue;
                }
                assert!(
                    index.decode(raw, 0, &table).is_err(),
                    "{arch}/{family} {raw:032x}: unowned [75:74] decoded as {text}"
                );
                candidates += 1;
            }
        }
        // The full fixture boundary includes H's 66 words that E2 previously
        // decoded with the vendor's text and re-assembled with loss.
        assert_eq!(candidates, 678, "{arch}");
    }
}

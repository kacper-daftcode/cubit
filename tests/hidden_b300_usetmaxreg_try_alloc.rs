//! Measured missing production forms of USETMAXREG.TRY_ALLOC.CTAPOOL (SM103a/SM100a).
//! SASS text and lower-96 re-encoding only: no silicon allocation semantics is claimed.

include!("hb300_fixture.inc");

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::IsaTable;
use serde::Deserialize;

const M96: u128 = (1u128 << 96) - 1;
const KEY: &str = "USETMAXREG_UP_II";
const GROUP: &str = "CTAPOOL,TRY_ALLOC";

#[derive(Deserialize)]
struct Oracle {
    word: String,
    rc: i32,
    nvidia_sass: Option<String>,
    kind: String,
    labels: Vec<String>,
    role: String,
}

fn fixture(target: &str) -> Vec<Oracle> {
    let text = match target {
        "sm103a" => hb300_fixture("sm103_usetmaxreg_try_alloc_nvdisasm.jsonl"),
        "sm100a" => hb300_fixture("sm100_usetmaxreg_try_alloc_nvdisasm.jsonl"),
        _ => unreachable!(),
    };
    text.lines().map(|line| serde_json::from_str(line).unwrap()).collect()
}

fn table(target: &str) -> IsaTable {
    IsaTable::load(std::path::Path::new(&format!("tables/{target}.json"))).unwrap()
}

fn word(row: &Oracle) -> u128 {
    u128::from_str_radix(&row.word, 16).unwrap()
}

#[test]
fn production_and_measured_fields_vendor_exact_roundtrip() {
    for target in ["sm103a", "sm100a"] {
        let table = table(target);
        let index = DecodeIndex::build(&table);
        let rows = fixture(target);
        let mut production = 0;
        let mut historical = 0;
        let mut adopted = 0;
        for row in &rows {
            if row.role != "adopt" { continue; }
            assert_eq!(row.rc, 0, "{} {} oracle rejected", target, row.word);
            let text = row.nvidia_sass.as_deref().unwrap();
            let decoded = index.decode(word(row) & M96, 0, &table)
                .unwrap_or_else(|e| panic!("{target} {} {text}: {e}", row.word));
            assert_eq!(decoded.key, KEY, "{target} {}", row.word);
            assert_eq!(decoded.mod_group, GROUP, "{target} {}", row.word);
            assert_eq!(to_sass(&decoded), text, "{target} {}", row.word);
            let parsed = parse_sass(text, 0).unwrap();
            let encoded = encode_instruction(&parsed, &table).unwrap();
            assert_eq!(encoded & M96, word(row) & M96, "{target} {} lower96", row.word);
            adopted += 1;
            production += usize::from(row.kind == "production");
            historical += usize::from(row.kind == "historical");
        }
        assert_eq!(production, 25, "{target}: all unique production words");
        assert_eq!(historical, 2, "{target}: historical UP0 corpus controls");
        assert!(adopted > 1500, "{target}: expected measured field lattice");
        for value in 0u128..1024 {
            assert!(rows.iter().any(|row| row.labels.contains(&format!("imm10={value}"))),
                "{target}: immediate {value:#x}");
        }
        for value in 0..8 {
            assert!(rows.iter().any(|row| row.labels.contains(&format!("up3={value}"))),
                "{target}: UP destination {value}");
        }
        for value in 0..16 {
            assert!(rows.iter().any(|row| row.labels.contains(&format!("guard4={value}"))),
                "{target}: guard {value}");
        }
    }
}

#[test]
fn opcode_neighbors_and_unclaimed_inert_neighborhood_fail_closed() {
    for target in ["sm103a", "sm100a"] {
        let table = table(target);
        let index = DecodeIndex::build(&table);
        let mut rejected = 0;
        for row in fixture(target) {
            if row.role != "reject" { continue; }
            if let Ok(decoded) = index.decode(word(&row) & M96, 0, &table) {
                assert_ne!((decoded.key.as_str(), decoded.mod_group.as_str()), (KEY, GROUP),
                    "{target} overclaim: {} vendor={:?}", row.word, row.nvidia_sass);
            }
            rejected += 1;
        }
        assert!(rejected >= 700, "{target}: missing negative neighborhood records");
    }
}

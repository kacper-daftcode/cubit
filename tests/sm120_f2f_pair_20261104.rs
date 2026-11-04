//! `F2F.F64.F32 Rd, [-|]Ra[|]` and `F2F.F32.F64 Rd, [-|]Ra[|]` on SM120 and SM121a (fixture
//! tests/fixtures/sm120_f2f_pair_20261104_nvdisasm.jsonl: nvdisasm 13.1 `-b SM120` and `-b SM121`
//! agree on every word). Found by the GB10-host census of 2026-11-04: 217 sm_121 words of the shape
//! `F2F.F64.F32 R8, |R15|` printed as `F2F.F32.F64` because the sm121a rows carried their register
//! fields one bit off (Rd at shift 17, Ra at 33) and the words fell into the harvest group `F2F_R_R`
//! 'F32,F64' (mask 0, type flags on the wrong bits). The rows are rebuilt from the SM120 ones in both
//! tables (type pair in bits 67/76/77, Rd[23:16], Ra[39:32], abs 62, neg 63) plus the guard field,
//! and the sm121a harvest group is gone (blackwell-isa-internal/tools/t3_batch2_20261104.py).
use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;

fn fixture() -> Vec<Value> {
    include_str!("fixtures/sm120_f2f_pair_20261104_nvdisasm.jsonl").lines()
        .map(|l| serde_json::from_str(l).unwrap()).collect()
}

fn reencode(table: &IsaTable, word: u128, text: &str) -> u128 {
    let control = cubit::scheduling::format_control_code(
        &cubit::scheduling::decode_sched_upper32((word >> 96) as u32));
    let source = format!("[{control}] {text} ;");
    let parsed = cubit::parse_cuasm_line(&source, 0).unwrap();
    cubit::encoder::encode_instruction(&parsed, table).unwrap_or_else(|e| panic!("{source}: {e}"))
}

#[test]
fn both_tables_decode_print_and_reassemble_every_word() {
    for (arch, column) in [("sm120", "nvidia_sass_sm120"), ("sm121a", "nvidia_sass_sm121")] {
        let table = IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap();
        let index = DecodeIndex::build(&table);
        let mut n = 0;
        for r in fixture() {
            let word = u128::from_str_radix(r["word"].as_str().unwrap(), 16).unwrap();
            let vendor = r[column].as_str().unwrap();
            let d = index.decode(word, 0, &table).unwrap_or_else(|e| panic!("{arch} {word:032x}: {e}"));
            // (sm120 keeps a harmless harvest group F2F_R_R 'F32,F64' that wins the tiebreak for the
            // plain unguarded words and prints the same text; the keyed row owns everything else)
            assert!(d.key == r["key"].as_str().unwrap() || d.key == "F2F_R_R", "{arch} {word:032x}: {}", d.key);
            assert_eq!(cubit::printer::to_sass_lossless(&d), vendor, "{arch} {word:032x}");
            assert_eq!(reencode(&table, word, vendor), word, "{arch} {vendor}");
            n += 1;
        }
        assert_eq!(n, 29, "{arch}: fixture words");
        // the harvest group that swallowed the sm121a words is gone
        if arch == "sm121a" {
            let groups = &table.entries["F2F_R_R"].mod_groups;
            assert!(!groups.contains_key("F32,F64"), "sm121a F2F_R_R 'F32,F64' harvest group is back");
        }
    }
}

#[test]
fn the_rows_carry_the_provenance() {
    for arch in ["sm120", "sm121a"] {
        let raw: Value = serde_json::from_slice(
            &cubit::table::read_table_bytes(format!("tables/{arch}.json")).unwrap()).unwrap();
        for key in ["F2F.F64.F32_R_R", "F2F.F32.F64_R_R"] {
            let g = &raw["instructions"][key]["mod_groups"][""];
            assert_eq!(g["_src"], "f2f-pair-2026-11-04", "{arch} {key}");
            let shifts: Vec<u64> = g["fields"].as_array().unwrap().iter().map(|f| f["shift"].as_u64().unwrap()).collect();
            assert!(shifts.contains(&12) && shifts.contains(&16) && shifts.contains(&32) && shifts.contains(&62) && shifts.contains(&63), "{arch} {key}: {shifts:?}");
        }
    }
}

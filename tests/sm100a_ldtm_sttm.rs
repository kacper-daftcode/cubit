//! tcgen05 `LDTM Rd, tmem[URb+off]` / `STTM tmem[URb+off], Ra` on sm_100a and sm_103a (session T-5,
//! 2026-11-05; `docs/KNOWN_ISSUES.md` V5 (a), NEEDS_OWNER 19): the harvest rows of the
//! `16dp32bit_t16_t31` x2 / x8 / x32 shapes had no uniform-register field (the sample's URZ = 0xff
//! half-baked as 0xc0 in `and_base`), a 2-3-bit register field and a 32-bit offset field overlapping
//! the UR slot, so the B300 strict round trip of 2026-11-03 printed `tmem[URZ+0x20]` and re-encoded
//! `tmem[UR192+0x20]` (5 words). `tools/probes/re_sm100_ldtm_sttm.py` measured the whole family
//! with nvdisasm 13.1 (`-b SM100`, and `-b SM103` — text-identical): shape enum bits {87, 82, 81},
//! count `x2^n` at [85:83], bit 80 = PACK16BIT (LDTM) / EXPAND16BIT (STTM), 8-bit register and
//! 8-bit UR fields (255 = RZ / URZ; `tmem[URZ]` with offset 0, `tmem[0x20]` with one), the 24-bit
//! offset at [63:40] (its high byte [79:72] stays outside the rows: fail-closed), bit 91 = frame,
//! and a UNIFORM guard (`@UP0 LDTM …`). Both keys are rebuilt with 96 measured groups each
//! (6 shapes × 8 counts × pack) on both tables; the printer prints the guard as `@UPn` and the
//! pack modifier after the count.
//!
//! Runs against `tables/sm100a.json` by default and against `tables/sm103a.json` with
//! `CUBIT_TABLE` (the `sm103a` test below does the latter in-process).
use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;
use std::{path::Path, sync::OnceLock};

const SOURCE: &str = "ldtm-sttm-sm100-2026-11-05";
const CTRL: u128 = 0x000f_e400u128 << 96; // control code of the probe words

fn load(path: &str) -> (IsaTable, DecodeIndex) {
    let table = IsaTable::load(Path::new(path)).unwrap();
    let index = DecodeIndex::build(&table);
    (table, index)
}

fn sm100a() -> &'static (IsaTable, DecodeIndex) {
    static T: OnceLock<(IsaTable, DecodeIndex)> = OnceLock::new();
    T.get_or_init(|| load("tables/sm100a.json"))
}

fn sm103a() -> &'static (IsaTable, DecodeIndex) {
    static T: OnceLock<(IsaTable, DecodeIndex)> = OnceLock::new();
    T.get_or_init(|| load("tables/sm103a.json"))
}

fn fixture(arch: &str) -> Vec<Value> {
    let text = if arch == "sm103a" {
        include_str!("fixtures/sm103a_ldtm_sttm_nvdisasm.jsonl")
    } else {
        include_str!("fixtures/sm100a_ldtm_sttm_nvdisasm.jsonl")
    };
    text.lines().map(|l| serde_json::from_str(l).unwrap()).collect()
}

fn reencode(table: &IsaTable, word: u128, text: &str) -> u128 {
    let control = cubit::scheduling::format_control_code(
        &cubit::scheduling::decode_sched_upper32((word >> 96) as u32));
    let source = format!("[{control}] {text} ;");
    cubit::roundtrip_audit::check_semantic_source(&source).unwrap();
    let parsed = cubit::parse_cuasm_line(&source, 0).unwrap();
    assert!(parsed.hand_sched && parsed.rsd.is_none(), "{source}");
    cubit::encoder::encode_instruction(&parsed, table).unwrap_or_else(|e| panic!("{source}: {e}"))
}

fn check(tab: &(IsaTable, DecodeIndex), word: u128, vendor: &str) -> String {
    let (table, index) = tab;
    let decoded = index.decode(word, 0, table).unwrap_or_else(|e| panic!("{word:032x}: {e}"));
    assert!(decoded.key == "LDTM_R_II" || decoded.key == "STTM_II_R", "{word:032x}: {}", decoded.key);
    let own = cubit::printer::to_sass_lossless(&decoded);
    assert_eq!(own, vendor, "{word:032x}");
    assert_eq!(reencode(table, word, vendor), word, "{vendor}");
    decoded.mod_group.clone()
}

fn every_word(tab: &(IsaTable, DecodeIndex), arch: &str) {
    let mut n = 0;
    let mut groups = std::collections::BTreeSet::new();
    for row in fixture(arch) {
        if row.get("lattice").is_some() {
            continue;
        }
        let vendor = row["nvidia_sass"].as_str().unwrap();
        let word = u128::from_str_radix(row["word"].as_str().unwrap(), 16).unwrap() | CTRL;
        groups.insert(check(tab, word, vendor));
        n += 1;
    }
    assert_eq!(n, 576, "{arch}: form words in the fixture");
    // 48 shape x count groups, each plain, with PACK16BIT (LDTM) and with EXPAND16BIT (STTM)
    assert_eq!(groups.len(), 144, "{arch}: {groups:?}");
}

fn lattice(tab: &(IsaTable, DecodeIndex), arch: &str) {
    let (table, index) = tab;
    let (mut n, mut undecoded) = (0, 0);
    for row in fixture(arch) {
        if row.get("lattice").is_none() {
            continue;
        }
        n += 1;
        let word = u128::from_str_radix(row["word"].as_str().unwrap(), 16).unwrap() | CTRL;
        match index.decode(word, 0, table) {
            Err(_) => undecoded += 1,
            Ok(d) => panic!("{arch}: lattice word {word:032x} ({:?}) decodes as {}", row["nvidia_sass"], cubit::printer::to_sass_lossless(&d)),
        }
    }
    assert_eq!(n, 80, "{arch}: lattice words");
    assert_eq!(undecoded, 80, "{arch}: every lattice word stays unclaimed (INVALID shapes, the offset high byte, the inert bits, bit 91 clear)");
}

#[test]
fn sm100a_every_probed_word_matches_nvidia_and_reassembles_all_128_bits() {
    every_word(sm100a(), "sm100a");
}

#[test]
fn sm103a_every_probed_word_matches_nvidia_and_reassembles_all_128_bits() {
    every_word(sm103a(), "sm103a");
}

#[test]
fn sm100a_lattice_stays_unclaimed() {
    lattice(sm100a(), "sm100a");
}

#[test]
fn sm103a_lattice_stays_unclaimed() {
    lattice(sm103a(), "sm103a");
}

/// The five B300 words of 2026-11-03 (sm_100a publish corpus, `kst_16x32bx2_x{2,8,32}` /
/// `kld_16x32bx2_x8`), with their own control codes: text and all 128 bits.
#[test]
fn the_b300_strict_residue_words_round_trip() {
    for (word, vendor) in [
        (0x0001e40008aa00ff00002004000079edu128, "STTM.16dp32bit_t16_t31.x32 tmem[0x20], R4"),
        (0x0001e400089a00ff00000804000079edu128, "STTM.16dp32bit_t16_t31.x8 tmem[0x8], R4"),
        (0x0001e400088a00ff00000206000079edu128, "STTM.16dp32bit_t16_t31.x2 tmem[0x2], R6"),
        (0x000e2400089a0000000008ff000479eeu128, "LDTM.16dp32bit_t16_t31.x8 R4, tmem[0x8]"),
    ] {
        check(sm100a(), word, vendor);
    }
}

#[test]
fn the_measured_rows_carry_the_provenance_and_a_fail_closed_mask() {
    for path in ["tables/sm100a.json", "tables/sm103a.json"] {
        let raw: Value = serde_json::from_slice(&cubit::table::read_table_bytes(path).unwrap()).unwrap();
        let number = |v: &Value| u128::from_str_radix(v.as_str().unwrap().trim_start_matches("0x"), 16).unwrap();
        for key in ["LDTM_R_II", "STTM_II_R"] {
            let groups = raw["instructions"][key]["mod_groups"].as_object().unwrap();
            assert_eq!(groups.len(), 96, "{path} {key}");
            for (name, g) in groups {
                assert_eq!(g["_src"], SOURCE, "{path} {key} {name}");
                let mut field_mask = 0u128;
                for f in g["fields"].as_array().unwrap() {
                    let bits = ((1u128 << f["bits"].as_u64().unwrap()) - 1) << f["shift"].as_u64().unwrap();
                    assert_eq!(field_mask & bits, 0, "{name}: overlapping fields");
                    field_mask |= bits;
                }
                assert_eq!(number(&g["variable_mask"]), field_mask, "{name}");
                assert_eq!(number(&g["and_base"]) >> 105, 0, "{name}");
                assert_eq!(number(&g["and_base"]) & field_mask, 0, "{name}");
                assert!(g["count"].is_null(), "{name}");
                // the UR and register fields are 8 bits wide (255 = URZ / RZ), the offset 24 bits
                let widths: Vec<(String, u64)> = g["fields"].as_array().unwrap().iter()
                    .map(|f| (f["extraction"].as_str().unwrap().to_string(), f["bits"].as_u64().unwrap())).collect();
                assert!(widths.contains(&("tmem_ur".into(), 8)) && widths.contains(&("reg".into(), 8)) && widths.contains(&("tmem_off".into(), 24)), "{name}: {widths:?}");
            }
        }
    }
}

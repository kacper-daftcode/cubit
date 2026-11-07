//! SM120 FP32 ALU (FADD / FMUL / FFMA / FMNMX) rebuilt from measurement (session G, 2026-11-07; KNOWN_ISSUES T1):
//! the 14 plain keys carry the rows `tools/probes/re_sm120_fp32_alu.py` measures with nvdisasm 13.1 (1 636 form + 30
//! glyph + 492 lattice + 16 neighbour words; the same text on `-b SM103` / `SM100`). Law: guard [15:12]; Rd [23:16];
//! Ra [31:24] (`-Ra` 72, `|Ra|` 73, `.reuse` 122); the B operand [39:32] (Rb / URb with `|B|` 62, `-B` 63) or the f32
//! immediate [63:32]; the C slot [71:64] (FFMA: `|Rc|` 74, `-Rc` 75); FADD `[.FTZ][.RM|.RP|.RZ][.SAT]` (80, [79:78],
//! 77); FMUL `[.FTZ|.FMZ][.D8|.D4|.D2|.M2|.M4|.M8][.RM|.RP|.RZ][.SAT]` (80 / 76, [86:84] with 4 = unspelled and
//! 0 = `INVALID0`, FTZ + FMZ = `INVALID3`); FFMA `[.FTZ|.FMZ][.RM|.RP|.RZ][.SAT]`; FMNMX `[.FTZ][.NAN][.XORSIGN]`
//! (80, 81, 82) with the min/max predicate [89:87] + `!` 90; the UR forms carry bit 91; `.reuse` only on the
//! register operands the probe names (FADD's Rb reuse bit is 124). Bit 81 on the register / UR forms of FADD / FFMA
//! is the mixed-precision FHADD / FHFMA, bit 65 on FMNMX the unmodelled `FMNMX.IS_A` -- neighbours, never claimed by
//! these keys. Retired: 27 mis-tokenised / dotted / integer-spelling junk keys as `_meta.key_aliases` (the
//! hexadecimal f32 literal still encodes through the `*_II*` aliases).
use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;
use std::{path::PathBuf, sync::OnceLock};

const SOURCE: &str = "fp32-alu-family-2026-11-07";
const CTRL: u128 = 0x000f_e200u128 << 96;
const KEYS: [(&str, usize); 14] = [
    ("FADD_R_R_R", 16), ("FADD_R_R_FI", 16), ("FADD_R_R_UR", 16),
    ("FMUL_R_R_R", 168), ("FMUL_R_R_FI", 168), ("FMUL_R_R_UR", 168),
    ("FFMA_R_R_R_R", 24), ("FFMA_R_R_R_FI", 24), ("FFMA_R_R_FI_R", 24), ("FFMA_R_R_UR_R", 24), ("FFMA_R_R_R_UR", 24),
    ("FMNMX_R_R_R_P", 8), ("FMNMX_R_R_FI_P", 8), ("FMNMX_R_R_UR_P", 8),
];
const ALIASES: [(&str, &str); 27] = [
    ("FADD.FTZ_P_R_R_R", "FADD_R_R_R"), ("FADD.FTZ_R_R_R", "FADD_R_R_R"), ("FADD.RZ_R_R_R", "FADD_R_R_R"),
    ("FADD_R_L_R", "FADD_R_R_R"), ("FADD_R_R_L", "FADD_R_R_R"), ("FADD_R_R_R_?", "FADD_R_R_R"),
    ("FADD_R_R_R_II_?", "FADD_R_R_R"), ("FADD_R_R_R_II_II_?", "FADD_R_R_R"), ("FADD_R_R_R_R", "FADD_R_R_R"),
    ("FADD.FTZ_R_R_FI", "FADD_R_R_FI"), ("FADD.FTZ_R_R_II", "FADD_R_R_FI"), ("FADD_R_R_II", "FADD_R_R_FI"),
    ("FMUL_R_R_II", "FMUL_R_R_FI"), ("FMUL_R_R_R_II_?", "FMUL_R_R_R"), ("FMUL_R_R_R_II_II_?", "FMUL_R_R_R"),
    ("FMUL_R_R_R_R", "FMUL_R_R_R"), ("FMUL_R_R_UR_II_II_II_?", "FMUL_R_R_UR"),
    ("FFMA.RM_R_R_R_R", "FFMA_R_R_R_R"), ("FFMA.RM_R_R_R_II", "FFMA_R_R_R_FI"), ("FFMA.SAT_R_R_R_II", "FFMA_R_R_R_FI"),
    ("FFMA_R_R_R_II", "FFMA_R_R_R_FI"), ("FFMA_R_R_II_R", "FFMA_R_R_FI_R"),
    ("FMNMX.NAN_R_R_UR_UR", "FMNMX_R_R_UR_P"), ("FMNMX.NAN_R_R_UR_UR_?", "FMNMX_R_R_UR_P"), ("FMNMX_R_R_II_P", "FMNMX_R_R_FI_P"),
    ("FMNMX_R_R_R_P_II_II_?", "FMNMX_R_R_R_P"), ("FMNMX_R_R_R_R", "FMNMX_R_R_R_P"),
];

fn is_family_key(k: &str) -> bool {
    KEYS.iter().any(|(key, _)| *key == k)
}

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
    include_str!("fixtures/sm120_fp32_alu_nvdisasm.jsonl").lines().map(|l| serde_json::from_str(l).unwrap()).collect()
}

fn word_of(row: &Value) -> u128 {
    u128::from_str_radix(row["word"].as_str().unwrap(), 16).unwrap() | CTRL
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

fn check(word: u128, vendor: &str) -> (String, String) {
    let (table, index) = table_and_index();
    let decoded = index.decode(word, 0, table).unwrap_or_else(|e| panic!("{word:032x}: {e}"));
    assert!(is_family_key(&decoded.key), "{word:032x}: {}", decoded.key);
    let own = cubit::printer::to_sass_lossless(&decoded);
    assert_eq!(own, vendor, "{word:032x}");
    assert_eq!(reencode(table, word, vendor), word, "{vendor}");
    (decoded.key.clone(), decoded.mod_group.clone())
}

/// Every form word (the 696 groups on the canonical operands, the operand lattice of two groups per key -- guard,
/// Rd / Ra / Rb / Rc / URb at 0, 1, 63 and 255 (`RZ` / `URZ`), every sign and `|abs|` combination, the `.reuse`
/// bits, 14 f32 immediates incl. `+INF`, `-INF`, `-0.0` and the denormals, the eight min/max predicates with `!` --
/// and one word per key with every field away from its canonical value) decodes to the 14 keys, prints NVIDIA's
/// text and re-encodes bit for bit.
#[test]
fn every_probed_word_matches_nvidia_and_reassembles_all_128_bits() {
    let mut n = 0;
    let mut groups = std::collections::BTreeSet::new();
    for row in fixture() {
        if row.get("lattice").is_some() || row.get("glyph").is_some() {
            continue;
        }
        let vendor = row["nvidia_sass"].as_str().unwrap();
        groups.insert(check(word_of(&row), vendor));
        n += 1;
    }
    assert_eq!(n, 1636, "form words in the fixture");
    assert_eq!(groups.len(), 696, "16 x 3 FADD + 168 x 3 FMUL + 24 x 5 FFMA + 8 x 3 FMNMX groups");
}

/// The NaN immediates: nvdisasm prints the `+QNAN` / `-QNAN` / `+SNAN` glyph, cubit's display print does the same
/// and the lossless print keeps the payload as a hexadecimal that re-encodes (KNOWN_ISSUES A8, the f32 lane).
#[test]
fn the_nan_glyph_words_decode_to_the_vendor_glyph() {
    let (table, index) = table_and_index();
    let mut n = 0;
    for row in fixture() {
        if row.get("glyph").is_none() {
            continue;
        }
        n += 1;
        let vendor = row["nvidia_sass"].as_str().unwrap();
        let word = word_of(&row);
        let decoded = index.decode(word, 0, table).unwrap_or_else(|e| panic!("{word:032x}: {e}"));
        assert!(is_family_key(&decoded.key), "{word:032x}: {}", decoded.key);
        assert_eq!(cubit::printer::to_sass(&decoded), vendor, "{word:032x}");
        let lossless = cubit::printer::to_sass_lossless(&decoded);
        assert_eq!(reencode(table, word, &lossless), word, "{lossless}");
    }
    assert_eq!(n, 30);
}

/// The lattice: the frame bit flipped (illegal), the text-inert bits, FMUL's `INVALID0` scale and the `INVALID3`
/// denormal mode -- never claimed; the neighbours (FHADD / FHFMA at bit 81, `FMNMX.IS_A` at bit 65) never decode to a
/// key of this family. The encoder refuses the invalid states and a `.reuse` on an operand without the bit.
#[test]
fn the_lattice_around_the_form_is_never_rendered_as_another_text() {
    let (table, index) = table_and_index();
    let (mut n_lattice, mut n_neighbour, mut undecoded) = (0, 0, 0);
    for row in fixture() {
        if row.get("lattice").is_none() {
            continue;
        }
        let word = word_of(&row);
        match (row.get("neighbour").and_then(Value::as_str), index.decode(word, 0, table)) {
            (None, Err(_)) => {
                n_lattice += 1;
                undecoded += 1;
            }
            (None, Ok(d)) => panic!("lattice word {word:032x} ({:?}) decodes as {}", row["nvidia_sass"], cubit::printer::to_sass_lossless(&d)),
            (Some(_), Err(_)) => n_neighbour += 1,
            (Some(nb), Ok(d)) => {
                assert!(!is_family_key(&d.key), "neighbour word {word:032x} ({nb}) claimed by {}", d.key);
                n_neighbour += 1;
            }
        }
    }
    assert_eq!((n_lattice, undecoded, n_neighbour), (492, 492, 16));
    for text in ["FMUL.INVALID0 R4, R2, R3", "FMUL.FTZ.FMZ R4, R2, R3", "FFMA.FMZ.FTZ R4, R2, R3, R5",
                 "FMUL R4, R2, UR3.reuse", "FMNMX R4, R2, UR3.reuse, PT", "FFMA R4, R2, UR3.reuse, R5"] {
        let refused = cubit::parser::parse_sass(text, 0).map_or(true, |p| cubit::encoder::encode_instruction(&p, table).is_err());
        assert!(refused, "{text} must be refused");
    }
}

/// The 14 keys carry their full measured grid (`_src`, mask == the fields, nothing baked under a field, the
/// modifier bits of each group name and nothing else), the 27 junk keys are aliases of the plain keys and nothing
/// else of the four mnemonics is left, the provenance legend names the tag.
#[test]
fn the_rows_are_measured_and_the_junk_keys_are_gone() {
    let raw: Value = serde_json::from_slice(&cubit::table::read_table_bytes(table_path()).unwrap()).unwrap();
    let ins = raw["instructions"].as_object().unwrap();
    let left: Vec<&String> = ins.keys()
        .filter(|k| ["FADD_", "FADD.", "FMUL_", "FMUL.", "FFMA_", "FFMA.", "FMNMX_", "FMNMX."].iter().any(|p| k.starts_with(p)))
        .filter(|k| !is_family_key(k)).collect();
    assert!(left.is_empty(), "{left:?}");
    let aliases = raw["_meta"]["key_aliases"].as_object().unwrap();
    for (old, new) in ALIASES {
        assert_eq!(aliases[old], new, "{old}");
        assert!(ins.get(old).is_none(), "{old} still a key");
    }
    assert_eq!(raw["_meta"]["provenance"]["sources"][SOURCE]["rows"], 696);
    let number = |v: &Value| u128::from_str_radix(v.as_str().unwrap().trim_start_matches("0x"), 16).unwrap();
    for (key, count) in KEYS {
        assert_eq!(ins[key]["_src"], SOURCE, "{key}");
        let groups = ins[key]["mod_groups"].as_object().unwrap();
        assert_eq!(groups.len(), count, "{key}");
        let fmul = key.starts_with("FMUL");
        for (name, g) in groups {
            assert_eq!(g["_src"], SOURCE, "{key} {name}");
            assert!(g["count"].is_null(), "{key} {name}: measured rows carry no harvest count");
            let mut field_mask = 0u128;
            for f in g["fields"].as_array().unwrap() {
                let bits = ((1u128 << f["bits"].as_u64().unwrap()) - 1) << f["shift"].as_u64().unwrap();
                assert_eq!(field_mask & bits, 0, "{name}: overlapping fields");
                field_mask |= bits;
            }
            assert_eq!(number(&g["variable_mask"]), field_mask, "{key} {name}");
            let base = number(&g["and_base"]);
            assert_eq!(base >> 105, 0, "{key} {name}");
            assert_eq!(base & field_mask, 0, "{key} {name}");
            let mut want = 0u128;
            let mut scaled = false;
            for m in name.split(',').filter(|m| !m.is_empty()) {
                want |= match m {
                    "FTZ" => 1 << 80, "FMZ" => 1 << 76, "SAT" => 1 << 77,
                    "RM" => 1 << 78, "RP" => 2 << 78, "RZ" => 3 << 78,
                    "NAN" => 1 << 81, "XORSIGN" => 1 << 82,
                    "D8" => { scaled = true; 1 << 84 }, "D4" => { scaled = true; 2 << 84 }, "D2" => { scaled = true; 3 << 84 },
                    "M2" => { scaled = true; 5 << 84 }, "M4" => { scaled = true; 6 << 84 }, "M8" => { scaled = true; 7 << 84 },
                    other => panic!("{key} {name}: unexpected modifier {other}"),
                };
            }
            if fmul && !scaled {
                want |= 4 << 84;
            }
            assert_eq!(base & !0xfffu128 & !(1u128 << 91), want, "{key} {name}");
            assert_eq!((base >> 91) & 1 == 1, key.contains("UR"), "{key} {name}: the uniform frame bit");
            assert_ne!(field_mask & (1u128 << 122), 0, "{key} {name}: Ra.reuse is a field");
            assert_ne!(field_mask & (1u128 << 12), 0, "{key} {name}: the guard is a field");
            assert_eq!(field_mask & (0xffu128 << 16), 0xffu128 << 16, "{key} {name}: Rd is a field");
        }
    }
}

/// Production census witnesses of the harvest rows (incl. the hexadecimal-immediate `FMUL_R_R_II` words that now
/// decode through the f32 key) and the hexadecimal f32 literal that encodes through the `FMUL_R_R_II` alias.
#[test]
fn witness_words_round_trip() {
    for (word, vendor) in [
        (0x000fc40000010000000000170f177221u128, "FADD.FTZ R23, R15, R23"),
        (0x000fc400000000003f8000004d4d7421u128, "FADD R77, R77, 1"),
        (0x000fc400000000000000000405047221u128, "FADD R4, R5, R4"),
        (0x000fc60000400000bfb8aa3b06577820u128, "FMUL R87, R6, -1.4426950216293334961"),
        (0x000fe2000040c00000000002070a7220u128, "FMUL.RZ R10, R7, R2"),
        (0x000fc400084100000000000507477c20u128, "FMUL.FTZ R71, R7, UR5"),
        (0x000fc400004100003b124925000a7820u128, "FMUL.FTZ R10, R0, 0.0022321429569274187088"),
        (0x000fc400000100020000008829027223u128, "FFMA.FTZ R2, R41, R136, R2"),
        (0x041fe200000100093f80000008067423u128, "FFMA.FTZ R6, R8.reuse, R9, 1"),
        (0x000fc80000000000c3e0000003027823u128, "FFMA R2, R3, -448, R0"),
        (0x000fca00080100190000000400007c23u128, "FFMA.FTZ R0, R0, UR4, R25"),
        (0x000fc600038200000000000613137209u128, "FMNMX.NAN R19, R19, R6, PT"),
        (0x000fc4000381000043e0000004047809u128, "FMNMX.FTZ R4, R4, 448, PT"),
        (0x000fe2000b8200000000000402027c09u128, "FMNMX.NAN R2, R2, UR4, PT"),
        (0x000fc4000780000000000010ff107209u128, "FMNMX R16, RZ, R16, !PT"),
    ] {
        check(word, vendor);
    }
    let (table, _) = table_and_index();
    let hex = cubit::parser::parse_sass("FMUL R87, R6, 0xbfb8aa3b", 0).unwrap();
    assert_eq!(cubit::encoder::encode_instruction(&hex, table).unwrap() & ((1u128 << 96) - 1), 0x0000_0000_0040_0000_bfb8_aa3b_0657_7820,
               "the hexadecimal f32 literal encodes through the FMUL_R_R_II alias");
}

//! The UIADD3 `.64` groups on sm121a / sm103a / sm100a (session T-22, 2026-11-08): the UR form (opcode 0x297) and the immediate
//! form (0x897) of the 64-bit uniform add -- sm120's measured rows (`UIADD3.64_UR_UP_UP_UR_UR_UR` dsv41-sm120-2026-10-22, the
//! `64` group of `UIADD3_UR_UP_UP_UR_II_UR` rows-uniform-2026-11-07) placed as the `64` groups of the plain keys of the three
//! tables and re-measured there with `tools/probes/re_sm120_rows.py --family uniform --arch SM103` / `SM100` / `SM121`
//! (nvdisasm 13.1; the whole 128-bit circumference of every row; the words of the B300 publish corpus and of the GB10 census
//! as witnesses). Before: sm103a / sm100a carried a junk `64` row on the UR form (fields at shifts 6 / 69 / 77, a two-bit mask --
//! it decoded nothing) and no `64` group on the immediate form, so the publish corpus' 9 + 3 `UIADD3.64` words were holes;
//! sm121a's `64` group of the immediate form was mis-declared (no sign fields, a reuse bit) and its 16 GB10 words re-encoded to
//! other registers (`tests/corpus_pins.rs`). The two plain `""` harvest rows of the same keys were measured on the way. sm121a's
//! three dotted `UIADD3.64_*` harvest keys are `_meta.key_aliases` of the plain keys (whole-key twins).
use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;
use std::sync::OnceLock;

const SOURCE: &str = "rows-uniform-2026-11-07";
const CTRL: u128 = 0x000f_e200u128 << 96;
const TABLES: [(&str, &str, usize); 3] = [
    ("tables/sm121a.json", include_str!("fixtures/sm121a_rows_uniform_nvdisasm.jsonl"), 35),
    ("tables/sm103a.json", include_str!("fixtures/sm103a_rows_uniform_nvdisasm.jsonl"), 9),
    ("tables/sm100a.json", include_str!("fixtures/sm100a_rows_uniform_nvdisasm.jsonl"), 3),
];
const KEYS: [&str; 2] = ["UIADD3_UR_UP_UP_UR_UR_UR", "UIADD3_UR_UP_UP_UR_II_UR"];

fn table_and_index(path: &'static str) -> &'static (IsaTable, DecodeIndex) {
    static LOADED: OnceLock<Vec<(&'static str, (IsaTable, DecodeIndex))>> = OnceLock::new();
    let all = LOADED.get_or_init(|| {
        TABLES.iter().map(|(p, _, _)| {
            let table = IsaTable::load(std::path::Path::new(p)).unwrap();
            let index = DecodeIndex::build(&table);
            (*p, (table, index))
        }).collect()
    });
    &all.iter().find(|(p, _)| *p == path).unwrap().1
}

fn records(i: usize) -> Vec<Value> {
    TABLES[i].1.lines().skip(1).filter(|l| !l.trim().is_empty()).map(|l| serde_json::from_str(l).unwrap()).collect()
}

fn hex(v: &Value) -> u128 {
    u128::from_str_radix(v.as_str().unwrap().trim_start_matches("0x"), 16).unwrap()
}

fn list<'a>(rec: &'a Value, class: &str) -> &'a [Value] {
    rec.get(class).and_then(|v| v.as_array()).map(|v| v.as_slice()).unwrap_or(&[])
}

fn reencode(table: &IsaTable, word: u128, text: &str) -> u128 {
    let control = cubit::scheduling::format_control_code(&cubit::scheduling::decode_sched_upper32((word >> 96) as u32));
    let source = format!("[{control}] {text} ;");
    cubit::roundtrip_audit::check_semantic_source(&source).unwrap();
    let parsed = cubit::parse_cuasm_line(&source, 0).unwrap();
    assert!(parsed.hand_sched && parsed.rsd.is_none(), "{source}");
    cubit::encoder::encode_instruction(&parsed, table).unwrap_or_else(|e| panic!("{source}: {e}"))
}

fn decode_text(path: &'static str, word: u128) -> Option<(String, String, String)> {
    let (table, index) = table_and_index(path);
    index.decode(word, 0, table).ok().map(|d| (d.key.clone(), d.mod_group.clone(), cubit::printer::to_sass_lossless(&d)))
}

/// Every measured row (the `64` group and the plain group of both keys, per table): the canonical word decodes to the
/// row with the vendor's text and re-encodes bit for bit; every declared field bit moves exactly its own token (the
/// guard, URd, the two carry-out predicates, URa / URb / URc or the immediate, the three sign bits) and round-trips.
#[test]
fn the_canonical_words_and_every_field_bit_round_trip() {
    for (i, (path, _, _)) in TABLES.iter().enumerate() {
        let (table, _) = table_and_index(path);
        let recs = records(i);
        assert_eq!(recs.len(), 4, "{path}: rows in the fixture");
        for rec in &recs {
            let key = rec["key"].as_str().unwrap();
            let group = rec["group"].as_str().unwrap();
            assert_eq!(rec["status"], "measured", "{path}: {key} {group}");
            assert!(KEYS.contains(&key) && matches!(group, "" | "64"), "{path}: {key} {group}");
            let t0 = rec["t0"].as_str().unwrap();
            assert_eq!(t0.contains(".64"), group == "64", "{path}: {key} {group}: {t0}");
            let w0 = hex(&rec["w0"]) | CTRL;
            let (k, g, text) = decode_text(path, w0).unwrap_or_else(|| panic!("{path}: {w0:032x} does not decode"));
            assert_eq!((k.as_str(), g.as_str(), text.as_str()), (key, group, t0), "{path}: {w0:032x}");
            assert_eq!(reencode(table, w0, t0), w0, "{path}: {t0}");
            let mut n = 0;
            for entry in list(rec, "field") {
                let bit = entry[0].as_u64().unwrap();
                let vendor = entry[1].as_str().unwrap();
                let word = w0 ^ (1u128 << bit);
                let (k, g, text) = decode_text(path, word).unwrap_or_else(|| panic!("{path}: field bit {bit}: {word:032x}"));
                assert_eq!((k.as_str(), g.as_str()), (key, group), "{path}: field bit {bit} leaves the row");
                assert_eq!(text, vendor, "{path}: field bit {bit}");
                assert_eq!(reencode(table, word, vendor), word, "{path}: field bit {bit}: {vendor}");
                n += 1;
            }
            assert!(n >= 40, "{path}: {key} {group}: only {n} field bits verified");
        }
    }
}

/// Nothing outside the declared fields is rendered as a different UIADD3 text: the modifier / other-operand bits are
/// other groups' or forms' words (decoded only to the vendor's text or not at all), the text-inert bits fail closed or
/// print the canonical text, an nvdisasm-rejected bit is never a UIADD3 decode (the `.reuse` slots excepted, A12).
#[test]
fn the_lattice_around_each_row_is_never_rendered_as_another_uiadd3_text() {
    let mut harvest_claims = 0;
    for (i, (path, _, _)) in TABLES.iter().enumerate() {
        for rec in records(i) {
            let w0 = hex(&rec["w0"]) | CTRL;
            let t0 = rec["t0"].as_str().unwrap();
            for class in ["modifier", "complex", "operand_other"] {
                for entry in list(&rec, class) {
                    let bit = entry[0].as_u64().unwrap();
                    if let Some((k, g, text)) = decode_text(path, w0 ^ (1u128 << bit)) {
                        if text != entry[1].as_str().unwrap() {
                            // HARVEST rows rendering a lattice word vendor-false -- the uniform family's next items on these
                            // tables, counted here, never hidden: the `.X` words (bit 74) belong to the harvest `UIADD3_…_UP_UP`
                            // rows (sm103a / sm100a print `UP15, !UPT` for the vendor's `!UPT, !UPT`: a 4-bit carry-in window where
                            // the vendor has 3 bits + a sign); the opcode-bit neighbours (bit 1: the ULOP3 immediate form) fall
                            // into sm103a / sm100a's harvest `ULOP3_UP_UR_UR_II_UR_II_UP` `LUT` row (a 6-bit `pred` and a 9-bit LUT
                            // where sm120's measured row has 3 + 8 bits and the `.PAND` modifier: `ULOP3.LUT UP63, …, 0x1e0` for the
                            // vendor's `ULOP3.LUT.PAND …, 0xe0`). A measured row never renders a vendor-false text.
                            let raw: Value = serde_json::from_slice(&cubit::table::read_table_bytes(path).unwrap()).unwrap();
                            assert!(raw["instructions"][&k]["mod_groups"][&g]["_src"].is_null(),
                                    "{path}: {class} bit {bit}: `{text}` by the measured row {k} {g} (vendor `{}`)", entry[1]);
                            harvest_claims += 1;
                        }
                    }
                }
            }
            for bit in list(&rec, "inert") {
                let bit = bit.as_u64().unwrap();
                if let Some((k, g, text)) = decode_text(path, w0 ^ (1u128 << bit)) {
                    if text != t0 {
                        // a HARVEST row claiming a text-inert word through the sign-tolerant fallback (the NEEDS 56 class):
                        // the three tables' `UIADD3_UR_UP_UP_UR_II_UR_UP_UP` `X` rows (no `_src`; `pred@87` / `neg@90` harvest fields) takes
                        // the bit-73 and [90:77] words of the immediate form (the two carry-in predicate windows the plain form
                        // bakes as 111) and prints `UIADD3.X …, !UPT, !UPn`; the junk key `UIADD3_UR_UP_UP_UR_UR_R_II_P` takes the
                        // UR form's words with bits in the unused immediate window -- the uniform family's next
                        // sm121a item; a measured row never does this
                        let raw: Value = serde_json::from_slice(&cubit::table::read_table_bytes(path).unwrap()).unwrap();
                        let row = &raw["instructions"][&k]["mod_groups"][&g];
                        assert!(row["_src"].is_null(), "{path}: text-inert bit {bit} rendered `{text}` by the measured row {k} {g}");
                        assert!(k.starts_with("UIADD3"), "{path}: a new harvest claim of a text-inert word (bit {bit}, {k}): `{text}`");
                        harvest_claims += 1;
                    }
                }
            }
            for bit in list(&rec, "illegal") {
                let bit = bit.as_u64().unwrap();
                if bit >= 122 {
                    continue;
                }
                if let Some((k, _, text)) = decode_text(path, w0 ^ (1u128 << bit)) {
                    assert!(!k.starts_with("UIADD3"), "{path}: nvdisasm rejects bit {bit}, cubit prints `{text}` ({k})");
                }
            }
        }
    }
    assert!(harvest_claims > 0 && harvest_claims <= 120, "{harvest_claims} lattice words rendered vendor-false by the harvest UIADD3 .X / junk rows (the uniform family's next item)");
}

/// The corpus witnesses -- the 9 (sm103a: 3 UR-form + 6 immediate-form) and 3 (sm100a) `UIADD3.64` words of the B300
/// publish corpus that had no decode, the 16 + 19 UIADD3 words of the GB10 census (16 of them the re-encode residue of
/// the mis-declared harvest group) -- decode to the measured rows with the vendor's text, with their own control codes,
/// and re-encode bit for bit.
#[test]
fn the_corpus_witnesses_round_trip() {
    for (i, (path, _, n_64)) in TABLES.iter().enumerate() {
        let (table, _) = table_and_index(path);
        let mut n64 = 0;
        for rec in records(i) {
            let key = rec["key"].as_str().unwrap();
            let group = rec["group"].as_str().unwrap();
            for w in list(&rec, "witnesses") {
                let word = hex(&w[0]);
                let vendor = w[1].as_str().unwrap();
                let (k, g, text) = decode_text(path, word).unwrap_or_else(|| panic!("{path}: witness {word:032x} does not decode"));
                assert_eq!((k.as_str(), g.as_str()), (key, group), "{path}: witness {word:032x}");
                assert_eq!(text, vendor, "{path}: witness {word:032x}");
                assert_eq!(reencode(table, word, vendor), word, "{path}: {vendor}");
                n64 += usize::from(group == "64");
            }
        }
        assert_eq!(n64, *n_64, "{path}: corpus witnesses of the .64 groups");
    }
}

/// The rows carry the tag and exactly sm120's measured field layout (mask == the fields, nothing baked under a field);
/// sm121a's dotted `UIADD3.64_*` harvest keys are aliases of the plain key of their form.
#[test]
fn the_rows_are_measured_and_the_dotted_keys_are_aliases() {
    for (path, _, _) in TABLES.iter() {
        let raw: Value = serde_json::from_slice(&cubit::table::read_table_bytes(path).unwrap()).unwrap();
        let ins = raw["instructions"].as_object().unwrap();
        for key in KEYS {
            for group in ["", "64"] {
                let g = &ins[key]["mod_groups"][group];
                assert_eq!(g["_src"], SOURCE, "{path}: {key} {group}");
                let mut field_mask = 0u128;
                let mut kinds = std::collections::BTreeSet::new();
                for f in g["fields"].as_array().unwrap() {
                    let bits = ((1u128 << f["bits"].as_u64().unwrap()) - 1) << f["shift"].as_u64().unwrap();
                    assert_eq!(field_mask & bits, 0, "{path}: {key} {group}: overlapping fields");
                    field_mask |= bits;
                    kinds.insert(format!("{}@{}", f["extraction"].as_str().unwrap(), f["shift"]));
                }
                assert_eq!(hex(&g["variable_mask"]), field_mask, "{path}: {key} {group}: mask == the fields");
                assert_eq!(hex(&g["and_base"]) & field_mask, 0, "{path}: {key} {group}: nothing baked under a field");
                for want in ["guard@12", "ureg@16", "ureg@24", "neg@72", "ureg@64", "neg@75"] {
                    assert!(kinds.contains(want), "{path}: {key} {group}: field {want} missing from {kinds:?}");
                }
                // the two carry-out predicates: `upred` on sm120's rows, the harvest's `pred` name on sm121a's plain row (the
                // probe verified the tokens; the printer renders UPn for the uniform family either way)
                for shift in [81, 84] {
                    assert!(kinds.contains(&format!("upred@{shift}")) || kinds.contains(&format!("pred@{shift}")), "{path}: {key} {group}: carry-out predicate at {shift} missing from {kinds:?}");
                }
                if key.ends_with("_II_UR") {
                    assert!(kinds.contains("imm@32"), "{path}: {key} {group}: the immediate");
                } else {
                    assert!(kinds.contains("ureg@32") && kinds.contains("neg@63"), "{path}: {key} {group}: URb and -URb");
                }
                let opc = hex(&g["and_base"]) & 0xfff;
                let want_opc = match (key.ends_with("_II_UR"), group) {
                    (false, "") => 0x290, (false, _) => 0x297, (true, "") => 0x890, (true, _) => 0x897,
                };
                assert_eq!(opc, want_opc, "{path}: {key} {group}: the .64 form is opcode bits [2:0] = 7");
            }
        }
        if *path == "tables/sm121a.json" {
            let aliases = raw["_meta"]["key_aliases"].as_object().unwrap();
            for (old, new) in [("UIADD3.64_UR_UP_UP_UR_UR_UR", "UIADD3_UR_UP_UP_UR_UR_UR"), ("UIADD3.64_UR_UP_UP_UR_II_UR", "UIADD3_UR_UP_UP_UR_II_UR"),
                               ("UIADD3.64_UR_UP_UP_UR_II_II", "UIADD3_UR_UP_UP_UR_II_UR")] {
                assert!(ins.get(old).is_none(), "{old} is still a key");
                assert_eq!(aliases[old], new, "{old}");
            }
        }
    }
}

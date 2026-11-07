// Shared body of the `sm120_rows_<family>` tests (session G run 5, 2026-11-07; KNOWN_ISSUES T1): the per-row
// field verification of the remaining harvest rows, measured by `tools/probes/re_sm120_rows.py` against nvdisasm
// 13.1 over the whole 128-bit word. The including file defines `FAMILY`, `SOURCE`, `MNEMONICS`, `FIXTURE`,
// `MEASURED_ROWS`, `ALIAS_ROWS`, `ALIAS_KEYS`, `FORM_WORDS`, `WITNESS_WORDS` and `EXCEPTIONS` (rows of the family's
// mnemonics that stay without `_src`, each with its reason). Fixture format: one header line, then one record per
// probed row -- `w0` / `t0` (the canonical word and NVIDIA's text), `fields` (the measured field list: shift, bits,
// token, extraction), `field` / `modifier` / `operand_other` / `glyph` / `complex` (bit, text) pairs for the
// single-bit flips of `w0`, `inert` / `illegal` bit lists, `witnesses` (census words with their own control code),
// `fields_add` / `fields_fix` (what the sweep changed against the harvest row), `silicon_bits` (field flips the
// encoder refuses on a silicon law, BUG-037) and `status` (`measured` / `alias` with `target` + `alias_target` /
// `exception` with `reason`).
use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;
use std::{collections::BTreeSet, path::PathBuf, sync::OnceLock};

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

fn raw_table() -> &'static Value {
    static RAW: OnceLock<Value> = OnceLock::new();
    RAW.get_or_init(|| serde_json::from_slice(&cubit::table::read_table_bytes(table_path()).unwrap()).unwrap())
}

struct Fixture {
    ctrl: u128,
    rows: Vec<Value>,
}

fn fixture() -> &'static Fixture {
    static FX: OnceLock<Fixture> = OnceLock::new();
    FX.get_or_init(|| {
        let mut lines = FIXTURE.lines().filter(|l| !l.trim().is_empty()).map(|l| serde_json::from_str::<Value>(l).unwrap());
        let header = lines.next().unwrap();
        assert_eq!(header["family"], FAMILY);
        assert!(header["nvdisasm"].as_str().unwrap().contains("cuda_13.1"), "{}", header["nvdisasm"]);
        let ctrl = u128::from_str_radix(header["ctrl"].as_str().unwrap(), 16).unwrap() << 96;
        Fixture { ctrl, rows: lines.collect() }
    })
}

fn mnemonic_of(key: &str) -> &str {
    key.split('_').next().unwrap().split('.').next().unwrap()
}

fn is_family_key(key: &str) -> bool {
    MNEMONICS.contains(&mnemonic_of(key))
}

fn hex(v: &Value) -> u128 {
    u128::from_str_radix(v.as_str().unwrap().trim_start_matches("0x"), 16).unwrap()
}

fn pairs<'a>(row: &'a Value, class: &str) -> Vec<(u32, &'a str)> {
    row.get(class).and_then(Value::as_array).map(|a| {
        a.iter().map(|p| (p[0].as_u64().unwrap() as u32, p[1].as_str().unwrap())).collect()
    }).unwrap_or_default()
}

fn bits(row: &Value, class: &str) -> Vec<u32> {
    row.get(class).and_then(Value::as_array).map(|a| a.iter().map(|b| b.as_u64().unwrap() as u32).collect()).unwrap_or_default()
}

fn reencode(table: &IsaTable, word: u128, text: &str) -> Result<u128, String> {
    let control = cubit::scheduling::format_control_code(
        &cubit::scheduling::decode_sched_upper32((word >> 96) as u32));
    let source = format!("[{control}] {text} ;");
    cubit::roundtrip_audit::check_semantic_source(&source).map_err(|e| e.to_string())?;
    let parsed = cubit::parse_cuasm_line(&source, 0).map_err(|e| e.to_string())?;
    assert!(parsed.hand_sched && parsed.rsd.is_none(), "{source}");
    cubit::encoder::encode_instruction(&parsed, table).map_err(|e| e.to_string())
}

/// The word decodes to `(key, group)`, prints NVIDIA's text and re-encodes bit for bit -- or, when the encoder
/// refuses the text on a silicon law (BUG-037: a multi-register MMA operand off its alignment), prints it only.
fn check_form(word: u128, vendor: &str, key: &str, group: &str, silicon_ok: bool) {
    let (table, index) = table_and_index();
    let decoded = index.decode(word, 0, table).unwrap_or_else(|e| panic!("{word:032x} ({vendor}): {e}"));
    assert_eq!((decoded.key.as_str(), decoded.mod_group.as_str()), (key, group), "{word:032x} ({vendor})");
    assert_eq!(cubit::printer::to_sass_lossless(&decoded), vendor, "{word:032x}");
    match reencode(table, word, vendor) {
        Ok(w) => assert_eq!(w, word, "{vendor}"),
        Err(e) if silicon_ok && e.contains("ILLEGAL on silicon") => {}
        Err(e) => panic!("{vendor}: {e}"),
    }
}

/// Every measured row's canonical word and every single-bit flip inside its fields (the register numbers, the
/// guard, the predicates, the immediates, the sign / abs / reuse bits -- including the ones the sweep added)
/// decodes to the row, prints NVIDIA's text and re-encodes bit for bit.
#[test]
fn every_canonical_and_field_word_matches_nvidia_and_reassembles_all_128_bits() {
    let fx = fixture();
    let (mut rows, mut words) = (0, 0);
    for row in &fx.rows {
        if row["status"] != "measured" {
            continue;
        }
        rows += 1;
        let (key, group) = (row["key"].as_str().unwrap(), row["group"].as_str().unwrap());
        let w0 = hex(&row["w0"]) | fx.ctrl;
        check_form(w0, row["t0"].as_str().unwrap(), key, group, row.get("silicon").is_some());
        words += 1;
        let silicon: BTreeSet<u32> = bits(row, "silicon_bits").into_iter().collect();
        for (bit, text) in pairs(row, "field") {
            check_form(w0 ^ (1u128 << bit), text, key, group, silicon.contains(&bit) || row.get("silicon").is_some());
            words += 1;
        }
    }
    assert_eq!((rows, words), (MEASURED_ROWS, FORM_WORDS), "measured rows / form words in the fixture");
}

/// The lattice of every measured row: the bits nvdisasm rejects and the text-inert bits never decode to the row
/// (its mask is exactly its fields -- fail closed, the convention of every measured family) and no row of this
/// measurement claims them; the modifier bits (other groups' words), the vendor-invalid glyph planes (`???n` /
/// `INVALIDn`), the neighbouring forms and the opcode neighbours print NVIDIA's text wherever a key of the family
/// claims them.
#[test]
fn the_lattice_around_each_row_is_fail_closed_and_vendor_true_where_claimed() {
    let fx = fixture();
    let (table, index) = table_and_index();
    let ins = raw_table()["instructions"].as_object().unwrap();
    let measured = |key: &str| ins.get(key).is_some_and(|e| {
        e["mod_groups"].as_object().unwrap().values().any(|g| g["_src"] == SOURCE)
    });
    let (mut closed, mut claimed, mut unclaimed) = (0usize, 0usize, 0usize);
    for row in &fx.rows {
        if row["status"] != "measured" {
            continue;
        }
        let (key, group) = (row["key"].as_str().unwrap(), row["group"].as_str().unwrap());
        let w0 = hex(&row["w0"]) | fx.ctrl;
        for bit in bits(row, "illegal").into_iter().chain(bits(row, "inert")) {
            // [127:96] is the control word for cubit's decoder (scheduling, yield, the `.reuse` hints the A12
            // doctrine decodes like any other word); nvdisasm names 96..104 text-inert on every row
            if bit >= 96 {
                continue;
            }
            let word = w0 ^ (1u128 << bit);
            if let Ok(d) = index.decode(word, 0, table) {
                assert_ne!((d.key.as_str(), d.mod_group.as_str()), (key, group), "{word:032x}: bit {bit} of {key} is not a field");
                assert!(!(is_family_key(&d.key) && measured(&d.key) && cubit::printer::to_sass_lossless(&d) == row["t0"]),
                        "{word:032x}: bit {bit} claimed by the measured {} / {} with the canonical text", d.key, d.mod_group);
            }
            closed += 1;
        }
        for class in ["modifier", "glyph", "operand_other", "complex"] {
            for (bit, text) in pairs(row, class) {
                let word = w0 ^ (1u128 << bit);
                match index.decode(word, 0, table) {
                    Ok(d) if is_family_key(&d.key) => {
                        assert_eq!(cubit::printer::to_sass_lossless(&d), text, "{word:032x} (bit {bit} of {key}, {class})");
                        match reencode(table, word, text) {
                            Ok(w) => assert_eq!(w, word, "{text}"),
                            Err(e) if e.contains("ILLEGAL on silicon") => {}
                            Err(e) => panic!("{text}: {e}"),
                        }
                        claimed += 1;
                    }
                    _ => unclaimed += 1,
                }
            }
        }
    }
    assert!(closed > 0 && claimed + unclaimed > 0, "{closed} {claimed} {unclaimed}");
}

/// The census witnesses of the rows (production words, their own control code) decode to the row, print
/// NVIDIA's text and re-encode bit for bit.
#[test]
fn the_census_witnesses_decode_vendor_true() {
    let fx = fixture();
    let mut n = 0;
    for row in &fx.rows {
        if row["status"] != "measured" {
            continue;
        }
        let (key, group) = (row["key"].as_str().unwrap(), row["group"].as_str().unwrap());
        for w in row["witnesses"].as_array().unwrap() {
            let word = hex(&w[0]);
            check_form(word, w[1].as_str().unwrap(), key, group, true);
            n += 1;
        }
    }
    assert_eq!(n, WITNESS_WORDS);
}

/// The table: every probed row carries the measurement tag, its mask is exactly its fields, nothing is baked under
/// a field, no control bit is baked; the retired keys are aliases whose canonical words decode through their
/// targets with NVIDIA's text; the provenance legend names the tag; every row of the family's mnemonics is
/// measured except the named exceptions.
#[test]
fn the_rows_are_measured_and_the_shadowed_keys_are_aliases() {
    let fx = fixture();
    let raw = raw_table();
    let ins = raw["instructions"].as_object().unwrap();
    let aliases = raw["_meta"]["key_aliases"].as_object().unwrap();
    let (table, index) = table_and_index();
    let mut measured = 0;
    let mut alias_rows = 0;
    for row in &fx.rows {
        let (key, group) = (row["key"].as_str().unwrap(), row["group"].as_str().unwrap());
        if row["status"] == "alias" {
            // the key is gone, its name forwards to `alias_target`; the row's own canonical word decodes through
            // the key that shadowed it (`target`) with NVIDIA's text
            let (target, alias_target) = (row["target"].as_str().unwrap(), row["alias_target"].as_str().unwrap());
            assert!(ins.get(key).is_none(), "{key} still a key");
            assert_eq!(aliases[key], alias_target, "{key}");
            assert!(ins.contains_key(alias_target) && ins.contains_key(target), "{alias_target} / {target}");
            let w0 = hex(&row["w0"]) | fx.ctrl;
            let d = index.decode(w0, 0, table).unwrap_or_else(|e| panic!("{w0:032x}: {e}"));
            assert_eq!(d.key, target, "{key}: {w0:032x}");
            assert_eq!(cubit::printer::to_sass_lossless(&d), row["t0"], "{key}: {w0:032x}");
            alias_rows += 1;
            continue;
        }
        if row["status"] == "exception" {
            assert!(EXCEPTIONS.iter().any(|(k, g, _)| *k == key && *g == group), "{key} {group}: exception not listed");
            continue;
        }
        assert_eq!(row["status"], "measured", "{key} {group}");
        let g = &ins[key]["mod_groups"][group];
        assert_eq!(g["_src"], SOURCE, "{key} {group}");
        let mut field_mask = 0u128;
        let mut have: Vec<(u64, u64, i64, String)> = Vec::new();
        for f in g["fields"].as_array().unwrap() {
            let b = ((1u128 << f["bits"].as_u64().unwrap()) - 1) << f["shift"].as_u64().unwrap();
            assert_eq!(field_mask & b, 0, "{key} {group}: overlapping fields");
            field_mask |= b;
            have.push((f["shift"].as_u64().unwrap(), f["bits"].as_u64().unwrap(), f["token_idx"].as_i64().unwrap(),
                       f["extraction"].as_str().unwrap().to_string()));
        }
        // the table carries exactly the measured field list of the fixture
        let mut want: Vec<(u64, u64, i64, String)> = row["fields"].as_array().unwrap().iter().map(|f| {
            (f[0].as_u64().unwrap(), f[1].as_u64().unwrap(), f[2].as_i64().unwrap(), f[3].as_str().unwrap().to_string())
        }).collect();
        have.sort();
        want.sort();
        assert_eq!(have, want, "{key} {group}: fields");
        assert_eq!(hex(&g["variable_mask"]), field_mask, "{key} {group}");
        let base = hex(&g["and_base"]);
        assert_eq!(base >> 105, 0, "{key} {group}");
        assert_eq!(base & field_mask, 0, "{key} {group}");
        measured += 1;
    }
    assert_eq!((measured, alias_rows), (MEASURED_ROWS, ALIAS_ROWS), "rows in the fixture");
    for (key, target) in ALIAS_KEYS {
        assert_eq!(aliases[*key], *target, "{key}");
    }
    assert_eq!(raw["_meta"]["provenance"]["sources"][SOURCE]["rows"], MEASURED_ROWS);
    let mut left = Vec::new();
    for (key, entry) in ins {
        if !is_family_key(key) {
            continue;
        }
        for (group, g) in entry["mod_groups"].as_object().unwrap() {
            if g["_src"].is_null() && !EXCEPTIONS.iter().any(|(k, gr, _)| k == key && gr == group) {
                left.push(format!("{key} / {group}"));
            }
        }
    }
    assert!(left.is_empty(), "harvest rows left on the family's mnemonics: {left:?}");
    for (key, group, reason) in EXCEPTIONS {
        assert!(ins[*key]["mod_groups"][*group]["_src"].is_null(), "{key} {group}: no longer an exception ({reason})");
    }
}

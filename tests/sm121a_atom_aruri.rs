//! SM121a (GB10 / Spark) global atomics ATOM / ATOMG in the plain uniform-indexed address form -- measured on `-b SM121`
//! (session T-22, 2026-11-08, `tools/probes/re_sm120_atom_aruri.py probe --arch SM121 --witnesses`, nvdisasm 13.1):
//! every form word prints the text the probe's law predicts (`-b SM120` / `SM103` / `SM100` print the same text for the
//! canonical words) and every lattice word is illegal, a vendor `INVALIDn` glyph, an inert-bit twin or another form's
//! word. `apply` created `ATOM_P_R_ARURI_R` / `ATOMG_P_R_ARURI_R` (8 640 + 9 600 measured groups: 2 (`.E`) x 9 / 10 ops
//! x 5 types x 6 cache policies x 16 scopes); the 3 456 + 3 456 dotted harvest keys of the form (the GB10 line's 2026-08/09
//! rides, `.E` x 9 ops x 4 types only) are `_meta.key_aliases` now. The 15 ATOMG words of the GB10 census corpus are the
//! descriptor form (`desc[UR][R.64]`), outside this form: 0 witnesses. T-6's `re_sm120_atomg_el_aruri.py` measured the
//! operand layout of this form on sm120 (the two `.EL` rows); `tests/sm121a_redg_aruri.rs` is the template.
use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;
use std::{path::PathBuf, sync::OnceLock};

const SOURCE: &str = "atom-aruri-family-2026-11-08";
const CTRL: u128 = 0x000f_e200u128 << 96;
const OPCS: [(&str, u128); 2] = [("ATOM", 0x98a), ("ATOMG", 0x9a8)];
const KEYS: [&str; 2] = ["ATOM_P_R_ARURI_R", "ATOMG_P_R_ARURI_R"];
const SCOPE: [&str; 16] = [
    "", "CONSTANT.PRIVATE", "CONSTANT.CTA", "CONSTANT.CTA.PRIVATE", "STRONG.SM.PRIVATE", "STRONG.SM", "STRONG.GPU.PRIVATE",
    "STRONG.GPU", "MMIO.GPU", "CONSTANT.SM", "STRONG.SYS", "CONSTANT.SM.PRIVATE", "MMIO.SYS", "CONSTANT.VC",
    "CONSTANT.VC.PRIVATE", "CONSTANT.GPU",
];
const CACHE: [&str; 6] = ["EF", "", "EL", "LU", "EU", "NA"];
const TYPE: [&str; 5] = ["", "S32", "64", "S64", "128"];
const OP: [&str; 10] = ["ADD", "MIN", "MAX", "INC", "DEC", "AND", "OR", "XOR", "EXCH", "SAFEADD"];
const FORM_WORDS: usize = 18398;
const LATTICE_WORDS: usize = 55;
const GROUPS: [(&str, usize); 2] = [("ATOM_P_R_ARURI_R", 8640), ("ATOMG_P_R_ARURI_R", 9600)];
const ALIASES: usize = 3456 + 3456;

fn is_family_key(k: &str) -> bool {
    KEYS.contains(&k)
}

fn is_retired_dotted(k: &str) -> bool {
    (k.starts_with("ATOM.") || k.starts_with("ATOMG.")) && k.ends_with("_P_R_ARURI_R")
}

fn table_path() -> PathBuf {
    std::env::var_os("CUBIT_TABLE_SM121A").map(PathBuf::from).unwrap_or_else(|| "tables/sm121a.json".into())
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
    include_str!("fixtures/sm121a_atom_aruri_nvdisasm.jsonl").lines().map(|l| serde_json::from_str(l).unwrap()).collect()
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

fn refused(table: &IsaTable, text: &str) -> bool {
    cubit::parser::parse_sass(text, 0).map_or(true, |p| cubit::encoder::encode_instruction(&p, table).is_err())
}

/// Decode, print (display and lossless = the vendor text) and re-encode bit for bit.
fn check(word: u128, vendor: &str) -> (String, String) {
    let (table, index) = table_and_index();
    let decoded = index.decode(word, 0, table).unwrap_or_else(|e| panic!("{word:032x}: {e}"));
    assert!(is_family_key(&decoded.key), "{word:032x}: {}", decoded.key);
    assert_eq!(cubit::printer::to_sass(&decoded), vendor, "{word:032x} (display print)");
    assert_eq!(cubit::printer::to_sass_lossless(&decoded), vendor, "{word:032x} (lossless print)");
    assert_eq!(reencode(table, word, vendor), word, "{vendor}");
    (decoded.key.clone(), decoded.mod_group.clone())
}

/// The modifier bits a group name stands for (the probe's law) in [90:72].
fn law(name: &str) -> u128 {
    let toks: Vec<&str> = name.split(',').collect();
    let has = |t: &str| toks.contains(&t);
    let e = u128::from(has("E"));
    let op = OP.iter().position(|o| has(o)).unwrap_or_else(|| panic!("{name}: no op")) as u128;
    let ty = TYPE.iter().position(|t| !t.is_empty() && has(t)).unwrap_or(0) as u128;
    let cache = CACHE.iter().position(|c| !c.is_empty() && has(c)).unwrap_or(1) as u128;
    let rest: Vec<&str> = toks.iter().copied()
        .filter(|t| *t != "E" && !OP.contains(t) && !TYPE.contains(t) && !CACHE.contains(t)).collect();
    let scope = SCOPE.iter().position(|s| {
        let mut want: Vec<&str> = s.split('.').filter(|t| !t.is_empty()).collect();
        let mut got = rest.clone();
        want.sort_unstable();
        got.sort_unstable();
        want == got
    }).unwrap_or_else(|| panic!("{name}: no scope enum value spells {rest:?}")) as u128;
    (e << 72) | (op << 87) | (ty << 73) | (cache << 84) | (scope << 77)
}

/// Every form word (the 18 240 groups on the canonical operands, the operand lattice of two groups per key -- guard,
/// Pd, Rd / Ra / Rb / URb at 0, 1, 63 and 255, the offsets +0x1 / +0x10 / +0x1234 / +0x3fffff / -0x400000 / -0x1 -- and
/// one word per key with every field away from its canonical value) decodes to the two keys, prints NVIDIA's text and
/// re-encodes bit for bit.
#[test]
fn every_probed_word_matches_nvidia_and_reassembles_all_128_bits() {
    let mut n = 0;
    let mut groups = std::collections::BTreeSet::new();
    for row in fixture() {
        if row.get("lattice").is_some() || row.get("witness").is_some() {
            continue;
        }
        groups.insert(check(word_of(&row), row["nvidia_sass"].as_str().unwrap()));
        n += 1;
    }
    assert_eq!(n, FORM_WORDS, "form words in the fixture");
    assert_eq!(groups.len(), 8640 + 9600, "every group of the two keys has a form word");
}

/// The lattice: bit 91 clear (the `[Ra(+off)]` form), the text-inert bits 92-95, the INVALID op / type / cache planes,
/// the `.64` base (bit 63, another key's form), the descriptor bit alone (illegal) and with the base (the `desc[UR][R.64]`
/// form) -- never claimed by the two keys: undecoded, or (a legal word of another form) decoded to another key with the
/// vendor's text. The encoder refuses the unmodelled spellings.
#[test]
fn the_lattice_around_the_form_is_never_rendered_as_another_text() {
    let (table, index) = table_and_index();
    let (mut n, mut undecoded, mut other, mut harvest_claims) = (0, 0, 0, 0);
    for row in fixture() {
        if row.get("lattice").is_none() || row.get("witness").is_some() {
            continue;
        }
        n += 1;
        let word = word_of(&row);
        let vendor = row["nvidia_sass"].as_str();
        match index.decode(word, 0, table) {
            Err(_) => undecoded += 1,
            Ok(d) => {
                let text = cubit::printer::to_sass_lossless(&d);
                assert!(!is_family_key(&d.key), "lattice word {word:032x} ({vendor:?}) claimed by {} as {text}", d.key);
                let Some(vendor) = vendor else {
                    // nvdisasm rejects the word (the descriptor bit 76 without the `.64` base) and a HARVEST row claims it:
                    // the sm121a `ATOM[G]_P_R_dARI_R` descriptor-form rows (the wave-11 lattice's sm121a twins, no `_src`;
                    // their masks tolerate bit 63) -- the next batch of the sm121a line, outside this family. Pinned here
                    // so the class is counted, not hidden: a measured row never claims such a word.
                    assert!((word >> 76) & 1 == 1 && (word >> 63) & 1 == 0, "illegal word {word:032x} decodes through {} as {text}", d.key);
                    let raw: Value = serde_json::from_slice(&cubit::table::read_table_bytes(table_path()).unwrap()).unwrap();
                    let row = &raw["instructions"][&d.key]["mod_groups"][&d.mod_group];
                    assert!(row["_src"].is_null(), "illegal word {word:032x} claimed by the measured row {} {} as {text}", d.key, d.mod_group);
                    harvest_claims += 1;
                    continue;
                };
                assert!(!vendor.contains("???") && !vendor.contains("INVALID"), "{word:032x}: the vendor's glyph {vendor} decodes through {} as {text}", d.key);
                assert_eq!(text, vendor, "{word:032x}: another form's word through {}", d.key);
                other += 1;
            }
        }
    }
    assert_eq!(n, LATTICE_WORDS);
    assert_eq!(undecoded + other + harvest_claims, n);
    assert!(harvest_claims <= 2, "{harvest_claims} illegal words claimed by harvest rows (the two descriptor-bit-alone words at most)");
    for text in ["ATOMG.E.ADD.INVALID5.STRONG.GPU PT, R4, [R2.U32+UR4], R6", "ATOMG.E.ADD.INVALID6.STRONG.GPU PT, R4, [R2.U32+UR4], R6",
                 "ATOMG.E.INVALID10.STRONG.GPU PT, R4, [R2.U32+UR4], R6", "ATOM.E.SAFEADD.STRONG.GPU PT, R4, [R2.U32+UR4], R6",
                 "ATOMG.E.ADD.STRONG PT, R4, [R2.U32+UR4], R6", "ATOMG.E.ADD.STRONG.GPU PT, R4, [R2.U32+UR4+0x800000], R6"] {
        assert!(refused(table, text), "{text} must be refused");
    }
}

/// The operand law on a few words: Pd and the guard, RZ / URZ, the no-`.E` plane, the `.128` type, SAFEADD on ATOMG
/// alone, a negative offset, the `.64` base and the descriptor form belong to other keys.
#[test]
fn the_operand_and_modifier_law() {
    let (table, index) = table_and_index();
    let base = 0x000fe200081ee10400000006020479a8u128; // ATOMG.E.ADD.STRONG.GPU PT, R4, [R2.U32+UR4], R6
    let text = |w: u128| index.decode(w, 0, table).map(|d| cubit::printer::to_sass(&d)).unwrap_or_else(|e| panic!("{w:032x}: {e}"));
    let key = |w: u128| index.decode(w, 0, table).map(|d| d.key).unwrap_or_else(|e| panic!("{w:032x}: {e}"));
    assert_eq!(text(base), "ATOMG.E.ADD.STRONG.GPU PT, R4, [R2.U32+UR4], R6");
    assert_eq!(key(base), "ATOMG_P_R_ARURI_R");
    assert_eq!(key(base & !0xfffu128 | 0x98a), "ATOM_P_R_ARURI_R");
    assert_eq!(text(base & !0xfffu128 | 0x98a), "ATOM.E.ADD.STRONG.GPU PT, R4, [R2.U32+UR4], R6");
    let guarded = (base & !(0xfu128 << 12) & !(7u128 << 81)) | (8u128 << 12) | (2u128 << 81);
    assert_eq!(text(guarded), "@!P0 ATOMG.E.ADD.STRONG.GPU P2, R4, [R2.U32+UR4], R6");
    assert_eq!(reencode(table, guarded, "@!P0 ATOMG.E.ADD.STRONG.GPU P2, R4, [R2.U32+UR4], R6"), guarded);
    let rz = base | (0xffu128 << 24) | (0xffu128 << 64) | (0xffu128 << 16);
    assert_eq!(text(rz), "ATOMG.E.ADD.STRONG.GPU PT, RZ, [RZ.U32+URZ], R6");
    assert_eq!(reencode(table, rz, "ATOMG.E.ADD.STRONG.GPU PT, RZ, [RZ.U32+URZ], R6"), rz);
    let no_e = base & !(1u128 << 72);
    assert_eq!(text(no_e), "ATOMG.ADD.STRONG.GPU PT, R4, [R2.U32+UR4], R6");
    assert_eq!(reencode(table, no_e, "ATOMG.ADD.STRONG.GPU PT, R4, [R2.U32+UR4], R6"), no_e);
    let t128 = base | (4u128 << 73);
    assert_eq!(text(t128), "ATOMG.E.ADD.128.STRONG.GPU PT, R4, [R2.U32+UR4], R6");
    let safeadd = base | (9u128 << 87);
    assert_eq!(text(safeadd), "ATOMG.E.SAFEADD.STRONG.GPU PT, R4, [R2.U32+UR4], R6");
    assert!(index.decode(safeadd & !0xfffu128 | 0x98a, 0, table).is_err(), "ATOM has no SAFEADD (the vendor's INVALID9)");
    let neg = base | (0x7fffffu128 << 40);
    assert_eq!(text(neg), "ATOMG.E.ADD.STRONG.GPU PT, R4, [R2.U32+UR4+-0x1], R6");
    assert_eq!(reencode(table, neg, "ATOMG.E.ADD.STRONG.GPU PT, R4, [R2.U32+UR4+-0x1], R6"), neg);
    let big = base | (0x400000u128 << 40);
    assert_eq!(text(big), "ATOMG.E.ADD.STRONG.GPU PT, R4, [R2.U32+UR4+-0x400000], R6");
    let typed = (base | (3u128 << 73) | (7u128 << 87) | (5u128 << 84)) & !(0xfu128 << 77) | (14u128 << 77);
    assert_eq!(text(typed), "ATOMG.E.XOR.NA.S64.CONSTANT.VC.PRIVATE PT, R4, [R2.U32+UR4], R6"); // the cache policy prints before the type
    // the `.64` base and the descriptor form: never these keys
    for w in [base | (1u128 << 63), base | (1u128 << 63) | (1u128 << 76)] {
        if let Ok(d) = index.decode(w, 0, table) {
            assert!(!is_family_key(&d.key), "{w:032x} claimed by {}", d.key);
        }
    }
    // the descriptor bit without the `.64` base is illegal for nvdisasm; cubit's harvest `ATOMG_P_R_dARI_R` row (the
    // wave-11 lattice's sm121a twin, no `_src`, its mask tolerating bit 63) still claims the word -- never this key
    if let Ok(d) = index.decode(base | (1u128 << 76), 0, table) {
        assert_eq!(d.key, "ATOMG_P_R_dARI_R", "the descriptor-bit-alone word: {}", d.key);
    }
}

/// The two keys carry their full measured lattice (`_src`, mask == the fields, nothing baked under a field, the
/// opcode, bit 91 and the modifier bits of their group name and nothing else, `claim_forbid` on bits 63 / 76), no
/// dotted `_P_R_ARURI_R` key is left, the 6 912 aliases point at the plain key of their opcode and name one of its
/// groups, the legend = the live count.
#[test]
fn the_rows_are_measured_and_the_dotted_keys_are_gone() {
    let raw: Value = serde_json::from_slice(&cubit::table::read_table_bytes(table_path()).unwrap()).unwrap();
    let ins = raw["instructions"].as_object().unwrap();
    let left: Vec<&String> = ins.keys().filter(|k| is_retired_dotted(k)).collect();
    assert!(left.is_empty(), "{left:?}");
    let aliases = raw["_meta"]["key_aliases"].as_object().unwrap();
    let mut n_alias = 0;
    for (old, new) in aliases {
        if !is_retired_dotted(old) {
            continue;
        }
        n_alias += 1;
        let new = new.as_str().unwrap();
        let (mn, _sig) = old.split_once('_').unwrap();
        let base = mn.split('.').next().unwrap();
        assert_eq!(new, format!("{base}_P_R_ARURI_R"), "{old} -> {new}");
        assert!(ins.get(old).is_none(), "{old} still a key");
        assert!(is_family_key(new), "{old} -> {new}");
        let mut toks: Vec<&str> = mn.split('.').skip(1).collect();
        toks.sort_unstable();
        let group = toks.join(",");
        assert!(ins[new]["mod_groups"].get(&group).is_some(), "{old}: its spelling names no group {group} of {new}");
    }
    assert_eq!(n_alias, ALIASES, "the dotted one-group keys of the form");
    let tagged = ins.values().filter_map(|e| e["mod_groups"].as_object()).flat_map(|m| m.values()).filter(|g| g["_src"] == SOURCE).count();
    assert_eq!(raw["_meta"]["provenance"]["sources"][SOURCE]["rows"], tagged);
    assert_eq!(tagged, 8640 + 9600);
    let number = |v: &Value| u128::from_str_radix(v.as_str().unwrap().trim_start_matches("0x"), 16).unwrap();
    for ((key, n_groups), (mn, opc)) in GROUPS.iter().zip(OPCS.iter()) {
        assert_eq!(ins[*key]["_src"], SOURCE, "{key}");
        assert_eq!(ins[*key]["base_op"], *mn, "{key}");
        let groups = ins[*key]["mod_groups"].as_object().unwrap();
        assert_eq!(groups.len(), *n_groups, "{key}");
        for (name, g) in groups {
            assert_eq!(g["_src"], SOURCE, "{key} {name}");
            assert!(g["count"].is_null(), "{key} {name}: measured rows carry no harvest count");
            let mut field_mask = 0u128;
            let mut kinds = std::collections::BTreeSet::new();
            for f in g["fields"].as_array().unwrap() {
                let bits = ((1u128 << f["bits"].as_u64().unwrap()) - 1) << f["shift"].as_u64().unwrap();
                assert_eq!(field_mask & bits, 0, "{name}: overlapping fields");
                field_mask |= bits;
                kinds.insert(format!("{}@{}:{}#{}", f["extraction"].as_str().unwrap(), f["shift"], f["bits"], f["token_idx"]));
            }
            assert_eq!(number(&g["variable_mask"]), field_mask, "{key} {name}");
            let base = number(&g["and_base"]);
            assert_eq!(base & field_mask, 0, "{key} {name}");
            assert_eq!(base >> 96, 0, "{key} {name}");
            assert_eq!(base, opc | (1u128 << 91) | law(name), "{key} {name}: and_base = opcode + bit 91 + the modifier bits of the name");
            let want: std::collections::BTreeSet<String> = ["guard@12:4#0", "pred@81:3#1", "reg@16:8#2", "reg@24:8#3", "ureg@64:8#3", "imm@40:23#3", "reg@32:8#4"]
                .into_iter().map(String::from).collect();
            assert_eq!(kinds, want, "{key} {name}: the fields");
            let forbid: Vec<u64> = g["claim_forbid"].as_array().unwrap().iter().map(|c| c["shift"].as_u64().unwrap()).collect();
            assert_eq!(forbid, [63, 76], "{key} {name}: the .64 base and the descriptor bit are other forms");
        }
    }
}

/// Every retired dotted key round-trips through the plain key: the text its spelling names (`ATOM[G].<mods> PT, R4,
/// [R2.U32+UR4], R6`) encodes to a word that decodes to the alias's target and the group its tokens name, and prints
/// the same text back.
#[test]
fn every_alias_round_trips_through_the_plain_key() {
    let (table, index) = table_and_index();
    let raw: Value = serde_json::from_slice(&cubit::table::read_table_bytes(table_path()).unwrap()).unwrap();
    let aliases = raw["_meta"]["key_aliases"].as_object().unwrap();
    let mut n = 0;
    for (old, new) in aliases {
        if !is_retired_dotted(old) {
            continue;
        }
        n += 1;
        let (mn, _sig) = old.split_once('_').unwrap();
        let text = format!("{mn} PT, R4, [R2.U32+UR4], R6");
        let parsed = cubit::parser::parse_sass(&text, 0).unwrap_or_else(|e| panic!("{text}: {e}"));
        let word = cubit::encoder::encode_instruction(&parsed, table).unwrap_or_else(|e| panic!("{text}: {e}")) | CTRL;
        let d = index.decode(word, 0, table).unwrap_or_else(|e| panic!("{text}: {word:032x}: {e}"));
        assert_eq!(d.key, new.as_str().unwrap(), "{text}");
        let mut toks: Vec<&str> = mn.split('.').skip(1).collect();
        toks.sort_unstable();
        assert_eq!(d.mod_group, toks.join(","), "{text}");
        assert_eq!(cubit::printer::to_sass(&d), text, "{old}");
    }
    assert_eq!(n, ALIASES);
}

/// The ATOM / ATOMG words of the GB10 census corpus are all the descriptor form (`desc[UR][R.64]`), outside the
/// uniform-indexed form this probe measures: the fixture carries no witness row (the count is pinned so a corpus
/// refresh that brings one is noticed).
#[test]
fn the_gb10_census_words_of_the_form_round_trip() {
    let mut n = 0;
    for row in fixture() {
        if row.get("witness").is_none() {
            continue;
        }
        let vendor = row["nvidia_sass"].as_str().unwrap();
        let word = u128::from_str_radix(row["word"].as_str().unwrap(), 16).unwrap();
        let (table, index) = table_and_index();
        let decoded = index.decode(word, 0, table).unwrap_or_else(|e| panic!("{word:032x}: {e}"));
        assert!(is_family_key(&decoded.key), "{word:032x}: {}", decoded.key);
        assert_eq!(cubit::printer::to_sass_lossless(&decoded), vendor, "{word:032x}");
        assert_eq!(reencode(table, word, vendor), word, "{vendor}");
        n += 1;
    }
    assert_eq!(n, 0, "the GB10 census words of the form in the fixture");
}

//! SM120 float conversions F2I / I2F / FRND and the MUFU transcendentals rebuilt from measurement (session G,
//! 2026-11-07; KNOWN_ISSUES T1): the 12 plain keys `{F2I,I2F,FRND,MUFU}_R_{R,UR,FI|II}` carry the rows
//! `tools/probes/re_sm120_conv.py` measures with nvdisasm 13.1 (2 494 form + 18 glyph + 547 lattice words; the same
//! text on `-b SM103` / `SM100`). Law: guard [15:12]; Rd [23:16]; the source at [39:32] (Ra / URa with `|` 62 / `-` 63
//! except on I2F) or the immediate at [63:32] (f32 / the f16 or bf16 half / the f64 high dword / the integer, by the
//! group's type); F2I = destination width [76:75] + signed 72, source type [86:84], NTZ 77, rounding [79:78], FTZ 80,
//! printed `F2I[.FTZ][.dst][.src][.FLOOR|.CEIL|.TRUNC][.NTZ]` (S32 and F32 unspelled; the 64-bit destinations and
//! the F64 source on opcode 0x311, the rest on 0x305); I2F = destination type [77:75], source width [85:84] + signed
//! 74, rounding [79:78], the byte selector [61:60] / `.H1` 60 on the 8- / 16-bit sources (`I2F[.dst][.src][.RM|.RP|
//! .RZ] Rd, Ra[.B1|.B2|.B3|.H1]`; the F16 / BF16 sources of F2I / FRND / MUFU take `.H1` too, inside the sign wrapper: `-|R2.H1|`; F64 destination / 64-bit sources on 0x312; the immediate only for the 32- and
//! 64-bit sources, signed hex for the signed types); FRND = type [77:75] = [86:84], FTZ 80, rounding (`FRND[.FTZ]
//! [.type][.FLOOR|.CEIL|.TRUNC]`; F64 on 0x313); MUFU = function [77:74], half type [73:72] (`MUFU.<fn>[.F16|
//! .BF16]`; RCP64H / RSQ64H take no half type). The uniform forms = + 0xc00 + bit 91, the immediate forms = + 0x800;
//! no `.reuse` (text-inert on the family). Retired: the 207 dotted F2I keys, `I2F.RP_R_R`, the four dotted FRND keys
//! and the integer-spelling `MUFU_R_II` as `_meta.key_aliases` of the plain key of their operand signature; 10 of T's 26
//! `MUFU_R_UR` rows (`mufu-ur-sm120-2026-11-04`) are reproduced field for field and kept (the .F16 / .BF16 rows gain `.H1`).
use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;
use std::{path::PathBuf, sync::OnceLock};

const SOURCE: &str = "conv-family-2026-11-07";
const KEPT: &str = "mufu-ur-sm120-2026-11-04";
const CTRL: u128 = 0x000f_e200u128 << 96;
const KEYS: [(&str, usize); 12] = [
    ("F2I_R_R", 512), ("F2I_R_UR", 512), ("F2I_R_FI", 512),
    ("I2F_R_R", 128), ("I2F_R_UR", 128), ("I2F_R_II", 64),
    ("FRND_R_R", 32), ("FRND_R_UR", 32), ("FRND_R_FI", 32),
    ("MUFU_R_R", 26), ("MUFU_R_UR", 26), ("MUFU_R_FI", 26),
];
const INT_TYPES: [(&str, u128, u128); 8] = [
    ("U8", 0, 0), ("S8", 0, 1), ("U16", 1, 0), ("S16", 1, 1), ("U32", 2, 0), ("S32", 2, 1), ("U64", 3, 0), ("S64", 3, 1),
];
const FLOAT_TYPES: [(&str, u128); 4] = [("F16", 1), ("F32", 2), ("F64", 3), ("BF16", 4)];
const MUFU_FN: [&str; 10] = ["COS", "SIN", "EX2", "LG2", "RCP", "RSQ", "RCP64H", "RSQ64H", "SQRT", "TANH"];

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
    include_str!("fixtures/sm120_conv_nvdisasm.jsonl").lines().map(|l| serde_json::from_str(l).unwrap()).collect()
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

/// Every form word (the 2 030 groups on the canonical operands, the operand lattice of two groups per key -- guard,
/// Rd / Ra / URa at 0, 1, 63 and 255, the signs where the mnemonic has them, the I2F byte / half selectors on R and
/// UR, the immediates of every kind incl. `+INF`, `-INF`, `-0.0`, the denormals and the signed / unsigned integers --
/// and one word per key with every field away from its canonical value) decodes to the 12 keys, prints NVIDIA's text
/// and re-encodes bit for bit.
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
    assert_eq!(n, 2494, "form words in the fixture");
    assert_eq!(groups.len(), 2030, "512 x 3 F2I + 128 + 128 + 64 I2F + 32 x 3 FRND + 26 x 3 MUFU groups");
}

/// The NaN immediates of every float kind (f32, the f16 / bf16 halves, the f64 high dword): nvdisasm prints the
/// `+QNAN` / `-QNAN` / `+SNAN` glyph, cubit's display print does the same and the lossless print keeps the payload
/// as a hexadecimal that re-encodes (KNOWN_ISSUES A8).
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
    assert_eq!(n, 18);
}

/// The lattice: the frame bit flipped, the text-inert bits (incl. the high half above a half immediate), the
/// vendor-invalid glyph states (`F2I.???7`, `I2F.???0`, `R2.INVALID2`, `FRND.???19`, `MUFU.INVALID10`,
/// `MUFU.INVALID6.F16`) and the illegal combinations -- never claimed. The encoder refuses the unmodelled spellings.
#[test]
fn the_lattice_around_the_form_is_never_rendered_as_another_text() {
    let (table, index) = table_and_index();
    let (mut n, mut undecoded) = (0, 0);
    for row in fixture() {
        if row.get("lattice").is_none() {
            continue;
        }
        n += 1;
        let word = word_of(&row);
        match index.decode(word, 0, table) {
            Err(_) => undecoded += 1,
            Ok(d) => panic!("lattice word {word:032x} ({:?}) decodes as {}", row["nvidia_sass"], cubit::printer::to_sass_lossless(&d)),
        }
    }
    assert_eq!((n, undecoded), (547, 547));
    for text in ["F2I.U32.F32 R4, R2", "I2F.F32 R4, R2", "I2F.S8 R4, 0x10", "I2F.S16 R4, R2.B1", "FRND.F64.F32 R4, R2",
                 "MUFU.RCP64H.F16 R4, R2", "MUFU.INVALID10 R4, R2", "F2I.U32.F64.F16 R4, R2", "FRND.FLOOR R4, R2.H1"] {
        let refused = cubit::parser::parse_sass(text, 0).map_or(true, |p| cubit::encoder::encode_instruction(&p, table).is_err());
        assert!(refused, "{text} must be refused");
    }
}

/// The modifier bits a group name stands for (the probe's law), as (opcode of the register form, bits in [90:72]
/// and [86:84]) -- used to check every row's and_base against its name.
fn law(key: &str, name: &str) -> (u128, u128) {
    let toks: Vec<&str> = name.split(',').filter(|t| !t.is_empty()).collect();
    let has = |t: &str| toks.contains(&t);
    let rnd_f2i = if has("FLOOR") { 1 } else if has("CEIL") { 2 } else if has("TRUNC") { 3 } else { 0 };
    let rnd_i2f = if has("RM") { 1 } else if has("RP") { 2 } else if has("RZ") { 3 } else { 0 };
    let int_type = INT_TYPES.iter().find(|(t, _, _)| has(t)).copied().unwrap_or(("S32", 2, 1));
    let float_type = FLOAT_TYPES.iter().find(|(t, _)| has(t)).copied().unwrap_or(("F32", 2));
    if key.starts_with("F2I") {
        let opc = if int_type.1 == 3 || float_type.0 == "F64" { 0x311 } else { 0x305 };
        (opc, (int_type.1 << 75) | (int_type.2 << 72) | (float_type.1 << 84) | ((has("FTZ") as u128) << 80) | (rnd_f2i << 78) | ((has("NTZ") as u128) << 77))
    } else if key.starts_with("I2F") {
        let opc = if float_type.0 == "F64" || int_type.1 == 3 { 0x312 } else { 0x306 };
        (opc, (float_type.1 << 75) | (int_type.1 << 84) | (int_type.2 << 74) | (rnd_i2f << 78))
    } else if key.starts_with("FRND") {
        let opc = if float_type.0 == "F64" { 0x313 } else { 0x307 };
        (opc, (float_type.1 << 75) | (float_type.1 << 84) | ((has("FTZ") as u128) << 80) | (rnd_f2i << 78))
    } else {
        let fn_ = MUFU_FN.iter().position(|f| has(f)).unwrap() as u128;
        let half = if has("F16") { 1 } else if has("BF16") { 2 } else { 0 };
        (0x308, (fn_ << 74) | (half << 72))
    }
}

/// The 12 keys carry their full measured lattice (`_src`, mask == the fields, nothing baked under a field, the
/// opcode and modifier bits of their group name and nothing else, the right immediate kind per group), the 213
/// junk keys are aliases of the plain key of their operand signature and no dotted F2I / I2F / FRND key is left, the
/// provenance legend names the tag, T's 10 half-less MUFU_R_UR rows keep theirs.
#[test]
fn the_rows_are_measured_and_the_junk_keys_are_gone() {
    let raw: Value = serde_json::from_slice(&cubit::table::read_table_bytes(table_path()).unwrap()).unwrap();
    let ins = raw["instructions"].as_object().unwrap();
    let left: Vec<&String> = ins.keys()
        .filter(|k| ["F2I_", "F2I.", "I2F_", "I2F.", "FRND_", "FRND.", "MUFU_", "MUFU."].iter().any(|p| k.starts_with(p)))
        .filter(|k| !is_family_key(k)).collect();
    assert!(left.is_empty(), "{left:?}");
    let aliases = raw["_meta"]["key_aliases"].as_object().unwrap();
    let mut n_alias = 0;
    for (old, new) in aliases {
        let mn = old.split(['.', '_']).next().unwrap();
        if !matches!(mn, "F2I" | "I2F" | "FRND" | "MUFU") {
            continue;
        }
        n_alias += 1;
        let new = new.as_str().unwrap();
        if old == "MUFU_R_II" {
            assert_eq!(new, "MUFU_R_FI");
        } else {
            assert!(old.contains('.'), "{old}: a plain key aliased");
            let sig = old.split_once('_').unwrap().1;
            assert_eq!(new, format!("{mn}_{sig}"), "{old} -> {new}");
        }
        assert!(ins.get(old).is_none(), "{old} still a key");
        assert!(is_family_key(new), "{old} -> {new}");
    }
    assert_eq!(n_alias, 213, "207 F2I + 1 I2F + 4 FRND + MUFU_R_II");
    assert_eq!(raw["_meta"]["provenance"]["sources"][SOURCE]["rows"], 2020);
    let number = |v: &Value| u128::from_str_radix(v.as_str().unwrap().trim_start_matches("0x"), 16).unwrap();
    let mut kept = 0;
    for (key, count) in KEYS {
        assert_eq!(ins[key]["_src"], SOURCE, "{key}");
        let groups = ins[key]["mod_groups"].as_object().unwrap();
        assert_eq!(groups.len(), count, "{key}");
        let form = key.rsplit('_').next().unwrap();
        for (name, g) in groups {
            if g["_src"] == KEPT {
                kept += 1;
            } else {
                assert_eq!(g["_src"], SOURCE, "{key} {name}");
                assert!(g["count"].is_null(), "{key} {name}: measured rows carry no harvest count");
            }
            let mut field_mask = 0u128;
            let mut imm_kind = None;
            for f in g["fields"].as_array().unwrap() {
                let bits = ((1u128 << f["bits"].as_u64().unwrap()) - 1) << f["shift"].as_u64().unwrap();
                assert_eq!(field_mask & bits, 0, "{name}: overlapping fields");
                field_mask |= bits;
                if f["token_idx"] == 2 && f["shift"] == 32 && f["bits"].as_u64().unwrap() > 8 {
                    imm_kind = Some((f["extraction"].as_str().unwrap().to_string(), f["bits"].as_u64().unwrap()));
                }
            }
            assert_eq!(number(&g["variable_mask"]), field_mask, "{key} {name}");
            let base = number(&g["and_base"]);
            assert_eq!(base >> 105, 0, "{key} {name}");
            assert_eq!(base & field_mask, 0, "{key} {name}");
            let (opc, bits) = law(key, name);
            let want_opc = match form { "R" => opc, "UR" => (opc & 0x1ff) | 0xc00, _ => (opc & 0x1ff) | 0x800 };
            assert_eq!(base & 0xfff, want_opc, "{key} {name}: opcode");
            assert_eq!((base >> 91) & 1 == 1, form == "UR", "{key} {name}: the uniform frame bit");
            assert_eq!(base & !0xfffu128 & !(1u128 << 91), bits, "{key} {name}: the modifier bits of the name");
            assert_eq!(field_mask >> 105, 0, "{key} {name}: no .reuse field on the family");
            assert_ne!(field_mask & (1u128 << 12), 0, "{key} {name}: the guard is a field");
            assert_eq!(field_mask & (0xffu128 << 16), 0xffu128 << 16, "{key} {name}: Rd is a field");
            // the immediate kind follows the group's float type (F2I / FRND: the source / the type; MUFU: f64hi on
            // the 64-bit halves, the half on .F16 / .BF16); I2F's immediate is the integer
            if form == "FI" || form == "II" {
                let toks: Vec<&str> = name.split(',').collect();
                let want = if key.starts_with("I2F") { ("imm", 32) }
                    else if key.starts_with("MUFU") {
                        if toks.contains(&"F16") { ("f16", 16) } else if toks.contains(&"BF16") { ("bf16", 16) }
                        else if toks.contains(&"RCP64H") || toks.contains(&"RSQ64H") { ("f64hi", 32) } else { ("f32", 32) }
                    } else if toks.contains(&"F16") { ("f16", 16) } else if toks.contains(&"BF16") { ("bf16", 16) }
                    else if toks.contains(&"F64") { ("f64hi", 32) } else { ("f32", 32) };
                let got = imm_kind.clone().unwrap_or_else(|| panic!("{key} {name}: no immediate field"));
                assert_eq!((got.0.as_str(), got.1), want, "{key} {name}: immediate kind");
            } else {
                assert_eq!(field_mask & (0xffu128 << 32), 0xffu128 << 32, "{key} {name}: the source register is a field");
                let signs = field_mask & (3u128 << 62) != 0;
                assert_eq!(signs, !key.starts_with("I2F"), "{key} {name}: |Ra| / -Ra fields");
                let sel = (field_mask >> 60) & 3;
                let toks: Vec<&str> = name.split(',').collect();
                let want = if key.starts_with("I2F") {
                    if toks.iter().any(|t| matches!(*t, "U8" | "S8")) { 3 } else if toks.iter().any(|t| matches!(*t, "U16" | "S16")) { 1 } else { 0 }
                } else if toks.iter().any(|t| matches!(*t, "F16" | "BF16")) { 1 } else { 0 };
                assert_eq!(sel, want, "{key} {name}: the byte / half selector field ([61:60] on the 8-bit integer sources, .H1 at 60 on the 16-bit ones)");
            }
        }
    }
    assert_eq!(kept, 10, "T's MUFU_R_UR rows without a half type reproduced field for field (the 16 .F16 / .BF16 rows gain the .H1 selector)");
}

/// Production census witnesses: the harvest `F2I.FTZ.U32.TRUNC.NTZ_R_R` (190 distinct words, now a group of the plain
/// key), the I2F / MUFU workhorses, the `MUFU_R_II` NaN-immediate word (`-QNAN` on the f32 key now) and a hexadecimal
/// f32 literal through the `MUFU_R_II` alias.
#[test]
fn witness_words_round_trip() {
    for (word, vendor) in [
        (0x000064000021f0000000000200037305u128, "F2I.FTZ.U32.TRUNC.NTZ R3, R2"),
        (0x000e64000020f0000000000800087305u128, "F2I.U32.TRUNC.NTZ R8, R8"),
        (0x000e24000020d8000000000200027311u128, "F2I.U64.TRUNC R2, R2"),
        (0x000e2200002094000000000400097306u128, "I2F.RP R9, R4"),
        (0x000e22000020900000000000000d7306u128, "I2F.U32.RP R13, R0"),
        (0x000e2400003090000000000400077312u128, "I2F.U64.RP R7, R4"),
        (0x000fe2000010d0000000000400047306u128, "I2F.U16.RZ R4, R4"),
        (0x000e6200001010000000000a00047306u128, "I2F.U16 R4, R10"),
        (0x000e2400083090000000000600067d12u128, "I2F.U64.RP R6, UR6"),
        (0x00002200000008000000000800067308u128, "MUFU.EX2 R6, R8"),
        (0x0000620000000c000000000d00000308u128, "@P0 MUFU.LG2 R0, R13"),
        (0x000022000000100000000023002a2308u128, "@P2 MUFU.RCP R42, R35"),
        (0x000e2400080010000000000400007d08u128, "MUFU.RCP R0, UR4"),
    ] {
        check(word, vendor);
    }
    let (table, index) = table_and_index();
    let nan = 0x000e220000001400ffc0000000087908u128;
    let decoded = index.decode(nan, 0, table).unwrap();
    assert_eq!(decoded.key, "MUFU_R_FI");
    assert_eq!(cubit::printer::to_sass(&decoded), "MUFU.RSQ R8, -QNAN");
    assert_eq!(reencode(table, nan, &cubit::printer::to_sass_lossless(&decoded)), nan);
    let hex = cubit::parser::parse_sass("MUFU.RSQ R8, 0xffc00000", 0).unwrap();
    assert_eq!(cubit::encoder::encode_instruction(&hex, table).unwrap() & ((1u128 << 96) - 1), nan & ((1u128 << 96) - 1),
               "the hexadecimal literal encodes through the MUFU_R_II alias");
}

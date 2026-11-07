//! Era keys with a glued predicate token in the mnemonic (owner's decision of 2026-11-03, item 11):
//! `QMMA.16816.F16.E4M3.E4M3_P0_R_R_R_R`, `F2IP.U8.F32_P2_R_R_R_R`, `DMMA.8x8x4_P5_R_R_R_R`,
//! `S2R_P0_R_L`, `MOV_P0_R_II`, ... (20 keys in sm120.json, 10 of the same in sm121a.json). nvdisasm
//! 13.1 names every one of their canonical words with the plain mnemonic (fixture
//! `tests/fixtures/sm120_era_keys_20261104_nvdisasm.jsonl`, one word per call), so the rows left the
//! table and `_meta.key_aliases` maps each old key to the plain key (blackwell-isa, 2026-11-04,
//! `blackwell-isa-internal/tools/t3_20261104.py`). cubit's loader resolves an alias as an
//! encoder-visible, decoder-invisible copy of the plain entry: `table.entries[old]` and text written
//! with the old name keep working (`tests/bug280_qmma16816_b74.rs`, `tests/bug340_f2ip_opmodh1.rs`),
//! the decoder never prints a glued mnemonic again.
//!
//! Two plain rows were widened by the same probe so that the retired rows' words still decode:
//! `DMMA.8x8x4_R_R_R_R` gained its guard field (`@P0 DMMA.8x8x4 ...`), `F2FP.F16.F32.PACK_AB_R_R_R`
//! gained the guard field and the text-inert bits [71:64], 62, 63, 72; the F2FP PACK_AB lattice
//! bits nvdisasm rejects (73, 74, 82, 83) or prints as `???n` (79-81) fail closed in cubit (the
//! F2FP sign-window arm of the decoder), the sibling bits 75-78 (RELU / BF16 / SATFINITE / MERGE_C)
//! belong to their own rows. `MOV_P0_R_II` and `PLOP3.LUT_P1_...` carried a 1-bit "guard" at bit 7
//! and claimed UMOV / UPLOP3 words: aliases now, their words decode through the uniform rows.
use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;
use std::{path::PathBuf, sync::OnceLock};

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

fn fixture(family: &str) -> Vec<Value> {
    include_str!("fixtures/sm120_era_keys_20261104_nvdisasm.jsonl").lines()
        .map(|l| serde_json::from_str::<Value>(l).unwrap())
        .filter(|r| r["family"] == family)
        .collect()
}

fn normalise(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ").trim_end_matches(" ;").to_string()
}

fn aliases() -> serde_json::Map<String, Value> {
    let raw: Value = serde_json::from_slice(&cubit::table::read_table_bytes(table_path()).unwrap()).unwrap();
    raw["_meta"]["key_aliases"].as_object().unwrap().clone()
}

/// The mnemonics whose remaining harvest keys the per-row verification of session G run 5 retires (the mnemonic lists
/// of `tools/probes/re_sm120_rows.py` FAMILIES; the glued `_Pn_` era keys of the same mnemonics keep their own arm).
const ROW_PROBE_FAMILIES: &[&str] = &[
    "QMMA", "HMMA", "OMMA", "DMMA",
    "HFMA2", "HMNMX2", "HADD2", "HSET2", "F2FP", "I2FP", "F2IP", "I2IP", "UF2FP", "UI2FP", "F2F", "UF2I", "UI2F",
    "VIMNMX", "IADD", "IMAD", "IADD3", "IMNMX", "IABS", "VIADD", "SGXT", "BMSK", "PRMT", "LOP3", "SEL", "MOV", "FLO", "POPC",
    "BREV", "R2UR", "LDC", "S2R", "CS2R", "MOV64IUR", "LDCU", "S2UR", "FHADD", "DMUL", "DADD",
    "USHF", "ULEA", "ULOP3", "UFLO", "UMOV", "UIADD3", "UIMAD", "USEL", "UIMNMX", "UBMSK", "UVIMNMX", "UPRMT", "UCLEA",
    "UBREV", "UPOPC", "UISETP", "REDUX", "ELECT",
    "LDG", "STG", "LD", "ST", "LDS", "STS", "LDL", "STL", "LDGSTS", "LDGMC", "LDSM", "STSM", "MOVM", "CCTL", "QSPC",
    "LDGDEPBAR", "UTMALDG", "UTMASTG", "UTMACCTL", "UTMACMDFLUSH", "UBLKCP", "UBLKRED", "UBLKPF",
    "ATOMG", "ATOM", "ATOMS", "REDG",
    "WARPSYNC", "CALL", "BSSY", "BSYNC", "EXIT", "BREAK", "BAR", "MEMBAR", "NOP", "YIELD", "PREEXIT", "ERRBAR", "CGAERRBAR",
    "ACQBULK", "ACQSHMINIT", "NANOSLEEP", "BMOV", "UCGABAR",
];

#[test]
fn the_twenty_era_keys_are_aliases_of_plain_keys() {
    let (table, _) = table_and_index();
    let al = aliases();
    // 20 glued-predicate era keys (2026-11-04) + the three dotted BRA harvest keys retired by the
    // measured family (2026-11-06, T-9: `BRA.U_UP_II`, `BRA.DIV_UR_II`, `BRA.U_?_II` -> the plain keys)
    // + the two dotted RET harvest keys retired by the BRX / BRXU / RET family (2026-11-06, T-10:
    // `RET.REL.NODEC_R_II`, `RET.REL.NODEC_R` -> `RET_R_II`)
    // + the five dense IMMA harvest twins retired by the IMMA family (T-10: `_P_` / `_?` keys -> the typed keys)
    // + the SAT-less `FADD.SAT_R_R_R` harvest row retired by the audit exceptions (T-11: -> `FADD_R_R_R`)
    // + the three dotted HSETP2 harvest keys retired by the measured family (2026-11-06, G: the encode-only
    //   twin `HSETP2.GEU.AND_P_P_R_R_P` and the mis-tokenised `_P_P_R_R_R` / `_P_P_R_UR_UR` -> the plain keys)
    // + the eleven FSETP junk keys retired by the measured FSETP / DSETP family (G: eight mis-tokenised dotted
    //   harvest samples, `FSETP_P_P_II_II_P` / `_II_R_P`, and the integer-spelling twin `FSETP_P_P_R_II_P`
    //   -> the plain key of their opcode)
    // + the ten junk keys retired by the measured PLOP3 / P2R / R2P family (G: the dotted `PLOP3.LUT_P_P_P_P_P_II_II`
    //   twin -- the era alias `PLOP3.LUT_P1_...` follows it to the plain key -- seven P2R and two R2P harvest keys)
    // + the IMMA.SF hypothesis key renamed to the measured QMMA.SF opcode-bit-2 variant (2026-11-06, NEEDS 44:
    //   `IMMA.SF.16832.U8.U8_R_R_R_R_R_R_UR` -> `QMMA.SF.16832.F32.UNIDENTIFIED.E8_R_R_R_R_R_R_UR`), and that
    //   interim name itself once the element types were identified on silicon (2026-11-07, T-13:
    //   -> `QMMA.SF.16832.F32.MXINT8.MXINT8.E8_R_R_R_R_R_R_UR`)
    // + the six UFSETP junk keys retired by the measured UFSETP family (G: the integer-spelling twin
    //   `UFSETP_UP_UP_UR_II_UP` and five dotted harvest samples -> the plain key of their opcode)
    // + the 27 junk keys retired by the measured FP32 ALU family (2026-11-07, G: mis-tokenised `_?` / `_L` / `_R_R_R_R`
    //   harvest keys, dotted twins with the modifier in the key, the integer-spelling `*_II*` twins of the f32 forms
    //   -> the plain key of their opcode)
    // + the nine junk keys retired by the measured uniform FP32 ALU (2026-11-07, G: the `_II` / `_L` / `_?` spellings
    //   of the f32 immediate forms of UFADD / UFMUL / UFFMA / UFSEL -> the f32 key)
    // + the 213 keys retired by the measured conversions (2026-11-07, G: the 207 dotted F2I keys, `I2F.RP_R_R`, four
    //   dotted FRND keys -> the plain key of their operand signature; the integer-spelling `MUFU_R_II` -> `MUFU_R_FI`)
    // + the eight junk keys retired by the measured FSET / FSEL / FCHK family (2026-11-07, G: the dotted `FSET.BF.F.AND`
    //   twin, six mis-tokenised FSEL keys, the integer-spelling `FCHK_P_R_II` -> the plain key of their opcode; the
    //   BUG-178 / BUG-249 `+QNAN` lane `FSEL_R_R_II_P` stays a key)
    // + the 781 dotted one-group harvest keys of the 256-bit load's descriptor form retired by the measured family
    //   (2026-11-07, G batch 10: `LDG.E.<cache>.<L2>[.LTC].256.<scope>_R_R_dARI[_II][_P]` -> the plain key of their
    //   operand signature, whose 1 152 measured groups include the one each dotted key spelled)
    // + the 3 084 dotted keys of the load's `.64` uniform-indexed form (G batch 11: `..._R_R_ARURI64[_II][_P]`)
    // + the 3 120 dotted keys of the load's U32 uniform-indexed form (G batch 12: `..._R_R_ARURI[_II][_P]`)
    // + the 1 164 dotted keys of the 256-bit store (G batch 13: `STG.E.<cache>.<L2>.256.<scope>_{dARI,ARURI,ARURI64}_R_R[_II]`)
    // + the 6 144 dotted keys of the reduction's uniform-indexed forms (G batch 14: `REDG.E.<op>[.cache][.type].<scope>_{ARURI,ARURI64}_R`)
    // + the 78 shadowed tensor-core twins retired by the row verification (2026-11-07, G run 5,
    //   tools/probes/re_sm120_rows.py --family tensor: 73 byte-identical `_P_` twins of the QMMA.SP / HMMA.SP / HMMA /
    //   DMMA plain keys, the three `QMMA..._UP_II_?` and `DMMA.8x8x4_R_R_R_R_?` junk spellings, the dotted
    //   `HMMA.1684.F32.TF32_R_R_R_R` twin of `HMMA_R_R_R_R`'s measured group -> the key cubit decodes their words through)
    // + the 148 twin keys retired by the row verification of the long tail (G run 5 batch 16, the six other families:
    //   dotted twins, integer spellings of float-immediate forms, `?` / phantom-token junk, byte-identical rows -> the key
    //   cubit decodes their words through; `tests/sm120_rows_<family>.rs` pins each)
    assert_eq!(al.len(), 14839, "sm120.json key_aliases"); // 14 691 + 148 (T-17: batches 12-16 on one base)
    let glued = regex::Regex::new(r"_P\d_").unwrap();
    let mut glued_n = 0;
    for (old, new) in &al {
        let new = new.as_str().unwrap();
        if old.starts_with("BRA.") {
            assert!(matches!(new, "BRA_UP_II" | "BRA_UR_II" | "BRA_II"), "{old} -> {new}");
            continue;
        }
        if old.starts_with("RET.REL.NODEC_R") {
            assert_eq!(new, "RET_R_II", "{old} -> {new}");
            continue;
        }
        if old == "FADD.SAT_R_R_R" {
            // the SAT-less harvest row retired by the T-11 audit exceptions: its words are plain FADD words
            assert_eq!(new, "FADD_R_R_R", "{old} -> {new}");
            continue;
        }
        if old.starts_with("HSETP2.") {
            // the dotted HSETP2 harvest keys: their words are the plain keys' (selectors are fields there)
            assert_eq!(new, if old.ends_with("_UR_UR") { "HSETP2_P_P_R_UR_P" } else { "HSETP2_P_P_R_R_P" }, "{old} -> {new}");
            continue;
        }
        if old.starts_with("P2R") || old.starts_with("R2P") || old == "PLOP3.LUT_P_P_P_P_P_II_II" {
            // the predicate-file junk keys: the `PR` token read as a register / label, shifted fields
            assert!(matches!(new, "P2R_R_II_R_II" | "R2P_II_R_II" | "PLOP3_P_P_P_P_P_II_II"), "{old} -> {new}");
            continue;
        }
        if old.starts_with("FSETP") {
            // the FSETP junk keys: their words are the plain keys' (register / uniform / f32-immediate form by opcode)
            assert!(matches!(new, "FSETP_P_P_R_R_P" | "FSETP_P_P_R_UR_P" | "FSETP_P_P_R_FI_P"), "{old} -> {new}");
            continue;
        }
        if old == "IMMA.SF.16832.U8.U8_R_R_R_R_R_R_UR" || old == "QMMA.SF.16832.F32.UNIDENTIFIED.E8_R_R_R_R_R_R_UR" {
            // the 2026-03 hypothesis key and the interim 2026-11-06 name: the QMMA.SF opcode-bit-2 variant, measured
            // on silicon as the MXINT8 x MXINT8 block-scaled MMA (NEEDS 44, 2026-11-07)
            assert_eq!(new, "QMMA.SF.16832.F32.MXINT8.MXINT8.E8_R_R_R_R_R_R_UR", "{old} -> {new}");
            assert!(table.entries.get(new).is_some_and(|e| !e.encode_only), "{new}: the measured row is a real row");
            continue;
        }
        if old.starts_with("UFSETP") {
            assert!(matches!(new, "UFSETP_UP_UP_UR_UR_UP" | "UFSETP_UP_UP_UR_FI_UP"), "{old} -> {new}");
            continue;
        }
        if ["F2I.", "I2F.", "FRND."].iter().any(|m| old.starts_with(m)) || old == "MUFU_R_II" {
            // the conversion junk keys: the modifiers in the key -> the plain key of the operand signature
            let mn = old.split(['.', '_']).next().unwrap();
            assert!(new.starts_with(mn) && !new.contains('.'), "{old} -> {new}");
            assert!(table.entries.get(new).is_some_and(|e| !e.encode_only), "{new}: the plain key is a real row");
            continue;
        }
        if (old.starts_with("LDG.") && old.contains("_R_R_")) || (old.starts_with("STG.") && old.contains(".256"))
            || (old.starts_with("REDG.") && (old.ends_with("_ARURI_R") || old.ends_with("_ARURI64_R"))) {
            // the 256-bit load's / store's dotted keys (the three address forms) and the reduction's uniform-indexed
            // dotted keys: the modifier tokens -> a group of the plain key
            let (mn, sig) = old.split_once('_').unwrap();
            assert_eq!(new, format!("{}_{sig}", mn.split('.').next().unwrap()), "{old} -> {new}");
            let target = table.entries.get(new).unwrap_or_else(|| panic!("{new} missing"));
            assert!(!target.encode_only, "{new}: the plain key is a real row");
            let mut toks: Vec<&str> = old.split('_').next().unwrap().split('.').skip(1).collect();
            toks.sort_unstable();
            assert!(target.mod_groups.contains_key(&toks.join(",")), "{old}: its spelling names no group of {new}");
            continue;
        }
        if ["FSET", "FSEL", "FCHK"].iter().any(|m| old.starts_with(m)) {
            // the FSET / FSEL / FCHK junk keys: their words are the plain keys' (register / f32-immediate / uniform form)
            assert!(new.starts_with(&old[..4]) && !new.contains('.') && !new.contains('?') && !new.contains("II"), "{old} -> {new}");
            assert!(table.entries.get(new).is_some_and(|e| !e.encode_only), "{new}: the plain key is a real row");
            continue;
        }
        if ["UFADD", "UFMUL", "UFFMA", "UFSEL"].iter().any(|m| old.starts_with(m)) {
            // the uniform FP32 ALU junk keys: the integer / label spellings of the f32 immediate form
            assert!(new.starts_with(&old[..5]) && new.contains("_FI"), "{old} -> {new}");
            assert!(table.entries.get(new).is_some_and(|e| !e.encode_only), "{new}: the plain key is a real row");
            continue;
        }
        if ["FADD", "FMUL", "FFMA", "FMNMX"].iter().any(|m| old.starts_with(m)) {
            // the FP32 ALU junk keys: their words are the plain keys' (register / f32-immediate / uniform form by opcode)
            assert!(new.starts_with(&old[..4]) && !new.contains('.') && !new.contains('?') && !new.contains("II"), "{old} -> {new}");
            assert!(table.entries.get(new).is_some_and(|e| !e.encode_only), "{new}: the plain key is a real row");
            continue;
        }
        if old.starts_with("IMMA.") {
            // the dense IMMA twins: `_P_R_R_R_R` / `_R_R_R_R_?` / `_R_R_R_R_II_?` -> the typed `_R_R_R_R` key
            assert!(new.starts_with("IMMA.168") && new.ends_with("_R_R_R_R"), "{old} -> {new}");
            assert!(table.entries.get(new).is_some_and(|e| !e.encode_only), "{new}: the typed key is a real row");
            continue;
        }
        if !glued.is_match(old) && ROW_PROBE_FAMILIES.iter().any(|m| old.split(['.', '_']).next() == Some(m)) {
            // the keys retired by the per-row verification of the long tail (session G run 5, 2026-11-07,
            // tools/probes/re_sm120_rows.py; `tests/sm120_rows_<family>.rs` pins each alias and its canonical word):
            // a shadowed twin (`_P_` / `_?` / dotted / integer-spelling) -> the real key cubit decodes its words through
            let mn = old.split(['.', '_']).next().unwrap();
            assert_eq!(new.split(['.', '_']).next().unwrap(), mn, "{old} -> {new}");
            assert!(table.entries.get(new).is_some_and(|e| !e.encode_only), "{new}: the target is a real row");
            continue;
        }
        glued_n += 1;
        assert!(glued.is_match(old) && !glued.is_match(new), "{old} -> {new}");
        let e = table.entries.get(old).unwrap_or_else(|| panic!("alias {old} does not resolve"));
        assert!(e.encode_only, "{old}: an alias is decoder-invisible");
        let target = table.entries.get(new).unwrap_or_else(|| panic!("{new} missing"));
        assert!(!target.encode_only, "{new}: the plain key is a real row");
        assert_eq!(e.mod_groups.keys().collect::<Vec<_>>(), target.mod_groups.keys().collect::<Vec<_>>());
    }
    assert_eq!(glued_n, 20, "the twenty glued-predicate era keys");
    // no instruction key carries a glued predicate token any more
    let raw: Value = serde_json::from_slice(&cubit::table::read_table_bytes(table_path()).unwrap()).unwrap();
    let left: Vec<&String> = raw["instructions"].as_object().unwrap().keys().filter(|k| glued.is_match(k)).collect();
    assert!(left.is_empty(), "{left:?}");
}

#[test]
fn era_words_decode_to_the_vendor_text_never_to_a_glued_mnemonic() {
    let (table, index) = table_and_index();
    let glued = regex::Regex::new(r"_P\d\b").unwrap();
    // families still open in docs/KNOWN_ISSUES.md T1 (SHF: the SM120 SHF rows carry the wrong
    // direction/type law, MOV: a UMOV word is absorbed by a MOV junk row): the text may differ
    // there, the mnemonic must be plain everywhere
    let open = ["SHF.L.U32_P0_R_R_II_R", "MOV_P0_R_II"];
    let mut compared = 0;
    for r in fixture("era_key") {
        let word = u128::from_str_radix(r["word"].as_str().unwrap(), 16).unwrap();
        let key = r["key"].as_str().unwrap();
        let vendor = r["nvidia_sass"].as_str();
        match index.decode(word, 0, table) {
            Ok(d) => {
                let text = cubit::printer::to_sass(&d);
                assert!(!glued.is_match(&text) && !glued.is_match(&d.key), "{word:032x}: {text} via {}", d.key);
                if let Some(v) = vendor {
                    if !open.contains(&key) {
                        assert_eq!(normalise(&text), normalise(v), "{word:032x} ({key})");
                        compared += 1;
                    }
                }
            }
            Err(e) => assert!(vendor.is_none(), "{word:032x} ({key}): nvdisasm says {vendor:?}, cubit: {e}"),
        }
    }
    assert!(compared >= 60, "{compared} era words compared with the vendor text");
}

#[test]
fn dmma_guard_and_f2fp_inert_bits_follow_nvdisasm() {
    let (table, index) = table_and_index();
    for fam in ["dmma_guard", "f2fp_inert"] {
        for r in fixture(fam) {
            let word = u128::from_str_radix(r["word"].as_str().unwrap(), 16).unwrap();
            let vendor = r["nvidia_sass"].as_str().unwrap();
            let label = r["label"].as_str().unwrap();
            match index.decode(word, 0, table) {
                Ok(d) => {
                    // (a text-inert F2FP neighbour may be owned by the generic F2FP_R_R_R row -
                    // the text is what counts)
                    if fam == "dmma_guard" {
                        assert_eq!(d.key, r["key"].as_str().unwrap(), "{word:032x}");
                    }
                    assert_eq!(normalise(&cubit::printer::to_sass(&d)), normalise(vendor), "{word:032x} ({label})");
                }
                // bits 62/63/72/84/88 are text-inert for nvdisasm and unclaimed by the row: a hole,
                // never a junk `|R8|` / `-R6` print (the F2FP sign-window arm fails closed)
                Err(_) => assert!(label.starts_with("bit"), "{word:032x} ({label}) must decode"),
            }
        }
    }
}

#[test]
fn f2fp_rejected_and_invalid_glyph_words_fail_closed() {
    let (table, index) = table_and_index();
    for r in fixture("f2fp_reject") {
        let word = u128::from_str_radix(r["word"].as_str().unwrap(), 16).unwrap();
        let vendor = r["nvidia_sass"].as_str();
        assert!(vendor.is_none() || vendor.unwrap().contains("???"), "{word:032x}: {vendor:?}");
        if let Ok(d) = index.decode(word, 0, table) {
            panic!("{word:032x} ({}): nvdisasm {vendor:?}, cubit decoded {} via {}", r["label"],
                   cubit::printer::to_sass(&d), d.key);
        }
    }
    // the sibling bits name other rows (or nothing), never the plain PACK_AB row
    for r in fixture("f2fp_sibling") {
        let word = u128::from_str_radix(r["word"].as_str().unwrap(), 16).unwrap();
        if let Ok(d) = index.decode(word, 0, table) {
            assert_ne!(d.key, "F2FP.F16.F32.PACK_AB_R_R_R", "{word:032x} ({}) absorbed by the plain row", r["label"]);
            assert_eq!(normalise(&cubit::printer::to_sass(&d)), normalise(r["nvidia_sass"].as_str().unwrap()), "{word:032x}");
        }
    }
}


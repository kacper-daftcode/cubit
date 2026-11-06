//! A16 (KNOWN_ISSUES; found 2026-11-05 writing the ARRIVES probe, closed 2026-11-06 by session T-11): the
//! guard bits [15:12] carry only (predicate, negation) -- whether they name `P2` or `UP2` follows the row's
//! family (`printer::guard_is_uniform_family`: the uniform datapath is `U*`, `LDCU`, `SYNCS_UR*`, `S2UR`,
//! `CS2UR`, `LDTM`, `STTM`). `@!P2 SYNCS.EXCH.64 URZ, [UR8], UR6` therefore assembled silently as the word
//! nvdisasm names `@!UP2 SYNCS.EXCH.64 ...`, and the barrier init ran under an uninitialised UP2. The
//! encoder now refuses a guard whose class disagrees with the family, naming both; `@PT` / `@UPT` read no
//! register and stay interchangeable; the decoder / printer side is unchanged (the census round-trip pins it).

use cubit::{decoder::DecodeIndex, encoder::encode_instruction, parser::parse_sass, printer::to_sass, table::IsaTable};
use std::{path::Path, sync::OnceLock};

fn table() -> &'static IsaTable {
    static T: OnceLock<IsaTable> = OnceLock::new();
    T.get_or_init(|| IsaTable::load(Path::new("tables/sm120.json")).unwrap())
}

fn table_sm103a() -> &'static IsaTable {
    static T: OnceLock<IsaTable> = OnceLock::new();
    T.get_or_init(|| IsaTable::load(Path::new("tables/sm103a.json")).unwrap())
}

fn encode_on(text: &str, table: &IsaTable) -> Result<u128, String> {
    let insn = parse_sass(text, 0).map_err(|e| e.to_string())?;
    encode_instruction(&insn, table).map_err(|e| e.to_string())
}

fn encode(text: &str) -> Result<u128, String> {
    encode_on(text, table())
}

fn roundtrip(text: &str) -> String {
    let word = encode(text).unwrap_or_else(|e| panic!("{text}: {e}"));
    let index = DecodeIndex::build(table());
    to_sass(&index.decode(word, 0, table()).unwrap())
}

#[test]
fn a_vector_guard_on_a_uniform_datapath_form_is_refused_with_the_family_named() {
    for text in [
        "@!P2 SYNCS.EXCH.64 URZ, [UR8], UR6",   // the A16 witness
        "@P1 UIADD3 UR55, UPT, UPT, UR55, 0x1, UR63",
        "@!P0 LDCU.64 UR4, c[0x0][UR8]",
    ] {
        let err = encode(text).expect_err(text);
        assert!(err.contains("A16") && err.contains("uniform-datapath") && err.contains("would assemble as @"),
            "{text}: {err}");
        assert!(err.contains("Write the @UPn guard"), "{text}: {err}");
    }
    // the tensor-memory load lives on the sm_103a / sm_100a tables
    for text in ["@P3 LDTM R0, tmem[UR0]", "@!P1 STTM tmem[UR4], R8"] {
        let err = encode_on(text, table_sm103a()).expect_err(text);
        assert!(err.contains("A16") && err.contains("uniform-datapath") && err.contains("would assemble as @"),
            "{text}: {err}");
        assert!(err.contains("Write the @UPn guard"), "{text}: {err}");
    }
}

#[test]
fn a_uniform_guard_on_a_vector_datapath_form_is_refused_too() {
    for text in [
        "@UP0 IADD3 R5, PT, PT, R9, R4, R5",
        "@!UP2 SYNCS.ARRIVE.TRANS64.A1T0 RZ, [R8], RZ",
        "@UP1 LDG.E.64 R0, desc[UR4][R20.64]",
    ] {
        let err = encode(text).expect_err(text);
        assert!(err.contains("A16") && err.contains("vector-datapath") && err.contains("Write the @Pn guard"), "{text}: {err}");
    }
}

#[test]
fn the_matching_guard_class_assembles_and_prints_as_written_and_pt_stays_interchangeable() {
    for text in [
        "@!UP2 SYNCS.EXCH.64 URZ, [UR8], UR6",
        "@UP1 UIADD3 UR55, UPT, UPT, UR55, 0x1, UR63",
        "@!UP0 LDCU.64 UR4, c[0x0][UR8]",
        "@P0 IADD3 R5, PT, PT, R9, R4, R5",
        "@!P2 SYNCS.ARRIVE.TRANS64.A1T0 RZ, [R8+URZ], RZ",
    ] {
        assert_eq!(roundtrip(text), text);
    }
    assert_eq!(to_sass(&DecodeIndex::build(table_sm103a()).decode(encode_on("@UP3 LDTM R0, tmem[UR0]", table_sm103a()).unwrap(), 0, table_sm103a()).unwrap()),
        "@UP3 LDTM R0, tmem[UR0]");
    // the always-true guard names no register: both spellings assemble to the unguarded word
    let plain = encode("UIADD3 UR55, UPT, UPT, UR55, 0x1, UR63").unwrap();
    assert_eq!(encode("@PT UIADD3 UR55, UPT, UPT, UR55, 0x1, UR63").unwrap(), plain);
    assert_eq!(encode("@UPT UIADD3 UR55, UPT, UPT, UR55, 0x1, UR63").unwrap(), plain);
    let plain = encode("IADD3 R5, PT, PT, R9, R4, R5").unwrap();
    assert_eq!(encode("@UPT IADD3 R5, PT, PT, R9, R4, R5").unwrap(), plain);
    // the two classes share the bits: the vector spelling's word IS the uniform word
    let good = encode("@!UP2 SYNCS.EXCH.64 URZ, [UR8], UR6").unwrap();
    assert_eq!((good >> 12) & 0xf, 0xa, "@!UP2 = negation bit 15 + predicate 2");
}

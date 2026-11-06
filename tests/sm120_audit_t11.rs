//! The named exceptions of the SM120 dynamic audit at the T-10 end state (KNOWN_ISSUES T1: 14 rows) re-checked
//! by session T-11 (2026-11-06) with nvdisasm 13.1 sweeps on the four targets (`T/t11/exc_probe.py`, identical
//! texts on `-b SM120` / `SM103` / `SM100` / `SM121`), and what closed each:
//!
//! * `DEPBAR_II_II [LE]` — the scoreboard field [46:44] names SB0..SB5; 6 / 7 are `INVALID6` / `INVALID7`
//!   → the table row forbids the two values (decode fails closed, the encoder refuses the text).
//! * `FADD.SAT_R_R_R` — a mis-keyed harvest row: no SAT bit (77) in its and_base, `Ra = RZ` baked, its
//!   `abs@62` the `|Rb|` of a plain FADD (`FADD R4, RZ, |R8|`) → retired (alias → `FADD_R_R_R`; the `[SAT]`
//!   group carries bit 77).
//! * `ULEA_UR_UP_UR_UR_II` / `ULEA_UR_UR_UR_II` — the UP operand [83:81] prints `UP0..UP6` and is elided at 7;
//!   bit 72 is `-URa` (the first source), bit 63 `-URb` → `neg@72` on the 4-operand row, the printer elides a
//!   `UPT` operand (the explicit spelling stays a bitwise alias, as BUG-045 does for ULOP3).
//! * `ULOP3_UP_UR_UR_II_UR_II_P [LUT]` — the UP destination is elided at 7 and the dest-less row
//!   `ULOP3_UR_UR_II_UR_II_UP [LUT]` had the source predicate baked as `!UPT` ([89:87] = 7, bit 90) → the two
//!   are fields now, the dest-less row owns the UPT-destination words and prints the vendor's six operands.
//! * `BMOV.64_II_UR [64]` — the first operand is the special register `ATEXIT_PC` for every value of [23:16]
//!   → printed and parsed as the literal (the row keeps its shape).
//! * `USETMAXREG_II [CTAPOOL,DEALLOC]` — bit 72 = DEALLOC, 73 = TRY_ALLOC, 74 = CTAPOOL (`???0` otherwise),
//!   63 text-inert; the sign-tolerant fallback printed the bit-63 DEALLOC word as `TRY_ALLOC … UPT, 0x0`
//!   → USETMAXREG is off the fallback (the inert-bit word fails closed).
//! * `LDG_R_ARURI` ×3 / `STG_ARURI_R` ×3 / `ST_ARURI_R` — the 64-bit-base plain form with base 255 is the
//!   vendor's degenerate glyph `[???255.64+UR6+0x10]` (the U32 width prints `[RZ.U32+UR6+0x10]` normally)
//!   → printed text-faithfully like the REDG / ATOMG `.EL` twins (BUG-461 doctrine); the encoder refuses it.
//! * `IMMA.SF.16832.U8.U8_R_R_R_R_R_R_UR` stays: the documented hypothesis (every probe word rejected), kept
//!   by the owner's rule for undocumented forms until a numerical oracle on silicon.

use cubit::{decoder::DecodeIndex, encoder::encode_instruction, parser::parse_sass, printer::to_sass, table::IsaTable};
use serde_json::Value;
use std::{path::Path, sync::OnceLock};

const CTRL: u128 = 0x000f_e200u128 << 96;

fn loaded() -> &'static (IsaTable, DecodeIndex) {
    static T: OnceLock<(IsaTable, DecodeIndex)> = OnceLock::new();
    T.get_or_init(|| {
        let table = IsaTable::load(Path::new("tables/sm120.json")).unwrap();
        let index = DecodeIndex::build(&table);
        (table, index)
    })
}

fn dec(word: u128) -> Result<(String, String), String> {
    let (table, index) = loaded();
    index.decode(word | CTRL, 0, table).map(|d| (to_sass(&d), d.key.clone())).map_err(|e| e.to_string())
}

fn enc(text: &str) -> Result<u128, String> {
    let (table, _) = loaded();
    let insn = parse_sass(text, 0).map_err(|e| e.to_string())?;
    encode_instruction(&insn, table).map_err(|e| e.to_string())
}

const LOW96: u128 = (1u128 << 96) - 1;

#[test]
fn depbar_scoreboards_six_and_seven_fail_closed() {
    for sb in 0..6u128 {
        let w = 0x0000_0000_0000_0000_0000_8400_0000_791a | (sb << 44);
        assert_eq!(dec(w).unwrap().0, format!("DEPBAR.LE SB{sb}, 0x10"));
        assert_eq!(enc(&format!("DEPBAR.LE SB{sb}, 0x10")).unwrap() & LOW96, w);
    }
    for sb in 6..8u128 {
        let w = 0x0000_0000_0000_0000_0000_8400_0000_791a | (sb << 44);
        assert!(dec(w).is_err(), "SB{sb}: nvdisasm prints INVALID{sb}");
        let err = enc(&format!("DEPBAR.LE SB{sb}, 0x10")).unwrap_err();
        assert!(err.contains("claim-forbidden"), "{err}");
    }
}

#[test]
fn the_sat_less_fadd_sat_row_is_gone_and_its_words_are_plain_fadd() {
    let (text, key) = dec(0x0000_0000_0000_0000_4000_0008_ff04_7221).unwrap();
    assert_eq!((text.as_str(), key.as_str()), ("FADD R4, RZ, |R8|", "FADD_R_R_R"));
    let sat = enc("FADD.SAT R4, RZ, |R8|").unwrap();
    assert_eq!((sat >> 77) & 1, 1, "SAT is bit 77");
    assert_eq!(dec(sat & LOW96).unwrap().0, "FADD.SAT R4, RZ, |R8|");
    let raw: Value = serde_json::from_slice(&cubit::table::read_table_bytes(Path::new("tables/sm120.json")).unwrap()).unwrap();
    assert!(raw["instructions"].get("FADD.SAT_R_R_R").is_none());
    assert_eq!(raw["_meta"]["key_aliases"]["FADD.SAT_R_R_R"], "FADD_R_R_R");
}

#[test]
fn ulea_prints_the_first_source_negation_and_elides_a_upt_operand() {
    let base: u128 = 0x0000_0000_0f8e_08ff_0000_0000_0700_7291; // ULEA UR0, UR7, UR0, 0x1 (UP field = 7)
    assert_eq!(dec(base).unwrap().0, "ULEA UR0, UR7, UR0, 0x1");
    assert_eq!(dec(base | (1 << 72)).unwrap().0, "ULEA UR0, -UR7, UR0, 0x1");
    assert_eq!(dec(base | (1 << 63)).unwrap().0, "ULEA UR0, UR7, -UR0, 0x1");
    let up3 = (base & !(0x7u128 << 81)) | (3 << 81);
    assert_eq!(dec(up3).unwrap(), ("ULEA UR0, UP3, UR7, UR0, 0x1".to_string(), "ULEA_UR_UP_UR_UR_II".to_string()));
    assert_eq!(dec(up3 | (1 << 72)).unwrap().0, "ULEA UR0, UP3, -UR7, UR0, 0x1");
    for (text, word) in [
        ("ULEA UR0, -UR7, UR0, 0x1", base | (1 << 72)),
        ("ULEA UR0, UPT, -UR7, UR0, 0x1", base | (1 << 72)), // the explicit spelling is a bitwise alias
        ("ULEA UR0, UP3, -UR7, UR0, 0x1", up3 | (1 << 72)),
        ("ULEA UR0, UR7, -UR0, 0x1", base | (1 << 63)),
    ] {
        assert_eq!(enc(text).unwrap() & LOW96, word, "{text}");
    }
}

#[test]
fn ulop3_prints_six_operands_for_a_upt_destination_and_round_trips_both_source_spellings() {
    let base: u128 = 0x0000_0000_0b8e_10ff_0000_0010_0706_7892; // UPd = 7, source UPT (bit 90 clear)
    assert_eq!(dec(base).unwrap(), ("ULOP3.LUT UR6, UR7, 0x10, URZ, 0x10, UPT".to_string(), "ULOP3_UR_UR_II_UR_II_UP".to_string()));
    assert_eq!(dec(base | (1 << 90)).unwrap().0, "ULOP3.LUT UR6, UR7, 0x10, URZ, 0x10, !UPT");
    let up3 = (base & !(0x7u128 << 87)) | (3 << 87);
    assert_eq!(dec(up3).unwrap().0, "ULOP3.LUT UR6, UR7, 0x10, URZ, 0x10, UP3");
    assert_eq!(dec(up3 | (1 << 90)).unwrap().0, "ULOP3.LUT UR6, UR7, 0x10, URZ, 0x10, !UP3");
    let upd2 = (base & !(0x7u128 << 81)) | (2 << 81);
    assert_eq!(dec(upd2).unwrap().0, "ULOP3.LUT UP2, UR6, UR7, 0x10, URZ, 0x10, UPT");
    for (text, word) in [
        ("ULOP3.LUT UR6, UR7, 0x10, URZ, 0x10, UPT", base),
        ("ULOP3.LUT UR6, UR7, 0x10, URZ, 0x10, !UPT", base | (1 << 90)),
        ("ULOP3.LUT UR6, UR7, 0x10, URZ, 0x10, !UP3", up3 | (1 << 90)),
        ("ULOP3.LUT UPT, UR6, UR7, 0x10, URZ, 0x10, UPT", base), // BUG-045: the explicit destination is an alias
        ("ULOP3.LUT UP2, UR6, UR7, 0x10, URZ, 0x10, UPT", upd2),
    ] {
        assert_eq!(enc(text).unwrap() & LOW96, word, "{text}");
    }
}

#[test]
fn bmov64_names_atexit_pc() {
    let w: u128 = 0x0000_0000_0800_0000_0000_0006_0000_7d57;
    assert_eq!(dec(w).unwrap().0, "BMOV.64 ATEXIT_PC, UR6");
    assert!(dec(w | (5 << 16)).is_err(), "[23:16] carries nothing for nvdisasm (text-inert); the row fails closed on it");
    assert_eq!(enc("BMOV.64 ATEXIT_PC, UR6").unwrap() & LOW96, w);
    assert_eq!(enc("@P2 BMOV.64 ATEXIT_PC, UR9").unwrap() & LOW96, (w & !(0xffu128 << 32) & !0xf000) | (9 << 32) | (2 << 12));
    // the numeral cubit used to print stays an accepted legacy spelling of the same word (old frozen listings)
    assert_eq!(enc("BMOV.64 0x0, UR6").unwrap() & LOW96, w);
}

#[test]
fn usetmaxreg_inert_bit_63_fails_closed_instead_of_flipping_the_form() {
    let dealloc: u128 = 0x0000_0000_080e_0500_0000_0000_0000_79c8;
    let tryalloc: u128 = 0x0000_0000_0800_0600_0000_0000_0000_79c8;
    assert_eq!(dec(dealloc).unwrap().0, "USETMAXREG.DEALLOC.CTAPOOL 0x0");
    assert_eq!(dec(dealloc | (0x18 << 32)).unwrap().0, "USETMAXREG.DEALLOC.CTAPOOL 0x18");
    assert_eq!(dec(tryalloc).unwrap().0, "USETMAXREG.TRY_ALLOC.CTAPOOL UP0, 0x0");
    assert_eq!(dec(tryalloc | (0xe0 << 32) | (7 << 81)).unwrap().0, "USETMAXREG.TRY_ALLOC.CTAPOOL UPT, 0xe0");
    assert!(dec(dealloc | (1 << 63)).is_err(), "the text-inert bit 63 word stays unclaimed");
    assert!(dec(dealloc & !(1 << 74)).is_err(), "bit 74 clear is the vendor's ???0 pool");
}

#[test]
fn the_rz_base_64bit_plain_forms_print_the_vendor_glyph_and_do_not_assemble() {
    for (word, text) in [
        (0x0000_0000_0c1e_0d20_0000_1006_ff04_7981u128, "LDG.E.LTC128B.128 R4, [???255.64+UR6+0x10]"),
        (0x0000_0000_0c1e_0b20_0000_1006_ff04_7981, "LDG.E.LTC128B.64 R4, [???255.64+UR6+0x10]"),
        (0x0000_0000_0c1e_0920_0000_1006_ff04_7981, "LDG.E.LTC128B R4, [???255.64+UR6+0x10]"),
        (0x0000_0000_0c10_0d05_0000_1006_ff00_7986, "STG.E.128 [???255.64+UR5+0x10], R6"),
        (0x0000_0000_0c10_0b05_0000_1006_ff00_7986, "STG.E.64 [???255.64+UR5+0x10], R6"),
        (0x0000_0000_0c10_0905_0000_1006_ff00_7986, "STG.E [???255.64+UR5+0x10], R6"),
        (0x0000_0000_0c10_0b05_0000_1006_ff00_7985, "ST.E.64 [???255.64+UR5+0x10], R6"),
    ] {
        assert_eq!(dec(word).unwrap().0, text);
        assert!(enc(text).is_err(), "{text}: the degenerate glyph is not mintable (BUG-461)");
        // a real base prints and assembles as before
        let real = (word & !(0xffu128 << 24)) | (2 << 24);
        let real_text = text.replace("???255", "R2");
        assert_eq!(dec(real).unwrap().0, real_text);
        assert_eq!(enc(&real_text).unwrap() & LOW96, real, "{real_text}");
    }
    assert!(enc("LDG.E.LTC128B.128 R4, [RZ.64+UR6+0x10]").is_err(), "the old cubit-only spelling stays refused (BUG-461 mint-side)");
}

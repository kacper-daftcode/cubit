//! BUG-049 (rejestr sm120: 049_imad_hi_perarch_reject.md, SPARK q3 gx4):
//! guard BUG-002 odrzucal IMAD.HI[.U32] na KAZDYM targecie, bo
//! (a) loader nie znal SM121A (_meta.architecture) i domykal sie na e_flags
//!     sm_120, przez co tabela sm_121a udawala sm_120 w target_sm();
//! (b) warunek skip guard-a dla non-120 wymagal, by dopasowany wpis tabeli
//!     sam niosl literalnie klucz/modgrupe "HI" — nvcc-owski 4-operandowy
//!     `IMAD.HI.U32 R8, R2, R3, R4` (ktory sm_121a wykonuje POPRAWNIE:
//!     hi32 dobrze, Rd+1 nietkniety, krzem GB10 potwierdzone) nie mial czesto
//!     takiego wpisu i byl odrzucany mimo ze ally.
//! Fix u zrodla: arch_ef_flags zna SM121 => target_sm()==121; guard BUG-002
//! strzela WYLACZNIE dla sm_120 (jedyne arch z krzemowym dowodem zepsucia
//! HI->WIDE). Na innych arch tabela jest autorytetem, jak dla kazdego opkodu.
//! sm_120 reject pozostaje nietkniety (bugs_errata_sm120::bug002_* go paletuje).
use cubit::encoder::encode_instruction;
use cubit::table::IsaTable;

fn write_table(arch: &str, with_hi_entry: bool, strip_imad: bool, tag: &str) -> std::path::PathBuf {
    let src: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string("tables/sm120.json").unwrap()).unwrap();
    let mut t = src.clone();
    t["_meta"]["architecture"] = serde_json::Value::String(arch.into());
    if strip_imad {
        let ins = t.as_object_mut().unwrap().get_mut("instructions").unwrap()
            .as_object_mut().unwrap();
        let drop_keys: Vec<String> = ins.keys().filter(|k| k.starts_with("IMAD")).cloned().collect();
        for k in drop_keys { ins.remove(&k); }
    }
    if with_hi_entry {
        // Wpis w ksztalcie harvestowanym: geometria jak IMAD_R_R_R_R, klucz
        // niesie HI jawnie (jak IMAD.HI.U32_R_P_R_R_R w tabeli sm121a sparka).
        let base = src["instructions"]["IMAD_R_R_R_R"].clone();
        t.as_object_mut().unwrap().get_mut("instructions").unwrap()
            .as_object_mut().unwrap()
            .insert("IMAD.HI.U32_R_R_R_R".into(), base);
    }
    let dir = std::env::temp_dir().join(format!("bug049r_{tag}_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let p = dir.join("t.json");
    std::fs::write(&p, serde_json::to_string(&t).unwrap()).unwrap();
    p
}

fn enc_result(t: &IsaTable, s: &str) -> Result<u128, String> {
    let insn = cubit::parser::parse_sass(s, 0).unwrap_or_else(|e| panic!("parse {s:?}: {e}"));
    encode_instruction(&insn, t).map_err(|e| e.to_string())
}

const HI_TEXT: &str = "IMAD.HI.U32 R8, R2, R3, R4 ;";

#[test]
fn bug049r_sm121a_table_reports_target_121() {
    let p = write_table("SM121A", false, false, "arch");
    let t = IsaTable::load(&p).unwrap();
    assert_eq!(t.target_sm(), 121, "SM121A _meta must not masquerade as sm_120");
}

#[test]
fn bug049r_imad_hi_encodes_on_sm121a_same_table_bytes() {
    // Ta sama zawartosc tabeli: etykieta SM121A => encode OK (wpis
    // IMAD_R_R_R_R mg "HI,U32" niesie modyfikator); etykieta SM120 =>
    // reject BUG-002. Pin obu stron scope-ingu.
    let p121 = write_table("SM121A", false, false, "ok121");
    let t121 = IsaTable::load(&p121).unwrap();
    let w = enc_result(&t121, HI_TEXT)
        .unwrap_or_else(|e| panic!("sm_121a must allow silicon-true IMAD.HI: {e}"));
    assert_ne!(w, 0);

    let p120 = write_table("SM120", false, false, "rej120");
    let t120 = IsaTable::load(&p120).unwrap();
    let e = enc_result(&t120, HI_TEXT).unwrap_err();
    assert!(e.contains("BUG-002") || e.contains("CLOBBERED"), "{e}");
}

#[test]
fn bug049r_imad_hi_dedicated_entry_path_also_ok_on_sm121a() {
    let p = write_table("SM121A", true, false, "dedicated");
    let t = IsaTable::load(&p).unwrap();
    assert!(enc_result(&t, HI_TEXT).is_ok());
}

#[test]
fn bug049r_enfail_without_any_imad_entry_uses_scoped_note() {
    // Zero wpisow IMAD: uczciwy lookup-fail; komunikat NIE moze przypisywac
    // sm_120 krzemowej prawdy innemu archowi.
    let p = write_table("SM121A", false, true, "gap");
    let t = IsaTable::load(&p).unwrap();
    let e = enc_result(&t, HI_TEXT).unwrap_err();
    assert!(e.contains("no operand-compatible table entry"), "{e}");
    assert!(e.contains("BUG-049"), "scoped note expected: {e}");
    assert!(!e.contains("silicon executes the"), "must not claim sm_120 silicon truth here: {e}");
}

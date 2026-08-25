//! BUG-128: REDG no-EL aliasing onto the bare-PT sink, breaking era-text
//! ingest. Era text
//! `REDG.E.ADD.STRONG.GPU PT, desc[UR4][R54.64], R40 ;` (P_TXT from pol*.
//! era harvest, a sink-PT family like the sibling EL keys *_P_dARI_R)
//! hit `REDG_P_dARI_R "..." not in table` -> until now the only working channel =
//! dropping PT (vendor spelling), brittle for render/RE parity.
//! Fix: a NEW REDG_P_dARI_R key, 13 mod groups cloned from REDG_dARI_R
//! with a +1 token shift (sink PT = text-only, the guard keeps tok0 as in EL),
//! vmask |= 0xF000 (guard nibble open, EL pattern), encode_only=true
//! (decoder surface 0-diff). Post-fix probes: 15/15 PASS
//! (work/bug128/sondy128.py); pre-fix control: encode aliases FAIL.

use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::table::IsaTable;

fn t103() -> IsaTable {
    IsaTable::load(std::path::Path::new("tables/sm103a.json")).unwrap()
}
fn enc(s: &str) -> u128 {
    let insn = parse_sass(s, 0).unwrap_or_else(|e| panic!("parse {s:?}: {e}"));
    encode_instruction(&insn, &t103()).unwrap_or_else(|e| panic!("encode {s:?}: {e}"))
}

/// 13 groups = the full REDG_dARI_R no-EL range; (era PT sink, vendor-unguarded).
const GROUPS: &[(&str, &str)] = &[
    ("REDG.E.ADD.STRONG.GPU PT, desc[UR4][R54.64], R40 ;",
     "REDG.E.ADD.STRONG.GPU desc[UR4][R54.64], R40 ;"),
    ("REDG.E.MAX.STRONG.GPU.64 PT, desc[UR4][R54.64], R41 ;",
     "REDG.E.MAX.STRONG.GPU.64 desc[UR4][R54.64], R41 ;"),
    ("REDG.E.MIN.STRONG.GPU.64 PT, desc[UR4][R54.64], R41 ;",
     "REDG.E.MIN.STRONG.GPU.64 desc[UR4][R54.64], R41 ;"),
    ("REDG.E.ADD.F32.RN.STRONG.GPU.FTZ PT, desc[UR4][R54.64], R40 ;",
     "REDG.E.ADD.F32.RN.STRONG.GPU.FTZ desc[UR4][R54.64], R40 ;"),
    ("REDG.E.ADD.F64.RN.STRONG.GPU PT, desc[UR4][R54.64], R40 ;",
     "REDG.E.ADD.F64.RN.STRONG.GPU desc[UR4][R54.64], R40 ;"),
    ("REDG.E.ADD.STRONG.GPU.S32 PT, desc[UR4][R54.64], R40 ;",
     "REDG.E.ADD.STRONG.GPU.S32 desc[UR4][R54.64], R40 ;"),
    ("REDG.E.AND.STRONG.GPU PT, desc[UR4][R54.64], R40 ;",
     "REDG.E.AND.STRONG.GPU desc[UR4][R54.64], R40 ;"),
    ("REDG.E.MAX.STRONG.GPU.S32 PT, desc[UR4][R54.64], R40 ;",
     "REDG.E.MAX.STRONG.GPU.S32 desc[UR4][R54.64], R40 ;"),
    ("REDG.E.MIN.STRONG.GPU.S32 PT, desc[UR4][R54.64], R40 ;",
     "REDG.E.MIN.STRONG.GPU.S32 desc[UR4][R54.64], R40 ;"),
    ("REDG.E.MIN.STRONG.GPU PT, desc[UR4][R54.64], R40 ;",
     "REDG.E.MIN.STRONG.GPU desc[UR4][R54.64], R40 ;"),
    ("REDG.E.OR.STRONG.GPU PT, desc[UR4][R54.64], R40 ;",
     "REDG.E.OR.STRONG.GPU desc[UR4][R54.64], R40 ;"),
    ("REDG.E.MAX.STRONG.GPU PT, desc[UR4][R54.64], R40 ;",
     "REDG.E.MAX.STRONG.GPU desc[UR4][R54.64], R40 ;"),
    ("REDG.E.ADD.STRONG.GPU.64 PT, desc[UR4][R54.64], R41 ;",
     "REDG.E.ADD.STRONG.GPU.64 desc[UR4][R54.64], R41 ;"),
];

#[test]
fn t128_1_all_13_groups_pt_sink_word_equals_unguarded() {
    for (pts, plain) in GROUPS {
        assert_eq!(enc(pts), enc(plain), "group mismatch for {pts:?}");
    }
}

#[test]
fn t128_2_explicit_pt_guard_double_form_encodes_same() {
    assert_eq!(
        enc("@PT REDG.E.ADD.STRONG.GPU PT, desc[UR4][R54.64], R40 ;"),
        enc("REDG.E.ADD.STRONG.GPU desc[UR4][R54.64], R40 ;")
    );
}

#[test]
fn t128_3_bug080_real_guard_still_fail_closed() {
    for g in ["@P0", "@P3", "@!PT"] {
        let text = format!("{g} REDG.E.ADD.STRONG.GPU PT, desc[UR4][R54.64], R40 ;");
        let insn = parse_sass(&text, 0).unwrap();
        assert!(
            encode_instruction(&insn, &t103()).is_err(),
            "BUG-080 errata opened back up for {g}"
        );
    }
}

#[test]
fn t128_4_sink_value_pt_token_real_hw_semantics_anchor() {
    // zera zmian w slowie bazowym: piny bajtowe dwoch reprezentantow
    // (the alias word must stay equal to the vendor form's word) — ADD and OR.
    let w_add = enc("REDG.E.ADD.STRONG.GPU PT, desc[UR4][R54.64], R40 ;");
    assert_eq!(w_add & 0xFFFF, 0x798e, "low16 word drift ADD");
    let w_or = enc("REDG.E.OR.STRONG.GPU PT, desc[UR4][R54.64], R40 ;");
    assert_eq!(w_or & 0xFFFF, 0x798e, "low16 word drift OR");
}

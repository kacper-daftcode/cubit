//! BUG-128 (F2-Q, 124-kand z DESCCAMP-D1, severity low, decode-parity breaking
//! era ingest): REDG no-EL alias pod bare-PT sink. Era-tekst
//! `REDG.E.ADD.STRONG.GPU PT, desc[UR4][R54.64], R40 ;` (P_TXT z pol*.
//! era-harvest, rodzina sink-PT jak w siostrzanych EL kluczach *_P_dARI_R)
//! padal `REDG_P_dARI_R "..." not in table` -> dzis jedyny chodzacy kanal =
//! opuszczenie PT (pisownia vendor), kruche dla render/RE-parity.
//! Fix: NOWY klucz REDG_P_dARI_R, 13 mod-grup sklonowanych z REDG_dARI_R
//! z token-shift +1 (sink PT = text-only, guard zachowuje tok0 jak w EL),
//! vmask |= 0xF000 (guard nibble otwarty, wzor EL), encode_only=true
//! (powierzchnia dekodera 0-diff). Sondy post-fix: 15/15 PASS
//! (work/bug128/sondy128.py); kontrola pre-fix: encode-aliasy FAIL.

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

/// 13 grup = pelny zakres REDG_dARI_R no-EL; (era-PT-sink, vendor-unguarded).
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
    // (slowo aliasu musi zostac rowne slowu formy vendor) — ADD i OR.
    let w_add = enc("REDG.E.ADD.STRONG.GPU PT, desc[UR4][R54.64], R40 ;");
    assert_eq!(w_add & 0xFFFF, 0x798e, "low16 word drift ADD");
    let w_or = enc("REDG.E.OR.STRONG.GPU PT, desc[UR4][R54.64], R40 ;");
    assert_eq!(w_or & 0xFFFF, 0x798e, "low16 word drift OR");
}

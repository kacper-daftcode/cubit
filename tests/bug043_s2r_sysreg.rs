//! BUG-043 (rejestr sm120: 043_sr_ntid_encodes_laneid.md, CONFIRMED i120):
//! `S2R Rx, SR_NTID.X` / `SR_NCTAID.X` kodowaly sie jako SR_LANEID — nazwy
//! nieobecne w sysreg_id() spadaly na cichy fallback 0. Na krzemie (sm120)
//! kolumna "NTID.X" zwracala laneid, co w hopb dawalo wyscigi zapisu przy
//! nb>=2 (EXACT dopiero przez przypadek przy nb=1).
//! Fix (fail-closed, u zrodla) + nvdisasm-13.3 sm_120 census:
//!  - SR_NTID/SR_NTID.X -> 0x28 (krzemowo potwierdzone blockDim, i120);
//!  - nieznana nazwa SR = blad enkodera z wskazowka SR_0x<hex> (NIE fallback 0);
//!  - dodane nvdisasm-named kody z pelnego sweepu 256 kodow (results/cubitfix/
//!    r043/sr_sweep_nvdisasm133.txt);
//!  - printer: SYSREG_NAMES zgodne z nvdisasm-13.3 sm120 (literaturne
//!    NTID.Y/Z=0x29/0x2a i NCTAID.*=0x2c..0x2e byly BLONE dla sm120 — to
//!    SR_CirQueueIncrMinusOne/SR_NLATC i SR_SM_SPA_VERSION/SR_MULTIPASSSHADERINFO/
//!    SR_LWINHI; WARPID/SMID/GRIDID tez nie istnieja w tej tabeli).

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::table::IsaTable;

fn t120() -> IsaTable {
    IsaTable::load(std::path::Path::new("tables/sm120.json")).unwrap()
}
const SCHED: u128 = 0x1FFFFu128 << (64 + 41);
fn enc_clean(table: &IsaTable, s: &str) -> u128 {
    let insn = cubit::parse_cuasm_line(s, 0).unwrap();
    encode_instruction(&insn, table).unwrap() & !SCHED
}
fn enc_err(table: &IsaTable, s: &str) -> String {
    let insn = parse_sass(s, 0).unwrap();
    encode_instruction(&insn, table).unwrap_err().to_string()
}
fn sr_code(w: u128) -> u64 {
    ((w >> 72) & 0xFF) as u64
}

#[test]
fn bug043_ntid_x_encodes_0x28_not_laneid() {
    let t = t120();
    let w = enc_clean(&t, "S2R R9, SR_NTID.X ;");
    assert_eq!(sr_code(w), 0x28, "SR_NTID.X must encode 0x28 (silicon: blockDim)");
    assert_ne!(sr_code(w), 0x00, "the BUG: silent fallback to SR_LANEID");
    // nvdisasm spellings and the numeric escape hatch are the same word:
    assert_eq!(w, enc_clean(&t, "S2R R9, SR_NTID ;"));
    assert_eq!(w, enc_clean(&t, "S2R R9, SR_0x28 ;"));
}

#[test]
fn bug043_names_without_sm120_code_fail_closed() {
    let t = t120();
    for name in [
        "SR_NCTAID.X", "SR_NCTAID.Y", "SR_NTID.Y", "SR_NTID.Z",
        "SR_WARPID", "SR_SMID", "SR_GRIDID", "SR_BOGUS",
    ] {
        let e = enc_err(&t, &format!("S2R R9, {name} ;"));
        assert!(e.contains("unknown sysreg"), "{name}: {e}");
        assert!(e.contains("SR_0x<hex>"), "{name}: escape hint missing: {e}");
    }
}

#[test]
fn bug043_decoder_names_match_nvdisasm_133_sm120() {
    let t = t120();
    let idx = DecodeIndex::build(&t);
    for (code, want) in [
        (0x28u8, "SR_NTID"),
        (0x29, "SR_CirQueueIncrMinusOne"),
        (0x2a, "SR_NLATC"),
        (0x2c, "SR_SM_SPA_VERSION"),
        (0x2d, "SR_MULTIPASSSHADERINFO"),
        (0x2e, "SR_LWINHI"),
        (0x40, "SR_GLOBALERRORSTATUS"),
        (0x42, "SR_WARPERRORSTATUS"),
        (0x44, "SR_VIRTUALENGINEID"),
        (0x36, "SR_LMEMLOSZ"),
        (0x32, "SR_SMEMSZ"),
        (0x38, "SR_EQMASK"),
    ] {
        let w = enc_clean(&t, &format!("S2R R9, SR_0x{code:02x} ;"));
        assert_eq!(sr_code(w), code as u64);
        let d = idx.decode(w, 0, &t).unwrap();
        let got = format!("{d}");
        assert!(got.contains(want), "code 0x{code:02x}: render {got:?} lacks {want:?}");
    }
}

#[test]
fn bug043_new_named_codes_roundtrip() {
    let t = t120();
    for name in [
        "SR_SWINLO", "SR_SWINSZ", "SR_SMEMSZ", "SR_SMEMBANKS", "SR_LWINLO",
        "SR_LWINSZ", "SR_LMEMLOSZ", "SR_LMEMHIOFF", "SR_EQMASK",
        "SR_GLOBALERRORSTATUS", "SR_CGAERRORSTATUS", "SR_WARPERRORSTATUS",
        "SR_VIRTUALENGINEID", "SR_GLOBALTIMERHI", "SR_VARIABLE_RATE",
        "SR_GpcLocalCgaId", "SR_CTARegPoolSz", "SR_TMemSz",
    ] {
        let w = enc_clean(&t, &format!("S2R R9, {name} ;"));
        let idx = DecodeIndex::build(&t);
        let d = idx.decode(w, 0, &t).unwrap();
        let got = format!("{d}");
        assert!(got.contains(name), "{name}: render gave {got:?}");
    }
}

#[test]
fn bug043_report_repro_fails_visibly_via_cli() {
    let dir = std::env::temp_dir().join(format!("bug043sr_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let src = dir.join("r043.sass");
    let out = dir.join("r043.cubin");
    let _ = std::fs::remove_file(&out);
    // Exact shape of results/cubit-bugs/repro/r043_sr_ntid.sass.
    std::fs::write(&src, ".entry r043\n    .param u64 mem\n    LDCU.64 UR4, c[0x0][0x358] ;\n    S2R R9, SR_NTID.X ;\n    S2R R10, SR_NCTAID.X ;\n    EXIT ;\n.endentry\n").unwrap();
    let res = std::process::Command::new(env!("CARGO_BIN_EXE_cubit"))
        .args(["asm", "-t", "tables/sm120.json", src.to_str().unwrap(),
               "-o", out.to_str().unwrap()])
        .output().unwrap();
    assert!(!res.status.success(), "SR_NCTAID.X must not assemble silently");
    assert!(!out.exists(), "fail-closed: no output cubin");
    let stderr = String::from_utf8_lossy(&res.stderr);
    assert!(stderr.contains("unknown sysreg"), "{stderr}");
}

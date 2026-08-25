//! BUG-140 (F2-Q, follow-up of BUG-139): TIER-2 promotion — aggregate
//! per-operand coverage model. BUG-139 showed a per-field "value fits mask"
//! lint is not the harvest-table semantics: operands split across sibling
//! windows, branch-fixup-owned payloads, and_base-carried constants and
//! narrow sentinel carriers all truncate LEGITIMATELY. The aggregate audit
//! (aggregate_fit_audit in encoder.rs) evaluates each (entry, token, scalar)
//! domain against the UNION of the entry's sibling pieces and fail-closes on
//! bits nothing carries; CUBIT_FIT_LINT=warn downgrades a bail to a census
//! report with the legacy payload kept.
//!
//! Positive byte pins were captured from the pre-fix control binary
//! (78fad04) — default-mode output must be byte-identical on every covered
//! idiom, and the grafted-row negatives below name the lost bits.

use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::table::IsaTable;

const SCHED: u128 = 0x1FFFFu128 << (64 + 41);

fn t103() -> IsaTable {
    IsaTable::load(std::path::Path::new("tables/sm103a.json")).unwrap()
}

fn enc_clean(table: &IsaTable, s: &str) -> u128 {
    let insn = parse_sass(s, 0).unwrap();
    encode_instruction(&insn, table).unwrap() & !SCHED
}

fn enc_err(table: &IsaTable, s: &str) -> String {
    let insn = parse_sass(s, 0).unwrap();
    encode_instruction(&insn, table).unwrap_err().to_string()
}

/// Rewrite matching `bits` (or drop matching fields) in one row of the
/// sm103a table and load the grafted copy.
fn grafted_table<F: Fn(&mut serde_json::Value) -> usize>(f: F) -> IsaTable {
    let mut v: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string("tables/sm103a.json").unwrap()).unwrap();
    let n = f(&mut v);
    assert!(n > 0, "graft matched no field");
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    let path = std::env::temp_dir().join(format!("bug140_graft_{}_{}.json", std::process::id(), nanos));
    std::fs::write(&path, serde_json::to_string(&v).unwrap()).unwrap();
    let t = IsaTable::load(&path).unwrap();
    let _ = std::fs::remove_file(&path);
    t
}

fn graft_bits(key: &str, mods: &str, extraction: &str, token_idx: i64, bits: u32) -> IsaTable {
    grafted_table(|v| {
        let mut n = 0;
        for f in v["instructions"][key]["mod_groups"][mods]["fields"].as_array_mut().unwrap() {
            if f["extraction"] == extraction && f["token_idx"] == token_idx {
                f["bits"] = serde_json::Value::from(bits);
                n += 1;
            }
        }
        n
    })
}

// ---------------------------------------------------------------------------
// Covered census classes (a)-(d) are silent and byte-identical to the
// pre-fix control (78fad04) in default mode.
// ---------------------------------------------------------------------------
#[test]
fn t140_1_covered_classes_byte_exact() {
    let t = t103();
    // (a) split-window lattice imm: 0xFE = imm[0:3)@64 + imm_shr3[3:8)@72.
    assert_eq!(enc_clean(&t, "PLOP3.LUT P0, P1, P2, P3, P4, 0xFE, 0x8 ;"),
        0x0000000001707f460000000000087804u128);
    assert_eq!(enc_clean(&t, "PLOP3.LUT P0, P1, P2, P3, P4, 0x6, 0x8 ;"),
        0x00000000017060460000000000087804u128);
    // (d) DEPBAR.LE count enum 0x9 in the shipped 6-bit window, and 0x3f.
    assert_eq!(enc_clean(&t, "DEPBAR.LE 0x0, 0x9 ;"),
        0x0000000000000000000082400000791au128);
    assert_eq!(enc_clean(&t, "DEPBAR.LE 0x0, 0x3f ;"),
        0x000000000000000000008fc00000791au128);
    // URZ / real UR numbers through the drain row's 8-bit ureg slot.
    assert_eq!(enc_clean(&t, "UIADD3 UR4, UP0, UP1, UR5, 0x80, URZ ;"),
        0x000000000f91e0ff0000008005047890u128);
    assert_eq!(enc_clean(&t, "UIADD3 UR4, UP0, UP1, UR5, 0x80, UR41 ;"),
        0x000000000f91e0290000008005047890u128);
    // Sysreg values (incl. bit7-set 0x84) in the shipped 24-bit window.
    assert_eq!(enc_clean(&t, "S2R R2, SR_TID.X ;"),
        0x00000000000021000000000000027919u128);
    assert_eq!(enc_clean(&t, "S2R R2, SR_VARIABLE_RATE ;"),
        0x00000000000084000000000000027919u128);
    // (c) branch-fixup-owned target with a dead harvested imm window.
    assert_eq!(enc_clean(&t, "BRA 0x170 ;"),
        0x00000000038000000000000000587947u128);
    // (d) RZ sentinel in the 7-bit LDS.S8 base window (t123-golden idiom).
    assert_eq!(enc_clean(&t, "LDS.S8 R1, [RZ+0x10] ;"),
        0x0000000000000200000000087f017984u128);
    // Signed leg: -1 through the 32-bit immediate window.
    assert_eq!(enc_clean(&t, "IADD3 R0, PT, PT, R1, -0x1, R2 ;"),
        0x0000000007ffe002ffffffff01007810u128);
}

// ---------------------------------------------------------------------------
// (a) Removing a split-window sibling makes the orphaned high bits bail.
// ---------------------------------------------------------------------------
#[test]
fn t140_2_split_window_member_removed_bails() {
    let g = grafted_table(|v| {
        let fs = v["instructions"]["PLOP3_P_P_P_P_P_II_II"]["mod_groups"]["LUT"]["fields"]
            .as_array_mut().unwrap();
        let before = fs.len();
        fs.retain(|f| !(f["extraction"] == "imm_shr3" && f["token_idx"] == 6));
        before - fs.len()
    });
    let err = enc_err(&g, "PLOP3.LUT P0, P1, P2, P3, P4, 0xFE, 0x8 ;");
    assert!(err.contains("encode-lint"), "expected encode-lint bail, got: {err}");
    assert!(err.contains("operand 6"), "error must name the operand slot: {err}");
    // Bits that DO live in the remaining [0:3) window still encode (the ctl
    // payload on the same grafted row):
    assert_eq!(enc_clean(&g, "PLOP3.LUT P0, P1, P2, P3, P4, 0x6, 0x8 ;"),
        0x00000000017060460000000000087804u128);
}

// ---------------------------------------------------------------------------
// (d) DEPBAR.LE enum: grafted down to the vendor 1-bit shape, 0x9 is the
// blessed count; 0x5 (which the ctl silently folds INTO the 0x9 word) bails.
// On the shipped 6-bit row, 0x40 (bit 6 outside the union) bails too.
// ---------------------------------------------------------------------------
#[test]
fn t140_3_depbar_enum_sentinel_and_overflow() {
    let g = graft_bits("DEPBAR_II_II", "LE", "imm", 2, 1);
    // ctl payload for the blessed enum on the grafted row (== 0x9's word):
    assert_eq!(enc_clean(&g, "DEPBAR.LE 0x0, 0x9 ;"),
        0x0000000000000000000080400000791au128);
    let err = enc_err(&g, "DEPBAR.LE 0x0, 0x5 ;");
    assert!(err.contains("encode-lint"), "0x5 must bail (ctl aliases it to the 0x9 word): {err}");
    assert!(err.contains("lost 0x4"), "lost bits named: {err}");
    let err = enc_err(&t103(), "DEPBAR.LE 0x0, 0x40 ;");
    assert!(err.contains("encode-lint"), "shipped 6-bit row: 0x40 bail, got: {err}");
}

// ---------------------------------------------------------------------------
// Sysreg slice-union: narrowing the shipped 24-bit sysreg window makes a
// bit-6 value (SR_CLOCKLO=0x50) bail while a fitting value (SR_TID.X=0x21)
// keeps encoding.
// ---------------------------------------------------------------------------
#[test]
fn t140_4_sysreg_window_narrowed_bails() {
    let g = graft_bits("S2R_R_L", "", "sysreg", 2, 6);
    let err = enc_err(&g, "S2R R2, SR_CLOCKLO ;");
    assert!(err.contains("encode-lint"), "0x50 in a 6-bit window must bail: {err}");
    let err = enc_err(&g, "S2R R2, SR_VARIABLE_RATE ;");
    assert!(err.contains("encode-lint"), "0x84 in a 6-bit window must bail: {err}");
    let _ = enc_clean(&g, "S2R R2, SR_TID.X ;");
    let _ = enc_clean(&t103(), "S2R R2, SR_VARIABLE_RATE ;");
}

// ---------------------------------------------------------------------------
// (d) RZ/URZ narrow sentinel: in a grafted 6-bit ureg window URZ keeps the
// vendor all-ones payload; narrowing below the sentinel floor (window top
// < 6) bails, and so does a real UR number past the window.
// ---------------------------------------------------------------------------
#[test]
fn t140_5_urz_narrow_sentinel() {
    let g6 = graft_bits("UIADD3_UR_UP_UP_UR_II_UR", "", "ureg", 6, 6);
    // ctl payload with the sentinel truncation (URZ -> 0x3f):
    assert_eq!(enc_clean(&g6, "UIADD3 UR4, UP0, UP1, UR5, 0x80, URZ ;"),
        0x000000000f91e03f0000008005047890u128);
    assert_eq!(enc_clean(&g6, "UIADD3 UR4, UP0, UP1, UR5, 0x80, UR41 ;"),
        0x000000000f91e0290000008005047890u128);
    let g5 = graft_bits("UIADD3_UR_UP_UP_UR_II_UR", "", "ureg", 6, 5);
    let err = enc_err(&g5, "UIADD3 UR4, UP0, UP1, UR5, 0x80, URZ ;");
    assert!(err.contains("encode-lint"), "URZ below the sentinel floor must bail: {err}");
    let err = enc_err(&graft_bits("UIADD3_UR_UP_UP_UR_II_UR", "", "ureg", 6, 5),
        "UIADD3 UR4, UP0, UP1, UR5, 0x80, UR41 ;");
    assert!(err.contains("encode-lint"), "UR41 in a 5-bit window must bail: {err}");
}

// ---------------------------------------------------------------------------
// (c) Branch-fixup-owned target: never bailed regardless of the address.
// ---------------------------------------------------------------------------
#[test]
fn t140_6_branch_fixup_owned_targets_never_bail() {
    let t = t103();
    let insn = parse_sass("BRA 0x0 ;", 0).unwrap();
    encode_instruction(&insn, &t).unwrap();
    let insn = parse_sass("BRA 0x3930 ;", 0).unwrap();
    encode_instruction(&insn, &t).unwrap();
}

// ---------------------------------------------------------------------------
// CLI: default mode fail-closes on shipped-table silent truncation; the
// CUBIT_FIT_LINT=warn census mode reports and keeps the legacy payload.
// ---------------------------------------------------------------------------
#[test]
fn t140_7_cli_default_bails_warn_mode_reports() {
    let dir = std::env::temp_dir().join(format!("bug140_cli_{}_{}",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
    std::fs::create_dir_all(&dir).unwrap();
    let sass = dir.join("k.sass");
    std::fs::write(&sass, concat!(
        ".entry test_k
",
        "    .reg R0-R31
",
        "    DEPBAR.LE 0x0, 0x40 ;
",
        "    EXIT ;
")).unwrap();
    let run = |env: Option<&str>| -> (bool, String) {
        let out = dir.join(if env.is_some() { "w.cubin" } else { "n.cubin" });
        let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_cubit"));
        cmd.args(["asm", "-t", "tables/sm103a.json", "-o"])
            .arg(&out)
            .arg(&sass);
        if let Some(e) = env { cmd.env("CUBIT_FIT_LINT", e); }
        let r = cmd.output().unwrap();
        (r.status.success(), String::from_utf8_lossy(&r.stderr).into_owned())
    };
    let (ok_n, err_n) = run(None);
    assert!(!ok_n, "default mode must fail closed on the 0x40 truncation");
    assert!(err_n.contains("encode-lint"), "error names the lint: {err_n}");
    let (ok_w, err_w) = run(Some("warn"));
    assert!(ok_w, "warn census mode keeps the legacy payload: {err_w}");
    assert!(err_w.contains("[fit-lint]"), "warn mode logs the misfit: {err_w}");
    let _ = std::fs::remove_dir_all(&dir);
}

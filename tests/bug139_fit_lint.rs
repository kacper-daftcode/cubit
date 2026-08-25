//! BUG-139 (F2-Q follow-up of BUG-130): generic encode-lint "value must fit
//! field". Pre-fix, every field application truncated the operand payload
//! with `value & field.mask`, so an operand that did not fit its window was
//! silently re-issued as a DIFFERENT value (BUG-130: barrier id 16..255
//! masked to B0.., aliasing two live reconvergence regions; BUG-136: VOTEU
//! source predicate P4..P6 wrapped mod-4 by a narrow harvested mask).
//!
//! Post-fix two tiers in `extract_value`:
//!   TIER-1 (hard, fail-closed): guards, predicates, barriers, reuse and the
//!     0/1/2-domain flag extractions — total small domains with no
//!     split-window or sentinel carrier semantics. Any loss bails with an
//!     `encode-lint:` error naming the op, key, operand and would-be payload.
//!   TIER-2 (soft audit, `CUBIT_FIT_LINT=warn`): value-carrying families
//!     (reg/imm/addr/cmem/sysreg) keep the legacy masked payload, because the
//!     harvest model truncates there BY DESIGN — split windows across sibling
//!     fields (PLOP3.LUT lattice imm = imm[0:3)@64 + imm_shr3[3:8)@72),
//!     and_base/branch-fixup ownership (BRA/WARPSYNC label rows), sentinel
//!     carriers (RZ base 0xFF -> 0x7F in a 7-bit window, vendor-blessed per
//!     t123 goldens). Violations are logged under the env flag (census);
//!     promotion to hard needs the aggregate per-operand coverage model
//!     (see results/cubitfix/139.md).
//! Debug-build panic wraps (`7 - n` UPredGate, `1 - f` UrExplInv, `v - 1`
//! SubURm1 underflow) now return domain errors instead.

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

/// Patch one field's `bits` in the sm103a table and load the grafted copy.
fn grafted_table(key: &str, mods: &str, extraction: &str, token_idx: i64, bits: u32) -> IsaTable {
    let mut v: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string("tables/sm103a.json").unwrap()).unwrap();
    let fields = v["instructions"][key]["mod_groups"][mods]["fields"]
        .as_array_mut()
        .unwrap_or_else(|| panic!("no fields for {key}::{mods}"));
    let mut n = 0;
    for f in fields.iter_mut() {
        if f["extraction"] == extraction && f["token_idx"] == token_idx {
            f["bits"] = serde_json::Value::from(bits);
            n += 1;
        }
    }
    assert_eq!(n, 1, "expected exactly one {extraction}/tok{token_idx} field in {key}::{mods}");
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    let path = std::env::temp_dir().join(format!("bug139_graft_{}_{}.json", std::process::id(), nanos));
    std::fs::write(&path, serde_json::to_string(&v).unwrap()).unwrap();
    let t = IsaTable::load(&path).unwrap();
    let _ = std::fs::remove_file(&path);
    t
}

// ---------------------------------------------------------------------------
// TIER-1: a harvested-narrow predicate field bails loudly instead of
// re-issuing P5 as P1 (the BUG-136 mod-wrap class, closed at the encoder).
// ---------------------------------------------------------------------------
#[test]
fn t139_1_narrow_pred_field_fails_closed() {
    let g = grafted_table("SEL_R_R_R_P", "", "pred", 4, 2);
    let err = enc_err(&g, "SEL R0, R1, R2, P5 ;");
    assert!(err.contains("encode-lint"), "expected encode-lint bail, got: {err}");
    assert!(err.contains("operand 4"), "error must name the operand slot: {err}");
    // Controls: the grafted table still carries values that DO fit...
    let _ = enc_clean(&g, "SEL R0, R1, R2, P3 ;");
    // ...and the ungrafted table is untouched by the lint for this idiom.
    let _ = enc_clean(&t103(), "SEL R0, R1, R2, P5 ;");
}

// ---------------------------------------------------------------------------
// TIER-1: same for the guard slot — a 2-bit guard mask re-issues @!P2
// (guard 10) as @P2 (guard 2); now a loud bail.
// ---------------------------------------------------------------------------
#[test]
fn t139_2_narrow_guard_field_fails_closed() {
    let g = grafted_table("ISETP_P_P_R_R_P", "AND,EQ", "guard", 0, 2);
    let err = enc_err(&g, "@!P2 ISETP.EQ.AND P0, PT, R1, R2, PT ;");
    assert!(err.contains("encode-lint"), "expected encode-lint bail, got: {err}");
    let _ = enc_clean(&g, "@P1 ISETP.EQ.AND P0, PT, R1, R2, PT ;");
    let _ = enc_clean(&t103(), "@!P2 ISETP.EQ.AND P0, PT, R1, R2, PT ;");
}

// ---------------------------------------------------------------------------
// TIER-2 keeps legacy payloads byte-exact: pins captured from the pre-fix
// binary (174e2dcd control) over the known split-window / sentinel idioms.
// ---------------------------------------------------------------------------
#[test]
fn t139_3_legacy_payloads_byte_exact() {
    let t = t103();
    // PLOP3 lattice imm split: imm[0:3)@64 + imm_shr3[3:8)@72 carries 0x80.
    assert_eq!(enc_clean(&t, "PLOP3.LUT P0, P1, P2, P3, P4, 0x80, 0x8 ;"),
        0x00000000017070400000000000087804u128);
    // Two's-complement negative immediate.
    assert_eq!(enc_clean(&t, "IADD3 R0, PT, PT, R1, -0x1, R2 ;"),
        0x0000000007ffe002ffffffff01007810u128);
    // Const-mem combined offset field.
    assert_eq!(enc_clean(&t, "LDC R0, c[0x0][0x40] ;"),
        0x000000000000080000001000ff007b82u128);
    // RZ-base sentinel in a 7-bit window (vendor-blessed truncation idiom).
    assert_eq!(enc_clean(&t, "LDS.S8 R1, [RZ+0x10] ;"),
        0x0000000000000200000000087f017984u128);
    assert_eq!(enc_clean(&t, "S2R R2, SR_TID.X ;"),
        0x00000000000021000000000000027919u128);
    // Branch-fixup-owned operand row (dead imm field + BRA target fixup).
    assert_eq!(enc_clean(&t, "BRA 0x0 ;"),
        0x000000000383fffffffffffc00fc7947u128);
    assert_eq!(enc_clean(&t, "SEL R0, R1, R2, P5 ;"),
        0x00000000028000000000000201007207u128);
}

// ---------------------------------------------------------------------------
// TIER-2 soft audit: never bails on the census classes at the library level.
// ---------------------------------------------------------------------------
#[test]
fn t139_4_soft_audit_never_bails() {
    let t = t103();
    for line in [
        "PLOP3.LUT P0, P1, P2, P3, P4, 0x80, 0x8 ;", // lattice split window
        "LDS.S8 R1, [RZ+0x10] ;",                    // RZ sentinel truncation
        "BRA 0x0 ;",                                 // fixup-owned operand
        "IADD3 R0, PT, PT, R1, -0x1, R2 ;",          // two's complement
    ] {
        let insn = parse_sass(line, 0).unwrap();
        encode_instruction(&insn, &t).unwrap_or_else(|e| panic!("soft audit bailed on {line}: {e}"));
    }
}

// ---------------------------------------------------------------------------
// End-to-end through the CLI: the soft audit logs iff CUBIT_FIT_LINT=warn,
// the cubin payload is identical either way.
// ---------------------------------------------------------------------------
#[test]
fn t139_5_cli_warn_mode_logs_and_preserves_payload() {
    let dir = std::env::temp_dir().join(format!("bug139_cli_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let sass = dir.join("k.sass");
    std::fs::write(&sass, concat!(
        ".entry test_k\n",
        "    .reg R0-R31\n",
        "    PLOP3.LUT P0, P1, P2, P3, P4, 0x80, 0x8 ;\n",
        "    LDS.S8 R1, [RZ+0x10] ;\n",
        "    EXIT ;\n")).unwrap();
    let run = |env: Option<&str>| -> (bool, String, Vec<u8>) {
        let out = dir.join(if env.is_some() { "w.cubin" } else { "n.cubin" });
        let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_cubit"));
        cmd.args(["asm", "-t", "tables/sm103a.json", "-o"])
            .arg(&out)
            .arg(&sass);
        if let Some(e) = env { cmd.env("CUBIT_FIT_LINT", e); }
        let r = cmd.output().unwrap();
        (r.status.success(), String::from_utf8_lossy(&r.stderr).into_owned(),
         std::fs::read(&out).unwrap())
    };
    let (ok_w, err_w, cubin_w) = run(Some("warn"));
    let (ok_n, err_n, cubin_n) = run(None);
    assert!(ok_w && ok_n, "soft audit must never break assembly");
    assert!(err_w.contains("[fit-lint] encode-lint: `PLOP3.LUT`"),
        "warn mode must log the lattice split: {err_w}");
    assert!(!err_n.contains("[fit-lint]"), "default mode stays silent: {err_n}");
    assert_eq!(cubin_w, cubin_n, "warn mode must not change the payload");
    let _ = std::fs::remove_dir_all(&dir);
}

//! g15a-stale (F2Q; dryf powierzchni po BUG-099/095): frozen-disasm of the
//! certified R0b now renders era LTC128B.128 words with the canon plain
//! bracket form `[R.U32+URx+off]` whose UR slot carries the desc/payload
//! namespace (values >= 64, e.g. `[R69.U32+UR64+0x10]`). RA apply used to
//! demand those numerals from the plan -- `plan misses UR64` -- bailing out
//! of the G15a decode-transfer proof. Doctrine mirror of the Desc arm:
//! < 64 = architectural uniform register (remappable via the plan), >= 64 =
//! desc/payload namespace (pass-through opaque; validate_coverage_apply
//! keeps rejecting UR>=64 plan keys).

use cubit::ra::{run_file, ApplyPlan, RaMode};

fn ksrc(body: &str) -> String {
    format!(".entry k\n    .reg R0-R255\n{body}    EXIT ;\n.endentry\n")
}

fn plan_with(r: &[(u8, u8)], ur: &[(u8, u8)]) -> ApplyPlan {
    let mut k = cubit::ra::ApplyPlanKernel::default();
    for &(s, d) in r {
        k.r.insert(s.to_string(), d);
    }
    for &(s, d) in ur {
        k.ur.insert(s.to_string(), d);
    }
    let mut p = ApplyPlan::default();
    p.kernels.insert("k".to_string(), k);
    p
}

#[test]
fn t_descns_ur64_addr_passthrough() {
    // The exact G15a-stale shape: LDG.E.LTC128B.128 plain-rendered with a
    // >= 64 UR slot; the plan covers only the hot R base. Apply must
    // succeed, rename the R base, and leave the UR slot untouched.
    let src = ksrc("    MOV R7, 0x4 ;\n    LDG.E.LTC128B.128 R0, [R7.U32+UR64+0x10] ;\n    IMAD R2, R0, R1, RZ ;\n");
    let p = plan_with(&[(7, 100), (0, 40), (1, 41), (2, 42)], &[]);
    let run = run_file(&src, RaMode::ApplyFile(p)).unwrap();
    assert!(run.out_text.contains("[R100.U32+UR64+0x10]"), "{}", run.out_text);
}

#[test]
fn t_descns_ur8_addr_still_remapped() {
    // < 64 UR slots in the bracket form stay architectural (desc[URx<64]
    // pair-base doctrine): the plan owns them and the byte gets renamed.
    let src = ksrc("    UMOV UR8, 0x10 ;\n    MOV R7, 0x4 ;\n    LDG.E.LTC128B.128 R0, [R7.U32+UR8+0x10] ;\n    IMAD R2, R0, R1, RZ ;\n");
    let p = plan_with(&[(7, 100), (0, 40), (1, 41), (2, 42)], &[(8, 20)]);
    let run = run_file(&src, RaMode::ApplyFile(p)).unwrap();
    assert!(run.out_text.contains("[R100.U32+UR20+0x10]"), "{}", run.out_text);
}

#[test]
fn t_descns_ur64_plan_key_still_rejected() {
    // Doctrine unchanged: the desc namespace is not allocatable -- a plan
    // entry for UR64 must keep failing closed.
    let src = ksrc("    MOV R7, 0x4 ;\n    LDG.E.LTC128B.128 R0, [R7.U32+UR64+0x10] ;\n    IMAD R2, R0, R1, RZ ;\n");
    let p = plan_with(&[(7, 100), (0, 40), (1, 41), (2, 42)], &[(64, 65)]);
    assert!(run_file(&src, RaMode::ApplyFile(p)).is_err());
}

#[test]
fn t_descns_constmem_ur64_passthrough() {
    // Same namespace rule on the ConstMem arm: c[bank][R+URm+off] with
    // m >= 64 passes through opaque, R base still remapped.
    let src = ksrc("    MOV R7, 0x4 ;\n    LDC.64 R0, c[0x0][R7+UR64+0x210] ;\n    IMAD R2, R0, R1, RZ ;\n");
    let p = plan_with(&[(7, 100), (0, 40), (1, 41), (2, 42)], &[]);
    let run = run_file(&src, RaMode::ApplyFile(p)).unwrap();
    assert!(run.out_text.contains("c[0x0][R100+UR64+0x210]"), "{}", run.out_text);
}

//! M4.3a: standalone IR -> SASS text renderer. Byte-exact identity on the
//! certified R0b corpus is BARRACUDA gate G14a (results/fe/M4); here: unit
//! rendering rules per operand class, the label-anchor contract, the
//! structural self-check and fail-closed doctrine.

use cubit::ra::{apply_plan, plan_for_mode, RaMode};
use cubit::reg_liveness::reg_xfer;
use cubit::render::{render_file, run_file};
use cubit::sass_file::parse_sass_file_str_strict;

fn body() -> &'static str {
    "    .reg R0-R224\n    .param u64 p0\n"
}

#[test]
fn t_render_identity_simple() {
    let src = format!(
        ".entry k\n{}    [B------:R-:W0:Y:S01] S2R R0, SR_TID.X ;\n    [B------:R-:W-:Y:S09] IMAD.SHL.U32 R4, |R0|, 0x20, RZ ;\n    EXIT ;\n.endentry\n",
        body()
    );
    let out = run_file(&src, true).unwrap();
    assert_eq!(out, src, "render must be byte-identical");
}

#[test]
fn t_render_operand_classes() {
    // one instruction per operand surface the R0b census carries
    let lines = [
        "    [B------:R-:W-:Y:S09] IADD3 R3, PT, PT, R3, -0x1, RZ ;",
        "    [B------:R-:W0:Y:S02] LDG.E.LTC128B.128 R8, desc[UR8][R6.64+0x5000] !rsd[0:1,73:1,76:0] ;",
        "    [B------:R5:W-:Y:S02] STS.128 [R5.X16+0x10], R204 ;",
        "    [B------:R-:W-:Y:S01] LDCU.64 UR0, c[0x0][0x358] ;",
        "    [B------:R-:W-:Y:S06] UIADD3.X UR53, UPT, UPT, UR2, 0xa, URZ ;",
        "    [B------:R-:W-:Y:S09] MOV R81, 0x1 ;",
        "    [B------:R-:W-:Y:S09] ISETP.EQ.AND P0, PT, R3, 0x0, PT ;",
        "    [B------:R-:W-:Y:S09] IMAD.WIDE.U32 R90, R60, R61, RZ ;",
        "    [B------:R-:W-:Y:S09] MOV R3, ~R2 ;",
        "    [B------:R-:W-:Y:S09] MOV R3, -R2 ;",
        "    [B------:R-:W-:Y:S09] IMAD R4, R5.reuse, R6, RZ ;",
        "    [B---345:R-:W-:Y:S01] BAR.SYNC.DEFER_BLOCKING 0x0 ;",
        "    [B------:R-:W-:Y:S01] UISETP.?GT.?S32.?OR UP0, UPT, UR63, UR15, UPT ;",
        "    [B------:R-:W-:-:S01] @!P0 BRA L_e0 !rsd[32:1] ;",
        "L_170:  [B------:R-:W-:Y:S01] IADD3 R3, PT, PT, R3, 0x1, RZ ;",
        "    [B------:R-:W-:-:S06] EXIT ;",
    ];
    let src = format!(".entry k\n{}{}\n.endentry\n", body(), lines.join("\n"));
    let out = run_file(&src, true).unwrap();
    assert_eq!(out, src, "operand-class render drifted");
}

#[test]
fn t_render_orphan_labels_preserved() {
    // Labels that no branch targets (metafix/block anchors like L_8710)
    // must survive parse -> render (KernelDef.labels contract).
    let src = format!(
        ".entry k\n{}    [B------:R-:W-:Y:S01] MOV R0, 0x0 ;\nL_10:  [B------:R-:W-:Y:S01] MOV R1, 0x1 ;\nL_20:\nL_30:  [B------:R-:W-:Y:S01] MOV R2, 0x2 ;\n    EXIT ;\n.endentry\n",
        body()
    );
    let out = run_file(&src, true).unwrap();
    // L_10 rides its instruction (addr 0x10); the stacked pair L_20/L_30 both
    // anchor at 0x20: first as a label-only line, last on the instruction.
    let want = src.replacen("L_20:\nL_30:  [B", "L_20:\nL_30:  [B", 1);
    assert_eq!(out, want, "stacked/orphan labels drifted");
    let sf = parse_sass_file_str_strict(&src).unwrap();
    let k = &sf.kernels[0];
    assert_eq!(k.labels.len(), 2, "labels map keyed by addr");
    assert_eq!(k.labels[&0x20], vec!["L_20".to_string(), "L_30".to_string()]);
}

#[test]
fn t_render_trailing_label_fail_closed() {
    // A label with no following instruction has no carrier: refuse to drop it.
    let src = format!(
        ".entry k\n{}    [B------:R-:W-:Y:S01] EXIT ;\nL_tail:\n.endentry\n",
        body()
    );
    let e = render_file(&parse_sass_file_str_strict(&src).unwrap())
        .expect_err("trailing label must fail closed");
    let msg = format!("{e:#}");
    assert!(msg.contains("not anchored") || msg.contains("label"), "msg: {msg}");
}

#[test]
fn t_render_verify_detects_drift() {
    // structural_eq deltas trip the self-check (operands differ).
    let src = format!(
        ".entry k\n{}    [B------:R-:W-:Y:S01] MOV R0, 0x0 ;\n    EXIT ;\n.endentry\n",
        body()
    );
    let mut sf = parse_sass_file_str_strict(&src).unwrap();
    // renumber R0 -> R5 WITHOUT a plan (direct IR poke): render then verify
    // against tex ORIGINAL semantics is impossible here (verify compares
    // parse(render(IR)) vs IR, which is self-consistent) -- so instead prove
    // structural_eq catches a hand-made IR delta.
    let sf2 = parse_sass_file_str_strict(&src.replace("R0, 0x0", "R5, 0x0")).unwrap();
    assert!(cubit::render::structural_eq(&sf, &sf2).is_err());
    // and sanity: run_file(verify) passes on the untampered file
    assert!(run_file(&src, true).is_ok());
    // mutate IR then render+verify consistency holds also post-RA:
    let xfers: Vec<_> = sf.kernels[0].instructions.iter().map(reg_xfer).collect();
    let pxfers: Vec<_> = sf.kernels[0]
        .instructions
        .iter()
        .map(|i| cubit::pred_liveness::pred_xfer(i, cubit::pred_liveness::XferMode::Strict))
        .collect();
    let plan = plan_for_mode(&RaMode::Identity, "k", &xfers, &pxfers).unwrap();
    apply_plan(&mut sf.kernels[0].instructions, &plan).unwrap();
    let out = render_file(&sf).unwrap();
    let sf3 = parse_sass_file_str_strict(&out).unwrap();
    assert!(cubit::render::structural_eq(&sf, &sf3).is_ok());
}

#[test]
fn t_render_no_ctrl_prefix_when_not_hand_sched() {
    // Bare (non-frozen) lines render bare: builder-style input without the
    // [B..:R..:W..:Y:S..] prefix must NOT gain one.
    let src = "    IMAD R1, R2, 0x4, RZ ;\n    EXIT ;\n";
    let full = format!(".entry k\n{}{src}.endentry\n", body());
    let out = run_file(&full, true).unwrap();
    assert_eq!(out, full);
}

#[test]
fn t_render_raw_verbatim_word() {
    // __raw__ lines render as the frozen token, unaffected by ctrl handling.
    let hex = "8845c00081c7f60a8000000000000000";
    let src = format!(".entry k\n{}    __raw__0x{hex} ;\n    EXIT ;\n.endentry\n", body());
    let out = render_file(&parse_sass_file_str_strict(&src).unwrap()).unwrap();
    assert!(out.contains(&format!("    __raw__0x{hex} ;")), "out: {out}");
}

#[test]
fn t_render_multi_kernel_blank_line() {
    let k = |n: &str| {
        format!(".entry {n}\n{}    EXIT ;\n.endentry\n", body())
    };
    let src = format!("{}\n{}", k("a"), k("b"));
    let out = run_file(&src, true).unwrap();
    assert_eq!(out, src, "exactly one blank line between kernels");
}

#[test]
fn t_render_guard_forms() {
    let lines = [
        "    @P2 MOV R0, 0x0 ;",
        "    @!P2 MOV R0, 0x0 ;",
        "    @UP2 UMOV UR1, 0x0 ;",
        "    @!UPT NLUR ;",
    ];
    let src = format!(".entry k\n{}{}\n    EXIT ;\n.endentry\n", body(), lines.join("\n"));
    let out = run_file(&src, true).unwrap();
    assert_eq!(out, src, "guard render drifted");
}

#[test]
fn t_render_fail_closed_double_guard() {
    let src = format!(".entry k\n{}    @P2 @P5 MOV R0, 0x0 ;\n.endentry\n", body());
    assert!(run_file(&src, true).is_err(), "double guard must fail closed");
}

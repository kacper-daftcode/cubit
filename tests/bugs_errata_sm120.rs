//! Regression tests for the sm120lab silicon errata (results/cubit-bugs,
//! BUG-001..011, fixed 2026-08-18). Every test is tool-level (no GPU): the
//! silicon proofs live in the bug package; here we pin the tool behavior.
//!
//! Table scope: the traps are sm_120 findings; the sm_103a table shares the
//! engine, so guards that would regress ptxas-faithful sm_103a flows must be
//! provably quiet there (asserted too).

use cubit::decoder::DecodeIndex;
use cubit::encoder::{encode_instruction, errata_warnings};
use cubit::parser::parse_sass;
use cubit::sass_file::{auto_detect_resources, kernel_def_to_meta, parse_sass_file_str};
use cubit::table::IsaTable;

fn t120() -> IsaTable {
    IsaTable::load(std::path::Path::new("tables/sm120.json")).unwrap()
}
fn t103a() -> IsaTable {
    IsaTable::load(std::path::Path::new("tables/sm103a.json")).unwrap()
}
const SCHED: u128 = 0x1FFFFu128 << (64 + 41);
fn enc(table: &IsaTable, s: &str) -> u128 {
    // parse_cuasm_line (not bare parse_sass) so frozen `[B...] CC` prefixes work.
    let insn = cubit::parse_cuasm_line(s, 0).unwrap();
    encode_instruction(&insn, table).unwrap()
}
fn enc_clean(table: &IsaTable, s: &str) -> u128 {
    enc(table, s) & !SCHED
}
fn enc_err(table: &IsaTable, s: &str) -> String {
    let insn = parse_sass(s, 0).unwrap();
    encode_instruction(&insn, table).unwrap_err().to_string()
}
fn warns(table: &IsaTable, s: &str) -> Vec<String> {
    let insn = parse_sass(s, 0).unwrap();
    errata_warnings(&insn, table)
}

// ── BUG-001 ─────────────────────────────────────────────────────────────────
// PRMT text order is the HARDWARE order (d, a, sel, b) — same order nvdisasm
// prints — not the PTX order (d, a, b, sel). The encoder must keep matching
// the NVIDIA corpus reference word, and the PTX-idiom-with-immediate must
// fail with an explicit operand-order hint.
#[test]
fn bug001_prmt_hw_order_matches_corpus_reference() {
    let t = t120();
    // Reference: libcublasLt .320 sm_120 — PRMT R6, RZ, 0x7610, R6.
    // Corpus word (sched masked): lo64=0x00007610_ff068816 -> selector 0x7610
    // in the [55:32] imm field, b register R6 at [71:64].
    let w = enc_clean(&t, "PRMT R6, RZ, 0x7610, R6 ;");
    assert_eq!(w as u64, 0x0000_7610_ff06_7816,
               "HW-order text must encode selector at [55:32], b at [71:64]");
    assert_eq!((w >> 64) as u32, 0x0000_0006);
    // PTX order silently swaps sel/b by construction — pin the behavior AND
    // the README-documented convention (word content, not an error).
    let w_ptx = enc_clean(&t, "PRMT R20, R10, R11, R12 ;");
    assert_eq!((w_ptx >> 32) as u32 & 0xFF, 11, "operand 3 lands in the sel slot");
}

#[test]
fn bug001_prmt_ptx_idiom_with_imm_selector_errors_with_hint() {
    let t = t120();
    let e = enc_err(&t, "PRMT R20, R10, R11, 0x7610 ;");
    assert!(e.contains("no operand-compatible table entry"), "{e}");
    assert!(e.contains("PRMT note"), "missing operand-order hint: {e}");
}

// ── BUG-002 ─────────────────────────────────────────────────────────────────
// IMAD.HI used to encode a word silicon runs as IMAD.WIDE.U32: Rd = LOW half,
// Rd+1 CLOBBERED (iter60 hi_t.sass). Fail-closed on sm_120.
#[test]
fn bug002_imad_hi_is_fail_closed_on_sm120() {
    let t = t120();
    for s in [
        "IMAD.HI R20, R10, R11, RZ ;",
        "IMAD.HI.U32 R20, R10, R11, RZ ;",
        "IMAD.HI R20, P2, R10, R11, RZ ;",
    ] {
        let e = enc_err(&t, s);
        assert!(e.contains("BUG-002") || e.contains("CLOBBERED") || e.contains("IMAD.HI"),
                "{s} must fail with the BUG-002 diagnosis, got: {e}");
    }
    // The silicon-true replacement stays encodable:
    let w1 = enc_clean(&t, "IMAD.WIDE.U32 R20, R10, R11, RZ ;");
    let w2 = enc_clean(&t, "IMAD.WIDE R20, R10, R11, RZ ;");
    assert_ne!(w1, 0); assert_ne!(w2, 0);
}

#[test]
fn bug002_sm103a_hi_forms_left_alone() {
    // sm_103a corpus carries ptxas-emitted IMAD.HI.U32 forms that hardware
    // honors; the fail-closed rule must not fire there.
    let t = t103a();
    let insn = parse_sass("IMAD.HI.U32 R20, R10, R11, RZ ;", 0).unwrap();
    // Must either encode or fail for UNRELATED table reasons (no BUG-002 text).
    if let Err(e) = encode_instruction(&insn, &t) {
        assert!(!e.to_string().contains("BUG-002"), "sm_103a must not errata-fail: {e}");
    }
}

// ── BUG-004 ─────────────────────────────────────────────────────────────────
// P7 used to alias to PT (identical 128-bit word) — every @P7 / ->P7 fired on
// all lanes (iter61). Now a clear hard error, for operands and guards alike.
#[test]
fn bug004_p7_is_a_hard_error() {
    for tab in [t120(), t103a()] {
        for s in [
            "ISETP.GE.AND P7, PT, R4, R10, PT ;",
            "ISETP.GE.AND PT, PT, R4, R10, P7 ;",
            "@P7 IADD3 R5, R6, R7, RZ ;",
            "@!P7 IADD3 R5, R6, R7, RZ ;",
            "VOTE.ANY P7, PT, PT ;",
        ] {
            let insn = parse_sass(s, 0).unwrap();
            let e = encode_instruction(&insn, &tab).unwrap_err().to_string();
            assert!(e.contains("BUG-004") || e.contains("invalid predicate literal"),
                    "{s} must fail closed (BUG-004), got: {e}");
        }
    }
}

#[test]
fn bug004_out_of_range_predicates_also_fail() {
    let t = t120();
    for s in ["ISETP.GE.AND P8, PT, R4, R10, PT ;", "ISETP.GE.AND PT, PT, R4, R10, P19 ;"] {
        let insn = parse_sass(s, 0).unwrap();
        assert!(encode_instruction(&insn, &t).is_err(), "{s} must fail");
    }
}

#[test]
fn bug004_pt_and_real_preds_unchanged() {
    let t = t120();
    let pt = enc_clean(&t, "ISETP.GE.AND PT, PT, R4, R10, PT ;");
    let p5 = enc_clean(&t, "ISETP.GE.AND P5, PT, R4, R10, PT ;");
    let p6 = enc_clean(&t, "ISETP.GE.AND P6, PT, R4, R10, PT ;");
    assert_ne!(pt, p5); assert_ne!(p5, p6); assert_ne!(pt, p6);
}

// ── BUG-005 ─────────────────────────────────────────────────────────────────
// Plain WARPSYNC with a register membermask: accepted by cubit+nvdisasm,
// ILLEGAL on sm_120 silicon depending on the surrounding schedule (iter60).
// Encodes (the word is structurally fine) but the driver must WARN on sm_120.
#[test]
fn bug005_warpsync_reg_mask_warns_on_sm120_only() {
    let w = warns(&t120(), "WARPSYNC R7 ;");
    assert!(w.iter().any(|m| m.contains("BUG-005")), "WARN missing: {w:?}");
    assert!(warns(&t120(), "WARPSYNC.ALL ;").is_empty());
    assert!(warns(&t103a(), "WARPSYNC R7 ;").is_empty());
    // still encodes (word is table-valid; the trap is silicon context)
    assert_ne!(enc(&t120(), "WARPSYNC R7 ;"), 0);
}

// ── BUG-006 ─────────────────────────────────────────────────────────────────
// Negated carry-in predicates on .X forms: slot (a) IMAD.WIDE.U32.X cin and
// slot (b) IADD3.X cin1 used to drop the neg bit silently — silicon then read
// the UN-negated value (iter64 chain measured 3M+2 vs 3M). Table now carries
// neg@90 for these slots; anything .X whose neg would still drop must error.
#[test]
fn bug006_cin_neg_bits_encode() {
    let t = t120();
    // (b) IADD3.X cin1 (Bug repro pair used to be bit-identical)
    let a = enc_clean(&t, "IADD3.X R10, PT, PT, RZ, RZ, RZ, PT, P1 ;");
    let b = enc_clean(&t, "IADD3.X R10, PT, PT, RZ, RZ, RZ, !PT, P1 ;");
    assert_ne!(a, b, "cin1 neg must flip a bit");
    assert_eq!(a ^ b, 1u128 << 90, "cin1 neg must be exactly bit90 (had: xor 0x{:x})", a ^ b);
    // control: cin2 neg sits at bit80 (unchanged, pre-existing correct path)
    let c = enc_clean(&t, "IADD3.X R10, PT, PT, RZ, RZ, RZ, P1, PT ;");
    let d = enc_clean(&t, "IADD3.X R10, PT, PT, RZ, RZ, RZ, P1, !PT ;");
    assert_eq!(c ^ d, 1u128 << 80);
    // (a) IMAD.WIDE.U32.X cin
    let e1 = enc_clean(&t, "IMAD.WIDE.U32.X R8, P1, R12, R12, RZ, PT ;");
    let e2 = enc_clean(&t, "IMAD.WIDE.U32.X R8, P1, R12, R12, RZ, !PT ;");
    assert_eq!(e1 ^ e2, 1u128 << 90, "IMAD.WIDE.U32.X cin neg must be bit90");
}

#[test]
fn bug006_unencodable_x_cin_neg_fails_closed() {
    // sm_103a has no corpus evidence for the cin1 neg slot -> no field ->
    // the negation must NOT silently drop there.
    let t = t103a();
    let insn = parse_sass("IADD3.X R10, PT, PT, RZ, RZ, RZ, !PT, P1 ;", 0).unwrap();
    match encode_instruction(&insn, &t) {
        Err(e) => assert!(e.to_string().contains("BUG-006"), "{e}"),
        Ok(_) => panic!("sm_103a must fail closed for !PT in IADD3.X cin1"),
    }
    // .. while the encodable cin2 path keeps working
    assert_ne!(enc_clean(&t, "IADD3.X R10, PT, PT, RZ, RZ, RZ, P1, PT ;"),
               enc_clean(&t, "IADD3.X R10, PT, PT, RZ, RZ, RZ, P1, !PT ;"));
}

// ── BUG-007 ─────────────────────────────────────────────────────────────────
// `cubit disassemble` used to render tail STG.E words as `LDG.E.LTC128B ...`
// (an LDG key's pred@81 field hijacked the match via an unscoped disambiguation
// divert). Not re-assemblable. Words must now print STG and round-trip exactly.
#[test]
fn bug007_stg_desc_words_decode_as_stg() {
    let t = t120();
    let idx = DecodeIndex::build(&t);
    for src in [
        "STG.E desc[UR4][R2.64], R6 ;",
        "STG.E desc[UR4][R2.64+0x4], R7 ;",
        "STG.E desc[UR4][R2.64], R177 ;",
    ] {
        let w = enc(&t, src);
        let d = idx.decode(w, 0, &t).unwrap();
        let text = cubit::printer::to_sass(&d);
        assert!(text.starts_with("STG.E"), "must decode as STG.E, got: {text}");
        // byte-faithful round-trip (modulo scheduling)
        let insn = parse_sass(&text, 0).unwrap();
        let w2 = encode_instruction(&insn, &t).unwrap();
        assert_eq!(w & !SCHED, w2 & !SCHED, "{src} must round-trip");
    }
}

// ── BUG-008 ─────────────────────────────────────────────────────────────────
// 4-operand IMAD.WIDE with c != RZ: silicon reads c as the 64-bit pair
// (Rc,Rc+1) — a register the text never names silently shapes the hi half.
// Encodable (ptxas emits the form too) but the driver warns loudly; sm_103a
// (ptxas-faithful corpus) stays quiet.
#[test]
fn bug008_wide_cpair_warns_precisely() {
    let w = warns(&t120(), "IMAD.WIDE.U32 R46, R34, 0x3d1, R18 ;");
    assert!(w.iter().any(|m| m.contains("BUG-008") && m.contains("R19")), "{w:?}");
    assert!(warns(&t120(), "IMAD.WIDE.U32 R46, R34, 0x3d1, RZ ;").is_empty());
    assert!(warns(&t120(), "IMAD.WIDE.U32 R46, PT, R34, R35, R18 ;").is_empty());
    assert!(warns(&t103a(), "IMAD.WIDE.U32 R2, R5, 0x8, R2 ;").is_empty());
    // ptxas-faithful encodings keep working everywhere
    assert_ne!(enc(&t120(), "IMAD.WIDE.U32 R46, R34, 0x3d1, R18 ;"), 0);
}

// ── BUG-009 (ported at source) ──────────────────────────────────────────────
// IMAD.WIDE.U32.X with an immediate b operand was missing from the table even
// though hardware has the form (iter75 ximm fix, pod-side only). Ported.
#[test]
fn bug009_wide_x_imm_b_encodes() {
    let t = t120();
    let a = enc_clean(&t, "IMAD.WIDE.U32.X R8, P1, R12, 0x3d1, RZ, PT ;");
    let b = enc_clean(&t, "IMAD.WIDE.U32.X R8, P1, R12, 0x3d1, RZ, !PT ;");
    assert_ne!(a, 0);
    assert_eq!(a ^ b, 1u128 << 90, "imm-b form must keep the cin neg slot");
}

// ── BUG-010 ─────────────────────────────────────────────────────────────────
// Frozen re-encode of DEPBAR/MEMBAR lost the sched-window bits b104..111: the
// encoder took the barrier epoch verbatim and discarded the parsed control
// word. Now hand-scheduled CCs merge into the epoch frame (as NOP already did).
#[test]
fn bug010_frozen_depbar_membar_ctrl_roundtrips() {
    let t = t120();
    // CC strings are derived from the RC kernel_sm120.cubin reference words.
    let dep = enc(&t, "[B------:R-:W-:Y:S04] DEPBAR.LE SB0, 0x9 !rsd[41:1] ;");
    assert_eq!(dep, 0x000f_e800_0000_0000_0000_8240_0000_791a,
               "want the RC DEPBAR word (had 0x...e200.. pre-fix): 0x{dep:032x}");
    let mem = enc(&t, "[B------:R-:W-:-:S06] MEMBAR.GPU.SC ;");
    assert_eq!(mem, 0x000f_cc00_0000_2000_0000_0000_0000_7992,
               "want the RC MEMBAR.GPU.SC word: 0x{mem:032x}");
    // text WITHOUT a control prefix keeps the epoch default (fresh asm unchanged)
    let dep_default = enc(&t, "DEPBAR.LE SB0, 0x9 ;");
    assert_eq!((dep_default >> 96) as u32 & !0x1C00_0000, 0x000f_e200 & !0x1C00_0000,
               "epoch default must be unchanged for unannotated text");
}

// ── BUG-011 ─────────────────────────────────────────────────────────────────
// REGCOUNT: `.reg R0-R255` emitted 256 (invalid; R255 is the RZ alias), and
// --eiattr-from rebuilds TRUNCATED the template's 255 to 128 -> silicon
// "illegal instruction" at launch (iter77). Both paths must yield 255.
#[test]
fn bug011_regcount_clamps_to_255() {
    let sass = ".entry k\n    .reg R0-R255\n    EXIT ;\n.endentry\n";
    let mut f = parse_sass_file_str(sass).unwrap();
    for def in &mut f.kernels { auto_detect_resources(def); }
    let meta = kernel_def_to_meta(&f.kernels[0], &[0u8; 16]);
    assert_eq!(meta.regcount, 255, "REGCOUNT must clamp at the hardware max");
}

#[test]
fn bug011_rebuild_never_lowers_template_regcount() {
    use cubit::elf_builder::{build_cubin_for_arch, rebuild_cubin, KernelEntry};
    let t = t120();
    // template: 255-reg kernel
    let mk = |body: &str, regs: &str| -> Vec<u8> {
        let sass = format!(".entry k\n    .reg {regs}\n{body}\n.endentry\n");
        let mut f = parse_sass_file_str(&sass).unwrap();
        for def in &mut f.kernels { auto_detect_resources(def); }
        let def = &f.kernels[0];
        let mut insns = def.instructions.clone();
        cubit::scheduling_pass::schedule(&mut insns, Some(&t));
        let mut code = vec![0u8; insns.len() * 16];
        for (i, in_) in insns.iter().enumerate() {
            let w = encode_instruction(in_, &t).unwrap();
            code[i * 16..i * 16 + 8].copy_from_slice(&(w as u64).to_le_bytes());
            code[i * 16 + 8..i * 16 + 16].copy_from_slice(&((w >> 64) as u64).to_le_bytes());
        }
        let meta = kernel_def_to_meta(def, &code);
        build_cubin_for_arch(&[KernelEntry {
            name: "k".into(), code, meta, mercury_stub: None, opcodes: None,
        }], t.ef_flags).unwrap()
    };
    let template = mk("    EXIT ;", "R0-R255");
    // patch with small-reg code: rebuild must keep the template's 255
    let patch_sass = ".entry k\n    .reg R0-R31\n    EXIT ;\n.endentry\n";
    let mut f = parse_sass_file_str(patch_sass).unwrap();
    for def in &mut f.kernels { auto_detect_resources(def); }
    let small = {
        let def = &f.kernels[0];
        let mut insns = def.instructions.clone();
        cubit::scheduling_pass::schedule(&mut insns, Some(&t));
        let mut code = vec![0u8; insns.len() * 16];
        for (i, in_) in insns.iter().enumerate() {
            let w = encode_instruction(in_, &t).unwrap();
            code[i * 16..i * 16 + 8].copy_from_slice(&(w as u64).to_le_bytes());
            code[i * 16 + 8..i * 16 + 16].copy_from_slice(&((w >> 64) as u64).to_le_bytes());
        }
        code
    };
    let out = rebuild_cubin(&template, &[("k", small, None)]).unwrap();
    // find the REGCOUNT SVAL record: 04 2f 08 00 <sym4> <rc4>
    let mut rc = None;
    for i in 0..out.len().saturating_sub(12) {
        if out[i..i + 4] == [0x04, 0x2f, 0x08, 0x00] {
            rc = Some(u32::from_le_bytes(out[i + 8..i + 12].try_into().unwrap()));
            break;
        }
    }
    assert_eq!(rc, Some(255), "rebuild must preserve the template REGCOUNT floor");
}

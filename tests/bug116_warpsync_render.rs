//! BUG-116: WARPSYNC collective
//! render printed the RAW offset field (e.g. "0x5") instead of the resolved partner
//! vendor target (nvdisasm: `\((.L_x_N)`) — text->word did not round-trip.
//!
//! Data truth (full harvest of 2145 cubins / 33,258,037 instrs, 262,879 WARPSYNC
//! words, nvdisasm 13.3 -hex + L-label resolution):
//!  * forms: WARPSYNC.ALL (30,871), WARPSYNC Rn (1,032), WARPSYNC.EXCLUSIVE Rn
//!    (32), WARPSYNC.COLLECTIVE Rn,(L) (226,828), WARPSYNC.COLLECTIVE.ALL (L)
//!    (4,116).  DISCRIMINATORS: bit9=1 <=> reg operand; bit11=1 <=> .ALL.
//!  * collective geometry: the PER-SAMPLE target == addr + 16 + (v<<4), v =
//!    [23:18]|[43:34]<<6 (230,944/230,944, zero exceptions; the corpus has vhi=0
//!    everywhere and v6 in {2,3} for the reg form / {3,5} for the ALL form).
//!  * the previous fits were census-EXACT (and_base/vmask); what was wrong was
//!    `fields`: WARPSYNC_IIALL::"ALL,COLLECTIVE" imm 32b (the field wrapped around
//!    reg/ctrl bits; encode wrote the raw operand over REL16 -> garbage,
//!    mk33 failures_run.jsonl already shows this on 2026-08-13 as the text "0x5910"),
//!    WARPSYNC_R_II::"COLLECTIVE" imm 2b (under-sized vs the REL16 window).
//!  * the printer trigger `key.starts_with("WARPSYNC_R_")` did not cover the
//!    register-less form (WARPSYNC_II) -> render "0x5", i.e. the raw field.
//!
//! Fix (data-level + trigger):
//!  * tables/sm103a.json: both collective rows' imm -> 6b (REL16 low
//!    window; the encoder rewrites everything via apply_branch_encoding anyway;
//!    the field exclusion in the matcher closes the v=5 reg-form hole on decode).
//!  * src/printer.rs: resolved trigger = opcode WARPSYNC && mod COLLECTIVE
//!    && operand II (covers R_II and II regardless of the key name).
//!  * The mod spelling stays canonical "ALL.COLLECTIVE" (mk66 documents it;
//!    nvdis prints "COLLECTIVE.ALL" — a known, deliberate render-parity delta).
//!
//! Pins (1)(2)(4) FAIL before the fix, PASS after; (3)(5) anchors.

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::IsaTable;

fn t103() -> IsaTable {
    IsaTable::load(std::path::Path::new("tables/sm103a.json")).unwrap()
}

/// libcusolver.so.1025.sm_100.cubin @0x4360: WARPSYNC.COLLECTIVE.ALL `(.L_x_98);
/// vendor label .L_x_98 stoi na 0x43c0 (v=5: 0x4360+16+5*16 = 0x43c0).
const W_ALL: u128 = 0x02cfea0003c00000_0000000000147948;
/// libcusparse.so.167.sm_103.cubin @0x39e0: WARPSYNC.COLLECTIVE R40, `(.L_x_14415)
/// (v=3 -> target 0x39e0+16+0x30 = 0x3a20). Kontrola formy reg z v!=2.
const W_REG_V3: u128 = 0x021fea0003c00000_00000000280c7348;
/// Korpus NIE ma reg-form z bit20=1 (v>=4): syntetyka z W_REG_V3 (v 3->5,
/// R40 zachowany) — dziura decode-matching wypelniona field-6b@18,
/// geometria dzielona z BRA/CALL/RET (REL16). Target = 0x39e0+16+0x50.
const W_REG_V5_SYNTH: u128 = (0x021fea0003c00000u128 << 64)
    | (((0x280c7348u64 & !((0x3F) << 18)) | ((5u64) << 18)) as u128);
/// Anchory: libcusolver.so.403.sm_103.cubin @0x4d0 WARPSYNC R32;
/// libcusolver.so.1673.sm_103.cubin @0x8d50 WARPSYNC.EXCLUSIVE R16;
/// fa4_m5.cubin @0xf10 WARPSYNC.ALL.
const W_R32: u128 = 0x000fea0003800000_0000000020007348;
const W_EXCL: u128 = 0x000fea0003a00000_0000000010007348;
const W_ALL_PLAIN: u128 = 0x000fea0003800000_0000000000007948;

const NOSCHED: u128 = !(0xFFFF_FFFFu128 << 96);

fn dec103(word: u128, addr: u32) -> String {
    let t = t103();
    let idx = DecodeIndex::build(&t);
    let d = idx.decode(word, addr, &t).expect("decode failed");
    to_sass(&d)
}

fn enc103(text: &str, addr: u32) -> u128 {
    let insn = parse_sass(text, addr).unwrap_or_else(|e| panic!("parse {text:?}: {e}"));
    encode_instruction(&insn, &t103()).unwrap_or_else(|e| panic!("encode {text:?}: {e}"))
}

/// t116_1: the register-less form (WARPSYNC_II/"ALL,COLLECTIVE") renders the
/// RESOLVED target, not the raw field "0x5".
#[test]
fn t116_1_all_form_renders_resolved_target() {
    let s = dec103(W_ALL, 0x4360);
    assert_eq!(s, "WARPSYNC.ALL.COLLECTIVE 0x43c0",
               "render musi resolvowac partner target (vendor .L_x_98 @0x43c0): {s}");
    assert!(s.ends_with("0x43c0"), "surowy field wrocil: {s}");
}

/// t116_2: encode resolved targetu formy .ALL == vendor slowo (masked);
/// kontrola regresji field-spill 32b@18 (pre-fix encode "0x43c0" dawal
/// 0x...10f147948 — smieci ponad oknem REL16).
#[test]
fn t116_2_all_form_encode_byte_exact_masked() {
    let c = enc103("WARPSYNC.ALL.COLLECTIVE 0x43c0", 0x4360);
    assert_eq!(c & NOSCHED, W_ALL & NOSCHED,
               "encode resolved: {c:032x} vs vendor {W_ALL:032x}");
}

/// t116_3: kotwice form — reg v=3, plain R32, EXCLUSIVE R16, ALL-plain
/// decode unchanged (pre==post behavior).
#[test]
fn t116_3_plain_and_reg_forms_unchanged() {
    assert_eq!(dec103(W_REG_V3, 0x39e0), "WARPSYNC.COLLECTIVE R40, 0x3a20");
    assert_eq!(dec103(W_R32, 0x4d0), "WARPSYNC R32");
    assert_eq!(dec103(W_EXCL, 0x8d50), "WARPSYNC.EXCLUSIVE R16");
    assert_eq!(dec103(W_ALL_PLAIN, 0xf10), "WARPSYNC.ALL");
    // and re-encode byte-exact (masked) for the target-less forms:
    for (w, txt, addr) in [
        (W_R32, "WARPSYNC R32 ;", 0x4d0u32),
        (W_EXCL, "WARPSYNC.EXCLUSIVE R16", 0x8d50),
        (W_ALL_PLAIN, "WARPSYNC.ALL ;", 0xf10),
    ] {
        assert_eq!(enc103(txt, addr) & NOSCHED, w & NOSCHED, "anchor {txt}");
    }
}

/// t116_4: the decode->text->encode round-trip on the collective forms is
/// byte-exact (masked) — jadro "lossy" z rejestru (pre-fix: text niosl
/// the raw field; encode wrote it over REL16 => a different word).
#[test]
fn t116_4_collective_roundtrip_byte_exact() {
    for (w, addr) in [(W_ALL, 0x4360u32), (W_REG_V3, 0x39e0)] {
        let s = dec103(w, addr);
        let c = enc103(&s, addr);
        assert_eq!(c & NOSCHED, w & NOSCHED, "roundtrip {s} @0x{addr:x}");
    }
}

/// t116_5: rozszerzenie ponad korpus (REL16-doctrine): reg-form z v=5
/// (bit20) decodes to the resolved target, not __raw__. Pre-fix: strict/
/// relaxed/BROAD did not match (and_base baked bit19=1, the 2b field
/// did not cover bit20).
#[test]
fn t116_5_reg_form_v5_beyond_corpus_resolves() {
    let s = dec103(W_REG_V5_SYNTH, 0x39e0);
    assert_eq!(s, "WARPSYNC.COLLECTIVE R40, 0x3a40", "v=5 syntetyka: {s}");
    let c = enc103(&s, 0x39e0);
    assert_eq!(c & NOSCHED, W_REG_V5_SYNTH & NOSCHED, "v=5 roundtrip: {s}");
}

/// t116_6: vendor spelling + label form e2e (strict file-parse, like bug091):
/// "COLLECTIVE.ALL" normalizuje do grupy "ALL,COLLECTIVE"; `(.L_x_1) ->
/// BranchTarget; encode na korpusowych koordynatach = vendor slowo (masked).
#[test]
fn t116_6_vendor_spelling_and_label_flow() {
    use cubit::sass_file::parse_sass_file_str_strict;
    let sass = ".entry k\n    .reg R0-R15\n\
        WARPSYNC.COLLECTIVE.ALL `(.L_x_1) ;\n\
        NOP ;\n    NOP ;\n\
        \x20   .L_x_1:\n\
        EXIT ;\n.endentry\n";
    let file = parse_sass_file_str_strict(sass).expect("nvdisasm-style text must assemble");
    let insns = &file.kernels[0].instructions;
    assert_eq!(insns.len(), 4);
    assert_eq!(insns[0].opcode, "WARPSYNC");
    match &insns[0].operands[0] {
        cubit::ir::Operand::BranchTarget(t) => assert_eq!(*t, 0x30, "target: {t:#x}"),
        other => panic!("operand must be BranchTarget: {other:?}"),
    }
    // rq przy relokacji na koordynaty korpusowe (0x4360 -> 0x43c0, v=5):
    let shifted = cubit::ir::Instruction {
        addr: 0x4360,
        operands: vec![cubit::ir::Operand::BranchTarget(0x43c0)],
        ..insns[0].clone()
    };
    let w = encode_instruction(&shifted, &t103()).expect("encode shifted");
    assert_eq!(w & NOSCHED, W_ALL & NOSCHED, "vendor slowo: {w:032x} vs {W_ALL:032x}");
    // numeric target (nasza forma canon) identycznie:
    let insn = parse_sass("WARPSYNC.ALL.COLLECTIVE 0x43c0 ;", 0x4360).unwrap();
    let cw = encode_instruction(&insn, &t103()).unwrap();
    assert_eq!(cw & NOSCHED, W_ALL & NOSCHED, "numeric target");
}

/// t116_7 (harness, gated): full census of 262,879 WARPSYNC words from the corpus
/// (CUBIT_WS_CENSUS -> work/f2-115/ws_words.json, JSON array) — decode kazdego
/// words + render re-encode masked-identical; zero __raw__. SKIP when env absent.

#[test]
fn t116_7_corpus_census_gated() {
    let Ok(path) = std::env::var("CUBIT_WS_CENSUS") else { return };
    let data = std::fs::read_to_string(path).expect("census file");
    let arr: Vec<serde_json::Value> = serde_json::from_str(&data).expect("json array");
    let t = t103();
    let idx = DecodeIndex::build(&t);
    let mut n = 0u64;
    for v in &arr {
        let w = u128::from_str_radix(v["word"].as_str().unwrap().trim_start_matches("0x"), 16).unwrap();
        let addr = u32::from_str_radix(v["addr"].as_str().unwrap(), 16).unwrap();
        let d = idx.decode(w, addr, &t).unwrap_or_else(|e| panic!("decode {w:032x}: {e}"));
        let s = to_sass(&d);
        assert!(!s.contains("__raw__"), "raw w renderze: {s}");
        let insn = parse_sass(&s, addr).unwrap_or_else(|e| panic!("parse {s:?}: {e}"));
        let c = encode_instruction(&insn, &t).unwrap_or_else(|e| panic!("encode {s:?}: {e}"));
        assert_eq!(c & NOSCHED, w & NOSCHED, "census roundtrip {s} @0x{addr:x} ({w:032x})");
        n += 1;
    }
    eprintln!("t116_7 census ok: {n} words");
}


//! BUG-059 (from M4.8 silicon work): ARCH-DELTA
//! legality sm120 -> sm_103a for the consumer IMNMX opcode class.
//! The sm120-era rt98 lineage carries 21 words of
//! `IMNMX.S64 P0, P0, (|)Rn|, Rn, imm, PT, P0` shape (and_base 0x*817 class).
//! The same bytes ran EXACT on sm_120 (rt98_pub 19-20 GK/s), decode+encode
//! cleanly under both repo tables -- but on B300 (sm_103a) the capsule traps
//! CUDA_ERROR_ILLEGAL_INSTRUCTION at KernelA+0x4640, and the m48 probe series
//! showed the opcode FORM itself is illegal: exact-bytes w/ era guard (P2),
//! payload w/ PT guard (P1), ALL predicate slots forced PT (P3) all ILLEGAL;
//! ptxas never emits consumer IMNMX for sm_103a (u32 -> VIMNMX.U32, s64 ->
//! UISETP+USEL emulation); pred-output VIMNMX is also illegal (P5), so no
//! legal 1:1 mapping exists.
//! Fix (F2 policy option (a)): the sm103a.json row stays DECODE-ONLY (RE of
//! era sm120 cubins keeps rendering), and the encoder fails closed on
//! target sm_103a for base-op IMNMX. UIMNMX/UVIMNMX (uniform datapath) are
//! deliberately NOT covered by the guard -- no silicon probe exists either
//! way (F2Q-060-kand audits era/lookup-provenance rows more broadly).
//! Evidence: results/fe/M4/M4_8_silicon.md + m48_silicon/silicon_log.txt.

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::table::IsaTable;

fn t103a() -> IsaTable {
    IsaTable::load(std::path::Path::new("tables/sm103a.json")).unwrap()
}
fn t120() -> IsaTable {
    IsaTable::load(std::path::Path::new("tables/sm120.json")).unwrap()
}

const KB_FORM: &str = "IMNMX.S64 P0, P0, |R218|, R218, 0x3ffff, PT, P0";
const KA_FORM: &str = "@!P4 IMNMX.S64 P0, P0, R115, R115, 0xf, PT, P0";

fn enc(text: &str, t: &IsaTable) -> anyhow::Result<u128> {
    let insn = parse_sass(&format!("{text} ;"), 0).map_err(|e| anyhow::anyhow!("parse: {e}"))?;
    encode_instruction(&insn, t)
}

// (1) the era forms must fail closed under sm_103a, with the silicon citation.
#[test]
fn t1_sm103a_imnmx_kb_form_rejected() {
    let e = enc(KB_FORM, &t103a()).expect_err("era IMNMX must not encode for sm_103a");
    let m = format!("{e}");
    assert!(m.contains("BUG-059") && m.contains("SILICON-ILLEGAL"), "got: {m}");
}

#[test]
fn t2_sm103a_imnmx_guarded_form_rejected() {
    let e = enc(KA_FORM, &t103a()).expect_err("guarded era IMNMX must not encode for sm_103a");
    assert!(format!("{e}").contains("BUG-059"), "got: {e}");
}

// (2) arch scoping: the identical text stays encodable for sm_120 (silicon-
// proven legal there; rt98_pub ran EXACT at 19-20 GK/s).
#[test]
fn t3_sm120_imnmx_forms_still_encode() {
    enc(KB_FORM, &t120()).expect("sm120 must keep encoding era IMNMX (KB form)");
    enc(KA_FORM, &t120()).expect("sm120 must keep encoding era IMNMX (KA form)");
}

// (3) decode-only retention: the exact era word still decodes+renders under
// sm103a.json (RE of legacy cubins unaffected by the encoder guard).
#[test]
fn t4_sm103a_decode_of_era_word_retained() {
    let t = t103a();
    let idx = DecodeIndex::build(&t);
    let d = idx
        .decode(0x020fec00038002000003ffffdada7817u128, 0, &t)
        .expect("era IMNMX word must stay decodable under sm103a.json");
    assert_eq!(cubit::printer::to_sass(&d), KB_FORM);
}

// (4) guard precision: it keys on the exact base op, so UIMNMX (uniform
// datapath, unprobed) and unrelated ALU ops must not see the BUG-059 path.
#[test]
fn t5_guard_precision_not_blanket() {
    // IMAD round-trips fine under sm_103a.
    enc("IMAD R10, R2, R3, RZ", &t103a()).expect("plain IMAD unaffected");
    // UIMNMX.S64 text: whatever the table verdict is, it must NOT be the
    // BUG-059 guard (no silicon evidence for the uniform path).
    if let Err(e) = enc("UIMNMX.S64 P0, P0, UR4, UR5, UR6, PT, P0", &t103a()) {
        assert!(
            !format!("{e}").contains("BUG-059"),
            "UIMNMX must not hit the consumer-IMNMX guard, got: {e}"
        );
    }
}

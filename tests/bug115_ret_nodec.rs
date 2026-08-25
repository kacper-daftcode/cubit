//! BUG-115: RET.REL.NODEC over-fit harvest — two accidental
//! AND-split cohorts in `tables/sm103a.json`:
//!  * `RET_II` (phantom): and_base == the literal FA4 W_B word, fields=[],
//!    count=2 -> won strict-match via priority, IR lost the register.
//!  * `RET_R_II`: bit24 (reg bit0) baked 0 (the corpus carried only even
//!    registers) + corridor bits [55:34] partially baked.
//!
//! Data truth (full harvest over 2145 cubins, 33,258,037
//! instructions, 11,714 RET words — 100% `RET.REL.NODEC Rn, 0x0`):
//!  the [63:32] corridor is NOTHING ELSE than the sm_103a REL16 imm: rq=(t-addr-16)>>4,
//!  rq[5:0]@[23:18], rq[15:6]@[43:34], sign-ext [63:44] (the same geometry
//!  as CALL/BRA, via encoder.rs apply_branch_encoding). 11,703/11,714 words
//!  imply target=0x0 (trap pads after BPT.TRAP, landings at kernel
//!  ends), and 11 words are the legal forward target 0x100000. The 0x54 vs
//!  0xec split is an address-histogram artifact, NOT two semantic kinds.
//!
//! Fix (data-level, the phantom-delete + field-width-widen doctrine):
//!  * `RET_II` removed from the table (zero corpus words without a register).
//!  * `RET_R_II`: and_base = AND(11714), variable_mask = XOR-OR(11714)
//!    OR (1<<24) — the full 8 reg-field bits. count = 11714.
//!
//! Pins: (1)-(3) FAIL before the fix, PASS after; (4)-(5) behavior anchors.

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::table::IsaTable;

fn t103() -> IsaTable {
    IsaTable::load(std::path::Path::new("tables/sm103a.json")).unwrap()
}

/// FA4 trap pad: two words after BPT.TRAP (fa4_fwd_hdim64_fp16_full.cubin).
const W_A: u128 = 0x000fea0003c3ffff_ffffff54_023c7950; // @0xab00
const W_B: u128 = 0x000fea0003c3ffff_ffffff54_02307950; // @0xab30
/// Normalna kohorta (merclab q_tail_call.cubin @0x0110, nvdisasm-verbatim).
const W_C: u128 = 0x000fea0003c3ffff_fffffffc_02b87950;
/// Region outside scheduling (as in bug049): the decoder matches 96 bits.
const NOSCHED: u128 = !(0xFFFF_FFFFu128 << 96);

fn dec103(word: u128, addr: u32) -> cubit::decoder::DecodedInst {
    let idx = DecodeIndex::build(&t103());
    idx.decode(word, addr, &t103()).expect("decode failed")
}

fn enc103(text: &str, addr: u32) -> u128 {
    let insn = parse_sass(text, addr).unwrap_or_else(|e| panic!("parse {text:?}: {e}"));
    encode_instruction(&insn, &t103()).unwrap_or_else(|e| panic!("encode {text:?}: {e}"))
}

/// t115_1: both trap-pad words decode into full IR with a register
/// (key RET_R_II, Ra=R2), not into the phantom field-less form.
#[test]
fn t115_1_trap_pad_words_decode_with_register() {
    for (w, addr) in [(W_A, 0xab00u32), (W_B, 0xab30)] {
        let d = dec103(w, addr);
        assert_eq!(d.key, "RET_R_II", "fantom RET_II wrocil? {d}");
        let ra = d
            .fields
            .iter()
            .find(|f| f.name == "Ra")
            .expect("brak pola Ra — rejestr stracony");
        assert_eq!(ra.value, 2, "{w:#x} powinno niesc R2");
        assert_eq!(format!("{d}").trim_end_matches([' ', ';']),
                   "RET.REL.NODEC R2, 0x0", "{w:#x} render");
    }
}

/// t115_2: rejestry NIEPARZYSTE (korpus 0/11714 — poprzedni and_base
/// baked bit24=0) decode natively; the reg field = a full 8 bits.
#[test]
fn t115_2_odd_register_decodes_natively() {
    let w3 = (W_A & !(0xFFu128 << 24)) | (3u128 << 24); // RET.REL.NODEC R3 cohort
    let d = dec103(w3, 0xab00);
    assert_eq!(d.key, "RET_R_II");
    let ra = d.fields.iter().find(|f| f.name == "Ra").expect("Ra lost");
    assert_eq!(ra.value, 3);
}

/// t115_3: tekst -> slowo bajtowo odtwarza oba slowa trap-pada na ich
/// adresach (natywny 0-rsd roundtrip, doktryna "zadnego __raw__").
#[test]
fn t115_3_text_reencodes_trap_pads_byte_exact() {
    for (w, addr) in [(W_A, 0xab00u32), (W_B, 0xab30), (W_C, 0x0110)] {
        let rc = enc103("RET.REL.NODEC R2, 0x0", addr);
        assert_eq!(rc & NOSCHED, w & NOSCHED,
                   "re-encode @{addr:#x} rozjechal: {:#034x} vs {:#034x}",
                   rc & NOSCHED, w & NOSCHED);
    }
}

/// t115_4: the normal cohort — control anchor (render identical to
/// the vendor's: nvdisasm 13.3 prints "RET.REL.NODEC R2, 0x0" for W_C).
#[test]
fn t115_4_normal_cohort_anchor() {
    let d = dec103(W_C, 0x0110);
    assert_eq!(format!("{d}").trim_end_matches([' ', ';']),
               "RET.REL.NODEC R2, 0x0");
    assert_eq!(d.key, "RET_R_II");
}

/// t115_5: the `RET_II` phantom does not exist in the table (a pill against a
/// 2-sample harvest regression); the sole owner of opcode 0x950 is the R form.
#[test]
fn t115_5_phantom_ret_ii_removed() {
    let t = t103();
    assert!(!t.entries.contains_key("RET_II"),
            "RET_II phantom re-introduced");
    // The register-less form ("RET.REL.NODEC 0x0") — nothing to encode with,
    // stays fail-closed (corpus: 0 occurrences).
    let insn = parse_sass("RET.REL.NODEC 0x0", 0);
    match insn {
        Err(_) => {} // parse does not know the form: OK
        Ok(i) => assert!(encode_instruction(&i, &t).is_err(),
                         "bez-rejestrowy RET musi zostac fail-closed"),
    }
}

/// t115_6: the rq21 encoder — RET from distant addresses to 0x0 rebuilds the
/// vendora bajtowo (payload): (a) rq ujemny z wrap imm16-pozytywnym:
/// curand/libcurand.so.16 @0xad3d0 (R58); (b) rq ujemny z rq[16]=1:
/// cusolver/libcusolver.so.43 @0x10c710 (R20, ext 0xFFFFE, bit44=0).
/// Pre-fix (enc 16+blanket-ones): (a) dropped [63:44] (kept and_base),
/// (b) emitted 0xFFFFF instead of 0xFFFFE — both words would have to land
/// in !rsd[44:1]; now native.
#[test]
fn t115_6_far_ret_words_encode_byte_exact() {
    for (w, addr, text) in [
        (0x002fec0003c3ffff_fffff52c_3a087950u128, 0xad3d0u32, "RET.REL.NODEC R58, 0x0"),
        (0x001fea0003c3ffff_ffffef38_14387950u128, 0x10c710u32, "RET.REL.NODEC R20, 0x0"),
    ] {
        let rc = enc103(text, addr);
        assert_eq!(rc & NOSCHED, w & NOSCHED,
                   "rq21 lost: {:#034x} vs {:#034x}", rc & NOSCHED, w & NOSCHED);
        // ...and the decoder walks forward on that word with the same text
        let d = dec103(w, addr);
        assert_eq!(format!("{d}").trim_end_matches([' ', ';']), text,);
    }
}

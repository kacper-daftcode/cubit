//! BUG-115 (F2-Q, dyrektywa wlasciciela 2026-08-24: "RET.NODEC trzeba
//! poprawic, zadnego __raw__"): RET.REL.NODEC over-fit harvest — dwie
//! przypadkowe koharty AND-split w `tables/sm103a.json`:
//!  * `RET_II` (fantom): and_base == doslownie slowo FA4 W_B, fields=[],
//!    count=2 -> ciagnela strict-match przez priority, IR tracilo rejestr.
//!  * `RET_R_II`: bit24 (reg bit0) wypieczony 0 (korpus mial tylko parzyste
//!    rejestry) + corridor-bits [55:34] czesciowo wypieczone.
//!
//! Prawda danych (pelny harvest nad korpusem 2145 cubinow, 33,258,037
//! instrukcji, 11,714 slow RET — 100% `RET.REL.NODEC Rn, 0x0`):
//!  corridor [63:32] to NIC INNEGO jak imm REL16 sm_103a: rq=(t-addr-16)>>4,
//!  rq[5:0]@[23:18], rq[15:6]@[43:34], sign-ext [63:44] (ta sama geometria
//!  co CALL/BRA, z encoder.rs apply_branch_encoding). 11,703/11,714 slow
//!  implikuje target=0x0 (trap-pady za BPT.TRAP, landingi na koncach
//!  kerneli), 11 slow to legalny forward-target 0x100000. Split 0x54 vs
//!  0xec to artefakt histogramu adresow, NIE dwa rodzaje semantyczne.
//!
//! Fix (data-level, doktryna fantom-delete + field-width widen):
//!  * `RET_II` usuniety z tabeli (zero slow korpusu bez rejestru).
//!  * `RET_R_II`: and_base = AND(11714), variable_mask = XOR-OR(11714)
//!    OR (1<<24) — pelne 8 bit pola reg. count = 11714.
//!
//! Piny: (1)-(3) FAIL przed fixem, PASS po; (4)-(5) kotwice zachowania.

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::table::IsaTable;

fn t103() -> IsaTable {
    IsaTable::load(std::path::Path::new("tables/sm103a.json")).unwrap()
}

/// FA4 trap-pad: dwa slowa po BPT.TRAP (fa4_fwd_hdim64_fp16_full.cubin).
const W_A: u128 = 0x000fea0003c3ffff_ffffff54_023c7950; // @0xab00
const W_B: u128 = 0x000fea0003c3ffff_ffffff54_02307950; // @0xab30
/// Normalna kohorta (merclab q_tail_call.cubin @0x0110, nvdisasm-verbatim).
const W_C: u128 = 0x000fea0003c3ffff_fffffffc_02b87950;
/// Region poza schedulingiem (jak w bug049): dekoder matchuje 96 bitow.
const NOSCHED: u128 = !(0xFFFF_FFFFu128 << 96);

fn dec103(word: u128, addr: u32) -> cubit::decoder::DecodedInst {
    let idx = DecodeIndex::build(&t103());
    idx.decode(word, addr, &t103()).expect("decode failed")
}

fn enc103(text: &str, addr: u32) -> u128 {
    let insn = parse_sass(text, addr).unwrap_or_else(|e| panic!("parse {text:?}: {e}"));
    encode_instruction(&insn, &t103()).unwrap_or_else(|e| panic!("encode {text:?}: {e}"))
}

/// t115_1: oba slowa trap-pada dekoduja sie do pelnego IR z rejestrem
/// (klucz RET_R_II, Ra=R2), nie do fantomowej formy bez-pola.
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
/// piekl bit24=0) dekoduja sie natywnie; pole reg = pelne 8 bitow.
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

/// t115_4: kohorta normalna — kotwica sterowania (render identyczny jak
/// u vendora: nvdisasm 13.3 drukuje "RET.REL.NODEC R2, 0x0" dla W_C).
#[test]
fn t115_4_normal_cohort_anchor() {
    let d = dec103(W_C, 0x0110);
    assert_eq!(format!("{d}").trim_end_matches([' ', ';']),
               "RET.REL.NODEC R2, 0x0");
    assert_eq!(d.key, "RET_R_II");
}

/// t115_5: fantom `RET_II` nie istnieje w tabeli (pill przeciw regresji
/// harvestu 2-probkowego); jedynym wlascicielem opcode 0x950 jest R-forma.
#[test]
fn t115_5_phantom_ret_ii_removed() {
    let t = t103();
    assert!(!t.entries.contains_key("RET_II"),
            "RET_II phantom re-introduced");
    // Forma bez-rejestrowa ("RET.REL.NODEC 0x0") — nie ma czym enkodowac,
    // zostaje fail-closed (korpus: 0 wystapien).
    let insn = parse_sass("RET.REL.NODEC 0x0", 0);
    match insn {
        Err(_) => {} // parse nie zna formy: OK
        Ok(i) => assert!(encode_instruction(&i, &t).is_err(),
                         "bez-rejestrowy RET musi zostac fail-closed"),
    }
}

/// t115_6: enkoder rq21 — RET z dalekich adresow do 0x0 odtwarza słowa
/// vendora bajtowo (payload): (a) rq ujemny z wrap imm16-pozytywnym:
/// curand/libcurand.so.16 @0xad3d0 (R58); (b) rq ujemny z rq[16]=1:
/// cusolver/libcusolver.so.43 @0x10c710 (R20, ext 0xFFFFE, bit44=0).
/// Pre-fix (enc 16+blanket-ones): (a) gubił [63:44] (zostawiał and_base),
/// (b) nadawał 0xFFFFF zamiast 0xFFFFE — oba słowa musiałyby lądować
/// w !rsd[44:1]; teraz natywnie.
#[test]
fn t115_6_far_ret_words_encode_byte_exact() {
    for (w, addr, text) in [
        (0x002fec0003c3ffff_fffff52c_3a087950u128, 0xad3d0u32, "RET.REL.NODEC R58, 0x0"),
        (0x001fea0003c3ffff_ffffef38_14387950u128, 0x10c710u32, "RET.REL.NODEC R20, 0x0"),
    ] {
        let rc = enc103(text, addr);
        assert_eq!(rc & NOSCHED, w & NOSCHED,
                   "rq21 lost: {:#034x} vs {:#034x}", rc & NOSCHED, w & NOSCHED);
        // ...i dekoder idzie naprzód na tym słowie z tym samym tekstem
        let d = dec103(w, addr);
        assert_eq!(format!("{d}").trim_end_matches([' ', ';']), text,);
    }
}

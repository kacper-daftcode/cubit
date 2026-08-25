//! BUG-071 (F2Q-071, from the 068 sweeps): ENCODER — harvest rows with baked
//! imm/ureg payloads in and_base and no field for the token in question made texts
//! with a default payload (imm 0 / URZ) emit the BAKED constants (severity A):
//!   FMUL.FTZ R4, R5, 0x0 -> a word with payload 0.5f (nvdisasm: "0.5")
//!   FADD R1, R2, 0x0     -> payload 1.0f; a nonzero imm -> encode FAIL
//!   FMUL.FTZ .., UR6     -> the FTZ-UR row without a ureg field -> FTZ lost
//!                           through the (key,"") fallback [mod-drop class]
//!   FADD R2, R3, URZ     -> ureg narrow 4b -> URZ&0xF = UR15 (corruption)
//!
//! Oracle (work/f2-068/, nvdisasm13.3 sm_120): vendor FMUL.FTZ imm word
//! 0x0000000000410000_<f32>_00007820 (bit80 = FTZ), FADD imm 0.5 ->
//! ..._7421; the UR FTZ form = non-FTZ UR | bit80 (bit91 = UR signature);
//! URZ = 0xff on the [39:32] window (sweep window=0/63/255).
//!
//! Fix: data-level repair of 5 sm120.json rows (3x FMUL FTZ, FADD_R_R_II,
//! FADD_R_R_UR width 4->8) + the zero_payload_junk sentinel (encoder.rs):
//! an operand with a default payload on a fieldless token + baked bits in a
//! sibling-proven window = REJECT (fail-closed instead of junk emit,
//! when no correct form matches).

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::table::IsaTable;

fn t120() -> IsaTable {
    IsaTable::load(std::path::Path::new("tables/sm120.json")).unwrap()
}
const SCHED: u128 = 0xFFFF_FFFFu128 << 96;

fn enc(sass: &str, t: &IsaTable) -> u128 {
    let insn = parse_sass(&format!("{sass};"), 0).unwrap();
    encode_instruction(&insn, t).unwrap()
}

#[test]
fn bug071_fmul_ftz_imm_payload_exact() {
    let t = t120();
    // zero payload must EMIT zero (vendor: imm-form imm=0 is legal; ptxas
    // merely canonicalizes to RZ)
    assert_eq!((enc("FMUL.FTZ R4, R5, 0x0", &t) >> 32) & 0xFFFF_FFFF, 0);
    assert_eq!((enc("FMUL.FTZ R4, R5, 0.0", &t) >> 32) & 0xFFFF_FFFF, 0);
    // non-zero payloads exact
    assert_eq!((enc("FMUL.FTZ R4, R5, 0.5", &t) >> 32) & 0xFFFF_FFFF, 0x3f00_0000);
    assert_eq!((enc("FMUL.FTZ R4, R5, -2.0", &t) >> 32) & 0xFFFF_FFFF, 0xc000_0000);
    // FTZ discriminator bit80 + register placement
    let w = enc("FMUL.FTZ R4, R5, 0.5", &t);
    assert_eq!((w >> 80) & 1, 1, "FTZ bit");
    assert_eq!((w >> 16) & 0xFF, 4);
    assert_eq!((w >> 24) & 0xFF, 5);
    // vendor-pinned unconditional shape (guard=PT overlays [15:12]=7)
    let w0 = enc("FMUL.FTZ R4, R5, 0x0", &t) & !SCHED;
    assert_eq!(w0 & 0xFFFF, 0x7820, "opcode+guard low16, got {w0:032x}");
}

#[test]
fn bug071_fadd_imm_and_ur_payloads() {
    let t = t120();
    assert_eq!((enc("FADD R1, R2, 0x0", &t) >> 32) & 0xFFFF_FFFF, 0);
    assert_eq!((enc("FADD R1, R2, 0.25", &t) >> 32) & 0xFFFF_FFFF, 0x3e80_0000);
    // pre-Fix: FADD with a non-zero immediate failed closed; now encodable
    assert!(encode_instruction(&parse_sass("FADD R1, R2, 0x3f000000 ;", 0).unwrap(), &t).is_ok());
    // UR window full width: URZ=0xff, UR63 real (0x3f), UR6
    assert_eq!((enc("FADD R2, R3, URZ", &t) >> 32) & 0xFF, 0xff);
    assert_eq!((enc("FADD R2, R3, UR63", &t) >> 32) & 0xFF, 63);
    assert_eq!((enc("FADD R2, R3, UR6", &t) >> 32) & 0xFF, 6);
}

#[test]
fn bug071_fmul_ftz_ur_form_keeps_ftz_and_ur() {
    let t = t120();
    let idx = DecodeIndex::build(&t);
    let w = enc("FMUL.FTZ R4, R5, UR6", &t);
    assert_eq!((w >> 80) & 1, 1, "FTZ must survive on the UR form");
    assert_eq!((w >> 32) & 0xFF, 6);
    let d = idx.decode(w & !SCHED, 0, &t).unwrap();
    assert_eq!(cubit::printer::to_sass(&d), "FMUL.FTZ R4, R5, UR6");
    // URZ round-trip
    let w2 = enc("FMUL.FTZ R4, R5, URZ", &t);
    assert_eq!((w2 >> 32) & 0xFF, 0xff);
    let d2 = idx.decode(w2 & !SCHED, 0, &t).unwrap();
    assert_eq!(cubit::printer::to_sass(&d2), "FMUL.FTZ R4, R5, URZ");
}

#[test]
fn bug071_decode_reencode_fixed_points() {
    let t = t120();
    let idx = DecodeIndex::build(&t);
    for sass in [
        "FMUL.FTZ R4, R5, 0",
        "FMUL.FTZ R4, R5, 0.5",
        "@P0 FMUL.FTZ R11, R7, 0.25",
        "FADD R1, R2, 0.25",
        "FADD R2, R3, URZ",
        "FADD R2, R3, UR6",
    ] {
        let w = enc(sass, &t);
        let text = cubit::printer::to_sass(&idx.decode(w & !SCHED, 0, &t).unwrap());
        let w2 = enc(&text, &t);
        assert_eq!(w2 & !SCHED, w & !SCHED, "not a fixed point: {sass} -> {text}");
    }
}

#[test]
fn bug071_zero_payload_junk_guard_fail_closed() {
    // Synthetic table: FMUL_R_R_II with a clean sibling (f32 field proves the
    // token-3 window) and a junk-baked modgroup with no field. Text that hits
    // ONLY the junk entry must fail CLOSED (not emit the baked 0.5f).
    let dir = std::env::temp_dir().join(format!("bug071_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let table = r#"{
 "_meta": {"ef_flags": 1510114562},
 "instructions": {
  "FMUL_R_R_II": {
   "base_op": "FMUL", "operand_sig": "R_R_II",
   "mod_groups": {
    "EXPR": {
     "and_base": "0x00000000004100003f000000080c0820",
     "fields": [
      {"shift": 12, "bits": 4, "token_idx": 0, "extraction": "guard"},
      {"shift": 16, "bits": 8, "token_idx": 1, "extraction": "reg"},
      {"shift": 24, "bits": 8, "token_idx": 2, "extraction": "reg"},
      {"shift": 122, "bits": 1, "token_idx": 2, "extraction": "reuse"}
     ],
     "variable_mask": "0x1c00000000000300c0000000fffff000"
    },
    "EXPR,CLEAN": {
     "and_base": "0x00000000024100000000000000007820",
     "fields": [
      {"shift": 12, "bits": 4, "token_idx": 0, "extraction": "guard"},
      {"shift": 16, "bits": 8, "token_idx": 1, "extraction": "reg"},
      {"shift": 24, "bits": 8, "token_idx": 2, "extraction": "reg"},
      {"shift": 32, "bits": 32, "token_idx": 3, "extraction": "f32"},
      {"shift": 122, "bits": 1, "token_idx": 2, "extraction": "reuse"}
     ],
     "variable_mask": "0x1c00000000000300fffffffffffff000"
    }
   }
  }
 }
 }"#;
    let path = dir.join("t071_synth.json");
    std::fs::write(&path, table).unwrap();
    let t = IsaTable::load(&path).unwrap();
    let insn = parse_sass("FMUL.EXPR R4, R5, 0x0 ;", 0).unwrap();
    let r = encode_instruction(&insn, &t);
    let msg = format!("{r:?}");
    assert!(r.is_err(), "junk row must not encode default-payload text: {msg}");
    assert!(msg.contains("BUG-071-class"), "guard attribution in error: {msg}");
    // non-zero imm was already fail-closed via completeness (no field)
    let insn2 = parse_sass("FMUL.EXPR R4, R5, 0.5 ;", 0).unwrap();
    assert!(encode_instruction(&insn2, &t).is_err());
}

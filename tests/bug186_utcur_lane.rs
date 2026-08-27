//! BUG-186 (F2-iter91, front2/blind): tcgen05 UTC*MMA lane — byte48 window-law
//! hygiene + mk296 tok2 repair + idesc elision render parity.
//!
//! Defects on main 2bd2a82 (zero corpus exposure; proven by arbitration):
//!   D1 (decode): '' UTCOMMA 6II words with gdesc2 != 0xff FAILED strict match
//!      (tok2 field duplicated on tok1's (24,8) window, so byte32 sat in
//!      match_mask) and fell to prio-3, which hijacked the family:
//!      ptxas-13.3.73 gold witness (kind::mxf4 2X) decoded as
//!      `UTCHMMA ..._UR_UP` (CUBIT_DEBUG_DECODE candidates, work/bug186).
//!   D2 (render): derived idesc printed `UR256` when tok4 tmem = 0xff; vendor
//!      propagates the elision sentinel: `tmem[URZ], idesc[URZ]` (arb186b on
//!      the ptxas witness; arb186c on the ''-lane fmha anchor @0x3090).
//!   D3 (encode): on '' UTCOMMA/6II texts, tok2 gdesc went to [24:32)
//!      (clobbering tok1) and byte32 kept the baked 0xff — silent wrong code;
//!      vendor byte32=0x04 in the witness word.
//!   H  (hygiene): stale training consts under the declared (48,8) field
//!      contradicted the vendor window law (arb186a 8/8 2CTA sweep: any UR,
//!      0xff elides): ab48=0x08/`tc5-verify-const8` on 2CTA _UR_ groups,
//!      vm48=0x0c on '' _UR_, ab48=0x06/0x04 + vm48=0x00/0x7e/0x0a on 6II rows.
//!      Inert in-engine (field_mask dominates match_mask; the field writes all
//!      8 bits on encode) but false data claiming constness.
//! Fix: patch186.py (data: tok2 (24,8)->(32,8) on '' / BLOCK16 UTCOMMA rows;
//!      ab48 := 0, vm48 |= 0xff on the 12 tcgen05 groups with a (48,8) field)
//!      + printer.rs elision-aware idesc derivation.

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::table::IsaTable;

const SCHED: u128 = 0xFFFF_FFFFu128 << 96;

fn tab(p: &str) -> IsaTable { IsaTable::load(std::path::Path::new(p)).unwrap() }
fn enc(t: &IsaTable, text: &str) -> u128 {
    let insn = parse_sass(&format!("{text} ;"), 0).expect("parse");
    encode_instruction(&insn, t).expect("encode") & !SCHED
}
fn dec(idx: &DecodeIndex, t: &IsaTable, w: u128) -> String {
    cubit::printer::to_sass(&idx.decode(w, 0, t).expect("decode"))
        .trim_end_matches(" ;").to_string()
}

// ptxas-13.3.73 kind::mxf4 2X witness (work/bug186/omma5.cubin @0x80) and its
// byte40/byte48 sweeps, vendor texts per arb186b.json. hi = ptxas ctrl.
const W_OMMA_BASE: u128 = 0x0033d8000f800008_c006ff04040075ea;
fn omma_w(v40: u128, v48: u128) -> u128 {
    (W_OMMA_BASE & !(0xffu128 << 40) & !(0xffu128 << 48)) | (v40 << 40) | (v48 << 48)
}

// gold 77_blackwell_mla_2sm_fp8.1 @0x1920 (2CTA QMMA ''-anchor), arb186a.json.
const W_2CTA_BASE: u128 = 0x0003e4000fa0030a_00ff1006180075ea;
fn q2cta_w(v48: u128) -> u128 { (W_2CTA_BASE & !(0xffu128 << 48)) | (v48 << 48) }

// gold 77_blackwell_fmha_fp8.1 @0x3090 (''-lane), arb186c.json.
const W_PLAIN_BASE: u128 = 0x0003e2000f800308_00ff0a3a3c0075ea;
fn qplain_w(v40: u128) -> u128 { (W_PLAIN_BASE & !(0xffu128 << 40)) | (v40 << 40) }

#[test]
fn t186_1_utcomma_witness_no_hijack() {
    let t = tab("tables/sm103a.json");
    let idx = DecodeIndex::build(&t);
    // D1: pre-fix this decoded as UTCHMMA ''_UR_UP (prio-3 family hijack).
    let got = dec(&idx, &t, W_OMMA_BASE);
    assert_eq!(got, "UTCOMMA gdesc[UR4], gdesc[UR4], tmem[UR8], tmem[URZ], idesc[URZ], tmem[UR6], !UPT");
}

#[test]
fn t186_2_idesc_derivation_elision_law() {
    let t = tab("tables/sm103a.json");
    let idx = DecodeIndex::build(&t);
    // arb186b: idesc = tok4+1 literal (UR64 printed), 0xff => URZ propagates.
    for (v40, t4, id) in [
        (0x00u128, "tmem[UR0]", "idesc[UR1]"),
        (0x01, "tmem[UR1]", "idesc[UR2]"),
        (0x2a, "tmem[UR42]", "idesc[UR43]"),
        (0x3f, "tmem[UR63]", "idesc[UR64]"),
        (0xff, "tmem[URZ]", "idesc[URZ]"),
    ] {
        let got = dec(&idx, &t, omma_w(v40, 0x06));
        assert!(got.starts_with("UTCOMMA "), "row {got}");
        assert!(got.contains(&format!(", {t4}, {id}, tmem[UR6],")),
                "tok4={v40:#04x}: {got}");
    }
    // arb186c: same elision law on the ''-lane (no 6II trailing token).
    let got = dec(&idx, &t, qplain_w(0xff));
    assert_eq!(got, "UTCQMMA gdesc[UR60], gdesc[UR58], tmem[UR8], tmem[URZ], idesc[URZ], !UPT");
}

#[test]
fn t186_3_trailing_ur_window_2cta() {
    let t = tab("tables/sm103a.json");
    let idx = DecodeIndex::build(&t);
    // arb186a 8/8: any UR0..63 prints literally; 0xff elides (plain 2CTA row).
    for v in [0x00u128, 0x01, 0x08, 0x2a, 0x3f] {
        let got = dec(&idx, &t, q2cta_w(v));
        assert!(got.ends_with(&format!(", UR{v}, !UPT")), "{v:#04x}: {got}");
        assert!(got.starts_with("UTCQMMA.2CTA "), "{v:#04x}: {got}");
    }
    let got = dec(&idx, &t, q2cta_w(0xff));
    assert_eq!(got, "UTCQMMA.2CTA gdesc[UR24], gdesc[UR6], tmem[UR10], tmem[UR16], idesc[UR17], !UPT");
}

#[test]
fn t186_4_encode_no_clobber_no_bake() {
    let t = tab("tables/sm103a.json");
    // D3: divergent gdescs must land in their own windows (pre-fix tok2 wrote
    // tok1's slot and byte32 stayed baked 0xff).
    let w = enc(&t, "UTCOMMA gdesc[UR4], gdesc[UR7], tmem[UR8], tmem[URZ], idesc[URZ], tmem[UR6], !UPT");
    assert_eq!((w >> 24) & 0xff, 4, "tok1 window: {w:#034x}");
    assert_eq!((w >> 32) & 0xff, 7, "tok2 window: {w:#034x}");
    assert_eq!((w >> 40) & 0xff, 0xff, "tok4 window: {w:#034x}");
    assert_eq!((w >> 48) & 0xff, 6, "tok6 window: {w:#034x}");
    // roundtrip back to the same text
    let idx = DecodeIndex::build(&t);
    let got = dec(&idx, &t, w);
    assert_eq!(got, "UTCOMMA gdesc[UR4], gdesc[UR7], tmem[UR8], tmem[URZ], idesc[URZ], tmem[UR6], !UPT");
}

#[test]
fn t186_5_encode_trailing_ur_roundtrip() {
    let t = tab("tables/sm103a.json");
    let idx = DecodeIndex::build(&t);
    let w = enc(&t, "UTCQMMA.2CTA gdesc[UR24], gdesc[UR6], tmem[UR10], tmem[UR16], idesc[UR17], UR42, !UPT");
    assert_eq!((w >> 48) & 0xff, 42, "trailing UR window: {w:#034x}");
    let got = dec(&idx, &t, w);
    assert!(got.ends_with(", UR42, !UPT"), "{got}");
}

#[test]
fn t186_6_table_lane_invariants() {
    for p in ["tables/sm103a.json", "tables/sm100a.json"] {
        let t = tab(p);
        for (key, mg_name) in [
            ("UTCQMMA_II_II_II_II_II_UR_UP", ""), ("UTCQMMA_II_II_II_II_II_UR_UP", "2CTA"),
            ("UTCIMMA_II_II_II_II_II_UR_UP", ""), ("UTCIMMA_II_II_II_II_II_UR_UP", "2CTA"),
            ("UTCHMMA_II_II_II_II_II_UR_UP", ""), ("UTCHMMA_II_II_II_II_II_UR_UP", "2CTA"),
            ("UTCHMMA_II_II_II_II_II_UR_UP_II", ""),
            ("UTCOMMA_II_II_II_II_II_II_UP", ""), ("UTCOMMA_II_II_II_II_II_II_UP", "4X"),
            ("UTCOMMA_II_II_II_II_II_II_UP", "BLOCK16"),
            ("UTCQMMA_II_II_II_II_II_II_UP", ""), ("UTCQMMA_II_II_II_II_II_II_UP", "2CTA"),
        ] {
            let raw = cubit_table_raw(p, key, mg_name);
            let ab = raw.0; let vm = raw.1; let f48 = raw.2;
            assert!(f48, "{p} {key}[{mg_name}]: (48,8) field missing");
            assert_eq!((ab >> 48) & 0xff, 0, "{p} {key}[{mg_name}]: ab48 not zeroed");
            assert_eq!((vm >> 48) & 0xff, 0xff, "{p} {key}[{mg_name}]: vm48 not full");
        }
        // D3 structural: UTCOMMA ''/BLOCK16 tok2 owns [32:40).
        for mg_name in ["", "BLOCK16"] {
            let v: serde_json::Value =
                serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap();
            let fs = v["instructions"]["UTCOMMA_II_II_II_II_II_II_UP"]["mod_groups"][mg_name]
                ["fields"].as_array().unwrap();
            let tok2: Vec<_> = fs.iter()
                .filter(|f| f["token_idx"].as_u64() == Some(2)).collect();
            assert_eq!(tok2.len(), 1, "{p}[{mg_name}]: tok2 field roster drift");
            assert_eq!(tok2[0]["shift"].as_u64(), Some(32), "{p}[{mg_name}]: tok2 not @32");
            let tok1: Vec<_> = fs.iter()
                .filter(|f| f["token_idx"].as_u64() == Some(1)).collect();
            assert_eq!(tok1.len(), 1, "{p}[{mg_name}]: tok1 field roster drift");
            assert_eq!(tok1[0]["shift"].as_u64(), Some(24), "{p}[{mg_name}]: tok1 not @24");
        }
    }
}

// raw table access for invariant assertions (the public row API normalizes).
fn cubit_table_raw(path: &str, key: &str, mg: &str) -> (u128, u128, bool) {
    let v: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let g = &v["instructions"][key]["mod_groups"][mg];
    let ab = u128::from_str_radix(g["and_base"].as_str().unwrap().trim_start_matches("0x"), 16).unwrap();
    let vm = u128::from_str_radix(g["variable_mask"].as_str().unwrap().trim_start_matches("0x"), 16).unwrap();
    let f48 = g["fields"].as_array().unwrap().iter()
        .any(|f| f["shift"].as_u64() == Some(48) && f["bits"].as_u64() == Some(8));
    (ab, vm, f48)
}

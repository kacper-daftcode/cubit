//! BUG-164 (front-main iter77; port spark ERR-249 / nota floty
//! 154_rz_elision_ari_fleet_latent): vendor nvdisasm elides the base register
//! of a plain-ARI/AI address when base==RZ and imm!=0: prints ONLY the raw
//! window (unsigned hex), dropping base, .Xn scale and the "+-" spelling.
//! Exceptions: imm==0 -> "[RZ]"; UR component or base!=RZ -> full form;
//! LDSM/STSM print the elided immediate SIGNED ("[-0x10]").
//! Pre-fix cubit printed "[RZ+0x10]"/"[RZ+-0x10]" everywhere (render-parity
//! gap; 692/1404 sweep probes divergent, zero corpus incidence hexdb 32.2M,
//! arbitration 56/56 on nvdisasm 13.3.73). Post-fix: printer-only elision in
//! format_addr/format_lds_scaled_addr; tables untouched; legacy "[RZ+0x10]"
//! spelling still parses and encodes identically.
//!
//! Pins: t164_1 decode==nvdisasm (47 arbitrowane formy minus klasy parked-geo
//! z BUG-155/161 ff), t164_2 decode==law dla LDGSTS/split/baked-imm (pozostale
//! nogi niosa parked-147/158/160 quirks i sa osobno kontrolowane), t164_3
//! encode identity + kompat wsteczny "[RZ+0x10]", t164_4 kontrol-brak-elizji
//! (imm0/baza!=RZ), t164_5 fixed-point decode(encode(decode(w))).

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::table::IsaTable;

const SCHED: u128 = 0xFFFF_FFFFu128 << 96;

fn t103a() -> IsaTable { IsaTable::load(std::path::Path::new("tables/sm103a.json")).unwrap() }
fn t120() -> IsaTable { IsaTable::load(std::path::Path::new("tables/sm120.json")).unwrap() }

fn tbl(name: &str) -> IsaTable { if name == "sm120" { t120() } else { t103a() } }

fn dec(t: &IsaTable, idx: &DecodeIndex, w: u128) -> String {
    let s = idx.decode(w, 0, t).map(|d| cubit::printer::to_sass(&d)).expect("decode");
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn enc(t: &IsaTable, text: &str) -> u128 {
    let insn = parse_sass(text, 0).expect("parse");
    encode_instruction(&insn, t).expect("encode")
}

fn word(lo: u64, hi: u64) -> u128 { (lo as u128) | ((hi as u128) << 64) }

// t164_1: decode(slowo) == render nvdisasm 13.3.73 (arbitraz work/i77/arb).
const ARB: &[(&str, u64, u64, &str)] = &[
    ("sm103a", 0x00001000ff000984, 0x0000000000000800, "@P0 LDS R0, [0x10]"), // LDS_R_ARI  pos
    ("sm103a", 0xfffff000ff000984, 0x0000000000000800, "@P0 LDS R0, [0xfffff0]"), // LDS_R_ARI  neg
    ("sm103a", 0x80000000ff000984, 0x0000000000000800, "@P0 LDS R0, [0x800000]"), // LDS_R_ARI  min
    ("sm103a", 0x00000000ff000984, 0x0000000000000800, "@P0 LDS R0, [RZ]"), // LDS_R_ARI  imm0
    ("sm103a", 0x00001000ff000388, 0x0001c00000000800, "@P0 STS [0x10], R0"), // STS_ARI_R  pos
    ("sm103a", 0xfffff000ff000388, 0x0001c00000000800, "@P0 STS [0xfffff0], R0"), // STS_ARI_R  neg
    ("sm103a", 0x80000000ff000388, 0x0001c00000000800, "@P0 STS [0x800000], R0"), // STS_ARI_R  min
    ("sm103a", 0x00000000ff000388, 0x0001c00000000800, "@P0 STS [RZ], R0"), // STS_ARI_R  imm0
    ("sm103a", 0x00001000ff000983, 0x0000000000100800, "@P0 LDL R0, [0x10]"), // LDL_R_ARI  pos
    ("sm103a", 0xfffff000ff000983, 0x0000000000100800, "@P0 LDL R0, [0xfffff0]"), // LDL_R_ARI  neg
    ("sm103a", 0x80000000ff000983, 0x0000000000100800, "@P0 LDL R0, [0x800000]"), // LDL_R_ARI  min
    ("sm103a", 0x00000000ff000983, 0x0000000000100800, "@P0 LDL R0, [RZ]"), // LDL_R_ARI  imm0
    ("sm103a", 0x00001000ff000387, 0x0001c00000100800, "@P0 STL [0x10], R0"), // STL_ARI_R  pos
    ("sm103a", 0xfffff000ff000387, 0x0001c00000100800, "@P0 STL [0xfffff0], R0"), // STL_ARI_R  neg
    ("sm103a", 0x80000000ff000387, 0x0001c00000100800, "@P0 STL [0x800000], R0"), // STL_ARI_R  min
    ("sm103a", 0x00000000ff000387, 0x0001c00000100800, "@P0 STL [RZ], R0"), // STL_ARI_R  imm0
    ("sm103a", 0x00001000ff00758d, 0x000e240001800001, "ATOMS.CAST.SPIN P0, [0x10], R0, R1"), // ATOMS_P_ARI_R_R CAST,SPIN pos
    ("sm103a", 0xfffff000ff00758d, 0x000e240001800001, "ATOMS.CAST.SPIN P0, [0xfffff0], R0, R1"), // ATOMS_P_ARI_R_R CAST,SPIN neg
    ("sm103a", 0x80000000ff00758d, 0x000e240001800001, "ATOMS.CAST.SPIN P0, [0x800000], R0, R1"), // ATOMS_P_ARI_R_R CAST,SPIN min
    ("sm103a", 0x00000000ff00758d, 0x000e240001800001, "ATOMS.CAST.SPIN P0, [RZ], R0, R1"), // ATOMS_P_ARI_R_R CAST,SPIN imm0
    ("sm103a", 0x00001000ffff73aa, 0x000e240000000500, "QSPC.E.S P0, RZ, [0x10]"), // QSPC_P_R_ARI E,S pos
    ("sm103a", 0xfffff000ffff73aa, 0x000e240000000500, "QSPC.E.S P0, RZ, [0xfffff0]"), // QSPC_P_R_ARI E,S neg
    ("sm103a", 0x80000000ffff73aa, 0x000e240000000500, "QSPC.E.S P0, RZ, [0x800000]"), // QSPC_P_R_ARI E,S min
    ("sm103a", 0x00000000ffff73aa, 0x000e240000000500, "QSPC.E.S P0, RZ, [RZ]"), // QSPC_P_R_ARI E,S imm0
    ("sm103a", 0x00001000ff00038d, 0x0000000000000000, "@P0 ATOMS.CAS R0, [0x10], R0, R0"), // ATOMS_R_ARI_R_R CAS pos
    ("sm103a", 0xfffff000ff00038d, 0x0000000000000000, "@P0 ATOMS.CAS R0, [0xfffff0], R0, R0"), // ATOMS_R_ARI_R_R CAS neg
    ("sm103a", 0x80000000ff00038d, 0x0000000000000000, "@P0 ATOMS.CAS R0, [0x800000], R0, R0"), // ATOMS_R_ARI_R_R CAS min
    ("sm103a", 0x00000000ff00038d, 0x0000000000000000, "@P0 ATOMS.CAS R0, [RZ], R0, R0"), // ATOMS_R_ARI_R_R CAS imm0
    ("sm120", 0x00001000ff000983, 0x0000000000100800, "@P0 LDL R0, [0x10]"), // LDL_R_ARI  pos
    ("sm120", 0xfffff000ff000983, 0x0000000000100800, "@P0 LDL R0, [0xfffff0]"), // LDL_R_ARI  neg
    ("sm120", 0x80000000ff000983, 0x0000000000100800, "@P0 LDL R0, [0x800000]"), // LDL_R_ARI  min
    ("sm120", 0x00000000ff000983, 0x0000000000100800, "@P0 LDL R0, [RZ]"), // LDL_R_ARI  imm0
    ("sm120", 0x00001000ff000984, 0x0000000000000800, "@P0 LDS R0, [0x10]"), // LDS_R_ARI  pos
    ("sm120", 0xfffff000ff000984, 0x0000000000000800, "@P0 LDS R0, [0xfffff0]"), // LDS_R_ARI  neg
    ("sm120", 0x80000000ff000984, 0x0000000000000800, "@P0 LDS R0, [0x800000]"), // LDS_R_ARI  min
    ("sm120", 0x00000000ff000984, 0x0000000000000800, "@P0 LDS R0, [RZ]"), // LDS_R_ARI  imm0
    ("sm120", 0x00001000ff000387, 0x0001c00000100800, "@P0 STL [0x10], R0"), // STL_ARI_R  pos
    ("sm120", 0xfffff000ff000387, 0x0001c00000100800, "@P0 STL [0xfffff0], R0"), // STL_ARI_R  neg
    ("sm120", 0x80000000ff000387, 0x0001c00000100800, "@P0 STL [0x800000], R0"), // STL_ARI_R  min
    ("sm120", 0x00000000ff000387, 0x0001c00000100800, "@P0 STL [RZ], R0"), // STL_ARI_R  imm0
    ("sm120", 0x00001000ff000388, 0x0001c00000000800, "@P0 STS [0x10], R0"), // STS_ARI_R  pos
    ("sm120", 0xfffff000ff000388, 0x0001c00000000800, "@P0 STS [0xfffff0], R0"), // STS_ARI_R  neg
    ("sm120", 0x80000000ff000388, 0x0001c00000000800, "@P0 STS [0x800000], R0"), // STS_ARI_R  min
    ("sm120", 0x00000000ff000388, 0x0001c00000000800, "@P0 STS [RZ], R0"), // STS_ARI_R  imm0
];

// encode-legalny podzbior ARB (bez ATOM/REDG — BUG-080 guard).
const ENC: &[(&str, u64, u64, &str)] = &[
    ("sm103a", 0x00001000ff000984, 0x0000000000000800, "@P0 LDS R0, [0x10]"), // LDS_R_ARI  pos
    ("sm103a", 0xfffff000ff000984, 0x0000000000000800, "@P0 LDS R0, [0xfffff0]"), // LDS_R_ARI  neg
    ("sm103a", 0x80000000ff000984, 0x0000000000000800, "@P0 LDS R0, [0x800000]"), // LDS_R_ARI  min
    ("sm103a", 0x00000000ff000984, 0x0000000000000800, "@P0 LDS R0, [RZ]"), // LDS_R_ARI  imm0
    ("sm103a", 0x00001000ff000388, 0x0001c00000000800, "@P0 STS [0x10], R0"), // STS_ARI_R  pos
    ("sm103a", 0xfffff000ff000388, 0x0001c00000000800, "@P0 STS [0xfffff0], R0"), // STS_ARI_R  neg
    ("sm103a", 0x80000000ff000388, 0x0001c00000000800, "@P0 STS [0x800000], R0"), // STS_ARI_R  min
    ("sm103a", 0x00000000ff000388, 0x0001c00000000800, "@P0 STS [RZ], R0"), // STS_ARI_R  imm0
    ("sm103a", 0x00001000ff000983, 0x0000000000100800, "@P0 LDL R0, [0x10]"), // LDL_R_ARI  pos
    ("sm103a", 0xfffff000ff000983, 0x0000000000100800, "@P0 LDL R0, [0xfffff0]"), // LDL_R_ARI  neg
    ("sm103a", 0x80000000ff000983, 0x0000000000100800, "@P0 LDL R0, [0x800000]"), // LDL_R_ARI  min
    ("sm103a", 0x00000000ff000983, 0x0000000000100800, "@P0 LDL R0, [RZ]"), // LDL_R_ARI  imm0
    ("sm103a", 0x00001000ff000387, 0x0001c00000100800, "@P0 STL [0x10], R0"), // STL_ARI_R  pos
    ("sm103a", 0xfffff000ff000387, 0x0001c00000100800, "@P0 STL [0xfffff0], R0"), // STL_ARI_R  neg
    ("sm103a", 0x80000000ff000387, 0x0001c00000100800, "@P0 STL [0x800000], R0"), // STL_ARI_R  min
    ("sm103a", 0x00000000ff000387, 0x0001c00000100800, "@P0 STL [RZ], R0"), // STL_ARI_R  imm0
    ("sm103a", 0x00001000ffff73aa, 0x000e240000000500, "QSPC.E.S P0, RZ, [0x10]"), // QSPC_P_R_ARI E,S pos
    ("sm103a", 0xfffff000ffff73aa, 0x000e240000000500, "QSPC.E.S P0, RZ, [0xfffff0]"), // QSPC_P_R_ARI E,S neg
    ("sm103a", 0x80000000ffff73aa, 0x000e240000000500, "QSPC.E.S P0, RZ, [0x800000]"), // QSPC_P_R_ARI E,S min
    ("sm103a", 0x00000000ffff73aa, 0x000e240000000500, "QSPC.E.S P0, RZ, [RZ]"), // QSPC_P_R_ARI E,S imm0
    ("sm120", 0x00001000ff000983, 0x0000000000100800, "@P0 LDL R0, [0x10]"), // LDL_R_ARI  pos
    ("sm120", 0xfffff000ff000983, 0x0000000000100800, "@P0 LDL R0, [0xfffff0]"), // LDL_R_ARI  neg
    ("sm120", 0x80000000ff000983, 0x0000000000100800, "@P0 LDL R0, [0x800000]"), // LDL_R_ARI  min
    ("sm120", 0x00000000ff000983, 0x0000000000100800, "@P0 LDL R0, [RZ]"), // LDL_R_ARI  imm0
    ("sm120", 0x00001000ff000984, 0x0000000000000800, "@P0 LDS R0, [0x10]"), // LDS_R_ARI  pos
    ("sm120", 0xfffff000ff000984, 0x0000000000000800, "@P0 LDS R0, [0xfffff0]"), // LDS_R_ARI  neg
    ("sm120", 0x80000000ff000984, 0x0000000000000800, "@P0 LDS R0, [0x800000]"), // LDS_R_ARI  min
    ("sm120", 0x00000000ff000984, 0x0000000000000800, "@P0 LDS R0, [RZ]"), // LDS_R_ARI  imm0
    ("sm120", 0x00001000ff000387, 0x0001c00000100800, "@P0 STL [0x10], R0"), // STL_ARI_R  pos
    ("sm120", 0xfffff000ff000387, 0x0001c00000100800, "@P0 STL [0xfffff0], R0"), // STL_ARI_R  neg
    ("sm120", 0x80000000ff000387, 0x0001c00000100800, "@P0 STL [0x800000], R0"), // STL_ARI_R  min
    ("sm120", 0x00000000ff000387, 0x0001c00000100800, "@P0 STL [RZ], R0"), // STL_ARI_R  imm0
    ("sm120", 0x00001000ff000388, 0x0001c00000000800, "@P0 STS [0x10], R0"), // STS_ARI_R  pos
    ("sm120", 0xfffff000ff000388, 0x0001c00000000800, "@P0 STS [0xfffff0], R0"), // STS_ARI_R  neg
    ("sm120", 0x80000000ff000388, 0x0001c00000000800, "@P0 STS [0x800000], R0"), // STS_ARI_R  min
    ("sm120", 0x00000000ff000388, 0x0001c00000000800, "@P0 STS [RZ], R0"), // STS_ARI_R  imm0
];

#[test]
fn t164_1_decode_eq_nvdisasm() {
    let i103 = DecodeIndex::build(&t103a());
    let i120 = DecodeIndex::build(&t120());
    for (tn, lo, hi, want) in ARB {
        let t = tbl(tn);
        let idx = if tn == &"sm120" { &i120 } else { &i103 };
        let got = dec(&t, idx, word(*lo, *hi));
        assert_eq!(got, *want, "decode==nvdisasm {tn} {want}");
    }
}

// t164_2: law-bracket dla LDGSTS/split/baked (pozostale nogi = parked quirks).
const LAWB: &[(&str, u64, u64, &str)] = &[
    ("sm103a", 0x00001000ff000388, 0x0001c00000000800, "0x10"), // STS_ARI_R  tok1 pos
    ("sm103a", 0xfffff000ff000388, 0x0001c00000000800, "0xfffff0"), // STS_ARI_R  tok1 neg
    ("sm103a", 0x80000000ff000388, 0x0001c00000000800, "0x800000"), // STS_ARI_R  tok1 min
    ("sm103a", 0x00001000ff000188, 0x0001c00000000a00, "0x10"), // STS_ARI_R 64 tok1 pos
    ("sm103a", 0xfffff000ff000188, 0x0001c00000000a00, "0xfffff0"), // STS_ARI_R 64 tok1 neg
    ("sm103a", 0x80000000ff000188, 0x0001c00000000a00, "0x800000"), // STS_ARI_R 64 tok1 min
    ("sm103a", 0x00001000ff000388, 0x0000000000000c00, "0x10"), // STS_ARI_R 128 tok1 pos
    ("sm103a", 0xfffff000ff000388, 0x0000000000000c00, "0xfffff0"), // STS_ARI_R 128 tok1 neg
    ("sm103a", 0x80000000ff000388, 0x0000000000000c00, "0x800000"), // STS_ARI_R 128 tok1 min
    ("sm103a", 0x00001000ff000388, 0x0001c00000000400, "0x10"), // STS_ARI_R U16 tok1 pos
    ("sm103a", 0xfffff000ff000388, 0x0001c00000000400, "0xfffff0"), // STS_ARI_R U16 tok1 neg
    ("sm103a", 0x80000000ff000388, 0x0001c00000000400, "0x800000"), // STS_ARI_R U16 tok1 min
    ("sm103a", 0x00001000ff000388, 0x0001e00000000000, "0x10"), // STS_ARI_R U8 tok1 pos
    ("sm103a", 0xfffff000ff000388, 0x0001e00000000000, "0xfffff0"), // STS_ARI_R U8 tok1 neg
    ("sm103a", 0x80000000ff000388, 0x0001e00000000000, "0x800000"), // STS_ARI_R U8 tok1 min
    ("sm103a", 0x0001000000ff7fae, 0x0001e000081a1400, "0x10"), // LDGSTS_ARI_dARI_P 64,E tok1 pos
    ("sm103a", 0xffff000000ff7fae, 0x0001e000081a1400, "0xffff0"), // LDGSTS_ARI_dARI_P 64,E tok1 neg
    ("sm103a", 0x8000000000ff7fae, 0x0001e000081a1400, "0x80000"), // LDGSTS_ARI_dARI_P 64,E tok1 min
    ("sm103a", 0x0001000000ff7fae, 0x0001e000081a1000, "0x10"), // LDGSTS_ARI_dARI_P E tok1 pos
    ("sm103a", 0xffff000000ff7fae, 0x0001e000081a1000, "0xffff0"), // LDGSTS_ARI_dARI_P E tok1 neg
    ("sm103a", 0x8000000000ff7fae, 0x0001e000081a1000, "0x80000"), // LDGSTS_ARI_dARI_P E tok1 min
    ("sm103a", 0x0001000000ff7fae, 0x0001e00008181a00, "0x10"), // LDGSTS_ARI_dARI_P 128,BYPASS,E,LTC128B tok1 pos
    ("sm103a", 0xffff000000ff7fae, 0x0001e00008181a00, "0xffff0"), // LDGSTS_ARI_dARI_P 128,BYPASS,E,LTC128B tok1 neg
    ("sm103a", 0x8000000000ff7fae, 0x0001e00008181a00, "0x80000"), // LDGSTS_ARI_dARI_P 128,BYPASS,E,LTC128B tok1 min
    ("sm103a", 0x0001000000ff7fae, 0x0001e000081a1600, "0x10"), // LDGSTS_ARI_dARI_P 64,E,LTC128B tok1 pos
    ("sm103a", 0xffff000000ff7fae, 0x0001e000081a1600, "0xffff0"), // LDGSTS_ARI_dARI_P 64,E,LTC128B tok1 neg
    ("sm103a", 0x8000000000ff7fae, 0x0001e000081a1600, "0x80000"), // LDGSTS_ARI_dARI_P 64,E,LTC128B tok1 min
    ("sm103a", 0x0001000000ff7fae, 0x0001e000081a1200, "0x10"), // LDGSTS_ARI_dARI_P E,LTC128B tok1 pos
    ("sm103a", 0xffff000000ff7fae, 0x0001e000081a1200, "0xffff0"), // LDGSTS_ARI_dARI_P E,LTC128B tok1 neg
    ("sm103a", 0x8000000000ff7fae, 0x0001e000081a1200, "0x80000"), // LDGSTS_ARI_dARI_P E,LTC128B tok1 min
    ("sm103a", 0x0001000000ff7fae, 0x00000000081c1a00, "0x10"), // LDGSTS_ARI_dARI_P 128,BYPASS,E,LTC128B,ZFILL tok1 pos
    ("sm103a", 0xffff000000ff7fae, 0x00000000081c1a00, "0xffff0"), // LDGSTS_ARI_dARI_P 128,BYPASS,E,LTC128B,ZFILL tok1 neg
    ("sm103a", 0x8000000000ff7fae, 0x00000000081c1a00, "0x80000"), // LDGSTS_ARI_dARI_P 128,BYPASS,E,LTC128B,ZFILL tok1 min
    ("sm103a", 0x0001000000ff7fae, 0x00000000081c1800, "0x10"), // LDGSTS_ARI_dARI_P 128,BYPASS,E,ZFILL tok1 pos
    ("sm103a", 0xffff000000ff7fae, 0x00000000081c1800, "0xffff0"), // LDGSTS_ARI_dARI_P 128,BYPASS,E,ZFILL tok1 neg
    ("sm103a", 0x8000000000ff7fae, 0x00000000081c1800, "0x80000"), // LDGSTS_ARI_dARI_P 128,BYPASS,E,ZFILL tok1 min
    ("sm103a", 0x0001000000ff0fae, 0x0001e0000b981a00, "0x10"), // LDGSTS_ARI_dARI 128,BYPASS,E,LTC128B tok1 pos
    ("sm103a", 0xffff000000ff0fae, 0x0001e0000b981a00, "0xffff0"), // LDGSTS_ARI_dARI 128,BYPASS,E,LTC128B tok1 neg
    ("sm103a", 0x8000000000ff0fae, 0x0001e0000b981a00, "0x80000"), // LDGSTS_ARI_dARI 128,BYPASS,E,LTC128B tok1 min
    ("sm103a", 0x0001000000ff0fae, 0x0001e0000b9a1600, "0x10"), // LDGSTS_ARI_dARI 64,E,LTC128B tok1 pos
    ("sm103a", 0xffff000000ff0fae, 0x0001e0000b9a1600, "0xffff0"), // LDGSTS_ARI_dARI 64,E,LTC128B tok1 neg
    ("sm103a", 0x8000000000ff0fae, 0x0001e0000b9a1600, "0x80000"), // LDGSTS_ARI_dARI 64,E,LTC128B tok1 min
    ("sm103a", 0x0001000000ff0fae, 0x0001e0000b981800, "0x10"), // LDGSTS_ARI_dARI 128,BYPASS,E tok1 pos
    ("sm103a", 0xffff000000ff0fae, 0x0001e0000b981800, "0xffff0"), // LDGSTS_ARI_dARI 128,BYPASS,E tok1 neg
    ("sm103a", 0x8000000000ff0fae, 0x0001e0000b981800, "0x80000"), // LDGSTS_ARI_dARI 128,BYPASS,E tok1 min
    ("sm103a", 0x0001000000ff0fae, 0x0001e0000b9a1400, "0x10"), // LDGSTS_ARI_dARI 64,E tok1 pos
    ("sm103a", 0xffff000000ff0fae, 0x0001e0000b9a1400, "0xffff0"), // LDGSTS_ARI_dARI 64,E tok1 neg
    ("sm103a", 0x8000000000ff0fae, 0x0001e0000b9a1400, "0x80000"), // LDGSTS_ARI_dARI 64,E tok1 min
    ("sm103a", 0x0001000000ff0fae, 0x0001e0000b9a1200, "0x10"), // LDGSTS_ARI_dARI E,LTC128B tok1 pos
    ("sm103a", 0xffff000000ff0fae, 0x0001e0000b9a1200, "0xffff0"), // LDGSTS_ARI_dARI E,LTC128B tok1 neg
    ("sm103a", 0x8000000000ff0fae, 0x0001e0000b9a1200, "0x80000"), // LDGSTS_ARI_dARI E,LTC128B tok1 min
    ("sm103a", 0x0001000000ff0fae, 0x0001e0000b9a1000, "0x10"), // LDGSTS_ARI_dARI E tok1 pos
    ("sm103a", 0xffff000000ff0fae, 0x0001e0000b9a1000, "0xffff0"), // LDGSTS_ARI_dARI E tok1 neg
    ("sm103a", 0x8000000000ff0fae, 0x0001e0000b9a1000, "0x80000"), // LDGSTS_ARI_dARI E tok1 min
    ("sm103a", 0x0001000000ff0fae, 0x0001e0000b9a1700, "0x10"), // LDGSTS_ARI_dARI 64,E,LTC256B tok1 pos
    ("sm103a", 0xffff000000ff0fae, 0x0001e0000b9a1700, "0xffff0"), // LDGSTS_ARI_dARI 64,E,LTC256B tok1 neg
    ("sm103a", 0x8000000000ff0fae, 0x0001e0000b9a1700, "0x80000"), // LDGSTS_ARI_dARI 64,E,LTC256B tok1 min
    ("sm103a", 0x0001000000ff7fae, 0x0001e000081a06ff, "0x10"), // LDGSTS_ARI_ARI_P 64,E,LTC128B tok1 pos
    ("sm103a", 0xffff000000ff7fae, 0x0001e000081a06ff, "0xffff0"), // LDGSTS_ARI_ARI_P 64,E,LTC128B tok1 neg
    ("sm103a", 0x8000000000ff7fae, 0x0001e000081a06ff, "0x80000"), // LDGSTS_ARI_ARI_P 64,E,LTC128B tok1 min
    ("sm103a", 0x00000010ff007fae, 0x0001e000081a06ff, "0x10"), // LDGSTS_ARI_ARI_P 64,E,LTC128B tok2 pos
    ("sm103a", 0x0007fff0ff007fae, 0x0001e000081a06ff, "0x7fff0"), // LDGSTS_ARI_ARI_P 64,E,LTC128B tok2 neg
    ("sm103a", 0x00040000ff007fae, 0x0001e000081a06ff, "0x40000"), // LDGSTS_ARI_ARI_P 64,E,LTC128B tok2 min
    ("sm103a", 0x00000010ff807fae, 0x0001e00008180aff, "0x10"), // LDGSTS_ARI_ARI_P 128,BYPASS,E,LTC128B tok2 pos
    ("sm103a", 0x0007fff0ff807fae, 0x0001e00008180aff, "0x7fff0"), // LDGSTS_ARI_ARI_P 128,BYPASS,E,LTC128B tok2 neg
    ("sm103a", 0x00040000ff807fae, 0x0001e00008180aff, "0x40000"), // LDGSTS_ARI_ARI_P 128,BYPASS,E,LTC128B tok2 min
    ("sm103a", 0x0001000000ff7fae, 0x0001e000081a0aff, "0x10"), // LDGSTS_ARI_ARI_P 128,E,LTC128B tok1 pos
    ("sm103a", 0xffff000000ff7fae, 0x0001e000081a0aff, "0xffff0"), // LDGSTS_ARI_ARI_P 128,E,LTC128B tok1 neg
    ("sm103a", 0x8000000000ff7fae, 0x0001e000081a0aff, "0x80000"), // LDGSTS_ARI_ARI_P 128,E,LTC128B tok1 min
    ("sm103a", 0x00000010ffbc7dae, 0x0001e000081a0218, "0x10"), // LDGSTS_ARURI_ARI_P E,LTC128B tok2 pos
    ("sm103a", 0x0003fff0ffbc7dae, 0x0001e000081a0218, "0x3fff0"), // LDGSTS_ARURI_ARI_P E,LTC128B tok2 neg
    ("sm103a", 0x00020000ffbc7dae, 0x0001e000081a0218, "0x20000"), // LDGSTS_ARURI_ARI_P E,LTC128B tok2 min
    ("sm103a", 0x00000010ff007dae, 0x0001e000081a0600, "0x10"), // LDGSTS_ARURI_ARI_P 64,E,LTC128B tok2 pos
    ("sm103a", 0x00000ff0ff007dae, 0x0001e000081a0600, "0xff0"), // LDGSTS_ARURI_ARI_P 64,E,LTC128B tok2 neg
    ("sm103a", 0x00000800ff007dae, 0x0001e000081a0600, "0x800"), // LDGSTS_ARURI_ARI_P 64,E,LTC128B tok2 min
    ("sm103a", 0x00000010ff807dae, 0x0001e00008180a08, "0x10"), // LDGSTS_ARURI_ARI_P 128,BYPASS,E,LTC128B tok2 pos
    ("sm103a", 0x0007fff0ff807dae, 0x0001e00008180a08, "0x3ffff0"), // LDGSTS_ARURI_ARI_P 128,BYPASS,E,LTC128B tok2 neg
    ("sm103a", 0x00040000ff807dae, 0x0001e00008180a08, "0x3c0000"), // LDGSTS_ARURI_ARI_P 128,BYPASS,E,LTC128B tok2 min
    ("sm103a", 0x00000010ff800dae, 0x0001c0000b980a00, "0x10"), // LDGSTS_ARURI_ARI 128,BYPASS,E,LTC128B tok2 pos
    ("sm103a", 0x0007fff0ff800dae, 0x0001c0000b980a00, "0x7fff0"), // LDGSTS_ARURI_ARI 128,BYPASS,E,LTC128B tok2 neg
    ("sm103a", 0x00040000ff800dae, 0x0001c0000b980a00, "0x40000"), // LDGSTS_ARURI_ARI 128,BYPASS,E,LTC128B tok2 min
    ("sm103a", 0x0089000000ff7fae, 0x0003e000081a0a00, "0x890"), // LDGSTS_ARI_ARURI_P 128,E,LTC128B tok1 pos
    ("sm103a", 0xffff000000ff7fae, 0x0003e000081a0a00, "0xffff0"), // LDGSTS_ARI_ARURI_P 128,E,LTC128B tok1 neg
    ("sm103a", 0x8088000000ff7fae, 0x0003e000081a0a00, "0x80880"), // LDGSTS_ARI_ARURI_P 128,E,LTC128B tok1 min
    ("sm103a", 0x00c1000000ff7fae, 0x0001e000099a0600, "0xc10"), // LDGSTS_ARI_ARURI_P 64,E,LTC128B tok1 pos
    ("sm103a", 0xffff000000ff7fae, 0x0001e000099a0600, "0xffff0"), // LDGSTS_ARI_ARURI_P 64,E,LTC128B tok1 neg
    ("sm103a", 0x80c0000000ff7fae, 0x0001e000099a0600, "0x80c00"), // LDGSTS_ARI_ARURI_P 64,E,LTC128B tok1 min
    ("sm120", 0x0001000000ff7fae, 0x0001e000081a06ff, "0x10"), // LDGSTS_ARI_ARI_P 64,E,LTC128B tok1 pos
    ("sm120", 0xffff000000ff7fae, 0x0001e000081a06ff, "0xffff0"), // LDGSTS_ARI_ARI_P 64,E,LTC128B tok1 neg
    ("sm120", 0x8000000000ff7fae, 0x0001e000081a06ff, "0x80000"), // LDGSTS_ARI_ARI_P 64,E,LTC128B tok1 min
    ("sm120", 0x00000010ff007fae, 0x0001e000081a06ff, "0x10"), // LDGSTS_ARI_ARI_P 64,E,LTC128B tok2 pos
    ("sm120", 0x0007fff0ff007fae, 0x0001e000081a06ff, "0x7fff0"), // LDGSTS_ARI_ARI_P 64,E,LTC128B tok2 neg
    ("sm120", 0x00040000ff007fae, 0x0001e000081a06ff, "0x40000"), // LDGSTS_ARI_ARI_P 64,E,LTC128B tok2 min
    ("sm120", 0x00000010ff807fae, 0x0001e00008180aff, "0x10"), // LDGSTS_ARI_ARI_P 128,BYPASS,E,LTC128B tok2 pos
    ("sm120", 0x0007fff0ff807fae, 0x0001e00008180aff, "0x7fff0"), // LDGSTS_ARI_ARI_P 128,BYPASS,E,LTC128B tok2 neg
    ("sm120", 0x00040000ff807fae, 0x0001e00008180aff, "0x40000"), // LDGSTS_ARI_ARI_P 128,BYPASS,E,LTC128B tok2 min
    ("sm120", 0x0001000000ff7fae, 0x0001e000081a0aff, "0x10"), // LDGSTS_ARI_ARI_P 128,E,LTC128B tok1 pos
    ("sm120", 0xffff000000ff7fae, 0x0001e000081a0aff, "0xffff0"), // LDGSTS_ARI_ARI_P 128,E,LTC128B tok1 neg
    ("sm120", 0x8000000000ff7fae, 0x0001e000081a0aff, "0x80000"), // LDGSTS_ARI_ARI_P 128,E,LTC128B tok1 min
    ("sm120", 0x0089000000ff7fae, 0x0003e000081a0a00, "0x890"), // LDGSTS_ARI_ARURI_P 128,E,LTC128B tok1 pos
    ("sm120", 0xffff000000ff7fae, 0x0003e000081a0a00, "0xffff0"), // LDGSTS_ARI_ARURI_P 128,E,LTC128B tok1 neg
    ("sm120", 0x8088000000ff7fae, 0x0003e000081a0a00, "0x80880"), // LDGSTS_ARI_ARURI_P 128,E,LTC128B tok1 min
    ("sm120", 0x00c1000000ff7fae, 0x0001e000099a0600, "0xc10"), // LDGSTS_ARI_ARURI_P 64,E,LTC128B tok1 pos
    ("sm120", 0xffff000000ff7fae, 0x0001e000099a0600, "0xffff0"), // LDGSTS_ARI_ARURI_P 64,E,LTC128B tok1 neg
    ("sm120", 0x80c0000000ff7fae, 0x0001e000099a0600, "0x80c00"), // LDGSTS_ARI_ARURI_P 64,E,LTC128B tok1 min
    ("sm120", 0x0001000000ff0fae, 0x0001e0000b981a00, "0x10"), // LDGSTS_ARI_dARI 128,BYPASS,E,LTC128B tok1 pos
    ("sm120", 0xffff000000ff0fae, 0x0001e0000b981a00, "0xffff0"), // LDGSTS_ARI_dARI 128,BYPASS,E,LTC128B tok1 neg
    ("sm120", 0x8000000000ff0fae, 0x0001e0000b981a00, "0x80000"), // LDGSTS_ARI_dARI 128,BYPASS,E,LTC128B tok1 min
    ("sm120", 0x0001000000ff0fae, 0x0001e0000b9a1600, "0x10"), // LDGSTS_ARI_dARI 64,E,LTC128B tok1 pos
    ("sm120", 0xffff000000ff0fae, 0x0001e0000b9a1600, "0xffff0"), // LDGSTS_ARI_dARI 64,E,LTC128B tok1 neg
    ("sm120", 0x8000000000ff0fae, 0x0001e0000b9a1600, "0x80000"), // LDGSTS_ARI_dARI 64,E,LTC128B tok1 min
    ("sm120", 0x0001000000ff0fae, 0x0001e0000b981800, "0x10"), // LDGSTS_ARI_dARI 128,BYPASS,E tok1 pos
    ("sm120", 0xffff000000ff0fae, 0x0001e0000b981800, "0xffff0"), // LDGSTS_ARI_dARI 128,BYPASS,E tok1 neg
    ("sm120", 0x8000000000ff0fae, 0x0001e0000b981800, "0x80000"), // LDGSTS_ARI_dARI 128,BYPASS,E tok1 min
    ("sm120", 0x0001000000ff0fae, 0x0001e0000b9a1400, "0x10"), // LDGSTS_ARI_dARI 64,E tok1 pos
    ("sm120", 0xffff000000ff0fae, 0x0001e0000b9a1400, "0xffff0"), // LDGSTS_ARI_dARI 64,E tok1 neg
    ("sm120", 0x8000000000ff0fae, 0x0001e0000b9a1400, "0x80000"), // LDGSTS_ARI_dARI 64,E tok1 min
    ("sm120", 0x0001000000ff0fae, 0x0001e0000b9a1200, "0x10"), // LDGSTS_ARI_dARI E,LTC128B tok1 pos
    ("sm120", 0xffff000000ff0fae, 0x0001e0000b9a1200, "0xffff0"), // LDGSTS_ARI_dARI E,LTC128B tok1 neg
    ("sm120", 0x8000000000ff0fae, 0x0001e0000b9a1200, "0x80000"), // LDGSTS_ARI_dARI E,LTC128B tok1 min
    ("sm120", 0x0001000000ff0fae, 0x0001e0000b9a1000, "0x10"), // LDGSTS_ARI_dARI E tok1 pos
    ("sm120", 0xffff000000ff0fae, 0x0001e0000b9a1000, "0xffff0"), // LDGSTS_ARI_dARI E tok1 neg
    ("sm120", 0x8000000000ff0fae, 0x0001e0000b9a1000, "0x80000"), // LDGSTS_ARI_dARI E tok1 min
    ("sm120", 0x0001000000ff7fae, 0x0001e000081a1400, "0x10"), // LDGSTS_ARI_dARI_P 64,E tok1 pos
    ("sm120", 0xffff000000ff7fae, 0x0001e000081a1400, "0xffff0"), // LDGSTS_ARI_dARI_P 64,E tok1 neg
    ("sm120", 0x8000000000ff7fae, 0x0001e000081a1400, "0x80000"), // LDGSTS_ARI_dARI_P 64,E tok1 min
    ("sm120", 0x0001000000ff7fae, 0x0001e000081a1000, "0x10"), // LDGSTS_ARI_dARI_P E tok1 pos
    ("sm120", 0xffff000000ff7fae, 0x0001e000081a1000, "0xffff0"), // LDGSTS_ARI_dARI_P E tok1 neg
    ("sm120", 0x8000000000ff7fae, 0x0001e000081a1000, "0x80000"), // LDGSTS_ARI_dARI_P E tok1 min
    ("sm120", 0x0001000000ff7fae, 0x0001e00008181a00, "0x10"), // LDGSTS_ARI_dARI_P 128,BYPASS,E,LTC128B tok1 pos
    ("sm120", 0xffff000000ff7fae, 0x0001e00008181a00, "0xffff0"), // LDGSTS_ARI_dARI_P 128,BYPASS,E,LTC128B tok1 neg
    ("sm120", 0x8000000000ff7fae, 0x0001e00008181a00, "0x80000"), // LDGSTS_ARI_dARI_P 128,BYPASS,E,LTC128B tok1 min
    ("sm120", 0x0001000000ff7fae, 0x0001e000081a1600, "0x10"), // LDGSTS_ARI_dARI_P 64,E,LTC128B tok1 pos
    ("sm120", 0xffff000000ff7fae, 0x0001e000081a1600, "0xffff0"), // LDGSTS_ARI_dARI_P 64,E,LTC128B tok1 neg
    ("sm120", 0x8000000000ff7fae, 0x0001e000081a1600, "0x80000"), // LDGSTS_ARI_dARI_P 64,E,LTC128B tok1 min
    ("sm120", 0x0001000000ff7fae, 0x0001e000081a1200, "0x10"), // LDGSTS_ARI_dARI_P E,LTC128B tok1 pos
    ("sm120", 0xffff000000ff7fae, 0x0001e000081a1200, "0xffff0"), // LDGSTS_ARI_dARI_P E,LTC128B tok1 neg
    ("sm120", 0x8000000000ff7fae, 0x0001e000081a1200, "0x80000"), // LDGSTS_ARI_dARI_P E,LTC128B tok1 min
    ("sm120", 0x00000010ff800dae, 0x0001c0000b980a00, "0x10"), // LDGSTS_ARURI_ARI 128,BYPASS,E,LTC128B tok2 pos
    ("sm120", 0x0007fff0ff800dae, 0x0001c0000b980a00, "0x7fff0"), // LDGSTS_ARURI_ARI 128,BYPASS,E,LTC128B tok2 neg
    ("sm120", 0x00040000ff800dae, 0x0001c0000b980a00, "0x40000"), // LDGSTS_ARURI_ARI 128,BYPASS,E,LTC128B tok2 min
    ("sm120", 0x00000010ffbc7dae, 0x0001e000081a0218, "0x10"), // LDGSTS_ARURI_ARI_P E,LTC128B tok2 pos
    ("sm120", 0x0003fff0ffbc7dae, 0x0001e000081a0218, "0x3fff0"), // LDGSTS_ARURI_ARI_P E,LTC128B tok2 neg
    ("sm120", 0x00020000ffbc7dae, 0x0001e000081a0218, "0x20000"), // LDGSTS_ARURI_ARI_P E,LTC128B tok2 min
    ("sm120", 0x00000010ff007dae, 0x0001e000081a0600, "0x10"), // LDGSTS_ARURI_ARI_P 64,E,LTC128B tok2 pos
    ("sm120", 0x00000ff0ff007dae, 0x0001e000081a0600, "0xff0"), // LDGSTS_ARURI_ARI_P 64,E,LTC128B tok2 neg
    ("sm120", 0x00000800ff007dae, 0x0001e000081a0600, "0x800"), // LDGSTS_ARURI_ARI_P 64,E,LTC128B tok2 min
    ("sm120", 0x00000010ff807dae, 0x0001e00008180a08, "0x10"), // LDGSTS_ARURI_ARI_P 128,BYPASS,E,LTC128B tok2 pos
    ("sm120", 0x0007fff0ff807dae, 0x0001e00008180a08, "0x3ffff0"), // LDGSTS_ARURI_ARI_P 128,BYPASS,E,LTC128B tok2 neg
    ("sm120", 0x00040000ff807dae, 0x0001e00008180a08, "0x3c0000"), // LDGSTS_ARURI_ARI_P 128,BYPASS,E,LTC128B tok2 min
    ("sm120", 0x00001000ff000388, 0x0001c00000000800, "0x10"), // STS_ARI_R  tok1 pos
    ("sm120", 0xfffff000ff000388, 0x0001c00000000800, "0xfffff0"), // STS_ARI_R  tok1 neg
    ("sm120", 0x80000000ff000388, 0x0001c00000000800, "0x800000"), // STS_ARI_R  tok1 min
    ("sm120", 0x00001000ff000188, 0x0001c00000000a00, "0x10"), // STS_ARI_R 64 tok1 pos
    ("sm120", 0xfffff000ff000188, 0x0001c00000000a00, "0xfffff0"), // STS_ARI_R 64 tok1 neg
    ("sm120", 0x80000000ff000188, 0x0001c00000000a00, "0x800000"), // STS_ARI_R 64 tok1 min
    ("sm120", 0x00001000ff000388, 0x0000000000000c00, "0x10"), // STS_ARI_R 128 tok1 pos
    ("sm120", 0xfffff000ff000388, 0x0000000000000c00, "0xfffff0"), // STS_ARI_R 128 tok1 neg
    ("sm120", 0x80000000ff000388, 0x0000000000000c00, "0x800000"), // STS_ARI_R 128 tok1 min
    ("sm120", 0x00001000ff000388, 0x0001c00000000400, "0x10"), // STS_ARI_R U16 tok1 pos
    ("sm120", 0xfffff000ff000388, 0x0001c00000000400, "0xfffff0"), // STS_ARI_R U16 tok1 neg
    ("sm120", 0x80000000ff000388, 0x0001c00000000400, "0x800000"), // STS_ARI_R U16 tok1 min
    ("sm120", 0x00001000ff000388, 0x0001e00000000000, "0x10"), // STS_ARI_R U8 tok1 pos
    ("sm120", 0xfffff000ff000388, 0x0001e00000000000, "0xfffff0"), // STS_ARI_R U8 tok1 neg
    ("sm120", 0x80000000ff000388, 0x0001e00000000000, "0x800000"), // STS_ARI_R U8 tok1 min
];

#[test]
fn t164_2_law_bracket_ldgsts_split() {
    let i103 = DecodeIndex::build(&t103a());
    let i120 = DecodeIndex::build(&t120());
    for (tn, lo, hi, want_b) in LAWB {
        let t = tbl(tn);
        let idx = if tn == &"sm120" { &i120 } else { &i103 };
        let got = dec(&t, idx, word(*lo, *hi));
        let brs: Vec<&str> = got.split('[').skip(1)
            .filter_map(|s| s.split(']').next()).collect();
        assert!(brs.iter().any(|b| b == want_b),
            "law bracket [{want_b}] not in: {got}");
    }
}

#[test]
fn t164_3_encode_identity_and_legacy_spelling() {
    for (tn, lo, hi, txt) in ENC {
        let t = tbl(tn);
        let w = word(*lo, *hi);
        assert_eq!(enc(&t, txt) & !SCHED, w & !SCHED, "encode identity {txt}");
    }
    // legacy spelling "[RZ+0x10]"/"[RZ+-0x10]" must keep parsing and encode
    // to the same word as the elided form (backward compatibility).
    let t = t103a();
    let pairs = [
        ("@P0 LDS R0, [0x10]", "@P0 LDS R0, [RZ+0x10]"),
        ("@P0 LDS R0, [0xfffff0]", "@P0 LDS R0, [RZ+-0x10]"),
        ("@P0 STS [0x10], R0", "@P0 STS [RZ+0x10], R0"),
    ];
    for (elided, legacy) in pairs {
        assert_eq!(enc(&t, elided), enc(&t, legacy), "legacy==elided {legacy}");
    }
}

// t164_4: kontrola braku elizji (imm0 -> [RZ]; baza != RZ -> pełna forma).
const CTLX: &[(&str, u64, u64, &str)] = &[
    ("sm103a", 0x00000000ff00783b, 0x0000200000000200, "LDSM.16.M88.4 R0, [RZ]"), // LDSM_R_ARI 16,4,M88 tok2 imm0
    ("sm103a", 0x000010000500783b, 0x0000200000000200, "LDSM.16.M88.4 R0, [R5+0x10]"), // LDSM_R_ARI 16,4,M88 tok2 b5pos
    ("sm103a", 0xfffff0000500783b, 0x0000200000000200, "LDSM.16.M88.4 R0, [R5+-0x10]"), // LDSM_R_ARI 16,4,M88 tok2 b5neg
    ("sm103a", 0x00000000ff000984, 0x0000000000000800, "@P0 LDS R0, [RZ]"), // LDS_R_ARI  tok2 imm0
    ("sm103a", 0x0000100005000984, 0x0000000000000800, "@P0 LDS R0, [R5+0x10]"), // LDS_R_ARI  tok2 b5pos
    ("sm103a", 0xfffff00005000984, 0x0000000000000800, "@P0 LDS R0, [R5+-0x10]"), // LDS_R_ARI  tok2 b5neg
    ("sm103a", 0x00000000ff000984, 0x0000000000000a00, "@P0 LDS.64 R0, [RZ]"), // LDS_R_ARI 64 tok2 imm0
    ("sm103a", 0x0000100005000984, 0x0000000000000a00, "@P0 LDS.64 R0, [R5+0x10]"), // LDS_R_ARI 64 tok2 b5pos
    ("sm103a", 0xfffff00005000984, 0x0000000000000a00, "@P0 LDS.64 R0, [R5+-0x10]"), // LDS_R_ARI 64 tok2 b5neg
    ("sm103a", 0x00000000ff000844, 0x0000000000000200, "@P0 STSM.16.M88.4 [RZ], R0"), // STSM_ARI_R 16,4,M88 tok1 imm0
    ("sm103a", 0x0000100005000844, 0x0000000000000200, "@P0 STSM.16.M88.4 [R5+0x10], R0"), // STSM_ARI_R 16,4,M88 tok1 b5pos
    ("sm103a", 0xfffff00005000844, 0x0000000000000200, "@P0 STSM.16.M88.4 [R5+-0x10], R0"), // STSM_ARI_R 16,4,M88 tok1 b5neg
    ("sm103a", 0x00000000ff000388, 0x0001c00000000800, "@P0 STS [RZ], R0"), // STS_ARI_R  tok1 imm0
    ("sm103a", 0x0000100005000388, 0x0001c00000000800, "@P0 STS [R5+0x10], R0"), // STS_ARI_R  tok1 b5pos
    ("sm103a", 0xfffff00005000388, 0x0001c00000000800, "@P0 STS [R5+-0x10], R0"), // STS_ARI_R  tok1 b5neg
    ("sm103a", 0x00000000ff000188, 0x0001c00000000a00, "@P0 STS.64 [RZ], R0"), // STS_ARI_R 64 tok1 imm0
    ("sm103a", 0x0000100005000188, 0x0001c00000000a00, "@P0 STS.64 [R5+0x10], R0"), // STS_ARI_R 64 tok1 b5pos
    ("sm103a", 0xfffff00005000188, 0x0001c00000000a00, "@P0 STS.64 [R5+-0x10], R0"), // STS_ARI_R 64 tok1 b5neg
];

#[test]
fn t164_4_no_elision_controls() {
    let i103 = DecodeIndex::build(&t103a());
    let i120 = DecodeIndex::build(&t120());
    for (tn, lo, hi, want) in CTLX {
        let t = tbl(tn);
        let idx = if tn == &"sm120" { &i120 } else { &i103 };
        let got = dec(&t, idx, word(*lo, *hi));
        assert_eq!(got, *want, "control no-elision {tn} {want}");
    }
}

#[test]
fn t164_5_fixed_point() {
    let i103 = DecodeIndex::build(&t103a());
    let i120 = DecodeIndex::build(&t120());
    for (tn, lo, hi, _txt) in ENC {
        let t = tbl(tn);
        let idx = if tn == &"sm120" { &i120 } else { &i103 };
        let w = word(*lo, *hi);
        let s1 = dec(&t, idx, w);
        let w2 = enc(&t, &s1);
        let s2 = dec(&t, idx, w2);
        assert_eq!(s1, s2, "fixed-point {s1}");
        assert_eq!(w2 & !SCHED, w & !SCHED, "payload stable {_txt}");
    }
}

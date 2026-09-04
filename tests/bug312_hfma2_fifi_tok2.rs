//! BUG-312 (F2-iter165, loop5/blind front2, 2026-08-31): HFMA2
//! R_R_R_FI_FI tok2 register-basis window repair, all 74+24 instances x4
//! archs (main key 74 mod-groups + 24 dotted RELU _P era keys on
//! sm120/sm121a; canonical ed4c840 + 88697c2; graft patch312.py).
//!
//! LAW (arb312/arb312b: nvdisasm 13.3.73 raw -b, x4 models SM100a/SM103a/
//! SM120/SM121a agree on EVERY probe -- arb312 23/23, arb312b 8/8 incl.
//! _P-lattice and tok3!=RZ legs): on the 0x74-lane FI_FI class the tok2
//! register basis lives in window [31:24] with sign/hsel windows neg@72 /
//! abs@73 / hsel[75:74] (v1='.INVALID1', v2='.H0_H0', v3='.H1_H1'),
//! IDENTICAL to the II_FI 0x04-lane law (arb306 G56); f16 tails tok4@48 /
//! tok5@32 are live on both lanes. The harvest-era row (reg@64 on BOTH
//! tok2 and tok3 + and_base 0xff@[31:24]) was lattice-fiction.
//! PRE-FIX (measure_pre312, pub pyo3-31a06b1): every authored
//! 'HFMA2 R<d>, R<a>, R<b>, <f>, <f>' minted 0xff@[31:24] from the and_base
//! pin while tok3's value overwrote tok2 at [71:64] (14/40 probe mints
//! dropped tok2; vendor reads src1 as RZ; own decode dup-printed
//! '<d>, <b>, <b>'); authored (RZ,Rc) text minted right but decode
//! dup-printed tok2=tok3 whenever Rc!=RZ.
//! CORPUS EXPOSURE ZERO (routex312_pre, 2,406 cubins x4 legs: 97,337
//! words on the FI_FI fingerprint, ALL tok2=RZ/tok3=RZ -> pre/post decode
//! texts byte-identical; ZERO words with [31:24]!=0xff -> no hole->decode
//! transitions; rt/abtext deltas 0 by construction).
use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::{Extraction, IsaTable};

const M96: u128 = (1u128 << 96) - 1;
fn tab(arch: &str) -> IsaTable {
    IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap()
}
fn dec(t: &IsaTable, w: u128) -> Option<String> {
    let idx = DecodeIndex::build(t);
    idx.decode(w & M96, 0, t).map(|d| to_sass(&d)).ok()
}
fn enc(t: &IsaTable, text: &str) -> Result<u128, String> {
    let insn = parse_sass(&format!("{text};"), 0).unwrap();
    encode_instruction(&insn, t).map_err(|e| format!("{e}"))
}

#[test]
fn t312_1_structure_tok2_basis_all_instances() {
    for arch in ["sm100a", "sm103a", "sm120", "sm121a"] {
        let t = tab(arch);
        let mut n = 0usize;
        for (key, entry) in &t.entries {
            if !(key == "HFMA2_R_R_R_FI_FI" || key.ends_with("_R_R_R_FI_FI_P")) {
                continue;
            }
            for (mg_name, mg) in &entry.mod_groups {
                n += 1;
                let has = |ex: Extraction, sh: u32, ti: i32| {
                    mg.fields
                        .iter()
                        .any(|f| f.extraction == ex && f.shift == sh && f.token_idx == ti)
                };
                assert!(
                    has(Extraction::Reg, 24, 2),
                    "{arch} {key}|{mg_name} tok2 basis @24"
                );
                assert!(
                    !has(Extraction::Reg, 64, 2),
                    "{arch} {key}|{mg_name} no tok2 dup @64"
                );
                assert!(
                    has(Extraction::Reg, 64, 3),
                    "{arch} {key}|{mg_name} tok3 basis @64"
                );
                assert!(
                    has(Extraction::Neg, 72, 2),
                    "{arch} {key}|{mg_name} neg@72 tok2"
                );
                assert_eq!(
                    mg.and_base & (0xffu128 << 24),
                    0,
                    "{arch} {key}|{mg_name} ab pins tok2"
                );
                assert_eq!(
                    mg.variable_mask & (0xffu128 << 24),
                    0xffu128 << 24,
                    "{arch} {key}|{mg_name} vm missing tok2 window"
                );
            }
        }
        // FLIP (BUG-354, F2-iter184, canonical 5c12995): sparse FI_FI
        // family grew 1 -> 18 (11 mod-lane mgs on the key + 6 RELU _P
        // dotted keys; every instance is a lane clone of '' so the
        // tok2/tok3 basis assertions above apply unchanged).
        // FLIP (BUG-367, F2-iter193, canonical 0933cf6): SAT/FTZ/OOB
        // lane closure completes the sparse lattice: 18 -> 48 = dense
        // parity (36 mgs on the key + 12 RELU _P dotted keys, every
        // instance still a lane clone of ''/bf16sub('')).
        let want = 48;
        assert_eq!(n, want, "{arch} FI_FI instance census");
    }
}

#[test]
fn t312_2_decode_vendor_law_exact() {
    // arb312/arb312b probes == vendor text (x4 models agree in arb).
    let t103 = tab("sm103a");
    let t120 = tab("sm120");
    let t121 = tab("sm121a");
    let cases: &[(&IsaTable, u128, &str)] = &[
        // arb312 L0 (0x74 lane, tok2 R5@24 window, tok3 RZ)
        (
            &t103,
            0x00000000000000ff0000000005000431u128 | (7 << 12) | (0 << 16) | (5 << 24),
            "HFMA2 R0, R5, RZ, 0, 0",
        ),
        // L4: tok2 hsel v2... armed on sm120 leg (arb312 L4 law text)
        (
            &t120,
            0x00000000000008ff0000000005000431u128 | (7 << 12) | (5 << 24),
            "HFMA2 R0, R5.H0_H0, RZ, 0, 0",
        ),
        // arb312b Q0: main '' tok2 R5, tok3 R7 (tok3 window live)
        (
            &t103,
            0x00000000000000070000000005007431,
            "HFMA2 R0, R5, R7, 0, 0",
        ),
        // arb312b Q2: + f16 tails both 1.0
        (
            &t103,
            0x00000000000000073c003c0005007431,
            "HFMA2 R0, R5, R7, 1, 1",
        ),
        // arb312b P0: _P era key (RELU) both windows
        (
            &t120,
            0x00000000000080070000000005007431,
            "HFMA2.RELU R0, R5, R7, 0, 0, P0",
        ),
        // arb306 G56 base (class-P 0x04 lane, @P0 guard) -- II_FI on 121a
        (
            &t121,
            0x00000000000000040000000003020431,
            "@P0 HFMA2 R2, R3, R4, 0, 0",
        ),
    ];
    for (t, w, want) in cases {
        let got = dec(t, *w).unwrap_or_else(|| panic!("hole {w:#034x}"));
        assert_eq!(&got, want, "decode {w:#034x}");
    }
}

#[test]
fn t312_3_encode_mint_law_byte_exact() {
    // The 312-class mints: byte-exact payload expectations (measured
    // post-fix, each cross-read by nvdisasm in arb312 / arb306 G56).
    let cases: &[(&str, &str, u128)] = &[
        (
            "sm103a",
            "@P0 HFMA2 R2, R3, R4, 0, 0",
            0x00000000000000040000000003020431,
        ), // == arb306 A0
        (
            "sm103a",
            "HFMA2 R2, R3, R4, 0, 0",
            0x00000000000000040000000003027431,
        ), // == arb312 A4 shape
        (
            "sm103a",
            "@P0 HFMA2 R2, -R3, R4, 0, 0",
            0x000000000001040000000003020431,
        ),
        (
            "sm103a",
            "@P0 HFMA2 R2, R3, R4, 1, 0",
            0x000000000000043c00000003020431,
        ),
        (
            "sm103a",
            "@P0 HFMA2 R0, R5, R7, 1, 1",
            0x000000000000073c003c0005000431,
        ),
        (
            "sm103a",
            "@P0 HFMA2 R2, RZ, R4, 0, 0",
            0x0000000000000400000000ff020431,
        ),
        (
            "sm120",
            "@P0 HFMA2 R2, R3.H0_H0, R4, 0, 0",
            0x000000000008040000000003020431,
        ),
        (
            "sm120",
            "@P0 HFMA2.RELU R0, R5, R7, 0, 0, P0",
            0x000000000080070000000005000431,
        ),
        (
            "sm121a",
            "@P0 HFMA2.RELU R0, R5, R7, 0, 0, P0",
            0x000000000080070000000005000431,
        ),
    ];
    for (arch, text, want) in cases {
        let t = tab(arch);
        let w = enc(&t, text).unwrap_or_else(|e| panic!("encode {text}: {e}")) & M96;
        assert_eq!(w, *want, "{arch} mint {text}");
        // roundtrip: decode(mint) == authored text (normalized)
        let got = dec(&t, w).unwrap();
        assert_eq!(&got, text, "{arch} roundtrip {text}");
    }
}

#[test]
fn t312_4_corpus_rz_class_byte_stable() {
    // routex312: 97,337 corpus words are tok2=RZ/tok3=RZ. Authored RZ-class
    // text must mint byte-IDENTICAL words pre/post fix (measure_pre312
    // literals) -- the repair must not perturb the corpus class.
    let pre: &[(&str, u128)] = &[
        ("@P0 HFMA2 R2, RZ, RZ, 0, 0", 0xff00000000ff020431),
        ("@P0 HFMA2 R2, RZ, R4, 1, 0", 0x43c000000ff020431),
        ("@P0 HFMA2 R2, RZ, R4, 0, 1", 0x400003c00ff020431),
    ];
    for arch in ["sm100a", "sm103a", "sm120", "sm121a"] {
        let t = tab(arch);
        for (text, want) in pre {
            let w = enc(&t, text).unwrap() & M96;
            assert_eq!(w, *want, "{arch} RZ-class byte drift {text}");
            let back = dec(&t, w).unwrap();
            assert_eq!(&back, text, "{arch} RZ-class dup-print survived {text}");
        }
    }
}

#[test]
fn t312_5_cross_leg_parity_and_drop_tripwire() {
    // Same authored text mints the same payload on every leg; the fixed
    // headline case must put tok2 in [31:24], never the pre-fix 0xff.
    for arch in ["sm100a", "sm103a", "sm120", "sm121a"] {
        let t = tab(arch);
        let w = enc(&t, "@P0 HFMA2 R2, R3, R4, 0, 0").unwrap() & M96;
        assert_eq!((w >> 24) & 0xff, 3, "{arch}: tok2 dropped (0xff@24)");
        assert_eq!((w >> 64) & 0xff, 4, "{arch}: tok3 lost");
        assert_eq!(w, 0x00000000000000040000000003020431, "{arch} parity");
    }
}

//! BUG-286 (F2-iter158, loop5/blind front2, 2026-08-31; canonical 16210e9):
//! sm121a FI_FI-family era-shape repair. The 279/285 grafts armed the
//! HFMA2 packed-f16 imm window laws on both legs, but the sm121a host rows
//! of the *_R_R_R_FI_FI sig family kept the pre-243 era shape
//! ([72:64]=0x1ff Rc-sentinel+neg@72 bake, f16_d, missing tok2/tok3 reg
//! fields). Consequences measured pre-fix on pub pyo3-91a970e:
//!   DECODE: era HFMA2_R_R_R_FI_II shadowed the family on sign/suffix-
//!     window words ('0, 0x0' payload-drop texts; b86+hsel vendor-INVALID
//!     fail-closed bypassed — 271-doctrine hole fired only on sm120);
//!   ENCODE: every authored family text minted neg@72=1 on sm121a — plain
//!     'RZ' authored '-RZ' SILICON (silent wrong-code), '|RZ|' minted
//!     '-|RZ|' (0x3ff shape);
//!   RELU _P imm token printed '0x0' (era/f16_d cosmetics).
//! Law arb286 (160 probes, work/bug286/arb286_verdicts.json; nvdisasm
//! 13.3.73 raw -b; x4 models SM100a/103a/120/121a agree on EVERY probe):
//! window/tok2/guard/imm laws arch-invariant; b72=0=>'RZ', b72=1=>'-RZ';
//! b86+hsel v1/v2 => vendor '.INVALID5'/'.INVALID6' (printed; engine holes
//! per the 271 fail-closed doctrine).
//! Graft patch286.py (replayable+idempotent, re-run skip x48): 48 instances
//! (36 mgs on HFMA2_R_R_R_FI_FI + 12 *RELU_R_R_R_FI_FI_P keys, mg '') get
//! and_base &= ~(0x1ff<<64), variable_mask |= 1<<72, fields := the sm120
//! counterpart list/order (bug286-2026-08-31 tags; pre-existing 279/271/274
//! tags kept). Top bits >=96 untouched (era ctl convention). sm120 + donors
//! sm100a/sm103a byte-untouched (census pins below).
//! Flips with attribution: t270_3 (era '0, 0x0' texts -> vendor-exact both
//! legs), t271_4 (era '-RZ' encode baseline -> unified bit-exact), t274_2
//! (RELU_P '0x0' -> '0'), t274_3 (FIB mint base -> FIB0), t279_2 (imm0
//! per-leg -> '0').
//! Remaining measured buckets = BOTH-LEG pre-existing, registered NOT fixed
//! here (mirror doctrine; arb286 x4 evidence): 317-kand (BF16_V2 b85 tok4
//! payload print semantics '1' vs '1.875'), 318-kand (tok2 abs@73 ghost
//! '-RZ' at tok3 on the era row), 319-kand (family tok2 real-reg law =
//! Ra@24 vendor vs reg@64 latent field; corpus exposure zero by the
//! ab-baked Ra=RZ care), plus the standing 270-line payload-gap on the era
//! row's tok2-hsel claims (B_04-set: both legs, '0, 0x0'-drop).
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
    idx.decode(w, 0, t).map(|d| to_sass(&d)).ok()
}
fn dec_key(t: &IsaTable, w: u128) -> Option<String> {
    let idx = DecodeIndex::build(t);
    idx.decode(w, 0, t).ok().map(|d| d.key.clone())
}
fn enc(t: &IsaTable, text: &str) -> u128 {
    let insn = parse_sass(&format!("{text};"), 0).unwrap_or_else(|e| panic!("parse {text}: {e}"));
    encode_instruction(&insn, t).unwrap_or_else(|e| panic!("encode {text}: {e}"))
}

// arb286 shadow-host words (era FI_II lattice, tok4=f16@48=1.875 payload).
const HOST: u128 = 0x00ff3f800000ff000431 & M96;

#[test]
fn t286_1_structure_repair_census() {
    // 48 repaired instances on sm121a: ab bake cleared, fields hold the
    // reg@64 tok2 + reg@64 tok3 + neg@72 tok2 + f16 (not f16_d) arms.
    let t = tab("sm121a");
    let main = &t.entries["HFMA2_R_R_R_FI_FI"];
    assert_eq!(main.mod_groups.len(), 36, "main mg census");
    let pkeys: Vec<&String> = t
        .entries
        .keys()
        .filter(|k| k.ends_with("_R_R_R_FI_FI_P"))
        .collect();
    assert_eq!(pkeys.len(), 12, "_P key census");
    let mut n_inst = 0usize;
    let mut check = |e: &cubit::table::InsKeyEntry, mgname: &str, what: &str| {
        n_inst += 1;
        let g = &e.mod_groups[mgname];
        let ab: u128 = g.and_base;
        let vm: u128 = g.variable_mask;
        assert_eq!(ab & (0x1ff << 64), 0, "{what} era bake survived");
        assert_ne!(vm & (1 << 72), 0, "{what} vm b72 not armed");
        let has = |ex: Extraction, sh: u32, ti: i32, bits: u32| {
            g.fields
                .iter()
                .any(|f| f.extraction == ex && f.shift == sh && f.token_idx == ti && f.bits == bits)
        };
        // BUG-312 flip (F2-iter165, graft patch312.py, arb312 x4 models):
        // tok2 register basis repaired 64 -> @24 (the @64 slot was a harvest
        // fiction duplicating tok3's window; and_base 0xff@[31:24] cleared,
        // vm freed). neg@72/abs@73/hsel@74 tok2 windows unchanged.
        assert!(has(Extraction::Reg, 24, 2, 8), "{what} reg@24 t2 (BUG-312)");
        assert!(!has(Extraction::Reg, 64, 2, 8), "{what} no reg@64 t2 dup");
        assert!(has(Extraction::Reg, 64, 3, 8), "{what} reg@64 t3");
        assert!(has(Extraction::Neg, 72, 2, 1), "{what} neg@72 t2");
        // BUG-288 flip (F2-iter160, graft patch288.py Part B): on the
        // BF16_V2 mod-groups / dotted BF16_V2 keys the two 16b imm slots are
        // extraction BF16 (vendor reads bf16 constants; arb288 E-set x4);
        // every other row keeps the 286-era F16 (not F16d) shape.
        if mgname.starts_with("BF16_V2") || what.contains("BF16_V2") {
            assert!(has(Extraction::BF16, 48, 4, 16), "{what} bf16 tok4");
            assert!(has(Extraction::BF16, 32, 5, 16), "{what} bf16 tok5");
        } else {
            assert!(has(Extraction::F16, 48, 4, 16), "{what} f16 tok4");
            assert!(has(Extraction::F16, 32, 5, 16), "{what} f16 tok5");
        }
    };
    for mgname in main.mod_groups.keys() {
        check(main, mgname, &format!("FI_FI|{mgname}"));
    }
    for k in &pkeys {
        check(&t.entries[*k], "", &format!("{k}|''"));
    }
    assert_eq!(n_inst, 48, "repaired instance count");
    // Provenance census (table-JSON level): exactly 288 bug286-2026-08-31
    // field tags on sm121a and ZERO on sm120 + donors (byte-untouched legs).
    let count_tags = |arch: &str| -> usize {
        let v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(format!("tables/{arch}.json")).unwrap())
                .unwrap();
        let mut n = 0usize;
        for (_k, e) in v["instructions"].as_object().unwrap() {
            if let Some(mgs) = e.get("mod_groups") {
                for (_m, g) in mgs.as_object().unwrap() {
                    for f in g["fields"].as_array().unwrap() {
                        if f.get("_src").and_then(|x| x.as_str()) == Some("bug286-2026-08-31") {
                            n += 1;
                        }
                    }
                }
            }
        }
        n
    };
    // BUG-288 flip (F2-iter160): 32 of the 286-tagged fields (the two imm
    // slots on the FI_FI BF16_V2 mgs x12 + dotted BF16_V2 FI_FI_P keys x4,
    // x2 legs-worth here on sm121a) were re-tagged bug288-2026-08-31 by the
    // bf16-extraction swap (arb288 E-set: vendor reads bf16 constants).
    // BUG-312 second flip: the 48 tok2 basis fields (reg@64 dup -> reg@24)
    // were re-tagged bug312-2026-08-31 (canonical ed4c840 + 88697c2).
    assert_eq!(
        count_tags("sm121a"),
        208,
        "sm121a bug286 tag census (288 - 32 bug288 - 48 bug312)"
    );
    assert_eq!(count_tags("sm120"), 0, "sm120 byte-untouched");
    assert_eq!(count_tags("sm100a"), 0, "donor sm100a untouched");
    assert_eq!(count_tags("sm103a"), 0, "donor sm103a untouched");
}

#[test]
fn t286_2_decode_shadow_closed_vendor_exact() {
    // arb286 A/D/E law subset: decode vendor-exact on BOTH legs, claiming
    // key == HFMA2_R_R_R_FI_FI (era row no longer wins the window words).
    let cases: &[(u128, &str)] = &[
        (HOST, "@P0 HFMA2 R0, RZ, RZ, 1.875, 0"),
        (HOST | (1 << 80), "@P0 HFMA2.FTZ R0, RZ, RZ, 1.875, 0"),
        (HOST | (1 << 81), "@P0 HFMA2 R0, RZ, RZ.F32, 1.875, 0"),
        (HOST | (2 << 81), "@P0 HFMA2 R0, RZ, RZ.H0_H0, 1.875, 0"),
        (HOST | (1 << 83), "@P0 HFMA2 R0, RZ, |RZ|, 1.875, 0"),
        (HOST | (1 << 84), "@P0 HFMA2 R0, RZ, -RZ, 1.875, 0"),
        (HOST | (3 << 83), "@P0 HFMA2 R0, RZ, -|RZ|, 1.875, 0"),
        (HOST | (1 << 86), "@P0 HFMA2 R0, RZ, RZ.H0_NH1, 1.875, 0"),
        (
            HOST | (1 << 86) | (1 << 83),
            "@P0 HFMA2 R0, RZ, |RZ|.H0_NH1, 1.875, 0",
        ),
        (HOST | (1 << 72), "@P0 HFMA2 R0, -RZ, RZ, 1.875, 0"),
        (HOST | (7 << 12), "HFMA2 R0, RZ, RZ, 1.875, 0"), // PT guard elides
        (HOST | (1 << 12), "@P1 HFMA2 R0, RZ, RZ, 1.875, 0"),
    ];
    for arch in ["sm120", "sm121a"] {
        let t = tab(arch);
        for (w, want) in cases {
            let got = dec(&t, w & M96).unwrap_or_else(|| panic!("{arch} hole at {want}"));
            assert_eq!(got, *want, "{arch} shadow text");
            assert!(
                !got.contains("0x0"),
                "{arch}: era payload-drop cosmetics survived: {got}"
            );
            // BUG-330 attribution (iter176): arming II_FI tok4 f16_d@48
            // moved the sm121a claim of these RZ/RZ-payload words from
            // FI_FI to II_FI (text byte-equal, vendor-exact; sm120 keeps
            // FI_FI by name-order tie). The anti-regression invariant is
            // NOT the era FI_II row and a text-exact print, not a fixed
            // twin owner: pin both.
            let owner = dec_key(&t, w & M96);
            assert!(
                matches!(
                    owner.as_deref(),
                    Some("HFMA2_R_R_R_FI_FI") | Some("HFMA2_R_R_R_II_FI")
                ),
                "{arch}: neither twin row claims {want}: {owner:?}"
            );
            assert_ne!(
                owner.as_deref(),
                Some("HFMA2_R_R_R_FI_II"),
                "{arch}: era FI_II row reclaims {want}"
            );
        }
        // b86+hsel vendor-INVALID combos: 271-doctrine fail-closed on BOTH
        // legs now (pre-fix sm121a printed '.F32' via the era row).
        assert!(
            dec(&t, (HOST | (1 << 86) | (1 << 81)) & M96).is_none(),
            "{arch} INVALID5 must hole"
        );
        assert!(
            dec(&t, (HOST | (1 << 86) | (2 << 81)) & M96).is_none(),
            "{arch} INVALID6 must hole"
        );
    }
}

#[test]
fn t286_3_encode_mint_law_and_leg_parity() {
    // Era silent wrong-code CLOSED: authored 'RZ' mints b72=0 on sm121a
    // (pre: b72=1 = '-RZ' silicon); authored signs mint exactly the window
    // bits; both legs mint identical words.
    let cases: &[(&str, u128)] = &[
        ("HFMA2 R3, RZ, RZ, 0, 0", 0x000000ff00000000ff037431),
        ("HFMA2 R3, -RZ, RZ, 0, 0", 0x000001ff00000000ff037431),
        ("HFMA2 R3, |RZ|, RZ, 0, 0", 0x000002ff00000000ff037431),
        ("HFMA2.FTZ R3, RZ, RZ, 0, 0", 0x000100ff00000000ff037431),
        ("HFMA2 R3, RZ, RZ.H0_NH1, 0, 0", 0x004000ff00000000ff037431),
        (
            "HFMA2.RELU R3, RZ, RZ, 0, 0, P2",
            0x010080ff00000000ff037431,
        ),
        ("HFMA2.BF16_V2 R3, RZ, RZ, 0, 0", 0x002000ff00000000ff037431),
        ("HFMA2 R3, RZ, RZ, 1.875, 0", 0x000000ff3f800000ff037431),
    ];
    for (txt, want) in cases {
        let w120 = enc(&tab("sm120"), txt) & M96;
        let w121 = enc(&tab("sm121a"), txt) & M96;
        assert_eq!(w121, w120, "leg mint parity {txt}");
        assert_eq!(w121, want & M96, "mint law {txt}");
    }
    // '-RZ' remains the ONLY authored path to b72=1; the '|RZ|' shape no
    // longer absorbs neg (era 0x3ff mint is gone).
    let w = enc(&tab("sm121a"), "HFMA2 R3, |RZ|, RZ, 0, 0") & M96;
    assert_eq!(w & (3 << 72), 1 << 73, "abs-only shape for |RZ|");
}

#[test]
fn t286_4_roundtrip_window_and_imm_retention() {
    // decode(encode(txt)) == txt and encode(decode(word)) == word of the
    // armed window texts on both legs (f16@48 payload retained, no era
    // '0, 0x0' tail).
    for arch in ["sm120", "sm121a"] {
        let t = tab(arch);
        for w in [
            HOST,
            HOST | (1 << 80),
            HOST | (1 << 81),
            HOST | (1 << 86),
            HOST | (1 << 72),
        ] {
            let w = w & M96;
            let text = dec(&t, w).expect("decode hole");
            let back = enc(&t, &text) & M96;
            assert_eq!(back, w, "{arch}: word rt via '{text}'");
        }
        // REAL f16 payload must print (era tok4-drop would print '0'):
        let got = dec(
            &t,
            ((HOST & !(0xffffu128 << 48)) | (0x4200u128 << 48)) & M96,
        )
        .expect("f16 payload");
        assert!(got.contains("3"), "{arch}: f16 payload dropped: {got}");
    }
}

#[test]
fn t286_5_anchors_era_and_invalid_law() {
    // era row HFMA2_R_R_R_FI_II stays armed (encode-visible retention,
    // identical on both legs) — repair did NOT delete it:
    for arch in ["sm120", "sm121a"] {
        let t = tab(arch);
        let era = t.entries.get("HFMA2_R_R_R_FI_II").expect("era row present");
        let g = era.mod_groups.get("").unwrap();
        assert_eq!(
            g.and_base & M96,
            0x00ff3f800000ff000431u128 & M96,
            "{arch} era ab drifted"
        );
        assert_eq!(g.fields.len(), 9, "{arch} era field census");
        // 306 law intact on sm121a (hsel v1 spellings on the R-domain):
        assert_eq!(
            dec(&t, (HOST | (3 << 81)) & M96).as_deref(),
            Some("@P0 HFMA2 R0, RZ, RZ.H1_H1, 1.875, 0"),
            "{arch}"
        );
        // BF16_V2 cross-key still wins on b85 (285-law intact):
        let got = dec(&t, (HOST | (1 << 85)) & M96).unwrap_or_else(|| panic!("{arch} b85 hole"));
        assert!(
            got.starts_with("@P0 HFMA2.BF16_V2 R0, RZ, RZ,"),
            "{arch}: {got}"
        );
    }
}

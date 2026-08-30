//! BUG-251 (F2-iter128, loop5/blind front2, 2026-08-28): decoder.rs
//! `extraction_name()` had no `NegAbs` arm -- Debug-lowercase catch-all
//! emitted "negabs", which the printer's "neg_abs" arm never matches, so the
//! sign window was silently dropped for every row carrying that extraction
//! (inventory: exactly 31 rows, all sm121a DSETP, tok3 2b@72; zero rows on
//! sm100a/sm103a/sm120). Encoder patched symmetrically: NegAbs was
//! abs-wins-if-set (2), now exact printer-inverse ((abs<<1)|neg) so the
//! vendor-legal both-set window (value 3) round-trips.
//!
//! Evidence: law251 census (2,406-cubin battery, nvdisasm 13.3.73 raw-binary
//! probes): DSETP 38,317 uniq / 127,999 occ; pre==post x4 legs (dec251
//! tallies identical) = latent fix, zero corpus drift (corpus words with the
//! sign bits set do not route into these rows today; sm121a DSETP inventory
//! gaps are the separately-registered classes 253/254).
//! arb251 (host 'DSETP.GT.AND P0, PT, R50, R44, PT', raw -b SM121a + SM103a,
//! identical models): tok3 neg@72/abs@73, both-set '-|R50|' legal; tok4
//! neg@63/abs@62 (already armed as neg/abs fields).
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
fn enc(t: &IsaTable, text: &str) -> u128 {
    let insn = parse_sass(&format!("{text};"), 0).unwrap_or_else(|e| panic!("parse {text}: {e}"));
    encode_instruction(&insn, t).unwrap_or_else(|e| panic!("encode {text}: {e}"))
}

// arb251 witnesses (full 128-bit; engine matches 96-bit payload).
const W_BASE: u128 = 0xfe40003f040000000002c3200722a; // DSETP.GT.AND P0, PT, R50, R44, PT
const W_TOK3_NEG: u128 = W_BASE ^ (1u128 << 72); //     -R50
const W_TOK3_ABS: u128 = W_BASE ^ (1u128 << 73); //     |R50|
const W_TOK3_BOTH: u128 = W_BASE ^ (3u128 << 72); //    -|R50|
const W_TOK4_ABS: u128 = W_BASE ^ (1u128 << 62); //     |R44|
const W_TOK4_NEG: u128 = W_BASE ^ (1u128 << 63); //     -R44
const W_TOK4_BOTH: u128 = W_BASE ^ (3u128 << 62); //    -|R44|
                                                  // arb251b witnesses (DFMA sentinel for 253-kand).
const W_DF_BASE: u128 = 0x4fc6000000001c000000402020722b; // DFMA R32, R32, R64, R28
const W_DF_TOK3_NEG: u128 = W_DF_BASE ^ (1u128 << 63); //    vend: -R64
const W_DF_TOK4_NEG: u128 = W_DF_BASE ^ (1u128 << 75); //    vend: -R28

#[test]
fn t251_1_structure() {
    // NegAbs rows: were exactly 31 (all sm121a era DSETP keys, tok3 2b@72) at
    // the BUG-251 fix; BUG-254 (canonical 9fd3368) deleted the 32 sm121a era
    // DSETP keys wholesale (donor-structure graft), so the NegAbs inventory
    // is now ZERO on all four arches. The engine NegAbs arm stays (future
    // rows may use it); this pin flips 31 -> 0 as the 254-era sentinel.
    let t = tab("sm121a");
    let mut n = 0;
    for (k, row) in &t.entries {
        for (_mg, g) in &row.mod_groups {
            for f in &g.fields {
                if f.extraction == Extraction::NegAbs {
                    n += 1;
                }
            }
        }
    }
    assert_eq!(n, 0, "sm121a NegAbs post-254 inventory must stay zero");
    for arch in ["sm100a", "sm103a", "sm120"] {
        let t = tab(arch);
        for (k, row) in &t.entries {
            for (_mg, g) in &row.mod_groups {
                for f in &g.fields {
                    assert!(
                        f.extraction != Extraction::NegAbs,
                        "{arch} {k}: NegAbs must stay zero"
                    );
                }
            }
        }
    }
    // Sibling-gap inventories (registrations, not this fix): NegShl1 = 12
    // rows DFMA sm121a, NegF32 = 1 row UFADD sm121a.
    let shl: usize = t
        .entries
        .values()
        .flat_map(|r| r.mod_groups.values())
        .flat_map(|g| g.fields.iter())
        .filter(|f| f.extraction == Extraction::NegShl1)
        .count();
    assert_eq!(shl, 12, "NegShl1 inventory (253-kand)");
    let nf: usize = t
        .entries
        .values()
        .flat_map(|r| r.mod_groups.values())
        .flat_map(|g| g.fields.iter())
        .filter(|f| f.extraction == Extraction::NegF32)
        .count();
    assert_eq!(nf, 1, "NegF32 inventory (UFADD)");
}

#[test]
fn t251_2_decode_vendor_true() {
    let cases: &[(u128, &str)] = &[
        (W_BASE, "DSETP.GT.AND P0, PT, R50, R44, PT"),
        (W_TOK3_NEG, "DSETP.GT.AND P0, PT, -R50, R44, PT"),
        (W_TOK3_ABS, "DSETP.GT.AND P0, PT, |R50|, R44, PT"),
        (W_TOK3_BOTH, "DSETP.GT.AND P0, PT, -|R50|, R44, PT"),
        (W_TOK4_ABS, "DSETP.GT.AND P0, PT, R50, |R44|, PT"),
        (W_TOK4_NEG, "DSETP.GT.AND P0, PT, R50, -R44, PT"),
        (W_TOK4_BOTH, "DSETP.GT.AND P0, PT, R50, -|R44|, PT"),
    ];
    for arch in ["sm100a", "sm103a", "sm120", "sm121a"] {
        let t = tab(arch);
        for (i, (w, want)) in cases.iter().enumerate() {
            let got = dec(&t, *w).unwrap_or_else(|| panic!("{arch} case{i} HOLE"));
            assert_eq!(got, *want, "{arch} case{i} decode != vendor (arb251)");
        }
    }
}

#[test]
fn t251_3_encode_payload_exact() {
    let t = tab("sm121a");
    let cases: &[(&str, u128)] = &[
        ("DSETP.GT.AND P0, PT, R50, R44, PT", W_BASE),
        ("DSETP.GT.AND P0, PT, -R50, R44, PT", W_TOK3_NEG),
        ("DSETP.GT.AND P0, PT, |R50|, R44, PT", W_TOK3_ABS),
        ("DSETP.GT.AND P0, PT, -|R50|, R44, PT", W_TOK3_BOTH),
        ("DSETP.GT.AND P0, PT, R50, -|R44|, PT", W_TOK4_BOTH),
    ];
    for (i, (text, w)) in cases.iter().enumerate() {
        let got = enc(&t, text);
        assert_eq!(got & M96, w & M96, "case{i} encode payload drift");
    }
}

#[test]
fn t251_4_roundtrip() {
    for arch in ["sm100a", "sm103a", "sm120", "sm121a"] {
        let t = tab(arch);
        for (i, w) in [
            W_BASE,
            W_TOK3_NEG,
            W_TOK3_ABS,
            W_TOK3_BOTH,
            W_TOK4_ABS,
            W_TOK4_NEG,
            W_TOK4_BOTH,
        ]
        .iter()
        .enumerate()
        {
            let txt = dec(&t, *w).unwrap_or_else(|| panic!("{arch} w{i} decode"));
            let back = enc(&t, &txt);
            assert_eq!(back & M96, w & M96, "{arch} w{i} roundtrip drift: {txt}");
        }
    }
}

#[test]
fn t251_5_sentinel_negshl1_flipped() {
    // BUG-253 landed (this pin flipped at F2-iter129): the NegShl1 arm now
    // matches the printer, so sm121a DFMA rows print the vendor sign glyphs
    // (arb251b/arb253 models identical). Full 253 witness set (both-set,
    // corpus words, encode inverse, 256-reuse sentinel) lives in
    // tests/bug253_negshl1.rs.
    let t = tab("sm121a");
    let d = tab("sm100a");
    assert_eq!(
        dec(&d, W_DF_TOK3_NEG).as_deref(),
        Some("DFMA R32, R32, -R64, R28"),
        "donor leg lost DFMA tok3 neg (generic arm regress?)"
    );
    assert_eq!(
        dec(&t, W_DF_TOK3_NEG).as_deref(),
        Some("DFMA R32, R32, -R64, R28"),
        "sm121a tok3 neg must print (BUG-253 arm)"
    );
    assert_eq!(
        dec(&t, W_DF_TOK4_NEG).as_deref(),
        Some("DFMA R32, R32, R64, -R28"),
        "sm121a tok4 neg must print (BUG-253 arm)"
    );
}

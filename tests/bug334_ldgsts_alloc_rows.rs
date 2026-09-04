//! BUG-334 (F2-iter179, loop5/blind front2, 2026-09-01): sm100a/sm103a
//! LDGSTS desc L1-allocate '128,E' closure + sm100a donor imm2 width flip
//! (canonical bfc8480; ENGINE untouched).
//!
//! PRE (publish 737a74a, canonical 1c415e8; work/bug334/measure_pre334.json):
//!   D1: era L1-alloc word F = 0x000000000b9a180e0000000016038fae decoded
//!       HOLE on sm100a/sm103a (vendor prints it on x4).
//!   D2: authored 'LDGSTS.E.128 [R3], desc[UR14][R22.64]' SUPERSET-ROUTED to
//!       a BYPASS+LTC128B mint (word b73=1 b81=0) = silent wrong-code.
//!   D2b: sm100a encode of desc offsets >0xfff SILENTLY DROPPED the offset
//!       (21b@32 era field); sm103a/sm120 encode-lint LOUD FAIL (12b law).
//!   D3: sm100a donor mgs decode dst-imm bits [52:44]/' [50:44] as desc-imm
//!       ghost prints (A|b44 'desc...+0x1000' vs vendor dst-side).
//! FIX: (A) sm100a donor imm2 21/19->12b@32 on 5 mgs (i84-180 port, _src
//!   bug334); (B) '128,E' mg on LDGSTS_ARI_dARI{,_P} x2 legs cloned with
//!   ab|b81 / (ab&~b73)|b81 from the (fixed) donors.
//! CORPUS (census334, 2,406 cubins / 10,951 LDGSTS desc slots): alloc .128
//!   shape ZERO; donor ghost windows ZERO on both windows -> zero delta.
//! LAW (arb334 46 probes nvdisasm 13.3.73 raw -b, x4 models agree on every
//!   probe; + arb311 91 probes): b81 = L1-alloc<->BYPASS pair-wise toggle,
//!   dst imm 20b@44 owns [52:44], desc imm 12b@32 SIGNED, b82 ZFILL and
//!   b73 LTC alloc crosses vendor-legal but NOT grafted (359-kand; loud
//!   refuse parity with sm120 kept).

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::IsaTable;

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
fn t334_1_structure_claims_and_donor_parity() {
    for leg in ["sm100a", "sm103a"] {
        let t = tab(leg);
        let get = |key: &str, mg: &str| {
            t.entries
                .get(key)
                .and_then(|e| e.mod_groups.get(mg))
                .unwrap_or_else(|| panic!("{leg} {key}::{mg} missing"))
        };
        // B: cloned rows exist, ab delta exactly b81 / (b73 cleared,b81 set)
        let d = get("LDGSTS_ARI_dARI", "128,BYPASS,E");
        let n = get("LDGSTS_ARI_dARI", "128,E");
        assert_eq!((n.and_base ^ d.and_base) & M96, 1u128 << 81, "{leg} dARI");
        let dp = get("LDGSTS_ARI_dARI_P", "128,BYPASS,E,LTC128B");
        let np = get("LDGSTS_ARI_dARI_P", "128,E");
        assert_eq!(
            (np.and_base ^ dp.and_base) & M96,
            (1u128 << 81) | (1u128 << 73),
            "{leg} dARI_P"
        );
        let shape = |g: &cubit::table::ModGroupEntry| {
            g.fields
                .iter()
                .map(|f| (f.shift, f.bits, f.token_idx))
                .collect::<Vec<_>>()
        };
        assert_eq!(shape(n), shape(d), "{leg} clone fields == donor fields");
        assert_eq!(shape(np), shape(dp), "{leg} P clone fields == P donor");
        // clone + donor sub_imm2 = 12b@32 (i84-180 port law); vm/fields do
        // not touch discriminants b81/b73
        for g in [d, n, dp, np] {
            let f = g
                .fields
                .iter()
                .find(|f| matches!(f.extraction, cubit::table::Extraction::SubImm(2)))
                .unwrap();
            assert_eq!((f.bits, f.shift), (12, 32), "{leg} imm2 12b law");
            assert_eq!(g.variable_mask & ((1u128 << 81) | (1u128 << 73)), 0);
        }
        // FLIPPED by BUG-359 (2026-09-03): the ZFILL/LTC alloc crosses are
        // grafted on this leg pre-359-era assertion retired; pins for the
        // grafted rows live in tests/bug359_ldgsts_alloc_crosses.rs.
        let zfill = t.entries["LDGSTS_ARI_dARI"]
            .mod_groups
            .contains_key("128,E,ZFILL")
            || t.entries["LDGSTS_ARI_dARI_P"]
                .mod_groups
                .contains_key("128,E,ZFILL");
        assert!(zfill, "{leg}: ZFILL cross rows grafted by BUG-359");
    }
    // donor byte-parity across the two grafted legs (post-flip)
    let a = tab("sm100a");
    let b = tab("sm103a");
    for (key, mg) in [
        ("LDGSTS_ARI_dARI", "128,BYPASS,E"),
        ("LDGSTS_ARI_dARI", "128,BYPASS,E,LTC128B"),
        ("LDGSTS_ARI_dARI_P", "128,BYPASS,E,LTC128B,ZFILL"),
    ] {
        let fa = &a.entries[key].mod_groups[mg].fields;
        let fb = &b.entries[key].mod_groups[mg].fields;
        let strip = |fl: &Vec<cubit::table::Field>| {
            fl.iter()
                .map(|f| (f.shift, f.bits, f.token_idx, format!("{:?}", f.extraction)))
                .collect::<Vec<_>>()
        };
        assert_eq!(strip(fa), strip(fb), "{key}::{mg} cross-leg parity");
    }
    // sm120 unchanged (311 graft is the reference implementation)
    let t = tab("sm120");
    let n = &t.entries["LDGSTS_ARI_dARI"].mod_groups["128,E"];
    assert_eq!(
        n.and_base & M96,
        0x000000000b9a18000000000000000faeu128,
        "sm120 reference untouched"
    );
}

#[test]
fn t334_2_decode_law_and_ghost_closure() {
    // era L1-alloc witness decodes on all four legs, vendor text
    let f: u128 = 0x000000000b9a180e0000000016038fae;
    for leg in ["sm100a", "sm103a", "sm120", "sm121a"] {
        let t = tab(leg);
        let s = dec(&t, f).unwrap_or_else(|| panic!("{leg}: F hole"));
        assert!(
            s.contains("LDGSTS.E.128 [R3], desc[UR14][R22.64]"),
            "{leg}: {s}"
        );
    }
    // guard variants (arb334 P-set): unguarded elision + @P0 + @!P0
    let ung: u128 = 0x000000000b9a180e0000000016037fae;
    let p0: u128 = 0x000000000b9a180e0000000016030fae;
    for leg in ["sm100a", "sm103a"] {
        let t = tab(leg);
        assert_eq!(
            dec(&t, ung).unwrap(),
            "LDGSTS.E.128 [R3], desc[UR14][R22.64]"
        );
        assert_eq!(
            dec(&t, p0).unwrap(),
            "@P0 LDGSTS.E.128 [R3], desc[UR14][R22.64]"
        );
    }
    // A: sm100a donor flip = ghost closure on the BYPASS donors (bits
    // [52:44] print dst-side, vendor law; pre-fix ghosted desc-side).
    let a: u128 = 0x0007e2000b98181206000000181b7fae;
    let b: u128 = 0x0003e20008981a0e018800801c5a7fae;
    let t100 = tab("sm100a");
    let t103 = tab("sm103a");
    assert_eq!(
        dec(&t100, a | (1u128 << 44)).unwrap(),
        "LDGSTS.E.BYPASS.128 [R27+0x6001], desc[UR18][R24.64]"
    );
    assert_eq!(
        dec(&t100, b | (1u128 << 44)).unwrap(),
        "LDGSTS.E.BYPASS.LTC128B.128 [R90+0x1881], desc[UR14][R28.64+0x80], P1"
    );
    assert_eq!(
        dec(&t100, b | (1u128 << 50)).unwrap(),
        "LDGSTS.E.BYPASS.LTC128B.128 [R90+0x18c0], desc[UR14][R28.64+0x80], P1"
    );
    // signed 12b desc-imm print closure on sm100a (i84-180 port): corpus
    // slots 'desc.. +0x800/+0xff4' re-print as vendor '+-0x800'/'+-0xc'
    // (attr334_deltas 28/28 vendor==NEW, x4 models; pre-fix printed raw).
    let c800: u128 = 0x0003e6000b98180802000800342f7fae;
    assert_eq!(
        dec(&t100, c800).unwrap(),
        "LDGSTS.E.BYPASS.128 [R47+0x2000], desc[UR8][R52.64+-0x800]"
    );
    // sm103a was already right; stays byte-equal
    assert_eq!(
        dec(&t103, b | (1u128 << 44)).unwrap(),
        dec(&t100, b | (1u128 << 44)).unwrap()
    );
}

#[test]
fn t334_3_authored_mint_bytepins() {
    // authored alloc texts mint the vendor-law words on both grafted legs;
    // pins are the post-311 sm120 reference mints (nvdisasm-verified, see
    // work/bug334/ref120_mints.json).
    let cases: &[(&str, u128)] = &[
        (
            "LDGSTS.E.128 [R3], desc[UR14][R22.64]",
            0x0b9a180e0000000016037fae,
        ),
        (
            "@P0 LDGSTS.E.128 [R3], desc[UR14][R22.64]",
            0x0b9a180e0000000016030fae,
        ),
        (
            "@!P0 LDGSTS.E.128 [R3], desc[UR14][R22.64]",
            0x0b9a180e0000000016038fae,
        ),
        (
            "LDGSTS.E.128 [R3], desc[UR14][R22.64], P1",
            0x089a180e0000000016037fae,
        ),
        (
            "LDGSTS.E.128 [R3], desc[UR14][R22.64], P6",
            0x0b1a180e0000000016037fae,
        ),
        (
            "@P2 LDGSTS.E.128 [R9], desc[UR4][R30.64+0x7ff], P3",
            0x099a1804000007ff1e092fae,
        ),
        (
            "LDGSTS.E.128 [R3], desc[UR14][R22.64+-0xc]",
            0x0b9a180e00000ff416037fae,
        ),
        (
            "LDGSTS.E.128 [R3+0x1ff], desc[UR14][R22.64]",
            0x0b9a180e001ff00016037fae,
        ),
    ];
    for leg in ["sm100a", "sm103a"] {
        let t = tab(leg);
        for (text, want) in cases {
            let got = enc(&t, text).unwrap_or_else(|e| panic!("{leg} {text}: {e}"));
            assert_eq!(got & M96, want & M96, "{leg} {text}");
            // roundtrip byte-exact
            let s = dec(&t, got).unwrap();
            let re = enc(&t, &s).unwrap();
            assert_eq!(re & M96, got & M96, "{leg} roundtrip {s}");
        }
    }
}

#[test]
fn t334_4_fail_closed_residuum_and_sm100a_encode_lint() {
    for leg in ["sm100a", "sm103a", "sm120"] {
        let t = tab(leg);
        // FLIPPED by BUG-359 (2026-09-03): ZFILL/LTC alloc crosses grafted
        // (arb334+arb359 law, 134 probes x4 agree). The mints below are now
        // LEGAL and pinned word-exact in tests/bug359_ldgsts_alloc_crosses.rs;
        // verbatim-mint smoke kept here as a regression tripwire.
        assert!(
            enc(&t, "LDGSTS.E.128.ZFILL [R3], desc[UR14][R22.64]").is_ok(),
            "{leg}: ZFILL mint grafted by BUG-359"
        );
        let v = enc(&t, "LDGSTS.E.LTC128B.128 [R3], desc[UR14][R22.64], P1");
        assert!(v.is_ok(), "{leg}: LTC128B alloc mint grafted by BUG-359");
        // desc offset beyond signed-12 -> encode-lint LOUD (was: silent drop
        // on sm100a pre-flip) -- orthogonal to 359, kept.
        let v = enc(&t, "LDGSTS.E.BYPASS.128 [R3], desc[UR14][R22.64+0x1000]");
        assert!(v.is_err(), "{leg}: desc overflow must be encode-lint loud");
        // b73=1 alloc word now claims the grafted row (359); assert the
        // vendor-exact text instead of the retired hole.
        let w: u128 = 0x0003e200089a1a0e018800801c5a7fae; // B ^ b81
        let d = dec(&t, w).unwrap_or_else(|| panic!("{leg}: alloc+LTC _P must decode post-359"));
        assert_eq!(
            d, "LDGSTS.E.LTC128B.128 [R90+0x1880], desc[UR14][R28.64+0x80], P1",
            "{leg}: post-359 decode must equal vendor text"
        );
    }
}

#[test]
fn t334_5_corpus_samples_byte_stable() {
    // census334 attribution: the donor flip is invisible on real corpus words
    // (ghost windows empty); a fixed sample of battery BYPASS.128 words keeps
    // byte-identical decode on sm100a and sm103a (strings as printed by
    // nvdisasm, census334b_slots.json).
    let t100 = tab("sm100a");
    let t103 = tab("sm103a");
    let cases: &[(u128, &str)] = &[
        (
            0x0007e2000b98181206000000181b7fae,
            "LDGSTS.E.BYPASS.128 [R27+0x6000], desc[UR18][R24.64]",
        ),
        (
            0x0003e20008981a0e018800801c5a7fae,
            "LDGSTS.E.BYPASS.LTC128B.128 [R90+0x1880], desc[UR14][R28.64+0x80], P1",
        ),
    ];
    for (w, want) in cases {
        assert_eq!(dec(&t100, *w).unwrap(), *want, "100a corp sample");
        assert_eq!(dec(&t103, *w).unwrap(), *want, "103a corp sample");
    }
}

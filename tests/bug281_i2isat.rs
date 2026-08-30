//! BUG-281 (F2-iter147, loop5/blind front2, 2026-08-30): 2-op
//! I2I.U8.S32.SAT family closure on the 0x238 lattice, legs sm120+sm121a.
//! Registered LOW at F2-iter140 (276 report sec.6): generic predicated
//! form = engine HOLE; P0/P2/P5 era-clones shadowed by '' under
//! guard-masked matching. Measurement-first (work/bug281):
//! measure_pre281 (pub pyo3-72eaa3e), arb281/arb281p (516 probes,
//! nvdisasm 13.3.73 raw -b, x4 models SM120/121a/100a/103a agree on
//! EVERY probe), routex281 FULL 2,406-cubin battery.
//!
//! LAW (x4 models): lattice = 2-op I2I.U8.S32.SAT; opcode care {3,4,5,9};
//! guard 4b@[15:12] (3b pred + inv@15; g=7 -> PT bare; '@!PT' legal);
//! dest 8b@16, src 8b@32. TEXT-INERT: [31:24], [75:40], [90:78],
//! [95:92] singles + (62,63)/(80,81) + guard*payload compositions.
//! NOT-INERT: b76='.S8'/b77='.U16' variant ops (no rows today -> stay
//! care = hole; registered), b91 = vendor KILL (rc=1 x4, stays hole).
//!
//! PRE-FIX (measured pub pyo3-72eaa3e, arb281 E exhibits): SILENT
//! WRONG-CODE on encode -- the era '' row carried dest@17/src@33
//! (off-by-one) + and_base bit32-bake: 'I2I.U8.S32.SAT R14, R38'
//! encoded a word nvdisasm reads 'R28, R77' (x4); '@P2/R7,R19' ->
//! '@P2 R14, R39'; even 'R0, R0' -> vendor 'R0, R1'. Decode-side:
//! vendor's own base 0x7238 = HOLE (bit32 care-1), whole guard
//! spectrum HOLE; P0-clone base 0x200 leaks '_P0' literal text.
//! GRAFT (patch281.py, both legs): '' row surgery (and_base
//! 0x100007238 -> 0x238; fields=[guard 4b@12, reg 8b@16, reg 8b@32];
//! vm=0xf7ffcffffffffffffffff000 covering guard/dest/src + measured
//! inert bands, b76/77/91 stay care) + DELETE era clones
//! I2I.U8.S32.SAT{,_P0,_P2,_P5}_R_R (P0 base vendor-ILLEGAL x4;
//! P2/P5 shadowed mis-fielded clones; doctrine 265/276). Engine ZERO.
//! DONORS sm100a/sm103a byte-untouched.
//! Roundtrip note: text-stable; word-lossy ONLY on vendor-undefined
//! inert-bit patterns (re-encoded canonical form clears them).
use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::IsaTable;

const M96: u128 = (1u128 << 96) - 1;
const NEW_VM: u128 = 0xf7ffcffffffffffffffff000u128;
const DEL: [&str; 3] = [
    "I2I.U8.S32.SAT_P0_R_R",
    "I2I.U8.S32.SAT_P2_R_R",
    "I2I.U8.S32.SAT_P5_R_R",
];
fn tab(arch: &str) -> IsaTable {
    IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap()
}
fn dec(t: &IsaTable, w: u128) -> Option<String> {
    let idx = DecodeIndex::build(t);
    idx.decode(w & M96, 0, t).map(|d| to_sass(&d)).ok()
}
fn enc_res(t: &IsaTable, text: &str) -> Result<u128, String> {
    let insn = parse_sass(&format!("{text};"), 0).map_err(|e| format!("parse: {e}"))?;
    encode_instruction(&insn, t).map_err(|e| format!("encode: {e}"))
}

#[test]
fn t281_1_structure_surgery_and_donors() {
    for leg in ["sm120", "sm121a"] {
        let t = tab(leg);
        for k in DEL {
            assert!(
                !t.entries.contains_key(k),
                "{leg}: era clone {k} not deleted"
            );
        }
        let e = t
            .entries
            .get("I2I.U8.S32.SAT_R_R")
            .unwrap_or_else(|| panic!("{leg}: family key missing"));
        assert_eq!(e.mod_groups.len(), 1, "{leg}: family must be mg '' only");
        let g = &e.mod_groups[""];
        assert_eq!(g.and_base, 0x238u128, "{leg}: and_base drift (281)");
        assert_eq!(g.variable_mask, NEW_VM, "{leg}: vmask drift (281)");
        assert_eq!(
            (g.variable_mask >> 76) & 3,
            0,
            "{leg}: variant bits b76/77 in vmask"
        );
        assert_eq!(
            (g.variable_mask >> 91) & 1,
            0,
            "{leg}: kill-bit b91 in vmask"
        );
        // field program: guard + dest 8b@16 + src 8b@32, nothing else
        assert_eq!(g.fields.len(), 3, "{leg}: field count drift");
        assert!(
            g.fields.iter().any(|f| f.token_idx == 0
                && f.bits == 4
                && f.shift == 12
                && matches!(f.extraction, cubit::table::Extraction::Guard)),
            "{leg}: guard field missing"
        );
        assert!(
            g.fields.iter().any(|f| f.token_idx == 1
                && f.bits == 8
                && f.shift == 16
                && matches!(f.extraction, cubit::table::Extraction::Reg)),
            "{leg}: dest field missing"
        );
        assert!(
            g.fields.iter().any(|f| f.token_idx == 2
                && f.bits == 8
                && f.shift == 32
                && matches!(f.extraction, cubit::table::Extraction::Reg)),
            "{leg}: src field missing"
        );
    }
    for leg in ["sm100a", "sm103a"] {
        let t = tab(leg);
        assert!(
            !t.entries.keys().any(|k| k.starts_with("I2I.U8.S32")),
            "{leg}: donor carries the family"
        );
    }
}

#[test]
fn t281_2_decode_laws_vendor_equal() {
    let base = 0x7238u128; // guard PT baked: bare text
    let wr = base | (5 << 16) | (38 << 32); // 'I2I.U8.S32.SAT R5, R38'
    for leg in ["sm120", "sm121a"] {
        let t = tab(leg);
        // vendor base words (pre-fix HOLES): PT + R0,R0 + payload
        assert_eq!(
            dec(&t, base).as_deref(),
            Some("I2I.U8.S32.SAT R0, R0"),
            "{leg}: PT base drift"
        );
        assert_eq!(
            dec(&t, wr).as_deref(),
            Some("I2I.U8.S32.SAT R5, R38"),
            "{leg}: payload drift"
        );
        // full guard spectrum incl. invert (arb281 A, x4 models)
        for g in 0..7u128 {
            let want_p = format!("@P{g} I2I.U8.S32.SAT R5, R38");
            assert_eq!(
                dec(&t, wr & !(0xF << 12) | (g << 12)).as_deref(),
                Some(want_p.as_str()),
                "{leg}: guard g{g} drift"
            );
            let want_n = format!("@!P{g} I2I.U8.S32.SAT R5, R38");
            assert_eq!(
                dec(&t, wr & !(0xF << 12) | (g << 12) | (1 << 15)).as_deref(),
                Some(want_n.as_str()),
                "{leg}: inv guard g{g} drift"
            );
        }
        assert_eq!(
            dec(&t, wr | (1 << 15)).as_deref(),
            Some("@!PT I2I.U8.S32.SAT R5, R38"),
            "{leg}: @!PT drift"
        );
        // arb276 E witness + payload extents (R128 boundaries)
        assert_eq!(
            dec(&t, 0x26000e5238u128).as_deref(),
            Some("@P5 I2I.U8.S32.SAT R14, R38"),
            "{leg}: arb276 E witness drift"
        );
        assert_eq!(
            dec(&t, base & !(0xF << 12) | (1 << 23)).as_deref(),
            Some("@P0 I2I.U8.S32.SAT R128, R0"),
            "{leg}: dest b23 boundary drift"
        );
        assert_eq!(
            dec(&t, base & !(0xF << 12) | (1 << 39)).as_deref(),
            Some("@P0 I2I.U8.S32.SAT R0, R128"),
            "{leg}: src b39 boundary drift"
        );
        // inert bands: text identical under same guard
        for (tag, bits) in [
            ("mid[31:24]=FF", 0xFFu128 << 24),
            ("(62,63)=3", 0x3u128 << 62),
            ("b72", 1u128 << 72),
            ("b74", 1u128 << 74),
            ("(80,81)=3", 0x3u128 << 80),
            ("b95", 1u128 << 95),
            ("b40", 1u128 << 40),
        ] {
            assert_eq!(
                dec(&t, wr | bits).as_deref(),
                dec(&t, wr).as_deref(),
                "{leg}: inert {tag} not text-stable"
            );
        }
        // era deletee bases: P2/P5 decode vendor-exact via ''; P0 base (0x200)
        // is vendor-ILLEGAL x4 and must HOLE
        assert_eq!(
            dec(&t, 0x100002238u128).as_deref(),
            Some("@P2 I2I.U8.S32.SAT R0, R1"),
            "{leg}: former P2-row base not vendor-equal"
        );
        assert_eq!(
            dec(&t, 0x100005238u128).as_deref(),
            Some("@P5 I2I.U8.S32.SAT R0, R1"),
            "{leg}: former P5-row base not vendor-equal"
        );
        assert!(
            dec(&t, 0x200).is_none(),
            "{leg}: vendor-illegal 0x200 decodes"
        );
    }
}

#[test]
fn t281_3_holes_killbit_variants_stay() {
    // FLIP (BUG-294/295, F2-iter149): b76/b77/b76+b77 variant entries were
    // removed from this hole list -- they now decode via the armed
    // .S8/.U16/.S16 rows (vendor-equal, pinned in t294_2); per-variant
    // b91-kill holes are pinned in t294_3.
    let base = 0x7238u128 | (5 << 16) | (38 << 32);
    for leg in ["sm120", "sm121a"] {
        let t = tab(leg);
        for (tag, w) in [
            ("b91 kill", base | (1 << 91)),
            ("b91 kill guard", (base & !(0xF << 12)) | (1 << 91)),
            ("0x27a lattice (276 closed)", 0x27a),
            ("zero word", 0u128),
        ] {
            assert!(dec(&t, w).is_none(), "{leg}: {tag} silently decoded (281)");
        }
    }
}

#[test]
fn t281_4_encode_vendor_exact_and_roundtrip() {
    for leg in ["sm120", "sm121a"] {
        let t = tab(leg);
        let cases: [(&str, u128); 9] = [
            ("I2I.U8.S32.SAT R0, R0", 0x7238),
            ("I2I.U8.S32.SAT R0, R1", 0x7238 | (1 << 32)),
            ("I2I.U8.S32.SAT R5, R38", 0x7238 | (5 << 16) | (38 << 32)),
            ("I2I.U8.S32.SAT R14, R38", 0x7238 | (14 << 16) | (38 << 32)),
            ("@P0 I2I.U8.S32.SAT R0, R0", 0x238),
            (
                "@P2 I2I.U8.S32.SAT R7, R19",
                0x238 | (2 << 12) | (7 << 16) | (19 << 32),
            ),
            (
                "@!P2 I2I.U8.S32.SAT R7, R19",
                0x238 | (2 << 12) | (1 << 15) | (7 << 16) | (19 << 32),
            ),
            (
                "@P6 I2I.U8.S32.SAT R5, R38",
                0x238 | (6 << 12) | (5 << 16) | (38 << 32),
            ),
            ("@!PT I2I.U8.S32.SAT R0, R0", 0x7238 | (1 << 15)),
        ];
        for (text, want) in cases {
            let w = enc_res(&t, text).unwrap_or_else(|e| panic!("{leg}: enc '{text}': {e}"));
            assert_eq!(w & M96, want, "{leg}: enc '{text}' word drift");
            assert_eq!(
                dec(&t, w & M96).as_deref(),
                Some(text),
                "{leg}: decode(encode('{text}')) roundtrip drift"
            );
        }
        // PT-elision on decode of explicit PT word
        assert_eq!(
            dec(&t, 0x7238 | (5 << 16)).as_deref(),
            Some("I2I.U8.S32.SAT R5, R0"),
            "{leg}: PT-elided decode drift"
        );
    }
}

#[test]
fn t281_5_fail_closed_and_roundtrip_semantics() {
    for leg in ["sm120", "sm121a"] {
        let t = tab(leg);
        for (tag, text) in [
            // era text-leak form: the dead '_P0' key text must not encode
            ("era _P0 leak", "@P0 I2I.U8.S32.SAT_P0 R0, R0"),
            // 272-gate: unknown operand suffix on bare regs
            ("272 garbage suffix", "I2I.U8.S32.SAT R0.GARBAGE, R1"),
            ("272 invalid suffix", "I2I.U8.S32.SAT R5, R38.INVALID2"),
            // wrong operand classes / arity
            ("UR operand", "I2I.U8.S32.SAT R0, UR1"),
            ("3-op shape", "I2I.U8.S32.SAT R0, R1, R2"),
            ("reg out of range", "I2I.U8.S32.SAT R0, R256"),
            // unknown guard
            ("P7 guard", "@P7 I2I.U8.S32.SAT R0, R0"),
            // (variant-op entries "S8 variant"/"U16 variant" FLIPPED OUT by
            // BUG-294/295: they now encode vendor-exact, pinned t294_4;
            // their fail-closed sign/suffix/shape semantics moved to t294_5)
            // 281 fail-closed arm: signs are vendor text-inert on this
            // lattice (arb281 x4) -- no encoding exists, refuse the drop
            ("neg src sign-drop", "I2I.U8.S32.SAT R5, -R38"),
            ("abs src sign-drop", "I2I.U8.S32.SAT R5, |R38|"),
            ("neg dest sign-drop", "I2I.U8.S32.SAT -R5, R38"),
            ("guard+neg", "@P2 I2I.U8.S32.SAT R5, -R38"),
        ] {
            assert!(
                enc_res(&t, text).is_err(),
                "{leg}: {tag} '{text}' silently encodes (281)"
            );
        }
        // text-stable / word-lossy-only-on-inert: decode of an inert-dirtied
        // word re-encodes to the canonical inert-cleared word
        let dirty = 0x26000e5238u128 | (0xAB << 24) | (1 << 40) | (1 << 90);
        let text = dec(&t, dirty).expect("dirty word must decode");
        assert_eq!(
            text, "@P5 I2I.U8.S32.SAT R14, R38",
            "{leg}: dirty text drift"
        );
        let canon = enc_res(&t, &text).expect("re-encode");
        assert_eq!(canon & M96, 0x26000e5238u128, "{leg}: canonical form drift");
        assert_ne!(canon & M96, dirty, "{leg}: inert bits must not roundtrip");
    }
}

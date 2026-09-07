//! BUG-394 AUDIT pin-pack (deferred rider with the BUG-392 commit;
//! practice 379/380: audit pins ride with the next fix commit).
//! Machine witnesses from work/bug394/pin_wit394.json (built by
//! gen394pins.py from measure_pre394.json; vendor law = nvdisasm
//! 13.3.73 raw -b x4 models AGREE, measured at F2-iter212 on publish
//! cubit_py-964a321f / canonical 2285a05).

use cubit::decoder::DecodeIndex;
use cubit::printer::to_sass;
use cubit::table::IsaTable;

const M96: u128 = (1u128 << 96) - 1;
const LEGS4: [&str; 4] = ["sm100a", "sm103a", "sm120", "sm121a"];

fn tab(arch: &str) -> IsaTable {
    IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap()
}
fn dec96(t: &IsaTable, w: u128) -> Option<String> {
    let idx = DecodeIndex::build(t);
    idx.decode(w & M96, 0, t).map(|d| to_sass(&d)).ok()
}

const T394_1: [(usize, u128, &str); 8] = [
    (
        0,
        0x00040802200000011c024231,
        "@P4 HFMA2 R2, R28.H0_H0, R1.H0_H0, R2.H0_H0",
    ),
    (
        1,
        0x00040802200000011c024231,
        "@P4 HFMA2 R2, R28.H0_H0, R1.H0_H0, R2.H0_H0",
    ),
    (
        2,
        0x00040802200000011c024231,
        "@P4 HFMA2 R2, R28.H0_H0, R1.H0_H0, R2.H0_H0",
    ),
    (
        3,
        0x00040802200000011c024231,
        "@P4 HFMA2 R2, R28.H0_H0, R1.H0_H0, R2.H0_H0",
    ),
    (
        0,
        0x002408002000000000000231,
        "@P0 HFMA2.BF16_V2 R0, R0.H0_H0, R0.H0_H0, R0.H0_H0",
    ),
    (
        1,
        0x002408002000000000000231,
        "@P0 HFMA2.BF16_V2 R0, R0.H0_H0, R0.H0_H0, R0.H0_H0",
    ),
    (
        2,
        0x002408002000000000000231,
        "@P0 HFMA2.BF16_V2 R0, R0.H0_H0, R0.H0_H0, R0.H0_H0",
    ),
    (
        3,
        0x002408002000000000000231,
        "@P0 HFMA2.BF16_V2 R0, R0.H0_H0, R0.H0_H0, R0.H0_H0",
    ),
];

const T394_2: [(u128, &str, bool, &str); 18] = [
    (
        0x00040802200001011c024231,
        "@P4 HFMA2 R2, R28.H0_H0, R1.H0_H0, R2.H0_H0",
        true,
        "flip40",
    ),
    (
        0x00040802200080011c024231,
        "@P4 HFMA2 R2, R28.H0_H0, R1.H0_H0, R2.H0_H0",
        true,
        "flip47",
    ),
    (
        0x00040802208000011c024231,
        "@P4 HFMA2 R2, R28.H0_H0, R1.H0_H0, R2.H0_H0",
        true,
        "flip55",
    ),
    (
        0x00040802210000011c024231,
        "@P4 HFMA2 R2, R28.H0_H0, R1.H0_H0, R2.H0_H0",
        false,
        "flip56",
    ),
    (
        0x00040802280000011c024231,
        "@P4 HFMA2 R2, R28.H0_H0, R1.H0_H0, R2.H0_H0",
        false,
        "flip59",
    ),
    (
        0x00840802200000011c024231,
        "@P4 HFMA2 R2, R28.H0_H0, R1.H0_H0, R2.H0_H0",
        false,
        "flip87",
    ),
    (
        0x04040802200000011c024231,
        "@P4 HFMA2 R2, R28.H0_H0, R1.H0_H0, R2.H0_H0",
        false,
        "flip90",
    ),
    (
        0x10040802200000011c024231,
        "@P4 HFMA2 R2, R28.H0_H0, R1.H0_H0, R2.H0_H0",
        false,
        "flip92",
    ),
    (
        0x80040802200000011c024231,
        "@P4 HFMA2 R2, R28.H0_H0, R1.H0_H0, R2.H0_H0",
        false,
        "flip95",
    ),
    (
        0x002408002000010000000231,
        "@P0 HFMA2.BF16_V2 R0, R0.H0_H0, R0.H0_H0, R0.H0_H0",
        true,
        "flip40",
    ),
    (
        0x002408002000800000000231,
        "@P0 HFMA2.BF16_V2 R0, R0.H0_H0, R0.H0_H0, R0.H0_H0",
        true,
        "flip47",
    ),
    (
        0x002408002080000000000231,
        "@P0 HFMA2.BF16_V2 R0, R0.H0_H0, R0.H0_H0, R0.H0_H0",
        true,
        "flip55",
    ),
    (
        0x002408002100000000000231,
        "@P0 HFMA2.BF16_V2 R0, R0.H0_H0, R0.H0_H0, R0.H0_H0",
        false,
        "flip56",
    ),
    (
        0x002408002800000000000231,
        "@P0 HFMA2.BF16_V2 R0, R0.H0_H0, R0.H0_H0, R0.H0_H0",
        false,
        "flip59",
    ),
    (
        0x00a408002000000000000231,
        "@P0 HFMA2.BF16_V2 R0, R0.H0_H0, R0.H0_H0, R0.H0_H0",
        false,
        "flip87",
    ),
    (
        0x042408002000000000000231,
        "@P0 HFMA2.BF16_V2 R0, R0.H0_H0, R0.H0_H0, R0.H0_H0",
        false,
        "flip90",
    ),
    (
        0x102408002000000000000231,
        "@P0 HFMA2.BF16_V2 R0, R0.H0_H0, R0.H0_H0, R0.H0_H0",
        false,
        "flip92",
    ),
    (
        0x802408002000000000000231,
        "@P0 HFMA2.BF16_V2 R0, R0.H0_H0, R0.H0_H0, R0.H0_H0",
        false,
        "flip95",
    ),
];
const T394_3: [u128; 4] = [
    0x00440802200000011c024231,
    0x002448002000000000000231,
    0x006408002000000000000231,
    0x08040802200000011c024231,
];

/// t394_1: era base words decode vendor-exact on all x4 legs.
#[test]
fn t394_1_era_base_decode() {
    let tabs: Vec<IsaTable> = LEGS4.iter().map(|a| tab(a)).collect();
    for (li, w, ven) in T394_1 {
        let got = dec96(&tabs[li], w).expect("era base must decode");
        assert_eq!(
            got.trim_end_matches(';').trim(),
            ven,
            "leg {} word 0x{w:024x}",
            LEGS4[li]
        );
    }
}

/// t394_2: inert strays decode == vendor base text on ALL x4 legs.
///
/// FLIP (BUG-393 / F2-iter214, canonical 8f2571b): pre-393 posture was the
/// 285/289 fail-closed asymmetry measured in this audit (sparse HOLE on
/// every window; dense MATCH only on [55:40]). The measured vendor law
/// (measure_pre394 lattice + audit balls + the 144-tetrad closure sweep,
/// work/bug393/) makes all four windows inert on every leg, so the
/// fail-closed posture is superseded by lawful-accept parity. b91 kill +
/// INVALID markers stay HOLE (t394_3 stands).
#[test]
fn t394_2_inert_doctrine() {
    let tabs: Vec<IsaTable> = LEGS4.iter().map(|a| tab(a)).collect();
    for (w, ven, _pre_393_dense_match_only, tag) in T394_2 {
        for li in 0..4usize {
            let got = dec96(&tabs[li], w)
                .unwrap_or_else(|| panic!("leg {} post-393 inert must decode {tag}", LEGS4[li]));
            assert_eq!(
                got.trim_end_matches(';').trim(),
                ven,
                "leg {} {tag}",
                LEGS4[li]
            );
        }
    }
}

/// t394_3: INVALID marker words + b91 vendor-kill stay HOLE x4.
#[test]
fn t394_3_invalid_kill_hole() {
    let tabs: Vec<IsaTable> = LEGS4.iter().map(|a| tab(a)).collect();
    for (li, t) in tabs.iter().enumerate() {
        for w in T394_3 {
            assert!(
                dec96(t, w).is_none(),
                "leg {} word 0x{w:024x} must stay HOLE",
                LEGS4[li]
            );
        }
    }
}

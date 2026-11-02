//! BUG-477 (2026-10-29): `ATOMS.MAX.S32 Rd, [R+UR+imm], Rb` lost its uniform register and offset.
//!
//! The canonical `ATOMS_R_ARURI_R` / `MAX,S32` row was a harvest leftover: it read the address UR
//! byte [71:64] as a fourth register operand, declared no offset field and no guard, and its
//! variable mask excluded the offset bits - the same defect tools/re_sm120_memory_fields.py had
//! retired on `ATOMS_R_ARI_R_R`. The decoder still reached the row through its broad
//! memory-address fallback and printed `ATOMS.MAX.S32 RZ, [R157], R58` for the shipped word
//! 0x0001e200090002070151003a9dff798c (nvdisasm: `[R157+UR7+0x15100]`); the encoder then refused
//! the vendor text ("operand 2 (addr UR) has no field able to encode it"). 96 words of FlashInfer
//! 0.7.2's GLM-5.3 MG prefill kernel (sparse_mla_prefill_mg_kernel<ModelType 3>, sm_120 AOT cubin
//! of vLLM-Moet image r21) did not round-trip.
//!
//! Fix: the canonical row carries the measured fields (tools/re_sm120_atoms_aruri.py, nvdisasm
//! 13.1, 65 form words + 54 lattice words in tests/fixtures/sm120_atoms_aruri_nvdisasm.jsonl):
//! guard [15:12], Rd [23:16], base R [31:24] (255 = RZ -> `[UR+imm]`), Rb [39:32], signed offset
//! [63:40], UR [71:64]; opcode 0x98c + bit 91 = uniform-indexed address, [90:87] = 2 (MAX),
//! bit 73 = S32. The lattice (other operations, INVALID3/INVALID5 types, .X4/.X8 scale, text-inert
//! bits, the illegal opcode mixes) stays outside the row.
use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;
use std::sync::OnceLock;

const KEY: &str = "ATOMS_R_ARURI_R";
const GROUP: &str = "MAX,S32";

fn table_and_index() -> &'static (IsaTable, DecodeIndex) {
    static TABLE: OnceLock<(IsaTable, DecodeIndex)> = OnceLock::new();
    TABLE.get_or_init(|| {
        let path = std::env::var_os("CUBIT_TABLE").map(std::path::PathBuf::from)
            .unwrap_or_else(|| "tables/sm120.json".into());
        let table = IsaTable::load(&path).unwrap();
        let index = DecodeIndex::build(&table);
        (table, index)
    })
}

fn fixture() -> Vec<Value> {
    include_str!("fixtures/sm120_atoms_aruri_nvdisasm.jsonl").lines()
        .map(|l| serde_json::from_str(l).unwrap()).collect()
}

fn reencode(table: &IsaTable, word: u128, text: &str) -> u128 {
    let control = cubit::scheduling::format_control_code(
        &cubit::scheduling::decode_sched_upper32((word >> 96) as u32));
    let source = format!("[{control}] {text} ;");
    cubit::roundtrip_audit::check_semantic_source(&source).unwrap();
    let parsed = cubit::parse_cuasm_line(&source, 0).unwrap();
    assert!(parsed.hand_sched && parsed.rsd.is_none(), "{source}");
    cubit::encoder::encode_instruction(&parsed, table).unwrap_or_else(|e| panic!("{source}: {e}"))
}

/// Decode -> vendor text -> re-encode must reproduce every bit, through the measured row (an RZ base
/// prints as the `[UR+imm]` spelling, which the sibling `ATOMS_R_AURI_R` row may own).
fn check(word: u128, vendor: &str) {
    let (table, index) = table_and_index();
    let decoded = index.decode(word, 0, table).unwrap_or_else(|e| panic!("{word:032x}: {e}"));
    let rz_base = (word >> 24) & 0xff == 0xff;
    assert!(decoded.key == KEY || (rz_base && decoded.key == "ATOMS_R_AURI_R"), "{word:032x}: {}", decoded.key);
    assert_eq!(decoded.mod_group, GROUP, "{word:032x}");
    let own = cubit::printer::to_sass_lossless(&decoded);
    assert_eq!(own, vendor, "{word:032x}");
    assert_eq!(reencode(table, word, vendor), word, "{vendor}");
}

/// t477_1: the shipped MG-prefill words print the uniform register and the offset and reassemble.
#[test]
fn t477_1_shipped_words_print_ur_and_offset_and_reassemble() {
    for (word, vendor) in [
        (0x0001e200090002070151003a9dff798cu128, "ATOMS.MAX.S32 RZ, [R157+UR7+0x15100], R58"),
        (0x0003e200090002070151203c9dff798cu128, "ATOMS.MAX.S32 RZ, [R157+UR7+0x15120], R60"),
        (0x0005e20009000207015140349dff798cu128, "ATOMS.MAX.S32 RZ, [R157+UR7+0x15140], R52"),
    ] {
        check(word, vendor);
        let (table, index) = table_and_index();
        let decoded = index.decode(word, 0, table).unwrap();
        let value = |ext: &str| decoded.fields.iter().find(|f| f.extraction == ext).map(|f| f.value)
            .unwrap_or_else(|| panic!("{ext} field missing on {word:032x}"));
        assert_eq!(value("sub_ur1"), 7);
        assert_eq!(value("sub_imm2"), ((word >> 40) & 0xffffff) as u64);
        assert_eq!(value("sub_r0"), 157);
        assert_eq!(value("guard"), 7);
        assert!(decoded.fields.iter().all(|f| f.extraction != "reuse" && f.token_idx <= 3), "{word:032x}");
    }
}

/// t477_2: every nvdisasm form word (guard, Rd, RZ base, Rb, UR incl. URZ, signed offset) round-trips.
#[test]
fn t477_2_every_probed_form_word_matches_nvidia_and_reassembles_all_128_bits() {
    let mut n = 0;
    let (mut urz, mut rz_base, mut negative, mut guarded) = (0, 0, 0, 0);
    for row in fixture() {
        if row.get("lattice").is_some() {
            continue;
        }
        let vendor = row["nvidia_sass"].as_str().unwrap();
        assert!(vendor.contains("ATOMS.MAX.S32 "), "{vendor}");
        // the fixture words carry no control code; the shipped words have 0x0001e200
        let word = u128::from_str_radix(row["word"].as_str().unwrap(), 16).unwrap() | (0x0001_e200u128 << 96);
        check(word, vendor);
        urz += vendor.contains("URZ") as usize;
        rz_base += vendor.contains(", [UR") as usize;
        negative += vendor.contains("+-0x") as usize;
        guarded += vendor.starts_with('@') as usize;
        n += 1;
    }
    assert_eq!(n, 65);
    assert!(urz >= 1 && rz_base >= 2 && negative >= 2 && guarded >= 15, "{urz} {rz_base} {negative} {guarded}");
}

/// t477_3: the row claims nothing outside its measured neighbourhood (fail-closed): the other
/// operations, the INVALID types, the .X4/.X8 scale and the text-inert bits are never rendered
/// as this row, and the two illegal opcode mixes decode nowhere. (Several of those legal
/// neighbours are still absorbed by the harvest-era `ATOMS_R_ARI_R_R` OR / XOR and
/// `ATOMS_R_AURI_R` EXCH rows with wrong text - a standing defect of those rows, outside this
/// fix; the fixture carries NVIDIA's text for every one of them.)
#[test]
fn t477_3_lattice_words_stay_outside_the_measured_row() {
    let (table, index) = table_and_index();
    let (mut n, mut illegal, mut inert, mut reuse) = (0, 0, 0, 0);
    for row in fixture() {
        if row.get("lattice").is_none() {
            continue;
        }
        n += 1;
        let word = u128::from_str_radix(row["word"].as_str().unwrap(), 16).unwrap() | (0x0001_e200u128 << 96);
        let vendor = row["nvidia_sass"].as_str();
        let decoded = index.decode(word, 0, table).ok();
        let Some(vendor) = vendor else {
            illegal += 1;
            assert!(decoded.is_none(), "vendor-illegal word {word:032x} decoded as {:?}",
                decoded.map(|d| cubit::printer::to_sass_lossless(&d)));
            continue;
        };
        if (word >> 96) != 0x0001_e200 {
            // reuse window [124:122]: the 96-bit claim zone is the base word, so the row owns these;
            // nvdisasm prints nothing for the bits on ATOMS (the lossless text may carry `.reuse`)
            reuse += 1;
            let d = decoded.unwrap();
            assert_eq!((d.key.as_str(), d.mod_group.as_str()), (KEY, GROUP));
            assert_eq!(cubit::printer::to_sass_lossless(&d).replace(".reuse", ""), vendor, "{word:032x}");
            continue;
        }
        inert += (vendor == "ATOMS.MAX.S32 RZ, [R157+UR7+0x15100], R58") as usize;
        if let Some(d) = decoded {
            assert_ne!((d.key.as_str(), d.mod_group.as_str()), (KEY, GROUP), "{word:032x} ({vendor}) claimed by the measured row");
        }
    }
    assert_eq!(n, 54);
    assert_eq!(illegal, 2, "0x38c with bit 91 and 0x98c without it");
    assert_eq!(inert, 14, "bits 72, 76, 77, 80..86, 92..95");
    assert_eq!(reuse, 3);
}

/// t477_4: the encoder places the UR and the offset for both address spellings.
#[test]
fn t477_4_encoder_places_ur_and_offset() {
    let (table, _) = table_and_index();
    for (text, want) in [
        ("ATOMS.MAX.S32 RZ, [R157+UR7+0x15100], R58", 0x090002070151003a9dff798cu128),
        ("@!P0 ATOMS.MAX.S32 R0, [R1+URZ], R2", 0x090002ff000000020100898cu128),
        ("ATOMS.MAX.S32 R4, [UR63+-0x1], R5", 0x0900023fffffff05ff04798cu128),
    ] {
        let parsed = cubit::parse_sass(&format!("{text} ;"), 0).unwrap();
        let got = cubit::encoder::encode_instruction(&parsed, table).unwrap_or_else(|e| panic!("{text}: {e}"));
        assert_eq!(got & ((1u128 << 96) - 1), want, "{text}");
    }
    for text in ["ATOMS.MAX.S32 RZ, [R157.X4+UR7+0x15100], R58 ;", "ATOMS.MAX.INVALID3 RZ, [R157+UR7], R58 ;"] {
        if let Ok(parsed) = cubit::parse_sass(text, 0) {
            assert!(cubit::encoder::encode_instruction(&parsed, table).is_err(), "{text}");
        }
    }
}

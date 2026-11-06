//! The plain `UTMALDG.<dim> [URa], [URb]` form on sm120 / sm103a / sm100a (session T-7, 2026-11-06, the
//! extension of coldface's B300-3 row): nvdisasm 13.1 renders the five dimensions from the enum at
//! [81:79] (0 = 1D, 1 = 2D, 2 = 3D, 3 = 4D, 4 = 5D; 5-7 = INVALID5/6/7) on the same operand layout
//! (uniform guard [15:12], URa [39:32], URb [31:24]); bit 76 is the descriptor form (the `_II` rows),
//! 84 GATHER4, 85 2CTA. sm120 had no plain key -- its dotted era keys `UTMALDG.1D_AUR_AUR` /
//! `UTMALDG.2D_AUR_AUR` shared one and_base without the dimension bits and the vendor's
//! `UTMALDG.2D [UR8], [UR14]` was a decode miss; they are retired. Pins: every dimension word decodes
//! to the vendor text and re-encodes bit for bit on the three tables; INVALID codes stay holes; the
//! descriptor word stays on its own row; the era keys are gone.

use cubit::{decoder::DecodeIndex, table::IsaTable};
use std::{path::Path, sync::OnceLock};

const CTRL: u128 = 0x000f_c400u128 << 96;
const TABLES: [&str; 3] = ["tables/sm120.json", "tables/sm103a.json", "tables/sm100a.json"];

fn loaded() -> &'static Vec<(IsaTable, DecodeIndex)> {
    static ALL: OnceLock<Vec<(IsaTable, DecodeIndex)>> = OnceLock::new();
    ALL.get_or_init(|| {
        TABLES.iter().map(|p| { let t = IsaTable::load(Path::new(p)).unwrap(); let i = DecodeIndex::build(&t); (t, i) }).collect()
    })
}

fn word(dim: u128, ura: u128, urb: u128, guard: u128) -> u128 {
    CTRL | 0x5b4 | (1 << 91) | (dim << 79) | (ura << 32) | (urb << 24) | (guard << 12)
}

fn encode(table: &IsaTable, word: u128, text: &str) -> u128 {
    let control = cubit::scheduling::format_control_code(&cubit::scheduling::decode_sched_upper32((word >> 96) as u32));
    let source = format!("[{control}] {text} ;");
    let parsed = cubit::parse_cuasm_line(&source, 0).unwrap_or_else(|e| panic!("{source}: {e}"));
    cubit::encoder::encode_instruction(&parsed, table).unwrap_or_else(|e| panic!("{source}: {e}"))
}

#[test]
fn the_five_dimensions_decode_and_round_trip_on_the_three_tables() {
    for (i, (table, index)) in loaded().iter().enumerate() {
        for (dim, name) in [(0u128, "1D"), (1, "2D"), (2, "3D"), (3, "4D"), (4, "5D")] {
            for (ura, urb, guard, prefix) in [(8u128, 14u128, 7u128, ""), (0, 63, 0, "@UP0 "), (255, 0, 15, "@!UPT ")] {
                let w = word(dim, ura, urb, guard);
                let d = index.decode(w, 0, table).unwrap_or_else(|e| panic!("{}: {w:032x}: {e}", TABLES[i]));
                assert_eq!(d.key, "UTMALDG_AURI_AURI", "{}: {w:032x}", TABLES[i]);
                let ua = if ura == 255 { "URZ".to_string() } else { format!("UR{ura}") };
                let ub = if urb == 255 { "URZ".to_string() } else { format!("UR{urb}") };
                let vendor = format!("{prefix}UTMALDG.{name} [{ua}], [{ub}]");
                assert_eq!(cubit::printer::to_sass(&d), vendor, "{}: {w:032x}", TABLES[i]);
                assert_eq!(encode(table, w, &vendor), w, "{}: {vendor}", TABLES[i]);
            }
        }
        for dim in [5u128, 6, 7] {
            let w = word(dim, 8, 14, 7);
            let d = index.decode(w, 0, table).ok();
            assert!(d.as_ref().is_none_or(|d| d.key != "UTMALDG_AURI_AURI"), "{}: INVALID{dim} must not decode through the plain row", TABLES[i]);
        }
        // the descriptor form (bit 76) stays on its own rows
        let desc = word(1, 8, 14, 7) | (1 << 76);
        if let Ok(d) = index.decode(desc, 0, table) {
            assert_ne!(d.key, "UTMALDG_AURI_AURI", "{}: the desc word must not be claimed by the plain row", TABLES[i]);
        }
    }
}

#[test]
fn the_sm120_era_keys_are_retired() {
    let (table, _) = &loaded()[0];
    for key in ["UTMALDG.1D_AUR_AUR", "UTMALDG.2D_AUR_AUR"] {
        assert!(!table.entries.contains_key(key), "{key} must be retired");
    }
}

//! `UP2UR`'s 32-bit immediate prints unsigned on every form of the key, not on `.B3` alone.
//!
//! The B300 measurement lane measured `UP2UR.B3 URd, UPR, URs, imm` (`tests/hidden_b300_up2ur_ur2up_production.rs`) and
//! taught the printer its unsigned mask for that group. The engine differential of the batch that took the form (session
//! T-26, 2026-11-10: every row of the four tables decoded, printed and re-assembled before and after the change, nvdisasm
//! 13.1 the judge) showed the plain word still printing `-0x1` where nvdisasm prints `0xffffffff`. nvdisasm 13.1 names
//! the four words below identically on `-b SM120`, `-b SM121`, `-b SM103` and `-b SM100`:
//!
//!     0000000008000000ffffffff00007883   UP2UR    UR0, UPR, UR0, 0xffffffff
//!     0000000008001000ffffffff00007883   UP2UR.B1 UR0, UPR, UR0, 0xffffffff
//!     0000000008002000ffffffff00007883   UP2UR.B2 UR0, UPR, UR0, 0xffffffff
//!     0000000008003000ffffffff00007883   UP2UR.B3 UR0, UPR, UR0, 0xffffffff
//!
//! sm103a / sm100a carry the plain form (a harvest row) and `.B3` (measured); `.B1` / `.B2` have no row and fail closed.
//! sm120 / sm121a have no row at opcode 0x883 at all.
use cubit::{decoder::DecodeIndex, table::IsaTable};

#[test]
fn the_plain_and_the_b3_immediate_print_unsigned_and_reassemble() {
    for arch in ["sm103a", "sm100a"] {
        let table = IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap();
        let index = DecodeIndex::build(&table);
        for (word, text) in [
            (0x0000000008000000ffffffff00007883_u128, "UP2UR UR0, UPR, UR0, 0xffffffff"),
            (0x0000000008003000ffffffff00007883_u128, "UP2UR.B3 UR0, UPR, UR0, 0xffffffff"),
            (0x000000000800000080000000050c7883_u128, "UP2UR UR12, UPR, UR5, 0x80000000"),
            (0x00000000080000000000000100007883_u128, "UP2UR UR0, UPR, UR0, 0x1"),
        ] {
            let decoded = index.decode(word, 0, &table).unwrap_or_else(|e| panic!("{arch}: {word:032x}: {e}"));
            assert_eq!(decoded.key, "UP2UR_UR_II_UR_II", "{arch}: {word:032x}");
            assert_eq!(cubit::printer::to_sass_lossless(&decoded), text, "{arch}: {word:032x}");
            let ctrl = cubit::scheduling::format_control_code(&cubit::scheduling::decode_sched_upper32((word >> 96) as u32));
            let parsed = cubit::parse_cuasm_line(&format!("[{ctrl}] {text} ;"), 0).unwrap_or_else(|e| panic!("{arch}: parse {text}: {e}"));
            assert_eq!(
                cubit::encoder::encode_instruction(&parsed, &table).unwrap_or_else(|e| panic!("{arch}: encode {text}: {e}")),
                word,
                "{arch}: {text}"
            );
        }
        // the byte selectors without a row stay refused (nvdisasm names them: a gap, not a wrong text)
        for word in [0x0000000008001000ffffffff00007883_u128, 0x0000000008002000ffffffff00007883_u128] {
            assert!(index.decode(word, 0, &table).is_err(), "{arch}: {word:032x}");
        }
    }
}

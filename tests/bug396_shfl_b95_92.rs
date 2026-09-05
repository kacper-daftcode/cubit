//! BUG-396 (F2-iter207, loop5/blind front2, 2026-09-05): SHFL [95:92]
//! stray-window relax -- b92/b93/b94/b95 write-inert na WSZYSTKICH
//! graftowanych rodzinach SHFL (RR x4 tryby, R_II x4, II_II x4, II_R x2)
//! x4 nogi. Rejestracja 396-kand LOW (387.md sec.7, F2-iter206).
//! Canonical graft patch396.py (93bc221 -> c155d00, tabele-only,
//! ENGINE ZERO).
//!
//! LAW: arb387 (iter206) 280 sond: b93/b95 inert 56/56 x4 modele;
//! arb387b: b92/b94/ball(92..95) legal-unanimous 42/42 x4; arb396
//! (iter207) 84 sondy kompozycji: pary wewnatrz okna (92|93, 94|95,
//! 92|94, 93|95) + ball okna + ball z regionami [63:61] (BUG-387) i
//! [90:88]+b63 (BUG-382) = 84/84 rc=0 JEDNOMYSLNE x4, tekst == clean
//! anchor; arb396b: rodzina t225 x okno (7/7). nvdisasm 13.3.73 raw -b,
//! x4 modele SM100a/SM103a/SM120/SM121a AGREE na KAZDEJ sondzie,
//! DIVERGENT=0. b91 = KILL x4 na kazdej klasie (pin ZOSTAJE); b64/b65 =
//! LIVE reg-c field [71:64] na RR/II_R (granica dolna, zostaje).
//! Bity >=96: poza domena tabel (M96) -- vendor rozszerza tam Rc
//! (397-kand); relax rozlaczny z pólsetem [127:96] ex definitione.
//! Pre-fix (publish cubit_py-fe384b27 81d27aa0..; canonical 93bc221;
//! measure_pre396.json): 224 ogniwa b92..b95 + 56 ball LOUD HOLE x4
//! nogi, 0 DECODED (zero cichego misprintu); kontrole b62/b61/b63
//! DECODED 56/56 (grafy 387/382 zywe), b91 HOLE 56/56 (kill);
//! II_R IDX/BFLY mint REFUSE x8 = residuum 358/368 sec.6 (zostaje).
use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::IsaTable;

const M96: u128 = (1u128 << 96) - 1;
const LEGS: [&str; 4] = ["sm100a", "sm103a", "sm120", "sm121a"];
const RELAX: u128 = 0xfu128 << 92;
const PREV387: u128 = 0x7u128 << 61; // [63:61] = BUG-387 (b63: BUG-382)
const PREV382: u128 = 0x7u128 << 88; // [90:88] = BUG-382

fn tab(arch: &str) -> IsaTable {
    IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap()
}
fn dec(t: &IsaTable, w: u128) -> Option<String> {
    DecodeIndex::build(t)
        .decode(w & M96, 0, t)
        .map(|d| to_sass(&d))
        .ok()
        .map(|s| s.trim_end().trim_end_matches(';').to_string())
}
fn enc(t: &IsaTable, text: &str) -> Result<u128, String> {
    let insn = parse_sass(&format!("{text};"), 0).map_err(|e| format!("parse: {e}"))?;
    encode_instruction(&insn, t).map_err(|e| format!("encode: {e}"))
}

#[test]
fn t396_1_structure_relax_rows_x4_legs() {
    let era: &[(&str, &[&str])] = &[
        ("SHFL_P_R_R_II_II", &["BFLY", "DOWN", "IDX", "UP"]),
        ("SHFL_P_R_R_II_R", &["DOWN", "UP"]),
        ("SHFL_P_R_R_R_II", &["BFLY", "DOWN", "IDX", "UP"]),
        ("SHFL_P_R_R_R_R", &["BFLY", "DOWN", "IDX", "UP"]),
    ];
    for leg in ["sm100a", "sm103a", "sm120"] {
        let t = tab(leg);
        let mut n = 0;
        for (k, mgs) in era {
            for mg in *mgs {
                let g = &t.entries[*k].mod_groups[*mg];
                let vm = g.variable_mask;
                let mut fmask = 0u128;
                for f in &g.fields {
                    fmask |= ((1u128 << f.bits) - 1) << f.shift;
                }
                let care = M96 & !(vm | fmask);
                assert_eq!(
                    care & RELAX,
                    0,
                    "{leg} {k}[{mg}] window [95:92] still pinned"
                );
                assert_eq!((care >> 91) & 1, 1, "{leg} {k}[{mg}] b91 kill-pin lost");
                assert_eq!(
                    care & PREV387,
                    0,
                    "{leg} {k}[{mg}] [63:61] (387) relax lost"
                );
                assert_eq!(
                    care & PREV382,
                    0,
                    "{leg} {k}[{mg}] [90:88] (382) relax lost"
                );
                assert_eq!(RELAX & fmask, 0, "{leg} {k}[{mg}] relax overlaps fields");
                n += 1;
            }
        }
        assert_eq!(n, 14, "{leg} era relax row count");
    }
    let t = tab("sm121a");
    let ka: &[(&str, &str)] = &[
        ("SHFL.BFLY_P_R_R_II_II", ""),
        ("SHFL_P_R_R_II_II", "DOWN"),
        ("SHFL_P_R_R_II_II", "IDX"),
        ("SHFL_P_R_R_II_II", "UP"),
        ("SHFL_P_R_R_II_R", "DOWN"),
        ("SHFL_P_R_R_II_R", "UP"),
        ("SHFL_P_R_R_R_II", "BFLY"),
        ("SHFL_P_R_R_R_II", "DOWN"),
        ("SHFL_P_R_R_R_II", "UP"),
        ("SHFL.IDX_P_R_R_R_II", ""),
        ("SHFL.BFLY_P_R_R_R_R", ""),
        ("SHFL_P_R_R_R_R", "BFLY"),
        ("SHFL_P_R_R_R_R", "DOWN"),
        ("SHFL_P_R_R_R_R", "IDX"),
        ("SHFL_P_R_R_R_R", "UP"),
    ];
    for (k, mg) in ka {
        let g = &t.entries[*k].mod_groups[*mg];
        let vm = g.variable_mask;
        let mut fmask = 0u128;
        for f in &g.fields {
            fmask |= ((1u128 << f.bits) - 1) << f.shift;
        }
        let care = M96 & !(vm | fmask);
        assert_eq!(
            care & RELAX,
            0,
            "sm121a {k}[{mg}] window [95:92] still pinned"
        );
        assert_eq!((care >> 91) & 1, 1, "sm121a {k}[{mg}] b91 kill-pin lost");
        assert_eq!(
            care & PREV387,
            0,
            "sm121a {k}[{mg}] [63:61] (387) relax lost"
        );
    }
    // '_?' residuum rows stay pinned w.r.t. [95:92] (celowo nietkniete)
    for k in ["SHFL.BFLY_P_R_R_II_II_?", "SHFL.IDX_P_R_R_R_II_?"] {
        let g = &t.entries[k].mod_groups[""];
        let vm = g.variable_mask;
        assert_eq!(vm & RELAX, 0, "sm121a {k} residuum relaxed?!");
    }
}

#[test]
fn t396_2_vendor_window_words_decode_clean_x4() {
    // Machine-generated arb-verbatim pins (work/bug396/pin_words396.json;
    // cross-checked vs arb396/arb396b/arb387/arb387b verdicts): single bits
    // b92..b95, pairs, ball(92..95), full-ball with [63:61]/[90:88],
    // t225-family; expected text = nvdisasm x4 unanimous canonical render
    // == clean anchor text.
    let cases: &[(u128, &str)] = &[
        (
            0x000fc200f00000000fe00c0012097f89u128,
            "SHFL.BFLY P0, R9, R18, 0x1f, 0xc",
        ), // arb396:II_II-BFLY-7f89-ballwin
        (
            0x000fc200f7000000efe00c0012097f89u128,
            "SHFL.BFLY P0, R9, R18, 0x1f, 0xc",
        ), // arb396:II_II-BFLY-7f89-fullball
        (
            0x000fc200300000000fe00c0012097f89u128,
            "SHFL.BFLY P0, R9, R18, 0x1f, 0xc",
        ), // arb396:II_II-BFLY-7f89-pair9293
        (
            0x000fc200500000000fe00c0012097f89u128,
            "SHFL.BFLY P0, R9, R18, 0x1f, 0xc",
        ), // arb396:II_II-BFLY-7f89-pair9294
        (
            0x000fc200a00000000fe00c0012097f89u128,
            "SHFL.BFLY P0, R9, R18, 0x1f, 0xc",
        ), // arb396:II_II-BFLY-7f89-pair9395
        (
            0x000fc200c00000000fe00c0012097f89u128,
            "SHFL.BFLY P0, R9, R18, 0x1f, 0xc",
        ), // arb396:II_II-BFLY-7f89-pair9495
        (
            0x000fc200f00000000be00c0012097f89u128,
            "SHFL.DOWN P0, R9, R18, 0x1f, 0xc",
        ), // arb396:II_II-DOWN-7f89-ballwin
        (
            0x000fc200f7000000ebe00c0012097f89u128,
            "SHFL.DOWN P0, R9, R18, 0x1f, 0xc",
        ), // arb396:II_II-DOWN-7f89-fullball
        (
            0x000fc200300000000be00c0012097f89u128,
            "SHFL.DOWN P0, R9, R18, 0x1f, 0xc",
        ), // arb396:II_II-DOWN-7f89-pair9293
        (
            0x000fc200500000000be00c0012097f89u128,
            "SHFL.DOWN P0, R9, R18, 0x1f, 0xc",
        ), // arb396:II_II-DOWN-7f89-pair9294
        (
            0x000fc200a00000000be00c0012097f89u128,
            "SHFL.DOWN P0, R9, R18, 0x1f, 0xc",
        ), // arb396:II_II-DOWN-7f89-pair9395
        (
            0x000fc200c00000000be00c0012097f89u128,
            "SHFL.DOWN P0, R9, R18, 0x1f, 0xc",
        ), // arb396:II_II-DOWN-7f89-pair9495
        (
            0x000fc200f000000003e00c0012097f89u128,
            "SHFL.IDX P0, R9, R18, 0x1f, 0xc",
        ), // arb396:II_II-IDX-7f89-ballwin
        (
            0x000fc200f7000000e3e00c0012097f89u128,
            "SHFL.IDX P0, R9, R18, 0x1f, 0xc",
        ), // arb396:II_II-IDX-7f89-fullball
        (
            0x000fc2003000000003e00c0012097f89u128,
            "SHFL.IDX P0, R9, R18, 0x1f, 0xc",
        ), // arb396:II_II-IDX-7f89-pair9293
        (
            0x000fc2005000000003e00c0012097f89u128,
            "SHFL.IDX P0, R9, R18, 0x1f, 0xc",
        ), // arb396:II_II-IDX-7f89-pair9294
        (
            0x000fc200a000000003e00c0012097f89u128,
            "SHFL.IDX P0, R9, R18, 0x1f, 0xc",
        ), // arb396:II_II-IDX-7f89-pair9395
        (
            0x000fc200c000000003e00c0012097f89u128,
            "SHFL.IDX P0, R9, R18, 0x1f, 0xc",
        ), // arb396:II_II-IDX-7f89-pair9495
        (
            0x000fc200f000000007e00c0012097f89u128,
            "SHFL.UP P0, R9, R18, 0x1f, 0xc",
        ), // arb396:II_II-UP-7f89-ballwin
        (
            0x000fc200f7000000e7e00c0012097f89u128,
            "SHFL.UP P0, R9, R18, 0x1f, 0xc",
        ), // arb396:II_II-UP-7f89-fullball
        (
            0x000fc2003000000007e00c0012097f89u128,
            "SHFL.UP P0, R9, R18, 0x1f, 0xc",
        ), // arb396:II_II-UP-7f89-pair9293
        (
            0x000fc2005000000007e00c0012097f89u128,
            "SHFL.UP P0, R9, R18, 0x1f, 0xc",
        ), // arb396:II_II-UP-7f89-pair9294
        (
            0x000fc200a000000007e00c0012097f89u128,
            "SHFL.UP P0, R9, R18, 0x1f, 0xc",
        ), // arb396:II_II-UP-7f89-pair9395
        (
            0x000fc200c000000007e00c0012097f89u128,
            "SHFL.UP P0, R9, R18, 0x1f, 0xc",
        ), // arb396:II_II-UP-7f89-pair9495
        (
            0x000fc200f00000100be0000012097989u128,
            "SHFL.DOWN P0, R9, R18, 0x1f, R16",
        ), // arb396:II_R-DOWN-7989-ballwin
        (
            0x000fc200f7000010ebe0000012097989u128,
            "SHFL.DOWN P0, R9, R18, 0x1f, R16",
        ), // arb396:II_R-DOWN-7989-fullball
        (
            0x000fc200300000100be0000012097989u128,
            "SHFL.DOWN P0, R9, R18, 0x1f, R16",
        ), // arb396:II_R-DOWN-7989-pair9293
        (
            0x000fc200500000100be0000012097989u128,
            "SHFL.DOWN P0, R9, R18, 0x1f, R16",
        ), // arb396:II_R-DOWN-7989-pair9294
        (
            0x000fc200a00000100be0000012097989u128,
            "SHFL.DOWN P0, R9, R18, 0x1f, R16",
        ), // arb396:II_R-DOWN-7989-pair9395
        (
            0x000fc200c00000100be0000012097989u128,
            "SHFL.DOWN P0, R9, R18, 0x1f, R16",
        ), // arb396:II_R-DOWN-7989-pair9495
        (
            0x000fc200f000001007e0000012097989u128,
            "SHFL.UP P0, R9, R18, 0x1f, R16",
        ), // arb396:II_R-UP-7989-ballwin
        (
            0x000fc200f7000010e7e0000012097989u128,
            "SHFL.UP P0, R9, R18, 0x1f, R16",
        ), // arb396:II_R-UP-7989-fullball
        (
            0x000fc2003000001007e0000012097989u128,
            "SHFL.UP P0, R9, R18, 0x1f, R16",
        ), // arb396:II_R-UP-7989-pair9293
        (
            0x000fc2005000001007e0000012097989u128,
            "SHFL.UP P0, R9, R18, 0x1f, R16",
        ), // arb396:II_R-UP-7989-pair9294
        (
            0x000fc200a000001007e0000012097989u128,
            "SHFL.UP P0, R9, R18, 0x1f, R16",
        ), // arb396:II_R-UP-7989-pair9395
        (
            0x000fc200c000001007e0000012097989u128,
            "SHFL.UP P0, R9, R18, 0x1f, R16",
        ), // arb396:II_R-UP-7989-pair9495
        (
            0x000fc200f00000100c00000b0a127389u128,
            "SHFL.BFLY P0, R18, R10, R11, R16",
        ), // arb396:RR-BFLY-7389-ballwin
        (
            0x000fc200f7000010ec00000b0a127389u128,
            "SHFL.BFLY P0, R18, R10, R11, R16",
        ), // arb396:RR-BFLY-7389-fullball
        (
            0x000fc200300000100c00000b0a127389u128,
            "SHFL.BFLY P0, R18, R10, R11, R16",
        ), // arb396:RR-BFLY-7389-pair9293
        (
            0x000fc200500000100c00000b0a127389u128,
            "SHFL.BFLY P0, R18, R10, R11, R16",
        ), // arb396:RR-BFLY-7389-pair9294
        (
            0x000fc200a00000100c00000b0a127389u128,
            "SHFL.BFLY P0, R18, R10, R11, R16",
        ), // arb396:RR-BFLY-7389-pair9395
        (
            0x000fc200c00000100c00000b0a127389u128,
            "SHFL.BFLY P0, R18, R10, R11, R16",
        ), // arb396:RR-BFLY-7389-pair9495
        (
            0x000fc200f00000100800000b0a127389u128,
            "SHFL.DOWN P0, R18, R10, R11, R16",
        ), // arb396:RR-DOWN-7389-ballwin
        (
            0x000fc200f7000010e800000b0a127389u128,
            "SHFL.DOWN P0, R18, R10, R11, R16",
        ), // arb396:RR-DOWN-7389-fullball
        (
            0x000fc200300000100800000b0a127389u128,
            "SHFL.DOWN P0, R18, R10, R11, R16",
        ), // arb396:RR-DOWN-7389-pair9293
        (
            0x000fc200500000100800000b0a127389u128,
            "SHFL.DOWN P0, R18, R10, R11, R16",
        ), // arb396:RR-DOWN-7389-pair9294
        (
            0x000fc200a00000100800000b0a127389u128,
            "SHFL.DOWN P0, R18, R10, R11, R16",
        ), // arb396:RR-DOWN-7389-pair9395
        (
            0x000fc200c00000100800000b0a127389u128,
            "SHFL.DOWN P0, R18, R10, R11, R16",
        ), // arb396:RR-DOWN-7389-pair9495
        (
            0x000fc200f00000100000000b0a127389u128,
            "SHFL.IDX P0, R18, R10, R11, R16",
        ), // arb396:RR-IDX-7389-ballwin
        (
            0x000fc200f7000010e000000b0a127389u128,
            "SHFL.IDX P0, R18, R10, R11, R16",
        ), // arb396:RR-IDX-7389-fullball
        (
            0x000fc200300000100000000b0a127389u128,
            "SHFL.IDX P0, R18, R10, R11, R16",
        ), // arb396:RR-IDX-7389-pair9293
        (
            0x000fc200500000100000000b0a127389u128,
            "SHFL.IDX P0, R18, R10, R11, R16",
        ), // arb396:RR-IDX-7389-pair9294
        (
            0x000fc200a00000100000000b0a127389u128,
            "SHFL.IDX P0, R18, R10, R11, R16",
        ), // arb396:RR-IDX-7389-pair9395
        (
            0x000fc200c00000100000000b0a127389u128,
            "SHFL.IDX P0, R18, R10, R11, R16",
        ), // arb396:RR-IDX-7389-pair9495
        (
            0x000fc200f00000100400000b0a127389u128,
            "SHFL.UP P0, R18, R10, R11, R16",
        ), // arb396:RR-UP-7389-ballwin
        (
            0x000fc200f7000010e400000b0a127389u128,
            "SHFL.UP P0, R18, R10, R11, R16",
        ), // arb396:RR-UP-7389-fullball
        (
            0x000fc200300000100400000b0a127389u128,
            "SHFL.UP P0, R18, R10, R11, R16",
        ), // arb396:RR-UP-7389-pair9293
        (
            0x000fc200500000100400000b0a127389u128,
            "SHFL.UP P0, R18, R10, R11, R16",
        ), // arb396:RR-UP-7389-pair9294
        (
            0x000fc200a00000100400000b0a127389u128,
            "SHFL.UP P0, R18, R10, R11, R16",
        ), // arb396:RR-UP-7389-pair9395
        (
            0x000fc200c00000100400000b0a127389u128,
            "SHFL.UP P0, R18, R10, R11, R16",
        ), // arb396:RR-UP-7389-pair9495
        (
            0x000fc200f00200000c001f0a170b7589u128,
            "SHFL.BFLY P1, R11, R23, R10, 0x1f",
        ), // arb396:R_II-BFLY-7589-ballwin
        (
            0x000fc200f7020000ec001f0a170b7589u128,
            "SHFL.BFLY P1, R11, R23, R10, 0x1f",
        ), // arb396:R_II-BFLY-7589-fullball
        (
            0x000fc200300200000c001f0a170b7589u128,
            "SHFL.BFLY P1, R11, R23, R10, 0x1f",
        ), // arb396:R_II-BFLY-7589-pair9293
        (
            0x000fc200500200000c001f0a170b7589u128,
            "SHFL.BFLY P1, R11, R23, R10, 0x1f",
        ), // arb396:R_II-BFLY-7589-pair9294
        (
            0x000fc200a00200000c001f0a170b7589u128,
            "SHFL.BFLY P1, R11, R23, R10, 0x1f",
        ), // arb396:R_II-BFLY-7589-pair9395
        (
            0x000fc200c00200000c001f0a170b7589u128,
            "SHFL.BFLY P1, R11, R23, R10, 0x1f",
        ), // arb396:R_II-BFLY-7589-pair9495
        (
            0x000fc200f002000008001f0a170b7589u128,
            "SHFL.DOWN P1, R11, R23, R10, 0x1f",
        ), // arb396:R_II-DOWN-7589-ballwin
        (
            0x000fc200f7020000e8001f0a170b7589u128,
            "SHFL.DOWN P1, R11, R23, R10, 0x1f",
        ), // arb396:R_II-DOWN-7589-fullball
        (
            0x000fc2003002000008001f0a170b7589u128,
            "SHFL.DOWN P1, R11, R23, R10, 0x1f",
        ), // arb396:R_II-DOWN-7589-pair9293
        (
            0x000fc2005002000008001f0a170b7589u128,
            "SHFL.DOWN P1, R11, R23, R10, 0x1f",
        ), // arb396:R_II-DOWN-7589-pair9294
        (
            0x000fc200a002000008001f0a170b7589u128,
            "SHFL.DOWN P1, R11, R23, R10, 0x1f",
        ), // arb396:R_II-DOWN-7589-pair9395
        (
            0x000fc200c002000008001f0a170b7589u128,
            "SHFL.DOWN P1, R11, R23, R10, 0x1f",
        ), // arb396:R_II-DOWN-7589-pair9495
        (
            0x000fc200f002000000001f0a170b7589u128,
            "SHFL.IDX P1, R11, R23, R10, 0x1f",
        ), // arb396:R_II-IDX-7589-ballwin
        (
            0x000fc200f7020000e0001f0a170b7589u128,
            "SHFL.IDX P1, R11, R23, R10, 0x1f",
        ), // arb396:R_II-IDX-7589-fullball
        (
            0x000fc2003002000000001f0a170b7589u128,
            "SHFL.IDX P1, R11, R23, R10, 0x1f",
        ), // arb396:R_II-IDX-7589-pair9293
        (
            0x000fc2005002000000001f0a170b7589u128,
            "SHFL.IDX P1, R11, R23, R10, 0x1f",
        ), // arb396:R_II-IDX-7589-pair9294
        (
            0x000fc200a002000000001f0a170b7589u128,
            "SHFL.IDX P1, R11, R23, R10, 0x1f",
        ), // arb396:R_II-IDX-7589-pair9395
        (
            0x000fc200c002000000001f0a170b7589u128,
            "SHFL.IDX P1, R11, R23, R10, 0x1f",
        ), // arb396:R_II-IDX-7589-pair9495
        (
            0x000fc200f002000004001f0a170b7589u128,
            "SHFL.UP P1, R11, R23, R10, 0x1f",
        ), // arb396:R_II-UP-7589-ballwin
        (
            0x000fc200f7020000e4001f0a170b7589u128,
            "SHFL.UP P1, R11, R23, R10, 0x1f",
        ), // arb396:R_II-UP-7589-fullball
        (
            0x000fc2003002000004001f0a170b7589u128,
            "SHFL.UP P1, R11, R23, R10, 0x1f",
        ), // arb396:R_II-UP-7589-pair9293
        (
            0x000fc2005002000004001f0a170b7589u128,
            "SHFL.UP P1, R11, R23, R10, 0x1f",
        ), // arb396:R_II-UP-7589-pair9294
        (
            0x000fc200a002000004001f0a170b7589u128,
            "SHFL.UP P1, R11, R23, R10, 0x1f",
        ), // arb396:R_II-UP-7589-pair9395
        (
            0x000fc200c002000004001f0a170b7589u128,
            "SHFL.UP P1, R11, R23, R10, 0x1f",
        ), // arb396:R_II-UP-7589-pair9495
        (
            0x00000000100000000800000000007f89u128,
            "SHFL.DOWN P0, R0, R0, 0x0, 0x0",
        ), // arb396b:t225-b92
        (
            0x00000000200000000800000000007f89u128,
            "SHFL.DOWN P0, R0, R0, 0x0, 0x0",
        ), // arb396b:t225-b93
        (
            0x00000000400000000800000000007f89u128,
            "SHFL.DOWN P0, R0, R0, 0x0, 0x0",
        ), // arb396b:t225-b94
        (
            0x00000000800000000800000000007f89u128,
            "SHFL.DOWN P0, R0, R0, 0x0, 0x0",
        ), // arb396b:t225-b95
        (
            0x00000000800000008800000000007f89u128,
            "SHFL.DOWN P0, R0, R0, 0x0, 0x0",
        ), // arb396b:t225-b9563
        (
            0x00000000f00000000800000000007f89u128,
            "SHFL.DOWN P0, R0, R0, 0x0, 0x0",
        ), // arb396b:t225-ball9295
        (
            0x000fc200200000000fe00c0012097f89u128,
            "SHFL.BFLY P0, R9, R18, 0x1f, 0xc",
        ), // arb387:II_II-BFLY-v0-b93
        (
            0x000fc200800000000fe00c0012097f89u128,
            "SHFL.BFLY P0, R9, R18, 0x1f, 0xc",
        ), // arb387:II_II-BFLY-v0-b95
        (
            0x000fc200200600000e00050014047f89u128,
            "SHFL.BFLY P3, R4, R20, 0x10, 0x5",
        ), // arb387:II_II-BFLY-v1-b93
        (
            0x000fc200800600000e00050014047f89u128,
            "SHFL.BFLY P3, R4, R20, 0x10, 0x5",
        ), // arb387:II_II-BFLY-v1-b95
        (
            0x000fc200200000000be00c0012097f89u128,
            "SHFL.DOWN P0, R9, R18, 0x1f, 0xc",
        ), // arb387:II_II-DOWN-v0-b93
        (
            0x000fc200800000000be00c0012097f89u128,
            "SHFL.DOWN P0, R9, R18, 0x1f, 0xc",
        ), // arb387:II_II-DOWN-v0-b95
        (
            0x000fc200200600000a00050014047f89u128,
            "SHFL.DOWN P3, R4, R20, 0x10, 0x5",
        ), // arb387:II_II-DOWN-v1-b93
        (
            0x000fc200800600000a00050014047f89u128,
            "SHFL.DOWN P3, R4, R20, 0x10, 0x5",
        ), // arb387:II_II-DOWN-v1-b95
        (
            0x000fc2002000000003e00c0012097f89u128,
            "SHFL.IDX P0, R9, R18, 0x1f, 0xc",
        ), // arb387:II_II-IDX-v0-b93
        (
            0x000fc2008000000003e00c0012097f89u128,
            "SHFL.IDX P0, R9, R18, 0x1f, 0xc",
        ), // arb387:II_II-IDX-v0-b95
        (
            0x000fc200200600000200050014047f89u128,
            "SHFL.IDX P3, R4, R20, 0x10, 0x5",
        ), // arb387:II_II-IDX-v1-b93
        (
            0x000fc200800600000200050014047f89u128,
            "SHFL.IDX P3, R4, R20, 0x10, 0x5",
        ), // arb387:II_II-IDX-v1-b95
        (
            0x000fc2002000000007e00c0012097f89u128,
            "SHFL.UP P0, R9, R18, 0x1f, 0xc",
        ), // arb387:II_II-UP-v0-b93
        (
            0x000fc2008000000007e00c0012097f89u128,
            "SHFL.UP P0, R9, R18, 0x1f, 0xc",
        ), // arb387:II_II-UP-v0-b95
        (
            0x000fc200200600000600050014047f89u128,
            "SHFL.UP P3, R4, R20, 0x10, 0x5",
        ), // arb387:II_II-UP-v1-b93
        (
            0x000fc200800600000600050014047f89u128,
            "SHFL.UP P3, R4, R20, 0x10, 0x5",
        ), // arb387:II_II-UP-v1-b95
        (
            0x000fc200200000100be0000012097989u128,
            "SHFL.DOWN P0, R9, R18, 0x1f, R16",
        ), // arb387:II_R-DOWN-v0-b93
        (
            0x000fc200800000100be0000012097989u128,
            "SHFL.DOWN P0, R9, R18, 0x1f, R16",
        ), // arb387:II_R-DOWN-v0-b95
        (
            0x000fc200200400110bc0000013037989u128,
            "SHFL.DOWN P2, R3, R19, 0x1e, R17",
        ), // arb387:II_R-DOWN-v1-b93
        (
            0x000fc200800400110bc0000013037989u128,
            "SHFL.DOWN P2, R3, R19, 0x1e, R17",
        ), // arb387:II_R-DOWN-v1-b95
        (
            0x000fc2002000001007e0000012097989u128,
            "SHFL.UP P0, R9, R18, 0x1f, R16",
        ), // arb387:II_R-UP-v0-b93
        (
            0x000fc2008000001007e0000012097989u128,
            "SHFL.UP P0, R9, R18, 0x1f, R16",
        ), // arb387:II_R-UP-v0-b95
        (
            0x000fc2002004001107c0000013037989u128,
            "SHFL.UP P2, R3, R19, 0x1e, R17",
        ), // arb387:II_R-UP-v1-b93
        (
            0x000fc2008004001107c0000013037989u128,
            "SHFL.UP P2, R3, R19, 0x1e, R17",
        ), // arb387:II_R-UP-v1-b95
        (
            0x000fc200200000100c00000b0a127389u128,
            "SHFL.BFLY P0, R18, R10, R11, R16",
        ), // arb387:RR-BFLY-v0-b93
        (
            0x000fc200800000100c00000b0a127389u128,
            "SHFL.BFLY P0, R18, R10, R11, R16",
        ), // arb387:RR-BFLY-v0-b95
        (
            0x000fc2002006000f0c00000c09117389u128,
            "SHFL.BFLY P3, R17, R9, R12, R15",
        ), // arb387:RR-BFLY-v1-b93
        (
            0x000fc2008006000f0c00000c09117389u128,
            "SHFL.BFLY P3, R17, R9, R12, R15",
        ), // arb387:RR-BFLY-v1-b95
        (
            0x000fc200200000100800000b0a127389u128,
            "SHFL.DOWN P0, R18, R10, R11, R16",
        ), // arb387:RR-DOWN-v0-b93
        (
            0x000fc200800000100800000b0a127389u128,
            "SHFL.DOWN P0, R18, R10, R11, R16",
        ), // arb387:RR-DOWN-v0-b95
        (
            0x000fc2002006000f0800000c09117389u128,
            "SHFL.DOWN P3, R17, R9, R12, R15",
        ), // arb387:RR-DOWN-v1-b93
        (
            0x000fc2008006000f0800000c09117389u128,
            "SHFL.DOWN P3, R17, R9, R12, R15",
        ), // arb387:RR-DOWN-v1-b95
        (
            0x000fc200200000100000000b0a127389u128,
            "SHFL.IDX P0, R18, R10, R11, R16",
        ), // arb387:RR-IDX-v0-b93
        (
            0x000fc200800000100000000b0a127389u128,
            "SHFL.IDX P0, R18, R10, R11, R16",
        ), // arb387:RR-IDX-v0-b95
        (
            0x000fc2002006000f0000000c09117389u128,
            "SHFL.IDX P3, R17, R9, R12, R15",
        ), // arb387:RR-IDX-v1-b93
        (
            0x000fc2008006000f0000000c09117389u128,
            "SHFL.IDX P3, R17, R9, R12, R15",
        ), // arb387:RR-IDX-v1-b95
        (
            0x000fc200200000100400000b0a127389u128,
            "SHFL.UP P0, R18, R10, R11, R16",
        ), // arb387:RR-UP-v0-b93
        (
            0x000fc200800000100400000b0a127389u128,
            "SHFL.UP P0, R18, R10, R11, R16",
        ), // arb387:RR-UP-v0-b95
        (
            0x000fc2002006000f0400000c09117389u128,
            "SHFL.UP P3, R17, R9, R12, R15",
        ), // arb387:RR-UP-v1-b93
        (
            0x000fc2008006000f0400000c09117389u128,
            "SHFL.UP P3, R17, R9, R12, R15",
        ), // arb387:RR-UP-v1-b95
        (
            0x000fc200200200000c001f0a170b7589u128,
            "SHFL.BFLY P1, R11, R23, R10, 0x1f",
        ), // arb387:R_II-BFLY-v0-b93
        (
            0x000fc200800200000c001f0a170b7589u128,
            "SHFL.BFLY P1, R11, R23, R10, 0x1f",
        ), // arb387:R_II-BFLY-v0-b95
        (
            0x000fc200200400000c001709160c7589u128,
            "SHFL.BFLY P2, R12, R22, R9, 0x17",
        ), // arb387:R_II-BFLY-v1-b93
        (
            0x000fc200800400000c001709160c7589u128,
            "SHFL.BFLY P2, R12, R22, R9, 0x17",
        ), // arb387:R_II-BFLY-v1-b95
        (
            0x000fc2002002000008001f0a170b7589u128,
            "SHFL.DOWN P1, R11, R23, R10, 0x1f",
        ), // arb387:R_II-DOWN-v0-b93
        (
            0x000fc2008002000008001f0a170b7589u128,
            "SHFL.DOWN P1, R11, R23, R10, 0x1f",
        ), // arb387:R_II-DOWN-v0-b95
        (
            0x000fc2002004000008001709160c7589u128,
            "SHFL.DOWN P2, R12, R22, R9, 0x17",
        ), // arb387:R_II-DOWN-v1-b93
        (
            0x000fc2008004000008001709160c7589u128,
            "SHFL.DOWN P2, R12, R22, R9, 0x17",
        ), // arb387:R_II-DOWN-v1-b95
        (
            0x000fc2002002000000001f0a170b7589u128,
            "SHFL.IDX P1, R11, R23, R10, 0x1f",
        ), // arb387:R_II-IDX-v0-b93
        (
            0x000fc2008002000000001f0a170b7589u128,
            "SHFL.IDX P1, R11, R23, R10, 0x1f",
        ), // arb387:R_II-IDX-v0-b95
        (
            0x000fc2002004000000001709160c7589u128,
            "SHFL.IDX P2, R12, R22, R9, 0x17",
        ), // arb387:R_II-IDX-v1-b93
        (
            0x000fc2008004000000001709160c7589u128,
            "SHFL.IDX P2, R12, R22, R9, 0x17",
        ), // arb387:R_II-IDX-v1-b95
        (
            0x000fc2002002000004001f0a170b7589u128,
            "SHFL.UP P1, R11, R23, R10, 0x1f",
        ), // arb387:R_II-UP-v0-b93
        (
            0x000fc2008002000004001f0a170b7589u128,
            "SHFL.UP P1, R11, R23, R10, 0x1f",
        ), // arb387:R_II-UP-v0-b95
        (
            0x000fc2002004000004001709160c7589u128,
            "SHFL.UP P2, R12, R22, R9, 0x17",
        ), // arb387:R_II-UP-v1-b93
        (
            0x000fc2008004000004001709160c7589u128,
            "SHFL.UP P2, R12, R22, R9, 0x17",
        ), // arb387:R_II-UP-v1-b95
        (
            0x000fc200100000000fe00c0012097f89u128,
            "SHFL.BFLY P0, R9, R18, 0x1f, 0xc",
        ), // arb387b:II_II-BFLY-7f89-b92
        (
            0x000fc200400000000fe00c0012097f89u128,
            "SHFL.BFLY P0, R9, R18, 0x1f, 0xc",
        ), // arb387b:II_II-BFLY-7f89-b94
        (
            0x000fc200100000000be00c0012097f89u128,
            "SHFL.DOWN P0, R9, R18, 0x1f, 0xc",
        ), // arb387b:II_II-DOWN-7f89-b92
        (
            0x000fc200400000000be00c0012097f89u128,
            "SHFL.DOWN P0, R9, R18, 0x1f, 0xc",
        ), // arb387b:II_II-DOWN-7f89-b94
        (
            0x000fc2001000000003e00c0012097f89u128,
            "SHFL.IDX P0, R9, R18, 0x1f, 0xc",
        ), // arb387b:II_II-IDX-7f89-b92
        (
            0x000fc2004000000003e00c0012097f89u128,
            "SHFL.IDX P0, R9, R18, 0x1f, 0xc",
        ), // arb387b:II_II-IDX-7f89-b94
        (
            0x000fc2001000000007e00c0012097f89u128,
            "SHFL.UP P0, R9, R18, 0x1f, 0xc",
        ), // arb387b:II_II-UP-7f89-b92
        (
            0x000fc2004000000007e00c0012097f89u128,
            "SHFL.UP P0, R9, R18, 0x1f, 0xc",
        ), // arb387b:II_II-UP-7f89-b94
        (
            0x000fc200100000100be0000012097989u128,
            "SHFL.DOWN P0, R9, R18, 0x1f, R16",
        ), // arb387b:II_R-DOWN-7989-b92
        (
            0x000fc200400000100be0000012097989u128,
            "SHFL.DOWN P0, R9, R18, 0x1f, R16",
        ), // arb387b:II_R-DOWN-7989-b94
        (
            0x000fc2001000001007e0000012097989u128,
            "SHFL.UP P0, R9, R18, 0x1f, R16",
        ), // arb387b:II_R-UP-7989-b92
        (
            0x000fc2004000001007e0000012097989u128,
            "SHFL.UP P0, R9, R18, 0x1f, R16",
        ), // arb387b:II_R-UP-7989-b94
        (
            0x000fc200100000100c00000b0a127389u128,
            "SHFL.BFLY P0, R18, R10, R11, R16",
        ), // arb387b:RR-BFLY-7389-b92
        (
            0x000fc200400000100c00000b0a127389u128,
            "SHFL.BFLY P0, R18, R10, R11, R16",
        ), // arb387b:RR-BFLY-7389-b94
        (
            0x000fc200100000100800000b0a127389u128,
            "SHFL.DOWN P0, R18, R10, R11, R16",
        ), // arb387b:RR-DOWN-7389-b92
        (
            0x000fc200400000100800000b0a127389u128,
            "SHFL.DOWN P0, R18, R10, R11, R16",
        ), // arb387b:RR-DOWN-7389-b94
        (
            0x000fc200100000100000000b0a127389u128,
            "SHFL.IDX P0, R18, R10, R11, R16",
        ), // arb387b:RR-IDX-7389-b92
        (
            0x000fc200400000100000000b0a127389u128,
            "SHFL.IDX P0, R18, R10, R11, R16",
        ), // arb387b:RR-IDX-7389-b94
        (
            0x000fc200100000100400000b0a127389u128,
            "SHFL.UP P0, R18, R10, R11, R16",
        ), // arb387b:RR-UP-7389-b92
        (
            0x000fc200400000100400000b0a127389u128,
            "SHFL.UP P0, R18, R10, R11, R16",
        ), // arb387b:RR-UP-7389-b94
        (
            0x000fc200100200000c001f0a170b7589u128,
            "SHFL.BFLY P1, R11, R23, R10, 0x1f",
        ), // arb387b:R_II-BFLY-7589-b92
        (
            0x000fc200400200000c001f0a170b7589u128,
            "SHFL.BFLY P1, R11, R23, R10, 0x1f",
        ), // arb387b:R_II-BFLY-7589-b94
        (
            0x000fc2001002000008001f0a170b7589u128,
            "SHFL.DOWN P1, R11, R23, R10, 0x1f",
        ), // arb387b:R_II-DOWN-7589-b92
        (
            0x000fc2004002000008001f0a170b7589u128,
            "SHFL.DOWN P1, R11, R23, R10, 0x1f",
        ), // arb387b:R_II-DOWN-7589-b94
        (
            0x000fc2001002000000001f0a170b7589u128,
            "SHFL.IDX P1, R11, R23, R10, 0x1f",
        ), // arb387b:R_II-IDX-7589-b92
        (
            0x000fc2004002000000001f0a170b7589u128,
            "SHFL.IDX P1, R11, R23, R10, 0x1f",
        ), // arb387b:R_II-IDX-7589-b94
        (
            0x000fc2001002000004001f0a170b7589u128,
            "SHFL.UP P1, R11, R23, R10, 0x1f",
        ), // arb387b:R_II-UP-7589-b92
        (
            0x000fc2004002000004001f0a170b7589u128,
            "SHFL.UP P1, R11, R23, R10, 0x1f",
        ), // arb387b:R_II-UP-7589-b94
    ];
    for (w, exp) in cases {
        for leg in LEGS {
            let t = tab(leg);
            let got = dec(&t, *w).unwrap_or_else(|| panic!("{leg} HOLE on {w:#034x}"));
            assert_eq!(&got, exp, "{leg} wrong-text on {w:#034x}");
        }
    }
}

#[test]
fn t396_3_mints_byte_locked_no_relaxed_bits() {
    // Authored mints x4 nogi == canonical anchor words bajtowo; mint NIGDY
    // nie niesie bitow z zrelaksowanych okien ([95:92] 396, [63:61] 387,
    // [90:88] 382, b63 382); roundtrip tekst-exact.
    let anchors: &[(u128, &str)] = &[
        (
            0x000fc200000000100c00000b0a127389u128,
            "SHFL.BFLY P0, R18, R10, R11, R16",
        ), // RR-BFLY
        (
            0x000fc2000002000000001f0a170b7589u128,
            "SHFL.IDX P1, R11, R23, R10, 0x1f",
        ), // R_II-IDX
        (
            0x000fc200000000000fe00c0012097f89u128,
            "SHFL.BFLY P0, R9, R18, 0x1f, 0xc",
        ), // II_II-BFLY
        (
            0x000fc2000000001007e0000012097989u128,
            "SHFL.UP P0, R9, R18, 0x1f, R16",
        ), // II_R-UP
    ];
    let junk = RELAX | PREV387 | PREV382 | (1u128 << 63);
    for (refw, text) in anchors {
        for leg in LEGS {
            let t = tab(leg);
            let w = enc(&t, text).unwrap_or_else(|e| panic!("{leg} mint refuse: {e}"));
            assert_eq!(w & M96, refw & M96, "{leg} mint drifted for {text}");
            assert_eq!(w & junk, 0, "{leg} mint carries relaxed-window bits");
            let got = dec(&t, w).unwrap();
            assert_eq!(&got, text, "{leg} roundtrip drift for {text}");
        }
    }
}

#[test]
fn t396_4_kill_and_field_boundary_x4() {
    // b91 = KILL x4 na kazdej klasie (arb387 28/28 rc!=0 x4) -- pin ZOSTAJE.
    let anchors: &[u128] = &[
        0x000fc200000000100c00000b0a127389, // RR BFLY
        0x000fc2000002000000001f0a170b7589, // R_II IDX
        0x000fc200000000000fe00c0012097f89, // II_II BFLY
        0x000fc2000000001007e0000012097989, // II_R UP
    ];
    for w0 in anchors {
        let w = w0 | (1u128 << 91);
        for leg in LEGS {
            let t = tab(leg);
            assert!(dec(&t, w).is_none(), "{leg} b91 kill claimed on {w:#034x}");
        }
    }
    // granica dolna okien: b64/b65 = LIVE reg-c field [71:64] na RR;
    // pole musi renderowac rejestr (nie byc skonsumowane relaxami).
    let rr_down = 0x000fc200000000100800000b0a127389u128;
    for leg in LEGS {
        let t = tab(leg);
        let got = dec(&t, rr_down | (1u128 << 64)).unwrap();
        assert_eq!(
            &got, "SHFL.DOWN P0, R18, R10, R11, R17",
            "{leg} b64 field lost"
        );
        let got = dec(&t, rr_down | (1u128 << 65)).unwrap();
        assert_eq!(
            &got, "SHFL.DOWN P0, R18, R10, R11, R18",
            "{leg} b65 field lost"
        );
    }
}

#[test]
fn t396_5_flips_with_attribution_era_class() {
    // t387_4-class: dawny deferral [95:92] przechodzi na vendor-parity
    // (pelny zestaw w t396_2); tu: t225-family [95:92] + cross-window
    // b95|b63 na tej bazie (arb396b), x2 nogi era.
    let w_ball = 0x000000000800000000007f89u128 ^ (0xfu128 << 92);
    let w_cross = 0x000000000800000000007f89u128 ^ (1u128 << 95) ^ (1u128 << 63);
    for leg in ["sm100a", "sm103a"] {
        let t = tab(leg);
        for w in [w_ball, w_cross] {
            let got = dec(&t, w).unwrap_or_else(|| panic!("{leg} t225-window HOLE"));
            assert_eq!(&got, "SHFL.DOWN P0, R0, R0, 0x0, 0x0", "{leg} wrong-text");
        }
    }
    // II_R IDX/BFLY absent x4 = residuum no-claim 358/368 sec.6: mint musi
    // zostac LOUD REFUSE (poza zakresem 396)
    for leg in LEGS {
        let t = tab(leg);
        for text in [
            "SHFL.IDX P0, R9, R18, 0x1f, R16",
            "SHFL.BFLY P0, R9, R18, 0x1f, R16",
        ] {
            assert!(enc(&t, text).is_err(), "{leg} II_R {text} minted?!");
        }
    }
}

//! BUG-099 + BUG-095-kand (F2Q, F2-iter36, 2026-08-23): canon raw-address
//! uniform-indexed LDG/STG forms (`[Rn.U32+URm(+imm)]` = 099 coverage gap,
//! `[Rn.64+URm+imm]` = 095 claim-repair).
//! Pre-fix (HEAD a27931d):
//! (1) 099: 82 uniq era-rt98 words — canon sm103a ALL DECERR (193 `/* ? */`
//!     slots in the frozen dec stream); sm120 exact (native keys). Canon had
//!     no keys for the plain-UR raw-address global form at all.
//! (2) 095: 16 uniq/30 recs corpus-2049 words — canon LDG_R_ARURI::E junk
//!     (RE-epoch sub_* desc geometry) claimed them on BOTH tables and printed
//!     `desc[UR12][R12.64+-0x80]` (silent semantic rewrite of a raw-UR
//!     addressing word, incl. sign-flipped imm); true form is
//!     `LDG.E R10, [R12.64+UR12+0x80]` (mode [92:90]=3).
//! Fix: canon LDG_R_ARURI::E repaired in place to plain vendor geometry
//! (guard@12(4), reg@16(8), reg@24(8), ureg@32(6), imm@40(24); mode-3 baked;
//! addr_width="64") + 11 native keys imported verbatim from sm120 (the 10
//! `.U32+UR` owner keys + LDG.E_R_ARURI with vm +bit92 for the mode-2
//! `[RZ.U32+UR4]` corpus form; addr_width="U32" each). Same repair + pins on
//! sm120.json. Encoder: textual bracket suffix (.U32/.64) validated against
//! row `addr_width` BEFORE the raw-address bypass + same check in the Desc/
//! general Addr path — pre-fix `[Rn.64+URm+imm]` text silently rode the
//! ".U32" row (mode-6 word shipped for .64 mode semantics). Printer:
//! format_plain_u32_ur gains raw-driven width (mode bits [91:90]==0b11 =>
//! ".64", else ".U32"; canon-era key names join the plain arm only when the
//! mg carries plain ureg+reg fields — junk desc mgs unaffected).
//! Known residue (documented): corpus word 817900ff04.. (`LDG.E R0,
//! [RZ.U32+UR4]`, mode [92:90]=2, 13 slots / 2049 corpus) decodes vendor-
//! exact, but its TEXT re-encodes to the legal mode-6 word (textual forms
//! identical); RT96 universe therefore carries 13 documented non-exact slots
//! (pre: those slots were junk-misdecoded, i.e. worse). Modes 5/7 stay
//! fail-closed (no vendor evidence).
//! Report: the internal fix archive Anchors: the internal fix archive
//!
//! BUG-149 (iter70, 2026-08-25, front-main) follow-up: fresh-corpus evidence
//! (hexdb 2014 cubins, nvdisasm-13.3) shows sm_100/103-nvcc emits the raw
//! `.U32+UR` LDG forms with mode == 2 (10/10 anchors; LD.E + STG agree) while
//! the mode-6 shape exists only in the frozen sm120 vendor era bins (rt98/rc4,
//! 63 uniq words, LDG-only -- STG era words are mode-2). The donor-verbatim
//! and_base (mode-6) therefore: (a) OR-polluted encode vs its own arch
//! (battery mismatch `LDG.E.64 [RZ.U32+UR8]`, BUG-147 sec.5), and (b) left a
//! decode gap for mode-2 words that the junk row LDG_R_ARURI::64,E filled
//! with fabricated `desc[UR][RZ.64]` renders. Fix on sm103a: five raw LDG
//! rows get and_base mode-2 (canonical encode) + variable_mask bit92 (both
//! modes decode); LDG_R_ARURI::64,E deleted. sm120.json keeps mode-6 (its
//! vendor bin truth) -- per-arch canonical. sm103a era-word round-trips now
//! carry the mode bit through the !rsd[92:1] overlay (pins below).
use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::table::IsaTable;

fn t120() -> IsaTable { IsaTable::load(std::path::Path::new("tables/sm120.json")).unwrap() }
fn t103() -> IsaTable { IsaTable::load(std::path::Path::new("tables/sm103a.json")).unwrap() }
const M96: u128 = (1u128 << 96) - 1;

const GOLD95: &[(u128, &str)] = &[
    (0x002ea200081e090000000004ff007981u128, "LDG.E R0, [RZ.U32+UR4]"), // corpus 2049
    (0x000ea8000c1e09000000800c0c0a7981u128, "LDG.E R10, [R12.64+UR12+0x80]"), // corpus 2049
    (0x000ee8000c1e09000000800a0c057981u128, "LDG.E R5, [R12.64+UR10+0x80]"), // corpus 2049
    (0x000f22000c1e0900000080060c087981u128, "LDG.E R8, [R12.64+UR6+0x80]"), // corpus 2049
    (0x000ea8000c1e09000000800c0c097981u128, "LDG.E R9, [R12.64+UR12+0x80]"), // corpus 2049
    (0x000ee8000c1e09000000800a0c077981u128, "LDG.E R7, [R12.64+UR10+0x80]"), // corpus 2049
    (0x000f22000c1e0900000080060c0a7981u128, "LDG.E R10, [R12.64+UR6+0x80]"), // corpus 2049
    (0x002ee8000c1e0900000080080e097981u128, "LDG.E R9, [R14.64+UR8+0x80]"), // corpus 2049
    (0x004ea2000c1e0900000080060e077981u128, "LDG.E R7, [R14.64+UR6+0x80]"), // corpus 2049
    (0x002f22000c1e0900000080060e057981u128, "LDG.E R5, [R14.64+UR6+0x80]"), // corpus 2049
    (0x000ea8000c1e0900000080080a087981u128, "LDG.E R8, [R10.64+UR8+0x80]"), // corpus 2049
    (0x000ee8000c1e0900000080060a047981u128, "LDG.E R4, [R10.64+UR6+0x80]"), // corpus 2049
    (0x000f22000c1e0900000080040a067981u128, "LDG.E R6, [R10.64+UR4+0x80]"), // corpus 2049
    (0x000ea8000c1e09000000800808077981u128, "LDG.E R7, [R8.64+UR8+0x80]"), // corpus 2049
    (0x000ee8000c1e09000000800608057981u128, "LDG.E R5, [R8.64+UR6+0x80]"), // corpus 2049
    (0x000f22000c1e09000000800408047981u128, "LDG.E R4, [R8.64+UR4+0x80]"), // corpus 2049
];
const GOLD99: &[(u128, &str)] = &[
    (0x000e2400182ee9000a24001442430981u128, "@P0 LDG.E.EL.STRONG.GPU R67, [R66.U32+UR20+0xa2400]"), // era rt98
    (0x000e2400182ee90000240014187c0981u128, "@P0 LDG.E.EL.STRONG.GPU R124, [R24.U32+UR20+0x2400]"), // era rt98
    (0x000f6400181e0d0000000026d2dc3981u128, "@P3 LDG.E.128 R220, [R210.U32+UR38]"), // era rt98
    (0x000e2400181e0b000000000806087981u128, "LDG.E.64 R8, [R6.U32+UR8]"), // era rt98
    (0x000e2400181e0b0000080008060a7981u128, "LDG.E.64 R10, [R6.U32+UR8+0x800]"), // era rt98
    (0x000e2400181e0b0000100008060c7981u128, "LDG.E.64 R12, [R6.U32+UR8+0x1000]"), // era rt98
    (0x000e2400181e0b0000180008060e7981u128, "LDG.E.64 R14, [R6.U32+UR8+0x1800]"), // era rt98
    (0x000e2400181e0b000020000806107981u128, "LDG.E.64 R16, [R6.U32+UR8+0x2000]"), // era rt98
    (0x000e2400181e0b000028000806127981u128, "LDG.E.64 R18, [R6.U32+UR8+0x2800]"), // era rt98
    (0x000e2400181e0b000030000806147981u128, "LDG.E.64 R20, [R6.U32+UR8+0x3000]"), // era rt98
    (0x000e2400181e0b000038000806167981u128, "LDG.E.64 R22, [R6.U32+UR8+0x3800]"), // era rt98
    (0x000e2400181e0b000040000806187981u128, "LDG.E.64 R24, [R6.U32+UR8+0x4000]"), // era rt98
    (0x000e2400181e0b0000480008061a7981u128, "LDG.E.64 R26, [R6.U32+UR8+0x4800]"), // era rt98
    (0x000e2400181e0b0000500008061c7981u128, "LDG.E.64 R28, [R6.U32+UR8+0x5000]"), // era rt98
    (0x000e2400181e0b0000580008061e7981u128, "LDG.E.64 R30, [R6.U32+UR8+0x5800]"), // era rt98
    (0x000e2400181e0b000060000806207981u128, "LDG.E.64 R32, [R6.U32+UR8+0x6000]"), // era rt98
    (0x000e2400181e0b000068000806227981u128, "LDG.E.64 R34, [R6.U32+UR8+0x6800]"), // era rt98
    (0x000e2400181e0b000070000806247981u128, "LDG.E.64 R36, [R6.U32+UR8+0x7000]"), // era rt98
    (0x000e2400181e0b000078000806267981u128, "LDG.E.64 R38, [R6.U32+UR8+0x7800]"), // era rt98
    (0x000e2400181e0b000080000806287981u128, "LDG.E.64 R40, [R6.U32+UR8+0x8000]"), // era rt98
    (0x000e2400181e0b0000880008062a7981u128, "LDG.E.64 R42, [R6.U32+UR8+0x8800]"), // era rt98
    (0x000e2400181e0b0000900008062c7981u128, "LDG.E.64 R44, [R6.U32+UR8+0x9000]"), // era rt98
    (0x000e2400181e0b0000980008062e7981u128, "LDG.E.64 R46, [R6.U32+UR8+0x9800]"), // era rt98
    (0x00082400185ea9000000001a55687981u128, "LDG.E.NA.STRONG.SM R104, [R85.U32+UR26]"), // era rt98
    (0x000a2400185ea9000000001a55687981u128, "LDG.E.NA.STRONG.SM R104, [R85.U32+UR26]"), // era rt98
    (0x000a2400185ea9000000001a55697981u128, "LDG.E.NA.STRONG.SM R105, [R85.U32+UR26]"), // era rt98
    (0x00082400185ea9000030001a55697981u128, "LDG.E.NA.STRONG.SM R105, [R85.U32+UR26+0x3000]"), // era rt98
    (0x000a2400185ea9000000001a556a7981u128, "LDG.E.NA.STRONG.SM R106, [R85.U32+UR26]"), // era rt98
    (0x00082400185ea9000060001a556a7981u128, "LDG.E.NA.STRONG.SM R106, [R85.U32+UR26+0x6000]"), // era rt98
    (0x000a2400185ea9000000001a556b7981u128, "LDG.E.NA.STRONG.SM R107, [R85.U32+UR26]"), // era rt98
    (0x00082400185ea9000090001a556b7981u128, "LDG.E.NA.STRONG.SM R107, [R85.U32+UR26+0x9000]"), // era rt98
    (0x000a2400185ea9000000001a556c7981u128, "LDG.E.NA.STRONG.SM R108, [R85.U32+UR26]"), // era rt98
    (0x00082400185ea90000c0001a556c7981u128, "LDG.E.NA.STRONG.SM R108, [R85.U32+UR26+0xc000]"), // era rt98
    (0x000a2400185ea9000000001a556d7981u128, "LDG.E.NA.STRONG.SM R109, [R85.U32+UR26]"), // era rt98
    (0x00082400185ea90000f0001a556d7981u128, "LDG.E.NA.STRONG.SM R109, [R85.U32+UR26+0xf000]"), // era rt98
    (0x000a2400185ea9000000001a556e7981u128, "LDG.E.NA.STRONG.SM R110, [R85.U32+UR26]"), // era rt98
    (0x00082400185ea9000120001a556e7981u128, "LDG.E.NA.STRONG.SM R110, [R85.U32+UR26+0x12000]"), // era rt98
    (0x000a2400185ea9000000001a556f7981u128, "LDG.E.NA.STRONG.SM R111, [R85.U32+UR26]"), // era rt98
    (0x00082400185ea9000150001a556f7981u128, "LDG.E.NA.STRONG.SM R111, [R85.U32+UR26+0x15000]"), // era rt98
    (0x000a2400185ea9000000001a55707981u128, "LDG.E.NA.STRONG.SM R112, [R85.U32+UR26]"), // era rt98
    (0x00082400185ea9000180001a55707981u128, "LDG.E.NA.STRONG.SM R112, [R85.U32+UR26+0x18000]"), // era rt98
    (0x000a2400185ea9000000001a55717981u128, "LDG.E.NA.STRONG.SM R113, [R85.U32+UR26]"), // era rt98
    (0x00082400185ea90001b0001a55717981u128, "LDG.E.NA.STRONG.SM R113, [R85.U32+UR26+0x1b000]"), // era rt98
    (0x000e2400181e09000000002419fc7981u128, "LDG.E R252, [R25.U32+UR36]"), // era rt98
    (0x0009e40008100d0600002034da003986u128, "@P3 STG.E.128 [R218.U32+UR6+0x20], R52"), // era rt98
    (0x0009e40008100b0600003038da003986u128, "@P3 STG.E.64 [R218.U32+UR6+0x30], R56"), // era rt98
    (0x0009e40008100d060000203cda003986u128, "@P3 STG.E.128 [R218.U32+UR6+0x20], R60"), // era rt98
    (0x0009e40008100b0600003040da003986u128, "@P3 STG.E.64 [R218.U32+UR6+0x30], R64"), // era rt98
    (0x0009e4000810090600003844da003986u128, "@P3 STG.E [R218.U32+UR6+0x38], R68"), // era rt98
    (0x0009e4000810090600003845da003986u128, "@P3 STG.E [R218.U32+UR6+0x38], R69"), // era rt98
    (0x0009e40008100d06000010dcda003986u128, "@P3 STG.E.128 [R218.U32+UR6+0x10], R220"), // era rt98
    (0x0009e4000810090a000008d4d6004986u128, "@P4 STG.E [R214.U32+UR10+0x8], R212"), // era rt98
    (0x0009e4000820e9140024003f3c005986u128, "@P5 STG.E.EL.STRONG.GPU [R60.U32+UR20+0x2400], R63"), // era rt98
    (0x0009e40008100b080000000804007986u128, "STG.E.64 [R4.U32+UR8], R8"), // era rt98
    (0x0009e40008100b080000000a04007986u128, "STG.E.64 [R4.U32+UR8], R10"), // era rt98
    (0x0009e40008100b080000000c04007986u128, "STG.E.64 [R4.U32+UR8], R12"), // era rt98
    (0x0009e40008100b080000000e04007986u128, "STG.E.64 [R4.U32+UR8], R14"), // era rt98
    (0x0009e40008100b080000001004007986u128, "STG.E.64 [R4.U32+UR8], R16"), // era rt98
    (0x0009e40008100b080000001204007986u128, "STG.E.64 [R4.U32+UR8], R18"), // era rt98
    (0x0009e40008100b080000001404007986u128, "STG.E.64 [R4.U32+UR8], R20"), // era rt98
    (0x0009e40008100b080000001604007986u128, "STG.E.64 [R4.U32+UR8], R22"), // era rt98
    (0x0009e40008100b080000001804007986u128, "STG.E.64 [R4.U32+UR8], R24"), // era rt98
    (0x0009e40008100b080000001a04007986u128, "STG.E.64 [R4.U32+UR8], R26"), // era rt98
    (0x000be40008100b080050001c05007986u128, "STG.E.64 [R5.U32+UR8+0x5000], R28"), // era rt98
    (0x000be40008100b080050001e05007986u128, "STG.E.64 [R5.U32+UR8+0x5000], R30"), // era rt98
    (0x000be40008100b080050002005007986u128, "STG.E.64 [R5.U32+UR8+0x5000], R32"), // era rt98
    (0x000be40008100b080050002205007986u128, "STG.E.64 [R5.U32+UR8+0x5000], R34"), // era rt98
    (0x000be40008100b080050002405007986u128, "STG.E.64 [R5.U32+UR8+0x5000], R36"), // era rt98
    (0x000be40008100b080050002605007986u128, "STG.E.64 [R5.U32+UR8+0x5000], R38"), // era rt98
    (0x000be40008100b080050002805007986u128, "STG.E.64 [R5.U32+UR8+0x5000], R40"), // era rt98
    (0x000be40008100b080050002a05007986u128, "STG.E.64 [R5.U32+UR8+0x5000], R42"), // era rt98
    (0x000be40008100b080050002c05007986u128, "STG.E.64 [R5.U32+UR8+0x5000], R44"), // era rt98
    (0x000be40008100b080050002e05007986u128, "STG.E.64 [R5.U32+UR8+0x5000], R46"), // era rt98
    (0x0009e40008100924000000fc19007986u128, "STG.E [R25.U32+UR36], R252"), // era rt98
    (0x0007e40008100b0c0000003444007986u128, "STG.E.64 [R68.U32+UR12], R52"), // era rt98
    (0x0007e40008100b0c0000083644007986u128, "STG.E.64 [R68.U32+UR12+0x8], R54"), // era rt98
    (0x0007e40008100b0c0000103844007986u128, "STG.E.64 [R68.U32+UR12+0x10], R56"), // era rt98
    (0x0007e40008100b0c0000003c45007986u128, "STG.E.64 [R69.U32+UR12], R60"), // era rt98
    (0x0007e40008100b0c0000083e45007986u128, "STG.E.64 [R69.U32+UR12+0x8], R62"), // era rt98
    (0x0007e40008100b0c0000104045007986u128, "STG.E.64 [R69.U32+UR12+0x10], R64"), // era rt98
    (0x000be4000850e52a0000000972007986u128, "STG.E.NA.U16.STRONG.GPU [R114.U32+UR42], R9"), // era rt98
    (0x0007e4000850ed300000002c7200c986u128, "@!P4 STG.E.NA.128.STRONG.GPU [R114.U32+UR48], R44"), // era rt98
];

#[test]
fn bug099_decode_vendor_exact_sm103a() {
    let t = t103();
    let idx = DecodeIndex::build(&t);
    for (name, gold) in [("95", GOLD95), ("99", GOLD99)] {
        for &(w, golden) in gold {
            let d = idx.decode(w, 0, &t).unwrap_or_else(|e| panic!("{name} sm103a word {w:032x}: {e}"));
            assert_eq!(cubit::printer::to_sass(&d), golden, "{name} sm103a word {w:032x}");
        }
    }
}

#[test]
fn bug099_decode_vendor_exact_sm120() {
    let t = t120();
    let idx = DecodeIndex::build(&t);
    for (name, gold) in [("95", GOLD95), ("99", GOLD99)] {
        for &(w, golden) in gold {
            let d = idx.decode(w, 0, &t).unwrap_or_else(|e| panic!("{name} sm120 word {w:032x}: {e}"));
            assert_eq!(cubit::printer::to_sass(&d), golden, "{name} sm120 word {w:032x}");
        }
    }
}

#[test]
fn bug099_roundtrip_word_exact_both() {
    // All mode-6/3 anchors round-trip byte-exact on the sm120 table. On
    // sm103a (BUG-149) the raw `.U32+UR` LDG canonical encode is mode-2, so
    // mode-6 era words re-encode with bit92 cleared and the exact byte is
    // carried by the !rsd[92:1] overlay (pinned: overlay roundtrip exact).
    // The single mode-2 corpus word is asserted separately below.
    for t in [t120()] {
        let idx = DecodeIndex::build(&t);
        for &(w, golden) in GOLD95.iter().chain(GOLD99) {
            let word = w;
            if word == 0x002ea200081e090000000004ff007981u128 { continue; }
            let d = idx.decode(word, 0, &t).unwrap();
            let text = cubit::printer::to_sass(&d);
            assert_eq!(text, golden);
            let insn = parse_sass(&format!("{text} ;"), 0).unwrap();
            let w2 = encode_instruction(&insn, &t)
                .unwrap_or_else(|e| panic!("encode {text}: {e}"));
            assert_eq!(w2 & M96, word & M96, "roundtrip: {text}");
        }
    }
    let t = t103();
    let idx = DecodeIndex::build(&t);
    for &(word, golden) in GOLD95.iter().chain(GOLD99) {
        if word == 0x002ea200081e090000000004ff007981u128 { continue; }
        let d = idx.decode(word, 0, &t).unwrap();
        let text = cubit::printer::to_sass(&d);
        assert_eq!(text, golden);
        let insn = parse_sass(&format!("{text} ;"), 0).unwrap();
        let w2 = encode_instruction(&insn, &t)
            .unwrap_or_else(|e| panic!("encode {text}: {e}"));
        if (word >> 92) & 1 == 1 {
            // mode-6 era anchor: canonical sm103a encode clears bit92...
            assert_eq!(w2 & M96, word & !(1u128 << 92) & M96,
                       "canonical mode-2 roundtrip: {text}");
            // ...and the era byte stays reachable through the overlay.
            let ov = parse_sass(&format!("{text} !rsd[92:1] ;"), 0).unwrap();
            assert_eq!(encode_instruction(&ov, &t).unwrap() & M96, word & M96,
                       "rsd overlay roundtrip: {text}");
        } else {
            assert_eq!(w2 & M96, word & M96, "roundtrip: {text}");
        }
    }
}

#[test]
fn bug099_mode2_rz_documented_residue() {
    // `LDG.E R0, [RZ.U32+UR4]` (mode [92:90]=2): decodes vendor-exact on both
    // tables; text encodes to the legal era-proven mode-6 word (documented).
    let word = 0x002ea200081e090000000004ff007981u128;
    let mode6 = 0x002ea200181e090000000004ff007981u128;
    // sm103a (BUG-149): canonical encode = mode-2 (its own nvcc evidence);
    // the era mode-6 word stays byte-reachable via the !rsd[92:1] overlay.
    {
        let t = t103();
        let idx = DecodeIndex::build(&t);
        let d = idx.decode(word, 0, &t).unwrap();
        let text = cubit::printer::to_sass(&d);
        assert_eq!(text, "LDG.E R0, [RZ.U32+UR4]");
        let insn = parse_sass(&format!("{text} ;"), 0).unwrap();
        let w2 = encode_instruction(&insn, &t).unwrap();
        assert_eq!(w2 & M96, word & M96, "sm103a text encodes canonical mode-2");
        let ov = parse_sass(&format!("{text} !rsd[92:1] ;"), 0).unwrap();
        assert_eq!(encode_instruction(&ov, &t).unwrap() & M96, mode6 & M96,
                   "rsd overlay reproduces the era mode-6 word");
    }
    // sm120: unchanged -- mode-6 is the vendor bin truth there.
    {
        let t = t120();
        let idx = DecodeIndex::build(&t);
        let d = idx.decode(word, 0, &t).unwrap();
        assert_eq!(cubit::printer::to_sass(&d), "LDG.E R0, [RZ.U32+UR4]");
        let insn = parse_sass("LDG.E R0, [RZ.U32+UR4] ;", 0).unwrap();
        let w2 = encode_instruction(&insn, &t).unwrap();
        assert_eq!(w2 & M96, mode6 & M96, "sm120 text encodes mode-6 form");
    }
}

#[test]
fn bug099_desc_population_isolated() {
    // Legit desc-form words must keep their exact desc render (claim-census
    // isolation): universe diff pre/post = exactly the 43 raw-UR slots.
    // `STG.E desc[UR6][R2.64], R5` (ug.cubin) goes through the desc world.
    let word = 0x000fe2000c1019060000000502007986u128; // 86790002050000000619100c00e20f00 (le-bytes)
    for t in [t103(), t120()] {
        let idx = DecodeIndex::build(&t);
        let d = idx.decode(word, 0, &t).unwrap();
        assert_eq!(cubit::printer::to_sass(&d), "STG.E desc[UR6][R2.64], R5");
    }
}

#[test]
fn bug099_encoder_width_routing() {
    // `.64+UR` text must land on the addr_width=64 row (mode-3 word), not the
    // ".U32" donor row — regression pin for the pre-fix silent mis-encode.
    for t in [t103(), t120()] {
        let insn = parse_sass("LDG.E R10, [R12.64+UR12+0x80] ;", 0).unwrap();
        let w = encode_instruction(&insn, &t).unwrap();
        assert_eq!(w & M96, 0x000ea8000c1e09000000800c0c0a7981u128 & M96);
    }
    // `.U32+UR` text lands on the addr_width=U32 row; the mode byte is the
    // per-arch nvcc canonical (BUG-149): mode-2 on sm103a, mode-6 on sm120.
    let (t, want) = (t103(), 0x000e2400081e0b000008000806087981u128);
    let insn = parse_sass("LDG.E.64 R8, [R6.U32+UR8+0x800] ;", 0).unwrap();
    assert_eq!(encode_instruction(&insn, &t).unwrap() & M96, want & M96);
    let (t, want) = (t120(), 0x000e2400181e0b000008000806087981u128);
    let insn = parse_sass("LDG.E.64 R8, [R6.U32+UR8+0x800] ;", 0).unwrap();
    assert_eq!(encode_instruction(&insn, &t).unwrap() & M96, want & M96);
}

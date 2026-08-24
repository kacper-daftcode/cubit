//! BUG-045 (F2-kanoniczny, residual z BUG-030): ULOP3 forma UP-dest z tok4=UR
//! oraz kanonikalizacja UPT-dest.
//!
//! Mapa dekodowania ULOP3.LUT (korpus i93, 14777 slow, census the internal fix archive
//!   bit11=1 -> tok4 imm32:  ULOP3_UR_UR_II_UR_II_UP (bezin. UP-dest)
//!                           ULOP3_UP_UR_UR_II_UR_II_UP (UP-dest)
//!   bit11=0 -> tok4 UR:     ULOP3_UR_UR_UR_UR_II_UP  (bezin. UP-dest)
//!                           ULOP3_UP_UR_UR_UR_UR_II_UP (UP-dest) <- TEN FIX
//!
//! (A) HOLE (46 rekordow / 24 unikalne slowa z cublasLt/cudnn sm_120):
//!     `ULOP3.LUT UPd, URZ, URa, URb, URZ, 0xc0, !UPT` nie dekodowalo sie
//!     ("no instruction matches ... at opcode 0x292"). W tabeli byl wiersz-
//!     fantom `ULOP3_UP_UR_UR_UR_UR_II_UP` (count=4, scrambled-pola:
//!     imm 1b@24, zadne pole nie ekstraktowalo dest-UP). Wiersz zastapiony
//!     fitem z 24 zlotych slow: dest-UP 3b@81 straight, tok2 [23:16]=ff
//!     (UR-dest URZ — stala w zlocie, zaszta), tok3 ureg 6b@24 (max UR38),
//!     tok4 ureg 5b@32 (max UR27), tok5 [71:64]=ff (zaszta), tok6 lut 8b@72,
//!     tok7 !UPT ([90:87]=f), bit11=0 w and_base (rozdzielcza vs imm-forma).
//! (B) COSMETIC (7 rekordow / 3 unikalne): UP-dest == UPT jest kodowaniem
//!     formy BEZ destu — wszystkie bezdestne slowa zlota maja sel[83:81]=7
//!     zaszyte (histogram (7,*): 6329+4238). nvdisasm operand opuszcza, cubit
//!     drukowal "UPT, " (bitowo rownowazne). Printer: drop wiodacego UPT dla
//!     ULOP3 z UP-pierwszym operandem; re-encode idzie wierszem UR_* (sel=7
//!     zaszyte w and_base) -> bajty identyczne.
//! (C) ENCODER GAP: wiersz ULOP3_UR_UR_II_UR_II_UP nie mial pola tok4
//!     ([71:64]=ff zaszyte) -> tekst z URc!=URZ odrzucany ("operand 4 (UR7)
//!     has no field able to encode it") mimo 7 zlotych slow w korpusie.
//!     Pole tok4 ureg_ff 8b@64 dodane, vm rozszerzona, and_base[71:64] = 0,
//!     count 35 -> 42.

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::table::IsaTable;

fn t120() -> IsaTable {
    IsaTable::load(std::path::Path::new("tables/sm120.json")).unwrap()
}

const SCHED: u128 = 0xFFFF_FFFFu128 << 96;

fn enc(text: &str) -> Result<u128, String> {
    let insn = parse_sass(text, 0).unwrap_or_else(|e| panic!("parse {text:?}: {e}"));
    encode_instruction(&insn, &t120()).map_err(|e| format!("{e}"))
}

fn dec(word: u128) -> String {
    let idx = DecodeIndex::build(&t120());
    let d = idx.decode(word, 0, &t120()).expect("decode failed");
    format!("{d}").trim_end_matches([' ', ';']).to_string()
}

/// 24+3 zlote slowa z i93 harvest (nvdisasm -c, cublasLt/cudnn sm_120).
/// Dowody: the internal fix archive
const GOLD: &[(u128, &str)] = &[
    (0x000fe2000f80c0ff0000000410ff7292, "ULOP3.LUT UP0, URZ, UR16, UR4, URZ, 0xc0, !UPT"),
    (0x000fe2000f80c0ff0000000412ff7292, "ULOP3.LUT UP0, URZ, UR18, UR4, URZ, 0xc0, !UPT"),
    (0x000fe2000f80c0ff0000000414ff7292, "ULOP3.LUT UP0, URZ, UR20, UR4, URZ, 0xc0, !UPT"),
    (0x000fe2000f80c0ff0000000416ff7292, "ULOP3.LUT UP0, URZ, UR22, UR4, URZ, 0xc0, !UPT"),
    (0x000fe2000f80c0ff0000000418ff7292, "ULOP3.LUT UP0, URZ, UR24, UR4, URZ, 0xc0, !UPT"),
    (0x000fe2000f80c0ff000000041aff7292, "ULOP3.LUT UP0, URZ, UR26, UR4, URZ, 0xc0, !UPT"),
    (0x000fe2000f80c0ff000000041eff7292, "ULOP3.LUT UP0, URZ, UR30, UR4, URZ, 0xc0, !UPT"),
    (0x000fe2000f80c0ff000000051cff7292, "ULOP3.LUT UP0, URZ, UR28, UR5, URZ, 0xc0, !UPT"),
    (0x000fe2000f80c0ff0000000812ff7292, "ULOP3.LUT UP0, URZ, UR18, UR8, URZ, 0xc0, !UPT"),
    (0x000fe2000f80c0ff0000001112ff7292, "ULOP3.LUT UP0, URZ, UR18, UR17, URZ, 0xc0, !UPT"),
    (0x000fe2000f80c0ff0000001114ff7292, "ULOP3.LUT UP0, URZ, UR20, UR17, URZ, 0xc0, !UPT"),
    (0x000fe2000f80c0ff000000111cff7292, "ULOP3.LUT UP0, URZ, UR28, UR17, URZ, 0xc0, !UPT"),
    (0x000fe2000f80c0ff000000131cff7292, "ULOP3.LUT UP0, URZ, UR28, UR19, URZ, 0xc0, !UPT"),
    (0x000fe2000f80c0ff0000001518ff7292, "ULOP3.LUT UP0, URZ, UR24, UR21, URZ, 0xc0, !UPT"),
    (0x000fe2000f80c0ff0000001614ff7292, "ULOP3.LUT UP0, URZ, UR20, UR22, URZ, 0xc0, !UPT"),
    (0x000fe2000f80c0ff0000001924ff7292, "ULOP3.LUT UP0, URZ, UR36, UR25, URZ, 0xc0, !UPT"),
    (0x000fe2000f80c0ff0000001926ff7292, "ULOP3.LUT UP0, URZ, UR38, UR25, URZ, 0xc0, !UPT"),
    (0x000fe2000f80c0ff0000001b26ff7292, "ULOP3.LUT UP0, URZ, UR38, UR27, URZ, 0xc0, !UPT"),
    (0x002fe2000f82c0ff0000000608ff7292, "ULOP3.LUT UP1, URZ, UR8, UR6, URZ, 0xc0, !UPT"),
    (0x002fe2000f82c0ff0000000706ff7292, "ULOP3.LUT UP1, URZ, UR6, UR7, URZ, 0xc0, !UPT"),
    (0x002fe2000f82c0ff0000000804ff7292, "ULOP3.LUT UP1, URZ, UR4, UR8, URZ, 0xc0, !UPT"),
    (0x002fe2000f82c0ff0000000906ff7292, "ULOP3.LUT UP1, URZ, UR6, UR9, URZ, 0xc0, !UPT"),
    (0x004fe2000f82c0ff0000000608ff7292, "ULOP3.LUT UP1, URZ, UR8, UR6, URZ, 0xc0, !UPT"),
    (0x008fe4000f82c0ff0000000504ff7292, "ULOP3.LUT UP1, URZ, UR4, UR5, URZ, 0xc0, !UPT"),
    // (B)+(C): UPT-dest -> forma bez destu; URc != URZ enkodowalne
    (0x000fc8000f8ef8070000000704047892, "ULOP3.LUT UR4, UR4, 0x7, UR7, 0xf8, !UPT"),
    (0x000fe2000f8ef8170000000707077892, "ULOP3.LUT UR7, UR7, 0x7, UR23, 0xf8, !UPT"),
    (0x000fe2000f8ef8180000000707077892, "ULOP3.LUT UR7, UR7, 0x7, UR24, 0xf8, !UPT"),
];

/// Regresja sasiednich form (klasy 6322/451 z censusu — bez zmian w renderze).
const NEIGHBORS: &[(u128, &str)] = &[
    (0x000fe2000f8ec0fffffffff00b0b7892, "ULOP3.LUT UR11, UR11, 0xfffffff0, URZ, 0xc0, !UPT"),
    (0x000fe2000f8eb807000000060a067292, "ULOP3.LUT UR6, UR10, UR6, UR7, 0xb8, !UPT"),
    // imm-forma UP-dest (wiersz z BUG-012; rowniez 2 linie w rt98_pub)
    (0x000fe2000f82c03f00000001133f7892, "ULOP3.LUT UP1, UR63, UR19, 0x1, UR63, 0xc0, !UPT"),
];

#[test]
fn bug045_gold_decode_and_reencode_byte_exact() {
    for (word, text) in GOLD.iter().chain(NEIGHBORS) {
        let got = dec(*word);
        assert_eq!(&got, text, "render differs for {word:#034x}");
        let code = enc(text).unwrap();
        assert_eq!(code & !SCHED, word & !SCHED, "re-encode differs for {text:?}");
    }
}

#[test]
fn bug045_upt_explicit_dest_encodes_same_as_canonical() {
    // Tekst z jawnym UPT-destem (imm-forma) i forma bez destu daja to samo slowo.
    let explicit = enc("ULOP3.LUT UPT, UR4, UR4, 0x7, UR7, 0xf8, !UPT").unwrap();
    let canonical = enc("ULOP3.LUT UR4, UR4, 0x7, UR7, 0xf8, !UPT").unwrap();
    assert_eq!(explicit & !SCHED, canonical & !SCHED);
    // i dekoduje sie do formy kanonicznej (po druku z powrotem to samo slowo)
    let text = dec(explicit);
    assert_eq!(text, "ULOP3.LUT UR4, UR4, 0x7, UR7, 0xf8, !UPT");
}

#[test]
fn bug045_hole_fail_closed_outside_gold() {
    // tok2 (UR-dest) zaszyty URZ w zlocie — inny UR = glosny blad, nie silent-drop
    enc("ULOP3.LUT UP0, UR5, UR16, UR4, URZ, 0xc0, !UPT")
        .expect_err("UR dest other than URZ is outside fitted gold evidence");
    // tok5 zaszyty URZ analogicznie
    enc("ULOP3.LUT UP0, URZ, UR16, UR4, UR5, 0xc0, !UPT")
        .expect_err("src URc other than URZ is outside fitted gold evidence");
}

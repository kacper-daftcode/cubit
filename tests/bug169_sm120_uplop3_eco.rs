//! BUG-169 (F2-iter80, front2/blind): ekosystem UPLOP3/PLOP3 na sm120.
//! Zrodlo: nota 168 sec.8 (169-kand). ROOT: napis "upred" w tabelach
//! trafial na Extraction::Pred (kolaps enuma) => key_field_consistency_score
//! nigdy nie widzial upred (is_upred martwe); junk-wiersz
//! UPLOP3_UP_P_P_P_P_II_II (0 kotwic) wygrywal tiebreak z prawdziwa
//! UP-forma i fabrykowal 17/107 uniq slow korpusowych na sm120.
//! Arbitraz nvdisasm-13.3.73 (work/bug169/arb, kubiny sm120-class):
//!   dest[81:84) tok2[84:87) tok3[87:90)+neg@90 tok4[77:80)+neg@80
//!   tok5[68:71)+neg@71 (bit71 NIE nalezy do v1 -- sonda tok5b71)
//!   v1 = [64:67) | [72:77)<<3  pelne 8 bitow (sonda bit64 -> 0x1);
//!   v2 = [16:24); bit67 inert (fail-closed, doktryna t168_5).
//! Poprawki danych: (1) wiersz UPLOP3.LUT_UP_UP_UP_UP_UP_II_II na prawo
//! powyzej (era-stub mial imm_shr6@75/imm_shr2@18 + 2 pola), (2) kasacja
//! junk UPLOP3_UP_P_P_P_P_II_II, (3) PLOP3.LUT_P_P_P_P_UP_II_II tok6:
//! swap imm/imm_shr5 -> imm/imm_shr3 (59/423 uniq swap-class), (4) twin
//! PLOP3_P_P_P_P_UP_II_II += imm@64(3) (315/423, dotychczas poprawne
//! tylko dla low3==0 -- latentne).
//! Encoder: era-030 lattice-check (ops 6/7: {0x0,0x40,0x80,0xc0}x{0,4,8,0xc})
//! POZOSTAJE na main (klasa 0xf8/0x2 fail-closed asm-side) -- relaks do
//! pelnego 8-bit prawa = decyzja compose z parked-168 (kolizja linii
//! check_uplop3_lut_lattice; dowody oddania: sonde work/bug169/arb).
use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::table::IsaTable;

const SCHED: u128 = 0xFFFF_FFFFu128 << 96;

fn t120() -> IsaTable { IsaTable::load(std::path::Path::new("tables/sm120.json")).unwrap() }
fn t103a() -> IsaTable { IsaTable::load(std::path::Path::new("tables/sm103a.json")).unwrap() }

fn enc(t:&IsaTable,text:&str)->u128{
    let insn=parse_sass(text,0).expect("parse");
    encode_instruction(&insn,t).expect("encode") & !SCHED
}
fn dec(idx:&DecodeIndex,w:u128,t:&IsaTable)->String{
    let d=idx.decode(w,0,t).expect("decode");
    let s=cubit::printer::to_sass(&d);
    let s=s.split("/* @sched").next().unwrap().trim().to_string();
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}
fn dec_fail(idx:&DecodeIndex,w:u128,t:&IsaTable)->bool{ idx.decode(w,0,t).is_err() }

/// 107 uniq korpusowych slow UPLOP3.LUT (hexdb 32.2M; jak w 168 zrodlo slow).
const CORPUS107: &[(u128,&str)] = &[
    (0x000fc40003f0f070000000000008789cu128, "UPLOP3.LUT UP0, UPT, UPT, UPT, UPT, 0x80, 0x8"),
    (0x000fe20003f0e870000000000004789cu128, "UPLOP3.LUT UP0, UPT, UPT, UPT, UPT, 0x40, 0x4"),
    (0x000fc60003f0e870000000000004789cu128, "UPLOP3.LUT UP0, UPT, UPT, UPT, UPT, 0x40, 0x4"),
    (0x000fe40003f0f070000000000008789cu128, "UPLOP3.LUT UP0, UPT, UPT, UPT, UPT, 0x80, 0x8"),
    (0x000fe40003f0e870000000000004789cu128, "UPLOP3.LUT UP0, UPT, UPT, UPT, UPT, 0x40, 0x4"),
    (0x000fe20003f0f070000000000008789cu128, "UPLOP3.LUT UP0, UPT, UPT, UPT, UPT, 0x80, 0x8"),
    (0x000fc80000f21f7000000000008f789cu128, "UPLOP3.LUT UP1, UPT, UP1, UP0, UPT, 0xf8, 0x8f"),
    (0x000fc60003f0f070000000000008789cu128, "UPLOP3.LUT UP0, UPT, UPT, UPT, UPT, 0x80, 0x8"),
    (0x000fd60003f0e870000000000004789cu128, "UPLOP3.LUT UP0, UPT, UPT, UPT, UPT, 0x40, 0x4"),
    (0x000fe40003f0f030000000000008a89cu128, "@!UP2 UPLOP3.LUT UP0, UPT, UPT, UPT, UP3, 0x80, 0x8"),
    (0x000fe20003f2f040000000000008a89cu128, "@!UP2 UPLOP3.LUT UP1, UPT, UPT, UPT, UP4, 0x80, 0x8"),
    (0x000fe20000703f7000000000008f789cu128, "UPLOP3.LUT UP0, UPT, UP0, UP1, UPT, 0xf8, 0x8f"),
    (0x000fc40003f0f030000000000008a89cu128, "@!UP2 UPLOP3.LUT UP0, UPT, UPT, UPT, UP3, 0x80, 0x8"),
    (0x000fe40000703f7000000000008f789cu128, "UPLOP3.LUT UP0, UPT, UP0, UP1, UPT, 0xf8, 0x8f"),
    (0x000fc60003f0f030000000000008a89cu128, "@!UP2 UPLOP3.LUT UP0, UPT, UPT, UPT, UP3, 0x80, 0x8"),
    (0x000fc60003f2f040000000000008a89cu128, "@!UP2 UPLOP3.LUT UP1, UPT, UPT, UPT, UP4, 0x80, 0x8"),
    (0x000fc80000703f7000000000008f789cu128, "UPLOP3.LUT UP0, UPT, UP0, UP1, UPT, 0xf8, 0x8f"),
    (0x000fe20003f0f030000000000008a89cu128, "@!UP2 UPLOP3.LUT UP0, UPT, UPT, UPT, UP3, 0x80, 0x8"),
    (0x000fc40000703f7000000000008f789cu128, "UPLOP3.LUT UP0, UPT, UP0, UP1, UPT, 0xf8, 0x8f"),
    (0x000fc80003f2f040000000000008a89cu128, "@!UP2 UPLOP3.LUT UP1, UPT, UPT, UPT, UP4, 0x80, 0x8"),
    (0x000fc40003f2f040000000000008a89cu128, "@!UP2 UPLOP3.LUT UP1, UPT, UPT, UPT, UP4, 0x80, 0x8"),
    (0x000fe40003f2f040000000000008a89cu128, "@!UP2 UPLOP3.LUT UP1, UPT, UPT, UPT, UP4, 0x80, 0x8"),
    (0x000fc80003f0f030000000000008a89cu128, "@!UP2 UPLOP3.LUT UP0, UPT, UPT, UPT, UP3, 0x80, 0x8"),
    (0x000fc40003f0e870000000000004789cu128, "UPLOP3.LUT UP0, UPT, UPT, UPT, UPT, 0x40, 0x4"),
    (0x000fc80000705f7000000000008f789cu128, "UPLOP3.LUT UP0, UPT, UP0, UP2, UPT, 0xf8, 0x8f"),
    (0x000fc80003f0e800000000000004789cu128, "UPLOP3.LUT UP0, UPT, UPT, UPT, UP0, 0x40, 0x4"),
    (0x000fe40003f4f070000000000008789cu128, "UPLOP3.LUT UP2, UPT, UPT, UPT, UPT, 0x80, 0x8"),
    (0x000fee0003f2f070000000000008789cu128, "UPLOP3.LUT UP1, UPT, UPT, UPT, UPT, 0x80, 0x8"),
    (0x000fe40003f2e870000000000004789cu128, "UPLOP3.LUT UP1, UPT, UPT, UPT, UPT, 0x40, 0x4"),
    (0x000fe40003f2f070000000000008789cu128, "UPLOP3.LUT UP1, UPT, UPT, UPT, UPT, 0x80, 0x8"),
    (0x000fe20003f2f070000000000008789cu128, "UPLOP3.LUT UP1, UPT, UPT, UPT, UPT, 0x80, 0x8"),
    (0x000fc60003f2f070000000000008789cu128, "UPLOP3.LUT UP1, UPT, UPT, UPT, UPT, 0x80, 0x8"),
    (0x000fc40003f2f070000000000008789cu128, "UPLOP3.LUT UP1, UPT, UPT, UPT, UPT, 0x80, 0x8"),
    (0x000fe20003f4e870000000000004789cu128, "UPLOP3.LUT UP2, UPT, UPT, UPT, UPT, 0x40, 0x4"),
    (0x000fe20003f4f070000000000008789cu128, "UPLOP3.LUT UP2, UPT, UPT, UPT, UPT, 0x80, 0x8"),
    (0x000fe40003f8f070000000000008789cu128, "UPLOP3.LUT UP4, UPT, UPT, UPT, UPT, 0x80, 0x8"),
    (0x000fc80003f0f070000000000008789cu128, "UPLOP3.LUT UP0, UPT, UPT, UPT, UPT, 0x80, 0x8"),
    (0x000fe40000723f7000000000008f789cu128, "UPLOP3.LUT UP1, UPT, UP0, UP1, UPT, 0xf8, 0x8f"),
    (0x000fd60003f0e800000000000004789cu128, "UPLOP3.LUT UP0, UPT, UPT, UPT, UP0, 0x40, 0x4"),
    (0x000fc60000f25f7000000000008f789cu128, "UPLOP3.LUT UP1, UPT, UP1, UP2, UPT, 0xf8, 0x8f"),
    (0x002fd60003f0e870000000000004789cu128, "UPLOP3.LUT UP0, UPT, UPT, UPT, UPT, 0x40, 0x4"),
    (0x000fc80003f0e870000000000004789cu128, "UPLOP3.LUT UP0, UPT, UPT, UPT, UPT, 0x40, 0x4"),
    (0x000fd60003f0f070000000000008789cu128, "UPLOP3.LUT UP0, UPT, UPT, UPT, UPT, 0x80, 0x8"),
    (0x000fe40003f6f070000000000008789cu128, "UPLOP3.LUT UP3, UPT, UPT, UPT, UPT, 0x80, 0x8"),
    (0x000fc80000705f7000000000008f589cu128, "@UP5 UPLOP3.LUT UP0, UPT, UP0, UP2, UPT, 0xf8, 0x8f"),
    (0x000fc60003f6e800000000000004589cu128, "@UP5 UPLOP3.LUT UP3, UPT, UPT, UPT, UP0, 0x40, 0x4"),
    (0x000fe40003f8e870000000000004789cu128, "UPLOP3.LUT UP4, UPT, UPT, UPT, UPT, 0x40, 0x4"),
    (0x000fe80000723f7000000000008f789cu128, "UPLOP3.LUT UP1, UPT, UP0, UP1, UPT, 0xf8, 0x8f"),
    (0x000fe40000743f7000000000008f789cu128, "UPLOP3.LUT UP2, UPT, UP0, UP1, UPT, 0xf8, 0x8f"),
    (0x000ff20003f2f070000000000008789cu128, "UPLOP3.LUT UP1, UPT, UPT, UPT, UPT, 0x80, 0x8"),
    (0x000fec0003f2e820000000000004089cu128, "@UP0 UPLOP3.LUT UP1, UPT, UPT, UPT, UP2, 0x40, 0x4"),
    (0x000fe40003fcf070000000000008789cu128, "UPLOP3.LUT UP6, UPT, UPT, UPT, UPT, 0x80, 0x8"),
    (0x000fe40003fae870000000000004789cu128, "UPLOP3.LUT UP5, UPT, UPT, UPT, UPT, 0x40, 0x4"),
    (0x000fc40003f8e870000000000004789cu128, "UPLOP3.LUT UP4, UPT, UPT, UPT, UPT, 0x40, 0x4"),
    (0x000fe40003fcf070000000000008889cu128, "@!UP0 UPLOP3.LUT UP6, UPT, UPT, UPT, UPT, 0x80, 0x8"),
    (0x000fe40003fae870000000000004889cu128, "@!UP0 UPLOP3.LUT UP5, UPT, UPT, UPT, UPT, 0x40, 0x4"),
    (0x000fe40003f8f070000000000008889cu128, "@!UP0 UPLOP3.LUT UP4, UPT, UPT, UPT, UPT, 0x80, 0x8"),
    (0x000fe20003f6f070000000000008889cu128, "@!UP0 UPLOP3.LUT UP3, UPT, UPT, UPT, UPT, 0x80, 0x8"),
    (0x000fe20003f6e870000000000004789cu128, "UPLOP3.LUT UP3, UPT, UPT, UPT, UPT, 0x40, 0x4"),
    (0x000fe40003fce870000000000004789cu128, "UPLOP3.LUT UP6, UPT, UPT, UPT, UPT, 0x40, 0x4"),
    (0x000fe40003faf070000000000008789cu128, "UPLOP3.LUT UP5, UPT, UPT, UPT, UPT, 0x80, 0x8"),
    (0x000fc40003fae870000000000004789cu128, "UPLOP3.LUT UP5, UPT, UPT, UPT, UPT, 0x40, 0x4"),
    (0x000fe20003f6f070000000000008789cu128, "UPLOP3.LUT UP3, UPT, UPT, UPT, UPT, 0x80, 0x8"),
    (0x000fe40003f2f000000000000008789cu128, "UPLOP3.LUT UP1, UPT, UPT, UPT, UP0, 0x80, 0x8"),
    (0x000fc60003f4f010000000000008789cu128, "UPLOP3.LUT UP2, UPT, UPT, UPT, UP1, 0x80, 0x8"),
    (0x000fe20003f2e870000000000004789cu128, "UPLOP3.LUT UP1, UPT, UPT, UPT, UPT, 0x40, 0x4"),
    (0x00afd60003f0e870000000000004789cu128, "UPLOP3.LUT UP0, UPT, UPT, UPT, UPT, 0x40, 0x4"),
    (0x006fd60003f0e870000000000004789cu128, "UPLOP3.LUT UP0, UPT, UPT, UPT, UPT, 0x40, 0x4"),
    (0x000fe20003f0e800000000000004789cu128, "UPLOP3.LUT UP0, UPT, UPT, UPT, UP0, 0x40, 0x4"),
    (0x007fd60003f0e870000000000004789cu128, "UPLOP3.LUT UP0, UPT, UPT, UPT, UPT, 0x40, 0x4"),
    (0x000fde0003f0e870000000000004789cu128, "UPLOP3.LUT UP0, UPT, UPT, UPT, UPT, 0x40, 0x4"),
    (0x000fd80003f0e870000000000004789cu128, "UPLOP3.LUT UP0, UPT, UPT, UPT, UPT, 0x40, 0x4"),
    (0x000fc60003f4e870000000000004789cu128, "UPLOP3.LUT UP2, UPT, UPT, UPT, UPT, 0x40, 0x4"),
    (0x001fd60003f0e870000000000004789cu128, "UPLOP3.LUT UP0, UPT, UPT, UPT, UPT, 0x40, 0x4"),
    (0x008fd60003f0e870000000000004789cu128, "UPLOP3.LUT UP0, UPT, UPT, UPT, UPT, 0x40, 0x4"),
    (0x000fe20003f0f020000000000008989cu128, "@!UP1 UPLOP3.LUT UP0, UPT, UPT, UPT, UP2, 0x80, 0x8"),
    (0x000fde0003f2f030000000000008a89cu128, "@!UP2 UPLOP3.LUT UP1, UPT, UPT, UPT, UP3, 0x80, 0x8"),
    (0x000fe20003f0f040000000000008a89cu128, "@!UP2 UPLOP3.LUT UP0, UPT, UPT, UPT, UP4, 0x80, 0x8"),
    (0x000fe40000f40072000000000020789cu128, "UPLOP3.LUT UP2, UPT, UP1, UP0, UPT, 0x2, 0x20"),
    (0x000fc60003f0f040000000000008a89cu128, "@!UP2 UPLOP3.LUT UP0, UPT, UPT, UPT, UP4, 0x80, 0x8"),
    (0x000fd80000f40072000000000020789cu128, "UPLOP3.LUT UP2, UPT, UP1, UP0, UPT, 0x2, 0x20"),
    (0x000fe20003f2f030000000000008a89cu128, "@!UP2 UPLOP3.LUT UP1, UPT, UPT, UPT, UP3, 0x80, 0x8"),
    (0x000fc80003f0f040000000000008a89cu128, "@!UP2 UPLOP3.LUT UP0, UPT, UPT, UPT, UP4, 0x80, 0x8"),
    (0x000fe20000f40072000000000020789cu128, "UPLOP3.LUT UP2, UPT, UP1, UP0, UPT, 0x2, 0x20"),
    (0x000fce0003f0f070000000000008789cu128, "UPLOP3.LUT UP0, UPT, UPT, UPT, UPT, 0x80, 0x8"),
    (0x003fd60003f0e870000000000004789cu128, "UPLOP3.LUT UP0, UPT, UPT, UPT, UPT, 0x40, 0x4"),
    (0x000fde0003f0f030000000000008a89cu128, "@!UP2 UPLOP3.LUT UP0, UPT, UPT, UPT, UP3, 0x80, 0x8"),
    (0x000fd80000703f7000000000008f789cu128, "UPLOP3.LUT UP0, UPT, UP0, UP1, UPT, 0xf8, 0x8f"),
    (0x000fe40003f4e870000000000004789cu128, "UPLOP3.LUT UP2, UPT, UPT, UPT, UPT, 0x40, 0x4"),
    (0x000fd60003f4e840000000000004389cu128, "@UP3 UPLOP3.LUT UP2, UPT, UPT, UPT, UP4, 0x40, 0x4"),
    (0x000fc60003f4f070000000000008789cu128, "UPLOP3.LUT UP2, UPT, UPT, UPT, UPT, 0x80, 0x8"),
    (0x000fe60003f4f070000000000008789cu128, "UPLOP3.LUT UP2, UPT, UPT, UPT, UPT, 0x80, 0x8"),
    (0x000fe20003f8f050000000000008789cu128, "UPLOP3.LUT UP4, UPT, UPT, UPT, UP5, 0x80, 0x8"),
    (0x000fe40003f6e870000000000004789cu128, "UPLOP3.LUT UP3, UPT, UPT, UPT, UPT, 0x40, 0x4"),
    (0x000fe20003f6f000000000000008989cu128, "@!UP1 UPLOP3.LUT UP3, UPT, UPT, UPT, UP0, 0x80, 0x8"),
    (0x000fe20003f6e840000000000004889cu128, "@!UP0 UPLOP3.LUT UP3, UPT, UPT, UPT, UP4, 0x40, 0x4"),
    (0x000ff60003f6f010000000000008089cu128, "@UP0 UPLOP3.LUT UP3, UPT, UPT, UPT, UP1, 0x80, 0x8"),
    (0x000fe20003f2f000000000000008a89cu128, "@!UP2 UPLOP3.LUT UP1, UPT, UPT, UPT, UP0, 0x80, 0x8"),
    (0x000fe20003f2e840000000000004789cu128, "UPLOP3.LUT UP1, UPT, UPT, UPT, UP4, 0x40, 0x4"),
    (0x000ff60003f2f020000000000008089cu128, "@UP0 UPLOP3.LUT UP1, UPT, UPT, UPT, UP2, 0x80, 0x8"),
    (0x000fd60000703f7000000000008f789cu128, "UPLOP3.LUT UP0, UPT, UP0, UP1, UPT, 0xf8, 0x8f"),
    (0x000fc60000703f7000000000008f789cu128, "UPLOP3.LUT UP0, UPT, UP0, UP1, UPT, 0xf8, 0x8f"),
    (0x000fc40003f4e870000000000004789cu128, "UPLOP3.LUT UP2, UPT, UPT, UPT, UPT, 0x40, 0x4"),
    (0x000fc40003f2e870000000000004789cu128, "UPLOP3.LUT UP1, UPT, UPT, UPT, UPT, 0x40, 0x4"),
    (0x000fe20003fae870000000000004789cu128, "UPLOP3.LUT UP5, UPT, UPT, UPT, UPT, 0x40, 0x4"),
    (0x000fc40003fce870000000000004789cu128, "UPLOP3.LUT UP6, UPT, UPT, UPT, UPT, 0x40, 0x4"),
    (0x000fe20003f8e870000000000004789cu128, "UPLOP3.LUT UP4, UPT, UPT, UPT, UPT, 0x40, 0x4"),
];
/// Matryca arbitrazu (nvdisasm 13.3.73 odpowiedzi, work/bug169/arb_names.json).
const ARB: &[(u128,&str)] = &[
    (0x000fc40003d0f070000000000008789cu128, "UPLOP3.LUT UP0, UP5, UPT, UPT, UPT, 0x80, 0x8"), // tok2_84_5
    (0x000fc4000380f070000000000008789cu128, "UPLOP3.LUT UP0, UP0, UPT, UPT, UPT, 0x80, 0x8"), // tok2_84_0
    (0x000fc40003a0f070000000000008789cu128, "UPLOP3.LUT UP0, UP2, UPT, UPT, UPT, 0x80, 0x8"), // tok2_84_2
    (0x000fc40007f0f070000000000008789cu128, "UPLOP3.LUT UP0, UPT, !UPT, UPT, UPT, 0x80, 0x8"), // tok3neg90
    (0x000fc40003f1f070000000000008789cu128, "UPLOP3.LUT UP0, UPT, UPT, !UPT, UPT, 0x80, 0x8"), // tok4b80
    (0x000fc40003f0f0f0000000000008789cu128, "UPLOP3.LUT UP0, UPT, UPT, UPT, !UPT, 0x80, 0x8"), // tok5b71
    (0x000fc40003fef070000000000008789cu128, "UPLOP3.LUT UPT, UPT, UPT, UPT, UPT, 0x80, 0x8"), // dest7
    (0x000fc400037ef070000000000008789cu128, "UPLOP3.LUT UPT, UPT, UP6, UPT, UPT, 0x80, 0x8"), // dest7_tok3_6
    (0x000fc40003f0f572000000000008789cu128, "UPLOP3.LUT UP0, UPT, UPT, UPT, UPT, 0xaa, 0x8"), // v1_aa
    (0x000fc40003f0fff60000000000ff789cu128, "UPLOP3.LUT UP0, UPT, UPT, UPT, !UPT, 0xfe, 0xff"), // v1fe_v2ff
    (0x000fc40003f0f074000000000008789cu128, "UPLOP3.LUT UP0, UPT, UPT, UPT, UPT, 0x84, 0x8"), // b66
    (0x000fc40003f0f070000000000008589cu128, "@UP5 UPLOP3.LUT UP0, UPT, UPT, UPT, UPT, 0x80, 0x8"), // guard_up5
    (0x000fc40003f0f070000000000008a89cu128, "@!UP2 UPLOP3.LUT UP0, UPT, UPT, UPT, UPT, 0x80, 0x8"), // guard_neg_up2
    (0x000fc40003f00001000000000008789cu128, "UPLOP3.LUT UP0, UPT, UPT, UP0, UP0, 0x1, 0x8"), // bit64
    (0x000fc40003f00002000000000008789cu128, "UPLOP3.LUT UP0, UPT, UPT, UP0, UP0, 0x2, 0x8"), // bit65
    (0x000fc40003f00004000000000008789cu128, "UPLOP3.LUT UP0, UPT, UPT, UP0, UP0, 0x4, 0x8"), // bit66
    (0x000fc40003f00010000000000008789cu128, "UPLOP3.LUT UP0, UPT, UPT, UP0, UP1, 0x0, 0x8"), // bit68
    (0x000fc40003f00020000000000008789cu128, "UPLOP3.LUT UP0, UPT, UPT, UP0, UP2, 0x0, 0x8"), // bit69
    (0x000fc40003f00040000000000008789cu128, "UPLOP3.LUT UP0, UPT, UPT, UP0, UP4, 0x0, 0x8"), // bit70
    (0x000fc40003f00080000000000008789cu128, "UPLOP3.LUT UP0, UPT, UPT, UP0, !UP0, 0x0, 0x8"), // bit71
    (0x000fc40003f00100000000000008789cu128, "UPLOP3.LUT UP0, UPT, UPT, UP0, UP0, 0x8, 0x8"), // bit72
    (0x000fc40003f00200000000000008789cu128, "UPLOP3.LUT UP0, UPT, UPT, UP0, UP0, 0x10, 0x8"), // bit73
    (0x000fc40003f00400000000000008789cu128, "UPLOP3.LUT UP0, UPT, UPT, UP0, UP0, 0x20, 0x8"), // bit74
    (0x000fc40003f00800000000000008789cu128, "UPLOP3.LUT UP0, UPT, UPT, UP0, UP0, 0x40, 0x8"), // bit75
    (0x000fc40003f01000000000000008789cu128, "UPLOP3.LUT UP0, UPT, UPT, UP0, UP0, 0x80, 0x8"), // bit76
    (0x000fc40003f02000000000000008789cu128, "UPLOP3.LUT UP0, UPT, UPT, UP1, UP0, 0x0, 0x8"), // bit77
    (0x000fc40003f04000000000000008789cu128, "UPLOP3.LUT UP0, UPT, UPT, UP2, UP0, 0x0, 0x8"), // bit78
    (0x000fc40003f08000000000000008789cu128, "UPLOP3.LUT UP0, UPT, UPT, UP4, UP0, 0x0, 0x8"), // bit79
    (0x000fc40003f01080000000000008789cu128, "UPLOP3.LUT UP0, UPT, UPT, UP0, !UP0, 0x80, 0x8"), // b71_and_b76
];
/// Klasa swap-window PLOP3-UP (kotwice hexdb; przez cykl (0xea->0xd5->0x5d->..)).
const SWAP: &[(u128,&str)] = &[
    (0x000fc8000070fd0a0000000000ae781cu128, "PLOP3.LUT P0, PT, P0, PT, UP0, 0xea, 0xae"),
    (0x000fda000070fa0d00000000005d781cu128, "PLOP3.LUT P0, PT, P0, PT, UP0, 0xd5, 0x5d"),
    (0x000fda000070eb0d0000000000d5781cu128, "PLOP3.LUT P0, PT, P0, PT, UP0, 0x5d, 0xd5"),
];
const BIT67: u128 = 0x000fc40003f00008000000000008789cu128;

#[test]
fn t169_1_decode_corpus107_sm120_byte_exact() {
    let t=t120(); let idx=DecodeIndex::build(&t);
    let mut bad=0;
    for (w,txt) in CORPUS107 {
        let got=dec(&idx,*w,&t);
        if &got!=txt { bad+=1; eprintln!("MISM {:#034x}\n  exp {}\n  got {}",w,txt,got); }
    }
    assert_eq!(bad,0);
}

#[test]
fn t169_2_arb_law_matrix_sm120() {
    let t=t120(); let idx=DecodeIndex::build(&t);
    let mut bad=0;
    for (w,txt) in ARB {
        let got=dec(&idx,*w,&t);
        if &got!=txt { bad+=1; eprintln!("ARB-MISM {:#034x}\n  exp {}\n  got {}",w,txt,got); }
    }
    assert_eq!(bad,0);
}

#[test]
fn t169_3_plop3_upswap_decode() {
    let t=t120(); let idx=DecodeIndex::build(&t);
    for (w,txt) in SWAP {
        let got=dec(&idx,*w,&t);
        assert_eq!(&got,txt);
    }
}

#[test]
fn t169_4_encode_lattice_class_payload_exact() {
    let t=t120();
    // era-030 lattice: v1 in {0x0,0x40,0x80,0xc0}, v2 in {0,4,8,0xc} — tylko te
    // teksty sa dziurami encode-side; latticowe musza byc bajtowo dokladne.
    let mut n=0;
    for (w,txt) in CORPUS107 {
        let caps: Vec<&str>={
            let m: Vec<&str>=txt.split(',').collect();
            let n=m.len();
            vec![m[n-2].trim(), m[n-1].trim()]
        };
        let v1=i64::from_str_radix(caps[0].trim_start_matches("0x"),16).unwrap();
        let v2=i64::from_str_radix(caps[1].trim_start_matches("0x"),16).unwrap();
        let latt=[0x0,0x40,0x80,0xc0].contains(&v1) && [0x0,0x4,0x8,0xc].contains(&v2);
        if !latt { continue; }
        n+=1;
        let got=enc(&t,txt);
        assert_eq!(got,w & !SCHED, "encode payload {txt}");
    }
    assert!(n>=80, "lattice subset size {n}");
    // klasa 0xf8/0x2: compose z parked-168 wykonany (2026-08-26 wave) -- pelne
    // 8-bit prawo wygrywa (naglowek); pin = byte-exact encode corpus witness.
    let (w8,t8)=CORPUS107.iter().find(|(_,x)| x.contains("0xf8")).unwrap();
    assert_eq!(enc(&t,t8),w8 & !SCHED, "0xf8 8-bit-law witness encodes");
    // poza 8-bit (0x1f8) nadal fail-closed (lattice bound 0xfe/0xff):
    assert!(encode_instruction(&parse_sass(&t8.replace("0xf8","0x1f8"),0).unwrap(),&t).is_err());
    // junk-form text (UP dest + P sources) = klasa skasowana -> fail-closed
    assert!(encode_instruction(&parse_sass("UPLOP3.LUT UP0, PT, P0, P1, PT, 0x0, 0x8f",0).unwrap(),&t).is_err());
    // swap-class text PLOP3-UP enkoduje bajtowo (prawa strona prawdziwego prawa)
    for (w,txt) in SWAP {
        let got=enc(&t,txt);
        assert_eq!(got,w & !SCHED, "encode swap {txt}");
    }
}

#[test]
fn t169_5_fail_closed_inert_bit67_and_sm103a_nop() {
    let t=t120(); let idx=DecodeIndex::build(&t);
    assert!(dec_fail(&idx,BIT67,&t), "bit67 vendor-inert: fail-closed");
    // sm103a: zero napisow upred w tabeli => scoring bez zmian; 8 slow z 168
    let t3=t103a(); let idx3=DecodeIndex::build(&t3);
    for (w,txt) in &CORPUS107[..8] {
        let got=dec(&idx3,*w,&t3);
        assert_eq!(&got,txt);
    }
}

#[test]
fn t169_6_fixed_point_lattice_subset() {
    let t=t120(); let idx=DecodeIndex::build(&t);
    for (w,txt) in CORPUS107 {
        let caps: Vec<&str>={
            let m: Vec<&str>=txt.split(',').collect();
            let n=m.len();
            vec![m[n-2].trim(), m[n-1].trim()]
        };
        let v1=i64::from_str_radix(caps[0].trim_start_matches("0x"),16).unwrap();
        let v2=i64::from_str_radix(caps[1].trim_start_matches("0x"),16).unwrap();
        let latt=[0x0,0x40,0x80,0xc0].contains(&v1) && [0x0,0x4,0x8,0xc].contains(&v2);
        if !latt { continue; }
        let d1=dec(&idx,*w,&t);
        assert_eq!(&d1,txt);
        let w2=enc(&t,&d1);
        assert_eq!(w2,w & !SCHED, "roundtrip {txt}");
    }
}


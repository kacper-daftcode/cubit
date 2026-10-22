//! Independent NVIDIA SM120 corpus anchors: semantic text, complete words,
//! split tensor selector windows and float modifier/operand disambiguation.
use cubit::table::IsaTable;
use std::path::Path;
use std::sync::OnceLock;
fn table() -> &'static IsaTable {
    static TABLE: OnceLock<IsaTable> = OnceLock::new();
    TABLE.get_or_init(|| match std::env::var("CUBIT_TABLE") { Ok(path) => IsaTable::load(Path::new(&path)).unwrap(), Err(_) => IsaTable::load(Path::new("tables/sm120.json")).unwrap() })
}
fn roundtrip(word: u128, expected: &str) {
    let t=table(); let d=t.decode_index().decode(word,0,t).unwrap();
    let text=cubit::printer::to_sass_lossless(&d);
    assert_eq!(text,expected,"decoded key={} group={}",d.key,d.mod_group);
    let cc=cubit::scheduling::decode_sched_upper32((word>>96)as u32);
    let source=format!("[{}] {text} ;",cubit::scheduling::format_control_code(&cc));
    cubit::roundtrip_audit::check_semantic_source(&source).unwrap();
    let parsed=cubit::parse_cuasm_line(&source,0).unwrap();
    assert!(parsed.rsd.is_none());
    assert_eq!(cubit::encoder::encode_instruction(&parsed,t).unwrap(),word,"{source}");
}
#[test]
fn nvidia_semantic_corpus_anchors_reencode_all_128_bits() {
    for (w,s) in [
        (0x000fda00038000000000000000ff782f,"ELECT P0, URZ, PT"),
        (0x000fe4000382000000000000004f782f,"ELECT P1, UR79, PT"),
        (0x000fe200037234000000004f3600720b,"FSETP.LE.OR P1, PT, R54, R79, P6"),
        (0x0c0fe20003f042000000000f0c00720b,"FSETP.GT.AND P0, PT, |R12|.reuse, R15.reuse, PT"),
        (0x000fe2000781000040000011ff177209,"FMNMX.FTZ R23, RZ, |R17|, !PT"),
        (0x000fca00038200004120000006067809,"FMNMX.NAN R6, R6, 10, PT"),
        (0x000fe2000384020043e0000005057809,"FMNMX.XORSIGN R5, |R5|, 448, PT"),
        (0x020fe2000020be2074e045422820747a,"QMMA.SF.16832.F32.E4M3.E2M1.E8 R32, R40, R66, R32, R69, R78, URZ"),
        (0x000fe40000000000000000041c1c781a,"SGXT.U32 R28, R28, 0x4"),
        (0x000e2400001010001000001f001f7306,"I2F.U16 R31, R31.H1"),
        (0x000ea200002190000000000900097307,"FRND.FTZ.CEIL R9, R9"),
        (0x011fd8000f8e00040000000e050572a6,"UIMAD.HI.U32 UR5, UR5, UR14, UR4"),
        (0x000fe200080000000000001700007c13,"IABS R0, UR23"),
        (0x040fe200008e000000000000041702ca,"@P0 R2UR.BROADCAST UR23, R4.reuse"),
        (0x000fe200078000000000004804033240,"@P3 HMNMX2 R3, R4, R72, !PT"),
        (0x000fe60007a000000000000411047240,"HMNMX2.BF16_V2 R4, R17, R4, !PT"),
        (0x000e2200000008008000000d00097308,"MUFU.EX2 R9, -R13"),
        (0x0000a200000020000000002500027308,"MUFU.SQRT R2, R37"),
        (0x000fc800000108343e1039f62f307423,"FFMA.FTZ R48, R47, -R52, 0.14084610342979431152"),
        (0x000fe200000000143f8000000a0a7823,"FFMA R10, R10, 1, R20"),
        (0x000fe4000801010080000004ff077e21,"FADD.FTZ R7, -RZ, -UR4"),
        (0x000fe200000100003f800000002a3421,"@P3 FADD.FTZ R42, R0, 1"),
        (0x000fe40005800000ffffffff23237808,"FSEL R35, R35, 0xffffffffF, !P3"),
        (0x000fe200000e0400d555555505097835,"IADD.X R9, R5, -0x2aaaaaab, P0"),
        (0x000fe200078e00000000000605097235,"IADD R9, R5, R6"),
        (0x000fe2000f8e00000000000405097c35,"IADD R9, R5, UR4"),
        (0x000fe200000604000000000605097235,"IADD.X R9, P3, R5, R6, P0"),
        (0x000fe200080e05008000000405097c35,"IADD.X R9, ~R5, ~UR4, P0"),
        (0x080fe200018e040080000005ff0d7235,"IADD.X R13, RZ, ~R5.reuse, P3"),
        (0x000fe200087fe4ff80000027ff057290,"UIADD3.X UR5, UPT, UPT, URZ, ~UR39, URZ, UP0, !UPT"),
        (0x000fc80008ffe4ff80000027ff077290,"UIADD3.X UR7, UPT, UPT, URZ, ~UR39, URZ, UP1, !UPT"),
        (0x000fe2000f8fe0ff0000000607057290,"UIADD3 UR5, UPT, UP0, UR7, UR6, URZ"),
        (0x000fe2000f8fe0ff0000000607057890,"UIADD3 UR5, UPT, UP0, UR7, 0x6, URZ"),
        (0x000fc8000800000000000004000472bf,"UPOPC UR4, UR4"),
        (0x000fc8000800000080000004000472bf,"UPOPC UR4, ~UR4"),
        (0x001e1e000070e600200000000400742a,"DSETP.GEU.OR P0, PT, |R4|, 1.4916681462400413487e-154, P0"),
        (0x000e24000bf2b0000000000402007e2a,"DSETP.LEU.AND P1, PT, R2, UR4, PT"),
        (0x000e6200000010002000003000007306,"I2F.U8 R0, R48.B2"),
        (0x000e6200000014002000003000007306,"I2F.S8 R0, R48.B2"),
        (0x000fcc00080e04000000000b000b72bd,"UFLO.U32.SH UR11, UR11"),
        (0x000fe200082014000000000700067c45,"I2FP.F32.S32 R6, UR7"),
        (0x000fe2000c8000003f80000007077851,"UFSEL UR7, UR7, 1, !UP1"),
        (0x0c0fe20003fe02000000000e120f7248,"VIMNMX.U16x2 R15, R18.reuse, R14.reuse, PT"),
        (0x000fe2000bfe00000000000405057c48,"VIMNMX.U32 R5, R5, UR4, PT"),
        (0x000fe20003fe11000000000207027248,"VIMNMX.S32.RELU R2, R7, R2, PT"),
        (0x000fc8000fffe6000000000802047c17,"IMNMX.S64 PT, PT, R4, R2, UR8, !PT, !PT"),
        (0x004fcc000bffe4000000000e04047285,"UIMNMX.U64 UPT, UPT, UR4, UR4, UR14, UPT, !UPT"),
        (0x000fc8000f82000e00000012050e72a6,"UIMAD.HI.U32 UR14, UP1, UR5, UR18, UR14"),
        (0x000fe40000010247ffffffff00047419,"SHF.L.U64.HI R4, R0, R71, 0xffffffff"),
        (0x0042a200001018000000000600127312,"I2F.F64.U16 R18, R6"),
        (0x000e1e00003058000000001000027313,"FRND.F64.FLOOR R2, R16"),
        (0x000fc80000000000000000031203721a,"SGXT.U32 R3, R18, R3"),
        (0x000fe200080102ff0000000a042b7299,"USHF.L.U64.HI UR43, UR4, UR10, URZ"),
        (0x001fe2000c000000000000080e087251,"UFSEL UR8, UR14, UR8, !UP0"),
        (0x001fc800080000050000000b10067e16,"PRMT R6, R16, R5, UR11"),
        (0x000fc8000800fcff000000ffffff7292,"ULOP3.LUT UP0, URZ, URZ, URZ, URZ, 0xfc, UP0"),
        (0x000fd6000bf0e2000080000006007853,"UFSETP.GEU.AND UP0, UPT, |UR6|, 1.175494350822287508e-38, UPT"),
        (0x004fe2000bf04000000000ff06007253,"UFSETP.GT.AND UP0, UPT, UR6, URZ, UPT"),
        (0x000fce0008800001ffffffff04047487,"USEL.64 UR4, UR4, -0x1, UP1"),
        (0x000fe2000c00000000000001ff0e7887,"USEL UR14, URZ, 0x1, !UP0"),
        (0x002fd800080000ff0000777010107896,"UPRMT UR16, UR16, 0x7770, URZ"),
        (0x000fe2000bf16070000000032400788c,"UISETP.GE.U64.AND UP0, UPT, UR36, 0x3, UPT"),
        (0x000e24000020e400000000ff00057306,"I2F.BF16.RZ R5, RZ"),
        (0x060fe40003ffe6000000000204067217,"IMNMX.S64 PT, PT, R6, R4.reuse, R2, PT, !PT"),
        (0x000fc8000f800006000000040d067c27,"IMAD.HI.U32 R6, P0, R13, UR4, R6"),
        (0x000fe2000800000000000004ff06789b,"UBMSK UR6, URZ, 0x4"),
        (0x000fc80000000000000000000fff72ca,"R2UR P0, URZ, R15"),
        (0x000fe200000001ff00007fffff1f7431,"HFMA2 R31, -RZ, RZ, 0, 0x7fffe000F"),
        (0x002fca000bf660000000000423007c0b,"FSETP.GE.AND P3, PT, R35, UR4, PT"),
        (0x040fe2000f8002000000000418197c09,"FMNMX R25, |R24|.reuse, UR4, !PT"),
        (0x0040640000707400000000040400122a,"@P1 DSETP.NUM.OR P0, PT, R4, R4, P0"),
        (0x008fd2000bf35270000000ff0400728c,"UISETP.NE.S64.AND UP1, UPT, UR4, URZ, UPT"),
        (0x000fea000b80000000000a4204987947,"BRA.DIV UR4, 0xa4270"),
        (0x000fea000b80000000000a4204997947,"BRA.DIV UR4, 0xa4274"),
        (0x008ff600000800106000000c0808747f,"OMMA.SF.16864.F32.E2M1.E2M1.E8 R8, R8, R12, R16, R0, R0, UR6"),
    ] {roundtrip(w,s);}
}
#[test]
fn tensor_selector_split_windows_distinguish_ur63_and_urz_and_preserve_signs() {
    let anchor=0x020fe2000020be2074e045422820747au128;
    let base=anchor&!((7u128<<60)|(31u128<<73));
    for value in [0u128,1,7,8,31,63,255] {
        let word=base|((value&7)<<60)|((value>>3)<<73);
        let ur=if value==255 {"URZ".into()}else{format!("UR{value}")};
        roundtrip(word,&format!("QMMA.SF.16832.F32.E4M3.E2M1.E8 R32, R40, R66, R32, R69, R78, {ur}"));
    }
    roundtrip(anchor^(1<<63),"QMMA.SF.16832.F32.E4M3.E2M1.E8 R32, R40, -R66, R32, R69, R78, URZ");
    roundtrip(anchor^(1<<72),"QMMA.SF.16832.F32.E4M3.E2M1.E8 R32, -R40, R66, R32, R69, R78, URZ");
    roundtrip(anchor^(1<<51),"QMMA.SF.16832.F32.E4M3.E2M1.E8 R32, R40, R66, R32, R69, R78.reuse, URZ");
}
#[test]
fn tensor_type_pair_and_optional_uniform_predicate_have_distinct_named_fields() {
    // NVIDIA type-enumeration probes independently identified these bit
    // triples and names; A and B use separate triples, not reversed names.
    let anchor=0x020fe2000020be2074e045422820747au128;
    let type_mask=(1u128<<78)|(1u128<<82)|(1u128<<83)|(1u128<<79)|(1u128<<84)|(1u128<<85);
    for (a,ac) in [("E4M3",0u128),("E5M2",1),("E3M2",3),("E2M3",4),("E2M1",5)] {
        for (b,bc) in [("E4M3",0u128),("E5M2",1),("E3M2",3),("E2M3",4),("E2M1",5)] {
            let bits_a=((ac&1)<<78)|(((ac>>1)&1)<<82)|(((ac>>2)&1)<<83);
            let bits_b=((bc&1)<<79)|(((bc>>1)&1)<<84)|(((bc>>2)&1)<<85);
            roundtrip((anchor&!type_mask)|bits_a|bits_b,&format!("QMMA.SF.16832.F32.{a}.{b}.E8 R32, R40, R66, R32, R69, R78, URZ"));
        }
    }
    roundtrip(anchor^(1<<87),"QMMA.SF.16832.F32.E4M3.E2M1.E8 R32, R40, R66, R32, UP6, R69, R78, URZ");
    roundtrip(anchor^(1<<90),"QMMA.SF.16832.F32.E4M3.E2M1.E8 R32, R40, R66, R32, !UPT, R69, R78, URZ");
    roundtrip(anchor|(1<<80)|(3<<48),"QMMA.SF.SP.16864.F32.E4M3.E2M1.E8 R32, R40, R66, R32, R69, R78, URZ, 0x3");
}

#[test]
fn vector_minmax_type_enum_is_independent_of_source_values_and_relu() {
    // NVIDIA independently prints all six integer types for all three
    // source packets. In particular bit73 means U16x2, not source abs.
    for (dtype, name) in ["U32", "S32", "U16x2", "S16x2", "U8x4", "S8x4"].into_iter().enumerate() {
        for (packet, operand) in [(0x248u128, "R14"), (0x848, "0xe"), (0xc48 | (1<<91), "UR14")] {
            let word=0x000fe20003fe00000000000e120f7000u128 | packet | ((dtype as u128)<<72);
            roundtrip(word,&format!("VIMNMX.{name} R15, R18, {operand}, PT"));
            roundtrip(word|(1<<76),&format!("VIMNMX.{name}.RELU R15, R18, {operand}, PT"));
        }
    }
}

#[test]
fn source_width_and_selector_enums_match_independent_nvidia_probes() {
    let base=0x0042a200000018000000000600127312u128;
    for (code, unsigned, signed) in [(0,"U8","S8"),(1,"U16","S16"),(2,"U32",""),(3,"U64","S64")] {
        for (is_signed,dtype) in [(false,unsigned),(true,signed)] {
            let word=base|((code as u128)<<84)|((is_signed as u128)<<74);
            let dtype=if dtype.is_empty(){String::new()}else{format!(".{dtype}")};
            roundtrip(word,&format!("I2F.F64{dtype} R18, R6"));
        }
    }
    let permute=0x001fc800080000050000000b10067e16u128;
    for (mode,name) in ["","F4E","B4E","RC8","ECL","ECR","RC16"].into_iter().enumerate() {
        let name=if name.is_empty(){String::new()}else{format!(".{name}")};
        roundtrip(permute|((mode as u128)<<72),&format!("PRMT{name} R6, R16, R5, UR11"));
    }
    // The 64-bit USEL immediate is signed33. Clearing its bit32 (global64)
    // yields +0xffffffff; changing lower bit31 yields -0x80000001.
    let select=0x000fce0008800001ffffffff04047487u128;
    roundtrip(select^(1<<64),"USEL.64 UR4, UR4, 0xffffffff, UP1");
    roundtrip(select^(1<<63),"USEL.64 UR4, UR4, -0x80000001, UP1");
}

#[test]
fn packed_half_nan_literals_preserve_sign_and_payload_in_both_lanes() {
    // NVIDIA's SNAN/QNAN glyphs cannot name these distinct IEEE payloads.
    // Ordinary exact float literals preserve the ten representable bits.
    let base=0x000fe200000001ff00000000ff1f7431u128;
    for half in [0x7c01u32,0x7d55,0x7dff,0x7e01,0x7e55,0x7fff,
                 0xfc01,0xfd55,0xfdff,0xfe01,0xfe55,0xffff] {
        let float=((half&0x8000)<<16)|0x7f800000|((half&0x3ff)<<13);
        roundtrip(base|((half as u128)<<32),&format!("HFMA2 R31, -RZ, RZ, 0, 0x{float:08x}F"));
        roundtrip(base|((half as u128)<<48),&format!("HFMA2 R31, -RZ, RZ, 0x{float:08x}F, 0"));
    }
}

#[test]
fn exact_float_literals_preserve_signaling_nan_state_through_the_float_ir() {
    let base=0x000fe400058000000000000023237808u128;
    for bits in [0x7f800001u32,0x7fa00000,0x7fbfffff,0x7fc00001,0x7fffffff,
                 0xff800001,0xffbfffff,0xffffffff] {
        roundtrip(base|((bits as u128)<<32),&format!("FSEL R35, R35, 0x{bits:08x}F, !P3"));
        let parsed=cubit::parse_cuasm_line(&format!("FSEL R35, R35, 0x{bits:08x}F, !P3 ;"),0).unwrap();
        let cubit::ir::Operand::FloatImm(value)=parsed.operands[2] else {panic!("exact literal is not a typed float")};
        let expected=((bits as u64&0x80000000)<<32)|0x7ff0000000000000|(((bits&0x7fffff)as u64)<<29);
        assert_eq!(value,expected,"the typed IR quieted or changed the NaN payload");
    }
    let t=table();
    let negative=cubit::parse_cuasm_line("[B------:R-:W-:Y:S02] FSEL R35, R35, -0x7f800001F, !P3 ;",0).unwrap();
    assert_eq!(cubit::encoder::encode_instruction(&negative,t).unwrap(),base|(0xff800001u128<<32));
}

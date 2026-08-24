//! b9p12 (phase-3 #10) pins: intmisc lane (lop3/prmt/bfe/bfind/sad) + bar.red
//! + setmaxnreg + trap + ld.volatile + discard.global.L2 + barrier pack;
//! plus the phase-1 guess-mapping fixes clz/popc/brev (vendor -O0 macros).
//! Anchors: work/b9p12/probes corpus O0 cubins + work/b9p12/t probes;
//! doctrine: fail-closed on unanchored shapes.
use cubit::ptx_lower::lower_kernel;
use cubit::ptx_parse::parse_ptx;
use cubit::table::IsaTable;

fn table() -> IsaTable {
    IsaTable::load(std::path::Path::new("tables/sm103a.json")).unwrap()
}
fn assemble_body(text: &str) -> (Vec<u8>, usize) {
    let body: String = text.lines()
        .filter(|l| !l.trim_start().starts_with('.'))
        .collect::<Vec<_>>().join("\n");
    cubit::assemble(&body, 0, &table()).unwrap()
}
const PROLOG: &str = ".version 9.3\n.target sm_103a\n.address_size 64\n\n";
fn kern(body: &str) -> String {
    format!(r#"{} .visible .entry k(
    .param .u64 .ptr .align 1 k_param_0
)
{{
    .reg .pred %p<8>;
    .reg .b32  %r<40>;
    .reg .b64  %rd<10>;
    ld.param.b64 %rd1, [k_param_0];
    cvta.to.global.u64 %rd2, %rd1;
    // BUG-118 gate: driveable universe for the snippet (untyped bit-writes).
    mov.b32 %r1, 101; mov.b32 %r2, 102; mov.b32 %r3, 103; mov.b32 %r4, 104;
    mov.b32 %r5, 105; mov.b32 %r6, 106; mov.b32 %r7, 107; mov.b32 %r8, 108;
    mov.b64 %rd3, %rd1; mov.b64 %rd4, %rd1; mov.b64 %rd5, %rd1;
    mov.b64 %rd6, %rd1; mov.b64 %rd7, %rd1; mov.b64 %rd8, %rd1;
{}
    ret;
}}"#, PROLOG, body)
}
fn lower(body: &str) -> String {
    let k = parse_ptx(&kern(body)).unwrap();
    lower_kernel(&k[0]).unwrap().to_sass_text()
}
fn lower_err(body: &str) -> String {
    let k = parse_ptx(&kern(body)).unwrap();
    match lower_kernel(&k[0]) { Ok(_) => String::new(), Err(e) => format!("{:#}", e) }
}
fn lines_of(text: &str) -> Vec<String> {
    text.lines().map(|l| l.trim()).filter(|l| l.ends_with(';')).map(|l| l.to_string()).collect()
}

/// Register-allocation agnostic struct shape: R#/UR#/P# renamed to first-
/// appearance slots d0/d1/... (R255==RZ stays). Comparison is on the FULL
/// structural string, so operand ORDER inside each op is pinned.
fn shape(l: &[String]) -> Vec<String> {
    let re = regex::Regex::new(r"\b(?:R|UR|P)(\d+)(\.64)?\b").unwrap();
    let mut out = Vec::new();
    let mut map: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for ll in l {
        let s = re.replace_all(ll, |c: &regex::Captures| {
            let t = format!("{}{}", &c[1], c.get(2).map(|m| m.as_str()).unwrap_or(""));
            if t == "255" || t == "255.64" { return "255".to_string(); }
            let k = t.clone();
            let n = map.len();
            let v = map.entry(k).or_insert(n);
            format!("@{v}{}", c.get(2).map(|m| m.as_str()).unwrap_or(""))
        });
        out.push(s.to_string());
    }
    out
}

/// Shape with stable numbering: normalize only lines from `marker` on, so
/// param/LDC glue registers don't shift the slot ids.
fn shape_from(text: &str, marker_substr: &str) -> Vec<String> {
    let mut l = lines_of(text);
    let i = l.iter().position(|x| x.contains(marker_substr)).expect(marker_substr);
    l.drain(..i);
    shape(&l)
}

/// 1. lop3.b32 -> LOP3.LUT d,a,b,c,lut,!PT (anchor corpus p20 0x320).
#[test]
fn b9p12_lop3_plain() {
    let t = lower("    mov.b32 %r1, 1;\n    mov.b32 %r2, 2;\n    mov.b32 %r3, 3;\n    lop3.b32 %r4, %r1, %r2, %r3, 0xE8;");
    let l = shape_from(&t, "LOP3.LUT");
    assert_eq!(l[0], "LOP3.LUT @0, @1, @2, @3, 0xe8, !PT ;");
    let (b, n) = assemble_body("LOP3.LUT R17, R21, R6, R5, 0xe8, !PT ;");
    assert_eq!(n, 1);
    assert_eq!(&b[0..2], &[0x12, 0x72][..], "LOP3 4-src tag: {:02x?}", &b[..12]);
}

/// 2. prmt.b32: PTX d,a,b,c(sel) -> PRMT d,a,sel,b; imm mid + reg mid
///    (anchors corpus p20 0x330/0x340). Encoder byte-parity imm-sel anchor.
#[test]
fn b9p12_prmt_imm_and_reg() {
    let t = lower("    mov.b32 %r1, 11;\n    mov.b32 %r2, 22;\n    prmt.b32 %r3, %r1, %r2, 0x5410;\n    prmt.b32 %r4, %r1, %r2, %r3;");
    let l = shape_from(&t, "PRMT");
    assert!(l.iter().any(|x| x == "PRMT @0, @1, 0x5410, @2 ;"), "imm-sel middle: {:?}", l);
    assert!(l.iter().any(|x| x == "PRMT @3, @1, @0, @2 ;"), "reg-sel middle: {:?}", l);
    let (b, n) = assemble_body("PRMT R11, R5, 0x5410, R10 ;");
    assert_eq!(n, 1);
    assert_eq!(&b[..12], &[0x16, 0x78, 0x0b, 0x05, 0x10, 0x54, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00]);
}

/// 3. bfe.u32 imm pos/len: pos!=0 -> 8-op macro; pos==0 -> 7-op (no MOV pos,
///    LOP3 c-slot = RZ). Reg pos/len -> fail-closed.
#[test]
fn b9p12_bfe_imm_macro() {
    let t = lower("    mov.u32 %r1, 77;\n    bfe.u32 %r2, %r1, 4, 12;");
    // macro span, normalized from its first MOV (a is the loaded input reg = @1
    // because the LOP3-independence: %r1 appears at SHF.R.U32.HI as last src).
    let l = shape_from(&t, "MOV ");
    // locate span (starts at "MOV @?, 0xc"); a(%r1) resolved earlier by movs.
    let i = l.iter().position(|x| x.ends_with("0xc ;") && x.starts_with("MOV ")).expect(&t);
    let span = &l[i..i+8];
    let want: Vec<String> = {
        let lenu = span[0].split('@').nth(1).unwrap().split([' ', ',']).next().unwrap().to_string();
        vec![
            format!("MOV @{}, 0xc ;", lenu),
            format!("SHF.L.U32 @{0}, @{0}, 0x8, RZ ;", lenu),
        ]
    };
    assert_eq!(&span[0..2], &want[..], "bfe head: {:?}", span);
    // structural continuation by op sequence
    let ops: Vec<&str> = span.iter().map(|x| x.split(' ').next().unwrap()).collect();
    assert_eq!(ops, ["MOV","SHF.L.U32","MOV","LOP3.LUT","PRMT","PRMT","SHF.R.U32.HI","SGXT.U32"], "bfe op seq");
    assert!(span[3].contains("0xff00") && span[3].ends_with("0xe2, !PT ;"));
    assert!(span[4].starts_with("PRMT ") && span[4].contains(", RZ, 0x4, "));
    assert!(span[5].starts_with("PRMT ") && span[5].contains(", RZ, 0x5, "));
    assert!(span[6].starts_with("SHF.R.U32.HI ") && span[6].contains(", RZ, "));
    assert!(span[7].starts_with("SGXT.U32 "));
    let z = lower("    mov.u32 %r1, 77;\n    bfe.u32 %r2, %r1, 0, 31;");
    let lz = shape_from(&z, "MOV ");
    let j = lz.iter().position(|x| x.ends_with("0x1f ;") && x.starts_with("MOV ")).expect(&z);
    let opsz: Vec<&str> = lz[j..j+7].iter().map(|x| x.split(' ').next().unwrap()).collect();
    assert_eq!(opsz, ["MOV","SHF.L.U32","LOP3.LUT","PRMT","PRMT","SHF.R.U32.HI","SGXT.U32"], "pos=0 7-op seq");
    assert!(lz[j+2].contains(", RZ,"), "pos=0 folds RZ into LOP3 c-slot: {}", lz[j+2]);
    let e = lower_err("    mov.u32 %r1, 77;\n    bfe.u32 %r2, %r1, %r1, 12;");
    assert!(e.contains("bfe.u32"), "reg pos fail-closed: {}", e);
}

/// 4. bfind.shiftamt.u32 = FLO.U32.SH (anchor p19 0x420); bfind.u32 = FLO.U32
///    (anchor bfe_probe 0x380). Encode-parity corpus p19 FLO.U32.SH R7,R7.
#[test]
fn b9p12_bfind_forms() {
    let t = lower("    mov.u32 %r1, 7;\n    bfind.shiftamt.u32 %r2, %r1;\n    bfind.u32 %r3, %r1;");
    assert!(t.contains("FLO.U32.SH") && t.contains("FLO.U32 "), "forms: {}", t);
    let (b, n) = assemble_body("FLO.U32.SH R7, R7 ;");
    assert_eq!(n, 1);
    assert_eq!(&b[..12], &[0x00, 0x73, 0x07, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x04, 0x0e, 0x00]);
}

/// 5. sad.u32 = VABSDIFF.U32; encode anchor corpus p19 0x890
///    (VABSDIFF.U32 R17, R21, R6, R17; row b9p12 49-word fit).
#[test]
fn b9p12_sad_vabsdiff_row() {
    let t = lower("    mov.u32 %r1, 3;\n    mov.u32 %r2, 5;\n    mov.u32 %r3, 9;\n    sad.u32 %r4, %r1, %r2, %r3;");
    let l = shape_from(&t, "VABSDIFF");
    assert_eq!(l[0], "VABSDIFF.U32 @0, @1, @2, @3 ;");
    let (b, n) = assemble_body("VABSDIFF.U32 R17, R21, R6, R17 ;");
    assert_eq!(n, 1);
    assert_eq!(&b[..12], &[0x14, 0x72, 0x11, 0x15, 0x06, 0x00, 0x00, 0x00, 0x11, 0x00, 0x0e, 0x00]);
    // fail-closed classes: .S32 / plain spellings must not encode
    // VABSDIFF.S32 must not encode (fail-closed at row match)
    assert!(cubit::assemble("VABSDIFF.S32 R1, R2, R3, R4 ;", 0, &table()).is_err(), "S32 fail-closed");
}

/// 6. bar.red.and/or.pred (anchors corpus v55 + probe bar.ptx imm=1).
#[test]
fn b9p12_barred_forms() {
    let t = lower("    setp.gt.s32 %p1, %r1, %r2;\n    bar.red.and.pred %p2, 0, %p1;\n    bar.red.or.pred %p3, 1, %p1;");
    let l = shape_from(&t, "WARPSYNC.ALL");
    assert_eq!(l[1], "BAR.RED.AND.DEFER_BLOCKING 0x0, @0 ;");
    assert_eq!(l[2], "B2R.RESULT RZ, @1 ;");
    let j = l.iter().position(|x| x.contains("BAR.RED.OR")).unwrap();
    assert_eq!(l[j], "BAR.RED.OR.DEFER_BLOCKING 0x1, @0 ;");
    let (ba, _) = assemble_body("BAR.RED.AND.DEFER_BLOCKING 0x0, P0 ;");
    assert_eq!(&ba[..12], &[0x1d, 0x7b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x44, 0x01, 0x00]);
    let (bb, _) = assemble_body("BAR.RED.OR.DEFER_BLOCKING 0x0, P0 ;");
    assert_eq!(&bb[..12], &[0x1d, 0x7b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x01, 0x00]);
    let (b2, _) = assemble_body("B2R.RESULT RZ, P0 ;");
    assert_eq!(&b2[..12], &[0x1c, 0x73, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00]);
    let e = lower_err("    setp.gt.s32 %p1, %r1, %r2;\n    bar.red.and.pred %p2, 22, %p1;");
    assert!(e.contains("bar.red.and.pred"), "imm>15 fail-closed: {}", e);
}

/// 7. setmaxnreg: vendor elides (corpus p30 O0==O3); gateway emits NOTHING.
#[test]
fn b9p12_setmaxnreg_elided() {
    let t = lower("    setmaxnreg.inc.sync.aligned.u32 40;\n    mov.u32 %r1, %tid.x;\n    setmaxnreg.dec.sync.aligned.u32 32;\n    mul.wide.u32 %rd3, %r1, 4;");
    assert!(!t.to_uppercase().contains("SETLMEM") && !t.contains("maxnreg"), "no trace: {}", t);
    let l = lines_of(&t);
    let i = l.iter().position(|x| x.starts_with("S2R")).expect(&t);
    assert!(l[i+1].starts_with("IMAD.WIDE"), "no slot consumed: {:?}", &l[i..i+2]);
}

/// 8. trap = BPT.TRAP 0x1 (anchor corpus p32 0x250).
#[test]
fn b9p12_trap() {
    let t = lower("    trap;");
    assert!(t.contains("BPT.TRAP 0x1 ;"), "trap text: {}", t);
    let (b, n) = assemble_body("BPT.TRAP 0x1 ;");
    assert_eq!(n, 1);
    assert_eq!(&b[..12], &[0x5c, 0x79, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0x00]);
}

/// 9. ld.volatile.global.b32 -> LDG.E.EF (anchor corpus p02 0x530); b64 fail.
#[test]
fn b9p12_ld_volatile() {
    let t = lower("    ld.volatile.global.b32 %r5, [%rd2+4];");
    let l = shape(&lines_of(&t));
    assert!(l.iter().any(|x| x.starts_with("LDG.E.EF") && x.contains("+0x4")), "volatile->EF: {}", t);
    let e = lower_err("    ld.volatile.global.b64 %rd5, [%rd2+4];");
    assert!(e.contains("vendor-anchored"), "wide volatile fail: {}", e);
}

/// 10. discard.global.L2 [a], 128 = CCTL.E.RML2 [pair] (anchor p_cctl 0x200).
#[test]
fn b9p12_discard() {
    let t = lower("    discard.global.L2 [%rd2], 128;");
    assert!(t.contains("CCTL.E.RML2 ["), "discard text: {}", t);
    let e = lower_err("    discard.global.L2 [%rd2], 64;");
    assert!(e.contains("discard.global.L2"), "extent!=128 fail-closed: {}", e);
    let (b, n) = assemble_body("CCTL.E.RML2 [R2] ;");
    assert_eq!(n, 1);
    assert_eq!(&b[..12], &[0x8f, 0x79, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x80, 0x05]);
}

/// 11. barrier family law (probes bar.ptx/bar2.ptx + corpus p21).
#[test]
fn b9p12_barrier_law() {
    let t0 = lower("    bar.sync 0;");
    let iws = t0.find("WARPSYNC.ALL").expect(&t0);
    let ibs = t0.find("BAR.SYNC.DEFER_BLOCKING 0x0 ;").expect(&t0);
    assert!(iws < ibs, "WARPSYNC.ALL precedes BAR.SYNC: {}", t0);
    let t1 = lower("    bar.sync 2, 416;");
    assert!(t1.contains("BAR.SYNC.DEFER_BLOCKING 0x2, 0x1a0 ;"), "direct II_II: {}", t1);
    let t2 = lower("    barrier.sync.aligned 3, 160;");
    assert!(t2.contains("BAR.SYNC.DEFER_BLOCKING 0x3, 0xa0 ;"), "aligned direct: {}", t2);
    let t3 = lower("    barrier.sync 1, 128;");
    let l = lines_of(&t3);
    let i = l.iter().position(|x| x.starts_with("WARPSYNC.COLLECTIVE.ALL")).expect(&t3);
    // pack body: SHF.L x,x,0x10 ; LOP3 x,x,0xf,id,0xf8 ; BAR.SYNC x,x ; SHF.R ; ENDCOLLECTIVE
    let tgt = l[i+1].split(',').next().unwrap().replace("SHF.L.U32 ", "");
    assert!(l[i+1].starts_with("SHF.L.U32 ") && l[i+1].contains("0x10"), "shf.l: {}", l[i+1]);
    assert!(l[i+2].starts_with("LOP3.LUT ") && l[i+2].contains("0xf, ") && l[i+2].ends_with("0xf8, !PT ;"), "pack lop3: {}", l[i+2]);
    assert_eq!(l[i+3], format!("BAR.SYNC.DEFER_BLOCKING {0}, {0} ;", tgt), "pack bar: {}", l[i+3]);
    assert!(l[i+4].starts_with("SHF.R.U32"), "unwind: {}", l[i+4]);
    assert!(l[i+5].starts_with("ENDCOLLECTIVE"));
    let t4 = lower("    barrier.arrive 2, 128;");
    let l4 = lines_of(&t4);
    let k = l4.iter().position(|x| x.starts_with("BAR.ARV R")).expect(&t4);
    let ar: &str = &l4[k];
    let reg = ar.trim_start_matches("BAR.ARV ").split(',').next().unwrap();
    assert_eq!(*ar, format!("BAR.ARV {0}, {0} ;", reg), "arrive pack R,R same reg: {}", ar);
    let t5 = lower("    barrier.arrive.aligned 5, 192;");
    assert!(t5.contains("BAR.ARV 0x5, 0xc0 ;"), "arrive aligned direct: {}", t5);
    let (b, n) = assemble_body("BAR.ARV R4, R4 ;");
    assert_eq!(n, 1);
    assert_eq!(&b[..12], &[0x1d, 0x73, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00]);
    let e = lower_err("    bar.sync %r6, %r7;");
    assert!(e.contains("bar.sync"), "reg bar.sync fail-closed: {}", e);
}

/// 12. clz.b32 semantic fix: FLO.U32 d,a + IADD3 d = -t + 0x1f (anchor p19);
///     popc/brev -O0 idioms restored.
#[test]
fn b9p12_clz_popc_brev_fixed() {
    let t = lower("    mov.u32 %r1, 9;\n    clz.b32 %r2, %r1;\n    popc.b32 %r3, %r1;\n    brev.b32 %r4, %r1;");
    let l = lines_of(&t);
    let i = l.iter().position(|x| x.starts_with("FLO.U32")).expect(&t);
    let flo_dst = l[i].split(&[',', ' ']).filter(|s| !s.is_empty()).nth(1).unwrap().to_string();
    assert!(l[i+1].starts_with("IADD3") && l[i+1].contains(&format!("-{}, 0x1f, RZ ;", flo_dst)), "31-x fixup: {}", l[i+1]);
    let p = l.iter().position(|x| x.contains("0x33")).unwrap();
    assert!(l[p].contains("LOP3.LUT") && l[p+1].contains("0xc0") && l[p+2].starts_with("POPC"), "popc idiom");
    let b = l.iter().position(|x| x.starts_with("BREV")).unwrap();
    assert!(l[b+1].starts_with("SHF.R.U32.HI") && l[b+2].starts_with("SGXT.U32"), "brev 3-op: {:?}", &l[b..b+3]);
    let (_bytes, n) = assemble_body(&t);
    assert!(n >= 10);
}

/// 13. Label stability: labels directly after macro ops must not shift.
#[test]
fn b9p12_label_stability() {
    let t = lower("    mov.u32 %r1, 1;\n    setp.gt.s32 %p1, %r1, %r2;\n    bfe.u32 %r2, %r1, 4, 12;\n    @%p1 bra $L_x;\n    clz.b32 %r3, %r1;\n$L_x:\n    bar.red.or.pred %p2, 0, %p1;\n    barrier.arrive 2, 128;");
    let li = t.lines().position(|x| x.trim() == "DL_x:").expect("no sanitized label DL_x");
    let prev = t.lines().nth(li - 1).unwrap().trim();
    assert!(prev.starts_with("IADD3"), "label follows clz fixup: {}", prev);
    let (b, n) = assemble_body(&t);
    assert_eq!(b.len(), n * 16);
    assert!(n > 20);
}

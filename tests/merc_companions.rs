//! `.nv.merc.*` sovereign companion emission (CUBIT_MERC13).
//!
//! nvcc 13.3.73 (-arch=sm_103a) laws, derived on 9 vendor cubins + rc4 (12.8)
//! donor; per-section byte-parity evidence in the internal fix archive
//!   * `.debug_frame`/`.nv.merc.debug_frame`: per-kernel [CIE][FDE] pairs
//!     (CIE repeated, not factored), FDE.cie_ptr = block offset, CFI programs
//!     driven by EXIT offsets (SASS) / Mercury st_size (merc), FDE range =
//!     .text size / merc st_size.
//!   * `.rela.debug_frame`/`.nv.merc.rela.debug_frame`: entry per FDE at
//!     block+0x44, sym = func sym, PC32 / 0x1003d, REVERSE kernel order.
//!   * `.nv.merc.symtab`: note syms, ".text.K" naming for the capmerc
//!     section, smem-anchor cluster after kernel 0, reserved/alias val=0.
//!   * `.nv.merc.nv.info*`: record law 66/37(0x85)/5a/17*/50/1b/[4c]/5f/4a/1c;
//!     global: (2f,11) reverse + (12) forward, regcount = min(sass,16).
//!   * symtab: 13.3 layout (note syms, sh_info = total count).
//!   * `.nv.compat`/`.note.nv.cuinfo`: per-arch 13.3 blobs, api 0x85.
//!   Default = ON since 2026-08-24 (owner flip; new chain anchor
//!   6a58a60642b913697d8ba3a3b9168504). CUBIT_MERC13=0 = legacy bytes:
//!   the frozen chain anchor 3d15ab6a.

use std::process::Command;

fn cubit() -> Command {
    Command::new(env!("CARGO_BIN_EXE_cubit"))
}

fn run_asm(sass: &str, tag: &str, merc13: bool) -> Vec<u8> {
    let dir = std::env::temp_dir().join(format!("merc13_{}_{}", tag, std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let src = dir.join(format!("{tag}.sass"));
    let out = dir.join(format!("{tag}.cubin"));
    let _ = std::fs::remove_file(&out);
    std::fs::write(&src, sass).unwrap();
    let mut c = cubit();
    c.args(["asm", "-t", "tables/sm103a.json", src.to_str().unwrap(), "-o", out.to_str().unwrap()]);
    if merc13 {
        c.env("CUBIT_MERC13", "1");
    } else {
        // explicit legacy path (default is merc13 since 2026-08-24)
        c.env("CUBIT_MERC13", "0");
    }
    let res = c.output().expect("run cubit asm");
    assert!(res.status.success(), "asm failed: {}", String::from_utf8_lossy(&res.stderr));
    std::fs::read(&out).unwrap()
}

// ── minimal ELF readers ─────────────────────────────────────────────────────
fn rd32(d: &[u8], o: usize) -> u32 { u32::from_le_bytes(d[o..o + 4].try_into().unwrap()) }
fn rd64(d: &[u8], o: usize) -> u64 { u64::from_le_bytes(d[o..o + 8].try_into().unwrap()) }

#[derive(Debug)]
struct Sec { name: String, ty: u32, size: usize, off: usize, link: u32, info: u32 }

fn sections(d: &[u8]) -> Vec<Sec> {
    let shoff = rd64(d, 0x28) as usize;
    let entsz = rd32(d, 0x3a) as usize & 0xffff;
    let num = rd32(d, 0x3c) as usize & 0xffff;
    let strndx = rd32(d, 0x3e) as usize & 0xffff;
    let stroff = rd64(d, shoff + strndx * entsz + 0x18) as usize;
    (0..num).map(|i| {
        let b = shoff + i * entsz;
        let noff = stroff + rd32(d, b) as usize;
        let e = d[noff..].iter().position(|&c| c == 0).unwrap();
        Sec {
            name: String::from_utf8_lossy(&d[noff..noff + e]).to_string(),
            ty: rd32(d, b + 4),
            size: rd64(d, b + 0x20) as usize,
            off: rd64(d, b + 0x18) as usize,
            link: rd32(d, b + 0x28),
            info: rd32(d, b + 0x2c),
        }
    }).collect()
}

fn sec<'a>(d: &'a [u8], name: &str) -> Option<(&'a [u8], Sec)> {
    let ss = sections(d);
    let s = ss.into_iter().find(|s| s.name == name)?;
    let size = if s.ty == 8 { 0 } else { s.size };
    let meta = Sec {
        name: s.name.clone(), ty: s.ty, size: s.size, off: s.off, link: s.link, info: s.info,
    };
    let off = s.off;
    Some((&d[off..off + size], meta))
}

#[derive(Debug)]
struct Sym { name: String, info: u8, other: u8, shndx: u16, val: u64, size: u64 }

fn symtab(d: &[u8], table: &str) -> Vec<Sym> {
    let ss = sections(d);
    let s = ss.iter().find(|s| s.name == table).unwrap();
    let strsec = &ss[s.link as usize];
    let strb = &d[strsec.off..strsec.off + strsec.size];
    (0..s.size / 24).map(|j| {
        let b = s.off + j * 24;
        let noff = rd32(d, b) as usize;
        let name = if noff == 0 { String::new() } else {
            let e = strb[noff..].iter().position(|&c| c == 0).unwrap();
            String::from_utf8_lossy(&strb[noff..noff + e]).to_string()
        };
        Sym {
            name,
            info: d[b + 4],
            other: d[b + 5],
            shndx: u16::from_le_bytes(d[b + 6..b + 8].try_into().unwrap()),
            val: rd64(d, b + 8),
            size: rd64(d, b + 16),
        }
    }).collect()
}

fn relas(d: &[u8], name: &str) -> Vec<(u64, u32, u32, i64)> {
    let ss = sections(d);
    let s = ss.iter().find(|s| s.name == name).unwrap();
    (0..s.size / 24).map(|j| {
        let b = s.off + j * 24;
        (rd64(d, b), (rd64(d, b + 8) >> 32) as u32, rd64(d, b + 8) as u32, rd64(d, b + 16) as i64)
    }).collect()
}

fn tlv(d: &[u8], name: &str) -> Vec<(u8, Vec<u8>)> {
    let ss = sections(d);
    let s = ss.iter().find(|s| s.name == name).unwrap();
    let b = &d[s.off..s.off + s.size];
    let mut out = Vec::new();
    let mut o = 0;
    while o + 4 <= b.len() {
        let (f, a) = (b[o], b[o + 1]);
        match f {
            4 => {
                let sz = u16::from_le_bytes([b[o + 2], b[o + 3]]) as usize;
                out.push((a, b[o + 4..o + 4 + sz].to_vec()));
                o = (o + 4 + sz + 3) & !3;
            }
            2 => { out.push((a, b[o + 2..o + 4].to_vec())); o += 4; }
            1 | 3 => { out.push((a, b[o + 2..o + 4].to_vec())); o += 4; }
            _ => o += 4,
        }
    }
    out
}

const K1: &str = ".entry k\n    .reg R0-R7\n\n    MOV R0, 0x1 ;\n    EXIT ;\n.endentry\n";
const K1_EARLY: &str = ".entry k\n    .reg R0-R15\n\n    ISETP.EQ.AND P0, PT, R0, R0, PT ;\n    @P0 EXIT ;\n    MOV R0, 0x1 ;\n    EXIT ;\n.endentry\n";
const K2: &str =
    ".entry ka\n    .reg R0-R7\n\n    MOV R0, 0x1 ;\n    EXIT ;\n.endentry\n\
     .entry kb\n    .reg R0-R7\n\n    MOV R0, 0x2 ;\n    EXIT ;\n.endentry\n";
const K_SMEM: &str = ".entry k\n    .reg R0-R15\n    .shared .align 16 smem[1024]\n\n    MOV R0, 0x0 ;\n    STS [R0], R0 ;\n    EXIT ;\n.endentry\n";

/// The constant 48B CIE (code_align=4 variant) from vendor cubins.
#[test]
fn m13_debug_frame_law() {
    let d = run_asm(K1, "k1", true);
    let (df, _) = sec(&d, ".debug_frame").unwrap();
    assert_eq!(df.len(), 0x68, "one CIE(48)+FDE(56) for one kernel");
    // CIE: DWARF64 marker + len 0x24 + id + ver3 + ca=4 + da=-4 + rar=0xffffffff
    assert_eq!(&df[0..4], &[0xff, 0xff, 0xff, 0xff]);
    assert_eq!(rd64(df, 0x04), 0x24);
    assert_eq!(&df[0x14..0x17], &[0x03, 0x00, 0x04]);
    assert_eq!(&df[0x18..0x1d], &[0xff, 0xff, 0xff, 0xff, 0x0f]);
    // FDE at 0x30: len 0x2c, cie_ptr 0, init_loc 0, range == .text size
    let (txt, _) = sec(&d, ".text.k").unwrap();
    assert_eq!(rd64(df, 0x30 + 4), 0x2c);
    assert_eq!(rd64(df, 0x30 + 12), 0);
    assert_eq!(rd64(df, 0x30 + 20), 0);
    assert_eq!(rd64(df, 0x30 + 28), txt.len() as u64);
    // 1-EXIT program: adv4(E/4); adv4(4); OP6; nop*4. E = 0x10 for K1.
    assert_eq!(&df[0x30 + 36..0x30 + 41], &[0x04, 0x04, 0x00, 0x00, 0x00]);
    assert_eq!(&df[0x30 + 41..0x30 + 46], &[0x04, 0x04, 0x00, 0x00, 0x00]);
    assert_eq!(&df[0x30 + 46..0x30 + 52], &[0x0c, 0x81, 0x80, 0x80, 0x28, 0x00]);
    let r = relas(&d, ".rela.debug_frame");
    let syms = symtab(&d, ".symtab");
    let fidx = syms.iter().position(|s| s.name == "k").unwrap() as u32;
    assert_eq!(r, vec![(0x44, fidx, 2, 0)]);
}

/// Two-EXIT (early-return) shape-B program, vendor golden bytes.
#[test]
fn m13_debug_frame_two_exits() {
    let d = run_asm(K1_EARLY, "k1e", true);
    let (df, _) = sec(&d, ".debug_frame").unwrap();
    let ss = sections(&d);
    let t = ss.iter().find(|s| s.name == ".text.k").unwrap();
    let code = &d[t.off..t.off + t.size];
    let e: Vec<u32> = (0..code.len() / 16)
        .filter(|&i| (u16::from_le_bytes([code[i * 16], code[i * 16 + 1]]) & 0x0fff) == 0x094d)
        .map(|i| (i * 16) as u32)
        .collect();
    assert!(e.len() >= 2, "fixture must carry 2 EXITs");
    let (a1, a2) = ((e[0] + 0x10) / 4, (e[1] - e[0] - 0x10) / 4);
    let mut want = vec![0x04];
    want.extend_from_slice(&a1.to_le_bytes());
    want.extend_from_slice(&[0x0c, 0x81, 0x80, 0x80, 0x28, 0x00]);
    want.push(0x04);
    want.extend_from_slice(&a2.to_le_bytes());
    want.extend_from_slice(&[0, 0, 0, 0]);
    assert_eq!(&df[0x30 + 36..0x30 + 56], &want[..]);
}

/// SASS rela + FDE ranges for a 2-kernel file; entries in reverse order.
#[test]
fn m13_two_kernel_order() {
    let d = run_asm(K2, "k2", true);
    let (df, _) = sec(&d, ".debug_frame").unwrap();
    assert_eq!(df.len(), 2 * 0x68);
    let r = relas(&d, ".rela.debug_frame");
    // vendor law: entries in REVERSE kernel order; block k's init field sits
    // at k*0x68 + 0x44. Derive the kernel order from the func syms' shndx
    // (robust to the pre-existing parse-order nondeterminism, merc.md F-1).
    let syms = symtab(&d, ".symtab");
    let mut funcs: Vec<&Sym> = syms.iter().filter(|s| s.info == 0x12).collect();
    funcs.sort_by_key(|s| s.shndx);
    let (f0, f1) = (funcs[0], funcs[1]);
    let i0 = syms.iter().position(|s| s.name == f0.name).unwrap() as u32;
    let i1 = syms.iter().position(|s| s.name == f1.name).unwrap() as u32;
    assert_eq!(r, vec![(0x68 + 0x44, i1, 2, 0), (0x44, i0, 2, 0)]);
    // global .nv.info: (2f,11) reverse, (12) forward
    let g = tlv(&d, ".nv.info");
    let attrs: Vec<(u8, u32)> =
        g.iter().map(|(a, v)| (*a, u32::from_le_bytes(v[0..4].try_into().unwrap()))).collect();
    assert_eq!(
        attrs,
        vec![(0x2f, i1), (0x11, i1), (0x2f, i0), (0x11, i0), (0x12, i0), (0x12, i1)],
        "vendor interleave: (2f,11) reversed, (12) forward"
    );
    // merc rela reversed, block stride 0x70
    // merc rela reversed as well (block stride 0x70), funcs in merc symtab
    // ordered by their capmerc shndx (kernel order)
    let mr = relas(&d, ".nv.merc.rela.debug_frame");
    let msym = symtab(&d, ".nv.merc.symtab");
    let mut mfuncs: Vec<&Sym> = msym.iter().filter(|s| s.info == 0x12).collect();
    mfuncs.sort_by_key(|s| s.shndx);
    let m0 = msym.iter().position(|s| s.name == mfuncs[0].name).unwrap() as u32;
    let m1 = msym.iter().position(|s| s.name == mfuncs[1].name).unwrap() as u32;
    assert_eq!(mr, vec![(0x70 + 0x44, m1, 0x1003d, 0), (0x44, m0, 0x1003d, 0)]);
}

/// Mercury symtab law: naming, vals, note syms, anchor position.
#[test]
fn m13_merc_symtab_law() {
    let d = run_asm(K_SMEM, "ks", true);
    let ms = symtab(&d, ".nv.merc.symtab");
    let names: Vec<&str> = ms.iter().map(|s| s.name.as_str()).collect();
    assert_eq!(names[1], ".note.nv.tkinfo");
    assert_eq!(names[2], ".note.nv.cuinfo");
    assert_eq!(names[3], ".text.k", "merc domain names its text '.text.K'");
    assert_eq!(names[4], ".nv.shared.k");
    assert_eq!(names[5], ".nv.reservedSmem.offset0");
    assert_eq!(names[6], "__nv_reservedSMEM_offset_0_alias");
    assert_eq!(names[7], ".nv.reservedSmem.cap");
    assert_eq!(names[8], ".debug_frame");
    assert_eq!(names[9], ".nv.callgraph");
    assert_eq!(names[10], "k");
    // vals: reserved/alias/cap = 0 in the Mercury domain
    assert_eq!(ms[5].val, 0);
    assert_eq!(ms[6].val, 0);
    assert_eq!(ms[7].val, 0);
    // plain domain keeps F-2 consts
    let ps = symtab(&d, ".symtab");
    assert_eq!(ps.iter().find(|s| s.name == ".nv.reservedSmem.offset0").unwrap().val, 0x40);
    assert_eq!(ps.iter().find(|s| s.name == ".nv.reservedSmem.cap").unwrap().val, 0x400);
    // capmerc section sym points at .nv.capmerc.text.k; func st_size = align16(cap len)
    let ss = sections(&d);
    let cap_idx = ss.iter().position(|s| s.name == ".nv.capmerc.text.k").unwrap() as u16;
    let shr_idx = ss.iter().position(|s| s.name == ".nv.shared.k").unwrap() as u16;
    assert_eq!(ms[3].shndx, cap_idx);
    assert_eq!(ms[4].shndx, shr_idx, "merc shared sym -> plain shared section");
    let cap_len = ss.iter().find(|s| s.name == ".nv.capmerc.text.k").unwrap().size as u64;
    assert_eq!(ms[10].size, (cap_len + 0xf) & !0xf, "phase-1 st_size law");
    assert_eq!(ms[10].info, 0x12, "GLOBAL FUNC");
    assert_eq!(ms[10].other, 0x10, "hidden");
    // .nv.shared.k sized user+0x400 (F-2), reserved.0 present
    assert_eq!(ss.iter().find(|s| s.name == ".nv.shared.k").unwrap().size, 1024 + 0x400);
}

/// Mercury info record law (both global- and per-kernel-side).
#[test]
fn m13_merc_info_law() {
    let d = run_asm(K1, "k1mi", true);
    let krecs = tlv(&d, ".nv.merc.nv.info.k");
    let attrs: Vec<u8> = krecs.iter().map(|(a, _)| *a).collect();
    assert_eq!(attrs, vec![0x66, 0x37, 0x5a, 0x50, 0x1b, 0x5f, 0x4a, 0x1c], "no-param kernel record set");
    assert_eq!(krecs[0].1, 3u32.to_le_bytes());
    assert_eq!(krecs[1].1, 0x85u32.to_le_bytes(), "api 0x85 (13.3)");
    assert_eq!(krecs[2].1.len(), 32, "hash is 32 bytes");
    assert_eq!(krecs[2].1[..4], [0x8a, 0x9d, 0x22, 0xa4]);
    assert_eq!(krecs[5].1, vec![1, 1], "0x5f = ISA 1.1");
    // 1c: [st-0x10]
    let syms = symtab(&d, ".nv.merc.symtab");
    let st = syms.iter().find(|s| s.name == "k").unwrap().size;
    assert_eq!(krecs[7].1, ((st - 0x10) as u32).to_le_bytes());
    // global: 2f/11/12 with regcount = min(sass_regcount,16), frame/stack 0
    let g = tlv(&d, ".nv.merc.nv.info");
    let fidx = syms.iter().position(|s| s.name == "k").unwrap() as u32;
    assert_eq!(g.len(), 3);
    assert_eq!(g[0].0, 0x2f);
    assert_eq!(u32::from_le_bytes(g[0].1[0..4].try_into().unwrap()), fidx);
    let mrc = u32::from_le_bytes(g[0].1[4..8].try_into().unwrap());
    let plain_rc = tlv(&d, ".nv.info")
        .into_iter().find(|(a, _)| *a == 0x2f)
        .map(|(_, v)| u32::from_le_bytes(v[4..8].try_into().unwrap())).unwrap();
    assert_eq!(mrc, plain_rc.min(16), "merc regcount = min(SASS regcount, 16)");
    assert_eq!(u32::from_le_bytes(g[1].1[4..8].try_into().unwrap()), 0);
    // no-smem kernel must NOT have .nv.shared.k, nor either cap sym
    let ss = sections(&d);
    assert!(ss.iter().all(|s| s.name != ".nv.shared.k"));
    let ps = symtab(&d, ".symtab");
    assert!(ps.iter().all(|s| s.name != ".nv.reservedSmem.cap"));
    // merc reserved = empty (13.3 + 12.8 law)
    assert_eq!(ss.iter().find(|s| s.name == ".nv.merc.nv.shared.reserved.0").unwrap().size, 0);
    // cuinfo/compat pinned to sm_103a 13.3 blobs
    let (cu, _) = sec(&d, ".note.nv.cuinfo").unwrap();
    assert_eq!(&cu[cu.len() - 8..], &[0x02, 0x00, 0x67, 0x00, 0x85, 0x00, 0x00, 0x00]);
    let (cp, _) = sec(&d, ".nv.compat").unwrap();
    assert_eq!(&cp[8..12], &[0x03, 0x0d, 0x01, 0x01]);
}

/// Flag OFF = byte-legacy contract (frozen chain anchor 3d15ab6a untouched).
#[test]
fn m13_default_is_legacy() {
    let d = run_asm(K1, "k1off", false);
    let (df, _) = sec(&d, ".debug_frame").unwrap();
    assert_eq!(df.len(), 0, "legacy: empty .debug_frame");
    let (rdf, _) = sec(&d, ".rela.debug_frame").unwrap();
    assert_eq!(rdf.len(), 0);
    let ms = symtab(&d, ".nv.merc.symtab");
    let names: Vec<&str> = ms.iter().map(|s| s.name.as_str()).collect();
    assert_eq!(names[1], ".nv.capmerc.text.k", "legacy merc naming");
    assert!(names.iter().all(|n| !n.starts_with(".note.")));
    let krecs = tlv(&d, ".nv.merc.nv.info.k");
    assert_eq!(krecs[0].0, 0x37, "legacy merc info starts with 0x37");
    assert!(krecs.iter().all(|(a, _)| *a != 0x5f && *a != 0x66), "legacy set");
    // shared section emitted even for 0-smem (legacy)
    let ss = sections(&d);
    assert!(ss.iter().any(|s| s.name == ".nv.shared.k"));
}

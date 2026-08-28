//! BUG-225 (F2-iter109, front2/blind): cross-census of the decoder's
//! generic prio-3 sign-bit fallback (window b62/63, b72/73, b74/75) for
//! rows NOT covered by the 199/210/211/224 is_memlike arms.
//!
//! Class taxonomy per (key, mod_group, flipped sign bit):
//!   vm_ok     — strict match still holds (bit covered by vm/fields):
//!               genuinely variable per training, no action;
//!   relaxed_ok / broad_ok — lower-priority legit fallbacks absorb it;
//!   hole      — decode fails: fail-closed already;
//!   prio3_absorb (glyph_equal | glyph_junk, chosen == origin | other) —
//!               the sign fallback absorbs the word: candidate arm class.
//!
//! Pass 1 enumerates the row space (all 3 tables); pass 2 measures real
//! exposure over the A/B 2014-corpus unique instruction words.
//!
//! Ignored census tests (heavy, evidence/replay); decision pins t225_*.
use cubit::decoder::DecodeIndex;
use cubit::printer::to_sass;
use cubit::table::{Extraction, IsaTable};
use std::collections::{BTreeMap, HashSet};

const M96: u128 = (1u128 << 96) - 1;
const GUARD: u128 = 0xF000; // bits [15:12]
const SIGN: [u32; 6] = [62, 63, 72, 73, 74, 75];

struct RowMasks {
    and_base: u128,
    match_mask: u128,
    relaxed: u128,
    broad: u128,
    no_fields: bool,
    is_mem_addr: bool,
}

fn masks(t: &IsaTable, key: &str, mg_name: &str) -> Option<RowMasks> {
    let e = t.entries.get(key)?;
    let mg = e.mod_groups.get(mg_name)?;
    let mut field_mask: u128 = 0;
    let mut imm_extra: u128 = 0;
    for f in &mg.fields {
        let fm: u128 = if f.bits >= 128 {
            u128::MAX
        } else {
            ((1u128 << f.bits) - 1) << f.shift
        };
        field_mask |= fm;
        let is_imm = matches!(
            f.extraction,
            Extraction::Imm
                | Extraction::ImmShr(_)
                | Extraction::ImmDec
                | Extraction::ImmDecU32
                | Extraction::F32
                | Extraction::F16
                | Extraction::F16d
                | Extraction::F64hi
                | Extraction::F32Cast
                | Extraction::SubR(_)
                | Extraction::SubUR(_)
                | Extraction::SubImm(_)
                | Extraction::SubImmS24(_)
                | Extraction::SubRShr(_, _)
                | Extraction::SubURShr(_, _)
                | Extraction::SubImmShr(_, _)
                | Extraction::SubImmShrU(_, _)
        );
        if is_imm {
            imm_extra |= fm;
        }
    }
    let match_mask = !mg.variable_mask & !field_mask;
    let relaxed = match_mask & !imm_extra;
    let std_reg: u128 =
        (0xFFu128 << 16) | (0xFFu128 << 24) | (0xFFFFFFFFu128 << 32) | (0xFFu128 << 64);
    let broad = relaxed & !std_reg;
    let is_mem_addr = key.contains("_ARI")
        || key.contains("_AI")
        || key.contains("dARI")
        || key.contains("ARURI");
    Some(RowMasks {
        and_base: mg.and_base & !(0xFFFFFFFFu128 << 96),
        match_mask,
        relaxed,
        broad,
        no_fields: mg.fields.is_empty(),
        is_mem_addr,
    })
}

/// Which level (if any) matches word `w` for this row (strict/relaxed/broad).
fn level(m: &RowMasks, w: u128) -> Option<&'static str> {
    if (w & m.match_mask & !GUARD) == (m.and_base & m.match_mask & !GUARD) {
        return Some("strict");
    }
    if (w & m.relaxed & !GUARD) == (m.and_base & m.relaxed & !GUARD) {
        return Some("relaxed");
    }
    if (m.no_fields || m.is_mem_addr) && (w & m.broad & !GUARD) == (m.and_base & m.broad & !GUARD) {
        return Some("broad");
    }
    None
}

fn base_of(key: &str) -> &str {
    key.split('_')
        .next()
        .unwrap_or("")
        .split('.')
        .next()
        .unwrap_or("")
}

fn load(p: &str) -> IsaTable {
    IsaTable::load(std::path::Path::new(p)).unwrap()
}

#[test]
#[ignore]
fn census225_rows() {
    let out_dir =
        std::env::var("BUG225_OUT").unwrap_or_else(|_| "/root/blindlab/work/bug225".into());
    for (name, tp) in [
        ("sm100a", "tables/sm100a.json"),
        ("sm103a", "tables/sm103a.json"),
        ("sm120", "tables/sm120.json"),
    ] {
        let t = load(tp);
        let idx = DecodeIndex::build(&t);
        let mut rows: Vec<(String, String)> = Vec::new();
        for (k, ike) in &t.entries {
            if ike.encode_only {
                continue;
            }
            for (mgn, mg) in &ike.mod_groups {
                if mg.encode_only {
                    continue;
                }
                rows.push((k.clone(), mgn.clone()));
            }
        }
        rows.sort();
        let mut agg: BTreeMap<String, BTreeMap<String, u64>> = BTreeMap::new();
        let mut events: Vec<String> = Vec::new();
        for (k, mgn) in &rows {
            let m = masks(&t, k, mgn).unwrap();
            let b = base_of(k).to_string();
            let d0 = idx.decode(m.and_base & M96, 0, &t);
            let (d0km, g0) = match &d0 {
                Ok(d) => (Some((d.key.clone(), d.mod_group.clone())), Some(to_sass(d))),
                Err(_) => (None, None),
            };
            if d0km.as_ref() != Some(&(k.clone(), mgn.clone())) {
                *agg.entry(b)
                    .or_default()
                    .entry("shadowed".into())
                    .or_insert(0) += 1;
                continue;
            }
            for &bit in &SIGN {
                let w1 = (m.and_base & M96) ^ (1u128 << bit);
                match level(&m, w1) {
                    Some("strict") => {
                        *agg.entry(b.clone())
                            .or_default()
                            .entry("vm_ok".into())
                            .or_insert(0) += 1;
                        continue;
                    }
                    Some("relaxed") => {
                        *agg.entry(b.clone())
                            .or_default()
                            .entry("relaxed_ok".into())
                            .or_insert(0) += 1;
                        continue;
                    }
                    Some("broad") => {
                        *agg.entry(b.clone())
                            .or_default()
                            .entry("broad_ok".into())
                            .or_insert(0) += 1;
                        continue;
                    }
                    _ => {}
                }
                let rec = |agg: &mut BTreeMap<String, BTreeMap<String, u64>>, cls: &str| {
                    *agg.entry(b.clone())
                        .or_default()
                        .entry(cls.into())
                        .or_insert(0) += 1;
                };
                match idx.decode(w1, 0, &t) {
                    Err(_) => rec(&mut agg, "hole"),
                    Ok(d1) => {
                        let chosen_prio = match masks(&t, &d1.key, &d1.mod_group) {
                            Some(cm) => level(&cm, w1).is_none(),
                            None => true,
                        };
                        if !chosen_prio {
                            rec(&mut agg, "other_row_direct");
                            continue;
                        }
                        let g1 = to_sass(&d1);
                        let same = d1.key == *k && d1.mod_group == *mgn;
                        let cls = match (same, g0.as_deref() == Some(g1.as_str())) {
                            (true, true) => "prio3_same_glypheq",
                            (true, false) => "prio3_same_glyphjunk",
                            (false, _) => "prio3_other_row",
                        };
                        rec(&mut agg, cls);
                        events.push(format!(
                            "{k} | {mgn} | b{bit} | {cls} | chosen={} | {} | w0={:024x} g0={} g1={}",
                            if same {
                                "SELF".into()
                            } else {
                                format!("{}/{}", d1.key, d1.mod_group)
                            },
                            if m.no_fields { "nofields" } else { "fields" },
                            m.and_base & M96,
                            g0.clone().unwrap_or_default(),
                            g1
                        ));
                    }
                }
            }
        }
        let mut s = String::new();
        for (b, m) in &agg {
            s.push_str(&format!("{b}:"));
            for (c, n) in m {
                s.push_str(&format!(" {c}={n}"));
            }
            s.push('\n');
        }
        std::fs::write(format!("{out_dir}/census225_{name}_agg.txt"), &s).unwrap();
        std::fs::write(
            format!("{out_dir}/census225_{name}_events.txt"),
            events.join("\n"),
        )
        .unwrap();
        eprintln!("== {name}: rows={} events={}", rows.len(), events.len());
    }
}

/// Pass 2: real exposure — unique corpus words whose ONLY decode path on the
/// chosen row is prio-3, grouped by (table, key, mod_group).
#[test]
#[ignore]
fn census225_corpus() {
    let out_dir =
        std::env::var("BUG225_OUT").unwrap_or_else(|_| "/root/blindlab/work/bug225".into());
    let list = std::fs::read_to_string("/root/blindlab/work/bug220/ab103.list").unwrap();
    let mut words: HashSet<u128> = HashSet::new();
    for (i, path) in list.split_whitespace().enumerate() {
        if i % 400 == 0 {
            eprintln!("..scan {i}/2014");
        }
        let out = match std::process::Command::new("readelf")
            .args(["-S", "-W", path])
            .output()
        {
            Ok(o) => o,
            Err(_) => continue,
        };
        let txt = String::from_utf8_lossy(&out.stdout);
        let data = match std::fs::read(path) {
            Ok(d) => d,
            Err(_) => continue,
        };
        for l in txt.lines() {
            if let Some((fo, sz)) = text_section(l) {
                let end = (fo + sz).min(data.len());
                let blob = &data[fo..end];
                let mut off = 0usize;
                while off + 16 <= blob.len() {
                    let lo = u64::from_le_bytes(blob[off..off + 8].try_into().unwrap());
                    let hi = u64::from_le_bytes(blob[off + 8..off + 16].try_into().unwrap());
                    // decode strips [127:96]; identity = low96 (incl guard)
                    words.insert((((hi as u128) << 64) | lo as u128) & M96);
                    off += 16;
                }
            }
        }
    }
    eprintln!("unique words: {}", words.len());
    let mut dump = String::new();
    for (name, tp) in [
        ("sm100a", "tables/sm100a.json"),
        ("sm103a", "tables/sm103a.json"),
        ("sm120", "tables/sm120.json"),
    ] {
        let t = load(tp);
        let idx = DecodeIndex::build(&t);
        let mut per_row: BTreeMap<(String, String), Vec<String>> = BTreeMap::new();
        for &wl in &words {
            let d = match idx.decode(wl, 0, &t) {
                Ok(d) => d,
                Err(_) => continue,
            };
            let cm = match masks(&t, &d.key, &d.mod_group) {
                Some(m) => m,
                None => continue,
            };
            if level(&cm, wl).is_some() {
                continue;
            }
            per_row
                .entry((d.key.clone(), d.mod_group.clone()))
                .or_default()
                .push(format!("{wl:024x} {}", to_sass(&d)));
        }
        let mut s = String::new();
        let mut total = 0u64;
        let mut full: Vec<String> = Vec::new();
        for ((k, mg), v) in &per_row {
            total += v.len() as u64;
            s.push_str(&format!(
                "{k} | {mg} | {} words | base={}\n",
                v.len(),
                base_of(k)
            ));
            for e in v.iter().take(3) {
                s.push_str(&format!("    {e}\n"));
            }
            for e in v {
                full.push(format!("{name} | {k} | {mg} | {e}"));
            }
        }
        dump.push_str(&format!(
            "=== {name}: prio3-corpus rows={} words={total}\n{s}",
            per_row.len()
        ));
        std::fs::write(
            format!("{out_dir}/census225_corpus_full_{name}.txt"),
            full.join("\n"),
        )
        .unwrap();
    }
    std::fs::write(format!("{out_dir}/census225_corpus_exposure.txt"), &dump).unwrap();
    eprintln!("pass2 done");
}

/// Parse a `readelf -S -W` line into (file_off, size) for .text.* PROGBITS.
fn text_section(l: &str) -> Option<(usize, usize)> {
    if !l.contains("] .text.") || !l.contains("PROGBITS") {
        return None;
    }
    let toks: Vec<&str> = l.split_whitespace().collect();
    let pi = toks.iter().position(|t| *t == "PROGBITS")?;
    let off = usize::from_str_radix(toks.get(pi + 2)?, 16).ok()?;
    let sz = usize::from_str_radix(toks.get(pi + 3)?, 16).ok()?;
    Some((off, sz))
}

// ---------------------------------------------------------------------------
// Decision pins (post-arm state).
// ---------------------------------------------------------------------------

/// The census-driven arm batch (must mirror the two lists in src/decoder.rs).
const ARMED: &[&str] = &[
    "NANOSLEEP",
    "DEPBAR",
    "LDGDEPBAR",
    "ERRBAR",
    "CGAERRBAR",
    "UCGABAR",
    "UTCBAR",
    "BPT",
    "MEMBAR",
    "ACQBULK",
    "ACQSHMINIT",
    "ENDCOLLECTIVE",
    "CCTL",
    "YIELD",
    "PREEXIT",
    "WARPSYNC",
    "ELECT",
    "MATCH",
    "B2R",
    "CS2R",
    "CS2UR",
    "P2R",
    "BREAK",
    "BRX",
    "CALL",
    "BMOV",
    "UGETNEXTWORKID",
    "UVIRTCOUNT",
    "QSPC",
    "RPCMOV",
    "SHFL",
    "UBLKCP",
    "UBLKPF",
    "UBLKRED",
    "R2P",
    "R2UR",
    "UP2UR",
    "LDTM",
    "STTM",
    "STAS",
    "STSM",
    "UTCCP",
    "UTMALDG",
    "UTMAPF",
    "UTMAREDG",
    "UTMASTG",
    "UTMACCTL",
    "UTMACMDFLUSH",
    "UTCATOMSWS",
    "UTCHMMA",
    "UTCIMMA",
    "UTCQMMA",
    "SULD",
];

/// Structural pin: for every armed-base row on every table, no sign-window
/// flip may be re-absorbed onto the SAME row via the prio-3 fallback
/// (pre-arm census classes prio3_same_glypheq/prio3_same_glyphjunk must be
/// extinct). Absorption by a *different*, non-armed row remains allowed and
/// is logged (prio3_other_row drain) for future arm batches.
#[test]
fn t225_1_armed_bases_no_prio3_self_absorb_x3() {
    for tp in [
        "tables/sm100a.json",
        "tables/sm103a.json",
        "tables/sm120.json",
    ] {
        let t = load(tp);
        let idx = DecodeIndex::build(&t);
        let mut rows: Vec<(&String, &String)> = Vec::new();
        for (k, ike) in &t.entries {
            if ike.encode_only {
                continue;
            }
            if !ARMED.contains(&base_of(k)) {
                continue;
            }
            for mgn in ike.mod_groups.keys() {
                rows.push((k, mgn));
            }
        }
        assert!(!rows.is_empty(), "{tp}: no armed rows found");
        let mut drift = 0u64;
        for (k, mgn) in rows {
            if t.entries[k].mod_groups[mgn].encode_only {
                continue;
            }
            let m = masks(&t, k, mgn).unwrap();
            match idx.decode(m.and_base & M96, 0, &t) {
                Ok(d) if d.key == *k && &d.mod_group == mgn => {}
                _ => continue, // shadowed origin rows: out of pin scope
            }
            for &bit in &SIGN {
                let w1 = (m.and_base & M96) ^ (1u128 << bit);
                if level(&m, w1).is_some() {
                    continue; // strict/relaxed/broad still own the flip
                }
                if let Ok(d) = idx.decode(w1, 0, &t) {
                    let cbase = base_of(&d.key).to_string();
                    assert!(
                        !(d.key == *k
                            && &d.mod_group == mgn
                            && masks(&t, &d.key, &d.mod_group)
                                .map(|cm| level(&cm, w1).is_none())
                                .unwrap_or(false)),
                        "{tp}: prio-3 SELF-absorb post-arm: {k}|{mgn} b{bit}"
                    );
                    if d.key != *k || &d.mod_group != mgn {
                        // Cross-row selection drift (strict/relaxed/broad of a
                        // sibling row owns the flipped word instead of the
                        // pre-arm prio-3 self-absorb) — legal, pre-existing
                        // behavior class; counted for the report only.
                        drift += 1;
                    }
                }
            }
        }
        eprintln!("{tp}: cross-row drift count post-arm: {drift}");
    }
}

/// Anchors stay alive: armed rows' canonical (and_base) words decode to the
/// identical glyph text as pre-arm (control-positive; the arm only narrows
/// the fallback, never strict matches).
/// (table, w0 low96, expected glyph) — glyphs recorded by census pass 1.
const ANCHORS: &[(&[&str], u128, &str)] = &[
    (&["a", "c"], 0x03800000000000400000795d, "NANOSLEEP 0x40"),
    (&["s"], 0x00000000000000000000095d, "@P0 NANOSLEEP 0x0"),
    (
        &["a", "c", "s"],
        0x00000000000080000000791a,
        "DEPBAR.LE SB0, 0x0",
    ),
    (
        &["a", "c"],
        0x038000000000000000ff082f,
        "@P0 ELECT P0, URZ, PT",
    ),
    (
        &["s"],
        0x000000000000000000ff082f,
        "@P0 ELECT_P0 P0, UR0, P0",
    ),
    (&["a", "c"], 0x000e800000000000000073a1, "MATCH.ANY R0, R0"),
    (&["s"], 0x000e000000000000000003a1, "@P0 MATCH.ANY R0, R0"),
    (&["a", "c"], 0x0200000000000000ff00098f, "@P0 CCTL.IVALL"),
    (&["s"], 0x0000000000000000ff00098e, "@P0 CCTL.IVALL"),
    (&["a", "c", "s"], 0x0000000000000000000009ab, "@P0 ERRBAR"),
    (
        &["a", "c"],
        0x000080000000000000000992,
        "@P0 MEMBAR.CTA.ALL",
    ),
    (&["s"], 0x000020000000000000007992, "MEMBAR.GPU.SC"),
    (&["a", "c"], 0x00300000000000040000795c, "BPT.TRAP 0x1"),
    (&["s"], 0x00300000000000040000095c, "@P0 BPT.TRAP 0x0"),
    (&["a", "c", "s"], 0x038000000000000000007946, "YIELD"),
    (&["a", "c"], 0x00000000000000000000782d, "PREEXIT"),
    (&["s"], 0x00000000000000000000082d, "@P0 PREEXIT"),
    (&["a", "c"], 0x038000000000000000007948, "WARPSYNC.ALL"),
    (&["s"], 0x038000000000000000007348, "WARPSYNC"),
    (&["a", "c"], 0x000000000000000000ff72ca, "R2UR P0, URZ, R0"),
    (&["s"], 0x000e000000000000000002ca, "@P0 R2UR UR0, R0"),
    (
        &["a", "c"],
        0x000000000800000000007f89,
        "SHFL.DOWN P0, R0, R0, 0x0, 0x0",
    ),
    (
        &["s"],
        0x000e00000c00000000007f89,
        "SHFL.BFLY PT, R0, R0, 0x0, 0x0",
    ),
    (&["a", "c"], 0x0000000000000000000005ab, "@P0 CGAERRBAR"),
    (&["s"], 0x0000000000000000000075ab, "CGAERRBAR"),
    (
        &["a", "c"],
        0x03c000000000000000907944,
        "CALL.REL.NOINC 0x250",
    ),
    (&["a", "c"], 0x0383fffffffffff800007949, "BRX R0, -0x800"),
    (
        &["a", "c"],
        0x0838000000000000010009e7,
        "@UP0 UTCCP.T.S.2CTA.128dp128bit tmem[UR1], gdesc[UR0]",
    ),
    (
        &["a", "c"],
        0x0820900000000008100075b4,
        "UTMALDG.2D.2CTA [UR8], [UR16], desc[UR0]",
    ),
    (
        &["a", "c"],
        0x0804000000000000000079ee,
        "LDTM R0, tmem[UR0]",
    ),
    (
        &["a", "c"],
        0x080400c000000001000079ed,
        "STTM tmem[UR192], R1",
    ),
    (
        &["a", "c"],
        0x000007000000000000ff73aa,
        "QSPC.E.D P0, RZ, [R0]",
    ),
    (
        &["a", "c"],
        0x0800020000000000000003ba,
        "@UP0 UBLKCP.S.G [UR0], [UR0], UR0",
    ),
];

fn tabs_of(spec: &[&str]) -> Vec<&'static str> {
    let mut v = Vec::new();
    for s in spec {
        v.push(match *s {
            "a" => "tables/sm100a.json",
            "c" => "tables/sm103a.json",
            _ => "tables/sm120.json",
        });
    }
    v
}

#[test]
fn t225_2_anchors_alive_ident_glyph() {
    for (spec, w, glyph) in ANCHORS {
        for tp in tabs_of(spec) {
            let t = load(tp);
            let idx = DecodeIndex::build(&t);
            let got = idx
                .decode(w & M96, 0, &t)
                .map(|d| to_sass(&d))
                .unwrap_or_else(|e| panic!("{tp}: anchor HOLE {w:024x} ({glyph}): {e}"));
            assert_eq!(&got, glyph, "{tp}: anchor glyph drift {w:024x}");
        }
    }
}

/// Negative pins: the pre-arm prio-3 SELF-absorb words (exact flips from the
/// census evidence) must no longer decode as the armed base — fail-closed
/// (HOLE) or, at worst, a different non-armed row's claim. Fails on the
/// pre-arm build by construction (negative control).
const NEGS: &[(&[&str], u128, u32, &str)] = &[
    (&["a", "c"], 0x03800000000000400000795d, 72, "NANOSLEEP"),
    (&["s"], 0x00000000000000000000095d, 72, "NANOSLEEP"),
    (&["s"], 0x00000000000000000000095d, 73, "NANOSLEEP"),
    (&["a", "c", "s"], 0x00000000000080000000791a, 62, "DEPBAR"),
    (&["a", "c", "s"], 0x00000000000080000000791a, 75, "DEPBAR"),
    (&["a", "c"], 0x038000000000000000ff082f, 62, "ELECT"),
    (&["s"], 0x000000000000000000ff082f, 63, "ELECT"), // pre: -UR0 junk
    (&["a", "c"], 0x000e800000000000000073a1, 62, "MATCH"),
    (&["a", "c"], 0x0200000000000000ff00098f, 62, "CCTL"),
    (&["s"], 0x0000000000000000ff00098e, 63, "CCTL"),
    (&["a", "c", "s"], 0x0000000000000000000009ab, 62, "ERRBAR"),
    (&["a", "c"], 0x000080000000000000000992, 62, "MEMBAR"),
    (&["s"], 0x000020000000000000007992, 72, "MEMBAR"),
    (&["a", "c"], 0x00300000000000040000795c, 72, "BPT"),
    (&["a", "c", "s"], 0x038000000000000000007946, 72, "YIELD"),
    (&["a", "c"], 0x00000000000000000000782d, 72, "PREEXIT"),
    (&["a", "c"], 0x038000000000000000007948, 72, "WARPSYNC"),
    (&["s"], 0x038000000000000000007348, 62, "WARPSYNC"),
    (&["a", "c"], 0x000000000000000000ff72ca, 62, "R2UR"), // pre: |R0| junk
    (&["s"], 0x000e000000000000000002ca, 62, "R2UR"),
    (&["a", "c"], 0x000000000800000000007f89, 62, "SHFL"), // pre: |R0| junk
    (&["a", "c"], 0x000000000800000000007f89, 63, "SHFL"),
    (&["s"], 0x000e00000c00000000007f89, 63, "SHFL"), // pre: -R0 junk
    (&["a", "c"], 0x0000000000000000000005ab, 62, "CGAERRBAR"),
    (&["s"], 0x0000000000000000000075ab, 72, "CGAERRBAR"),
    (&["a", "c"], 0x03c000000000000000907944, 72, "CALL"),
    (&["a", "c"], 0x0383fffffffffff800007949, 62, "BRX"),
    (&["a", "c"], 0x0838000000000000010009e7, 62, "UTCCP"),
    (&["a", "c"], 0x0820900000000008100075b4, 62, "UTMALDG"),
    (&["a", "c"], 0x0804000000000000000079ee, 72, "LDTM"),
    (&["a", "c"], 0x080400c000000001000079ed, 62, "STTM"), // pre: |R1| junk
    (&["a", "c"], 0x000007000000000000ff73aa, 72, "QSPC"),
    (&["a", "c"], 0x0800020000000000000003ba, 72, "UBLKCP"),
];

#[test]
fn t225_3_negatives_fail_closed_not_self() {
    for (spec, w0, bit, base) in NEGS {
        let w1 = (w0 & M96) ^ (1u128 << bit);
        for tp in tabs_of(spec) {
            let t = load(tp);
            let idx = DecodeIndex::build(&t);
            if let Ok(d) = idx.decode(w1, 0, &t) {
                assert_ne!(
                    base_of(&d.key),
                    *base,
                    "{tp}: prio-3 self-absorb still alive {base} b{bit} ({})",
                    to_sass(&d)
                );
            }
        }
    }
}

/// Exclusion lock: bases with MEASURED corpus exposure of the prio-3 path
/// (VOTE/VOTEU/USETMAXREG/FENCE on sm120) are deliberately NOT armed — their
/// real words must keep decoding (their glyph-vs-vendor mismatch is the
/// separate 226 finding; see results/cubitfix/225.md sec. 5).
#[test]
fn t225_4_exposed_bases_not_silenced() {
    let t = load("tables/sm120.json");
    let idx = DecodeIndex::build(&t);
    for (w, base) in [
        (0x060e01000000000000157806u128, "VOTE"),
        (0x028801000000000000ffa886u128, "VOTEU"),
        (0x08000600000000e0000079c8u128, "USETMAXREG"),
        (0x0000020000000000000073c6u128, "FENCE"),
    ] {
        let d = idx
            .decode(w, 0, &t)
            .unwrap_or_else(|e| panic!("exposed-base word must keep decoding ({base}): {e}"));
        assert_eq!(base_of(&d.key), base, "armed by accident?");
    }
}

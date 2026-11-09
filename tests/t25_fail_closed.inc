// tests/t25_fail_closed.inc -- 2026-11-09 (session T-25). Included by the 2026-08/09 battery tests whose witness words
// carry text-inert bits.
//
// The measured-row doctrine (T-18 .. T-24, KNOWN_ISSUES T1): a row measured field by field (`_src` `rows-<family>-…`,
// `ModGroupEntry::row_probe`) has its fields for its mask and fails closed on every other bit -- nvdisasm prints the same
// text with the bit set or clear (text-inert), the row does not claim the word, cubit renders nothing rather than a text
// that would re-encode to a different word; and inside a measured row's neighbourhood a harvest sibling may not take the
// word through the broad address fallback either (T-24's zone rule, src/decoder.rs). The harvest rows (bugNNN tags) keep
// their tolerant windows elsewhere. T-23's per-row passes on -b SM121 / SM103 / SM100 measured the LDS / STS / LDSM /
// STSM / LDG / STG / LDC / HFMA2 / SHFL rows the battery's junk-bit witnesses sit on; the witnesses' texts are unchanged,
// their words are HOLEs on the measured legs.
//
// `t25_closed` is the battery's reading of such a word: the render of the clean word -- the witness with its junk bits
// cleared -- of the nearest row of the witness' opcode whose `and_base` the witness covers (measured or harvest: the
// junk bits are the bits the row neither fixes nor reads). The pin keeps the vendor text (the clean word must render it)
// and tolerates the fail-closed outcome on the junk bits; a kill word (vendor rc != 0) is still asserted `None` through
// the plain `dec`, never through this reading.
#[allow(dead_code)]
fn t25_closed(t: &cubit::table::IsaTable, w: u128) -> Option<String> {
    t25_closed_as(t, w, None)
}

/// The reading with the vendor text in hand: among the rows of the witness' opcode within sixteen bits of it (junk
/// bits the witness sets, or `and_base` bits of the row's canonical word it lacks -- an inert bit baked into a measured
/// row's `and_base`, like the upper half of a HADD2.F32 immediate), the nearest whose clean word renders `want`; without
/// `want`, the nearest row whose `and_base` the witness covers (junk bits only -- a witness lacking a bit of a row's
/// `and_base` is another form, not that row's junk).
#[allow(dead_code)]
fn t25_closed_as(t: &cubit::table::IsaTable, w: u128, want: Option<&str>) -> Option<String> {
    const M96: u128 = (1u128 << 96) - 1;
    let idx = cubit::decoder::DecodeIndex::build(t);
    let w = w & M96;
    let norm = |s: &str| s.trim().trim_end_matches(';').trim().to_string();
    let mut cands: Vec<(u32, bool, u128)> = Vec::new();
    for e in t.entries.values() {
        if e.encode_only {
            continue;
        }
        for mg in e.mod_groups.values() {
            let fm = mg.fields.iter().fold(0u128, |m, f| m | (((1u128 << f.bits) - 1) << f.shift));
            let d = (w ^ mg.and_base) & !fm & M96;
            // the same opcode byte, a handful of bits apart
            if d == 0 || d & 0xfff != 0 || d.count_ones() > 16 {
                continue;
            }
            cands.push((d.count_ones(), d & !w != 0, (w & fm) | (mg.and_base & M96 & !fm)));
        }
    }
    // junk-only candidates first, then by distance
    cands.sort_by_key(|&(n, missing, _)| (missing, n));
    let render = |clean: u128| idx.decode(clean, 0, t).ok().map(|d| cubit::printer::to_sass(&d));
    match want {
        None => cands.iter().find(|c| !c.1).and_then(|c| render(c.2)),
        Some(want) => {
            let want = norm(want);
            let mut nearest = None;
            for c in &cands {
                if let Some(text) = render(c.2) {
                    if norm(&text) == want {
                        return Some(text);
                    }
                    nearest.get_or_insert(text);
                }
            }
            nearest
        }
    }
}

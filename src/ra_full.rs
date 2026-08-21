//! M4.3b (BARRACUDA b1): full register allocation FROM ZERO.
//!
//! The input kernel's register numerals are treated as SYMBOLS: the plan is
//! computed purely from the liveness/spans dataflow (M3/M3.5), never read
//! from the seed numbering. A pure RENAMING (bijection on live sets per
//! instruction) is semantics-preserving by construction; the pass proves it
//! machine-checked instead of trusting the algorithm:
//!
//!   * span groups (WIDE pairs, .128 quads, .256 octets, addr-pair bases)
//!     are union-find linked: every symbol group keeps its old RELATIVE
//!     offsets, so implied members land where the encoder expects them
//!     (a `[Rx.64]` address operand prints only `Rx`; its high member must
//!     be exactly `map(Rx)+1`).
//!   * entry-live symbols (rlive_in/ulive_in of the first instruction) come
//!     from the hardware ABI: renaming a read of, say, physical R7 would
//!     desync from where the value actually sits. These groups are pinned
//!     to identity and counted (census tripwire: R0b has ZERO; M3.5 Q1).
//!   * conflicts are computed from the CFG dataflow (`reg_liveness`):
//!     two symbols conflict iff they co-occur in any instruction's
//!     (live_in U live_out U defs U uses), all span-expanded.
//!   * linear-scan over groups (order: first-live position, then size desc,
//!     then anchor) with lowest-free-base fit; pool R: 0..=253 (RZ=255 and
//!     the regcount-granule shadow R254/R255 are out, BUG-040 shape: the
//!     tail two registers of the declared granule are never value homes),
//!     UR: 0..=62 (URZ sink out; UR63-real kept only via identity pin when
//!     present -- allocator never hands it out fresh).
//!   * fail-closed: pool exhaustion, entry-live pin conflict, non-interval
//!     span group, and the post-allocation per-instruction injectivity audit
//!     over span-expanded co-occurrence sets.
//!
//! v0 scope notes: no value splitting (one home per symbol per kernel), no
//! spilling (kernels are static 200-2000 insn, ALU-dominated -- the budget
//! is met or the pass refuses), `.reg` directive left unchanged (EIATTR
//! over-provision is safe; shrinking is a later milestone), predicate and
//! uniform-predicate domains are not renamed.

use crate::reg_liveness::{InsRegLive, RegDom, RegXfer};
use anyhow::{bail, Result};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

/// Highest R datum handed out (pool is inclusive). R254/R255 stay out:
/// RZ (=255) is a sink and the (N-2)/(N-1) granule shadow is ABI-fragile.
pub const R_POOL_MAX: u8 = 253;
/// Highest UR datum handed out. UR63 encodes URZ in 8-bit slots (zero);
/// UR63-as-real-value stays only when already used (identity-pinned).
pub const UR_POOL_MAX: u8 = 62;

#[derive(Debug, Clone, Serialize)]
pub struct FullDomainStats {
    pub symbols: usize,
    pub groups: usize,
    /// Highest physical numeral handed out (inclusive) + 1 == watermark.
    pub watermark: u8,
    /// Highest OLD numeral seen (pen-and-paper "before" reference).
    pub old_max: Option<u8>,
    pub pinned: usize,
    pub singleton_width1: usize,
    pub max_group_width: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct FullAllocStats {
    pub r: FullDomainStats,
    pub ur: FullDomainStats,
    /// Entry-live symbols pinned to identity (ABI); [] on the certified R0b.
    pub entry_pins: Vec<String>,
    /// Operand-occurrence numerals the plan changes (== apply changed).
    pub renamed: usize,
}

// ---------------------------------------------------------------- union-find

struct Uf {
    parent: Vec<u8>,
}

impl Uf {
    fn new(n: usize) -> Self {
        Uf { parent: (0..n as u8).collect() }
    }
    fn find(&mut self, x: u8) -> u8 {
        let mut r = x;
        while self.parent[r as usize] != r {
            r = self.parent[r as usize];
        }
        let mut c = x;
        while self.parent[c as usize] != r {
            let nxt = self.parent[c as usize];
            self.parent[c as usize] = r;
            c = nxt;
        }
        r
    }
    fn union(&mut self, a: u8, b: u8) {
        let ra = self.find(a);
        let rb = self.find(b);
        if ra != rb {
            self.parent[ra as usize] = rb;
        }
    }
}

/// Symbols grouped by span linkage. Key: anchor (min old numeral); value:
/// consecutive old numerals anchor..=end (asserted gapless).
type Groups = BTreeMap<u8, BTreeSet<u8>>;

/// A span reaching the domain end (e.g. a .128 quad at R252 whose 4th word
/// is the RZ-sink) is silicon-certified on the corpus but NOT freely
/// placeable: after a rename the hardware still writes ALL width members,
/// and the clipped tail would clobber whatever physical home we chose.
/// Such groups are pinned to identity (liveness already clips the sets, so
/// only the placed-members check matters) and counted as `clip_span_pins`.
fn build_groups(
    xfers: &[RegXfer],
    dom: RegDom,
    dom_excl: u8,
) -> Result<(Groups, BTreeSet<u8>, BTreeMap<u8, u8>, BTreeMap<u8, u8>)> {
    let mut uf = Uf::new(dom_excl as usize);
    let mut touched: BTreeSet<u8> = BTreeSet::new();
    let mut clip_spans: Vec<(u8, usize)> = Vec::new();
    for x in xfers {
        for sp in &x.spans {
            if sp.dom != dom || sp.desc_ns {
                continue;
            }
            let mut clipped = false;
            for k in 0..sp.width as u32 {
                let r = sp.base as u32 + k;
                if r >= dom_excl as u32 {
                    clipped = true;
                    continue;
                }
                let r = r as u8;
                touched.insert(r);
                if k > 0 {
                    uf.union(sp.base, r);
                }
            }
            if clipped {
                clip_spans.push((sp.base, sp.width));
            }
        }
        let sets = match dom {
            RegDom::R => [&x.rdefs, &x.ruses],
            _ => [&x.udefs, &x.uuses],
        };
        for s in sets {
            touched.extend(s.iter().copied());
        }
    }
    let mut groups: Groups = BTreeMap::new();
    for &s in &touched {
        let root = uf.find(s);
        groups.entry(root).or_default().insert(s);
    }
    // anchor=min, assert gapless (span unions are interval-connected)
    // Remember every member of every clipped span: any group containing one
    // is forced to identity below (member-level, roots unneeded).
    let clip_members: BTreeSet<u8> = {
        let mut cm = BTreeSet::new();
        for x in xfers {
            for sp in &x.spans {
                if sp.dom != dom || sp.desc_ns {
                    continue;
                }
                if sp.base as u32 + sp.width as u32 > dom_excl as u32 {
                    for k in 0..sp.width as u32 {
                        let r = sp.base as u32 + k;
                        if r < dom_excl as u32 {
                            cm.insert(r as u8);
                        }
                    }
                }
            }
        }
        cm
    };
    let _ = &clip_spans;
    // per-symbol alignment applies to span BASES only (the aligned tuple
    // start); interior members carry no constraint of their own.
    let mut sym_align: BTreeMap<u8, u8> = BTreeMap::new();
    for x in xfers {
        for sp in &x.spans {
            if sp.dom != dom || sp.desc_ns || sp.align <= 1 {
                continue;
            }
            if (sp.base as u32) < dom_excl as u32 {
                let e = sym_align.entry(sp.base).or_insert(1);
                if sp.align > *e {
                    *e = sp.align;
                }
            }
        }
    }
    let mut keyed: Groups = BTreeMap::new();
    for (_root, members) in groups {
        let anchor = *members.iter().next().unwrap();
        let mut expect = anchor;
        for &m in &members {
            if m != expect {
                bail!(
                    "ra full: non-interval span group in {:?} ({}..{} has a hole at {})",
                    dom, anchor, members.iter().last().unwrap(), expect
                );
            }
            expect = expect.saturating_add(1);
        }
        keyed.insert(anchor, members);
    }
    let force_identity: BTreeSet<u8> = keyed
        .iter()
        .filter(|(_, members)| members.iter().any(|m| clip_members.contains(m)))
        .map(|(&anchor, _)| anchor)
        .collect();
    // anchor -> required base alignment (max over members). Alignment is
    // data-driven (span marks), never guessed: only MMA tuples carry >1
    // today (BUG-037 encoder rule), everything else stays at 1.
    let group_align: BTreeMap<u8, u8> = keyed
        .iter()
        .map(|(&anchor, members)| {
            let a = members
                .iter()
                .filter_map(|m| sym_align.get(m).copied())
                .max()
                .unwrap_or(1);
            (anchor, a)
        })
        .collect();
    Ok((keyed, force_identity, group_align, sym_align))
}

/// Co-occurrence (conflict) sets between GROUPS, from the dataflow:
/// co(sym at ins i) = live_in U live_out U defs U uses (span-expanded).
fn conflicts(
    live: &[InsRegLive],
    groups_members: &Groups,
    dom: RegDom,
) -> BTreeMap<u8, BTreeSet<u8>> {
    let mut owner: BTreeMap<u8, u8> = BTreeMap::new();
    for (&anchor, members) in groups_members {
        for &m in members {
            owner.insert(m, anchor);
        }
    }
    let mut conf: BTreeMap<u8, BTreeSet<u8>> = BTreeMap::new();
    for row in live {
        let (a, b, c, d) = match dom {
            RegDom::R => (&row.rlive_in, &row.rlive_out, &row.rdefs, &row.ruses),
            _ => (&row.ulive_in, &row.ulive_in, &row.udefs, &row.uuses),
        };
        let mut co: BTreeSet<u8> = BTreeSet::new();
        co.extend(a.iter().chain(b.iter()).chain(c.iter()).chain(d.iter()).copied());
        let mut gset: BTreeSet<u8> = BTreeSet::new();
        for &s in &co {
            if let Some(&g) = owner.get(&s) {
                gset.insert(g);
            }
        }
        for &g1 in &gset {
            let e = conf.entry(g1).or_default();
            for &g2 in &gset {
                if g2 != g1 {
                    e.insert(g2);
                }
            }
        }
    }
    conf
}

/// First instruction index where any member of the group is referenced.
fn first_live_pos(groups_members: &BTreeSet<u8>, live: &[InsRegLive], dom: RegDom) -> u32 {
    let mut best = u32::MAX;
    for (i, row) in live.iter().enumerate() {
        let (a, b, c, d) = match dom {
            RegDom::R => (&row.rlive_in, &row.rlive_out, &row.rdefs, &row.ruses),
            _ => (&row.ulive_in, &row.ulive_in, &row.udefs, &row.uuses),
        };
        let hit = groups_members.iter().any(|s| {
            a.contains(s) || b.contains(s) || c.contains(s) || d.contains(s)
        });
        if hit {
            best = i as u32;
            break;
        }
    }
    best
}

fn allocate_domain(
    xfers: &[RegXfer],
    live: &[InsRegLive],
    dom: RegDom,
) -> Result<(BTreeMap<u8, u8>, FullDomainStats, Vec<String>)> {
    let (dom_excl, pool_max) = match dom {
        RegDom::R => (255u8, R_POOL_MAX),
        _ => (64u8, UR_POOL_MAX),
    };
    let (groups, clip_forced, group_align, sym_align) = build_groups(xfers, dom, dom_excl)?;
    let conf = conflicts(live, &groups, dom);

    // identity pins (two sources, one contract: the group keeps its old home
    // and the pool may not hand those slots out):
    //  - entry-live symbols: hardware-ABI state (UR63-real class);
    //  - clipped-span groups: the hardware still writes the clipped tail,
    //    so the implied tail cells must stay exactly where the binary expects.
    let mut pins: Vec<String> = Vec::new();
    let mut placement: BTreeMap<u8, u8> = BTreeMap::new(); // anchor -> base
    for &anchor in &clip_forced {
        let members = &groups[&anchor].clone();
        placement.insert(anchor, anchor);
        for &m in members.iter() {
            pins.push(format!("{:?}{} (clip-span)", dom, m));
        }
    }
    if let Some(first) = live.first() {
        let entry = match dom {
            RegDom::R => &first.rlive_in,
            _ => &first.ulive_in,
        };
        let mut pin_anchors: BTreeSet<u8> = BTreeSet::new();
        for &s in entry {
            for (&anchor, members) in &groups {
                if members.contains(&s) {
                    pin_anchors.insert(anchor);
                }
            }
        }
        for &anchor in &pin_anchors {
            let members = &groups[&anchor];
            let size = members.len() as u8;
            // Identity pins keep the OLD home even outside the allocator pool
            // (e.g. UR63-real is ABI entry state on the certified corpus);
            // the pool constraint applies only to fresh placements. The home
            // must still be a real register of the domain, and its span must
            // fit below the domain end.
            if anchor as u32 + size as u32 - 1 >= dom_excl as u32 {
                bail!(
                    "ra full: entry-live group at {:?} anchor {} width {} escapes the domain",
                    dom, anchor, size
                );
            }
            if placement.insert(anchor, anchor).is_none() {
                for &m in members {
                    pins.push(format!("{:?}{} (entry-live)", dom, m));
                }
            }
        }
    }
    pins.sort();
    pins.dedup();

    // linear-scan: remaining groups by (first live pos, size desc, anchor)
    let mut order: Vec<u8> = groups
        .keys()
        .copied()
        .filter(|a| !placement.contains_key(a))
        .collect();
    order.sort_by_key(|&a| {
        (
            first_live_pos(&groups[&a], live, dom),
            std::cmp::Reverse(groups[&a].len() as u8),
            a,
        )
    });

    // occupied phys slots: base..base+len -> group anchor
    let mut occupied: Vec<(u8, u8, u8)> = placement
        .iter()
        .map(|(&a, &b)| (b, groups[&a].len() as u8, a))
        .collect();

    for &g in &order {
        let size = groups[&g].len() as u8;
        let align = group_align[&g] as u32;
        // member-level alignment feasibility (offset property only, since the
        // group base itself is chosen A-aligned): every member whose own span
        // carries an alignment mark must sit at an aligned offset from the
        // group anchor. A merged group that breaks this is unallocatable in
        // v0 (fail-closed census).
        for &m in &groups[&g] {
            let a = sym_align.get(&m).copied().unwrap_or(1) as u32;
            if a > 1 && (m - g) as u32 % a != 0 {
                bail!(
                    "ra full: {:?} group anchor {} member {} needs align {} but its \
                     in-group offset is {} -- span-merge shape unallocatable in v0",
                    dom, g, m, a, (m - g)
                );
            }
        }
        let cset = conf.get(&g).cloned().unwrap_or_default();
        let mut base: u32 = 0;
        let chosen;
        loop {
            if base + size as u32 - 1 > pool_max as u32 {
                bail!(
                    "ra full: {:?} pool exhausted placing group anchor {} (width {}, \
                     {} groups placed) -- no spilling in M4.3b v0",
                    dom, g, size, placement.len()
                );
            }
            if base % align != 0 {
                base += align - (base % align);
                continue;
            }
            // member-level alignment: a span whose own base (member) must be
            // A-aligned sits at offset (m-anchor) -- (base+offset)%A==0 must
            // hold for every marked member; with group base%A==0 this is a
            // pure offset property, so check once outside the slot walk.

            let lo = base as u8;
            let hi = (base + size as u32 - 1) as u8;
            let mut ok = true;
            for &(ob, olen, og) in &occupied {
                let ohi = ob + olen - 1;
                if lo <= ohi && ob <= hi && cset.contains(&og) {
                    ok = false;
                    break;
                }
            }
            if ok {
                chosen = lo;
                break;
            }
            base += 1;
        }
        occupied.push((chosen, size, g));
        placement.insert(g, chosen);
    }

    // emit the plan + stats
    let mut map: BTreeMap<u8, u8> = BTreeMap::new();
    let mut watermark: u8 = 0;
    let mut max_group_width = 0usize;
    let mut singleton_width1 = 0usize;
    for (&anchor, members) in &groups {
        let base = placement[&anchor];
        let w = members.len();
        max_group_width = max_group_width.max(w);
        if w == 1 {
            singleton_width1 += 1;
        }
        for &m in members {
            let p = base + (m - anchor);
            map.insert(m, p);
            watermark = watermark.max(p);
        }
    }
    let symbols: usize = groups.values().map(|m| m.len()).sum();
    let old_max = map.keys().last().copied();
    let stats = FullDomainStats {
        symbols,
        groups: groups.len(),
        watermark: if symbols == 0 { 0 } else { watermark.saturating_add(1) },
        old_max,
        pinned: pins.len(),
        singleton_width1,
        max_group_width,
    };
    Ok((map, stats, pins))
}

/// Machine-checked injectivity audit over every instruction's span-expanded
/// co-occurrence set: the renaming must be 1:1 wherever values coexist --
/// this is exactly the renaming-theorem premise, verified post-hoc rather
/// than trusted to the allocator.
pub(crate) fn audit_injectivity(
    kname: &str,
    live: &[InsRegLive],
    rmap: &BTreeMap<u8, u8>,
    urmap: &BTreeMap<u8, u8>,
) -> Result<()> {
    for (i, row) in live.iter().enumerate() {
        let mut co: BTreeSet<u8> = BTreeSet::new();
        co.extend(row.rlive_in.iter().chain(row.rlive_out.iter())
            .chain(row.rdefs.iter()).chain(row.ruses.iter()).copied());
        let mut seen: BTreeMap<u8, u8> = BTreeMap::new();
        for &s in &co {
            let p = rmap.get(&s).copied().unwrap_or(s);
            if let Some(&prev) = seen.get(&p) {
                bail!(
                    "ra full: kernel {kname:?} ins {i} (0x{:x}): renaming collision \
                     R{prev} and R{s} both -> R{p}",
                    row.addr
                );
            }
            seen.insert(p, s);
        }
        let mut cou: BTreeSet<u8> = BTreeSet::new();
        cou.extend(row.ulive_in.iter().chain(row.udefs.iter()).chain(row.uuses.iter()).copied());
        let mut seenu: BTreeMap<u8, u8> = BTreeMap::new();
        for &s in &cou {
            let p = urmap.get(&s).copied().unwrap_or(s);
            if let Some(&prev) = seenu.get(&p) {
                bail!(
                    "ra full: kernel {kname:?} ins {i} (0x{:x}): renaming collision \
                     UR{prev} and UR{s} both -> UR{p}",
                    row.addr
                );
            }
            seenu.insert(p, s);
        }
    }
    Ok(())
}

/// Public shim for ra::Apply validation (whole-kernel plans from JSON).
pub fn audit_injectivity_pub(
    kname: &str,
    live: &[InsRegLive],
    plan: &crate::ra::RegPlan,
) -> Result<()> {
    audit_injectivity(kname, live, &plan.r, &plan.ur)
}

/// Real entry: allocator over (xfers, live) both from reg_liveness.
pub fn plan_full_kernel_live(
    kname: &str,
    xfers: &[RegXfer],
    live: &[InsRegLive],
) -> Result<(crate::ra::RegPlan, FullAllocStats)> {
    let (rmap, rstats, rpins) = allocate_domain(xfers, live, RegDom::R)?;
    let (urmap, ustats, upins) = allocate_domain(xfers, live, RegDom::UR)?;
    audit_injectivity(kname, live, &rmap, &urmap)?;
    let mut entry_pins = rpins;
    entry_pins.extend(upins);
    Ok((
        crate::ra::RegPlan { r: rmap, ur: urmap },
        FullAllocStats {
            r: rstats,
            ur: ustats,
            entry_pins,
            renamed: 0,
        },
    ))
}

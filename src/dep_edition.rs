//! An EDITION of a dependency-latency table: the table with lower numbers in the entries that
//! have silicon evidence, and in nothing else. Opt-in by name, never the default.
//!
//! The table of `dep_stall` (`tables/dep_latency_sm120.json`) is the vendor assembler's practice,
//! raised wherever silicon asked for more. Silicon also shows where the practice is slack: a
//! measured floor below a cell. A schedule that stands on such a floor is only as good as the
//! floor's evidence, so the lower numbers do not go into the table. They go into an edition:
//!
//! * **one file, one name** — `tables/dep_latency_sm120_silicon.json`, read only when asked for:
//!   `CUBIT_SCHED2_LAT=sm120-silicon` (the scheduler, with `CUBIT_SCHED2`) or
//!   `CUBIT_DEP_TABLE=sm120-silicon` (the read-only checks `CUBIT_DEP_VERIFY`, `CUBIT_VERIFY_JSON`,
//!   `CUBIT_DEP_CELLS`, also on a frozen listing). The base table and every default path are
//!   untouched; an edition without entries prices every kernel exactly like its base;
//! * **an entry = measured floor + 1** — the floor is the smallest issue distance from which every
//!   thread of every launch was right, with a wrong result below it in the same family
//!   (`floor_basis: "wrong-below"`), or 1 where no smaller distance exists (`"interlock"`);
//! * **an entry never raises** — it names an existing cell (or a pair of member classes of an
//!   existing resource) and its `L` is at most today's number;
//! * **evidence beside the table** — every entry lists the digests of the probe runs it rests on
//!   (`tools/stallfloor/silicon/*.json`, the result files of `tools/stallfloor/probe.py`, each
//!   with its sha256 and the id of the request). The evidence of ONE entry must hold the Server
//!   Edition card and at least [`WORKSTATION_CARDS`] Workstation Edition cards — production's
//!   model; the floor of a model is the maximum over its cards —, each of those in two clock
//!   states: the mean SM clock at [`FAST_CLOCK_MIN_MHZ`] or more (short runs, the power cap not
//!   binding), and the card at its [`CAP_LIMIT_W`]-watt cap under a sustained load (median draw
//!   [`CAP_MIN_DRAW_W`] W or more). Each run must show the floor distance right at the four
//!   occupancies (and at the served grids for the tensor rows), a wrong result below the floor
//!   (unless `interlock`), nothing wrong at or above it, clean controls, and at least
//!   [`MIN_THREAD_LAUNCHES`] thread-launches right at the entry's own distance `L`;
//! * **the production cards as witnesses** — an edition with an entry names the floor files of
//!   [`PRODUCTION_CARDS`] production cards (`witnesses`), and no cell of it lies below any of
//!   their floors + 1.
//!
//! [`parse`] refuses a malformed edition, [`apply`] an entry that names nothing or raises,
//! [`validate_evidence`] an entry whose files are missing, altered, or show less than the rule
//! asks (`tests/dep_edition_silicon.rs` runs it on the bundled edition and on every way of
//! falling short). The write-after-read holds (`holds`) are a section of their own under the
//! same rule; they are carried and validated here, and `sync_class::hold_need` does not read
//! them yet.

use crate::dep_stall::{DepLatTable, SM120_TABLE};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashSet};

/// The schema word of an edition file.
pub const SCHEMA: &str = "cubit-dep-edition-1";
/// The name that selects the bundled sm_120 edition.
pub const SM120_SILICON_NAME: &str = "sm120-silicon";
/// The bundled sm_120 edition.
pub const SM120_SILICON: &str = include_str!("../tables/dep_latency_sm120_silicon.json");
/// Where the evidence files of an edition live in the repository.
pub const EVIDENCE_DIR: &str = "tools/stallfloor/silicon/";
/// Thread-launches that must be right at an entry's own distance, in each of the runs.
pub const MIN_THREAD_LAUNCHES: u64 = 100_000_000;
/// The "fast clock" state of the Workstation Edition card: mean SM clock of the run, MHz.
pub const FAST_CLOCK_MIN_MHZ: f64 = 2800.0;
/// The "capped" state of the Workstation Edition card: the power limit in force, W ...
pub const CAP_LIMIT_W: f64 = 400.0;
/// ... and the card's MEDIAN draw during the run that shows it was at that cap (95 % of it), W.
pub const CAP_MIN_DRAW_W: f64 = 380.0;
/// Workstation Edition cards the evidence of an entry must come from (the floor of the model is
/// the maximum over them: two cards of one model were measured one cycle apart on rare events).
pub const WORKSTATION_CARDS: usize = 2;
/// Production cards whose floors are recorded beside an edition that has an entry (witnesses).
pub const PRODUCTION_CARDS: usize = 4;
/// The schema word of a witness file.
pub const WITNESS_SCHEMA: &str = "cubit-dep-witness-1";
/// The occupancies every run must show the floor distance right at (probe.py's names: 1 / 8 / 32
/// warps per SM on every SM, 32 warps on 32 SMs).
pub const OCCUPANCIES: [&str; 4] = ["w1", "w8", "w32", "g32"];
/// The served grids, required in addition for the tensor rows: one CTA of 12 warps per SM
/// (`w12`), and two CTAs of 9 warps RESIDENT on an SM (`c2w9s`: 49 152 B of shared memory per
/// CTA). The 376-CTA grid `c2w9` of the earlier batches declares 65 536 B per CTA and holds ONE
/// CTA per SM (KNOWN_ISSUES A31): it is not the served grid and does not count for it.
pub const MMA_GRIDS: [&str; 2] = ["w12", "c2w9s"];
/// The holds an edition may carry, with today's number (`sync_class`).
pub const HOLDS: [(&str, u8); 3] = [
    ("mma_a_fragment", crate::sync_class::MMA_OPERAND_HOLD),
    ("mma_b_fragment", crate::sync_class::MMA_OPERAND_HOLD),
    ("uniform_operand", crate::sync_class::UNIFORM_OPERAND_HOLD),
];

/// One evidence file of an entry and the request in it.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceRef {
    pub file: String,
    pub sha256: String,
    pub request: String,
}

/// The floors of one production card, recorded beside the edition (`witnesses`): a file of the
/// schema [`WITNESS_SCHEMA`] -- `arch`, `conditions.gpu` / `.card`, `floors`: producer, consumer,
/// role, floor (an issue distance). No cell of the edition may lie below any of them + 1.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessRef {
    pub file: String,
    pub sha256: String,
}

/// One entry of an edition. The target fields depend on the section: `cells` name `producer`,
/// `consumer`, `role`; `resources` name `resource`, `first`, `second`; `holds` name `hold`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    pub id: String,
    #[serde(default)]
    pub producer: Option<String>,
    #[serde(default)]
    pub consumer: Option<String>,
    #[serde(default)]
    pub role: Option<String>,
    #[serde(default)]
    pub resource: Option<String>,
    #[serde(default)]
    pub first: Option<String>,
    #[serde(default)]
    pub second: Option<String>,
    #[serde(default)]
    pub hold: Option<String>,
    pub floor: u8,
    pub floor_basis: String,
    #[serde(rename = "L")]
    pub l: u8,
    #[serde(default)]
    pub evidence: Vec<EvidenceRef>,
    #[serde(default)]
    pub note: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct EditionJson {
    schema: String,
    edition: String,
    arch: String,
    base: String,
    #[serde(default)]
    #[allow(dead_code)]
    comment: Option<String>,
    #[serde(default)]
    cells: Vec<Entry>,
    #[serde(default)]
    resources: Vec<Entry>,
    #[serde(default)]
    holds: Vec<Entry>,
    #[serde(default)]
    witnesses: Vec<WitnessRef>,
}

/// A parsed, structurally valid edition.
#[derive(Debug, Clone)]
pub struct Edition {
    pub name: String,
    pub arch: String,
    pub base: String,
    pub cells: Vec<Entry>,
    pub resources: Vec<Entry>,
    pub holds: Vec<Entry>,
    pub witnesses: Vec<WitnessRef>,
}

impl Edition {
    /// Every entry with the section it stands in.
    pub fn entries(&self) -> impl Iterator<Item = (&'static str, &Entry)> {
        self.cells
            .iter()
            .map(|e| ("cells", e))
            .chain(self.resources.iter().map(|e| ("resources", e)))
            .chain(self.holds.iter().map(|e| ("holds", e)))
    }

    pub fn len(&self) -> usize {
        self.cells.len() + self.resources.len() + self.holds.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

fn is_sha256(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// What is wrong with the edition's own text (no base table, no file needed).
fn structural_problems(ed: &Edition) -> Vec<String> {
    let mut out = Vec::new();
    if ed.name.is_empty() || ed.arch.is_empty() || ed.base.is_empty() {
        out.push("`edition`, `arch` and `base` must be named".to_string());
    }
    for w in &ed.witnesses {
        if !w.file.starts_with(EVIDENCE_DIR) || !w.file.ends_with(".json") || w.file.contains("..") || w.file.contains('\\') {
            out.push(format!("witness `{}` is not a .json file under {EVIDENCE_DIR}", w.file));
        }
        if !is_sha256(&w.sha256) {
            out.push(format!("witness `{}` has no sha256 (64 lower-case hex digits)", w.file));
        }
    }
    let mut ids = HashSet::new();
    for (section, e) in ed.entries() {
        let at = format!("{section} entry `{}`", e.id);
        if e.id.is_empty() || !ids.insert(e.id.clone()) {
            out.push(format!("{at}: an entry needs an id of its own"));
        }
        let cell = [&e.producer, &e.consumer, &e.role];
        let res = [&e.resource, &e.first, &e.second];
        let (want, rest): (Vec<&Option<String>>, Vec<&Option<String>>) = match section {
            "cells" => (cell.to_vec(), res.iter().copied().chain([&e.hold]).collect()),
            "resources" => (res.to_vec(), cell.iter().copied().chain([&e.hold]).collect()),
            _ => (vec![&e.hold], cell.iter().copied().chain(res).collect()),
        };
        if want.iter().any(|f| f.as_deref().is_none_or(str::is_empty)) || rest.iter().any(|f| f.is_some()) {
            out.push(format!(
                "{at}: the target must be exactly {}",
                match section {
                    "cells" => "`producer`, `consumer`, `role`",
                    "resources" => "`resource`, `first`, `second`",
                    _ => "`hold`",
                }
            ));
        }
        if e.floor == 0 {
            out.push(format!("{at}: a floor is an issue distance of 1 or more"));
        }
        if u16::from(e.l) != u16::from(e.floor) + 1 {
            out.push(format!("{at}: L {} is not the measured floor {} + 1", e.l, e.floor));
        }
        match e.floor_basis.as_str() {
            "wrong-below" if e.floor < 2 => {
                out.push(format!("{at}: floor 1 has no smaller distance to be wrong at (`floor_basis` would be `interlock`)"))
            }
            "interlock" if e.floor != 1 => out.push(format!(
                "{at}: `interlock` is the floor 1 only (floor {} needs a wrong result below it: `wrong-below`)",
                e.floor
            )),
            "wrong-below" | "interlock" => {}
            other => out.push(format!("{at}: unknown `floor_basis` `{other}` (`wrong-below` or `interlock`)")),
        }
        if e.evidence.is_empty() {
            out.push(format!("{at}: no evidence file is named"));
        }
        for r in &e.evidence {
            if !r.file.starts_with(EVIDENCE_DIR) || !r.file.ends_with(".json") || r.file.contains("..") || r.file.contains('\\') {
                out.push(format!("{at}: evidence `{}` is not a .json file under {EVIDENCE_DIR}", r.file));
            }
            if !is_sha256(&r.sha256) {
                out.push(format!("{at}: evidence `{}` has no sha256 (64 lower-case hex digits)", r.file));
            }
            if r.request.is_empty() {
                out.push(format!("{at}: evidence `{}` names no request", r.file));
            }
        }
    }
    out
}

/// Parse an edition file; a malformed one, or one whose entries break the rule in their own
/// text (no evidence named, `L` not floor + 1, a mixed target), is refused whole.
pub fn parse(text: &str) -> anyhow::Result<Edition> {
    let j: EditionJson = serde_json::from_str(text).map_err(|e| anyhow::anyhow!("dependency-table edition: {e}"))?;
    if j.schema != SCHEMA {
        anyhow::bail!("dependency-table edition: schema `{}` is not `{SCHEMA}`", j.schema);
    }
    let ed = Edition { name: j.edition, arch: j.arch, base: j.base, cells: j.cells, resources: j.resources, holds: j.holds, witnesses: j.witnesses };
    let problems = structural_problems(&ed);
    if !problems.is_empty() {
        anyhow::bail!("dependency-table edition `{}` refused: {}", ed.name, problems.join("; "));
    }
    Ok(ed)
}

/// The base table under the edition. Refused: another architecture, an entry that names no
/// cell / resource pair / hold of the base, an entry above today's number.
pub fn apply(mut base: DepLatTable, ed: &Edition) -> anyhow::Result<DepLatTable> {
    let mut problems = Vec::new();
    if base.arch != ed.arch {
        problems.push(format!("the edition is for {} and the table for {}", ed.arch, base.arch));
    }
    if base.edition.is_some() {
        problems.push("the table already is an edition".to_string());
    }
    for e in &ed.cells {
        let (p, c, r) = (e.producer.as_deref().unwrap_or(""), e.consumer.as_deref().unwrap_or(""), e.role.as_deref().unwrap_or(""));
        match base.cell_l(p, c, r) {
            None => problems.push(format!("cells entry `{}`: the base table has no cell {p} -> {c} ({r})", e.id)),
            Some(today) if e.l > today => {
                problems.push(format!("cells entry `{}`: L {} is above today's {today} -- an edition only lowers", e.id, e.l))
            }
            Some(_) => base.lower_cell(p, c, r, e.l),
        }
    }
    for e in &ed.resources {
        let (name, a, b) = (e.resource.as_deref().unwrap_or(""), e.first.as_deref().unwrap_or(""), e.second.as_deref().unwrap_or(""));
        match base.resource_member_spacing(name, a) {
            None => problems.push(format!("resources entry `{}`: the base table has no resource `{name}` with the member {a}", e.id)),
            Some((ri, _)) if !base.is_resource_member(ri, b) => {
                problems.push(format!("resources entry `{}`: {b} is not a member of the resource `{name}`", e.id))
            }
            Some((_, today)) if e.l > today => {
                problems.push(format!("resources entry `{}`: L {} is above today's {today} -- an edition only lowers", e.id, e.l))
            }
            Some((ri, _)) => base.set_resource_pair(ri, a, b, e.l),
        }
    }
    let mut holds = Vec::new();
    for e in &ed.holds {
        let name = e.hold.as_deref().unwrap_or("");
        match HOLDS.iter().find(|(n, _)| *n == name) {
            None => problems.push(format!(
                "holds entry `{}`: unknown hold `{name}` ({})",
                e.id,
                HOLDS.iter().map(|(n, _)| *n).collect::<Vec<_>>().join(", ")
            )),
            Some((_, today)) if e.l > *today => {
                problems.push(format!("holds entry `{}`: L {} is above today's {today} -- an edition only lowers", e.id, e.l))
            }
            Some(_) if holds.iter().any(|(n, _): &(String, u8)| n == name) => {
                problems.push(format!("holds entry `{}`: the hold `{name}` is named twice", e.id))
            }
            Some(_) => holds.push((name.to_string(), e.l)),
        }
    }
    if !problems.is_empty() {
        anyhow::bail!("dependency-table edition `{}` refused: {}", ed.name, problems.join("; "));
    }
    base.edition = Some((ed.name.clone(), ed.len()));
    base.edition_holds = holds;
    Ok(base)
}

/// The bundled sm_120 table under its bundled 'silicon' edition.
pub fn load_bundled() -> anyhow::Result<DepLatTable> {
    apply(DepLatTable::from_json(SM120_TABLE)?, &parse(SM120_SILICON)?)
}

/// The clock state of a Workstation Edition run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ClockState {
    /// short runs, the power cap not binding: mean SM clock of [`FAST_CLOCK_MIN_MHZ`] or more
    Fast,
    /// the card at its [`CAP_LIMIT_W`]-watt cap under a sustained load: median draw of [`CAP_MIN_DRAW_W`] or more
    Capped,
}

impl ClockState {
    pub const BOTH: [ClockState; 2] = [ClockState::Fast, ClockState::Capped];

    pub fn text(self) -> &'static str {
        match self {
            ClockState::Fast => "at an SM clock of 2.8 GHz or more",
            ClockState::Capped => "at its 400 W cap under load",
        }
    }
}

/// Which run a digest is: the card model, and for the Workstation Edition (production's model)
/// the physical card and its clock state.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Run {
    Server,
    Workstation { card: String, state: ClockState },
}

#[derive(Default)]
struct RunFacts {
    launches_at_l: u64,
    floor_right_at: BTreeSet<String>,
    wrong_below: bool,
}

/// `"400.00 W"` / `400` -> 400.0
fn watts(v: &serde_json::Value) -> Option<f64> {
    match v {
        serde_json::Value::Number(n) => n.as_f64(),
        serde_json::Value::String(s) => s.split_whitespace().next().and_then(|x| x.parse().ok()),
        _ => None,
    }
}

/// The physical card of a Workstation Edition digest: `conditions.card`, an anonymous name of
/// its own (the files are public: not a serial number, not a host).
fn workstation_card(doc: &serde_json::Value) -> Result<String, String> {
    let c = &doc["conditions"];
    if !c["gpu"].as_str().unwrap_or("").contains("Workstation Edition") {
        return Err(format!("the card `{}` is not the Workstation Edition", c["gpu"].as_str().unwrap_or("")));
    }
    match c["card"].as_str() {
        Some(card) if !card.is_empty() => Ok(card.to_string()),
        _ => Err("a Workstation Edition digest that does not name its card (`conditions.card`: the model's floor is the maximum over at least two cards)".to_string()),
    }
}

/// Which run a digest is, from its own `conditions`.
fn classify_run(doc: &serde_json::Value) -> Result<Run, String> {
    let c = &doc["conditions"];
    let gpu = c["gpu"].as_str().unwrap_or("");
    if gpu.contains("Server Edition") {
        return Ok(Run::Server);
    }
    if !gpu.contains("Workstation Edition") {
        return Err(format!("the card `{gpu}` is neither card model of the rule"));
    }
    let card = workstation_card(doc)?;
    let clock = c["clock_busy_mean_mhz"].as_f64();
    let limit = watts(&c["power_limit"]);
    let draw = c["power_median_w"].as_f64();
    if limit.is_some_and(|w| (w - CAP_LIMIT_W).abs() < 0.5) && draw.is_some_and(|w| w >= CAP_MIN_DRAW_W) {
        return Ok(Run::Workstation { card, state: ClockState::Capped });
    }
    if clock.is_some_and(|m| m >= FAST_CLOCK_MIN_MHZ) {
        return Ok(Run::Workstation { card, state: ClockState::Fast });
    }
    Err(format!(
        "a Workstation Edition run in neither clock state (mean SM clock {} MHz, below {FAST_CLOCK_MIN_MHZ}; power limit {} W, median draw {} W, not at the {CAP_LIMIT_W} W cap)",
        clock.map_or("?".to_string(), |m| format!("{m:.0}")),
        limit.map_or("?".to_string(), |w| format!("{w:.0}")),
        draw.map_or("?".to_string(), |w| format!("{w:.0}")),
    ))
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes).iter().map(|b| format!("{b:02x}")).collect()
}

/// One evidence file of one entry -> the run it is and what it shows; `Err` = why it is refused.
fn read_evidence(ed: &Edition, e: &Entry, r: &EvidenceRef, bytes: &[u8]) -> Result<(Run, RunFacts), String> {
    let digest = sha256_hex(bytes);
    if digest != r.sha256 {
        return Err(format!("sha256 is {digest}, the entry names {}", r.sha256));
    }
    let doc: serde_json::Value = serde_json::from_slice(bytes).map_err(|x| format!("not JSON: {x}"))?;
    if doc["arch"].as_str() != Some(ed.arch.as_str()) {
        return Err(format!("measured for {}, the edition is for {}", doc["arch"], ed.arch));
    }
    let run = classify_run(&doc)?;
    let req = doc["requests"]
        .as_array()
        .and_then(|a| a.iter().find(|q| q["id"].as_str() == Some(r.request.as_str())))
        .ok_or_else(|| format!("has no request `{}`", r.request))?;
    if req["errors"].as_u64() != Some(0) || req["skipped_kernels"].as_u64() != Some(0) {
        return Err(format!("request `{}` is incomplete (launch errors or kernels not launched)", r.request));
    }
    if req["floor"]["oracle_failures"].as_array().is_none_or(|a| !a.is_empty()) {
        return Err(format!("request `{}` has a failed control (`oracle_failures`)", r.request));
    }
    let main = if req["request"]["kind"].as_str() == Some("raw") { "raw" } else { "bare" };
    let series: Vec<&serde_json::Value> =
        req["series"].as_array().map(|a| a.iter().filter(|s| s["variant"].as_str() == Some(main)).collect()).unwrap_or_default();
    if series.is_empty() {
        return Err(format!("request `{}` has no `{main}` series", r.request));
    }
    let mut facts = RunFacts::default();
    for s in series {
        let occ = s["occupancy"].as_str().unwrap_or("?");
        let at = format!("request `{}`, {occ} / {}", r.request, s["front"].as_str().unwrap_or("?"));
        if !s["oracle"].as_str().is_some_and(|o| o.starts_with("ok")) {
            return Err(format!("{at}: the series has no clean control"));
        }
        let tl = s["thread_launches_per_kernel"].as_u64().ok_or_else(|| format!("{at}: no thread-launch count"))?;
        let good: Vec<u64> = s["good_at"].as_array().map(|a| a.iter().filter_map(|d| d.as_u64()).collect()).unwrap_or_default();
        let bad: Vec<u64> = s["not_good"].as_object().map(|m| m.keys().filter_map(|d| d.parse().ok()).collect()).unwrap_or_default();
        if s["not_good"].as_object().is_some_and(|m| m.len() != bad.len()) {
            return Err(format!("{at}: a distance of `not_good` is not a number"));
        }
        if let Some(d) = bad.iter().find(|d| **d >= u64::from(e.floor)) {
            return Err(format!("{at}: a wrong result at distance {d}, at or above the floor {}", e.floor));
        }
        if !bad.is_empty() {
            facts.wrong_below = true;
        }
        if good.contains(&u64::from(e.floor)) {
            facts.floor_right_at.insert(occ.to_string());
        }
        if good.contains(&u64::from(e.l)) {
            facts.launches_at_l += tl;
        }
    }
    Ok((run, facts))
}

/// One witness file -> (its card, its floors as (producer, consumer, role, floor)).
#[allow(clippy::type_complexity)]
fn read_witness(ed: &Edition, w: &WitnessRef, bytes: &[u8]) -> Result<(String, Vec<(String, String, String, u64)>), String> {
    let digest = sha256_hex(bytes);
    if digest != w.sha256 {
        return Err(format!("sha256 is {digest}, the edition names {}", w.sha256));
    }
    let doc: serde_json::Value = serde_json::from_slice(bytes).map_err(|x| format!("not JSON: {x}"))?;
    if doc["schema"].as_str() != Some(WITNESS_SCHEMA) {
        return Err(format!("schema {} is not `{WITNESS_SCHEMA}`", doc["schema"]));
    }
    if doc["arch"].as_str() != Some(ed.arch.as_str()) {
        return Err(format!("measured for {}, the edition is for {}", doc["arch"], ed.arch));
    }
    let card = workstation_card(&doc)?;
    let mut floors = Vec::new();
    for f in doc["floors"].as_array().ok_or("has no `floors` list")? {
        match (f["producer"].as_str(), f["consumer"].as_str(), f["role"].as_str(), f["floor"].as_u64()) {
            (Some(p), Some(c), Some(r), Some(fl)) => floors.push((p.to_string(), c.to_string(), r.to_string(), fl)),
            _ => return Err(format!("a floor without producer / consumer / role / floor: {f}")),
        }
    }
    Ok((card, floors))
}

/// Every reason the evidence of the edition falls short of the rule (empty = every entry stands
/// on its files). `read` returns the bytes of a repository file by its path, `None` if absent.
pub fn validate_evidence(ed: &Edition, read: &dyn Fn(&str) -> Option<Vec<u8>>) -> Vec<String> {
    let mut out = Vec::new();
    // the witnesses: the floors of the production cards, recorded beside the table
    let mut witness_cards: BTreeSet<String> = BTreeSet::new();
    let mut witness_floors: Vec<(String, String, String, String, u64)> = Vec::new();
    for w in &ed.witnesses {
        let Some(bytes) = read(&w.file) else {
            out.push(format!("witness file {} is missing", w.file));
            continue;
        };
        match read_witness(ed, w, &bytes) {
            Err(why) => out.push(format!("witness {}: {why}", w.file)),
            Ok((card, floors)) => {
                witness_floors.extend(floors.into_iter().map(|(p, c, r, f)| (card.clone(), p, c, r, f)));
                witness_cards.insert(card);
            }
        }
    }
    if !ed.is_empty() && witness_cards.len() < PRODUCTION_CARDS {
        out.push(format!(
            "the floors of {} production card(s) are recorded beside the edition as witnesses; an edition with an entry needs those of {PRODUCTION_CARDS}",
            witness_cards.len()
        ));
    }
    for e in &ed.cells {
        for (card, p, c, r, floor) in &witness_floors {
            if e.producer.as_deref() == Some(p.as_str())
                && e.consumer.as_deref() == Some(c.as_str())
                && e.role.as_deref() == Some(r.as_str())
                && u64::from(e.l) < floor + 1
            {
                out.push(format!(
                    "cells entry `{}`: L {} is below the floor {floor} + 1 that production card `{card}` measured for {p} -> {c} ({r})",
                    e.id, e.l
                ));
            }
        }
    }
    for (section, e) in ed.entries() {
        let at = format!("{section} entry `{}`", e.id);
        let mut runs: BTreeMap<Run, RunFacts> = BTreeMap::new();
        for r in &e.evidence {
            let Some(bytes) = read(&r.file) else {
                out.push(format!("{at}: evidence file {} is missing", r.file));
                continue;
            };
            match read_evidence(ed, e, r, &bytes) {
                Err(why) => out.push(format!("{at}: evidence {}: {why}", r.file)),
                Ok((run, f)) => {
                    let acc = runs.entry(run).or_default();
                    acc.launches_at_l += f.launches_at_l;
                    acc.floor_right_at.extend(f.floor_right_at);
                    acc.wrong_below |= f.wrong_below;
                }
            }
        }
        // the runs the rule asks for: the Server Edition card, and at least two Workstation Edition
        // cards, each of them in both clock states
        let cards: BTreeSet<&String> = runs.keys().filter_map(|r| if let Run::Workstation { card, .. } = r { Some(card) } else { None }).collect();
        let mut wanted: Vec<(Run, String)> = vec![(Run::Server, "the Server Edition card".to_string())];
        for card in &cards {
            for state in ClockState::BOTH {
                wanted.push((Run::Workstation { card: (*card).clone(), state }, format!("the Workstation Edition card `{card}` {}", state.text())));
            }
        }
        match cards.len() {
            0 => out.push(format!("{at}: no evidence run on a Workstation Edition card (at least {WORKSTATION_CARDS} cards, each in both clock states)")),
            n if n < WORKSTATION_CARDS => out.push(format!(
                "{at}: evidence from {n} Workstation Edition card ({}): the floor of the model is the maximum over at least {WORKSTATION_CARDS} cards",
                cards.iter().map(|c| format!("`{c}`")).collect::<Vec<_>>().join(", ")
            )),
            _ => {}
        }
        let tensor = (section == "resources" && e.resource.as_deref() == Some("mma"))
            || (section == "holds" && e.hold.as_deref().is_some_and(|h| h.starts_with("mma_")));
        for (run, text) in &wanted {
            let Some(f) = runs.get(run) else {
                out.push(format!("{at}: no evidence run on {text}"));
                continue;
            };
            let grids: &[&str] = if tensor { &MMA_GRIDS } else { &[] };
            let missing: Vec<&str> =
                OCCUPANCIES.iter().chain(grids.iter()).copied().filter(|o| !f.floor_right_at.contains(*o)).collect();
            if !missing.is_empty() {
                out.push(format!("{at}: on {text} the floor distance {} is not shown right at the occupancies {}", e.floor, missing.join(", ")));
            }
            if e.floor_basis == "wrong-below" && !f.wrong_below {
                out.push(format!("{at}: on {text} no wrong result below the floor {} (a floor needs its positive control)", e.floor));
            }
            if f.launches_at_l < MIN_THREAD_LAUNCHES {
                out.push(format!(
                    "{at}: on {text} {} thread-launches right at the entry's own distance {} (the rule: {MIN_THREAD_LAUNCHES})",
                    f.launches_at_l, e.l
                ));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dep_stall;
    use crate::ir::Instruction;

    fn base() -> DepLatTable {
        DepLatTable::from_json(SM120_TABLE).unwrap()
    }

    fn ins(s: &str, stall: u8) -> Instruction {
        let mut i = crate::parse_sass(s, 0).unwrap();
        i.hand_sched = false;
        i.ctrl.stall = stall;
        i
    }

    /// `a` at `stall`, then `b`: the findings of `kind` the table has for the pair.
    fn below(t: &DepLatTable, a: &str, b: &str, stall: u8, kind: &str) -> usize {
        let k = vec![ins(a, stall), ins(b, 1), ins("EXIT", 1)];
        dep_stall::check(&k, t).iter().filter(|v| v.kind == kind).count()
    }

    const EV: &str = r#""evidence":[{"file":"tools/stallfloor/silicon/x.json","sha256":"0000000000000000000000000000000000000000000000000000000000000000","request":"r"}]"#;
    const QMMA_A: &str = "QMMA.SF.16832.F32.E4M3.E2M1.E8 R56, R96, R26, R56, R164, R152, UR4";
    const QMMA_B: &str = "QMMA.SF.16832.F32.E4M3.E2M1.E8 R60, R100, R30, R60, R164, R152, UR4";
    const HMMA: &str = "HMMA.16816.F32.BF16 R28, R64, R72, R28";

    fn edition(sections: &str) -> String {
        format!(r#"{{"schema":"cubit-dep-edition-1","edition":"t","arch":"sm_120","base":"dep_latency_sm120.json",{sections}}}"#)
    }

    fn refused(text: &str) -> String {
        match parse(text).and_then(|ed| apply(base(), &ed)) {
            Ok(_) => panic!("accepted: {text}"),
            Err(e) => e.to_string(),
        }
    }

    #[test]
    fn the_bundled_edition_is_named_and_applies_to_the_bundled_table() {
        let ed = parse(SM120_SILICON).unwrap();
        assert_eq!((ed.name.as_str(), ed.arch.as_str(), ed.base.as_str()), (SM120_SILICON_NAME, "sm_120", "dep_latency_sm120.json"));
        let t = load_bundled().unwrap();
        assert_eq!(t.edition, Some((SM120_SILICON_NAME.to_string(), ed.len())));
        assert_eq!(t.label(), format!("sm_120 edition sm120-silicon ({} entries)", ed.len()));
        // the default table is not an edition and says so nowhere
        assert_eq!(base().edition, None);
        assert_eq!(base().label(), "sm_120");
        // every entry of it lowers: nothing in the edition is above today's table
        for e in &ed.cells {
            let today = base().cell_l(e.producer.as_deref().unwrap(), e.consumer.as_deref().unwrap(), e.role.as_deref().unwrap()).unwrap();
            assert!(e.l <= today, "{}", e.id);
        }
    }

    #[test]
    fn a_resource_entry_lowers_one_pair_of_member_classes_and_nothing_else() {
        let b = base();
        // today: two tensor instructions are never closer than 16
        assert_eq!(below(&b, QMMA_A, QMMA_B, 2, "mma"), 1);
        assert_eq!(below(&b, QMMA_A, QMMA_B, 15, "mma"), 1);
        assert_eq!(below(&b, QMMA_A, QMMA_B, 16, "mma"), 0);
        let text = edition(&format!(
            r#""resources":[{{"id":"P1","resource":"mma","first":"QMMA","second":"QMMA","floor":1,"floor_basis":"interlock","L":2,{EV}}}]"#
        ));
        let t = apply(base(), &parse(&text).unwrap()).unwrap();
        assert_eq!(t.edition, Some(("t".to_string(), 1)));
        // the pair of the entry: its own distance, and still a finding below it
        assert_eq!(below(&t, QMMA_A, QMMA_B, 2, "mma"), 0);
        assert_eq!(below(&t, QMMA_A, QMMA_B, 1, "mma"), 1);
        // every other pair of members keeps the 16
        assert_eq!(below(&t, HMMA, QMMA_B, 15, "mma"), 1);
        assert_eq!(below(&t, QMMA_A, HMMA, 15, "mma"), 1);
        assert_eq!(below(&t, HMMA, "HMMA.16816.F32.BF16 R32, R68, R74, R32", 15, "mma"), 1);
        // and the other rows of the table are where they were (a memory pair: 4)
        assert_eq!(below(&t, "LDS R6, [R9]", "LDS R8, [R9+0x10]", 3, "mem"), below(&b, "LDS R6, [R9]", "LDS R8, [R9+0x10]", 3, "mem"));
    }

    #[test]
    fn a_cell_entry_lowers_that_cell_and_no_role_beside_it() {
        let b = base();
        assert_eq!(b.cell_l("IADD3", "IADD3", "r1"), Some(4), "the cell this test stands on");
        let prod = "IADD3 R6, PT, PT, R4, R5, RZ";
        let r1 = "IADD3 R8, PT, PT, R6, R5, RZ";
        let r2 = "IADD3 R8, PT, PT, R5, R6, RZ";
        assert_eq!(below(&b, prod, r1, 3, "raw"), 1);
        let text =
            edition(&format!(r#""cells":[{{"id":"c","producer":"IADD3","consumer":"IADD3","role":"r1","floor":2,"floor_basis":"wrong-below","L":3,{EV}}}]"#));
        let t = apply(base(), &parse(&text).unwrap()).unwrap();
        assert_eq!(t.cell_l("IADD3", "IADD3", "r1"), Some(3));
        assert_eq!(below(&t, prod, r1, 3, "raw"), 0);
        assert_eq!(below(&t, prod, r1, 2, "raw"), 1);
        // the second operand of the same pair is another cell: today's number
        for d in 1..=6 {
            assert_eq!(below(&t, prod, r2, d, "raw"), below(&b, prod, r2, d, "raw"), "role r2 at {d}");
        }
        // a role `<r>h` without a cell of its own borrowed the lowered cell: it keeps today's number
        let mut b2 = base();
        let p = ["SEL", "LOP3", "SHF", "LEA", "IMAD", "IADD3", "MOV", "FADD", "PRMT"]
            .into_iter()
            .find(|p| b2.cell_l(p, "IMAD.WIDE", "r3").is_some() && b2.cell_l(p, "IMAD.WIDE", "r3h").is_none());
        if let Some(p) = p {
            let today = b2.cell_l(p, "IMAD.WIDE", "r3").unwrap();
            b2.lower_cell(p, "IMAD.WIDE", "r3", today - 1);
            assert_eq!(b2.cell_l(p, "IMAD.WIDE", "r3"), Some(today - 1));
            assert_eq!(b2.cell_l(p, "IMAD.WIDE", "r3h"), Some(today), "{p} -> IMAD.WIDE: the upper register of the addend");
        }
    }

    #[test]
    fn a_hold_is_carried_in_its_own_section() {
        let text =
            edition(&format!(r#""holds":[{{"id":"A","hold":"mma_a_fragment","floor":5,"floor_basis":"wrong-below","L":6,{EV}}}]"#));
        let t = apply(base(), &parse(&text).unwrap()).unwrap();
        assert_eq!(t.edition_holds, vec![("mma_a_fragment".to_string(), 6)]);
        assert!(base().edition_holds.is_empty());
    }

    #[test]
    fn a_malformed_entry_is_refused() {
        let cell = |more: &str| edition(&format!(r#""cells":[{{"id":"c","producer":"IADD3","consumer":"IADD3","role":"r1",{more}}}]"#));
        // no evidence named
        assert!(refused(&cell(r#""floor":2,"floor_basis":"wrong-below","L":3"#)).contains("no evidence file is named"));
        assert!(refused(&cell(r#""floor":2,"floor_basis":"wrong-below","L":3,"evidence":[]"#)).contains("no evidence file is named"));
        // L is the floor + 1, not the floor and not more
        assert!(refused(&cell(&format!(r#""floor":2,"floor_basis":"wrong-below","L":2,{EV}"#))).contains("not the measured floor 2 + 1"));
        assert!(refused(&cell(&format!(r#""floor":2,"floor_basis":"wrong-below","L":4,{EV}"#))).contains("not the measured floor 2 + 1"));
        assert!(refused(&cell(&format!(r#""floor":0,"floor_basis":"interlock","L":1,{EV}"#))).contains("issue distance of 1 or more"));
        // a floor needs a wrong result below it; only floor 1 may be an interlock
        assert!(refused(&cell(&format!(r#""floor":1,"floor_basis":"wrong-below","L":2,{EV}"#))).contains("no smaller distance"));
        assert!(refused(&cell(&format!(r#""floor":2,"floor_basis":"interlock","L":3,{EV}"#))).contains("`interlock` is the floor 1 only"));
        assert!(refused(&cell(&format!(r#""floor":2,"floor_basis":"none found","L":3,{EV}"#))).contains("unknown `floor_basis`"));
        // the evidence is a digest under tools/stallfloor/silicon/ with its sha256 and the request
        let ev = |file: &str, sha: &str, req: &str| {
            cell(&format!(r#""floor":2,"floor_basis":"wrong-below","L":3,"evidence":[{{"file":"{file}","sha256":"{sha}","request":"{req}"}}]"#))
        };
        let sha = "0".repeat(64);
        assert!(refused(&ev("tools/stallfloor/probe_sm120_20261111_b8.json", &sha, "r")).contains("is not a .json file under tools/stallfloor/silicon/"));
        assert!(refused(&ev("tools/stallfloor/silicon/../x.json", &sha, "r")).contains("is not a .json file under"));
        assert!(refused(&ev("tools/stallfloor/silicon/x.json", "abc", "r")).contains("has no sha256"));
        assert!(refused(&ev("tools/stallfloor/silicon/x.json", &sha, "")).contains("names no request"));
        // the target of a section is its own, whole, and nothing of another section
        let ok = format!(r#""floor":2,"floor_basis":"wrong-below","L":3,{EV}"#);
        assert!(refused(&edition(&format!(r#""cells":[{{"id":"c","producer":"IADD3","consumer":"IADD3",{ok}}}]"#))).contains("the target must be exactly"));
        assert!(refused(&edition(&format!(r#""cells":[{{"id":"c","producer":"IADD3","consumer":"IADD3","role":"r1","hold":"x",{ok}}}]"#)))
            .contains("the target must be exactly"));
        assert!(refused(&edition(&format!(r#""resources":[{{"id":"c","resource":"mma","first":"QMMA",{ok}}}]"#))).contains("the target must be exactly"));
        // an id of its own
        let two = format!(r#"{{"id":"c","producer":"IADD3","consumer":"IADD3","role":"r1",{ok}}}"#);
        assert!(refused(&edition(&format!(r#""cells":[{two},{two}]"#))).contains("an id of its own"));
        // a key the format does not have (a lower-case `l`, a misspelt section) is not skipped
        assert!(refused(&cell(&format!(r#""floor":2,"floor_basis":"wrong-below","l":3,{EV}"#))).contains("unknown field"));
        assert!(refused(&edition(r#""cell":[]"#)).contains("unknown field"));
        // another schema
        assert!(refused(&edition(r#""cells":[]"#).replace("cubit-dep-edition-1", "cubit-dep-edition-2")).contains("schema"));
        // a witness is a file under the same directory with its sha256
        let wit = |file: &str, sha: &str| edition(&format!(r#""witnesses":[{{"file":"{file}","sha256":"{sha}"}}]"#));
        assert!(refused(&wit("somewhere/else.json", &sha)).contains("witness `somewhere/else.json` is not a .json file under"));
        assert!(refused(&wit("tools/stallfloor/silicon/w.json", "12")).contains("has no sha256"));
        assert!(parse(&wit("tools/stallfloor/silicon/w.json", &sha)).is_ok());
    }

    #[test]
    fn an_entry_that_names_nothing_or_raises_is_refused() {
        let ok = format!(r#""floor":2,"floor_basis":"wrong-below","L":3,{EV}"#);
        // no such cell in the base table (a pair priced with a default has no cell to lower)
        assert!(refused(&edition(&format!(r#""cells":[{{"id":"c","producer":"NOPE","consumer":"IADD3","role":"r1",{ok}}}]"#)))
            .contains("the base table has no cell NOPE -> IADD3 (r1)"));
        // above today's number: IADD3 -> IADD3 r1 is 4
        let up = format!(r#""floor":4,"floor_basis":"wrong-below","L":5,{EV}"#);
        assert!(refused(&edition(&format!(r#""cells":[{{"id":"c","producer":"IADD3","consumer":"IADD3","role":"r1",{up}}}]"#)))
            .contains("is above today's 4 -- an edition only lowers"));
        // resources: the resource, both members; never above the spacing
        assert!(refused(&edition(&format!(r#""resources":[{{"id":"c","resource":"tensor","first":"QMMA","second":"QMMA",{ok}}}]"#)))
            .contains("has no resource `tensor`"));
        assert!(refused(&edition(&format!(r#""resources":[{{"id":"c","resource":"mma","first":"QMMA","second":"LDS",{ok}}}]"#)))
            .contains("LDS is not a member of the resource `mma`"));
        let up = format!(r#""floor":16,"floor_basis":"wrong-below","L":17,{EV}"#);
        assert!(refused(&edition(&format!(r#""resources":[{{"id":"c","resource":"mma","first":"QMMA","second":"QMMA",{up}}}]"#)))
            .contains("is above today's 16"));
        // holds: a known name, never above today's
        assert!(refused(&edition(&format!(r#""holds":[{{"id":"c","hold":"anything",{ok}}}]"#))).contains("unknown hold `anything`"));
        let up = format!(r#""floor":8,"floor_basis":"wrong-below","L":9,{EV}"#);
        assert!(refused(&edition(&format!(r#""holds":[{{"id":"c","hold":"mma_a_fragment",{up}}}]"#))).contains("is above today's 8"));
        // another architecture
        assert!(refused(&edition(r#""cells":[]"#).replace("sm_120", "sm_103a")).contains("the edition is for sm_103a and the table for sm_120"));
        // an edition of an edition
        let ed = parse(&edition(r#""cells":[]"#)).unwrap();
        let once = apply(base(), &ed).unwrap();
        assert!(apply(once, &ed).unwrap_err().to_string().contains("already is an edition"));
    }
}

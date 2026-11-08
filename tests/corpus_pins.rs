//! The strict corpora of the other three tables as suite pins (session T-21, 2026-11-08; `T/NEEDS_OWNER.md` 56).
//!
//! From 2026-11-06 to 2026-11-08 the GB10 census ("91 927 / 91 927 words decode", KNOWN_ISSUES V3) had 564 words
//! without a decode -- every signed FSETP word of the corpus -- because a decoder arm measured on sm120 (FSETP off
//! the sign-tolerant match) applied to every table while the sm121a harvest rows declared no sign fields. Nothing
//! in the suite ran that census, so the regression lasted two days. These pins put the two corpora the gate runs
//! into `cargo test`:
//!
//! * `tests/fixtures/corpus_gb10_sm121a.jsonl.gz` -- the 91 927 distinct words of the GB10 / Spark corpus (gx4,
//!   `/root/sparklab/results/q1/corpus`, deduplicated 2026-11-08) with their nvdisasm 13.0 texts; table `sm121a`.
//! * `tests/fixtures/corpus_b300_sm103a.jsonl` / `corpus_b300_sm100a.jsonl` -- the 3 962 + 1 116 distinct instruction
//!   words of the B300 publish corpus (328 cubins, `/root/cubit-T/results/corpus103.txt`; the `cub_100a` group on
//!   `sm100a`, the rest on `sm103a`), with their occurrence counts.
//!
//! Each word is decoded, printed losslessly, re-parsed with its own control code and encoded again (the
//! `examples/audit_words.rs` procedure). The pins are exact: every word of the GB10 corpus decodes; the words that
//! do not re-encode bit for bit are named by key and counted (the GB10 residue: 40 words of three keys outside any
//! measured family; the B300 residue: the deliberate fail-closed refusals -- BUG-080's guarded non-EL ATOMS, the
//! text-inert `UMOV` bits -- and the table holes still open on the B300 line). A table or decoder change that moves a
//! count fails here with the words that moved, so a regression fails the suite and not the field; an improvement
//! re-pins the count in the same commit, as every census pin of this suite does.

use cubit::decoder::DecodeIndex;
use cubit::table::IsaTable;
use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read};

struct Outcome {
    words: usize,
    decoded: usize,
    reencoded: usize,
    /// decoded but not bit-exact: key -> count
    mismatch_by_key: BTreeMap<String, usize>,
    /// decoded but refused on the way back: first line of the error (its BUG tag where it has one) -> count
    refused_by_class: BTreeMap<String, usize>,
    /// no decode at all: the words
    undecoded: Vec<u128>,
}

fn read_words(path: &str) -> Vec<u128> {
    let raw = std::fs::read(path).unwrap_or_else(|e| panic!("{path}: {e}"));
    let text = if path.ends_with(".gz") {
        let mut s = String::new();
        flate2::read::GzDecoder::new(&raw[..]).read_to_string(&mut s).unwrap();
        s
    } else {
        String::from_utf8(raw).unwrap()
    };
    let mut out = Vec::new();
    for line in BufReader::new(text.as_bytes()).lines() {
        let line = line.unwrap();
        if line.trim().is_empty() {
            continue;
        }
        let v: serde_json::Value = serde_json::from_str(&line).unwrap();
        out.push(u128::from_str_radix(v["hex"].as_str().unwrap(), 16).unwrap());
    }
    out
}

fn class_of(err: &anyhow::Error) -> String {
    let first = err.to_string().lines().next().unwrap_or("").to_string();
    // the refusals name their law (`BUG-080`, `BUG-004`, ...): pin by tag, not by the whole message
    if let Some(i) = first.find("BUG-") {
        let tag: String = first[i..].chars().take_while(|c| c.is_ascii_alphanumeric() || *c == '-').collect();
        return tag;
    }
    first.chars().take(60).collect()
}

fn run(table: &str, words: &[u128]) -> Outcome {
    let t = IsaTable::load(std::path::Path::new(&format!("tables/{table}.json"))).unwrap();
    let idx = DecodeIndex::build(&t);
    let mut o = Outcome { words: words.len(), decoded: 0, reencoded: 0, mismatch_by_key: BTreeMap::new(),
                          refused_by_class: BTreeMap::new(), undecoded: Vec::new() };
    for &w in words {
        let d = match idx.decode(w, 0, &t) {
            Ok(d) => d,
            Err(_) => {
                o.undecoded.push(w);
                continue;
            }
        };
        o.decoded += 1;
        let text = cubit::printer::to_sass_lossless(&d);
        let ctrl = cubit::scheduling::decode_sched_upper32((w >> 96) as u32);
        let source = format!("[{}] {text} ;", cubit::scheduling::format_control_code(&ctrl));
        let back = (|| -> anyhow::Result<u128> {
            cubit::roundtrip_audit::check_semantic_source(&source)?;
            let parsed = cubit::parse_cuasm_line(&source, 0)?;
            anyhow::ensure!(parsed.hand_sched && parsed.rsd.is_none(), "nonsemantic source");
            cubit::encoder::encode_instruction(&parsed, &t)
        })();
        match back {
            Ok(x) if x == w => o.reencoded += 1,
            Ok(_) => *o.mismatch_by_key.entry(d.key.clone()).or_default() += 1,
            Err(e) => *o.refused_by_class.entry(class_of(&e)).or_default() += 1,
        }
    }
    o
}

fn pin(o: &Outcome, label: &str, decoded: usize, reencoded: usize, holes_by_opcode: &[(u16, usize)], mismatch: &[(&str, usize)],
       refused: &[(&str, usize)]) {
    assert!(o.undecoded.len() <= 24, "[{label}] {} words without a decode, the first: {:?}", o.undecoded.len(),
            o.undecoded.iter().take(24).map(|w| format!("{w:032x}")).collect::<Vec<_>>());
    assert_eq!((o.decoded, o.words), (decoded, o.words), "[{label}] decoded words; without a decode: {:?}",
               o.undecoded.iter().map(|w| format!("{w:032x}")).collect::<Vec<_>>());
    let mut holes: BTreeMap<u16, usize> = BTreeMap::new();
    for w in &o.undecoded {
        *holes.entry((w & 0xfff) as u16).or_default() += 1;
    }
    let want_h: BTreeMap<u16, usize> = holes_by_opcode.iter().copied().collect();
    assert_eq!(holes, want_h, "[{label}] words without a decode by opcode: {:?}",
               o.undecoded.iter().map(|w| format!("{w:032x}")).collect::<Vec<_>>());
    assert_eq!(o.reencoded, reencoded, "[{label}] words re-encoded bit for bit (mismatches {:?}, refusals {:?})",
               o.mismatch_by_key, o.refused_by_class);
    let want_m: BTreeMap<String, usize> = mismatch.iter().map(|(k, n)| (k.to_string(), *n)).collect();
    assert_eq!(o.mismatch_by_key, want_m, "[{label}] re-encode mismatches by key");
    let want_r: BTreeMap<String, usize> = refused.iter().map(|(k, n)| (k.to_string(), *n)).collect();
    assert_eq!(o.refused_by_class, want_r, "[{label}] re-encode refusals by class");
}

/// The GB10 / Spark corpus on sm121a: every one of the 91 927 words decodes (the T-20 regression class), 91 887
/// re-encode bit for bit (91 926 since T-22: the UIADD3 `64` groups measured; 91 910 since T-21 batch 7: the FP32 ALU measured on sm121a gave `FFMA_R_R_R_FI` the `.reuse`
/// field of its second register that the harvest immediate-form row lacked -- 23 words); the 17 that do not are the
/// harvest `UIADD3_UR_UP_UP_UR_UR_UR` `64` group 16 (its register fields are mis-declared: `-UR6` re-encodes to other
/// registers; the same form is a hole on sm103a / sm100a, see below) and `HMMA.1688.F32 R8, R6, R4, RZ` 1 (refused
/// by BUG-037's operand-alignment law: an A operand at R6 is not 4-aligned -- a cuBLASLt word nvdisasm names) --
/// the next GB10 batches' items.
#[test]
fn gb10_corpus_sm121a_decodes_and_reencodes() {
    let words = read_words("tests/fixtures/corpus_gb10_sm121a.jsonl.gz");
    assert_eq!(words.len(), 91927, "the GB10 corpus fixture");
    let o = run("sm121a", &words);
    assert!(o.undecoded.is_empty(), "[sm121a] GB10 words without a decode: {} (the 2026-11-06..08 class), the first: {:?}",
            o.undecoded.len(), o.undecoded.iter().take(8).map(|w| format!("{w:032x}")).collect::<Vec<_>>());
    // T-21 batch 7 (2026-11-08): the FP32 ALU measured on sm121a -- the 23 FFMA words re-encode bit for bit (91 887 -> 91 910);
    // T-22 (2026-11-08): the UIADD3 `64` groups measured on -b SM121 (sm120's rows with the corpus words as witnesses) -- the
    // 16 words of the mis-declared harvest group re-encode (91 910 -> 91 926); the one left is BUG-037's refusal
    pin(&o, "sm121a GB10", 91927, 91926, &[],
        &[], &[("BUG-037", 1)]);
}

/// The B300 publish corpus, sm103a half (177 cubins, 3 962 distinct words). The residue at the T-21 batch-4 tables:
/// 12 words without a decode (15 before batch 7 closed `I2F.U16[.RZ]` x 2 and `FMUL.RZ` x 1 by measuring the conversions
/// and the FP32 ALU on sm103a) -- the sm103a holes the B300 line's next batches close (`UIADD3.64` on the UR form 0x297
/// x 3 and the immediate form 0x897 x 6: the table has no `64` group; `MOV R2, 0x0` 0x802 x 3 with text-inert bits set in [67:64] /
/// 80 / [79:76] -- words of the hand-written probe cubins that nvdisasm names without them); 9 words the encoder
/// refuses on purpose (BUG-080: a guard-predicated non-EL ATOMS is silently broken on sm_103a silicon, B300 2026-08-22);
/// `RET.REL.NODEC` x 6 and `UMOV URn, 0x0` x 2 re-encode to other bits (the PC-relative target rendered at address 0 by
/// this isolated-word procedure -- the frozen round trip at the real address is exact, `T/NEEDS_OWNER.md` 51 -- and the
/// text-inert reuse bit 122 of the UMOV immediate form, KNOWN_ISSUES V5).
#[test]
fn b300_corpus_sm103a_strict() {
    let words = read_words("tests/fixtures/corpus_b300_sm103a.jsonl");
    assert_eq!(words.len(), 3962, "the B300 sm103a corpus fixture");
    let o = run("sm103a", &words);
    // T-21 batch 7 (2026-11-08): the conversions and the FP32 ALU measured on sm103a -- the I2F.U16 x 2 and FMUL.RZ x 1 holes
    // are closed (3 947 -> 3 950 decoded, 3 930 -> 3 933 bit-exact); T-22 (2026-11-08): the UIADD3 `64` groups measured on
    // -b SM103 (sm120's rows, the 9 corpus words as witnesses) -- 3 959 decoded, 3 942 bit-exact; the 3 MOV probe-cubin words remain
    pin(&o, "sm103a B300", 3959, 3942, &[(0x802, 3)],
        &[("RET_R_II", 6), ("UMOV_UR_II", 2)], &[("BUG-080", 9)]);
}

/// The B300 publish corpus, sm100a half (151 `cub_100a` cubins, 1 116 distinct words): every word decodes since T-22 (the
/// 3 `UIADD3.64` UR-form words were the last hole), 3 `RET.REL.NODEC` words of the isolated-word artefact re-encode to other bits.
#[test]
fn b300_corpus_sm100a_strict() {
    let words = read_words("tests/fixtures/corpus_b300_sm100a.jsonl");
    assert_eq!(words.len(), 1116, "the B300 sm100a corpus fixture");
    let o = run("sm100a", &words);
    // T-22 (2026-11-08): the UIADD3 `64` groups measured on -b SM100 -- the 3 UR-form words decode and re-encode (1 116 / 1 113)
    pin(&o, "sm100a B300", 1116, 1113, &[], &[("RET_R_II", 3)], &[]);
}

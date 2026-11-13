//! FHADD and HSET2 executed on silicon (the B300 measurement lane, 2026-11-11): 16 FHADD words and 2 HSET2 words,
//! each run on an NVIDIA B300 (sm_103a) and on an NVIDIA B200 (sm_100a) by a 17-instruction kernel that loads R2 and
//! R4, executes the word and stores R10. `tests/fixtures/sm103a_sm100a_fhadd_hset2_silicon.jsonl` holds, per word,
//! the vendor's text and the rows `[a, b, out]` = R2, R4, R10 — 352 per series, 7 040 in all; both devices returned
//! the same value in every row, so the rows are stored once. The raw records, the images and the harness are not in
//! this repository (the fixture's first line names the archive's manifest aggregate).
//! What the file pins: (1) on the `sm103a` and `sm100a` tables each of the 18 words decodes to the vendor's text
//! and that text re-assembles to the word, all 128 bits. (2) FHADD: R10 is the FP32 sum of one 16-bit half of R2
//! — H0 or H1, read as F16, with `.BF16` as BF16 — and R4 read as FP32, correctly rounded: no suffix = to nearest,
//! ties to even; `.RM` toward minus infinity, `.RP` toward plus infinity, `.RZ` toward zero. The law is computed
//! here in exact integer arithmetic (every finite operand is a multiple of 2^-149): the 4 800 rows with two finite
//! operands agree bit for bit (34 of those sums overflow), the 152 rows with an infinite operand give the infinity
//! of the law, and the 680 rows where the law gives a NaN give a NaN (the payload is not pinned). Two cases of the
//! law are not among the rows: the sum of two negative zeros, and an exact sum beyond the largest finite number
//! under a direction that keeps the result finite.
//! (3) HSET2 with the second source spelled `R4.H0_H0`: each half of R10 is the IEEE equality of the
//! same half of R2 with H0 of R4 (a NaN equals nothing, -0 equals +0) — 0xffff when true in `HSET2.EQ.AND`, BF16
//! 1.0 (0x3f80) in `HSET2.BF16_V2.BF.EQ.AND`, 0 when false — in every one of the 1 408 rows; the lane's own
//! rejected model, which pairs H1 of R2 with H1 of R4 and expects 0xffff in both forms, misses 9 and 40 rows of
//! the independent series. Measured rows only: no `.SAT` word, no other half selector, comparison or boolean
//! operand than the ones in the 18 texts, no NaN payload rule, no timing.
use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::cmp::Ordering;

const FIXTURE: &str = include_str!("fixtures/sm103a_sm100a_fhadd_hset2_silicon.jsonl");
const ROWS: usize = 352; // 11 launches of 32 lanes: rows 0..255 the finite domain, 256..351 the special one

fn records() -> Vec<Value> {
    let all: Vec<Value> = FIXTURE.lines().map(|line| serde_json::from_str(line).unwrap()).collect();
    assert_eq!(all[0]["fixture"], "sm103a_sm100a_fhadd_hset2_silicon");
    all[1..].to_vec()
}

fn rows(record: &Value) -> Vec<[u32; 3]> {
    let hex = |v: &Value| u32::from_str_radix(v.as_str().unwrap(), 16).unwrap();
    let rows: Vec<[u32; 3]> =
        record["rows"].as_array().unwrap().iter().map(|r| [hex(&r[0]), hex(&r[1]), hex(&r[2])]).collect();
    assert_eq!(rows.len(), ROWS, "{}", record["case"]);
    rows
}

// ---------------------------------------------------------------------------------------------------------------
// (1) the words
// ---------------------------------------------------------------------------------------------------------------

#[test]
fn the_18_executed_words_decode_to_the_vendor_text_and_reassemble_on_both_tables() {
    let records = records();
    let mut words = std::collections::BTreeMap::new();
    for record in &records {
        let word = u128::from_str_radix(record["word"].as_str().unwrap().trim_start_matches("0x"), 16).unwrap();
        let text = record["text"].as_str().unwrap().to_string();
        let family = record["family"].as_str().unwrap().to_string();
        assert!(text.starts_with(&family), "{text}");
        if let Some(seen) = words.insert(word, (family, text.clone())) {
            assert_eq!(seen.1, text, "one word, one text");
        }
    }
    assert_eq!(words.values().filter(|(family, _)| family == "FHADD").count(), 16);
    assert_eq!(words.values().filter(|(family, _)| family == "HSET2").count(), 2);
    for arch in ["sm103a", "sm100a"] {
        let table = IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap();
        let index = DecodeIndex::build(&table);
        for (&word, (family, text)) in &words {
            let decoded = index.decode(word, 0, &table).unwrap_or_else(|e| panic!("{arch} {word:032x}: {e}"));
            let key = if family == "FHADD" { "FHADD_R_R_R" } else { "HSET2_R_R_R_P" };
            assert_eq!(decoded.key, key, "{arch} {word:032x}");
            assert_eq!(&cubit::printer::to_sass(&decoded), text, "{arch} {word:032x}");
            assert_eq!(&cubit::printer::to_sass_lossless(&decoded), text, "{arch} {word:032x}");
            let control = cubit::scheduling::format_control_code(&cubit::scheduling::decode_sched_upper32(
                (word >> 96) as u32,
            ));
            let parsed = cubit::parse_cuasm_line(&format!("[{control}] {text} ;"), 0).unwrap();
            let encoded = cubit::encoder::encode_instruction(&parsed, &table).unwrap();
            assert_eq!(encoded, word, "{arch} {text}: {encoded:032x} is not the executed word {word:032x}");
        }
    }
}

// ---------------------------------------------------------------------------------------------------------------
// (2) FHADD: the exact sum, correctly rounded
// ---------------------------------------------------------------------------------------------------------------

/// A non-negative integer of 320 bits, least significant limb first: a magnitude in units of 2^-149.
/// The largest operand, FP32 `0x7f7fffff`, is (2^24 - 1) * 2^253 units; a sum stays below 2^279.
type Wide = [u64; 5];

fn shifted(mantissa: u64, shift: u32) -> Wide {
    let mut wide = [0u64; 5];
    let (limb, bit) = ((shift / 64) as usize, shift % 64);
    wide[limb] = mantissa << bit;
    if bit != 0 && mantissa >> (64 - bit) != 0 {
        wide[limb + 1] = mantissa >> (64 - bit);
    }
    wide
}

fn compare(a: &Wide, b: &Wide) -> Ordering {
    a.iter().rev().cmp(b.iter().rev())
}

fn add(a: &Wide, b: &Wide) -> Wide {
    let (mut sum, mut carry) = ([0u64; 5], 0u128);
    for i in 0..5 {
        let limb = a[i] as u128 + b[i] as u128 + carry;
        (sum[i], carry) = (limb as u64, limb >> 64);
    }
    assert_eq!(carry, 0);
    sum
}

/// `a - b` for `a >= b`.
fn subtract(a: &Wide, b: &Wide) -> Wide {
    let (mut difference, mut borrow) = ([0u64; 5], false);
    for i in 0..5 {
        let (limb, first) = a[i].overflowing_sub(b[i]);
        let (limb, second) = limb.overflowing_sub(borrow as u64);
        (difference[i], borrow) = (limb, first || second);
    }
    assert!(!borrow);
    difference
}

fn bit_length(a: &Wide) -> u32 {
    (0..5).rev().find(|&i| a[i] != 0).map_or(0, |i| 64 * i as u32 + 64 - a[i].leading_zeros())
}

fn bit(a: &Wide, position: u32) -> bool {
    a[(position / 64) as usize] >> (position % 64) & 1 == 1
}

/// What a 16- or 32-bit pattern is: the fraction width, the exponent width, and the weight of the last fraction
/// bit of the subnormals in units of 2^-149 (F16: 2^-24, BF16: 2^-133, FP32: 2^-149).
#[derive(Clone, Copy)]
struct Format {
    fraction_bits: u32,
    exponent_bits: u32,
    unit_shift: u32,
}
const F16: Format = Format { fraction_bits: 10, exponent_bits: 5, unit_shift: 125 };
const BF16: Format = Format { fraction_bits: 7, exponent_bits: 8, unit_shift: 16 };
const FP32: Format = Format { fraction_bits: 23, exponent_bits: 8, unit_shift: 0 };

#[derive(Debug, PartialEq)]
enum Number {
    Nan,
    Infinite { negative: bool },
    Finite { negative: bool, magnitude: Wide },
}

fn number(pattern: u32, format: Format) -> Number {
    let fraction = (pattern & ((1 << format.fraction_bits) - 1)) as u64;
    let exponent = pattern >> format.fraction_bits & ((1 << format.exponent_bits) - 1);
    let negative = pattern >> (format.fraction_bits + format.exponent_bits) & 1 == 1;
    if exponent == (1 << format.exponent_bits) - 1 {
        return if fraction != 0 { Number::Nan } else { Number::Infinite { negative } };
    }
    let magnitude = if exponent == 0 {
        shifted(fraction, format.unit_shift)
    } else {
        shifted(1 << format.fraction_bits | fraction, format.unit_shift + exponent - 1)
    };
    Number::Finite { negative, magnitude }
}

#[derive(Clone, Copy, PartialEq)]
enum Rounding {
    NearestEven,
    Down,
    Up,
    TowardZero,
}

/// The FP32 pattern of `(-1)^negative * magnitude * 2^-149`, `magnitude != 0`, rounded.
fn fp32(negative: bool, magnitude: &Wide, rounding: Rounding) -> u32 {
    let sign = (negative as u32) << 31;
    let length = bit_length(magnitude);
    if length <= 24 {
        // a subnormal or a number of the first binade: the pattern is the count of units itself
        return sign | magnitude[0] as u32;
    }
    let mut dropped = length - 24;
    let mut kept = (0..24).fold(0u32, |kept, i| kept | (bit(magnitude, dropped + i) as u32) << i);
    let half = bit(magnitude, dropped - 1);
    let below_half = (0..dropped - 1).any(|i| bit(magnitude, i));
    let away = match rounding {
        Rounding::NearestEven => half && (below_half || kept & 1 == 1),
        Rounding::Down => negative && (half || below_half),
        Rounding::Up => !negative && (half || below_half),
        Rounding::TowardZero => false,
    };
    if away {
        kept += 1;
        if kept == 1 << 24 {
            (kept, dropped) = (1 << 23, dropped + 1);
        }
    }
    if dropped + 1 >= 255 {
        // above the largest finite number: infinity, or that number where the direction forbids growing
        let grows = match rounding {
            Rounding::NearestEven => true,
            Rounding::Down => negative,
            Rounding::Up => !negative,
            Rounding::TowardZero => false,
        };
        return sign | if grows { 0x7f80_0000 } else { 0x7f7f_ffff };
    }
    // `kept` carries the implicit bit at 2^23: adding it to `dropped << 23` gives the exponent field `dropped + 1`
    sign | ((dropped << 23) + kept)
}

/// The law: `half + b` over the reals, rounded to FP32. `None` is "a NaN" (no payload is asserted).
fn fhadd(half: u32, format: Format, b: u32, rounding: Rounding) -> Option<u32> {
    let (x, y) = (number(half, format), number(b, FP32));
    match (&x, &y) {
        (Number::Nan, _) | (_, Number::Nan) => None,
        (Number::Infinite { negative: p }, Number::Infinite { negative: q }) => (p == q).then_some(inf(*p)),
        (Number::Infinite { negative }, _) | (_, Number::Infinite { negative }) => Some(inf(*negative)),
        (Number::Finite { negative: p, magnitude: m }, Number::Finite { negative: q, magnitude: n }) => {
            let zero: Wide = [0; 5];
            let (negative, magnitude) = match (p == q, compare(m, n)) {
                (true, _) => (*p, add(m, n)),
                (false, Ordering::Greater) => (*p, subtract(m, n)),
                (false, Ordering::Less) => (*q, subtract(n, m)),
                (false, Ordering::Equal) => (false, zero),
            };
            if magnitude != zero {
                return Some(fp32(negative, &magnitude, rounding));
            }
            // a zero sum: two zeros of one sign keep it; otherwise +0, and -0 when rounding down
            let negative = if p == q { *p } else { rounding == Rounding::Down };
            Some((negative as u32) << 31)
        }
    }
}

fn inf(negative: bool) -> u32 {
    (negative as u32) << 31 | 0x7f80_0000
}

#[test]
fn the_exact_arithmetic_of_this_file_agrees_with_the_host_fpu_to_nearest() {
    // the model against the host's own FP32 addition (to nearest, ties to even) on patterns of every class
    let patterns: Vec<u32> = [0u32, 1, 2, 0x7f_ffff, 0x80_0000, 0x80_0001, 0x33_8000, 0x3380_0000, 0x3400_0000]
        .into_iter()
        .chain([0x3f7f_ffff, 0x3f80_0000, 0x3f80_0001, 0x4b80_0000, 0x7f7f_fffe, 0x7f7f_ffff, 0x7f80_0000])
        .chain((0..64).map(|i| 0x9e37_79b9u32.wrapping_mul(i * i + 7 * i + 1) & 0x7fff_ffff))
        .flat_map(|p| [p, p | 0x8000_0000])
        .filter(|&p| number(p, FP32) != Number::Nan)
        .collect();
    let mut checked = 0;
    for &x in &patterns {
        for &y in &patterns {
            let host = f32::from_bits(x) + f32::from_bits(y);
            let law = match (number(x, FP32), number(y, FP32)) {
                // FP32 + FP32 through the same code path: an FP32 first operand is its own "half"
                (Number::Finite { .. }, _) | (Number::Infinite { .. }, _) => fhadd_fp32(x, y),
                (Number::Nan, _) => unreachable!(),
            };
            match law {
                None => assert!(host.is_nan(), "{x:08x} + {y:08x}"),
                Some(bits) => assert_eq!(bits, host.to_bits(), "{x:08x} + {y:08x}"),
            }
            checked += 1;
        }
    }
    assert!(checked > 20_000, "{checked}");
    // the directed modes on a sum that is not representable: 1 + 2^-24 and -(1 + 2^-24)
    let (one, tiny) = (0x3f80_0000u32, 0x3380_0000u32);
    let modes = [Rounding::NearestEven, Rounding::Down, Rounding::Up, Rounding::TowardZero];
    let got = modes.map(|m| fp32_sum(one, tiny, m));
    assert_eq!(got, [0x3f80_0000, 0x3f80_0000, 0x3f80_0001, 0x3f80_0000]);
    let got = modes.map(|m| fp32_sum(one | 1 << 31, tiny | 1 << 31, m));
    assert_eq!(got, [0xbf80_0000, 0xbf80_0001, 0xbf80_0000, 0xbf80_0000]);
    // ... and 1 + 1.5 * 2^-24, where to nearest and toward zero part
    let got = modes.map(|m| fp32_sum(one, 0x33c0_0000, m));
    assert_eq!(got, [0x3f80_0001, 0x3f80_0000, 0x3f80_0001, 0x3f80_0000]);
    // overflow by rounding (the largest number plus half its last place) and by the exact sum (twice the largest)
    let got = modes.map(|m| fp32_sum(0x7f7f_ffff, 0x7300_0000, m));
    assert_eq!(got, [0x7f80_0000, 0x7f7f_ffff, 0x7f80_0000, 0x7f7f_ffff]);
    let got = modes.map(|m| fp32_sum(0x7f7f_ffff, 0x7f7f_ffff, m));
    assert_eq!(got, [0x7f80_0000, 0x7f7f_ffff, 0x7f80_0000, 0x7f7f_ffff]);
    let got = modes.map(|m| fp32_sum(0xff7f_ffff, 0xff7f_ffff, m));
    assert_eq!(got, [0xff80_0000, 0xff80_0000, 0xff7f_ffff, 0xff7f_ffff]);
    // exact cancellation and the signed zeros
    assert_eq!(modes.map(|m| fp32_sum(one, one | 1 << 31, m)), [0, 1 << 31, 0, 0]);
    assert_eq!(modes.map(|m| fp32_sum(1 << 31, 1 << 31, m)), [1 << 31; 4]);
    assert_eq!(modes.map(|m| fp32_sum(0, 1 << 31, m)), [0, 1 << 31, 0, 0]);
    assert_eq!(modes.map(|m| fp32_sum(0, 0, m)), [0; 4]);
}

fn fhadd_fp32(x: u32, y: u32) -> Option<u32> {
    fhadd(x, FP32, y, Rounding::NearestEven)
}

fn fp32_sum(x: u32, y: u32, rounding: Rounding) -> u32 {
    fhadd(x, FP32, y, rounding).unwrap()
}

#[test]
fn fhadd_is_the_correctly_rounded_fp32_sum_of_the_selected_half_and_the_fp32_source() {
    // rows by the class of the operands: both finite (and how many of those sums overflow), one infinite, a NaN result
    let (mut finite, mut overflow, mut infinite, mut nan, mut cases) = (0, 0, 0, 0, 0);
    for record in records().iter().filter(|r| r["family"] == "FHADD") {
        let text = record["text"].as_str().unwrap();
        // the law is read off the vendor's text: the modifiers and the half selector of the first source
        let (mnemonic, operands) = text.split_once(' ').unwrap();
        let modifiers: Vec<&str> = mnemonic.split('.').skip(1).collect();
        let format = if modifiers.contains(&"BF16") { BF16 } else { F16 };
        let rounding = match modifiers.iter().find(|m| **m != "BF16") {
            None => Rounding::NearestEven,
            Some(&"RM") => Rounding::Down,
            Some(&"RP") => Rounding::Up,
            Some(&"RZ") => Rounding::TowardZero,
            Some(other) => panic!("{text}: modifier {other}"),
        };
        let high_half = match operands {
            "R10, R2, R4" => false,
            "R10, R2.H1, R4" => true,
            other => panic!("{text}: operands {other}"),
        };
        // ... and agrees with the record's own labels
        assert_eq!(record["format"], if modifiers.contains(&"BF16") { "bf16" } else { "f16" }, "{text}");
        assert_eq!(record["half"], high_half as u64, "{text}");
        let label = ["plain", "rm", "rp", "rz"][rounding as usize];
        assert_eq!(record["rounding"], label, "{text}");
        for (row, [a, b, out]) in rows(record).into_iter().enumerate() {
            let half = if high_half { a >> 16 } else { a & 0xffff };
            match fhadd(half, format, b, rounding) {
                None => {
                    assert!(out & 0x7f80_0000 == 0x7f80_0000 && out & 0x7f_ffff != 0, "{text} row {row}: {out:08x}");
                    nan += 1;
                }
                Some(law) => {
                    assert_eq!(out, law, "{text} row {row}: half {half:04x} + {b:08x}");
                    let operand = |n: Number| matches!(n, Number::Finite { .. });
                    if operand(number(half, format)) && operand(number(b, FP32)) {
                        finite += 1;
                        overflow += (law & 0x7fff_ffff == 0x7f80_0000) as usize;
                    } else {
                        infinite += 1;
                    }
                }
            }
        }
        cases += 1;
    }
    assert_eq!((cases, finite, overflow, infinite, nan), (16, 4800, 34, 152, 680));
}

// ---------------------------------------------------------------------------------------------------------------
// (3) HSET2 `R10, R2, R4.H0_H0, PT`
// ---------------------------------------------------------------------------------------------------------------

/// IEEE equality of two 16-bit patterns of one format: a NaN equals nothing, the two zeros are equal.
fn equal(x: u32, y: u32, format: Format) -> bool {
    match (number(x, format), number(y, format)) {
        (Number::Nan, _) | (_, Number::Nan) => false,
        (p, q) => p == q || (x | y) & 0x7fff == 0,
    }
}

#[test]
fn hset2_eq_with_h0_h0_compares_both_halves_of_the_first_source_with_h0_of_the_second() {
    let mut seen = Vec::new();
    for record in records().iter().filter(|r| r["family"] == "HSET2") {
        let text = record["text"].as_str().unwrap();
        let (format, truth) = match text {
            "HSET2.EQ.AND R10, R2, R4.H0_H0, PT" => (F16, 0xffff),
            "HSET2.BF16_V2.BF.EQ.AND R10, R2, R4.H0_H0, PT" => (BF16, 0x3f80), // 1.0 in BF16
            other => panic!("{other}"),
        };
        let series = record["series"].as_str().unwrap();
        let rows = rows(record);
        if series == "equal operands" {
            assert!(rows.iter().all(|[a, b, _]| a == b), "{text}");
        }
        let (mut selector_law, mut h1_h1_mask, mut packed) = (0, 0, Vec::new());
        for &[a, b, out] in &rows {
            let (a0, a1, b0, b1) = (a & 0xffff, a >> 16, b & 0xffff, b >> 16);
            let mask = |low: bool, high: bool, truth: u32| (low as u32 * truth) | ((high as u32 * truth) << 16);
            selector_law += (out != mask(equal(a0, b0, format), equal(a1, b0, format), truth)) as usize;
            h1_h1_mask += (out != mask(equal(a0, b0, format), equal(a1, b1, format), 0xffff)) as usize;
            packed.extend_from_slice(&out.to_le_bytes());
        }
        assert_eq!(selector_law, 0, "{text}, {series}");
        let digest: String = Sha256::digest(&packed).iter().map(|byte| format!("{byte:02x}")).collect();
        seen.push((record["case"].as_str().unwrap().to_string(), series.to_string(), h1_h1_mask, digest));
    }
    // the rejected model's misses on the independent series (9 and 40) and the SHA-256 of the 352 results of each
    // series as little-endian 32-bit words, as the lane's document states them
    let expected = [
        ("f16", "equal operands", 324, "6ad8bf38170ce8be55741c0bd84cf2fff909b3f23cd26d8e688f39e328e5875a"),
        ("f16", "independent operands", 9, "bbd953f5e5119347c7bb52f7b81098aeab306ed29341898f19a44db2b5209982"),
        ("bf16", "equal operands", 346, "6d708ae82e7d5aad89a63766389365e5a7b9163ee0271dcc3c02171d447b0c72"),
        ("bf16", "independent operands", 40, "374e9a24e5e9f32fddd9a83e7418fe2f3c0d99648f9834d7ad0ceada65049ba8"),
    ];
    assert_eq!(seen.len(), expected.len());
    for ((case, series, misses, digest), want) in seen.iter().zip(expected) {
        assert_eq!((case.as_str(), series.as_str(), *misses, digest.as_str()), want);
    }
}

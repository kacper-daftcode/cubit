#!/usr/bin/env python3
"""Independent exact-rational FHADD references and frozen input domains."""

from fractions import Fraction
import pathlib
import struct

import numpy as np

N = 32
GUARD = 16
HOST_WORDS = 2 * N + 2 * GUARD
ALLOCATE = HOST_WORDS * 4
CANARY = 0xC0FFEE11
ROOT = pathlib.Path(__file__).resolve().parent
FORMATS = ("f16", "bf16")
ROUNDS = ("plain", "rm", "rp", "rz")
CASES = [f"{rounding}_{fmt}_h{h1}" for rounding in ROUNDS
         for fmt in FORMATS for h1 in (0, 1)]
REPLAY = "plain_bf16_h1_replay"
ALL_CASES = CASES + [REPLAY]


def spec(case):
    if case == REPLAY:
        result = spec("plain_bf16_h1")
        result["replay"] = True
        return result
    rounding, fmt, half = case.split("_")
    assert rounding in ROUNDS and fmt in FORMATS and half in ("h0", "h1")
    return {"rounding": rounding, "format": fmt, "h1": int(half[1]), "replay": False}


def one(fmt):
    return 0x3C00 if fmt == "f16" else 0x3F80


def values(fmt, special=False):
    p, m, two = one(fmt), one(fmt) | 0x8000, one(fmt) + (0x80 if fmt == "f16" else 0x40)
    base = [0, 0x8000, p, m, two, two | 0x8000, p - 1, m - 1,
            p + 1, m + 1, p // 2, m // 2]
    if fmt == "f16":
        base += [1, 0x8001, 0x03FF, 0x83FF, 0x0400, 0x8400, 0x7BFF, 0xFBFF]
        specials = [0x7C00, 0xFC00, 0x7E00, 0xFE00, 0x7C01, 0xFC01, 0x7FFF, 0xFFFF]
    else:
        base += [1, 0x8001, 0x007F, 0x807F, 0x0080, 0x8080, 0x7F7F, 0xFF7F]
        specials = [0x7F80, 0xFF80, 0x7FC0, 0xFFC0, 0x7F81, 0xFF81, 0x7FFF, 0xFFFF]
    return base + specials if special else base


def domain(kind, fmt):
    assert kind in ("finite", "special")
    source = values(fmt, kind == "special")
    count = 96 if kind == "special" else 256
    rows = [{"index": i, "a0": source[i % len(source)],
             "a1": source[(7 * i + 3) % len(source)],
             "b0": 0, "b1": 0} for i in range(count)]
    if kind == "finite":
        b32_values = [0x00000000, 0x80000000, 0x3F800000, 0xBF800000,
                      0x3F800001, 0xBF800001, 0x3F7FFFFF, 0xBF7FFFFF,
                      0x33800000, 0xB3800000, 0x34000000, 0xB4000000,
                      0x00000001, 0x80000001, 0x007FFFFF, 0x807FFFFF,
                      0x00800000, 0x80800000, 0x7F7FFFFF, 0xFF7FFFFF]
    else:
        b32_values = [0x7F800000, 0xFF800000, 0x7FC00000, 0xFFC00000,
                      0x7F800001, 0xFF800001, 0x7FFFFFFF, 0xFFFFFFFF,
                      0x00000001, 0x80000001, 0x007FFFFF, 0x807FFFFF,
                      0x00800000, 0x80800000, 0x3F800000, 0xBF800000,
                      0x00000000, 0x80000000, 0x7F7FFFFF, 0xFF7FFFFF]
    for i, row in enumerate(rows):
        word = b32_values[(11 * i + 5) % len(b32_values)]
        row.update(b0=word & 0xFFFF, b1=word >> 16)
    if kind == "finite":
        p, m = one(fmt), one(fmt) | 0x8000
        # Independent operand roles, cancellation, zeros, half-selectors and rounding ties.
        for i, (a, b) in enumerate(((p, p), (p, m), (0, 0), (0x8000, 0x8000),
                                    (p, 0), (0, p), (m, m), (p, two := one(fmt) + 1))):
            rows[i].update(a0=a, a1=m if i & 1 else p, b0=p, b1=0)
            rows[32 + i].update(a0=p + 3, a1=a, b0=m & 0xFFFF, b1=m >> 16)
        # Exact FP32 halfway cases use A=2^-24 and independently supplied B.
        tiny = 0x0001 if fmt == "f16" else 0x3380
        rows[64].update(a0=tiny, a1=tiny, b0=0, b1=0x3F80)
        rows[65].update(a0=tiny, a1=tiny, b0=1, b1=0x3F80)
    return rows


def pow2(exp):
    return Fraction(1 << exp, 1) if exp >= 0 else Fraction(1, 1 << -exp)


def layout(fmt):
    if fmt == "f16":
        return 10, 5, 15, -24, -14
    if fmt == "bf16":
        return 7, 8, 127, -133, -126
    if fmt == "f32":
        return 23, 8, 127, -149, -126
    raise ValueError(fmt)


def bits(fmt, sign, exponent, fraction):
    frac_bits, exp_bits, _bias, _sub, _normal = layout(fmt)
    return (sign << (frac_bits + exp_bits) | exponent << frac_bits |
            fraction & ((1 << frac_bits) - 1))


def exact(word, fmt):
    assert class_of(word, fmt) == "finite"
    frac_bits, exp_bits, bias, sub, normal = layout(fmt)
    sign = word >> (frac_bits + exp_bits)
    exponent = (word >> frac_bits) & ((1 << exp_bits) - 1)
    fraction = word & ((1 << frac_bits) - 1)
    if fmt == "f32":
        magnitude = Fraction((1 << frac_bits) | fraction if exponent else fraction)
        magnitude *= pow2(exponent - 150 if exponent else sub)
    elif exponent:
        magnitude = Fraction((1 << frac_bits) | fraction) * pow2(exponent - bias - frac_bits)
    else:
        magnitude = Fraction(fraction) * pow2(sub)
    return -magnitude if sign else magnitude


def class_of(word, fmt):
    frac_bits, exp_bits, _bias, _sub, _normal = layout(fmt)
    fraction = word & ((1 << frac_bits) - 1)
    exponent = (word >> frac_bits) & ((1 << exp_bits) - 1)
    if exponent == (1 << exp_bits) - 1:
        return "nan" if fraction else "inf"
    return "finite"


def round_magnitude(value, mode, negative):
    quotient, remainder = divmod(value.numerator, value.denominator)
    if (mode == "rm" and negative) or (mode == "rp" and not negative):
        return quotient + bool(remainder)
    if mode in ("rz", "rm", "rp"):
        return quotient
    twice = remainder * 2
    return quotient + int(twice > value.denominator or
                          twice == value.denominator and quotient & 1)


def round_finite(value, fmt, mode="plain", zero_sign=0):
    if not value:
        return bits(fmt, zero_sign, 0, 0)
    negative = value < 0
    value = abs(value)
    frac_bits, exp_bits, bias, sub, normal = layout(fmt)
    exponent = value.numerator.bit_length() - value.denominator.bit_length()
    if value < pow2(exponent):
        exponent -= 1
    elif value >= pow2(exponent + 1):
        exponent += 1
    sign = int(negative)
    if exponent < normal:
        fraction = round_magnitude(value / pow2(sub), mode, negative)
        max_fraction = 1 << frac_bits
        if fraction >= max_fraction:
            return bits(fmt, sign, 1, 0)
        return bits(fmt, sign, 0, fraction)
    fraction = round_magnitude(value / pow2(exponent - frac_bits), mode, negative)
    if fraction == 1 << (frac_bits + 1):
        fraction >>= 1
        exponent += 1
    if exponent > bias:
        to_inf = mode == "plain" or mode == "rp" and not negative or mode == "rm" and negative
        max_exp = (1 << exp_bits) - 1
        return bits(fmt, sign, max_exp, 0) if to_inf else bits(fmt, sign, max_exp - 1, (1 << frac_bits) - 1)
    return bits(fmt, sign, exponent + bias, fraction)


def selected(case, row):
    fmt = spec(case)["format"]
    a = row["a1" if spec(case)["h1"] else "a0"]
    return a, row["b0"] | row["b1"] << 16, fmt


def model(case, row):
    """Return candidate laws; observed data alone selects none of them."""
    a, b, fmt = selected(case, row)
    mode = spec(case)["rounding"]
    a_class, b_class = class_of(a, fmt), class_of(b, "f32")
    if ("nan" in (a_class, b_class) or
            a_class == b_class == "inf" and ((a >> 15) ^ (b >> 31))):
        return {"class": "nan"}
    if "inf" in (a_class, b_class):
        sign = a >> 15 if a_class == "inf" else b >> 31
        return {"class": "inf", "sign": sign}
    av, bv = exact(a, fmt), exact(b, "f32")
    zero_sign = int(mode == "rm")
    if av == -bv and av:
        zero_sign = int(mode == "rm")
    elif not av and not bv:
        sa, sb = a >> 15, b >> 31
        zero_sign = sa & sb if mode != "rm" else sa | sb
    total = av + bv
    return {"class": "finite", "wide": round_finite(total, "f32", mode, zero_sign),
            "narrow": round_finite(total, fmt, mode, zero_sign)}


def candidates(expected):
    if expected["class"] != "finite":
        return expected
    narrow = expected["narrow"]
    return {"wide": expected["wide"], "low_zero": narrow,
            "low_ones": narrow | 0xFFFF0000, "replicated": narrow | narrow << 16}


def b16_wide_model(case, row):
    """Rejected rival: treat only R4's low half as a narrow source."""
    options = spec(case)
    a = row["a1" if options["h1"] else "a0"]
    a_cls, b_cls = class_of(a, options["format"]), class_of(row["b0"], options["format"])
    if a_cls == b_cls == "finite":
        return round_finite(exact(a, options["format"]) + exact(row["b0"], options["format"]),
                            "f32", options["rounding"], int(options["rounding"] == "rm"))
    return None


def to_float(word, fmt):
    if fmt == "f16":
        return struct.unpack("<e", struct.pack("<H", word))[0]
    return struct.unpack("<f", struct.pack("<I", word << 16))[0]


def f32_bits(word):
    return struct.unpack("<f", struct.pack("<I", word))[0]


def self_test():
    assert len(CASES) == 16 and len(ALL_CASES) == 17
    for fmt in FORMATS:
        assert exact(one(fmt), fmt) == 1
        assert round_finite(Fraction(0), fmt, "rm", 1) == 0x8000
        assert class_of(values(fmt, True)[-1], fmt) == "nan"
        checked = 0
        for a in range(0x10000):
            if a & 0x3F != 0 or class_of(a, fmt) != "finite":
                continue
            row = {"a0": a, "b0": 0, "b1": 0}
            for word in (0, 0x3F800000, 0xBF800000, 0x3F800001, 1, 0x80000001):
                row.update(b0=word & 0xFFFF, b1=word >> 16)
                got = np.float32(to_float(a, fmt)) + np.float32(f32_bits(word))
                actual = int(np.frombuffer(np.float32(got).tobytes(), dtype="<u4")[0])
                assert actual == model(f"plain_{fmt}_h0", row)["wide"], (fmt, a, word)
                checked += 1
        assert checked > 1000
    assert round_finite(Fraction(1) + pow2(-11), "f16") == 0x3C00
    assert round_finite(Fraction(1) + pow2(-11), "f16", "rp") == 0x3C01
    assert round_finite(Fraction(1) + pow2(-24), "f32") == 0x3F800000
    print("CPU MODEL PASS: exact rational F16/BF16/F32 and NumPy wide-RNE cross-checks; "
          "16 core cases + one replay; candidate representations remain unselected")


if __name__ == "__main__":
    self_test()

using AtlasPca;
using Xunit;

namespace AtlasPca.Corpus.Tests;

/// <summary>The JS Number() emulation (verb floors, monitor state, NVIDIA measurement keys) against the spec's table: every form JS reads
/// as NaN must stay NaN (= refused), so a forged floor such as "+-Infinity" can never pass a relational compare.</summary>
public class JsNumberSweepTests
{
    public static readonly string[] MustBeNaN =
    {
        "+-Infinity", "-+Infinity", "+0x1", "-0x1", "0x+1", "0x-1", "0x1_0", "0x 1", "0x", "0b2", "0o8", "1_000",
        "١", "１", "infinity", "INFINITY", "nan", "NaN", "1e", ".", "+", "1f", "1d", "1L", "1\0", "\u00851", "᠎1",
    };

    public static readonly (string S, double V)[] MustParse =
    {
        ("", 0), ("   ", 0), ("﻿", 0), (" ", 0), (" 12 ", 12), ("﻿12 ", 12),
        ("Infinity", double.PositiveInfinity), ("+Infinity", double.PositiveInfinity), ("-Infinity", double.NegativeInfinity),
        ("0x10", 16), ("0X1f", 31), ("0o7", 7), ("0b1", 1), ("1.", 1), (".5", 0.5), ("1e3", 1000), ("+1.5", 1.5),
        ("0x" + new string('f', 300), double.PositiveInfinity),
    };

    [Fact]
    public void EveryFormJsReadsAsNaNIsNaN()
    {
        foreach (var s in MustBeNaN)
        {
            Assert.True(double.IsNaN(Actions.JsNumber(s, true)), $"JsNumber({s})");
            Assert.False(NvidiaVerifier.JsNumberFromString(s).Ok, $"JsNumberFromString({s})");
        }
    }

    [Fact]
    public void EveryFormJsParsesParses()
    {
        foreach (var (s, v) in MustParse)
        {
            Assert.Equal(v, Actions.JsNumber(s, true));
            Assert.Equal((v, true), NvidiaVerifier.JsNumberFromString(s));
        }
        Assert.True(double.IsNegative(Actions.JsNumber("-0", true)));
        Assert.Equal(0d, Actions.JsNumber("-0", true));
    }
}

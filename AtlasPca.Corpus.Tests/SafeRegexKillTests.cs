using AtlasPca;
using Xunit;

namespace AtlasPca.Corpus.Tests;

/// <summary>Mutation kills for SafeRegex.cs that the shared oracle does not discriminate: class-range normalisation, the hex-escape guard
/// (Convert.ToInt32 alone would accept a "0x" prefix), a NUL after a backslash / dash, the negated class escapes inside a class, the
/// NFA work stack for deeply nested optional groups, and the safe-source guard (null, a trailing "(", the group flags propagated to the
/// enclosing frame, escaped brackets inside a class).</summary>
public class SafeRegexKillTests
{
    static bool? M(string re, string s) => SafeRegex.FullMatch(re, s);

    [Fact]
    public void OverlappingClassRangesAreMergedBeforeTheBinarySearch()
    {
        // [1-100] [2] [4]: unmerged, the probe of 50 lands on [2,2] / [4,4] and misses [1,100]
        Assert.True(M("[\\x01-\\x64\\x02\\x04]", "2"));
        Assert.True(M("[a-zb-db]", "z"));
        Assert.True(M("[\\x01-\\x64\\x02\\x04\\x06\\x08]", "2"));
    }

    [Fact]
    public void HexEscapesAcceptOnlyHexDigits()
    {
        Assert.Null(SafeRegex.Compile("\\u0x1F"));   // Convert.ToInt32("0x1F", 16) alone would accept this
        Assert.Null(SafeRegex.Compile("\\u0X1F"));
        Assert.Null(SafeRegex.Compile("\\u00G1"));
        Assert.Null(SafeRegex.Compile("\\x0g"));
        Assert.Null(SafeRegex.Compile("\\u004"));
        Assert.Null(SafeRegex.Compile("\\x4"));
        foreach (var ok in new[] { "\\u0041", "\\u004A", "\\u004a", "\\u0030", "\\u0039", "\\u00FF", "\\u00ff", "\\x41", "\\x4F", "\\x4f", "\\x09", "\\xAF", "\\xaf", "\\xFa" })
            Assert.NotNull(SafeRegex.Compile(ok));
        // the characters just outside each hex range
        foreach (var bad in new[] { '/', ':', '@', 'G', '`', 'g' })
        {
            Assert.Null(SafeRegex.Compile("\\x4" + bad));
            Assert.Null(SafeRegex.Compile("\\x" + bad + "4"));
            Assert.Null(SafeRegex.Compile("\\u004" + bad));
            Assert.Null(SafeRegex.Compile("\\u" + bad + "041"));
        }
        Assert.True(M("\\u0041", "A")); Assert.True(M("\\x4A", "J")); Assert.True(M("\\xaF", "¯"));
    }

    [Fact]
    public void NulAfterABackslashAndInsideARange()
    {
        Assert.True(M("\\\0", "\0"));
        Assert.False(M("\\\0", "a"));
        Assert.Null(SafeRegex.Compile("[a-\0]")); // a range a..NUL is out of order, not a literal dash
        Assert.True(M("[\0-a]", "A"));
    }

    [Fact]
    public void NegatedClassEscapesInsideARangePositionAreLiteralOperands()
    {
        // [\D-z] is \D, '-', 'z' (not a range from -1 to 'z')
        Assert.False(M("[\\D-z]", "5"));
        Assert.True(M("[\\D-z]", "-")); Assert.True(M("[\\D-z]", "x"));
        Assert.False(M("[\\W-z]", "a"));
        Assert.True(M("[\\W-z]", "!")); Assert.True(M("[\\W-z]", "z"));
        Assert.False(M("[\\S-z]", " "));
        Assert.True(M("[\\S-z]", "a"));
        Assert.False(M("[a-\\D]", "5"));
    }

    [Fact]
    public void DeeplyNestedOptionalGroupsFitTheNfaWorkStack()
    {
        var re = new string('(', 40) + "a?" + string.Concat(Enumerable.Repeat(")?", 40));
        Assert.True(M(re, "a"));
        Assert.True(M(re, ""));
        Assert.False(M(re, "b"));
    }

    [Fact]
    public void SafeSourceGuardEdges()
    {
        Assert.False(SafeRegex.IsSafeSource(null));
        Assert.False(SafeRegex.IsSafeSource("("));
        Assert.False(SafeRegex.IsSafeSource("a("));
        Assert.False(SafeRegex.IsSafeSource("(?"));
        Assert.False(SafeRegex.IsSafeSource("(a"));
        // a group that holds a quantifier / an alternation is never itself quantified, however deeply it is nested
        Assert.False(SafeRegex.IsSafeSource("((a*))*"));
        Assert.False(SafeRegex.IsSafeSource("(a?(b?))*"));
        Assert.False(SafeRegex.IsSafeSource("(a?(b))*"));
        Assert.False(SafeRegex.IsSafeSource("((a|b))*"));
        Assert.False(SafeRegex.IsSafeSource("(a|(b|c))*"));
        Assert.False(SafeRegex.IsSafeSource("((a)|b)*"));
        Assert.True(SafeRegex.IsSafeSource("((a))*"));
        Assert.True(SafeRegex.IsSafeSource("(a(b))*"));
        // an escaped ']' does not end a class: the '*' inside is a literal, costing nothing
        Assert.True(SafeRegex.IsSafeSource("[\\]*]*[\\]*]*"));
        Assert.True(SafeRegex.IsSafeSource("[^\\]*]*[^\\]*]*"));
        Assert.False(SafeRegex.IsSafeSource("[\\]*"));
        Assert.False(SafeRegex.IsSafeSource("[a"));
        Assert.False(SafeRegex.IsSafeSource("[^"));
    }
}

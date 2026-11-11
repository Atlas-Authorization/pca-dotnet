using System.Numerics;
using AtlasPca;
using Org.BouncyCastle.Crypto.Parameters;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Direct tests of guards and helpers that the public entry points never reach with the failing input today (their callers
/// validate first): each is called directly with that input and its exact answer asserted, so no fail-closed branch is untested.</summary>
public class LedgerKillTests
{
    static readonly BigInteger P = BigInteger.Pow(2, 255) - 19;

    static byte[] Le32(BigInteger v, bool sign)
    {
        var b = new byte[32];
        var raw = v.ToByteArray(isUnsigned: true, isBigEndian: false);
        Array.Copy(raw, b, raw.Length);
        if (sign) b[31] |= 0x80;
        return b;
    }

    // ---- strict Ed25519 point validation ------------------------------------------------------------------------------
    [Fact]
    public void PrimeOrderPointsAreAccepted()
    {
        // the base point and its negation (sign bit set); public keys from fixed seeds (both sqrt branches)
        var by = BigInteger.Parse("46316835694926478169428394003475163141307993866256225615783033603165251855960");
        Assert.True(Pca.IsPrimeOrderPoint(Le32(by, false)));
        Assert.True(Pca.IsPrimeOrderPoint(Le32(by, true)));
        for (int k = 1; k <= 24; k++)
        {
            var seed = new byte[32]; seed[0] = (byte)k; seed[5] = (byte)(k * 7);
            Assert.True(Pca.IsPrimeOrderPoint(new Ed25519PrivateKeyParameters(seed, 0).GeneratePublicKey().GetEncoded()), $"seed {k}");
        }
    }

    [Fact]
    public void NonCanonicalSmallOrderAndOffCurveEncodingsAreRefused()
    {
        Assert.False(Pca.IsPrimeOrderPoint(Le32(P, false)));                  // y == p: non-canonical encoding of y = 0
        Assert.False(Pca.IsPrimeOrderPoint(Le32(P + 1, false)));              // non-canonical y = 1 (identity)
        Assert.False(Pca.IsPrimeOrderPoint(Le32(BigInteger.One, false)));     // identity
        Assert.False(Pca.IsPrimeOrderPoint(Le32(BigInteger.One, true)));      // identity with the sign bit: x = 0 cannot be negative
        Assert.False(Pca.IsPrimeOrderPoint(Le32(P - 1, false)));              // y = -1: order 2
        Assert.False(Pca.IsPrimeOrderPoint(Le32(BigInteger.Zero, false)));    // y = 0: order 4
        Assert.False(Pca.IsPrimeOrderPoint(Le32(new BigInteger(2), false)));  // y = 2: not on the curve
        var by = BigInteger.Parse("46316835694926478169428394003475163141307993866256225615783033603165251855960");
        Assert.False(Pca.IsPrimeOrderPoint(Le32(by, false)[..31]));           // wrong length
        Assert.False(Pca.IsPrimeOrderPoint(new byte[33]));
    }

    [Fact]
    public void StrictVerifyRefusesWrongLengthsWithoutThrowing()
    {
        var msg = new byte[] { 1, 2, 3 };
        foreach (var (pk, sig) in new[] { (31, 64), (33, 64), (32, 63), (32, 65), (0, 0), (31, 63) })
            Assert.False(Pca.VerifyEd25519Strict(new byte[pk], msg, new byte[sig]), $"{pk}/{sig}");
    }

    // ---- suite dispatch ------------------------------------------------------------------------------------------------
    [Fact]
    public void VerifySuiteRefusesAnUnresolvableSuite()
    {
        Assert.False(Pca.VerifySuite(new D { ["alg"] = "no-such-suite", ["sig"] = "AA" }, "AA", new byte[] { 1 }, null));
        Assert.False(Pca.VerifySuite(new D { ["alg"] = 5L, ["sig"] = "AA" }, "AA", new byte[] { 1 }, null));
    }

    [Fact]
    public void MalformedInputVerdictIsWireOnly()
    {
        var v = Pca.MalformedInput(new InvalidOperationException("x"));
        Assert.False(v.Allow);
        Assert.Equal("wire: malformed input (InvalidOperationException)", v.Reason);
        Assert.Single(v.Checks);
        Assert.False(v.Checks["wire"]);
        Assert.Empty(v.Reasons);
    }

    // ---- SafeRegex range sets ------------------------------------------------------------------------------------------
    static string Show(int[][] rs) => string.Join(",", rs.Select(r => $"{r[0]:x}-{r[1]:x}"));

    [Fact]
    public void NormalizeMergesAdjacentAndOverlappingRanges()
    {
        Assert.Equal("1-4", Show(SafeRegex.Normalize(new[] { new[] { 3, 4 }, new[] { 1, 2 } })));   // adjacent
        Assert.Equal("1-4", Show(SafeRegex.Normalize(new[] { new[] { 1, 2 }, new[] { 2, 4 } })));   // one shared code unit
        Assert.Equal("1-5", Show(SafeRegex.Normalize(new[] { new[] { 1, 5 }, new[] { 2, 3 } })));
        Assert.Equal("1-2,4-5", Show(SafeRegex.Normalize(new[] { new[] { 4, 5 }, new[] { 1, 2 } })));
    }

    [Fact]
    public void ComplementCoversExactlyTheGaps()
    {
        Assert.Equal("6-ffff", Show(SafeRegex.Complement(new[] { new[] { 0, 5 } })));
        Assert.Equal("ffff-ffff", Show(SafeRegex.Complement(new[] { new[] { 0, 0xfffe } })));
        Assert.Equal("", Show(SafeRegex.Complement(new[] { new[] { 0, 0xffff } })));
        Assert.Equal("0-2f,3a-ffff", Show(SafeRegex.Complement(new[] { new[] { 0x30, 0x39 } })));
        Assert.Equal("0-0,3-ffff", Show(SafeRegex.Complement(new[] { new[] { 1, 1 }, new[] { 2, 2 } })));
    }

    // ---- LESS verify seam ----------------------------------------------------------------------------------------------
    [Fact]
    public void LessVerifyChecksLengthsBeforeTheNativeCall()
    {
        int calls = 0;
        LessNative.VerifyFn yes = (a, b, c, d, e, f) => { calls++; return c.Length == (int)d ? 1 : 0; };
        LessNative.VerifyFn boom = (a, b, c, d, e, f) => throw new InvalidOperationException();
        var pk = new byte[LessNative.PublicKeyBytes]; var sig = new byte[LessNative.SignatureMinBytes];
        Assert.True(LessNative.VerifyWith(yes, pk, Array.Empty<byte>(), sig));   // an empty message is passed as is
        Assert.True(LessNative.VerifyWith(yes, pk, new byte[] { 7 }, sig));
        Assert.Equal(2, calls);
        Assert.False(LessNative.VerifyWith(yes, new byte[LessNative.PublicKeyBytes - 1], new byte[] { 7 }, sig));
        Assert.False(LessNative.VerifyWith(yes, new byte[LessNative.PublicKeyBytes + 1], new byte[] { 7 }, sig));
        Assert.False(LessNative.VerifyWith(yes, pk, new byte[] { 7 }, new byte[LessNative.SignatureMinBytes + 1]));
        Assert.False(LessNative.VerifyWith(yes, pk, new byte[] { 7 }, new byte[LessNative.SignatureMaxBytes + 16]));
        Assert.Equal(2, calls);
        Assert.False(LessNative.VerifyWith(null, pk, new byte[] { 7 }, sig));
        Assert.False(LessNative.VerifyWith(boom, pk, new byte[] { 7 }, sig));
    }

    // ---- intent v2 context guards --------------------------------------------------------------------------------------
    [Fact]
    public void IntentV2ContextGuardsAnswerExactly()
    {
        Assert.Equal("the session context must be an object", IntentV2.SessionCtxError(IntentV2Context.FromJsonText("{\"session\":5}")));
        Assert.Null(IntentV2.SessionCtxError(IntentV2Context.FromJsonText("{\"session\":{}}")));
        Assert.Equal("the accumulator context must be an object", IntentV2.AccCtxError(IntentV2Context.FromJsonText("{\"acc\":[]}")));
        Assert.Null(IntentV2.AccCtxError(IntentV2Context.FromJsonText("{\"acc\":{}}")));
        foreach (var bad in new[] { "-1", "1.5", "\"5\"" })
            Assert.Equal("session policy misconfigured: max_revocation_age_s must be a non-negative safe integer (fail closed)",
                IntentV2.SessionStep(new D(), new D(), IntentV2Context.FromJsonText("{\"policy\":{\"session\":{\"max_revocation_age_s\":" + bad + "}}}"), 0));
        Assert.Equal("this verifier requires an intent_session but the PCActn carries none",
            IntentV2.SessionStep(new D(), new D(), IntentV2Context.FromJsonText("{\"policy\":{\"session\":{\"max_revocation_age_s\":0}}}"), 0));
    }

    // ---- closed key sets -----------------------------------------------------------------------------------------------
    [Fact]
    public void KeySetHelpersNeedEveryNamedKey()
    {
        foreach (var f in new Func<object?, string[], bool>[] { IntentSession.KeysAre, ActionSchema.ExactKeys })
        {
            Assert.True(f(new D { ["a"] = 1L, ["b"] = 2L }, new[] { "a", "b" }));
            Assert.False(f(new D { ["a"] = 1L, ["c"] = 2L }, new[] { "a", "b" }));
            Assert.False(f(new D { ["c"] = 1L, ["b"] = 2L }, new[] { "a", "b" }));
            Assert.False(f(new D { ["a"] = 1L }, new[] { "a", "b" }));
            Assert.False(f(new D { ["a"] = 1L, ["b"] = 2L, ["c"] = 3L }, new[] { "a", "b" }));
            Assert.False(f("ab", new[] { "a", "b" }));
        }
    }

    sealed class NullText { public override string? ToString() => null; }
    sealed class SomeText { public override string ToString() => "some"; }

    [Fact]
    public void JsTextOfAnOpaqueValueIsItsToStringOrEmpty()
    {
        Assert.Equal("", IntentRevocation.JsText(new NullText(), true));
        Assert.Equal("some", IntentRevocation.JsText(new SomeText(), true));
        Assert.Equal("undefined", IntentRevocation.JsText(new SomeText(), false));
    }

    // ---- oracle facts subject resolution -------------------------------------------------------------------------------
    [Fact]
    public void SubjectResolutionThrowsOnAMissingAction()
    {
        Assert.Equal("cannot read 'resource' of null", Assert.Throws<ArgumentException>(() => OracleFacts.Prop(null, "resource")).Message);
        Assert.Equal("r", OracleFacts.Prop(new D { ["resource"] = "r" }, "resource"));
        Assert.Equal("cannot read 'resource' of null", Assert.Throws<ArgumentException>(() => OracleFacts.SubjectOf(null, "action.resource")).Message);
        Assert.Equal("cannot read 'verb' of null", Assert.Throws<ArgumentException>(() => OracleFacts.SubjectOf(null, "action.verb")).Message);
        Assert.Equal("no action", Assert.Throws<ArgumentException>(() => OracleFacts.SubjectOf(null, "action.params.to")).Message);
        Assert.Equal("a@b", OracleFacts.SubjectOf(new D { ["params"] = new D { ["to"] = "a@b" } }, "action.params.to"));
        Assert.Equal("no action", Assert.Throws<ArgumentException>(() => OracleFacts.ActionParamsOf(new D())).Message);
        Assert.Equal("no action", Assert.Throws<ArgumentException>(() => OracleFacts.ActionParamsOf(new D { ["action"] = null })).Message);
        Assert.Empty(OracleFacts.ActionParamsOf(new D { ["action"] = new D() }));
    }
}

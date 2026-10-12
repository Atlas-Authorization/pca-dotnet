using AtlasPca;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>R6-05 totality of every public verifier entry point (a hostile or null input is a clean deny, never an exception)
/// and the JSON depth cap (MAX_JSON_DEPTH = 32, TS counting: the outermost container is depth 1) at limit-1 / limit / limit+1
/// and far beyond, on every path that walks untrusted JSON. Deep cases run on a small stack so unbounded recursion would kill
/// the test host instead of passing by luck. Category=Huge tests are excluded from Stryker runs (stryker-config.json test-case-filter): a
/// mutant that removes a depth cap overflows the stack on them and kills the shared VsTest host; the 31/32/33 boundary tests kill
/// those mutants without deep recursion.</summary>
public class TotalityDepthTests
{
    static void OnSmallStack(Action a)
    {
        Exception? err = null;
        var t = new Thread(() => { try { a(); } catch (Exception e) { err = e; } }, 256 * 1024);
        t.Start(); t.Join();
        if (err != null) throw new Xunit.Sdk.XunitException("threw on a small stack: " + err);
    }

    static object? NestArrays(int n, object? inner) { for (int i = 0; i < n; i++) inner = new L { inner }; return inner; }
    static object? NestObjects(int n, object? inner) { for (int i = 0; i < n; i++) inner = new D { ["k"] = inner }; return inner; }

    // ------------------------------------------------------------------ R6-05: null / ill-typed input never throws
    [Fact]
    public void VerifyRaw_NullText_IsAWireDeny()
    {
        var v = Pca.VerifyRaw(null!, new D(), 0, "a");
        Assert.False(v.Allow);
        Assert.False(v.Checks["wire"]);
    }

    [Fact]
    public void VerifyRaw_NullGrantAndAudience_IsADeny()
    {
        var v = Pca.VerifyRaw("{}", null!, 0, null!);
        Assert.False(v.Allow);
    }

    [Fact]
    public void SignerSetHashB64u_Null_IsNull() => Assert.Null(Pca.SignerSetHashB64u(null!));

    [Fact]
    public void VerifyEntryPoints_NullsAreDenies()
    {
        Assert.False(Pca.VerifyChain(null!, null, true).Ok);
        Assert.False(Pca.VerifyChain(new L { null }, null, false).Ok);
        Assert.False(Pca.VerifyThresholdShare((object?)null));
        Assert.False(Pca.VerifyThresholdShare((D)null!));
        Assert.False(Pca.VerifyPcactnCore(null, null!, 0, null!).Allow);
        Assert.False(Pca.VerifyInclusion(null!, null, null));
        Assert.False(Pca.VerifySuiteSig(null, null, null, null!, null, null));
        Assert.False(Pca.VerifySuiteSig("ml-dsa-65", null, "x", null!, "y", null));
        Assert.NotNull(Pca.ValidateWire(null));
    }

    // ------------------------------------------------------------------ depth: canonicalize (programmatic trees)
    [Theory]
    [InlineData(31, true)]
    [InlineData(32, true)]
    [InlineData(33, false)]
    public void Canonicalize_DepthBoundary(int n, bool ok)
    {
        foreach (var tree in new[] { NestArrays(n, new Num("1")), NestObjects(n, new Num("1")) })
        {
            if (ok) Assert.NotNull(Pca.Canonicalize(tree));
            else Assert.Equal("canonicalize: nesting too deep", Assert.Throws<InvalidOperationException>(() => Pca.Canonicalize(tree)).Message);
        }
    }

    [Fact, Trait("Category", "Huge")]
    public void Canonicalize_100k_RefusedWithoutRecursing() => OnSmallStack(() =>
    {
        Assert.Throws<InvalidOperationException>(() => Pca.Canonicalize(NestArrays(100_000, null)));
        Assert.Throws<InvalidOperationException>(() => Pca.HashCanonical(NestObjects(100_000, null)));
    });

    // ------------------------------------------------------------------ depth: strict parser and the R6-01 envelope
    [Theory]
    [InlineData(31, true)]
    [InlineData(32, true)]
    [InlineData(33, false)]
    public void ParseStrict_DepthBoundary(int n, bool ok)
    {
        var arr = new string('[', n) + new string(']', n);
        var obj = string.Concat(Enumerable.Repeat("{\"a\":", n)) + "1" + new string('}', n);
        foreach (var s in new[] { arr, obj })
        {
            if (ok) Pca.ParseStrict(s);
            else Assert.StartsWith("strict JSON: nesting too deep", Assert.Throws<StrictJsonException>(() => Pca.ParseStrict(s)).Message);
        }
    }

    [Theory]
    [InlineData(31, true)]
    [InlineData(32, true)]
    [InlineData(33, false)]
    public void ParseStrictEnvelope_CountsTheEnvelope(int total, bool ok)
    {
        // TS parity (require-pca.ts defaultExtract strictParse of the whole body): the envelope object is depth 1
        var s = "{\"pcactn\":" + new string('[', total - 1) + new string(']', total - 1) + "}";
        if (ok) Assert.NotNull(Pca.ParseStrictEnvelope(s));
        else Assert.StartsWith("strict JSON: nesting too deep", Assert.Throws<StrictJsonException>(() => Pca.ParseStrictEnvelope(s)).Message);
        Assert.StartsWith("strict JSON: duplicate key", Assert.Throws<StrictJsonException>(() => Pca.ParseStrictEnvelope("{\"pcactn\":{\"a\":[{\"b\":1,\"b\":2}]}}")).Message);
    }

    [Fact, Trait("Category", "Huge")]
    public void Parsers_100k_RefusedWithoutRecursing() => OnSmallStack(() =>
    {
        foreach (var s in new[] { new string('[', 100_000) + new string(']', 100_000), new string('[', 100_000) })
        {
            Assert.Throws<StrictJsonException>(() => Pca.ParseStrict(s));
            Assert.Throws<StrictJsonException>(() => Pca.ParseStrictEnvelope("{\"pcactn\":" + s + "}"));
            Assert.Throws<StrictJsonException>(() => Pca.ParseJson(s));
        }
        var v = Pca.VerifyRaw("{\"x\":" + new string('[', 100_000) + "}", new D(), 0, "a");
        Assert.False(v.Allow);
    });

    // ------------------------------------------------------------------ depth: host-built (already parsed) trees on the verify APIs
    [Fact, Trait("Category", "Huge")]
    public void VerifyChain_DeepCaveatValue_IsADenyNotACrash() => OnSmallStack(() =>
    {
        foreach (var n in new[] { 31, 32, 33, 100_000 })
        {
            var hop = new D
            {
                ["id"] = "x", ["issuer"] = "x", ["holder"] = "y", ["body_digest"] = "x", ["sig"] = "s",
                ["caveats"] = new L { new D { ["type"] = "t", ["v"] = NestArrays(n, null) } },
            };
            Assert.False(Pca.VerifyChain(new L { hop }, "x", true).Ok);
        }
    });

    [Fact, Trait("Category", "Huge")]
    public void VerifyThresholdShare_DeepEntry_IsADenyNotACrash() => OnSmallStack(() =>
    {
        foreach (var n in new[] { 31, 32, 33, 100_000 })
        {
            Assert.False(Pca.VerifyThresholdShare(NestObjects(n, null)));
            var e = new D { ["role"] = "agent", ["t"] = new Num("1"), ["threshold_message"] = "AAAA", ["signer_set"] = new L { new D { ["role"] = "agent", ["publicKey"] = NestArrays(n, null) } }, ["share"] = NestObjects(n, null) };
            Assert.False(Pca.VerifyThresholdShare(e));
            // a non-string pq_pk is not part of the hash input (the set is refused by ValidateSignerSet); no exception either way
            Pca.SignerSetHashB64u(new L { new D { ["role"] = "agent", ["publicKey"] = "k", ["pq_pk"] = NestArrays(n, null) } });
        }
    });

    [Fact, Trait("Category", "Huge")]
    public void VerifyPcactnCore_DeepTree_IsADenyNotACrash() => OnSmallStack(() =>
    {
        foreach (var n in new[] { 33, 100_000 })
        {
            var p = new D { ["risk_claim"] = new D { ["inputs"] = new D { ["x"] = NestArrays(n, null) } } };
            Assert.False(Pca.VerifyPcactnCore(p, new D { ["deep"] = NestArrays(n, null) }, 0, "a").Allow);
            Assert.NotNull(Pca.ValidateWire(p));
        }
    });
}

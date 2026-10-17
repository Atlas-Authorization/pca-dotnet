using AtlasPca;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>PCA 0.4.1: per-suite threshold-share wire validation, the policy-layer root-caveat helpers
/// (<see cref="Caveats.PolicyCaveats"/> / <see cref="Caveats.EvaluateCaveats"/>, incl. <c>max_spend</c>) and the strict
/// <c>PCA-Action</c> header decoder (<see cref="Pca.DecodePcaHeader"/>).</summary>
public class R041Tests
{
    static D M(params (string, object?)[] kv) { var d = new D(); foreach (var (k, v) in kv) d[k] = v; return d; }
    static L Li(params object?[] v) => new L(v);
    static Num N(string s) => new Num(s);
    static string B(int n) => Pca.B64u(new byte[n]);

    // ---- Fix 2: share signature per suite ----------------------------------------------------------------

    static D Share(params (string, object?)[] extra)
    {
        var s = M(("role", "guardian"), ("publicKey", B(32)));
        foreach (var (k, v) in extra) s[k] = v;
        return s;
    }
    static string? Sw(D s) => Pca.ValidateShareSignatureWire(s);

    [Fact]
    public void ShareWireAcceptsEachImplementedSuite()
    {
        Assert.Null(Sw(Share(("sig", B(64)))));
        Assert.Null(Sw(Share(("alg", "ed25519"), ("sig", B(64)))));
        Assert.Null(Sw(Share(("alg", "ml-dsa-65"), ("sig", B(3309)))));
        Assert.Null(Sw(Share(("alg", "hybrid-ed25519-ml-dsa-65"), ("sig", B(64)), ("pq_sig", B(3309)))));
        Assert.Null(Sw(Share(("alg", "ml-dsa-65"), ("sig", B(3309)), ("pq_pk", "junk")))); // pq_pk: judged by the threshold check
        Assert.Null(Sw(Share(("sig", B(64)), ("pq_pk", B(1952)))));
    }

    [Fact]
    public void ShareWireRefusesWrongLengthsAndFields()
    {
        Assert.Equal("'sig' is not canonical base64url (64 bytes) for alg 'ed25519'", Sw(Share(("sig", B(3309)))));
        Assert.NotNull(Sw(Share(("alg", "ed25519"), ("sig", B(3309)))));
        Assert.Equal("'sig' is not canonical base64url (3309 bytes) for alg 'ml-dsa-65'", Sw(Share(("alg", "ml-dsa-65"), ("sig", B(3308)))));
        Assert.NotNull(Sw(Share(("alg", "ml-dsa-65"), ("sig", B(3310)))));
        Assert.NotNull(Sw(Share(("alg", "ml-dsa-65"), ("sig", B(64)))));
        Assert.Equal("'pq_sig' is not canonical base64url (3309 bytes) for alg 'hybrid-ed25519-ml-dsa-65'",
            Sw(Share(("alg", "hybrid-ed25519-ml-dsa-65"), ("sig", B(64)))));
        Assert.NotNull(Sw(Share(("alg", "hybrid-ed25519-ml-dsa-65"), ("sig", B(64)), ("pq_sig", B(3308)))));
        Assert.NotNull(Sw(Share(("alg", "hybrid-ed25519-ml-dsa-65"), ("sig", B(3309)), ("pq_sig", B(3309)))));
        Assert.Equal("'pq_sig' must be absent for alg 'ed25519'", Sw(Share(("sig", B(64)), ("pq_sig", B(3309)))));
        Assert.Equal("'pq_sig' must be absent for alg 'ml-dsa-65'", Sw(Share(("alg", "ml-dsa-65"), ("sig", B(3309)), ("pq_sig", B(3309)))));
        Assert.Equal("'pq_sig' must be absent for alg 'ed25519'", Sw(Share(("sig", B(64)), ("pq_sig", null))));
        Assert.Null(Sw(Share(("alg", "ml-dsa-87"), ("sig", B(4627)))));
        Assert.Equal("unsupported_suite: fn-dsa-512", Sw(Share(("alg", "fn-dsa-512"), ("sig", B(666)))));
        Assert.Equal("unknown signature alg 'ml-dsa-99'", Sw(Share(("alg", "ml-dsa-99"), ("sig", B(4627)))));
        Assert.Equal("'alg' must be a string", Sw(Share(("alg", N("1")), ("sig", B(64)))));
        Assert.Equal("'alg' must be a string", Sw(Share(("alg", null), ("sig", B(64)))));
        Assert.NotNull(Sw(Share(("alg", "ml-dsa-65"), ("sig", B(3309) + "="))));
        Assert.NotNull(Sw(Share()));
    }

    // ---- Fix 1: policy caveats ---------------------------------------------------------------------------

    static D Ctx(object? amount) => M(("now", N("1800000000000")),
        ("action", M(("verb", "pay"), ("resource", "invoice:42"), ("reversibility_class", "reversible"), ("params", M(("amount", amount))))));
    static D Params(D c) => (D)((D)c["action"]!)["params"]!;
    static Caveats.Result Ev(object? caveats, object? c) => Caveats.EvaluateCaveats(caveats, c);

    [Fact]
    public void MaxSpend()
    {
        var cv = Li(M(("type", "max_spend"), ("usd", N("100"))));
        Assert.True(Ev(cv, Ctx(N("100"))).Ok);
        Assert.True(Ev(cv, Ctx(N("99.5"))).Ok);
        Assert.True(Ev(cv, Ctx(N("0"))).Ok);
        Assert.False(Ev(cv, Ctx(N("150"))).Ok);
        Assert.Equal(new[] { "max_spend" }, Ev(cv, Ctx(N("150"))).Failed);
        foreach (var bad in new object?[] { N("-1"), "100", true, null, N("1e400") }) Assert.False(Ev(cv, Ctx(bad)).Ok, $"{bad}");
        Assert.True(Ev(Li(M(("type", "max_spend"), ("usd", 100))), Ctx(42L)).Ok);
        Assert.True(Ev(Li(M(("type", "max_spend"), ("usd", 100.5m))), Ctx(100.25d)).Ok);
        Assert.False(Ev(Li(M(("type", "max_spend"), ("usd", 100))), Ctx(double.NaN)).Ok);
        Assert.False(Ev(Li(M(("type", "max_spend"), ("usd", "100"))), Ctx(N("1"))).Ok);
        Assert.False(Ev(Li(M(("type", "max_spend"), ("usd", N("-1")))), Ctx(N("0"))).Ok);
        Assert.False(Ev(Li(M(("type", "max_spend"))), Ctx(N("0"))).Ok);
        Assert.False(Ev(Li(M(("type", "max_spend"), ("usd", N("1e400")))), Ctx(N("1"))).Ok);
        var noNow = Ctx(N("5")); noNow.Remove("now");
        Assert.True(Ev(cv, noNow).Ok); // max_spend does not need `now`
    }

    [Fact]
    public void MaxSpendCurrencyAndShape()
    {
        var cv = Li(M(("type", "max_spend"), ("usd", N("100"))));
        foreach (var cur in new object?[] { "usd", "USD" }) { var c = Ctx(N("5")); Params(c)["currency"] = cur; Assert.True(Ev(cv, c).Ok, $"{cur}"); }
        foreach (var cur in new object?[] { "eur", "Usd", null, N("1"), Li("usd") }) { var c = Ctx(N("5")); Params(c)["currency"] = cur; Assert.False(Ev(cv, c).Ok, $"{cur}"); }
        var x = Ctx(N("5"));
        var act = (D)x["action"]!;
        act["params"] = Li(N("5")); Assert.False(Ev(cv, x).Ok);
        act.Remove("params"); Assert.False(Ev(cv, x).Ok);
        act["params"] = M(); Assert.False(Ev(cv, x).Ok);
        x["action"] = "pay"; Assert.False(Ev(cv, x).Ok);
        x.Remove("action"); Assert.False(Ev(cv, x).Ok);
    }

    [Fact]
    public void TimeAndContextCaveats()
    {
        var c = M(("now", N("1000")), ("delegation_depth", N("2")), ("blast_radius", N("5")), ("reversibility_class", "rate_limited"),
            ("recent_action_times", Li(N("1000"), N("500"), N("0"), "x", N("1001"))));
        Assert.True(Ev(Li(M(("type", "expires"), ("at", N("1001")))), c).Ok);
        Assert.False(Ev(Li(M(("type", "expires"), ("at", N("1000")))), c).Ok);
        Assert.True(Ev(Li(M(("type", "not_before"), ("at", N("1000")))), c).Ok);
        Assert.False(Ev(Li(M(("type", "not_before"), ("at", N("1001")))), c).Ok);
        Assert.False(Ev(Li(M(("type", "not_before"), ("at", "0"))), c).Ok);
        // rate: window (now - 1000, now] = (0, 1000], so 1000 and 500 count; 0, "x" and 1001 do not
        Assert.True(Ev(Li(M(("type", "rate"), ("max", N("3")), ("per_secs", N("1")))), c).Ok);
        Assert.False(Ev(Li(M(("type", "rate"), ("max", N("2")), ("per_secs", N("1")))), c).Ok);
        Assert.False(Ev(Li(M(("type", "rate"), ("max", N("3")), ("per_secs", N("0")))), c).Ok);
        Assert.True(Ev(Li(M(("type", "max_blast_radius"), ("max", N("5")))), c).Ok);
        Assert.False(Ev(Li(M(("type", "max_blast_radius"), ("max", N("4")))), c).Ok);
        Assert.True(Ev(Li(M(("type", "reversibility_max"), ("class", "rate_limited"))), c).Ok);
        Assert.True(Ev(Li(M(("type", "reversibility_max"), ("class", "irreversible"))), c).Ok);
        Assert.False(Ev(Li(M(("type", "reversibility_max"), ("class", "reversible"))), c).Ok);
        Assert.False(Ev(Li(M(("type", "reversibility_max"), ("class", Li("irreversible")))), c).Ok);
        Assert.True(Ev(Li(M(("type", "delegation_depth"), ("max", N("2")))), c).Ok);
        Assert.False(Ev(Li(M(("type", "delegation_depth"), ("max", N("1")))), c).Ok);
        Assert.True(Ev(Li(M(("type", "budget_alloc"), ("limit", N("0")))), c).Ok);
        Assert.False(Ev(Li(M(("type", "budget_alloc"), ("limit", N("-1")))), c).Ok);
        foreach (var t in new[] { "note", "envelope", "resource_prefix", "predicates", "tool_schema", "nope" }) Assert.False(Ev(Li(M(("type", t))), c).Ok, t);
        var bare = M(("now", N("1000")));
        foreach (var cv in new[] { M(("type", "rate"), ("max", N("3")), ("per_secs", N("1"))), M(("type", "max_blast_radius"), ("max", N("5"))),
                     M(("type", "reversibility_max"), ("class", "irreversible")), M(("type", "delegation_depth"), ("max", N("9"))) })
            Assert.False(Ev(Li(cv), bare).Ok);
        Assert.False(Ev(Li(M(("type", "budget_alloc"), ("limit", N("1")))), M()).Ok);
        Assert.False(Ev(Li(M(("type", "expires"), ("at", N("1")))), M(("now", "1000"))).Ok);
    }

    [Fact]
    public void EvaluateIsTotalAndOrdered()
    {
        var r = Ev("nope", M());
        Assert.False(r.Ok);
        Assert.Equal(new[] { "<malformed caveats>" }, r.Failed);
        Assert.Equal(new[] { "<malformed caveats>" }, Ev(null, M()).Failed);
        r = Ev(Li(M(("type", "note")), "x", M(("type", N("1"))), M(("type", "budget_alloc"), ("limit", N("1"))), M(("type", "expires"), ("at", N("0")))),
            M(("now", N("5"))));
        Assert.False(r.Ok);
        Assert.Equal(new[] { "note", "<malformed>", "<malformed>", "expires" }, r.Failed);
        r = Ev(Li(), null);
        Assert.True(r.Ok);
        Assert.Empty(r.Failed);
        Assert.False(Ev(Li(M(("type", "budget_alloc"), ("limit", N("1")))), "ctx").Ok);
    }

    [Fact]
    public void PolicyCaveatsDropsFirstEnvelopeAndAppendsHopCaveats()
    {
        var env = M(("type", "envelope"), ("x", N("1")));
        var env2 = M(("type", "envelope"), ("x", N("2")));
        var spend = M(("type", "max_spend"), ("usd", N("10")));
        var grant = M(("caveats", Li(spend, env, env2)));
        Assert.Equal(Li(spend, env2), (L)Caveats.PolicyCaveats(grant, null)!);
        Assert.Equal(Li(spend, env2), (L)Caveats.RootCaveats(grant)!);
        var hopCv = M(("type", "expires"), ("at", N("9")));
        var leaf = M(("caveats", Li(spend, env, env2, hopCv)));
        Assert.Equal(Li(spend, env2, hopCv), (L)Caveats.PolicyCaveats(grant, Li(grant, leaf))!);
        Assert.Equal(Li(spend, env2), (L)Caveats.PolicyCaveats(grant, Li())!);
        Assert.Equal(Li(spend, env2), (L)Caveats.PolicyCaveats(grant, "chain")!);
        Assert.Equal(Li(spend, env2), (L)Caveats.PolicyCaveats(grant, Li(M(("caveats", "x"))))!);
        Assert.Equal(Li(spend, env2), (L)Caveats.PolicyCaveats(grant, Li("leaf"))!);
        Assert.Equal(Li(spend, env2), (L)Caveats.PolicyCaveats(grant, Li(M(("caveats", Li()))))!);
        Assert.Equal("x", Caveats.PolicyCaveats(M(("caveats", "x")), Li(leaf)));
        Assert.Null(Caveats.PolicyCaveats("grant", null));
        Assert.Equal(new[] { "<malformed caveats>" }, Caveats.EvaluateCaveats(Caveats.PolicyCaveats(M(), null), M()).Failed);
        Assert.Equal(3, ((L)grant["caveats"]!).Count); // the input is not mutated
    }

    // ---- Fix 3: strict PCA-Action header ------------------------------------------------------------------

    [Fact]
    public void DecodePcaHeaderStrict()
    {
        Assert.Equal("{\"a\":1}", Pca.DecodePcaHeader("eyJhIjoxfQ"));
        Assert.Equal("﻿{}", Pca.DecodePcaHeader("77u_e30")); // BOM kept
        Assert.Equal("\"é😀\"", Pca.DecodePcaHeader("IsOp8J-YgCI"));
        foreach (var bad in new[] { "", "eyJhIjoxfQ==", "Ij8/PyI", "In5+fj4i", " e30", "e30 ", "e30\t", "eyJh IjoxfQ", "eyJhIjox\nfQ",
                     "eyJhIjox*fQ", "eyJhI", "QR", "QUJ", "__57", "IsCvIg", "Iu2ggCI", "IuKC" })
            Assert.Null(Pca.DecodePcaHeader(bad));
        Assert.Null(Pca.DecodePcaHeader(null));
    }

    // ---- the corpus sections (the Conformance runner runs them too) ----------------------------------------

    [Fact]
    public void CorpusCaveatEval()
    {
        var prim = (D)Snapshot.Core()["primitives"]!;
        int ran = 0;
        foreach (var x in (L)prim["caveat_eval"]!)
        {
            var e = (D)x!;
            var exp = (D)e["expect"]!;
            var r = Caveats.EvaluateCaveats(Caveats.PolicyCaveats(e.GetValueOrDefault("grant"), e.GetValueOrDefault("chain")), e.GetValueOrDefault("context"));
            Assert.True((bool)exp["allow"]! == r.Ok, $"{e["name"]} allow={r.Ok}");
            Assert.Equal(((L)exp["failed"]!).Cast<string>().ToArray(), r.Failed.ToArray());
            ran++;
        }
        Assert.True(ran >= 40, $"caveat_eval ran {ran}");
    }

    [Fact]
    public void CorpusPcaHeader()
    {
        var prim = (D)Snapshot.Core()["primitives"]!;
        int ran = 0;
        foreach (var x in (L)prim["pca_header"]!)
        {
            var e = (D)x!;
            var got = Pca.DecodePcaHeader((string)e["input"]!);
            Assert.True((got != null) == (bool)e["valid"]!, $"{e["name"]}");
            if (got != null) Assert.Equal((string)e["text"]!, got);
            ran++;
        }
        Assert.True(ran >= 27, $"pca_header ran {ran}");
    }
}

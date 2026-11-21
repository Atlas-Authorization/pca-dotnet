using AtlasPca;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>base differential oracle of offline Sigstore bundle verification (test-data/base-sigstore.json.gz, TS reference
/// packages/pca-attest-eat/src/sigstore.ts). Every trusted root is a parseTrustedRoot case; other cases name one as {"$root": id}
/// (parsed here from the same JSON). fn names ending in @suspect are reported, never failed.</summary>
public class BaseSigstoreDiffTests
{
    const string M = "sigstore";

    /// <summary>One root-resolver per test (no process-wide state derived from the code under test): the {$root} reference names a
    /// pinned-roots set; a root that does not parse is a refusal (the reference throws too).</summary>
    static Func<object?, SigstorePinnedRoots> NewRoots()
    {
        var json = new Dictionary<string, object?>();
        foreach (var c in Base.Of(M, "parseTrustedRoot")) json.TryAdd(((string)c["name"]!)["parseTrustedRoot/".Length..], Base.Args(c)[0]);
        var parsed = new Dictionary<string, SigstorePinnedRoots>();
        return r =>
        {
            var id = (string)((D)r!)["$root"]!;
            lock (parsed)
            {
                if (!parsed.TryGetValue(id, out var p)) parsed[id] = p = Sigstore.ParseTrustedRoot(json[id]);
                return p;
            }
        };
    }

    static D Summary(SigstorePinnedRoots r)
    {
        object? End(long e) => e == long.MaxValue ? null : (object?)e;
        object? Lg(SigstorePinnedLog l) => new D { ["keyId"] = Convert.ToBase64String(l.KeyId), ["start"] = l.Start, ["end"] = End(l.End), ["v2"] = l.V2Name };
        object? Ca(SigstorePinnedCa c) => new D { ["chain"] = (long)c.Chain.Count, ["start"] = c.Start, ["end"] = End(c.End) };
        return new D { ["tlogs"] = r.Tlogs.Select(Lg).ToList(), ["ctlogs"] = r.Ctlogs.Select(Lg).ToList(), ["cas"] = r.Cas.Select(Ca).ToList(), ["tsas"] = r.Tsas.Select(Ca).ToList() };
    }

    [Fact] public void ParseTrustedRoot() => Base.Check(M, "parseTrustedRoot", a => Summary(Sigstore.ParseTrustedRoot(a[0])));

    [Fact]
    public void VerifyBundleCore()
    {
        var roots = NewRoots();
        Base.Check(M, "verifySigstoreBundleCore", a =>
        {
            var r = Sigstore.VerifySigstoreBundleCore(a[0], roots(a[1]));
            return r.Ok ? new D { ["ok"] = true, ["core"] = r.Core } : new D { ["ok"] = false, ["code"] = r.Code };
        }, eq: NoDetail, min: 5000);
    }

    [Fact]
    public void VerifyBundle()
    {
        var roots = NewRoots();
        Base.Check(M, "verifySigstoreBundle", a =>
        {
            var r = Sigstore.VerifySigstoreBundle(a[0], roots(a[1]));
            return r.Ok ? new D { ["ok"] = true, ["facts"] = r.Facts } : new D { ["ok"] = false, ["code"] = r.Code };
        }, eq: NoDetail);
    }

    // ok and the exact core / facts, or the exact refusal code. The detail is informative only: the reference's details embed JavaScript
    // and OpenSSL runtime messages ("fail closed: Unexpected token ...", "error:0480006C:PEM routines::no start line").
    static bool NoDetail(D c, object? h) => Base.Show(c["out"] is D o && o.ContainsKey("detail") ? o.Where(e => e.Key != "detail").ToDictionary(e => e.Key, e => e.Value) : c["out"]) == Base.Show(Base.Json(h));

    [Fact]
    public void VerifyRfc3161()
    {
        var roots = NewRoots();
        Base.Check(M, "verifyRfc3161", a =>
            Sigstore.VerifyRfc3161(Convert.FromBase64String((string)a[0]!), Convert.FromBase64String((string)a[1]!), roots(a[2]).Tsas));
    }

    [Fact] public void DssePae() => Base.Check(M, "dssePae", a => Sigstore.DssePae((string)a[0]!, Convert.FromBase64String((string)a[1]!)));

    [Fact]
    public void EveryFn() { Base.Covers(M, new[] { "parseTrustedRoot", "verifySigstoreBundleCore", "verifySigstoreBundle", "verifyRfc3161", "dssePae" }); Assert.Equal(7002, Base.Total(M)); }
}

using AtlasPca;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>k05 differential oracle of offline Sigstore bundle verification (test-data/k05-sigstore.json.gz, TS reference
/// packages/pca-attest-eat/src/sigstore.ts). Every trusted root is a parseTrustedRoot case; other cases name one as {"$root": id}
/// (parsed here from the same JSON). fn names ending in @suspect are reported, never failed.</summary>
public class K05SigstoreDiffTests
{
    const string M = "sigstore";

    static readonly Lazy<Dictionary<string, object?>> RootJson = new(() =>
    {
        var m = new Dictionary<string, object?>();
        foreach (var c in K05.Of(M, "parseTrustedRoot")) m.TryAdd(((string)c["name"]!)["parseTrustedRoot/".Length..], K05.Args(c)[0]);
        return m;
    });
    static readonly Dictionary<string, SigstorePinnedRoots> Parsed = new();

    /// <summary>The pinned roots a {$root} reference names; a root that does not parse is a refusal (the reference throws too).</summary>
    static SigstorePinnedRoots Roots(object? r)
    {
        var id = (string)((D)r!)["$root"]!;
        lock (Parsed)
        {
            if (!Parsed.TryGetValue(id, out var p)) Parsed[id] = p = Sigstore.ParseTrustedRoot(RootJson.Value[id]);
            return p;
        }
    }

    static D Summary(SigstorePinnedRoots r)
    {
        object? End(long e) => e == long.MaxValue ? null : (object?)e;
        object? Lg(SigstorePinnedLog l) => new D { ["keyId"] = Convert.ToBase64String(l.KeyId), ["start"] = l.Start, ["end"] = End(l.End), ["v2"] = l.V2Name };
        object? Ca(SigstorePinnedCa c) => new D { ["chain"] = (long)c.Chain.Count, ["start"] = c.Start, ["end"] = End(c.End) };
        return new D { ["tlogs"] = r.Tlogs.Select(Lg).ToList(), ["ctlogs"] = r.Ctlogs.Select(Lg).ToList(), ["cas"] = r.Cas.Select(Ca).ToList(), ["tsas"] = r.Tsas.Select(Ca).ToList() };
    }

    [Fact] public void ParseTrustedRoot() => K05.Check(M, "parseTrustedRoot", a => Summary(Sigstore.ParseTrustedRoot(a[0])));

    [Fact]
    public void VerifyBundleCore() => K05.Check(M, "verifySigstoreBundleCore", a =>
    {
        var r = Sigstore.VerifySigstoreBundleCore(a[0], Roots(a[1]));
        return r.Ok ? new D { ["ok"] = true, ["core"] = r.Core } : new D { ["ok"] = false, ["code"] = r.Code };
    }, eq: NoDetail, min: 5000);

    [Fact]
    public void VerifyBundle() => K05.Check(M, "verifySigstoreBundle", a =>
    {
        var r = Sigstore.VerifySigstoreBundle(a[0], Roots(a[1]));
        return r.Ok ? new D { ["ok"] = true, ["facts"] = r.Facts } : new D { ["ok"] = false, ["code"] = r.Code };
    }, eq: NoDetail);

    // ok and the exact core / facts, or the exact refusal code. The detail is informative only: the reference's details embed JavaScript
    // and OpenSSL runtime messages ("fail closed: Unexpected token ...", "error:0480006C:PEM routines::no start line").
    static bool NoDetail(D c, object? h) => K05.Show(c["out"] is D o && o.ContainsKey("detail") ? o.Where(e => e.Key != "detail").ToDictionary(e => e.Key, e => e.Value) : c["out"]) == K05.Show(K05.Json(h));

    [Fact]
    public void VerifyRfc3161() => K05.Check(M, "verifyRfc3161", a =>
        Sigstore.VerifyRfc3161(Convert.FromBase64String((string)a[0]!), Convert.FromBase64String((string)a[1]!), Roots(a[2]).Tsas));

    [Fact] public void DssePae() => K05.Check(M, "dssePae", a => Sigstore.DssePae((string)a[0]!, Convert.FromBase64String((string)a[1]!)));

    [Fact]
    public void EveryFn() => K05.Covers(M, new[] { "parseTrustedRoot", "verifySigstoreBundleCore", "verifySigstoreBundle", "verifyRfc3161", "dssePae" });
}

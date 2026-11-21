using System.Numerics;
using System.Security.Cryptography;
using AtlasPca;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Replay of the pure SEV-SNP helpers (test-data/ref-sevsnp-helpers.json.gz, 248 cases): hex, PEM splitting, the report parser (every field), the P-384 key and signature helpers, the report signature,
/// the policy gate, the default identity, the AMD KDS VCEK fetch over an injected transport and the certificate helpers (TBS extraction, VCEK key, VCEK / report binding). {"$bigint": s} is a 64-bit unsigned
/// integer. Every fn has a handler and the totals are asserted; a binding reason after "VCEK extensions malformed:" is library text, only the prefix is compared.</summary>
public class RefSevSnpHelpersTests
{
    const string M = "ref-sevsnp-helpers";
    const string Mark = "VCEK extensions malformed:";
    static readonly string[] U64 = ["policy", "current_tcb", "platform_info", "reported_tcb", "committed_tcb", "launch_tcb", "launch_mit_vector", "current_mit_vector"];

    static object? Dec(object? v) => v switch
    {
        D m when m.Count == 1 && m.TryGetValue("$bigint", out var t) && t is string s => BigInteger.Parse(s),
        D m => m.ToDictionary(e => e.Key, e => Dec(e.Value)),
        L l => l.Select(Dec).ToList(),
        _ => v,
    };

    static D Big(object? v) => new() { ["$bigint"] = Convert.ToString(v, System.Globalization.CultureInfo.InvariantCulture) };

    static byte[] B(object? o) => Base.Bytes(o);

    static D ParseOut(L a)
    {
        var r = SevSnp.ParseSevSnpReport(B(a[0]));
        var o = r.Where(e => e.Key is not ("sig_r" or "sig_s" or "signed" or "raw")).ToDictionary(e => e.Key, e => e.Value);
        foreach (var k in U64) o[k] = Big(o[k]);
        o["signed_len"] = ((byte[])r["signed"]!).Length;
        o["signed_sha256"] = Convert.ToHexString(SHA256.HashData((byte[])r["signed"]!)).ToLowerInvariant();
        o["raw_len"] = ((byte[])r["raw"]!).Length;
        return o;
    }

    static object? Fetch(L a)
    {
        var op = (D)a[2]!;
        var seen = new List<string>();
        var opts = new KdsOptions { Product = op.GetValueOrDefault("product") as string, BaseUrl = op.GetValueOrDefault("baseUrl") as string };
        if (op.GetValueOrDefault("noFetch") is not true)
            opts.Fetch = url =>
            {
                seen.Add(url);
                int st = (int)Base.Long(op["status"]);
                return new KdsResponse(st is >= 200 and < 300, st, B(op["body"]));
            };
        var bytes = SevSnp.FetchVcekFromKds(B(a[0]), (ulong)(BigInteger)Dec(a[1])!, opts);
        return new D { ["url"] = seen[0], ["bytes"] = bytes };
    }

    static bool Same(object? got, object? want) =>
        want is string w && w.StartsWith(Mark, StringComparison.Ordinal) ? got is string g && g.StartsWith(Mark, StringComparison.Ordinal) : Base.Show(want) == Base.Show(got);

    static void Fn(string fn, Func<L, object?> run, int min) => Base.Check(M, fn, a => Base.Json(run(a)), (c, have) => Same(have, c["out"]), null, min);

    [Fact] public void Constants() => Fn("constants", _ => SevSnp.Constants().ToDictionary(e => e.Key, e => e.Value is BigInteger b ? Big(b) : e.Value), 1);
    [Fact] public void ToHex() => Fn("toHex", a => SevSnp.ToHex(B(a[0])), 4);
    [Fact] public void SplitPemCertificates() => Fn("splitPemCertificates", a => SevSnp.SplitPemCertificates((string)a[0]!), 15);
    [Fact] public void ParseReport() => Fn("parseReport", a => ParseOut(a), 17);
    [Fact] public void EcdsaP384PublicKey() => Fn("ecdsaP384PublicKey", a => new D { ["point"] = SevSnp.EcdsaP384PublicKey(B(a[0])) }, 11);
    [Fact] public void SignatureToCompact() => Fn("signatureToCompact", a => SevSnp.SevSnpSignatureToCompact(B(((D)a[0]!)["r"]), B(((D)a[0]!)["s"])), 10);
    [Fact] public void VerifyReportSignature() => Fn("verifyReportSignature", a => SevSnp.VerifySevSnpReportSignature(SevSnp.ParseSevSnpReport(B(a[0])), a[1] == null ? null : B(a[1])), 13);
    [Fact] public void CheckPolicy() => Fn("checkPolicy", a => SevSnp.CheckSevSnpPolicy(SevSnp.ParseSevSnpReport(B(a[0])), (D?)Dec(a[1])), 57);
    [Fact] public void DeriveIdentity() => Fn("deriveIdentity", a => SevSnp.MakeDefaultDeriveIdentity(a[1] is true)(SevSnp.ParseSevSnpReport(B(a[0]))), 8);
    [Fact] public void FetchVcek() => Fn("fetchVcek", Fetch, 14);
    [Fact] public void ExtractTbsCertificate() => Fn("extractTbsCertificate", a => SevSnp.ExtractTbsCertificate(B(a[0])), 16);
    [Fact] public void ExtractVcekPublicKey() => Fn("extractVcekPublicKey", a => { var (p, t) = SevSnp.ExtractVcekPublicKey(B(a[0])); return new D { ["point"] = p, ["tbs"] = t }; }, 7);
    [Fact] public void CheckVcekReportBinding() => Fn("checkVcekReportBinding", a => SevSnp.CheckVcekReportBinding(B(a[0]), SevSnp.ParseSevSnpReport(B(a[1]))), 75);

    [Fact]
    public void Covers()
    {
        Base.Covers(M, new[]
        {
            "constants", "toHex", "splitPemCertificates", "parseReport", "ecdsaP384PublicKey", "signatureToCompact", "verifyReportSignature", "checkPolicy", "deriveIdentity", "fetchVcek",
            "extractTbsCertificate", "extractVcekPublicKey", "checkVcekReportBinding",
        });
        Assert.Equal(248, Base.Total(M));
        var counts = Base.Cases(M).GroupBy(c => (string)c["fn"]!).ToDictionary(g => g.Key, g => g.Count());
        Assert.Equal(new Dictionary<string, int>
        {
            ["toHex"] = 4, ["splitPemCertificates"] = 15, ["parseReport"] = 17, ["ecdsaP384PublicKey"] = 11, ["signatureToCompact"] = 10, ["verifyReportSignature"] = 13, ["checkPolicy"] = 57,
            ["deriveIdentity"] = 8, ["fetchVcek"] = 14, ["extractTbsCertificate"] = 16, ["extractVcekPublicKey"] = 7, ["checkVcekReportBinding"] = 75, ["constants"] = 1,
        }, counts);
        Assert.Equal(39, Base.Cases(M).Count(c => c["out"] is D o && o.ContainsKey("$throws")));
    }
}

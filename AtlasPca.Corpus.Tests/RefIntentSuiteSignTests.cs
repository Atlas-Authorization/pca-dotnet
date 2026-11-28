using AtlasPca;
using AtlasPca.IntentPkg;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Suite signing of the intent artifacts (test-data/ref-intent-suite-sign-java.json.gz): statements, observations and profiles signed under
/// Ed25519, ML-DSA and the hybrids. The arguments are the body, the Ed25519 seed, the suite name and the ML-DSA seed. Compared: the signed artifact
/// without its signature members, the suite members, the signature lengths, and the verdict under the matching pin.</summary>
public class RefIntentSuiteSignTests
{
    const string M = "ref-intent-suite-sign-java";

    static SuiteKey Key(L a)
    {
        var alg = (string)a[2]!;
        var ed = EdKey.FromSeed(Pca.B64uDecode(a[1])!);
        return alg == "ed25519" ? SuiteKey.Ed25519(ed)
            : SuiteKey.Create(alg, ed, PqKey.FromSeed(alg.EndsWith("ml-dsa-87", StringComparison.Ordinal) ? Pq.Prim.MlDsa87 : Pq.Prim.MlDsa65, Pca.B64uDecode(a[3])!));
    }

    static object? Len(object? sig) => sig is string s ? IntentJs.OfLong(Pca.B64uDecode(s)!.Length) : null;

    static D Shape(D a, D verdict)
    {
        var rest = new D(a);
        foreach (var k in new[] { "sig", "pq_sig", "alg", "pq_pk" }) rest.Remove(k);
        return new D
        {
            ["alg"] = a.GetValueOrDefault("alg"), ["pq_pk"] = a.GetValueOrDefault("pq_pk"), ["rest"] = rest,
            ["sig_len"] = Len(a.GetValueOrDefault("sig")), ["pq_sig_len"] = Len(a.GetValueOrDefault("pq_sig")), ["ok"] = verdict.GetValueOrDefault("ok") is true,
        };
    }

    static D Pins(D a, string who) => a.GetValueOrDefault("pq_pk") is { } pk ? new D { [(string)a[who]!] = pk } : new D();

    [Fact]
    public void SignStatement() => Base.Check(M, "signStatement", a =>
    {
        var s = IntentStatement.SignIntent((D)a[0]!, Key(a));
        return Shape(s, IntentStatement.VerifyIntent(s, null, Pins(s, "principal")));
    }, min: 30);

    [Fact]
    public void SignObservation() => Base.Check(M, "signObservation", a =>
    {
        var s = IntentObservation.SignIntentObservation((D)a[0]!, Key(a));
        return Shape(s, IntentObservation.VerifyIntentObservation(s, null, Pins(s, "signer")));
    }, min: 18);

    [Fact]
    public void SignProfile() => Base.Check(M, "signProfile", a =>
    {
        var s = IntentProfile.SignIntentProfile((D)a[0]!, Key(a));
        return Shape(s, IntentProfile.VerifyIntentProfile(s, Pins(s, "owner")));
    }, min: 88);

    [Fact]
    public void Covers()
    {
        Base.Covers(M, new[] { "signStatement", "signObservation", "signProfile" });
        Assert.Equal(136, Base.Total(M));
    }
}

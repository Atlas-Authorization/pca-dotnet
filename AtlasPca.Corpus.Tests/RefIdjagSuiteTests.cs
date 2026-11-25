using System.Security.Cryptography;
using System.Text;
using AtlasPca;
using AtlasPca.IdJag;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;
using IJ = AtlasPca.IdJag.IdJag;

namespace AtlasPca.Corpus.Tests;

/// <summary>idJagToCapability under each root signature suite (test-data/ref-idjag-suite-java.json.gz). The arguments are the grant, the principal's seed
/// label, the suite name and the ML-DSA seed. ML-DSA signatures are not compared byte for byte: the capability without its signatures, the signature
/// lengths, and the chain verifying under the pinned post-quantum key are.</summary>
public class RefIdjagSuiteTests
{
    const string M = "ref-idjag-suite-java";

    static byte[] Seed(string label) => SHA256.HashData(Encoding.UTF8.GetBytes("atlas-pca-conformance/" + label));
    static object? Len(object? sig) => sig is string s ? IntentJs.OfLong(Pca.B64uDecode(s)!.Length) : null;

    [Fact]
    public void IdJagToCapabilitySuite() => Base.Check(M, "idJagToCapabilitySuite", a =>
    {
        var alg = (string)a[2]!;
        var seed = Seed((string)a[1]!);
        var ed = EdKey.FromSeed(seed);
        var suite = alg == "ed25519" ? SuiteKey.Ed25519(ed)
            : SuiteKey.Create(alg, ed, PqKey.FromSeed(alg.EndsWith("ml-dsa-87", StringComparison.Ordinal) ? Pq.Prim.MlDsa87 : Pq.Prim.MlDsa65, Pca.B64uDecode(a[3])!));
        var pub = a.Count > 4 && a[4] is string given ? given : ed.Id;
        var r = IJ.IdJagToCapability(a[0], new IdJagToCapabilityOptions
        {
            PrincipalSecret = seed, PrincipalPublic = pub, Holder = EdKey.FromSeed(Seed("idjag/holder")).Id, Suite = suite,
        });
        var full = (D)r["capability"]!;
        var cap = new D(full);
        cap.Remove("sig");
        cap.Remove("pq_sig");
        var pins = new Dictionary<string, string>();
        if (cap.GetValueOrDefault("pq_pk") is string pk) pins[pub] = pk;
        return new D
        {
            ["capability"] = cap, ["sig_len"] = Len(full.GetValueOrDefault("sig")), ["pq_sig_len"] = Len(full.GetValueOrDefault("pq_sig")),
            ["principal"] = r["principal"], ["scopes"] = r["scopes"],
            ["ok"] = Pca.VerifyChain(new L { full }, pub, true, null, pins).Ok,
        };
    }, min: 13);

    [Fact]
    public void Covers()
    {
        Base.Covers(M, new[] { "idJagToCapabilitySuite" });
        Assert.Equal(13, Base.Cases(M).Count);
    }
}

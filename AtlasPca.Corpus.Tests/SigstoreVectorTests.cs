using AtlasPca;
using Xunit;
using static AtlasPca.Corpus.Tests.Conf;

namespace AtlasPca.Corpus.Tests;

// Offline Sigstore bundle verification (track K9), replaying packages/pca/conformance/sigstore-vectors.json (decided by the
// TypeScript reference): every case, ok and the whole core on ok, and the reference's refusal code.
public class SigstoreVectorTests
{
    static readonly Dictionary<string, object?> Doc = Load("sigstore-vectors.json");
    static readonly Dictionary<string, SigstorePinnedRoots> Roots = D(Doc["roots"]).ToDictionary(e => e.Key, e => Sigstore.ParseTrustedRoot(e.Value));
    static List<object?> Cases => L(Doc["cases"]);

    [Fact]
    public void EveryCaseMatchesTheReference()
    {
        Assert.True(Cases.Count >= 35);
        var accepted = 0;
        foreach (var x in Cases)
        {
            var c = D(x);
            var want = D(c["expect"]);
            var r = Sigstore.VerifySigstoreBundleCore(c["bundle"], Roots[(string)c["roots"]!]);
            var name = c["name"];
            Assert.True(Equals(want["ok"], r.Ok), $"{name}: {r.Code} {r.Detail}");
            if (r.Ok)
            {
                accepted++;
                Assert.True(IntentJs.JsonEquals(want["core"], r.Core), $"{name}: core differs");
            }
            else Assert.True((string?)want["code"] == r.Code, $"{name}: want {want["code"]}, got {r.Code} ({r.Detail})");
        }
        Assert.True(accepted >= 9, $"accepted {accepted}");
    }

    [Fact]
    public void FactsFeedTheGate()
    {
        var c = D(Cases.First(x => (string?)D(x)["name"] == "npm/sigstore-5.0.0"));
        var r = Sigstore.VerifySigstoreBundle(c["bundle"], Roots[(string)c["roots"]!]);
        Assert.True(r.Ok, $"{r.Code} {r.Detail}");
        Assert.Null(ProvenanceGate.ProvenanceFactsError(r.Facts));
    }

    [Fact]
    public void HostileInputIsRefusedNotThrown()
    {
        var any = Roots.Values.First();
        var bad = Pca.ParseJson("{\"mediaType\":\"application/vnd.dev.sigstore.bundle.v0.3+json\",\"verificationMaterial\":{\"certificate\":{\"rawBytes\":\"MAA=\"}},\"dsseEnvelope\":{\"payloadType\":\"application/vnd.in-toto+json\",\"payload\":\"\",\"signatures\":[{\"sig\":\"\"}]}}");
        foreach (var b in new object?[] { null, "x", new List<object?>(), new Dictionary<string, object?> { ["verificationMaterial"] = new Dictionary<string, object?>() }, bad })
            Assert.False(Sigstore.VerifySigstoreBundleCore(b, any).Ok);
    }
}

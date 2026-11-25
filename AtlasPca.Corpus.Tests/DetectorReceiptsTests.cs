using AtlasPca.Dataflow;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

public class DetectorReceiptsTests
{
    static readonly byte[] Seed = Enumerable.Repeat((byte)4, 32).ToArray();
    static string Pk => EdKey.FromSeed(Seed).Id;

    static D Policy(string onSuspicious = "deny") => new()
    {
        ["detectors"] = new L { new D { ["id"] = "lakera", ["keys"] = new L { new D { ["pk"] = Pk } }, ["on_suspicious"] = onSuspicious, ["max_age_ms"] = new Num("60000") } },
    };

    static D Receipt(bool flagged, object content, double now = 1000) =>
        Detectors.LakeraReceipt(
            flagged ? new D { ["flagged"] = true, ["breakdown"] = new L { new D { ["detector_type"] = "prompt_attack", ["detected"] = true } } } : new D { ["flagged"] = false },
            new AdapterContext { Detector = "lakera", Version = "v2", Content = content, SecretKey = Seed, Now = now });

    [Fact]
    public void ShapeAndRef()
    {
        var r = Receipt(true, "hello");
        Assert.Null(DetectorReceipts.ShapeError(r));
        Assert.Equal("receipt must be an object", DetectorReceipts.ShapeError("x"));
        Assert.Equal(DetectorReceipts.Ref(r), DetectorReceipts.Ref(Receipt(true, "hello")));
        Assert.NotEqual(DetectorReceipts.Ref(r), DetectorReceipts.Ref(Receipt(true, "other")));
        Assert.Null(DetectorReceipts.PolicyError(Policy()));
        Assert.NotNull(DetectorReceipts.PolicyError(new D { ["detectors"] = new L { new D() } }));
    }

    [Fact]
    public void SuspiciousTightensAndCleanIsNeutral()
    {
        var digest = Detectors.DetectorInputDigest("hello");
        DetectorOutcome Run(DetectorInput i) => DetectorReceipts.Signal(i);
        DetectorInput Input(string pol, params D[] rs) => new()
        {
            Receipts = rs.Cast<object?>().ToList(), Policy = Policy(pol), InputDigests = new[] { digest }, Now = 2000,
        };
        var bad = Receipt(true, "hello");
        var clean = Receipt(false, "hello");
        Assert.Equal("ok", Run(Input("deny")).Signal);
        Assert.Equal("ok", Run(Input("deny", clean)).Signal);
        var o = Run(Input("deny", bad));
        Assert.Equal("deny", o.Signal);
        Assert.Equal(new[] { "lakera" }, o.Flagged);
        Assert.Equal(true, o.Detect["lakera"]);
        Assert.Equal("escalate", Run(Input("escalate", bad)).Signal);
        // a receipt about other content, a stale one and one from the future each raise escalate and are listed
        Assert.Equal("escalate", Run(Input("deny", Receipt(false, "other"))).Signal);
        Assert.Equal("escalate", Run(new DetectorInput { Receipts = new object?[] { clean }, Policy = Policy(), InputDigests = new[] { digest }, Now = 10_000_000 }).Signal);
        Assert.Equal("escalate", Run(new DetectorInput { Receipts = new object?[] { clean }, Policy = Policy(), InputDigests = new[] { digest }, Now = 1 }).Signal);
        // a malformed policy denies; a forged signature is not evidence
        Assert.Equal("deny", Run(new DetectorInput { Policy = new D() }).Signal);
        var forged = Receipt(false, "hello"); forged["sig"] = Pca.B64u(new byte[64]);
        Assert.Equal("escalate", Run(Input("deny", forged)).Signal);
    }
}

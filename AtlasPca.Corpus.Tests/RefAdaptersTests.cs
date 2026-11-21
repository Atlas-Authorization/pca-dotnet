using System.Security.Cryptography;
using System.Text;
using AtlasPca;
using AtlasPca.Adapters;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Differential oracle of the agent-side adapter helpers (test-data/ref-adapters.json.gz) plus unit tests of the guard and the bridge.</summary>
public class RefAdaptersTests
{
    const string M = "ref-adapters";

    static byte[] Seed(string label) => SHA256.HashData(Encoding.UTF8.GetBytes("atlas-pca-conformance/" + label));

    [Fact]
    public void MessageSegments() => Base.Check(M, "messageSegments", a =>
        PcaAdapters.MessageSegments(a[0]).Select(s => (object?)new D { ["origin"] = s.Origin, ["source"] = s.Source, ["content"] = s.Content }).ToList());

    [Fact]
    public void ProvenanceHeaders() => Base.Check(M, "provenanceHeaders", a => PcaAdapters.ProvenanceHeaders(a[0]));

    [Fact]
    public void RecordFlow() => Base.Check(M, "recordFlow", a =>
    {
        var rec = new ProvenanceRecorder("harness", "k1", SuiteKey.Ed25519(EdKey.FromSeed(Seed("ref-adapters/recorder"))), Pca.B64u(Seed("ref-adapters/session")), () => 1_800_000_000_000L);
        var bundles = new L();
        foreach (var s in (L)((D)a[0]!)["steps"]!)
        {
            var st = (D)s!;
            switch ((string)st["op"]!)
            {
                case "messages": PcaAdapters.RecordMessages(rec, (L)st["messages"]!); break;
                case "input": PcaAdapters.RecordInput(rec, st["input"]); break;
                case "principal": rec.Principal((string)st["text"]!); break;
                case "tool": rec.Tool((string)st["tool"]!, st["output"]); break;
                case "act":
                    var act = (D)st["action"]!;
                    bundles.Add(rec.ForAction((string)act["verb"]!, (string)act["resource"]!, act["params"]));
                    break;
                default: throw new InvalidOperationException("op " + st["op"]);
            }
        }
        return new D { ["bundles"] = bundles, ["receipts"] = rec.Receipts().Select(r => (object?)r).ToList() };
    });

    [Fact]
    public void CoversEveryFn() { Base.Covers(M, new[] { "messageSegments", "provenanceHeaders", "recordFlow" }); Assert.Equal(71, Base.Total(M)); }

    // ---- unit tests: guard, bridge, header and bundle readers ----

    static AgentHandle Refunds() => Agent.FromPrincipal(new AgentOptions
    {
        Principal = SuiteKey.Ed25519(EdKey.Generate()), Holder = SuiteKey.Ed25519(EdKey.Generate()), Goal = "refund order 1",
        Permissions = new D { ["stripe"] = new L { "refund" } },
        Limits = new Dictionary<string, string> { ["refund"] = "$500/day" }, Aud = "rs-test", Now = 1_000_000,
    });

    static readonly GuardSpec Refund = new() { Verb = "stripe.refund", Resource = p => "charge:" + p["id"] };

    [Fact]
    public async Task GuardDispatchesWithTheProofAndRecordsTheResult()
    {
        var ag = Refunds();
        PcaCall? seen = null;
        var run = PcaAdapters.Guard(ag, Refund, (p, call) => { seen = call; return Task.FromResult("done"); });
        Assert.Equal("done", await run(new D { ["id"] = "c1", ["amount"] = 125L }, new ActOptions { Now = 2_000_000 }));
        Assert.NotNull(seen);
        Assert.Equal(PcaAdapters.PcaHeaders(seen!.Encoded, seen.Provenance)["PCA-Action"], seen.Headers["PCA-Action"]);
        Assert.Equal(seen.Encoded, PcaAdapters.DecodePcaHeader(seen.Headers["PCA-Action"]));
        // the principal-less chain holds only the action so far; the tool result lands after it
        Assert.Single((L)seen.Provenance!["receipts"]!);
        Assert.Equal(2, ag.Provenance.Receipts().Count);
        Assert.Equal("tool", ag.Provenance.Receipts()[1]["origin"]);
    }

    [Fact]
    public async Task GuardRefusesALocalDenyBeforeRunning()
    {
        var ag = Refunds();
        var ran = false;
        var run = PcaAdapters.Guard(ag, Refund, (p, call) => { ran = true; return Task.FromResult(1); });
        var e = await Assert.ThrowsAsync<PcaDenied>(() => run(new D { ["id"] = "c1", ["amount"] = 600L }, new ActOptions { Now = 2_000_000 }));
        Assert.Equal("stripe.refund", e.Verb);
        Assert.Equal("charge:c1", e.Resource);
        Assert.False(ran);
        // with failFast off the dispatch proceeds and the resource server is the only gate
        var open = PcaAdapters.Guard(ag, new GuardSpec { Verb = "stripe.refund", Resource = p => "charge:c1", FailFast = false }, (p, call) => Task.FromResult(2));
        Assert.Equal(2, await open(new D { ["amount"] = 600L }, new ActOptions { Now = 2_000_000 }));
    }

    [Fact]
    public void BridgeDeclinesAnUnmappedToolAndBuildsAMappedOne()
    {
        var ag = Refunds();
        Assert.Null(PcaAdapters.BridgeToolCall(ag, new AgentToolCall("unknown", new D()), c => null));
        var call = PcaAdapters.BridgeToolCall(ag, new AgentToolCall("refund", new D { ["amount"] = 5L }), c => ("stripe.refund", "charge:c9"), new ActOptions { Now = 2_000_000 });
        Assert.NotNull(call);
        Assert.Equal("stripe.refund", ((D)call!.PCActn["action"]!)["verb"]);
    }

    [Fact]
    public void HeaderAndBundleReadersFailClosed()
    {
        Assert.Throws<PcaHeaderError>(() => PcaAdapters.DecodePcaHeader(""));
        Assert.Throws<PcaHeaderError>(() => PcaAdapters.DecodePcaHeader("e30="));
        Assert.Equal("{}", PcaAdapters.DecodePcaHeader("e30"));
        Assert.Null(PcaAdapters.ProvenanceFrom("not json or a header!"));
        Assert.Null(PcaAdapters.ProvenanceFrom(""));
        Assert.Null(PcaAdapters.ProvenanceFrom(5L));
        Assert.IsType<D>(PcaAdapters.ProvenanceFrom("{\"a\":1}"));
        Assert.IsType<D>(PcaAdapters.ProvenanceFrom("eyJhIjoxfQ"));
    }
}

using AtlasPca;
using Xunit;
using JD = System.Collections.Generic.Dictionary<string, object?>;
using JL = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

// The L4 information-flow taint (Taint.cs) and the enforce.taint gate of Authorize, ported from the reference taint.ts.
public class K05TaintTests
{
    static JD Prov(params string[] refs) => new() { ["causal_hash"] = "h", ["taint_level"] = 0L, ["trusted_refs"] = refs.Select(r => (object?)r).ToList() };

    static TaintContext Ctx(Action<InMemoryTrustedInputRegistry>? f = null, Func<string, bool>? node = null)
    {
        var r = new InMemoryTrustedInputRegistry();
        f?.Invoke(r);
        return new TaintContext(r, node);
    }

    [Fact]
    public void RanksValuesAndTheJoinFollowTheLattice()
    {
        Assert.Equal(new[] { 0, 1, 2, 3, 4 }, new[] { "trusted", "first_party", "tool", "web", "agent" }.Select(k => Taint.Rank(new TaintLabel(k))).ToArray());
        Assert.Equal(4, Taint.Rank(new TaintLabel("constructor"))); // an unknown kind is the worst rank
        Assert.Equal(4, Taint.Rank(null));
        Assert.Equal(0.25, Taint.Value(new TaintLabel("first_party")));
        Assert.Equal(new TaintLabel("web"), Taint.Join(new TaintLabel("tool", "a"), new TaintLabel("web")));
        Assert.Equal(new TaintLabel("web"), Taint.Join(new TaintLabel("web"), new TaintLabel("tool", "a")));
        Assert.Equal(new TaintLabel("tool", "a"), Taint.Join(new TaintLabel("tool", "a"), new TaintLabel("tool", "a")));
        Assert.Equal(new TaintLabel("tool"), Taint.Join(new TaintLabel("tool", "a"), new TaintLabel("tool", "b"))); // ids that differ collapse
        Assert.Equal(TaintLabel.Top, Taint.JoinAll(Array.Empty<TaintLabel>()));
        Assert.Equal(new TaintLabel("first_party"), Taint.JoinAll(new[] { new TaintLabel("trusted"), new TaintLabel("first_party") }));
        foreach (var k in new[] { "trusted", "first_party", "tool", "web", "agent" })
            Assert.Equal(new TaintLabel(k), Taint.Join(TaintLabel.Bottom, new TaintLabel(k)));
    }

    [Fact]
    public void EveryRefIsClassifiedFromServerFactsNeverFromTheAgent()
    {
        var ctx = Ctx(r => r.RecordTrusted("t").RecordFirstParty("f").RecordTool("x", "tool-1").RecordWeb("w"), id => id == "graph-node");
        Assert.Equal(0, Taint.Compute(Prov("t"), ctx).Taint);
        Assert.Equal(0.25, Taint.Compute(Prov("t", "f"), ctx).Taint);
        var mixed = Taint.Compute(Prov("t", "x", "w"), ctx);
        Assert.Equal(0.75, mixed.Taint);
        Assert.Equal(new TaintLabel("web"), mixed.Label);
        Assert.Equal(new[] { "t", "x", "w" }, mixed.Refs.Select(r => r.Ref).ToArray());
        Assert.Equal(0.25, Taint.Compute(Prov("graph-node"), ctx).Taint); // a first-party resource-graph node
        var unverifiable = Taint.Compute(Prov("t", "claims-to-be-trusted"), ctx);
        Assert.Equal(1, unverifiable.Taint);
        Assert.Equal(new TaintLabel("agent", "claims-to-be-trusted"), unverifiable.Refs[1].Label);
        Assert.Null(Taint.Compute(Prov(new string('a', 129)), ctx).Refs[0].Label.Id);
        Assert.Equal(1, Taint.Compute(Prov(), ctx).Taint); // an empty lineage is the worst case, and valid
        Assert.True(Taint.Compute(Prov(), ctx).Valid);
        Assert.Equal(1, Taint.Compute(new JD { ["causal_hash"] = "h" }, ctx).Taint); // trusted_refs absent
    }

    [Fact]
    public void AbsentOrMalformedProvenanceFailsClosedWithTheReferenceReasons()
    {
        var ctx = Ctx();
        void Bad(object? prov, TaintContext? c, string reason)
        {
            var r = Taint.Compute(prov, c);
            Assert.False(r.Valid);
            Assert.Equal(1, r.Taint);
            Assert.Equal(TaintLabel.Top, r.Label);
            Assert.Equal(reason, r.Reason);
        }
        Bad(null, ctx, "taint: provenance is absent or malformed");
        Bad(new JL(), ctx, "taint: provenance is absent or malformed");
        Bad("x", ctx, "taint: provenance is absent or malformed");
        Bad(Prov("a"), null, "taint: no trusted-input registry");
        Bad(new JD { ["trusted_refs"] = "a" }, ctx, "taint: trusted_refs must be an array");
        Bad(new JD { ["trusted_refs"] = null }, ctx, "taint: trusted_refs must be an array");
        Bad(new JD { ["trusted_refs"] = new JL { "a", "" } }, ctx, "taint: trusted_refs must be non-empty strings");
        Bad(new JD { ["trusted_refs"] = new JL { "a", 5L } }, ctx, "taint: trusted_refs must be non-empty strings");
        Bad(Prov("a"), new TaintContext(new ThrowingRegistry()), "taint: evaluation error (fail closed): boom");
    }

    sealed class ThrowingRegistry : ITrustedInputRegistry { public TaintLabel? Lookup(string digest) => throw new InvalidOperationException("boom"); }
    sealed class BogusRegistry : ITrustedInputRegistry { public TaintLabel? Lookup(string digest) => new TaintLabel("constructor"); }

    [Fact]
    public void ARegistryAnswerOfAnUnknownKindVouchesForNothing()
    {
        var r = Taint.Compute(Prov("a"), new TaintContext(new BogusRegistry(), id => id == "a"));
        Assert.Equal(new TaintLabel("first_party"), r.Refs[0].Label); // falls through to the resource graph
        Assert.Equal(1, Taint.Compute(Prov("a"), new TaintContext(new BogusRegistry())).Taint);
        Assert.Equal(1, Taint.Compute(Prov("a"), new TaintContext(new InMemoryTrustedInputRegistry(), _ => throw new InvalidOperationException())).Taint);
    }

    [Fact]
    public void TheRegistryIgnoresUnknownKindsAndEmptyDigests()
    {
        var reg = new InMemoryTrustedInputRegistry().Record("", new TaintLabel("trusted")).Record("d", new TaintLabel("bogus")).RecordTrusted("ok");
        Assert.Equal(1, reg.Size);
        Assert.Null(reg.Lookup("d"));
        Assert.Equal(new TaintLabel("trusted"), reg.Lookup("ok"));
    }

    [Fact]
    public void TheGateRefusesInvalidMisconfiguredAndTooTaintedLineage()
    {
        var ctx = Ctx(r => r.RecordTrusted("t").RecordWeb("w"));
        Assert.Equal((true, (string?)null), Taint.Gate(Prov("t"), ctx, 0));
        Assert.Equal((false, (string?)"information-flow taint 0.75 exceeds policy max 0.5"), Taint.Gate(Prov("t", "w"), ctx, 0.5));
        Assert.True(Taint.Gate(Prov("t", "w"), ctx, 0.75).Ok);
        Assert.True(Taint.Gate(Prov("w"), ctx, 1).Ok);
        Assert.Equal("taint: provenance is absent or malformed", Taint.Gate(null, ctx, 1).Reason);
        Assert.Equal("taint gate misconfigured: maxTaint must be a non-negative number (fail closed)", Taint.Gate(Prov("t"), ctx, -0.1).Reason);
        Assert.Equal("taint gate misconfigured: maxTaint must be a non-negative number (fail closed)", Taint.Gate(Prov("t"), ctx, double.NaN).Reason);
        Assert.False(Taint.Gate(Prov(), ctx, 0.9).Ok); // the empty lineage is taint 1
        Assert.Equal(3, Taint.CombineRank(1, 3));
        Assert.Equal(3, Taint.CombineRank(3, 1));
    }
}

using AtlasPca;
using Xunit;
using JD = System.Collections.Generic.Dictionary<string, object?>;
using JL = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

// Exact checks of the information-flow taint (Taint.cs): the lattice, the registry, the per-ref classification and the gate.
public class TaintKillTests2
{
    static readonly string[] Kinds = { "trusted", "first_party", "tool", "web", "agent" };

    static JD Prov(params string[] refs) => new() { ["trusted_refs"] = refs.Select(r => (object?)r).ToList() };

    sealed class FixedRegistry : ITrustedInputRegistry
    {
        readonly TaintLabel? _label;
        public FixedRegistry(TaintLabel? label) { _label = label; }
        public TaintLabel? Lookup(string digest) => _label;
    }

    sealed class ThrowingRegistry : ITrustedInputRegistry
    {
        public TaintLabel? Lookup(string digest) => throw new InvalidOperationException("boom");
    }

    [Fact]
    public void TheLevelsAreTheFiveLatticeKindsAndNothingElse()
    {
        foreach (var k in Kinds) Assert.True(Taint.IsLevel(k), k);
        foreach (var k in new[] { "", "Trusted", "AGENT", "constructor", "first-party", " web", "web " }) Assert.False(Taint.IsLevel(k), k);
        Assert.False(Taint.IsLevel(null));
        Assert.Equal(new TaintLabel("agent"), TaintLabel.Top);
        Assert.Equal(new TaintLabel("trusted"), TaintLabel.Bottom);
        Assert.Null(TaintLabel.Top.Id);
        Assert.Null(TaintLabel.Bottom.Id);
    }

    [Fact]
    public void RankAndValueFollowTheLatticeAndAnUnknownKindIsTheWorst()
    {
        for (int i = 0; i < 5; i++)
        {
            Assert.Equal(i, Taint.Rank(new TaintLabel(Kinds[i])));
            Assert.Equal(i, Taint.Rank(new TaintLabel(Kinds[i], "an-id")));
            Assert.Equal(i / 4.0, Taint.Value(new TaintLabel(Kinds[i])));
        }
        foreach (var k in new[] { "", "Trusted", "constructor", "bogus" })
        {
            Assert.Equal(4, Taint.Rank(new TaintLabel(k)));
            Assert.Equal(1.0, Taint.Value(new TaintLabel(k)));
        }
        Assert.Equal(4, Taint.Rank(null));
        Assert.Equal(1.0, Taint.Value(null));
    }

    [Fact]
    public void JoinIsTheHigherRankAndAtATieKeepsTheIdOnlyWhenBothAgree()
    {
        var tool = new TaintLabel("tool", "t");
        var web = new TaintLabel("web", "w");
        Assert.Same(web, Taint.Join(tool, web));
        Assert.Same(web, Taint.Join(web, tool));
        Assert.Same(tool, Taint.Join(tool, new TaintLabel("first_party", "f")));
        Assert.Same(tool, Taint.Join(new TaintLabel("trusted"), tool));
        Assert.Equal(new TaintLabel("web", "w"), Taint.Join(web, new TaintLabel("tool", "other")));
        var same = new TaintLabel("tool", "t");
        Assert.Same(tool, Taint.Join(tool, same));
        Assert.Equal(new TaintLabel("tool"), Taint.Join(tool, new TaintLabel("tool", "u")));
        Assert.Equal(new TaintLabel("tool"), Taint.Join(tool, new TaintLabel("tool")));
        Assert.Equal(new TaintLabel("tool"), Taint.Join(new TaintLabel("tool"), tool));
        var noId = new TaintLabel("web");
        Assert.Same(noId, Taint.Join(noId, new TaintLabel("web")));
        // unknown kinds tie with agent (both rank 4): the first argument's kind survives when the ids agree
        Assert.Equal(new TaintLabel("bogus", "1"), Taint.Join(new TaintLabel("bogus", "1"), new TaintLabel("agent", "1")));
        Assert.Equal(new TaintLabel("bogus"), Taint.Join(new TaintLabel("bogus", "1"), new TaintLabel("agent", "2")));
        Assert.Equal(new TaintLabel("agent"), Taint.Join(new TaintLabel("agent", "1"), new TaintLabel("bogus", "2")));
    }

    [Fact]
    public void JoinAllOfNothingIsTheTopAndOfOneIsItself()
    {
        Assert.Equal(TaintLabel.Top, Taint.JoinAll(Array.Empty<TaintLabel>()));
        var one = new TaintLabel("trusted");
        Assert.Same(one, Taint.JoinAll(new[] { one }));
        Assert.Equal(new TaintLabel("web", "w"), Taint.JoinAll(new[] { new TaintLabel("tool", "t"), new TaintLabel("web", "w"), new TaintLabel("first_party") }));
        Assert.Equal(new TaintLabel("tool"), Taint.JoinAll(new[] { new TaintLabel("tool", "a"), new TaintLabel("trusted"), new TaintLabel("tool", "b") }));
    }

    [Fact]
    public void TheRegistryRecordsATypedCopyAndReturnsACopy()
    {
        var reg = new InMemoryTrustedInputRegistry();
        Assert.Equal(0, reg.Size);
        Assert.Null(reg.Lookup("x"));
        var label = new TaintLabel("tool", "id-1");
        Assert.Same(reg, reg.Record("d", label));
        Assert.Equal(1, reg.Size);
        var got = reg.Lookup("d");
        Assert.Equal(label, got);
        Assert.NotSame(label, got);
        Assert.NotSame(got, reg.Lookup("d"));
        Assert.Null(reg.Lookup("D"));
        Assert.Null(reg.Lookup(""));
        reg.Record("d", new TaintLabel("web")); // a later record replaces
        Assert.Equal(1, reg.Size);
        Assert.Equal(new TaintLabel("web"), reg.Lookup("d"));
    }

    [Fact]
    public void TheRegistryIgnoresAnEmptyDigestANullLabelAndAnUnknownKind()
    {
        var reg = new InMemoryTrustedInputRegistry();
        Assert.Same(reg, reg.Record("", new TaintLabel("trusted")));
        Assert.Same(reg, reg.Record("d", null!));
        Assert.Same(reg, reg.Record("d", new TaintLabel("bogus")));
        Assert.Same(reg, reg.Record(null!, new TaintLabel("trusted")));
        Assert.Equal(0, reg.Size);
        Assert.Null(reg.Lookup("d"));
        // every real kind is accepted, the agent kind included
        foreach (var k in Kinds) reg.Record("d-" + k, new TaintLabel(k));
        Assert.Equal(5, reg.Size);
        foreach (var k in Kinds) Assert.Equal(new TaintLabel(k), reg.Lookup("d-" + k));
    }

    [Fact]
    public void TheShorthandRecordersUseTheirOwnKind()
    {
        var reg = new InMemoryTrustedInputRegistry().RecordTrusted("a").RecordFirstParty("b").RecordTool("c", "tool-id").RecordWeb("d");
        Assert.Equal(4, reg.Size);
        Assert.Equal(new TaintLabel("trusted"), reg.Lookup("a"));
        Assert.Equal(new TaintLabel("first_party"), reg.Lookup("b"));
        Assert.Equal(new TaintLabel("tool", "tool-id"), reg.Lookup("c"));
        Assert.Equal(new TaintLabel("web"), reg.Lookup("d"));
    }

    // ================= Compute =================

    [Fact]
    public void AnAgentLabelFromTheRegistryIsKeptAsIs()
    {
        var reg = new InMemoryTrustedInputRegistry().Record("r", new TaintLabel("agent", "vouched"));
        var t = Taint.Compute(Prov("r"), new TaintContext(reg));
        Assert.True(t.Valid);
        Assert.Equal(new TaintLabel("agent", "vouched"), t.Refs[0].Label);
        Assert.Equal(new TaintLabel("agent", "vouched"), t.Label);
        Assert.Equal(1.0, t.Taint);
        // an agent verdict from the registry wins over the resource graph
        var asFirstParty = Taint.Compute(Prov("r"), new TaintContext(reg, _ => true));
        Assert.Equal(new TaintLabel("agent", "vouched"), asFirstParty.Refs[0].Label);
    }

    [Fact]
    public void TheRegistryOutranksTheGraphAndTheGraphOutranksTheDefault()
    {
        var reg = new InMemoryTrustedInputRegistry().RecordWeb("w").RecordTrusted("t");
        var ctx = new TaintContext(reg, id => id != "plain");
        Assert.Equal(new TaintLabel("web"), Taint.Compute(Prov("w"), ctx).Refs[0].Label);
        Assert.Equal(new TaintLabel("trusted"), Taint.Compute(Prov("t"), ctx).Refs[0].Label);
        Assert.Equal(new TaintLabel("first_party"), Taint.Compute(Prov("node"), ctx).Refs[0].Label);
        Assert.Equal(new TaintLabel("agent", "plain"), Taint.Compute(Prov("plain"), ctx).Refs[0].Label);
        Assert.Equal(new TaintLabel("agent", "node"), Taint.Compute(Prov("node"), new TaintContext(reg)).Refs[0].Label);
        Assert.Equal(new TaintLabel("agent", "node"), Taint.Compute(Prov("node"), new TaintContext(reg, _ => false)).Refs[0].Label);
        Assert.Equal(new TaintLabel("agent", "node"), Taint.Compute(Prov("node"), new TaintContext(reg, _ => throw new InvalidOperationException("graph down"))).Refs[0].Label);
    }

    [Fact]
    public void AnUnverifiableRefKeepsItsIdOnlyUpToOneHundredTwentyEightChars()
    {
        var ctx = new TaintContext(new InMemoryTrustedInputRegistry());
        var at = new string('a', 128);
        var over = new string('a', 129);
        Assert.Equal(at, Taint.Compute(Prov(at), ctx).Refs[0].Label.Id);
        Assert.Null(Taint.Compute(Prov(over), ctx).Refs[0].Label.Id);
        Assert.Equal("agent", Taint.Compute(Prov(over), ctx).Refs[0].Label.Kind);
        Assert.Equal("x", Taint.Compute(Prov("x"), ctx).Refs[0].Label.Id);
    }

    [Fact]
    public void TheResultCarriesTheTaintTheJoinAndEveryRefInOrder()
    {
        var reg = new InMemoryTrustedInputRegistry().RecordTrusted("t").RecordFirstParty("f").RecordTool("x", "tool-1").RecordWeb("w");
        var ctx = new TaintContext(reg);
        var r = Taint.Compute(Prov("f", "t", "x"), ctx);
        Assert.True(r.Valid);
        Assert.Null(r.Reason);
        Assert.Equal(0.5, r.Taint);
        Assert.Equal(new TaintLabel("tool", "tool-1"), r.Label);
        Assert.Equal(new[] { "f", "t", "x" }, r.Refs.Select(x => x.Ref).ToArray());
        Assert.Equal(new[] { "first_party", "trusted", "tool" }, r.Refs.Select(x => x.Label.Kind).ToArray());
        Assert.Equal(0.0, Taint.Compute(Prov("t", "t"), ctx).Taint);
        Assert.Equal(0.75, Taint.Compute(Prov("w", "t"), ctx).Taint);
        var empty = Taint.Compute(Prov(), ctx);
        Assert.True(empty.Valid);
        Assert.Null(empty.Reason);
        Assert.Empty(empty.Refs);
        Assert.Equal(TaintLabel.Top, empty.Label);
        Assert.Equal(1.0, empty.Taint);
    }

    [Fact]
    public void AbsentRefsAreValidButAnExplicitNullIsNot()
    {
        var ctx = new TaintContext(new InMemoryTrustedInputRegistry());
        var absent = Taint.Compute(new JD { ["causal_hash"] = "h" }, ctx);
        Assert.True(absent.Valid);
        Assert.Null(absent.Reason);
        Assert.Equal(1.0, absent.Taint);
        Assert.Equal(TaintLabel.Top, absent.Label);
        Assert.Empty(absent.Refs);
        var nulled = Taint.Compute(new JD { ["trusted_refs"] = null }, ctx);
        Assert.False(nulled.Valid);
        Assert.Equal("taint: trusted_refs must be an array", nulled.Reason);
        Assert.Equal(1.0, nulled.Taint);
        Assert.Empty(nulled.Refs);
        Assert.True(Taint.Compute(new JD(), ctx).Valid);
    }

    [Fact]
    public void EveryMalformedShapeIsInvalidWithTheWorstTaint()
    {
        var ctx = new TaintContext(new InMemoryTrustedInputRegistry());
        void Bad(object? prov, TaintContext? c, string reason)
        {
            var r = Taint.Compute(prov, c);
            Assert.False(r.Valid);
            Assert.Equal(reason, r.Reason);
            Assert.Equal(1.0, r.Taint);
            Assert.Equal(TaintLabel.Top, r.Label);
            Assert.Empty(r.Refs);
        }
        Bad(Prov("a"), null, "taint: no trusted-input registry");
        Bad(Prov("a"), new TaintContext(null!), "taint: no trusted-input registry");
        Bad(null, null, "taint: no trusted-input registry"); // the registry is checked first
        Bad(null, ctx, "taint: provenance is absent or malformed");
        Bad("x", ctx, "taint: provenance is absent or malformed");
        Bad(new JL(), ctx, "taint: provenance is absent or malformed");
        Bad(5L, ctx, "taint: provenance is absent or malformed");
        foreach (var notList in new object[] { "a", 5L, new JD(), true })
            Bad(new JD { ["trusted_refs"] = notList }, ctx, "taint: trusted_refs must be an array");
        Bad(new JD { ["trusted_refs"] = new JL { "a", "" } }, ctx, "taint: trusted_refs must be non-empty strings");
        Bad(new JD { ["trusted_refs"] = new JL { "a", 5L } }, ctx, "taint: trusted_refs must be non-empty strings");
        Bad(new JD { ["trusted_refs"] = new JL { null } }, ctx, "taint: trusted_refs must be non-empty strings");
        Bad(new JD { ["trusted_refs"] = new JL { new JL { "a" } } }, ctx, "taint: trusted_refs must be non-empty strings");
        Bad(Prov("a"), new TaintContext(new ThrowingRegistry()), "taint: evaluation error (fail closed): boom");
    }

    // ================= Gate =================

    [Fact]
    public void TheGateAdmitsExactlyTheRanksAtOrBelowTheBound()
    {
        var reg = new InMemoryTrustedInputRegistry().RecordTrusted("t").RecordFirstParty("f").RecordTool("x", "i").RecordWeb("w");
        var ctx = new TaintContext(reg);
        var refs = new[] { "t", "f", "x", "w", "unverified" };
        var bounds = new[] { 0.0, 0.24, 0.25, 0.49, 0.5, 0.74, 0.75, 0.99, 1.0, 1.5, 100.0 };
        foreach (var bound in bounds)
            for (int rank = 0; rank < 5; rank++)
            {
                var ok = Taint.Gate(Prov(refs[rank]), ctx, bound);
                bool expected = rank / 4.0 <= bound;
                Assert.Equal(expected, ok.Ok);
                if (expected) Assert.Null(ok.Reason);
                else Assert.Equal($"information-flow taint {JsCanon.NumberString(rank / 4.0)} exceeds policy max {JsCanon.NumberString(bound)}", ok.Reason);
            }
    }

    [Fact]
    public void TheGateReasonsAreTheReferenceTexts()
    {
        var ctx = new TaintContext(new InMemoryTrustedInputRegistry().RecordWeb("w"));
        Assert.Equal((false, (string?)"information-flow taint 0.75 exceeds policy max 0.5"), Taint.Gate(Prov("w"), ctx, 0.5));
        Assert.Equal((false, (string?)"information-flow taint 1 exceeds policy max 0"), Taint.Gate(Prov("unverified"), ctx, 0));
        Assert.Equal((false, (string?)"information-flow taint 1 exceeds policy max 0.75"), Taint.Gate(Prov(), ctx, 0.75));
        Assert.Equal((true, (string?)null), Taint.Gate(Prov("unverified"), ctx, 1));
        Assert.Equal((true, (string?)null), Taint.Gate(Prov(), ctx, 1));
        Assert.Equal("taint: provenance is absent or malformed", Taint.Gate(null, ctx, 1).Reason);
        Assert.Equal("taint: no trusted-input registry", Taint.Gate(Prov("w"), null, 1).Reason);
        Assert.Equal("taint: trusted_refs must be an array", Taint.Gate(new JD { ["trusted_refs"] = "w" }, ctx, 1).Reason);
        foreach (var bad in new[] { null, (object?)Prov("w") })
            Assert.False(Taint.Gate(bad, null, 1).Ok);
    }

    [Fact]
    public void AMisconfiguredBoundNeverPasses()
    {
        var ctx = new TaintContext(new InMemoryTrustedInputRegistry().RecordTrusted("t"));
        const string reason = "taint gate misconfigured: maxTaint must be a non-negative number (fail closed)";
        foreach (var bad in new[] { -0.1, -1.0, double.NaN, double.NegativeInfinity })
        {
            var g = Taint.Gate(Prov("t"), ctx, bad);
            Assert.False(g.Ok);
            Assert.Equal(reason, g.Reason);
        }
        Assert.True(Taint.Gate(Prov("t"), ctx, 0).Ok);
        Assert.True(Taint.Gate(Prov("t"), ctx, double.PositiveInfinity).Ok);
        // the lineage is judged first: an invalid one reports its own reason, not the bound's
        Assert.Equal("taint: provenance is absent or malformed", Taint.Gate(null, ctx, -1).Reason);
    }

    [Fact]
    public void ACombinedRankIsTheLargerOfTheComputedAndTheClaimedOne()
    {
        Assert.Equal(3, Taint.CombineRank(1, 3));
        Assert.Equal(3, Taint.CombineRank(3, 1));
        Assert.Equal(2, Taint.CombineRank(2, 2));
        Assert.Equal(0, Taint.CombineRank(0, 0));
    }
}

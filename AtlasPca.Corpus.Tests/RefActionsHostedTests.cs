using AtlasPca.ActionsKit;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Differential replay of the hosted action registry (publish gate, verifier view) and source sync against the TypeScript reference.</summary>
public class RefActionsHostedTests
{
    const string M = "ref-actions-hosted";
    static IEnumerable<D> Ds(object? l) => ((L)l!).Select(x => (D)x!);
    static ActionHosted.HostedView View(L a) => ActionHosted.HostedViewOf(Ds(a[0]), a[1]);

    [Fact] public void PublishGate() => Base.Check(M, "publishGate", a => ActionHosted.PublishGate((D)a[0]!));
    [Fact] public void RulesDocError() => Base.Check(M, "rulesDocError", a => ActionHosted.RulesDocError(a[0], "acme", Ds(a[1])));
    [Fact] public void VersionDigest() => Base.Check(M, "hostedVersionDigest", a => ActionHosted.HostedVersionDigest((D)a[0]!));
    [Fact] public void ViewLookup() => Base.Check(M, "viewLookup", a => View(a).Lookup((string)a[2]!));
    [Fact] public void ViewProvenance() => Base.Check(M, "viewProvenance", a => View(a).Provenance(new D { ["verb"] = a[2] }));
    [Fact] public void ViewFloor() => Base.Check(M, "viewFloor", a => View(a).Floor((string)a[2]!, (D)a[3]!, ((L)a[4]!).Cast<string>()));
    [Fact] public void ViewUndo() => Base.Check(M, "viewUndo", a => View(a).UndoPlan((D)a[2]!));
    [Fact] public void CallContext() => Base.Check(M, "hostedCallContext", a => ActionHosted.HostedCallContext(a[0] as D, a[1] as D));
    [Fact] public void RateKeys() => Base.Check(M, "rateKeysOf", a => ActionHosted.RateKeysOf((D)a[0]!, (D)a[1]!));
    [Fact] public void GrantFacts() => Base.Check(M, "grantFactsOf", a => ActionHosted.GrantFactsOf(a[0]));

    [Fact]
    public void SyncSource() => Base.Check(M, "syncSource", a =>
        ActionSync.SyncSource(Ds(a[0]), Ds(a[1]), new string('S', 43), new Num("1800000000"), a[2] as D, null, _ => (bool)a[3]!));

    [Fact] public void SyncText() => Base.Check(M, "syncText", a => ActionSync.SyncText((D)a[0]!));

    [Fact]
    public void Covers() { Base.Covers(M, new[] { "publishGate", "rulesDocError", "hostedVersionDigest", "viewLookup", "viewProvenance", "viewFloor", "viewUndo",
        "hostedCallContext", "rateKeysOf", "grantFactsOf", "syncSource", "syncText" }); Assert.Equal(728, Base.Total(M)); }
}

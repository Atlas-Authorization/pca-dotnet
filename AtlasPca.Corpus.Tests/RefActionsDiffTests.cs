using AtlasPca.ActionsKit;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Differential replay of the action id patterns, effective profiles and semantic diffs against the TypeScript reference.</summary>
public class RefActionsDiffTests
{
    const string M = "ref-actions-diff";

    static Func<D, bool>? Conf(L a, int i) => a.Count > i && a[i] is bool b ? (_ => b) : null;
    static IEnumerable<D> Defs(object? o) => ((L)o!).Select(x => (D)x!);

    static object? Reversed(object? v) => v switch
    {
        L l => l.Select(Reversed).ToList(),
        D d => d.Keys.Reverse().ToDictionary(k => k, k => Reversed(d[k])),
        _ => v,
    };

    /// <summary>Key order is not meaning: a definition with every object key reversed (a stored copy against a fresh one) diffs as equal, both ways.</summary>
    [Fact]
    public void KeyOrderIsNotMeaning()
    {
        var def = (D)Pca.ParseJson("{\"v\":1,\"kind\":\"pca-action-def\",\"verb\":\"x.charge\",\"title\":\"t\",\"effects\":[\"pay\"],\"resource\":{\"type\":\"x.customer\",\"id\":{\"prefix\":\"cus_\",\"class\":\"any_safe\",\"len\":[8,64]},\"scope\":\"one\"},\"params\":{\"amount\":{\"type\":\"integer\",\"min\":1,\"max\":100,\"role\":\"money.amount\"},\"customer\":{\"type\":\"string\",\"max_len\":64}},\"reversibility\":\"irreversible\"}")!;
        var rev = (D)Reversed(def)!;
        Assert.Equal("equal", ActionDiff.DiffDefs(def, rev, Actions.CoreRegistry)["class"]);
        Assert.Equal("equal", ActionDiff.DiffDefs(rev, def, Actions.CoreRegistry)["class"]);
        Assert.Equal(ActionDiff.SortedJson(def), ActionDiff.SortedJson(rev));
        Assert.Equal("[2,1]", ActionDiff.SortedJson(new L { new Num("2"), new Num("1") }));
    }

    [Fact] public void IdMatches() => Base.Check(M, "idMatches", a => ActionIdPattern.IdMatches(a[0], a[1]));
    [Fact] public void IdPatternContains() => Base.Check(M, "idPatternContains", a => ActionIdPattern.IdPatternContains(a[0], a[1]));
    [Fact] public void Join() => Base.Check(M, "join", a => Actions.Join((D)a[0]!, (D)a[1]!));
    [Fact] public void Leq() => Base.Check(M, "leq", a => Actions.Leq((D)a[0]!, (D)a[1]!));
    [Fact] public void ProfileEq() => Base.Check(M, "profileEq", a => ActionEffective.ProfileEq((D)a[0]!, (D)a[1]!));
    [Fact] public void Effective() => Base.Check(M, "effective", a => ActionEffective.EffectiveWith((D)a[0]!, Actions.CoreRegistry, Conf(a, 1)));
    [Fact] public void HintTraits() => Base.Check(M, "hintTraits", a => Actions.HintTraits((D)a[0]!));
    [Fact] public void PrulesViolations() => Base.Check(M, "prulesViolations", a => ActionEffective.PrulesViolations((D)a[0]!));
    [Fact] public void EffWithTrait() => Base.Check(M, "effWithTrait", a => ActionEffective.EffWithTrait((D)a[0]!, (string)a[1]!, Actions.CoreRegistry));
    [Fact] public void RequiredPrulesViolated() => Base.Check(M, "requiredPrulesViolated", a => ActionEffective.RequiredPrulesViolated((D)a[0]!, (D)a[1]!));
    [Fact] public void DiffDefs() => Base.Check(M, "diffDefs", a => ActionDiff.DiffDefs((D)a[0]!, (D)a[1]!, Actions.CoreRegistry, Conf(a, 2)));
    [Fact] public void DiffDefsAuthoring() => Base.Check(M, "diffDefsAuthoring", a => ActionDefDiff.DiffDefs((D)a[0]!, (D)a[1]!, Actions.CoreRegistry));
    [Fact] public void DiffIsFree() => Base.Check(M, "diffIsFree", a => ActionDiff.DiffIsFree((string)a[0]!));
    [Fact] public void DiffPacks() => Base.Check(M, "diffPacks", a => ActionDefDiff.DiffPacks(Defs(a[0]), Defs(a[1]), Actions.CoreRegistry));

    [Fact]
    public void Covers() { Base.Covers(M, new[] { "idMatches", "idPatternContains", "join", "leq", "profileEq", "effective", "hintTraits", "prulesViolations", "effWithTrait", "requiredPrulesViolated", "diffDefs", "diffDefsAuthoring", "diffIsFree", "diffPacks" }); Assert.Equal(1302, Base.Total(M)); }
}

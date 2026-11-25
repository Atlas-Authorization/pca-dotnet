using AtlasPca.ActionsKit;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Differential replay of the action-kit migration shims and signed evolution records against the TypeScript reference.</summary>
public class RefActionsCompatTests
{
    const string C = "ref-actions-compat";
    const string E = "ref-actions-evolve";

    static IEnumerable<D> Defs(object? o) => ((L)o!).Select(x => (D)x!);
    static Func<D, bool>? Conf(L a, int i) => a.Count > i && a[i] is bool b ? (_ => b) : null;

    [Fact] public void NormalizeReversibility() => Base.Check(C, "normalizeReversibility", a => ActionCompat.NormalizeReversibility(a[0]));
    [Fact] public void LegacyOperationsClass() => Base.Check(C, "legacyOperationsClass", a => ActionCompat.LegacyOperationsClass((string)a[0]!));
    [Fact] public void MaxRevOf() => Base.Check(C, "maxRevOf", a => ActionCompat.MaxRevOf((string)a[0]!, (string)a[1]!));
    [Fact] public void UnitTagOf() => Base.Check(C, "unitTagOf", a => ActionCompat.UnitTagOf((D)a[0]!));
    [Fact] public void BlastOfFloat() => Base.Check(C, "blastOfFloat", a => ActionCompat.BlastOfFloat(a[0]));
    [Fact] public void BlastExactOfFloat() => Base.Check(C, "blastExactOfFloat", a => ActionCompat.BlastExactOfFloat(a[0]));
    [Fact] public void FromCatalogSpec() => Base.Check(C, "fromCatalogSpec", a => ActionCompat.FromCatalogSpec((D)a[0]!, a.Count > 1 ? a[1] as D : null));
    [Fact] public void FromCatalog() => Base.Check(C, "fromCatalog", a => ActionCompat.FromCatalog(Defs(a[0]), a.Count > 1 ? a[1] as D : null));
    [Fact] public void CompatCovers() { Base.Covers(C, new[] { "normalizeReversibility", "legacyOperationsClass", "maxRevOf", "unitTagOf", "blastOfFloat", "blastExactOfFloat", "fromCatalogSpec", "fromCatalog" }); Assert.Equal(133, Base.Total(C)); }

    [Fact] public void EvolutionRecords() => Base.Check(E, "evolutionRecords", a => ActionEvolve.EvolutionRecords((string)a[0]!, Defs(a[1]), Defs(a[2]), Actions.CoreRegistry, Conf(a, 3)));
    [Fact] public void SignEvolution() => Base.Check(E, "signEvolution", a => ActionEvolve.SignEvolution(Defs(a[0]), (string)a[1]!, Base.Bytes(a[2])));
    [Fact] public void EvolutionError() => Base.Check(E, "evolutionError", a => ActionEvolve.EvolutionError((string)a[0]!, Defs(a[1]), Defs(a[2]), (L)a[3]!, a[4], Actions.CoreRegistry, Conf(a, 5)));
    [Fact] public void EvolveCovers() { Base.Covers(E, new[] { "evolutionRecords", "signEvolution", "evolutionError" }); Assert.Equal(154, Base.Total(E)); }
}

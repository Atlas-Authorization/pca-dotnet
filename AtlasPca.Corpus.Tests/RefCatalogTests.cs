using AtlasPca;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Replay of the connector action catalog (test-data/ref-catalog.json.gz): entry validation, the fail-closed uncatalogued entry, the built-in rows with their
/// digest and blast presets, and a catalog driven through get / forConnector / all / resolve / resolveAction / digest / assertPinned / extend. Entries are given as
/// they are (not validated); an operation that refuses answers {"$err": true}. Non-finite numbers arrive as {"$num": text}.</summary>
public class RefCatalogTests
{
    const string M = "ref-catalog";

    static object? Nums(object? v) => v switch
    {
        D m when m.Count == 1 && m.TryGetValue("$num", out var t) && t is string s => s == "NaN" ? double.NaN : s == "Infinity" ? double.PositiveInfinity : double.NegativeInfinity,
        D m => m.ToDictionary(e => e.Key, e => Nums(e.Value)),
        L l => l.Select(Nums).ToList(),
        _ => v,
    };

    static string? S(L op, int i) => op.Count > i ? op[i] as string : null;

    static D J(CatalogAction a) => CatalogSpecs.ToJson(a);

    static L Js(IEnumerable<CatalogAction> xs) => xs.Select(x => (object?)J(x)).ToList();

    static Catalog Build(object? actions) => actions == null ? Catalog.Default : new Catalog(((L)Nums(actions)!).Select(x => CatalogSpecs.FromJson((D)x!)));

    [Fact] public void DefineAction() => Base.Check(M, "defineAction", a => Catalog.DefineActionJson(Nums(a[0])), min: 39);

    [Fact] public void UncataloguedSpec() => Base.Check(M, "uncataloguedSpec", a => J(Catalog.UncataloguedSpec((string)a[0]!)), min: 13);

    [Fact]
    public void Builtin() => Base.Check(M, "builtin", _ => new D { ["actions"] = Js(Catalog.Builtin), ["digest"] = Catalog.Default.Digest(), ["blast"] = Catalog.Blast }, min: 1);

    [Fact]
    public void CatalogOps() => Base.Check(M, "catalog", a =>
    {
        var cat = Build(a[0]);
        var res = new L();
        foreach (var o in (L)a[1]!)
        {
            var op = (L)o!;
            try
            {
                // an operation argument that is absent is undefined in the reference: no entry has it, so a lookup answers nothing
                res.Add((op[0] as string) switch
                {
                    "get" => S(op, 1) is { } v && cat.Get(v) is { } g ? J(g) : null,
                    "forConnector" => S(op, 1) is { } c ? Js(cat.ForConnector(c)) : new L(),
                    "all" => Js(cat.All()),
                    "resolve" => S(op, 1) is { } c && S(op, 2) is { } x && cat.Resolve(c, x) is { } r ? J(r) : null,
                    "resolveAction" => ResolveAction(cat, S(op, 1)!),
                    "digest" => cat.Digest(),
                    "assertPinned" => AssertPinned(cat, op[1]),
                    "extend" => Extend(cat, op[1]),
                    _ => throw new InvalidOperationException("bad op"),
                });
            }
            catch (Exception) { res.Add(new D { ["$err"] = true }); }
        }
        return res;
    }, min: 22);

    static D ResolveAction(Catalog cat, string verb)
    {
        var (spec, catalogued) = cat.ResolveAction(verb);
        return new D { ["spec"] = J(spec), ["catalogued"] = catalogued };
    }

    static object AssertPinned(Catalog cat, object? expected)
    {
        var e = expected is "$self" ? cat.Digest() : expected;
        // a pin that is not a string never equals a digest
        cat.AssertPinned(e as string ?? throw new InvalidOperationException("the pin is not a string"));
        return true;
    }

    static D Extend(Catalog cat, object? extra)
    {
        var e = cat.Extend(((L)Nums(extra)!).Select(x => CatalogSpecs.FromJson((D)x!)));
        return new D { ["all"] = Js(e.All()), ["digest"] = e.Digest() };
    }

    [Fact]
    public void Covers()
    {
        Base.Covers(M, new[] { "defineAction", "uncataloguedSpec", "builtin", "catalog" });
        Assert.Equal(75, Base.Total(M));
    }
}

using System.Text;
using AtlasPca;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

// Pinned to packages/pca-actions/src: traits.ts closure, def.ts isReadOnly, normalize.ts worstReversibility and normalize, digest.ts sortedDigests.
public class ActionsR3KillTests
{
    static readonly L Read = new() { "read" };
    static readonly D Bool = new() { ["type"] = "boolean" };

    static D Def(L effects, D? prms = null) => new()
    {
        ["kind"] = Actions.ActionDefKind, ["verb"] = "acme.thing.do", ["title"] = "t", ["effects"] = effects,
        ["resource"] = new D { ["type"] = "thing", ["id"] = new D(), ["scope"] = "one" }, ["params"] = prms ?? new D(),
    };

    static Dictionary<string, D> P(D p, string name = "p") => new() { [name] = p };

    // no default in the declaration: an uncovered domain reads "irreversible", a covered one the worst mapped class
    static string Wr(object? map, params string[] domain) => Actions.WorstReversibility(
        new D { ["by"] = "p", ["map"] = map },
        P(new D { ["type"] = "string", ["values"] = new L(domain) }));

    // a boolean parameter with both spellings mapped: only the class ranks decide
    static string Ranks(object? t) => Actions.WorstReversibility(
        new D { ["by"] = "p", ["map"] = new D { ["true"] = t, ["false"] = "reversible" } }, P(Bool));

    static D BothMapped(object? by) => new() { ["by"] = by, ["map"] = new D { ["true"] = "reversible", ["false"] = "reversible" } };

    [Fact]
    public void ClosureVisitsEachIdOnceSoAnImpliesCycleTerminates()
    {
        var reg = new Dictionary<string, D> { ["a"] = new D { ["implies"] = new L { "b" } }, ["b"] = new D { ["implies"] = new L { "a" } } };
        List<string>? got = null;
        var walk = new Thread(() => got = Actions.Closure(reg, new L { "a" })) { IsBackground = true };
        walk.Start();
        Assert.True(walk.Join(TimeSpan.FromSeconds(20)), "the closure walk did not terminate");
        Assert.Equal(new[] { "a", "b" }, got);
    }

    [Fact]
    public void NoEffectsIsNotReadOnly()
    {
        Assert.Equal("irreversible", (string)Actions.Normalize(Def(new L()))["reversibility"]!);
        Assert.Equal("reversible", (string)Actions.Normalize(Def(Read))["reversibility"]!);
        Assert.Equal("irreversible", (string)Actions.Normalize(Def(new L { "read", "send" }))["reversibility"]!);
    }

    [Fact]
    public void AnUnknownClassRanksBelowEveryClass()
    {
        Assert.Equal("reversible", Ranks("bogus"));
        Assert.Equal("reversible", Ranks(new L { "bogus" }));
        Assert.Equal("reversible", Ranks(new L { "reversible", "irreversible" }));
        Assert.Equal("reversible", Ranks(true));
        Assert.Equal("reversible", Ranks(null));
        Assert.Equal("reversible", Ranks(IntentJs.OfLong(1)));
        Assert.Equal("reversible", Ranks(new D()));
    }

    [Fact]
    public void AOneElementArrayNamesItsElement()
    {
        Assert.Equal("irreversible", Ranks(new L { "irreversible" }));
        Assert.Equal("rate_limited", Ranks(new L { "rate_limited" }));
    }

    [Fact]
    public void OnlyAnArrayIsReadThroughItsText() =>
        Assert.Equal("reversible", Ranks(new StringBuilder("irreversible")));

    [Fact]
    public void ANullOrAbsentMapThrowsTheObjectValuesError()
    {
        const string msg = "Cannot convert undefined or null to object";
        Assert.Equal(msg, Assert.Throws<ArgumentException>(() => Actions.WorstReversibility(new D { ["by"] = "p" }, P(Bool))).Message);
        Assert.Equal(msg, Assert.Throws<ArgumentException>(() => Actions.WorstReversibility(new D { ["by"] = "p", ["map"] = null }, P(Bool))).Message);
    }

    [Fact]
    public void ANullDeclarationThrowsTheMemberReadError() =>
        Assert.Equal("Cannot read properties of null (reading 'by')",
            Assert.Throws<ArgumentException>(() => Actions.WorstReversibility(null, P(Bool))).Message);

    [Fact]
    public void NonArrayValuesThrowTheEveryError()
    {
        var r = new D { ["by"] = "p", ["map"] = new D { ["a"] = "reversible" } };
        var ex = Assert.Throws<ArgumentException>(() => Actions.WorstReversibility(r, P(new D { ["type"] = "string", ["values"] = "abc" })));
        Assert.Equal("domain.every is not a function", ex.Message);
    }

    [Fact]
    public void APrimitiveMapHasNoOwnMembers()
    {
        foreach (var map in new object[] { true, IntentJs.OfLong(5) })
        {
            Assert.Equal("irreversible", Wr(map, "0"));
            Assert.Equal("irreversible", Wr(map, "length"));
            Assert.Equal("irreversible", Wr(map, "zzz"));
        }
    }

    [Fact]
    public void AnArrayOrStringMapOwnsItsLengthEvenWhenEmpty()
    {
        Assert.Equal("reversible", Wr(new L(), "length"));
        Assert.Equal("reversible", Wr("", "length"));
        Assert.Equal("reversible", Wr(new L { "reversible" }, "length"));
        Assert.Equal("irreversible", Wr(new L(), ""));
        Assert.Equal("irreversible", Wr(new L { "reversible" }, ""));
    }

    [Fact]
    public void AnArrayOrStringMapOwnsExactlyItsCanonicalIndexes()
    {
        var one = new L { "reversible" };
        Assert.Equal("reversible", Wr(one, "0"));
        Assert.Equal("irreversible", Wr(one, "1"));
        Assert.Equal("irreversible", Wr(new L(), "0"));
        Assert.Equal("irreversible", Wr(new L { "reversible", "reversible" }, "01"));
        Assert.Equal("reversible", Wr("ab", "1"));
        Assert.Equal("irreversible", Wr("ab", "2"));
    }

    [Fact]
    public void ANonStringByIsAPropertyKey()
    {
        Assert.Equal("reversible", Actions.WorstReversibility(BothMapped(new L { "p" }), P(Bool)));
        Assert.Equal("reversible", Actions.WorstReversibility(BothMapped(IntentJs.OfLong(5)), P(Bool, "5")));
        // an absent by reads params[undefined]
        var absent = new D { ["map"] = new D { ["true"] = "reversible", ["false"] = "reversible" } };
        Assert.Equal("reversible", Actions.WorstReversibility(absent, P(Bool, "undefined")));
        Assert.Equal("irreversible", Actions.WorstReversibility(absent, P(Bool)));
    }

    [Fact]
    public void ANonStringDomainValueIsAPropertyKey()
    {
        static string Over(object? value, string key) => Actions.WorstReversibility(
            new D { ["by"] = "p", ["map"] = new D { [key] = "reversible" } },
            P(new D { ["type"] = "string", ["values"] = new L { value } }));
        Assert.Equal("reversible", Over(new L { "a" }, "a"));
        Assert.Equal("reversible", Over(IntentJs.OfLong(5), "5"));
    }

    [Fact]
    public void NormalizeCopiesValues()
    {
        var values = new L { "x", "y" };
        var n = Actions.Normalize(Def(Read, new D { ["p"] = new D { ["type"] = "string", ["values"] = values } }));
        var p = (D)((D)n["params"]!)["p"]!;
        var got = (L)p["values"]!;
        Assert.NotSame(values, got);
        Assert.Equal(values, got);
        Assert.False(p.ContainsKey(""));
    }

    [Fact]
    public void NormalizeSortsParamsByName()
    {
        var one = new D { ["type"] = "string" };
        var n = Actions.Normalize(Def(Read, new D { ["b"] = one, ["c"] = one, ["a"] = one }));
        Assert.Equal(new[] { "a", "b", "c" }, ((D)n["params"]!).Keys.ToList());
    }

    [Fact]
    public void NormalizeSortsSideEffectsByTargetThenKind()
    {
        static D Se(string target, string kind) => new() { ["target"] = target, ["kind"] = kind };
        var d = Def(Read);
        d["side_effects"] = new L { Se("t", "send"), Se("t", "create"), Se("a", "read") };
        var got = ((L)Actions.Normalize(d)["side_effects"]!).Select(s => { var e = (D)s!; return (string)e["target"]! + "/" + (string)e["kind"]!; }).ToList();
        Assert.Equal(new[] { "a/read", "t/create", "t/send" }, got);
    }

    [Fact]
    public void ADuplicateDigestIsRefused()
    {
        var ex = Assert.Throws<ActionKitError>(() => Actions.PackRoot(new[] { "x", "x" }));
        Assert.Equal("duplicate_def", ex.Code);
        Assert.Equal("a pack lists a def digest twice", ex.Message);
    }

    [Fact]
    public void AnEmptyPackIsRefused()
    {
        var ex = Assert.Throws<ActionKitError>(() => Actions.PackRoot(Array.Empty<string>()));
        Assert.Equal("empty_pack", ex.Code);
        Assert.Equal("a pack has at least one def", ex.Message);
    }
}

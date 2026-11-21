using System.Security.Cryptography;
using System.Text;
using AtlasPca;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

// Pinned to packages/pca-actions/src: validate.ts (validateParam unit / accumulates, aliases, jsonProfileError), idpattern.ts; packages/pca/src/approval-render.ts WORDS.
public class K05FinalKillTests
{
    static D Def(D prms, Action<D>? edit = null)
    {
        var d = new D
        {
            ["v"] = IntentJs.OfLong(1), ["kind"] = Actions.ActionDefKind, ["verb"] = "acme.thing.do", ["title"] = "t", ["effects"] = new L { "read" },
            ["resource"] = new D { ["type"] = "thing", ["id"] = "*", ["scope"] = "one" }, ["params"] = prms,
            ["review"] = new D { ["state"] = "authored" },
        };
        edit?.Invoke(d);
        return d;
    }

    static D Int(D extra)
    {
        var p = new D { ["type"] = "integer" };
        foreach (var (k, v) in extra) p[k] = v;
        return p;
    }

    static string? Err(D prms) => Actions.ValidateDef(Def(prms));

    [Fact]
    public void TheBaselineDefIsValid()
    {
        Assert.Null(Err(new D { ["p"] = Int(new D { ["unit"] = new D { ["kind"] = "count" } }) }));
        Assert.Null(Err(new D { ["p"] = Int(new D { ["accumulates"] = new L { "a_b", "c" } }) }));
    }

    [Fact]
    public void AMoneyCurrencyReferenceHasExactlyTheFromMember()
    {
        // join(",") of {from, ""} is "from," in the reference; a joiner dropped from the join would read it as "from"
        var money = (object ccy) => Int(new D { ["unit"] = new D { ["kind"] = "money", ["exp"] = IntentJs.OfLong(2), ["ccy"] = ccy } });
        Assert.Null(Err(new D { ["p"] = money(new D { ["from"] = "cur" }), ["cur"] = new D { ["type"] = "string" } }));
        Assert.Equal("p: unit.ccy.from must name a declared parameter",
            Err(new D { ["p"] = money(new D { ["from"] = "cur", [""] = IntentJs.OfLong(1) }), ["cur"] = new D { ["type"] = "string" } }));
    }

    [Fact]
    public void ANonMoneyUnitHasExactlyTheKindMember()
    {
        Assert.Equal("p: unit has unknown members", Err(new D { ["p"] = Int(new D { ["unit"] = new D { ["kind"] = "count", [""] = IntentJs.OfLong(1) } }) }));
        Assert.Equal("p: unit has unknown members", Err(new D { ["p"] = Int(new D { ["unit"] = new D { ["kind"] = "count", ["x"] = IntentJs.OfLong(1) } }) }));
    }

    [Fact]
    public void EveryAccumulatesIdMustBeAUnitId()
    {
        Assert.Equal("p: accumulates must be 1..8 distinct unit ids", Err(new D { ["p"] = Int(new D { ["accumulates"] = new L { "a_b", "BAD UNIT" } }) }));
        Assert.Equal("p: accumulates must be 1..8 distinct unit ids", Err(new D { ["p"] = Int(new D { ["accumulates"] = new L { "BAD UNIT", "a_b" } }) }));
        Assert.Equal("p: accumulates must be 1..8 distinct unit ids", Err(new D { ["p"] = Int(new D { ["accumulates"] = new L { "a", 5L } }) }));
    }

    static string Alias(int len)
    {
        var s = new string('a', 32);
        for (int rem = len - 32; rem > 0;) { int n = Math.Min(32, rem - 1); s += "." + new string('c', n); rem -= n + 1; }
        return s;
    }

    [Fact]
    public void AnAliasMayBeExactlyTheVerbByteLimit()
    {
        Assert.Equal(128, Alias(128).Length);
        Assert.Null(Actions.ValidateDef(Def(new D(), d => d["aliases"] = new L { Alias(128) })));
        Assert.Equal("aliases must be distinct verb-shaped names other than the verb", Actions.ValidateDef(Def(new D(), d => d["aliases"] = new L { Alias(129) })));
    }

    [Fact]
    public void AFaultWhileValidatingARefusesTheDef()
    {
        Actions.DefFaultHook = () => throw new InvalidOperationException("boom");
        try { Assert.Equal("malformed def: boom", Actions.ValidateDef(Def(new D()))); }
        finally { Actions.DefFaultHook = null; }
        Assert.Null(Actions.ValidateDef(Def(new D())));
    }

    [Fact]
    public void OnlyJsonValuesAreAllowed()
    {
        Assert.Equal("only JSON values are allowed", Actions.JsonProfileError(new object()));
        Assert.Equal("only JSON values are allowed", Actions.JsonProfileError(DateTime.UnixEpoch));
    }

    [Fact]
    public void AnIdIsDrawnFromTheSafeCharacters()
    {
        const string exact = "resource.id.exact must be 1..128 safe characters", prefix = "resource.id.prefix must be up to 32 safe characters";
        foreach (var ok in new[] { "a", "Z", "0", "9", "m", "M", ".", "_", "-", ":", "/", "aZ09._-:/" })
        {
            Assert.Null(Actions.IdPatternError(new D { ["exact"] = ok }));
            Assert.Null(Actions.IdPatternError(new D { ["prefix"] = ok, ["class"] = "alnum", ["len"] = new L { IntentJs.OfLong(1), IntentJs.OfLong(2) } }));
        }
        foreach (var bad in new[] { "", " ", "a b", "a+b", "a@b", "é", "a\\b", "a~b", "a|b", "a`b" })
        {
            Assert.Equal(exact, Actions.IdPatternError(new D { ["exact"] = bad }));
            if (bad.Length > 0)
                Assert.Equal(prefix, Actions.IdPatternError(new D { ["prefix"] = bad, ["class"] = "alnum", ["len"] = new L { IntentJs.OfLong(1), IntentJs.OfLong(2) } }));
        }
    }

    [Fact]
    public void TheConfirmationWordListIsTheReferenceList()
    {
        Assert.Equal(256, Approval.Words.Length);
        var h = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(string.Join(",", Approval.Words)))).ToLowerInvariant();
        Assert.Equal("43bd0a77439a7b47058f7982b608492c0df941aa713d93055951c08373b1fc8d", h);
    }
}

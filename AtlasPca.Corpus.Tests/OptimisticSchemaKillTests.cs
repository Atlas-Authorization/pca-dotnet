using AtlasPca;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Fail-closed paths of the optimistic wire checks (nothing there throws on hostile input) and of the schema shape check (action-schema.ts:322, :417).</summary>
public class OptimisticSchemaKillTests
{
    sealed class Hostile : IEqualityComparer<string>
    {
        public bool Armed;
        public bool Equals(string? a, string? b) => Armed ? throw new InvalidOperationException("hostile") : a == b;
        public int GetHashCode(string s) => Armed ? throw new InvalidOperationException("hostile") : 0;
    }
    // an empty dictionary answers a lookup without asking its comparer, so it holds one member before it turns hostile
    static D HostileDict()
    {
        var h = new Hostile();
        var d = new D(h) { ["x"] = null };
        h.Armed = true;
        return d;
    }

    static D Claim(object? extra) => new()
    {
        ["pcactn_digest"] = "d", ["claimed_r"] = new Num("1"), ["issued_at"] = new Num("1000"), ["challenge_window_ms"] = new Num("5000"), ["sig"] = "x", ["extra"] = extra,
    };
    static string Check(object? c) => Optimistic.ClaimCheck(c, "d", new string('A', 43), 1000, ChallengeWindowPolicy.Default);

    [Fact]
    public void AClaimTheLenientFormRefusesIsMalformedAndABadSignatureIsNot()
    {
        Assert.Equal("malformed", Check(Claim(double.NaN)));
        Assert.Equal("malformed", Check(Claim(new object())));
        Assert.Equal("signature", Check(Claim("fine")));
    }

    [Fact]
    public void AWireCheckThatThrowsAnswersMalformed()
    {
        Assert.Equal("malformed", Check(HostileDict()));
        Assert.Equal("malformed", Optimistic.FraudProofWireCheck(new D(), HostileDict()));
        Assert.Equal("malformed", Optimistic.SettlementWireCheck(HostileDict(), "g"));
    }

    static D Open(object? extra) => new()
    {
        ["claimId"] = "c", ["action"] = "open", ["amount"] = new Num("5"), ["from"] = "a", ["to"] = "b", ["at"] = new Num("1"), ["evidenceDigest"] = "", ["sig"] = "x", ["extra"] = extra,
    };

    [Fact]
    public void ASettlementTheLenientFormRefusesIsMalformed()
    {
        Assert.Equal("malformed", Optimistic.SettlementWireCheck(Open(double.NaN), new string('A', 43)));
        Assert.Equal("signature", Optimistic.SettlementWireCheck(Open("fine"), new string('A', 43)));
    }

    static D Slash(bool withKey)
    {
        var split = new D
        {
            ["amount"] = new Num("5"), ["challengerReward"] = new Num("0"), ["victimCompensation"] = new Num("0"), ["treasuryRemainder"] = new Num("5"),
            ["victimAccount"] = "v", ["treasuryAccount"] = "b",
        };
        if (withKey) split["challengerAccount"] = null;
        return new D
        {
            ["claimId"] = "c", ["action"] = "slash", ["amount"] = new Num("5"), ["from"] = "a", ["to"] = "b", ["at"] = new Num("1"), ["evidenceDigest"] = "e", ["sig"] = "x", ["split"] = split,
        };
    }

    [Fact]
    public void AnAnonymousSlashMustNameTheChallengerAsNull()
    {
        Assert.Equal("signature", Optimistic.SettlementWireCheck(Slash(true), new string('A', 43)));
        Assert.Equal("split", Optimistic.SettlementWireCheck(Slash(false), new string('A', 43)));
    }

    static string? Shape(string members) =>
        ActionSchema.ShapeError(Pca.ParseJson("""{"v":1,"kind":"pca-action-schema","site":"s","aud":"a","version":"1",""" + members + "}"), signed: false);
    const string Verbs = """ "verbs":[{"verb":"x","kind":"read","params":{}}] """;

    [Fact]
    public void AV1VerbCannotCarryAV2Member()
    {
        Assert.Null(Shape(Verbs));
        Assert.Equal("verb entry: unknown member 'traits'", Shape(""" "verbs":[{"verb":"x","kind":"read","params":{},"traits":[]}] """));
    }

    [Fact]
    public void AnUnsignedSchemaMustBeStrictlyCanonical() =>
        Assert.StartsWith("malformed schema: ", Shape(Verbs + """, "state":[1.0] """));

    [Fact]
    public void AReservedParameterNameIsRefused() =>
        Assert.Equal("verb 'x': parameter name 'action.params.__proto__' is reserved (__proto__ / constructor / prototype)",
            Shape(""" "verbs":[{"verb":"x","kind":"read","params":{"action.params.__proto__":{"type":"string"}}}] """));
}

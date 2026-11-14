using AtlasPca;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>k05 differential oracle of the action kit (test-data/k05-actions.json.gz, TS reference packages/pca-actions/src: validate,
/// idpattern, traits, normalize, digest, effective, confirmation). A case with <c>cmp: "code"</c> carries the reference's own exception
/// text after its code: only the <c>code: </c> prefix is compared.</summary>
public class K05ActionsDiffTests
{
    const string M = "actions";

    static Dictionary<string, D> Reg(object? custom) => custom is L c ? Actions.ExtendRegistry(Actions.CoreRegistry, c) : Actions.CoreRegistry;

    static string Code(string s) { var i = s.IndexOf(": ", StringComparison.Ordinal); return i < 0 ? s : s[..(i + 2)]; }
    static bool CodeEq(D c, object? have) =>
        c.GetValueOrDefault("cmp") is "code" ? c["out"] is string w && have is string h && Code(w) == Code(h) : K05.Eq(c["out"], have);

    // a JS property read of a non-object yields undefined (an empty map); of null, a TypeError
    static D Obj(object? a) => a is D d ? d : a == null ? null! : new D();

    [Fact] public void ValidateDef() => K05.Check(M, "validateDef", a => Actions.ValidateDef(a[0]), eq: CodeEq, min: 30000);
    [Fact] public void IsRole() => K05.Check(M, "isRole", a => Actions.IsRole(a[0]));
    [Fact] public void IsFormat() => K05.Check(M, "isFormat", a => Actions.IsFormat(a[0]));
    [Fact] public void IsContextKey() => K05.Check(M, "isContextKey", a => Actions.IsContextKey(a[0]));
    [Fact] public void ParamNameError() => K05.Check(M, "paramNameError", a => Actions.ParamNameError((string)a[0]!));
    [Fact] public void JsonProfileError() => K05.Check(M, "jsonProfileError", a => Actions.JsonProfileError(a[0]));
    [Fact] public void IdPatternError() => K05.Check(M, "idPatternError", a => Actions.IdPatternError(a[0]));
    [Fact] public void ProfileError() => K05.Check(M, "profileError", a => Actions.ProfileError(a[0]));

    // typed (list, bool) port: a non-array trait list cannot be passed (the reference refuses each with its size message)
    [Fact]
    public void RegistryError() => K05.Check(M, "registryError", a => Actions.RegistryError((L)a[0]!, a[1] is true),
        skip: c => K05.Args(c)[0] is L ? null : "not an array (typed port)");

    [Fact] public void Closure() => K05.Check(M, "closure", a => Actions.Closure(Reg(a[0]), (L)a[1]!));
    [Fact] public void FloorOf() => K05.Check(M, "floorOf", a => Actions.FloorOf(Reg(a[0]), (L)a[1]!));
    [Fact] public void TopTraits() => K05.Check(M, "topTraits", a => Actions.TopTraits(Reg(a[0])));
    [Fact] public void TraitsDigest() => K05.Check(M, "traitsDigest", a => Actions.TraitsDigest(Reg(a[0])));
    [Fact] public void TablesDigest() => K05.Check(M, "tablesDigest", a => Actions.TablesDigest());
    [Fact] public void FloorDecision() => K05.Check(M, "floorDecision", a => Actions.FloorDecision((D)a[0]!, (D)a[1]!, (D)a[2]!));

    [Fact]
    public void WorstReversibility() => K05.Check(M, "worstReversibility", a =>
        Actions.WorstReversibility(a[0], ((D)a[1]!).ToDictionary(e => e.Key, e => (D)e.Value!)));

    [Fact] public void SensitivityFloor() => K05.Check(M, "sensitivityFloor", a => Actions.SensitivityFloor((D)a[0]!));

    [Fact]
    public void ImpliedFromFacts() => K05.Check(M, "impliedFromFacts", a =>
    {
        var f = (D)a[0]!;
        return Actions.ImpliedFromFacts(((L)f["effects"]!).Select(x => (string)x!), ((L)f["params"]!).Cast<D>(), f.GetValueOrDefault("scope") as string, (string)f["worstRev"]!);
    });

    [Fact] public void Normalize() => K05.Check(M, "normalize", a => Actions.Normalize((D)a[0]!));
    [Fact] public void DefDigest() => K05.Check(M, "defDigest", a => Actions.DefDigest((D)a[0]!));
    [Fact] public void DeclProfile() => K05.Check(M, "declProfile", a => Actions.DeclProfile((D)a[0]!));
    [Fact] public void HintTraits() => K05.Check(M, "hintTraits", a => Actions.HintTraits((D)a[0]!));
    [Fact] public void Effective() => K05.Check(M, "effective", a => Actions.Effective((D)a[0]!, Actions.CoreRegistry, a[1]));
    [Fact] public void ReviewerPinsError() => K05.Check(M, "reviewerPinsError", a => Actions.ReviewerPinsError(a[0]));

    [Fact]
    public void ReviewMessage() => K05.Check(M, "reviewMessage", a =>
    {
        var b = (D)a[0]!;
        return Actions.ReviewMessage(b, ((L)b["final_traits"]!).Cast<string>().ToList());
    });

    // TS verifyAttestation(d, {pins, registry: CORE}).ok
    [Fact]
    public void IsConfirmed() => K05.Check(M, "isConfirmed", a => Actions.AttestationError((D)a[0]!, Actions.CoreRegistry, a[1]) == null);
    [Fact] public void FactsDigest() => K05.Check(M, "factsDigest", a => Actions.FactsDigest((D)a[0]!));
    [Fact]
    public void SchemaVerbFloorError() => K05.Check(M, "schemaVerbFloorError", a => Actions.VerbFloorError(a[0], Actions.CoreRegistry, a[1]), eq: CodeEq);
    [Fact] public void SchemaFloorError() => K05.Check(M, "schemaFloorError", a => Actions.SchemaFloorError((D)a[0]!, a[1]), eq: CodeEq);
    [Fact] public void PackRoot() => K05.Check(M, "packRoot", a => Actions.PackRoot(((L)a[0]!).Select(x => (string)x!).ToList()));
    [Fact] public void PackProof() => K05.Check(M, "packProof", a => Actions.PackProof(((L)a[0]!).Select(x => (string)x!).ToList(), (string)a[1]!));

    [Fact]
    public void EveryFn() => K05.Covers(M, new[]
    {
        "validateDef", "isRole", "isFormat", "isContextKey", "paramNameError", "jsonProfileError", "idPatternError", "profileError", "registryError",
        "closure", "floorOf", "topTraits", "traitsDigest", "tablesDigest", "floorDecision", "worstReversibility", "sensitivityFloor", "impliedFromFacts",
        "normalize", "defDigest", "declProfile", "hintTraits", "effective", "reviewerPinsError", "reviewMessage", "isConfirmed", "factsDigest",
        "schemaVerbFloorError", "schemaFloorError", "packRoot", "packProof",
    });

    // ---- the reference fixes of d36d91ac7, one each ----
    [Fact]
    public void FloorDecisionDeniesANonIntegerTier()
    {
        var call = new D { ["context"] = new L() };
        object?[][] tiers = { new object?[] { new Num("3"), new Num("3") }, new object?[] { null, new Num("2") }, new object?[] { "3", new Num("2") },
            new object?[] { new Num("2.5"), new Num("2") }, new object?[] { new Num("3"), new Num("-1") }, new object?[] { new Num("-0"), new Num("0") }, new object?[] { new Num("3"), true } };
        for (var i = 0; i < tiers.Length; i++)
        {
            var g = new D { ["caveats"] = new L(), ["preauth_esc"] = tiers[i][1] };
            if (tiers[i][0] != null) g["max_esc"] = tiers[i][0];   // null = missing
            Assert.Equal(i == 0 ? "allow" : "deny", Actions.FloorDecision(g, call, Actions.Profile()));
        }
    }

    [Fact]
    public void AReadAttestationWithoutAnArrayFinalTraitsIsNotConfirmed()
    {
        var a = K05.Args(K05.Of(M, "isConfirmed").Single(c => (string)c["name"]! == "isConfirmed/read good"));
        Assert.Null(Actions.AttestationError((D)a[0]!, Actions.CoreRegistry, a[1]));
        foreach (var f in new object?[] { "missing", null, "" })
        {
            var d = (D)K05.Deep(a[0])!;
            var att = (D)((D)d["review"]!)["attestation"]!;
            if (f is "missing") att.Remove("final_traits"); else att["final_traits"] = f;
            Assert.NotNull(Actions.AttestationError(d, Actions.CoreRegistry, a[1]));
        }
    }

    [Fact]
    public void ANullMaxItemsImpliesBulk()
    {
        foreach (var mi in new object?[] { "missing", null, new Num("10") })
        {
            var p = new D { ["type"] = "array" };
            if (mi is not "missing") p["max_items"] = mi;
            Assert.Equal(mi is not Num, Actions.ImpliedFromFacts(new[] { "create" }, new[] { p }, null, "reversible").Contains("pca.bulk"));
        }
    }
}

using AtlasPca;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

// Pinned to packages/pca-actions/src: validate.ts:177 (verb <= MAX_VERB_BYTES = 128), validate.ts:185 (resource.type <= 128),
// traits.ts:141 (card_phrase 1..120); packages/pca/src/missing-context.ts setPath (a non-object intermediate is replaced).
public class K05R2BGuardTests
{
    const string VerbMsg = "verb must be <ns>.<noun...>.<action> (lowercase, 2..6 segments)";
    const string TypeMsg = "resource.type is malformed";

    // 32 + 1 + 32 + 1 + 32 + 1 + last characters: 128 for last = 29, 129 for last = 30 (all ASCII, so bytes == characters)
    static string Dotted(int last) => new string('a', 32) + "." + new string('b', 32) + "." + new string('c', 32) + "." + new string('d', last);

    static D Def(string verb, string type) => new()
    {
        ["v"] = IntentJs.OfLong(1), ["kind"] = Actions.ActionDefKind, ["verb"] = verb, ["title"] = "t", ["effects"] = new L { "read" },
        ["resource"] = new D { ["type"] = type, ["id"] = "*", ["scope"] = "one" }, ["params"] = new D(),
    };

    [Fact]
    public void AVerbOfExactly128BytesIsAcceptedAnd129IsRefused()
    {
        Assert.Equal(128, Dotted(29).Length);
        Assert.NotEqual(VerbMsg, Actions.ValidateDef(Def(Dotted(29), "thing")));
        Assert.Equal(VerbMsg, Actions.ValidateDef(Def(Dotted(30), "thing")));
    }

    [Fact]
    public void AResourceTypeOfExactly128CharactersIsAcceptedAnd129IsRefused()
    {
        Assert.NotEqual(TypeMsg, Actions.ValidateDef(Def("acme.thing.get", Dotted(29))));
        Assert.Equal(TypeMsg, Actions.ValidateDef(Def("acme.thing.get", Dotted(30))));
    }

    static D Trait(string phrase) => new() { ["id"] = "acme.one", ["implies"] = new L(), ["floor"] = Actions.Profile(), ["card_phrase"] = phrase };

    [Fact]
    public void ACardPhraseIsOneToOneHundredTwentyCharacters()
    {
        const string Msg = "trait 'acme.one': card_phrase must be a non-empty string up to 120 characters";
        Assert.Null(Actions.RegistryError(new L { Trait("x") }));
        Assert.Null(Actions.RegistryError(new L { Trait(new string('x', 120)) }));
        Assert.Equal(Msg, Actions.RegistryError(new L { Trait("") }));
        Assert.Equal(Msg, Actions.RegistryError(new L { Trait(new string('x', 121)) }));
    }

    // A bound scalar sits under the literal key "constructor". The supplied path env.constructor.x is not resolvable
    // (ResolvePath refuses a forbidden segment), so it is not "blocked" and SetPath must replace the scalar with an object.
    [Fact]
    public void ABoundNonObjectIntermediateIsReplacedByAnObject()
    {
        var bound = new D { ["env"] = new D { ["constructor"] = "scalar" } };
        var supplied = new D { ["env"] = new D { ["constructor.x"] = "v" } };
        var b = MissingContext.BindContext(bound, supplied);
        var env = Assert.IsType<D>(b.Context["env"]);
        var c = Assert.IsType<D>(env["constructor"]);
        Assert.Equal("v", c["x"]);
        Assert.Empty(b.Conflicts);
    }
}

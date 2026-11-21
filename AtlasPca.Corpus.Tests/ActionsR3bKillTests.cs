using System.Text;
using AtlasPca;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

// Pinned to packages/pca-actions/src: digest.ts packProof, effective.ts impliedFromFacts, confirmation.ts blankReason and verbConfirmationError,
// import/review.ts verifyAttestation, traits.ts subset and leq, derive.ts schemaVerbFloorError, registryOfSchema and schemaFloorError.
// "unknown effect" and "tags is not iterable" are the native wording of an engine-text refusal (the differential compares only their code).
public class ActionsR3bKillTests
{
    static Dictionary<string, D> Core => Actions.CoreRegistry;
    static EdKey Reviewer => EdKey.FromSeed(Enumerable.Repeat((byte)3, 32).ToArray());
    static object? Ts => IntentJs.OfLong(100);
    const string Unconfirmed = "schema_traits_forged: unconfirmed action must carry every trait (missing pca.agent_spawning)";
    const string Irreversible = "schema_traits_forged: missing implied trait pca.irreversible";
    const string BelowFloor = "schema_floor_forged: floors are below the floor of the carried traits";
    const string BelowRev = "schema_floor_forged: floors.rev is below the declared reversibility";
    const string BadDismissal = "a dismissed trait is also final, or has no reason";
    const string BadShape = "the attestation final_traits, dismissed, ts or reviewer_kid is malformed";

    static D PinKey(string kid, params string[] roles) => new() { ["kid"] = kid, ["pk"] = Reviewer.Id, ["roles"] = new L(roles) };
    static D Pins(params D[] keys) => new() { ["keys"] = new L(keys) };
    static D ReviewerPins() => Pins(PinKey("r", "reviewer"));

    static string Sig(byte[] msg) => Pca.B64u(Reviewer.Sign(msg));
    static void Sign(D a) => a["sig"] = Sig(Actions.ReviewMessage(a, ((L)a["final_traits"]!).Cast<string>().ToList()));

    // ---- a def with a good signed attestation; `edit` runs before the signature, so only the edited check can refuse --------------
    static D Def(params string[] traits) => new()
    {
        ["kind"] = Actions.ActionDefKind, ["verb"] = "acme.thing.get", ["title"] = "t", ["effects"] = new L { "read" },
        ["resource"] = new D { ["type"] = "thing", ["id"] = new D(), ["scope"] = "one" }, ["params"] = new D(), ["traits"] = new L(traits),
    };

    static D Attested(Action<D>? edit = null)
    {
        var def = Def("pca.bulk");
        var a = new D
        {
            ["def_digest"] = Actions.DefDigest(def), ["traits_digest"] = Actions.TraitsDigest(Core), ["facts_digest"] = "facts",
            ["final_traits"] = new L((L)def["traits"]!), ["dismissed"] = new L(), ["reviewer_kid"] = "r", ["ts"] = Ts, ["sig"] = "unsigned",
        };
        edit?.Invoke(a);
        if (a["sig"] as string == "unsigned" && a.ContainsKey("facts_digest") && a["final_traits"] is L ft && ft.All(x => x is string)
            && a["dismissed"] is L dm && dm.All(x => x is D xd && xd.ContainsKey("trait") && xd.ContainsKey("reason"))) Sign(a);
        def["review"] = new D { ["state"] = "confirmed", ["attestation"] = a };
        return def;
    }

    static string? AttErr(Action<D>? edit = null, object? pins = null) => Actions.AttestationError(Attested(edit), Core, pins ?? ReviewerPins());
    static D Dismissal(string reason, string trait = "pca.scheduled") => new() { ["trait"] = trait, ["reason"] = reason };
    static void Dismiss(D a, string reason) => a["dismissed"] = new L { Dismissal(reason) };

    // ---- a verb with a good signed confirmation -------------------------------------------------------------------------------
    static D ConfirmedVerb(Action<D>? edit = null)
    {
        var v = new D { ["verb"] = "acme.thing.get", ["kind"] = "read", ["effects"] = new L { "read" }, ["traits"] = new L { "pca.bulk" }, ["def"] = "digest" };
        var a = new D
        {
            ["def_digest"] = "digest", ["traits_digest"] = Actions.TraitsDigest(Core), ["facts_digest"] = Actions.FactsDigest(v),
            ["final_traits"] = new L { "pca.bulk" }, ["dismissed"] = new L(), ["reviewer_kid"] = "r", ["ts"] = Ts, ["sig"] = "unsigned",
        };
        edit?.Invoke(a);
        if (a["sig"] as string == "unsigned" && a["final_traits"] is L ft && ft.All(x => x is string) && a["dismissed"] is L dm && dm.All(x => x is D)) Sign(a);
        v["confirmation"] = a;
        return v;
    }

    static string? VerbErr(Action<D>? edit = null, object? pins = null) => Actions.VerbConfirmationError(ConfirmedVerb(edit), Core, pins ?? ReviewerPins());

    // ---- rule 22 probes -------------------------------------------------------------------------------------------------------
    static D Floors() => Actions.FloorOf(Core, Actions.TopTraits(Core));
    static L AllTraits() => new(Actions.TopTraits(Core).Cast<object?>());

    // no traits at all: "missing implied trait" comes first when one is implied, otherwise the unconfirmed-verb refusal
    static D Bare(params (string K, object? V)[] extra)
    {
        var v = new D { ["kind"] = "read", ["effects"] = new L { "read" }, ["traits"] = new L(), ["floors"] = new D(), ["params"] = new D() };
        foreach (var (k, x) in extra) v[k] = x;
        return v;
    }

    // every trait carried: only the floors can refuse
    static D Carrying(D floors, params (string K, object? V)[] extra)
    {
        var v = Bare(extra);
        v["traits"] = AllTraits();
        v["floors"] = floors;
        return v;
    }

    static D FloorsWith(string member, object? value) { var f = new D(Floors()); f[member] = value; return f; }
    static D FloorsWithout(string member) { var f = new D(Floors()); f.Remove(member); return f; }
    static string? Err(object? v) => Actions.VerbFloorError(v, Core, null);
    static D OneParam(D p) => new() { ["action.params.p"] = p };
    static D Boolean() => new() { ["type"] = "boolean" };
    static D BothMapped() => new() { ["true"] = "reversible", ["false"] = "reversible" };

    // ---- the pack ------------------------------------------------------------------------------------------------------------
    [Fact]
    public void ADigestOutsideThePackIsRefused()
    {
        var ex = Assert.Throws<ActionKitError>(() => Actions.PackProof(new[] { "a" }, "b"));
        Assert.Equal("not_in_pack", ex.Code);
        Assert.Equal("the digest is not in the pack", ex.Message);
    }

    // ---- implied traits -------------------------------------------------------------------------------------------------------
    [Fact]
    public void AnEffectIsReadAsAPropertyKey()
    {
        Assert.Equal("schema_traits_forged: missing implied trait pca.destructive", Err(Bare(("effects", new L { new L { "delete" } }))));
        Assert.Equal("schema_floor_forged: unknown effect bogus", Err(Bare(("effects", new L { "bogus" }))));
        Assert.Equal("schema_floor_forged: unknown effect 5", Err(Bare(("effects", new L { IntentJs.OfLong(5) }))));
        Assert.Equal("schema_floor_forged: unknown effect null", Err(Bare(("effects", new L { null }))));
    }

    [Fact]
    public void ARoleIsReadAsAPropertyKey()
    {
        var p = OneParam(new D { ["type"] = "string", ["role"] = new L { "credential.secret" } });
        Assert.Equal("schema_traits_forged: missing implied trait pca.credential_access", Err(Bare(("effects", new L { "create" }), ("params", p))));
    }

    [Fact]
    public void AReadOnlyVerbCallsStartsWithOnTheRole()
    {
        static D Role(object? r) => Bare(("params", OneParam(new D { ["type"] = "string", ["role"] = r })));
        Assert.Equal("schema_floor_forged: p.role.startsWith is not a function", Err(Role(IntentJs.OfLong(5))));
        Assert.Equal("schema_floor_forged: p.role.startsWith is not a function", Err(Role(new L { "money.amount" })));
        Assert.Equal("schema_floor_forged: Cannot read properties of null (reading 'startsWith')", Err(Role(null)));
    }

    [Fact]
    public void ATagIsReadAsAPropertyKeyAndTagsMustIterate()
    {
        static D Tags(object? t) => Bare(("params", OneParam(new D { ["type"] = "string", ["tags"] = t })));
        Assert.Equal("schema_traits_forged: missing implied trait pca.pii_access", Err(Tags(new L { new L { "pii" } })));
        Assert.Equal("schema_floor_forged: tags is not iterable", Err(Tags(IntentJs.OfLong(5))));
        Assert.Equal("schema_floor_forged: tags is not iterable", Err(Tags(new D())));
        Assert.Equal(Unconfirmed, Err(Tags("pii")));
    }

    // ---- JS whitespace ---------------------------------------------------------------------------------------------------------
    [Theory]
    [InlineData("\u2000")]
    [InlineData("\u2005")]
    [InlineData("\u200a")]
    [InlineData("\u001c")]
    [InlineData("\u001f")]
    [InlineData(" \u200a\u001f\t")]
    public void AReasonOfOnlyWhiteSpaceIsNoReason(string reason)
    {
        Assert.Equal(BadDismissal, AttErr(a => Dismiss(a, reason)));
        Assert.Equal(BadDismissal, VerbErr(a => Dismiss(a, reason)));
    }

    [Theory]
    [InlineData("\u1fff")]
    [InlineData("\u200b")]
    [InlineData("\u001b")]
    public void TheNeighboursOfTheWhiteSpaceRangesAreAReason(string reason)
    {
        Assert.Null(AttErr(a => Dismiss(a, reason)));
        Assert.Null(VerbErr(a => Dismiss(a, reason)));
    }

    // ---- the attestation: every refusal, in the reference's order ---------------------------------------------------------------
    [Fact]
    public void AGoodAttestationCounts() => Assert.Null(AttErr());

    [Fact]
    public void PinsAreChecked()
    {
        Assert.Equal("no reviewer keys are pinned", Actions.AttestationError(Attested(), Core, null));
        Assert.Equal("bad pins: pins must be {keys: [...]}", Actions.AttestationError(Attested(), Core, "x"));
        Assert.Equal("bad pins: pins must be {keys: [...]}", Actions.AttestationError(Attested(), Core, new D()));
        Assert.Equal("no reviewer keys are pinned", Actions.VerbConfirmationError(ConfirmedVerb(), Core, null));
        Assert.Equal("bad pins: pins must be {keys: [...]}", Actions.VerbConfirmationError(ConfirmedVerb(), Core, "x"));
        Assert.Equal("bad pins: pins must be {keys: [...]}", Actions.VerbConfirmationError(ConfirmedVerb(), Core, new D()));
    }

    [Fact]
    public void AnUnconfirmedOrUnattestedDefIsRefused()
    {
        var pins = ReviewerPins();
        Assert.Equal("review.state is not confirmed", Actions.AttestationError(Def(), Core, pins));
        var noAttestation = Def();
        noAttestation["review"] = new D { ["state"] = "confirmed" };
        Assert.Equal("a confirmed def carries an attestation", Actions.AttestationError(noAttestation, Core, pins));
    }

    [Fact]
    public void AnUnsignedAttestationIsRefused()
    {
        var def = Attested();
        ((D)((D)def["review"]!)["attestation"]!).Remove("sig");
        Assert.Equal("the attestation is unsigned", Actions.AttestationError(def, Core, ReviewerPins()));
    }

    [Fact]
    public void TheAttestationFactsDigestMustBeAString()
    {
        Assert.Equal("the attestation facts_digest must be a string", AttErr(a => a.Remove("facts_digest")));
        // it comes before every other shape check
        Assert.Equal("the attestation facts_digest must be a string", AttErr(a => { a["facts_digest"] = IntentJs.OfLong(1); a["final_traits"] = "x"; }));
    }

    [Fact]
    public void EachShapeMemberOfTheAttestationIsChecked()
    {
        Assert.Equal(BadShape, AttErr(a => a["final_traits"] = "pca.bulk"));
        Assert.Equal(BadShape, AttErr(a => a["final_traits"] = new L { "pca.bulk", IntentJs.OfLong(5) }));
        Assert.Equal(BadShape, AttErr(a => a["dismissed"] = "x"));
        Assert.Equal(BadShape, AttErr(a => a["dismissed"] = new L { Dismissal("why"), IntentJs.OfLong(5) }));
        Assert.Equal(BadShape, AttErr(a => a["dismissed"] = new L { new D { ["reason"] = "why" } }));
        Assert.Equal(BadShape, AttErr(a => a["dismissed"] = new L { new D { ["trait"] = "pca.scheduled" } }));
        Assert.Equal(BadShape, AttErr(a => a["ts"] = "100"));
        Assert.Equal(BadShape, AttErr(a => a["reviewer_kid"] = IntentJs.OfLong(1)));
        // shape before meaning: a digest mismatch does not hide it
        Assert.Equal(BadShape, AttErr(a => { a["ts"] = "100"; a["def_digest"] = "other"; }));
    }

    [Fact]
    public void AttestationBindingsAreChecked()
    {
        Assert.Equal("the def changed after it was reviewed", AttErr(a => a["def_digest"] = "other"));
        Assert.Equal("the trait registry changed since the review", AttErr(a => a["traits_digest"] = "other"));
        Assert.Equal("the attested final traits are not the def's declared traits", AttErr(a => a["final_traits"] = new L { "pca.pii_access" }));
    }

    [Fact]
    public void ADefThatCannotBeDigestedIsAMalformedAttestation()
    {
        var def = Attested();
        def.Remove("resource");
        var why = Actions.AttestationError(def, Core, ReviewerPins());
        Assert.StartsWith("malformed attestation: ", why);
    }

    [Fact]
    public void ANonArrayTraitsDigestsPinAcceptsNothingExtra()
    {
        var pins = ReviewerPins();
        pins["traits_digests"] = "other";
        Assert.Equal("the trait registry changed since the review", AttErr(a => a["traits_digest"] = "other", pins));
        Assert.Equal("the confirmation was made against a different trait registry", VerbErr(a => a["traits_digest"] = "other", pins));
        // stricter than the reference, which spreads a string pin and keeps the registry's own digest accepted
        Assert.Equal("the trait registry changed since the review", AttErr(null, pins));
    }

    [Fact]
    public void ADismissalOfAFinalTraitIsRefused()
    {
        Assert.Equal(BadDismissal, AttErr(a => a["dismissed"] = new L { Dismissal("why", "pca.bulk") }));
        Assert.Equal(BadDismissal, VerbErr(a => a["dismissed"] = new L { Dismissal("why", "pca.bulk") }));
    }

    [Fact]
    public void TheSignerMustBeAPinnedReviewer()
    {
        Assert.Equal("no pinned key 'nobody'", AttErr(a => a["reviewer_kid"] = "nobody"));
        Assert.Equal("no pinned key 'nobody'", VerbErr(a => a["reviewer_kid"] = "nobody"));
        var publisher = Pins(PinKey("r", "publisher"));
        Assert.Equal("key 'r' does not hold the reviewer role", AttErr(null, publisher));
        Assert.Equal("key 'r' does not hold the reviewer role", VerbErr(null, publisher));
    }

    [Theory]
    [InlineData("not_before", 101)]
    [InlineData("not_after", 99)]
    public void TheTimeMustBeInsideTheKeyValidity(string member, int bound)
    {
        var key = PinKey("r", "reviewer");
        key[member] = IntentJs.OfLong(bound);
        Assert.Equal("the attestation time is outside the key validity", AttErr(null, Pins(key)));
        Assert.Equal("the confirmation time is outside the key validity", VerbErr(null, Pins(key)));
    }

    [Fact]
    public void ABadSignatureIsRefusedInTheArtifactsOwnWords()
    {
        var other = Sig(new byte[] { 1 });
        Assert.Equal("the attestation signature is invalid", AttErr(a => a["sig"] = other));
        Assert.Equal("the confirmation signature is invalid", VerbErr(a => a["sig"] = other));
    }

    // ---- the verb confirmation -------------------------------------------------------------------------------------------------
    [Fact]
    public void AGoodConfirmationCounts() => Assert.Null(VerbErr());

    [Fact]
    public void AnAbsentOrNonObjectConfirmationIsRefused()
    {
        static D With(object? c) { var v = ConfirmedVerb(); v["confirmation"] = c; return v; }
        var pins = ReviewerPins();
        var none = ConfirmedVerb();
        none.Remove("confirmation");
        Assert.Equal("no confirmation", Actions.VerbConfirmationError(none, Core, pins));
        Assert.Equal("confirmation is not an object", Actions.VerbConfirmationError(With(null), Core, pins));
        Assert.Equal("confirmation is not an object", Actions.VerbConfirmationError(With("x"), Core, pins));
        Assert.Equal("the confirmation is unsigned", Actions.VerbConfirmationError(With(new L()), Core, pins));
        Assert.Equal("the confirmation is unsigned", Actions.VerbConfirmationError(With(new D()), Core, pins));
    }

    [Fact]
    public void ConfirmationBindingsAreChecked()
    {
        Assert.Equal("the confirmation covers a different def digest", VerbErr(a => a["def_digest"] = "other"));
        var noDef = ConfirmedVerb();
        noDef.Remove("def");
        Assert.Equal("the confirmation covers a different def digest", Actions.VerbConfirmationError(noDef, Core, ReviewerPins()));
        Assert.Equal("the confirmation was made against a different trait registry", VerbErr(a => a["traits_digest"] = "other"));
        Assert.Equal("the verb facts differ from the facts the reviewer confirmed", VerbErr(a => a["facts_digest"] = "other"));
        Assert.Equal("the verb facts differ from the facts the reviewer confirmed", VerbErr(a => a["facts_digest"] = IntentJs.OfLong(1)));
    }

    [Fact]
    public void EachShapeMemberOfTheConfirmationIsChecked()
    {
        Assert.Equal("malformed confirmation", VerbErr(a => a["final_traits"] = "x"));
        Assert.Equal("malformed confirmation", VerbErr(a => a["dismissed"] = "x"));
        Assert.Equal("malformed confirmation", VerbErr(a => a["ts"] = "100"));
        Assert.Equal("malformed confirmation", VerbErr(a => a["reviewer_kid"] = IntentJs.OfLong(1)));
        // before the carried check, as the reference
        Assert.Equal("malformed confirmation", VerbErr(a => { a["ts"] = "100"; a["final_traits"] = new L { "pca.pii_access" }; }));
    }

    [Fact]
    public void EveryFinalTraitMustBeCarried()
    {
        Assert.Equal("the verb does not carry every trait the reviewer signed", VerbErr(a => a["final_traits"] = new L { "pca.pii_access" }));
        Assert.Equal("the verb does not carry every trait the reviewer signed", VerbErr(a => a["final_traits"] = new L { IntentJs.OfLong(5) }));
    }

    [Fact]
    public void AVerbThatCannotBeDigestedIsAMalformedConfirmation()
    {
        var v = ConfirmedVerb();
        v["description"] = "\ud800";
        var why = Actions.VerbConfirmationError(v, Core, ReviewerPins());
        Assert.StartsWith("malformed confirmation: ", why);
    }

    // ---- T(d) ------------------------------------------------------------------------------------------------------------------
    [Fact]
    public void TraitsOfIsTheHintOnlyWhenConfirmed()
    {
        var d = Attested();
        Assert.Equal(new[] { "pca.bulk" }, Actions.TraitsOf(d, Core, ReviewerPins()));
        Assert.Equal(Actions.TopTraits(Core), Actions.TraitsOf(d, Core));
        Assert.Equal(Actions.TopTraits(Core), Actions.TraitsOf(d, Core, Pins()));
    }

    // ---- JavaScript Number() -----------------------------------------------------------------------------------------------------
    [Fact]
    public void ABooleanIsZeroOrOne()
    {
        Assert.Equal(1d, Actions.JsNumber(true, true));
        Assert.Equal(0d, Actions.JsNumber(false, true));
    }

    [Fact]
    public void AnArrayIsReadThroughItsText()
    {
        Assert.Equal(5d, Actions.JsNumber(new L { IntentJs.OfLong(5) }, true));
        Assert.Equal(5d, Actions.JsNumber(new L { "5" }, true));
        Assert.True(double.IsNaN(Actions.JsNumber(new L { "a", "b" }, true)));
        Assert.Throws<InvalidCastException>(() => Actions.JsNumber(new StringBuilder("5"), true));
    }

    [Fact]
    public void OctalAndBinaryUseTheirRadix()
    {
        Assert.Equal(15d, Actions.JsNumber("0o17", true));
        Assert.Equal(15d, Actions.JsNumber("0O17", true));
        Assert.Equal(3d, Actions.JsNumber("0b11", true));
        Assert.Equal(3d, Actions.JsNumber("0B11", true));
    }

    // ---- leq over presented floors -------------------------------------------------------------------------------------------------
    [Fact]
    public void FullFloorsPass() => Assert.Null(Err(Carrying(Floors())));

    [Fact]
    public void AMissingOrNullSetFloorThrowsTheIncludesError()
    {
        Assert.Equal("schema_floor_forged: Cannot read properties of undefined (reading 'includes')", Err(Carrying(FloorsWithout("caveats"))));
        Assert.Equal("schema_floor_forged: Cannot read properties of null (reading 'includes')", Err(Carrying(FloorsWith("caveats", null))));
    }

    [Fact]
    public void AStringSetFloorIsASubstringTestOfEveryMember()
    {
        Assert.Equal(BelowFloor, Err(Carrying(FloorsWith("caveats", "amount_cap"))));
        var every = string.Join(",", ((L)Floors()["caveats"]!).Cast<string>());
        Assert.Null(Err(Carrying(FloorsWith("caveats", every))));
    }

    [Fact]
    public void ANonArraySetFloorHasNoIncludes() =>
        Assert.Equal("schema_floor_forged: b.includes is not a function", Err(Carrying(FloorsWith("caveats", IntentJs.OfLong(5)))));

    [Fact]
    public void NullFloorsThrowTheRiskError() =>
        Assert.Equal("schema_floor_forged: Cannot read properties of null (reading 'risk')", Err(Carrying(null!)));

    // ---- schema verb reads -----------------------------------------------------------------------------------------------------------
    [Fact]
    public void ANullVerbThrowsTheEffectsError() =>
        Assert.Equal("schema_floor_forged: Cannot read properties of null (reading 'effects')", Err(null));

    [Fact]
    public void ANullParamThrowsTheTypeError() =>
        Assert.Equal("schema_floor_forged: Cannot read properties of null (reading 'type')", Err(Bare(("params", OneParam(null!)))));

    [Fact]
    public void AMissingOrNullByParamThrowsTheSliceError()
    {
        Assert.Equal("schema_floor_forged: Cannot read properties of undefined (reading 'slice')", Err(Bare(("reversibility_by", new D()))));
        Assert.Equal("schema_floor_forged: Cannot read properties of null (reading 'slice')", Err(Bare(("reversibility_by", new D { ["param"] = null }))));
    }

    [Fact]
    public void ANonStringNonArrayByParamHasNoSlice() =>
        Assert.Equal("schema_floor_forged: v.reversibility_by.param.slice is not a function", Err(Bare(("reversibility_by", new D { ["param"] = IntentJs.OfLong(5) }))));

    [Fact]
    public void AnArrayByParamIsSlicedAndReadAsAKey()
    {
        var param = new L();
        for (var i = 0; i < 14; i++) param.Add("z");
        param.Add("p");
        var v = Bare(("params", OneParam(Boolean())), ("reversibility_by", new D { ["param"] = param, ["map"] = BothMapped() }));
        Assert.Equal(Unconfirmed, Err(v));
    }

    [Fact]
    public void APathShorterThanThePrefixHasAnEmptyTail()
    {
        // the array's slice(14) is empty, so its key is "": only the short param path's empty tail can match it
        var v = Bare(("params", new D { ["x"] = Boolean() }), ("reversibility_by", new D { ["param"] = new L { "a" }, ["map"] = BothMapped() }));
        Assert.Equal(Unconfirmed, Err(v));
    }

    [Fact]
    public void TheByDefaultIsCarriedOver()
    {
        static D By(params (string K, object? V)[] m)
        {
            var rb = new D { ["param"] = "action.params.p", ["map"] = new D { ["true"] = "reversible" } };
            foreach (var (k, x) in m) rb[k] = x;
            return Bare(("params", OneParam(Boolean())), ("reversibility_by", rb));
        }
        Assert.Equal(Unconfirmed, Err(By(("default", "reversible"))));
        Assert.Equal(Irreversible, Err(By()));
    }

    [Fact]
    public void TheDeclaredReversibilityFallsBackToTheKind()
    {
        Assert.Equal(Unconfirmed, Err(Bare()));
        Assert.Equal(Irreversible, Err(Bare(("kind", "write"))));
        Assert.Equal(Irreversible, Err(Bare(("kind", null))));
        Assert.Equal(Unconfirmed, Err(Bare(("kind", "write"), ("reversibility", "reversible"))));
        Assert.Equal(Unconfirmed, Err(Bare(("reversibility", null))));
    }

    // a one-element array ranks in leq (a property lookup) but not in the indexOf check that follows
    [Fact]
    public void AnArrayFloorRevRanksBelowEveryDeclaredClass()
    {
        var f = FloorsWith("rev", new L { "irreversible" });
        Assert.Equal(BelowRev, Err(Carrying(f)));
        Assert.Equal(BelowRev, Err(Carrying(f, ("reversibility", "reversible"))));
    }

    [Fact]
    public void AnUnknownDeclaredClassRanksBelowEveryFloor() =>
        Assert.Null(Err(Carrying(FloorsWith("rev", new L { "irreversible" }), ("reversibility", "bogus"))));

    // ---- the document ---------------------------------------------------------------------------------------------------------------
    [Fact]
    public void AnEmptyTraitDefsListIsTheCoreRegistry()
    {
        // the core registry is built per access, so what an empty trait_defs list yields can only be told by its content
        var got = Actions.RegistryOfSchema(new D { ["trait_defs"] = new L() });
        Assert.Equal(Actions.CoreRegistry.Keys.OrderBy(k => k, StringComparer.Ordinal).ToList(), got.Keys.OrderBy(k => k, StringComparer.Ordinal).ToList());
        Assert.Equal(Actions.TraitsDigest(Actions.CoreRegistry), Actions.TraitsDigest(got));
    }

    [Fact]
    public void ADocumentWithoutVerbsIsABadRegistry()
    {
        var why = Actions.SchemaFloorError(new D());
        Assert.StartsWith("bad_registry: ", why);
    }
}

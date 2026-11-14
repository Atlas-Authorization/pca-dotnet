using AtlasPca;
using Xunit;
using static AtlasPca.Corpus.Tests.IntentV2KillTests;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Rule 22 (<c>traits</c>), the integrity half of the schema step and the grant pin (<c>pin</c>) inside DecideIntentV2, mirroring
/// packages/pca-actions/test/verifier.test.ts and packages/pca/src/intent-v2.ts (the schema documents are the shared rule 22 vectors).</summary>
public class Rule22PinWiringTests
{
    const string VERB = "stripe.refund", KID = "r22-site";
    const string SITE_KEY = "r22/site", REG_KEY = "r22/reg", ISSUER = "r22/principal";
    static string ROOT => B64Seed("r22/root");
    static string GRANT_ID => B64Seed("r22/grant");
    static readonly D PARAMS = M("amount", 1000L, "charge", "ch_abcdefgh", "idempotency_key", "k1");
    static readonly L CONTEXT = Li("fresh_revocation", "idempotency");
    static readonly L FLOOR_CAVEATS = Li("amount_cap", "count_cap", "window");
    const string ESCALATE = "escalate: the action floors need a caveat, context or confirmation the grant does not provide (rule 22)";
    const string EXCEED = "the action floors exceed what the grant authorizes (rule 22)";

    static D Input(string vector) =>
        (D)((D)Pca.ParseJson(File.ReadAllText(Path.Combine(Conf.ActionsDir(), vector + ".json")))!)["input"]!;
    static object? Pins => Input("rule22-allow")["pins"];

    /// <summary>A vector's document with a pack, signed by the pinned site key.</summary>
    static D Signed(string vector = "rule22-allow", Action<D>? mutate = null)
    {
        var doc = new D((D)Input(vector)["doc"]!) { ["pack"] = M("ns", "stripe", "version", "1.0.0", "root", ROOT) };
        mutate?.Invoke(doc);
        doc.Remove("sig");
        var sig = M("alg", "ed25519", "kid", KID, "value", Sign(SITE_KEY, IntentJs.Message(ActionSchema.ActionSchemaDomain, doc)));
        return new D(doc) { ["sig"] = sig };
    }
    static string DefOf(D doc) => (string)((L)doc["verbs"]!).Cast<D>().First(v => (string)v["verb"]! == VERB)["def"]!;
    static D HONEST => Signed();
    static string DEF => DefOf(HONEST);
    static L KEYS => Li(M("kid", KID, "alg", "ed25519", "pk", Pub(SITE_KEY)));
    static L REG_KEYS => Li(M("kid", "reg-1", "alg", "ed25519", "pk", Pub(REG_KEY)));

    static D Pin(params object?[] over)
    {
        var p = M("pack", M("ns", "stripe", "root", ROOT), "defs", M(VERB, DEF), "on_new_action", "deny", "max_esc", 3L, "preauth_esc", 2L, "caveats", FLOOR_CAVEATS);
        for (int i = 0; i < over.Length; i += 2)
        {
            if (over[i + 1] is null) p.Remove((string)over[i]!);
            else p[(string)over[i]!] = over[i + 1];
        }
        return p;
    }

    static D Grant(object? pin = null, bool hasPin = true, L? caveats = null)
    {
        var env = M("type", "envelope", "goal_commit", "x", "predicates", Li(), "caveats", caveats ?? Li(), "agent_binding", M(),
            "risk_policy", Pca.ParseJson("""{"weights":{"alpha":0,"beta":0,"gamma":1,"delta":0,"epsilon":0,"zeta":0},"theta1":1,"theta2":1,"kappa":100,"lambda":0,"rho":0.5,"bMax":1000000}"""));
        if (hasPin) env["actions"] = pin ?? Pin();
        return M("id", GRANT_ID, "issuer", Pub(ISSUER), "caveats", Li(env));
    }
    static D NoPin(L? caveats = null) => Grant(hasPin: false, caveats: caveats);

    static D P(string verb = VERB, D? parameters = null) =>
        M("aud", "pay", "action", M("verb", verb, "resource", "stripe.charge:ch", "params_digest", Pca.ParamsDigest(parameters ?? PARAMS)));

    static D CtxRaw(object? doc, bool closed = false, params object?[] over)
    {
        var c = M("schema", M("docs", Li(doc), "keys", KEYS), "params", PARAMS, "reviewers", Pins, "call_context", CONTEXT);
        if (closed) c["policy"] = M("schema", M("closed_world", true));
        for (int i = 0; i < over.Length; i += 2)
        {
            if (over[i + 1] is null) c.Remove((string)over[i]!);
            else c[(string)over[i]!] = over[i + 1];
        }
        return c;
    }
    static IntentV2.Decision Run(D grant, object? doc, bool closed = false, params object?[] over) =>
        IntentV2.Decide(P(), grant, IntentV2Context.FromJson(CtxRaw(doc, closed, over)), NOW);

    static IntentV2.Check Chk(IntentV2.Decision d, string name) => d.Checks.Single(c => c.Name == name);
    static string[] Names(IntentV2.Decision d) => d.Checks.Select(c => c.Name).ToArray();
    static void Passed(IntentV2.Decision d, params string[] names)
    {
        Assert.Equal(names, Names(d));
        Assert.All(d.Checks, c => Assert.True(c.Ok, c.Name + ": " + c.Reason));
    }

    // ---- control

    [Fact]
    public void ConsistentV2ExactPinAndProvidedFloorsPassInReferenceOrder()
    {
        Passed(Run(Grant(), HONEST, closed: true), "schema", "pin", "traits");
        Passed(Run(Grant(), HONEST), "pin", "traits");
    }

    [Fact]
    public void PinAndTraitsComeBeforeUnitsAndTighten()
    {
        var g = Grant();
        var env = (D)((L)g["caveats"]!)[0]!;
        env["units"] = M("money.usd", M("kind", "money", "currency", "USD", "exponent", 2L));
        env["tighten"] = Li();
        Assert.Equal(new[] { "pin", "traits", "units", "tighten" }, Names(Run(g, HONEST)));
    }

    [Fact]
    public void AGrantWithAPinNeedsTheV2Pipeline()
    {
        Assert.True(IntentV2.NeedsModelRules(Grant()));
        Assert.False(IntentV2.NeedsModelRules(NoPin()));
    }

    [Fact]
    public void NoPinAndNoClosedWorldReportsNothing() => Assert.Empty(Run(NoPin(), HONEST).Checks);

    // ---- integrity

    [Theory]
    [InlineData("rule22-forged-floors-denied", "schema_floor_forged")]
    [InlineData("rule22-dropped-traits-denied", "schema_traits_forged")]
    [InlineData("rule22-schema-trait-unknown", "unknown_trait")]
    [InlineData("rule22-unconf-claiming-reviewed-traits-denied", "schema_traits_forged")]
    public void AForgedDocumentIsRefusedByTheSchemaCheckAndByThePin(string vector, string code)
    {
        var doc = Signed(vector);
        var d = Run(Grant(), doc, closed: true);
        var want = "schema_floor_forged: " + Actions.SchemaFloorError((D)IntentJs.Normalize(doc)!, IntentJs.Normalize(Pins));
        Assert.Contains(code, want);
        Assert.Equal(want, Chk(d, "schema").Reason);
        Assert.Equal(want, Chk(d, "pin").Reason);
        Assert.Null(d.Schema);
        Assert.Equal(new[] { "schema", "pin" }, Names(d)); // no document, so no traits check
    }

    [Fact]
    public void TheIntegrityCheckPrecedesTheParamsCheck()
    {
        var d = Run(NoPin(), Signed("rule22-forged-floors-denied"), true, "params", null);
        Assert.StartsWith("schema_floor_forged: ", Chk(d, "schema").Reason);
    }

    [Fact]
    public void TheAudCheckPrecedesTheIntegrityCheck()
    {
        var d = IntentV2.Decide(M("aud", "other", "action", P()["action"]), NoPin(), IntentV2Context.FromJson(CtxRaw(Signed("rule22-forged-floors-denied"), true)), NOW);
        Assert.Equal("schema aud does not match the PCActn aud", Chk(d, "schema").Reason);
    }

    [Fact]
    public void AConfirmationIsNotTrustedWithoutThePinnedReviewer()
    {
        var d = Run(Grant(), HONEST, true, "reviewers", null);
        Assert.Contains("schema_traits_forged", Chk(d, "schema").Reason);
        Assert.Contains("schema_traits_forged", Chk(d, "pin").Reason);
    }

    [Fact]
    public void AV1SchemaIsNotCheckedForFloorsAndReportsOnlyTheSchemaCheck()
    {
        var v1 = Signed("rule22-allow", doc =>
        {
            doc["v"] = 1L;
            foreach (var k in new[] { "traits_digest", "trait_defs", "pack" }) doc.Remove(k);
            doc["verbs"] = Li(M("verb", VERB, "kind", "write", "reversibility", "irreversible", "params", M(
                "action.params.amount", M("type", "integer", "min", 0L, "max", 100000L, "semantic", "quantity", "sensitivity", "material"),
                "action.params.charge", M("type", "string", "semantic", "generic.string", "sensitivity", "free", "max_len", 128L),
                "action.params.idempotency_key", M("type", "string", "semantic", "generic.string", "sensitivity", "free", "max_len", 128L))));
            doc.Remove("units");
        });
        Passed(Run(NoPin(), v1, closed: true), "schema");
        // a pinned grant refuses it: it carries no pack, and no traits check is reported
        var d = Run(Grant(), v1, closed: true);
        Assert.Equal(new[] { "schema", "pin" }, Names(d));
        Assert.StartsWith("pack_mismatch: ", Chk(d, "pin").Reason);
    }

    // ---- the floor decision

    [Fact]
    public void WithoutAPinTheGrantDefaultsToPreauthZero() =>
        Assert.Equal(ESCALATE, Chk(Run(NoPin(new L { M("type", "amount_cap"), M("type", "count_cap"), M("type", "window") }), HONEST, closed: true), "traits").Reason);

    [Fact]
    public void AVerbAboveMaxEscIsDenied()
    {
        var d = Run(Grant(Pin("max_esc", 1L, "preauth_esc", 0L)), HONEST);
        Assert.Equal(EXCEED, Chk(d, "traits").Reason);
        Assert.True(Chk(d, "pin").Ok);
    }

    [Fact]
    public void ATierAbovePreauthEscalates() => Assert.Equal(ESCALATE, Chk(Run(Grant(Pin("preauth_esc", 1L)), HONEST), "traits").Reason);

    [Fact]
    public void AnAbsentMaxEscDefaultsToTheTopTier() => Passed(Run(Grant(Pin("max_esc", null)), HONEST), "pin", "traits");

    [Fact]
    public void AnAbsentPreauthEscDefaultsToZero() => Assert.Equal(ESCALATE, Chk(Run(Grant(Pin("preauth_esc", null)), HONEST), "traits").Reason);

    [Fact]
    public void AMissingCaveatEscalatesAndTheDecisionIsEscalate()
    {
        var d = Run(Grant(Pin("caveats", Li("amount_cap"))), HONEST);
        var t = Chk(d, "traits");
        Assert.Equal(ESCALATE, t.Reason);
        Assert.Equal(PcaDecision.Escalate, PcaDecision.Of(new[] { "traits" }, new[] { "traits: " + t.Reason }));
    }

    [Fact]
    public void AMissingContextKeyEscalatesAndAnAbsentContextIsEmpty()
    {
        Assert.Equal(ESCALATE, Chk(Run(Grant(), HONEST, false, "call_context", Li("idempotency")), "traits").Reason);
        Assert.Equal(ESCALATE, Chk(Run(Grant(), HONEST, false, "call_context", null), "traits").Reason);
    }

    [Fact]
    public void BothEnvelopeAndPinCaveatsCount()
    {
        Passed(Run(Grant(Pin("caveats", Li("amount_cap")), caveats: Li(M("type", "count_cap"), M("type", "window"))), HONEST), "pin", "traits");
        Passed(Run(Grant(Pin("caveats", null), caveats: Li(M("type", "amount_cap"), M("type", "count_cap"), M("type", "window"))), HONEST), "pin", "traits");
    }

    [Fact]
    public void ANonStringEnvelopeCaveatTypeIsNotCounted()
    {
        var d = Run(Grant(Pin("caveats", Li("amount_cap", "count_cap")), caveats: Li(M("type", 1L), M("nope", "window"), "window")), HONEST);
        Assert.Equal(ESCALATE, Chk(d, "traits").Reason);
    }

    [Fact]
    public void AMalformedPinFailsThePinAndGrantsNothingToTraits()
    {
        var d = Run(Grant(Pin("on_new_action", "maybe")), HONEST);
        Assert.StartsWith("bad_pin: ", Chk(d, "pin").Reason);
        Assert.Equal(ESCALATE, Chk(d, "traits").Reason); // its preauth_esc and caveats are ignored
    }

    [Fact]
    public void ANonObjectPinIsStillAPin()
    {
        var g = Grant();
        ((D)((L)g["caveats"]!)[0]!)["actions"] = null;
        var d = Run(g, HONEST);
        Assert.Equal("bad_pin: actions must be an object", Chk(d, "pin").Reason);
        Assert.True(IntentV2.NeedsModelRules(g));
    }

    // ---- the pin

    [Fact]
    public void AnUnnamedVerbFollowsOnNewAction()
    {
        var other = Pin("defs", M("stripe.charge", DEF));
        Assert.StartsWith("new_action: ", Chk(Run(Grant(other), HONEST), "pin").Reason);
        other["on_new_action"] = "escalate";
        var r = Chk(Run(Grant(other), HONEST), "pin").Reason;
        Assert.StartsWith("escalate: new_action: ", r);
        Assert.Equal(PcaDecision.Escalate, PcaDecision.Of(new[] { "pin" }, new[] { "pin: " + r }));
    }

    [Fact]
    public void AnotherPackNamespaceIsAMismatch() =>
        Assert.StartsWith("pack_mismatch: ", Chk(Run(Grant(Pin("pack", M("ns", "other", "root", ROOT))), HONEST), "pin").Reason);

    [Fact]
    public void APackOnlyPinNeedsTheExactRoot()
    {
        Assert.True(Chk(Run(Grant(Pin("defs", null)), HONEST), "pin").Ok);
        Assert.StartsWith("pack_mismatch: ", Chk(Run(Grant(Pin("defs", null, "pack", M("ns", "stripe", "root", B64Seed("r22/other")))), HONEST), "pin").Reason);
    }

    static string OLD => B64Seed("r22/old-def");

    static D Record(string cls)
    {
        var r = M("v", 1L, "kind", Actions.EvolutionRecordKind, "ns", "stripe", "verb", VERB, "from", OLD, "to", DEF, "class", cls, "reasons", Li());
        return new D(r) { ["sig"] = M("alg", "ed25519", "kid", "reg-1", "value", Sign(REG_KEY, IntentJs.Message(Actions.EvolutionDomain, r))) };
    }
    static D Reapproval(D record, string grant)
    {
        var r = M("v", 1L, "kind", Actions.ReapprovalKind, "grant", grant, "verb", VERB, "diff", Actions.EvolutionDiffDigest(record));
        return new D(r) { ["sig"] = M("alg", "ed25519", "value", Sign(ISSUER, IntentJs.Message(Actions.ReapprovalDomain, r))) };
    }
    static IntentV2.Decision Moved(object? actions) => Run(Grant(Pin("defs", M(VERB, OLD))), HONEST, false, "actions", actions);

    [Fact]
    public void AChangedDefinitionWithNoChainIsDefChanged()
    {
        Assert.StartsWith("def_changed: ", Chk(Run(Grant(Pin("defs", M(VERB, OLD))), HONEST), "pin").Reason);
        Assert.StartsWith("def_changed: ", Chk(Moved(M()), "pin").Reason);
    }

    [Fact]
    public void ARegistrySignedNarrowingIsAdmittedOnlyUnderThePinnedKey()
    {
        var rec = Record("narrow");
        Assert.True(Chk(Moved(M("keys", REG_KEYS, "records", Li(rec))), "pin").Ok);
        Assert.StartsWith("def_changed: ", Chk(Moved(M("records", Li(rec))), "pin").Reason);
        Assert.StartsWith("def_changed: ", Chk(Moved(M("keys", REG_KEYS)), "pin").Reason);
    }

    [Fact]
    public void AWideningNamesTheDiffToApproveAndTheExactReapprovalAdmitsIt()
    {
        var rec = Record("widen");
        var r = Chk(Moved(M("keys", REG_KEYS, "records", Li(rec))), "pin").Reason!;
        Assert.StartsWith("def_changed: ", r);
        Assert.EndsWith($" (re-approve diff {Actions.EvolutionDiffDigest(rec)})", r);
        Assert.True(Chk(Moved(M("keys", REG_KEYS, "records", Li(rec), "reapprovals", Li(Reapproval(rec, GRANT_ID)))), "pin").Ok);
        Assert.False(Chk(Moved(M("keys", REG_KEYS, "records", Li(rec), "reapprovals", Li(Reapproval(rec, B64Seed("r22/other-grant"))))), "pin").Ok);
    }

    [Fact]
    public void ASchemaFailureReachesThePinUnchanged()
    {
        var d = Run(Grant(), HONEST, false, "schema", M("docs", Li(), "keys", KEYS));
        Assert.Equal("this verifier has no action schema configured", Chk(d, "pin").Reason);
        Assert.Equal(new[] { "pin" }, Names(d));
    }

    [Fact]
    public void AReusedSchemaStepIsMemoisedAcrossPinTraitsAndUnits()
    {
        var g = Grant();
        ((D)((L)g["caveats"]!)[0]!)["units"] = M();
        var d = Run(g, HONEST, false, "schema", M("docs", Li(), "keys", KEYS));
        Assert.Equal(new[] { "pin", "units" }, Names(d));
        Assert.Equal(Chk(d, "pin").Reason, Chk(d, "units").Reason);
    }

    [Fact]
    public void ASchemaStepThatThrowsFailsThePinAndDecideStaysTotal()
    {
        var bad = (D)Pca.ParseJson("""{"x":1e999}""")!;
        var d = IntentV2.Decide(P(), Grant(), IntentV2Context.FromJson(CtxRaw(HONEST, false, "params", bad)), NOW);
        Assert.Equal(new[] { "pin" }, Names(d));
        Assert.StartsWith("pin error (fail closed): ", Chk(d, "pin").Reason);
    }

    // ---- the verifier context

    [Fact]
    public void AMalformedContextFailsClosedWithTheReferenceMessage()
    {
        var honest = HONEST; // one snapshot for the loops
        foreach (var (key, value, why) in new (string, object?, string)[]
        {
            ("reviewers", "x", "reviewers must be {keys: [...]}"),
            ("reviewers", M(), "reviewers must be {keys: [...]}"),
            ("reviewers", M("keys", "x"), "reviewers must be {keys: [...]}"),
            ("call_context", "x", "call_context must be an array of strings"),
            ("call_context", Li(1L), "call_context must be an array of strings"),
            ("actions", Li(), "actions must be an object"),
            ("actions", M("records", M()), "actions.records must be an array"),
            ("actions", M("keys", "x"), "actions.keys must be an array"),
            ("actions", M("reapprovals", 1L), "actions.reapprovals must be an array"),
        })
        {
            var d = Run(Grant(), honest, false, key, value);
            Assert.Equal("malformed v2 context: " + why, Chk(d, "schema").Reason);
        }
        foreach (var key in new[] { "reviewers", "call_context", "actions" })
        {
            var raw = CtxRaw(honest);
            raw[key] = null; // a present null is not absent
            Assert.False(Chk(IntentV2.Decide(P(), Grant(), IntentV2Context.FromJson(raw), NOW), "schema").Ok);
        }
    }

    [Fact]
    public void AWellFormedContextIsAccepted() =>
        Assert.Null(IntentV2.ContextError(IntentV2Context.FromJson(CtxRaw(HONEST, false, "actions", M("records", Li(), "keys", Li(), "reapprovals", Li())))));
}

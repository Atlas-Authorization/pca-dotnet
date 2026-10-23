using System.Text;
using AtlasPca;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;
using static AtlasPca.Corpus.Tests.IntentV2KillTests;


namespace AtlasPca.Corpus.Tests;

/// <summary>Round-3 kills, second batch: the defensive fail-closed catches (driven by a dictionary whose key lookups throw), the
/// reason texts they print, and the small predicates the oracles do not pin.</summary>
public class R3bKillTests
{
    /// <summary>A key comparer that throws once armed: every hashed lookup on a dictionary built with it throws, while enumeration works.</summary>
    sealed class Boom : IEqualityComparer<string>
    {
        public bool Armed;
        public bool Equals(string? a, string? b) { if (Armed) throw new InvalidOperationException("boom"); return a == b; }
        public int GetHashCode(string s) { if (Armed) throw new InvalidOperationException("boom"); return s.GetHashCode(); }
    }
    static D Throwing(D src)
    {
        var c = new Boom(); var d = new D(c);
        foreach (var (k, v) in src) d[k] = v;
        c.Armed = true;
        return d;
    }

    static readonly Lazy<D> First = new(() =>
    {
        var d = AppContext.BaseDirectory;
        for (int i = 0; i < 12 && d != null; i++, d = Path.GetDirectoryName(d))
        {
            var f = Path.Combine(d, "packages", "pca", "conformance", "vectors.json");
            if (File.Exists(f)) return (D)((L)((D)Pca.ParseJson(File.ReadAllText(f))!)["vectors"]!)[0]!;
        }
        throw new InvalidOperationException("vectors.json not found");
    });

    // ---------------------------------------------------------------- the failing-closed catches

    [Fact]
    public void CaveatEvaluationThatThrowsIsNotSatisfied()
    {
        var cv = new D { ["type"] = "max_spend", ["usd"] = new Num("5") };
        var r = Caveats.EvaluateCaveats(new L { cv }, Throwing(new D { ["action"] = new D() }));
        Assert.False(r.Ok);
        Assert.Equal(new[] { "max_spend" }, r.Failed);
    }

    [Fact]
    public void PredicateEvaluationThatThrowsDoesNotMatch()
    {
        var pred = new D { ["verb"] = "*" };
        var ctx = new D { ["action"] = new D { ["verb"] = "v", ["resource"] = "r" } };
        Assert.True(Predicates.PredicateMatches(pred, ctx));
        Assert.False(Predicates.PredicateMatches(pred, Throwing(ctx)));
        Assert.False(Predicates.PredicateMatches(Throwing(pred), ctx));
        Assert.False(Predicates.EvaluatePredicates(new L { pred }, Throwing(ctx)));
        Assert.False(Predicates.EvaluatePredicates(new L { Throwing(pred) }, ctx));
    }

    [Fact]
    public void KeySetVerificationThatThrowsFails()
    {
        var ks = Throwing(new D { ["v"] = new Num("1") });
        Assert.False(IntentAcc.VerifyKeySet(ks, "root", null, false));
        Assert.False(IntentAcc.VerifyKeySet(ks, null!, null, false));
        Assert.False(IntentAcc.VerifyReceiptSignature(Throwing(new D()), "signer", null));
    }

    [Fact]
    public void WorldProvenanceClassifierAndMapFailClosedOnInternalErrors()
    {
        var boom = Throwing(new D { ["x"] = 1L });
        var w = OracleFacts.Decide(boom);
        Assert.False(w.Ok);
        Assert.Equal("facts: evaluation error (fail closed): InvalidOperationException", w.Reason);
        var p = ParamProvenance.Decide(boom);
        Assert.Equal("deny", p.Outcome);
        Assert.Equal("provenance: evaluation error (fail closed): InvalidOperationException", p.Reason);
        var c = IntentClassifier.Decide(boom);
        Assert.False(c.Ok);
        Assert.Equal("classes: evaluation error (fail closed): InvalidOperationException", c.Reason);
        var ok = (D)IntentJs.Normalize(((L)((D)((D)Pca.ParseJson(File.ReadAllText(Path.Combine(ConfDir(), "vectors.json")))!)["primitives"]!)["intent_map"]!).Cast<D>()
            .First(e => (string)e["name"]! == "ok")["input"])!;
        Assert.True(IntentMap.Decide(ok["map_commit"], ok["action"], true, ok["params"], ok["disclosure"], null).Ok);
        var m = IntentMap.Decide(ok["map_commit"], Throwing((D)ok["action"]!), true, ok["params"], ok["disclosure"], null);
        Assert.False(m.Ok);
        Assert.Equal("map error (fail closed): InvalidOperationException", m.Reason);
    }

    [Fact]
    public void SchemaVerificationAndSessionRootErrorsCarryTheirMessage()
    {
        var shape = ActionSchemaDifferentialSchema();
        var verified = ActionSchema.Verify(shape, new L { Throwing(new D { ["kid"] = "k1" }) });
        Assert.Equal("schema verification error: boom", verified);
        Assert.Equal("malformed session root: boom", IntentSession.VerifyRoot(Throwing(new D { ["v"] = new Num("1") })));
        Assert.Equal("malformed: boom", Pca.ValidateWire(Throwing(new D { ["ver"] = new Num("2") })));
    }

    /// <summary>A well-formed (unsigned-checked-later) schema document: the shape check passes, then the key lookup throws.</summary>
    static D ActionSchemaDifferentialSchema() => (D)IntentJs.Normalize(Pca.ParseJson(
        "{\"v\":1,\"kind\":\"pca-action-schema\",\"site\":\"https://s.example\",\"aud\":\"s.example\",\"version\":\"1\",\"verbs\":[{\"verb\":\"a.b\",\"kind\":\"write\",\"params\":{}}],\"sig\":{\"alg\":\"ed25519\",\"kid\":\"k1\",\"value\":\"AA\"}}"))!;

    [Fact]
    public void IntentBindingFaultIsReportedWithItsExceptionType()
    {
        var grant = new D { ["caveats"] = new L { new D { ["type"] = "envelope", ["goal_commit"] = "x" } } };
        Assert.Equal("intent binding error (fail closed): InvalidCastException", Pca.DecideIntent("not-an-object", true, grant, null));
        Assert.Equal("intent binding error (fail closed): InvalidCastException", Pca.DecideIntent(new Num("7"), true, grant, new IntentPolicy(true)));
    }

    [Fact]
    public void ThrowingGrantIsAMalformedPcactnDenyWithEveryCheckFalse()
    {
        var v0 = First.Value;
        var ctx = (D)v0["context"]!;
        long now = long.Parse(((Num)ctx["now"]!).Raw);
        var good = Pca.VerifyPcactnCore(v0["pcactn"], (D)v0["grant"]!, now, (string)ctx["aud"]!);
        Assert.True(good.Allow, good.Reason);
        var bad = Pca.VerifyPcactnCore(v0["pcactn"], Throwing((D)v0["grant"]!), now, (string)ctx["aud"]!, null, new IntentPolicy(true));
        Assert.False(bad.Allow);
        Assert.StartsWith("malformed PCActn: boom", bad.Reason);
        Assert.False(bad.Checks["intent"]);
        Assert.False(bad.Checks["leaf_signature"]);
        Assert.True(bad.Checks["wire"]);
    }

    // ---------------------------------------------------------------- small predicates

    [Fact]
    public void ProvenanceRankFlowAndOverlap()
    {
        Assert.Equal(0, ParamProvenance.Rank("trusted")); Assert.Equal(3, ParamProvenance.Rank("web")); Assert.Equal(4, ParamProvenance.Rank("agent"));
        Assert.Equal(4, ParamProvenance.Rank("bogus")); Assert.Equal(4, ParamProvenance.Rank(null)); Assert.Equal(4, ParamProvenance.Rank(new Num("1")));
        var rules = new D { ["pii.*"] = new L { "a.example", "b.example" }, ["*"] = new L { "c.example" } };
        Assert.True(ParamProvenance.FlowAllowed(rules, "pii.name", "o.example", "a.example"));
        Assert.True(ParamProvenance.FlowAllowed(rules, "pii.name", "o.example", "b.example"));
        Assert.False(ParamProvenance.FlowAllowed(rules, "pii.name", "o.example", "c.example"));
        Assert.True(ParamProvenance.FlowAllowed(rules, "x", "o.example", "c.example"));
        Assert.True(ParamProvenance.FlowAllowed(rules, "x", "o.example", "o.example"));
        Assert.True(ParamProvenance.FlowAllowed(rules, "public", "o.example", "zzz"));
        Assert.False(ParamProvenance.FlowAllowed(new D(), "x", "o.example", "c.example"));
        Assert.Equal("pii.*", ParamProvenance.FlowRuleFor(rules, "pii.name"));
        Assert.Equal("*", ParamProvenance.FlowRuleFor(rules, "x"));
        var longer = new D { ["pii.*"] = new L(), ["pii.id.*"] = new L() };
        Assert.Equal("pii.id.*", ParamProvenance.FlowRuleFor(longer, "pii.id.x"));
        Assert.Equal("pii.*", ParamProvenance.FlowRuleFor(longer, "pii.name"));
        Assert.Null(ParamProvenance.FlowRuleFor(longer, "other"));
    }

    [Fact]
    public void ArtifactHelpers()
    {
        Assert.True(IntentArtifacts.ScalarEq(null, null));
        Assert.False(IntentArtifacts.ScalarEq(new D(), null)); Assert.False(IntentArtifacts.ScalarEq(null, new D())); Assert.False(IntentArtifacts.ScalarEq(new D(), new D()));
        Assert.False(IntentArtifacts.ScalarEq(new Num("5"), null)); Assert.False(IntentArtifacts.ScalarEq(null, new Num("5")));
        Assert.True(IntentArtifacts.ScalarEq(new Num("5"), new Num("5.0"))); Assert.False(IntentArtifacts.ScalarEq(new Num("5"), new Num("6")));
        Assert.False(IntentArtifacts.ScalarEq("5", new Num("5"))); Assert.False(IntentArtifacts.ScalarEq(true, new Num("1"))); Assert.False(IntentArtifacts.ScalarEq(new Num("1"), true));
        Assert.True(IntentArtifacts.ScalarEq("a", "a")); Assert.False(IntentArtifacts.ScalarEq("a", "b")); Assert.True(IntentArtifacts.ScalarEq(true, true)); Assert.False(IntentArtifacts.ScalarEq(true, false));

        Assert.Equal("pq_pk must be a string", IntentArtifacts.ArtifactSuiteError(new D { ["pq_pk"] = new Num("5") }));
        Assert.Equal("pq_sig must be a string", IntentArtifacts.ArtifactSuiteError(new D { ["pq_sig"] = new Num("5") }));
        Assert.Equal("pq_pk must be a string", IntentArtifacts.ArtifactSuiteError(new D { ["alg"] = "ml-dsa-65", ["pq_pk"] = null }));
        Assert.Equal("an ed25519 artifact must not carry pq_pk / pq_sig", IntentArtifacts.ArtifactSuiteError(new D { ["pq_sig"] = "x" }));
        Assert.Null(IntentArtifacts.ArtifactSuiteError(new D { ["alg"] = "ml-dsa-65", ["pq_pk"] = "x", ["pq_sig"] = "y" }));

        var root = new D();
        Assert.True(IntentArtifacts.SetNested(root, "a.b", "1"));
        Assert.False(IntentArtifacts.SetNested(root, "a.b", "2"));
        Assert.False(IntentArtifacts.SetNested(root, "a.b.c", "3"));
        Assert.False(IntentArtifacts.SetNested(root, "a", "4"));
        Assert.True(IntentArtifacts.SetNested(root, "a.c", "5"));
        Assert.True(IntentArtifacts.SetNested(root, "z", "6"));
        Assert.False(IntentArtifacts.SetNested(root, "z", "7"));

        Assert.Equal("not a list", Assert.Throws<ArgumentException>(() => IntentArtifacts.Iterable(new Num("1"))).Message);
        Assert.Equal("not a list", Assert.Throws<ArgumentException>(() => IntentArtifacts.Iterable(null)).Message);
        Assert.Equal("action.params is not an object", Assert.Throws<ArgumentException>(() => IntentArtifacts.ActionParams(new D { ["params"] = "x" })).Message);
        Assert.Equal("action.params is not an object", Assert.Throws<ArgumentException>(() => IntentArtifacts.ActionParams(new D { ["params"] = null })).Message);
        Assert.Empty(IntentArtifacts.ActionParams(new D()));
    }

    [Fact]
    public void CaveatBoundaries()
    {
        D Ctx(string cls, params object[] p) => new() { ["now"] = new Num("1"), ["action"] = new D { ["verb"] = "v", ["resource"] = "r", ["reversibility_class"] = cls, ["params"] = new D { ["amount"] = new Num("0") } } };
        Assert.True(Caveats.EvaluateCaveats(new L { new D { ["type"] = "max_spend", ["usd"] = new Num("0") } }, Ctx("reversible")).Ok);
        Assert.False(Caveats.EvaluateCaveats(new L { new D { ["type"] = "max_spend", ["usd"] = new Num("-1") } }, Ctx("reversible")).Ok);
        foreach (var (lim, cur, ok) in new[] { ("reversible", "reversible", true), ("rate_limited", "reversible", true), ("irreversible", "irreversible", true),
                     ("reversible", "rate_limited", false), ("reversible", "irreversible", false), ("rate_limited", "irreversible", false), ("bogus", "reversible", false), ("reversible", "bogus", false) })
        {
            var ctx = new D { ["now"] = new Num("1"), ["reversibility_class"] = cur, ["action"] = new D { ["reversibility_class"] = cur } };
            var r = Caveats.EvaluateCaveats(new L { new D { ["type"] = "reversibility_max", ["class"] = lim } }, ctx);
            Assert.True(r.Ok == ok, $"{lim} vs {cur}");
        }
    }

    [Fact]
    public void ParamValueViolationTreatsPresentNullAsDefault()
    {
        var d = new D { ["type"] = "string", ["max_len"] = null };
        Assert.Null(ActionSchema.ParamValueViolation(d, "abc"));
    }

    // ---------------------------------------------------------------- round 3, part c

    sealed class ThrowingPins : IReadOnlyDictionary<string, string>
    {
        public string this[string key] => throw new InvalidOperationException("boom");
        public IEnumerable<string> Keys => Array.Empty<string>();
        public IEnumerable<string> Values => Array.Empty<string>();
        public int Count => 0;
        public bool ContainsKey(string key) => throw new InvalidOperationException("boom");
        public bool TryGetValue(string key, out string value) => throw new InvalidOperationException("boom");
        public IEnumerator<KeyValuePair<string, string>> GetEnumerator() => throw new InvalidOperationException("boom");
        System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator() => throw new InvalidOperationException("boom");
    }

    [Fact]
    public void ThrowingPinsAndMessagesFailClosed()
    {
        var id = Pub("r3/id");
        Assert.False(IntentJs.VerifyPinnedSuite("ml-dsa-65", true, id, "pk", new byte[] { 1 }, "AA", "BB", new ThrowingPins()));
        Assert.False(Pq.Verify(Pq.Prim.MlDsa65, new byte[Pq.Lens(Pq.Prim.MlDsa65).Pk], null!, new byte[Pq.Lens(Pq.Prim.MlDsa65).Sig]));
        Assert.False(Pq.Verify(Pq.Prim.Slh128f, new byte[32], null!, new byte[Pq.Lens(Pq.Prim.Slh128f).Sig]));
        Assert.False(Pca.VerifyThresholdShare(Throwing(new D { ["role"] = "agent" })));
    }

    [Fact]
    public void RevocationEpochChecksSpellTheirReasonsAndHandleSessionlessScope()
    {
        // session and scope both absent: the grant binding is "pca-intent-session:null"
        var scope = "pca-intent-session:null";
        var ep = RevEpoch(new List<string> { "a" }, NOW - 1_000, "v2/revocation-authority", scope);
        var ev = new D { ["epoch"] = ep, ["revoked"] = new L { "a" } };
        Assert.Null(IntentRevocation.CheckSessionRevocation(IntentJs.Normalize(ev), null, Pub("v2/revocation-authority"), new L(), NOW, 60_000, null, null, false, null));
        // CheckRevocationEpoch directly: a guardian that is not the pinned one, and a suite this SDK lacks
        var e2 = (D)IntentJs.Normalize(ep)!;
        Assert.Equal("revocation epoch not signed by the pinned guardian", IntentRevocation.CheckRevocationEpoch(e2, Pub("v2/principal"), NOW, scope, null));
        var e3 = new D(e2) { ["alg"] = "fn-dsa-512" };
        Assert.Equal("revocation epoch not signed by the pinned guardian", IntentRevocation.CheckRevocationEpoch(e3, Pub("v2/revocation-authority"), NOW, scope, null));
        Assert.Null(IntentRevocation.CheckRevocationEpoch(e2, Pub("v2/revocation-authority"), NOW, scope, null));
        // a hybrid epoch verifies only under the pinned PQ key
        var k = UnitKillTests.PqKey();
        var body = new D(); foreach (var f in new[] { "instance_id", "grant_ref", "epoch", "set_size", "root", "issued_at", "not_after" }) body[f] = e2[f];
        var bound = IntentJs.BindSuiteFields(body, "hybrid-ed25519-ml-dsa-65", true, UnitKillTests.PqPk(k), true);
        var msg = Pca.Concat(Encoding.UTF8.GetBytes(IntentRevocation.RevepochDomain), IntentJs.CanonBytes(bound));
        var h = new D(e2) { ["alg"] = "hybrid-ed25519-ml-dsa-65", ["pq_pk"] = UnitKillTests.PqPk(k), ["sig"] = Sign("v2/revocation-authority", msg), ["pq_sig"] = UnitKillTests.PqSign(k, msg) };
        var pins = new Dictionary<string, string> { [Pub("v2/revocation-authority")] = UnitKillTests.PqPk(k) };
        Assert.Null(IntentRevocation.CheckRevocationEpoch(h, Pub("v2/revocation-authority"), NOW, scope, pins));
        Assert.Equal("revocation epoch signature invalid", IntentRevocation.CheckRevocationEpoch(h, Pub("v2/revocation-authority"), NOW, scope, null));
        var wrongPq = new D(h) { ["pq_sig"] = UnitKillTests.PqSign(UnitKillTests.PqKey(), msg) };
        Assert.Equal("revocation epoch signature invalid", IntentRevocation.CheckRevocationEpoch(wrongPq, Pub("v2/revocation-authority"), NOW, scope, pins));
        var noPqSig = new D(h); noPqSig.Remove("pq_sig");
        Assert.Equal("revocation epoch signature invalid", IntentRevocation.CheckRevocationEpoch(noPqSig, Pub("v2/revocation-authority"), NOW, scope, pins));
    }

    static D RevEpoch(List<string> revoked, long issued, string signer, string scope)
    {
        revoked.Sort(IntentJs.CompareUtf8);
        var body = M("instance_id", "ana", "grant_ref", scope, "epoch", (long)revoked.Count, "set_size", (long)revoked.Count, "root", IntentRevocation.RevsetRoot(revoked),
            "issued_at", issued, "not_after", issued + 300_000L);
        var ep = new D(body);
        ep["guardian"] = Pub(signer);
        ep["sig"] = Sign(signer, Pca.Concat(Encoding.UTF8.GetBytes(IntentRevocation.RevepochDomain), IntentJs.CanonBytes(body)));
        return ep;
    }

    [Fact]
    public void PrimitiveReasonsAndDenyShape()
    {
        var entry = ((L)((D)((D)Pca.ParseJson(File.ReadAllText(Path.Combine(ConfDir(), "vectors.json")))!)["primitives"]!)["intent_schema"]!).Cast<D>()
            .First(e => IntentPrimitives.Result("intent_schema", e["input"]) is { } g && g["sig"] is true && ((D)g["conform"]!)["ok"] is false);
        var inp = (D)IntentJs.Normalize(entry["input"])!;
        var want = ActionSchema.ConformAction(inp["schema"], IntentJs.Get(inp, "verb") as string ?? "", IntentJs.Get(inp, "params")).Reason;
        Assert.NotNull(want);
        Assert.Equal(want, IntentPrimitives.Reason("intent_schema", entry["input"]));
        var noVerb = new D(inp); noVerb.Remove("verb");
        Assert.Equal("verb '' is not declared by the schema", IntentPrimitives.Reason("intent_schema", noVerb));
        Assert.False(IntentPrimitives.Result("intent_schema", noVerb)!["conform"] is not D);
        var deny = ((L)((D)((D)Pca.ParseJson(File.ReadAllText(Path.Combine(ConfDir(), "vectors.json")))!)["primitives"]!)["intent_provenance"]!).Cast<D>()
            .First(e => (string)((D)e["expect"]!)["outcome"]! == "deny");
        var r = IntentPrimitives.Result("intent_provenance", deny["input"])!;
        Assert.Equal(new[] { "outcome" }, r.Keys.ToArray());
    }

    static string ConfDir()
    {
        var d = AppContext.BaseDirectory;
        for (int i = 0; i < 12 && d != null; i++, d = Path.GetDirectoryName(d))
        {
            var c = Path.Combine(d, "packages", "pca", "conformance");
            if (File.Exists(Path.Combine(c, "vectors.json"))) return c;
        }
        throw new InvalidOperationException("conformance dir not found");
    }

    [Fact]
    public void ClassRangeStartingAtAnEscapedBracket()
    {
        Assert.True(SafeRegex.FullMatch("[\\]-a]", "^") == true);
        Assert.True(SafeRegex.FullMatch("[\\]-a]", "_") == true);
        Assert.True(SafeRegex.FullMatch("[\\]-a]", "-") == false);
        Assert.Equal("4503599627370495.5", ((Num)IntentJs.Normalize(new Num("4503599627370495.5"))!).Raw);
        Assert.Equal("1234567890.123456", ((Num)IntentJs.Normalize(new Num("1234567890.123456"))!).Raw);
    }

    [Fact]
    public void ClassifierLabelsAreEachBoundedAndDistinct()
    {
        D Cl(params object[] labels) => new() { ["id"] = "tone", ["param"] = "action.params.text", ["labels"] = new L(labels), ["keys"] = new L { Pca.B64u(new byte[32]) }, ["k"] = new Num("1") };
        D Pol(D c) => new() { ["classifiers"] = new L { c } };
        Assert.Null(IntentClassifier.ValidatePolicy(Pol(Cl("a", "b"))));
        var msg = "classifier 'tone': labels must be distinct non-empty strings";
        Assert.Equal(msg, IntentClassifier.ValidatePolicy(Pol(Cl("a", new string('x', 65)))));
        Assert.Equal(msg, IntentClassifier.ValidatePolicy(Pol(Cl("a", "a"))));
        Assert.Equal(msg, IntentClassifier.ValidatePolicy(Pol(Cl("a", ""))));
        Assert.Equal(msg, IntentClassifier.ValidatePolicy(Pol(Cl(new string('x', 65), "a"))));
        Assert.Null(IntentClassifier.ValidatePolicy(Pol(Cl(new string('x', 64), "a"))));
    }
}

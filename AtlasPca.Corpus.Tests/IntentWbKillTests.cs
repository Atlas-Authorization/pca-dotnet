using AtlasPca;
using Xunit;
using static AtlasPca.Corpus.Tests.IntentV2KillTests;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Mutation kills for the W-B rules 16 (facts, relational, offer sets), 17 (provenance, label receipts, flows), 18
/// (classifiers), the W-B unit and its activity (mirrors IntentWbKillTest.java), plus the predicate DSL and the regex engine.</summary>
public class IntentWbKillTests
{
    static readonly string SESSION = B64Seed("wb/session");

    static D Signed(string domain, D body, string key) { var a = new D(body) { ["sig"] = Sign(key, IntentJs.Message(domain, body)) }; return a; }
    static D Fact(string name, string subject, object value, long tObs, string oracle, string key) =>
        Signed(OracleFacts.FactDomain, M("v", 1L, "kind", "pca-fact", "name", name, "subject", subject, "value", value, "t_obs", tObs, "oracle", oracle), key);
    static D World(int min, int faulty, long fresh) => M("name", "fx", "subject_path", "action.resource", "freshness_ms", fresh, "min_oracles", (long)min, "max_faulty", (long)faulty,
        "oracles", Li(M("kid", "o1", "pk", Pub("wb/o1")), M("kid", "o2", "pk", Pub("wb/o2")), M("kid", "o3", "pk", Pub("wb/o3"))));
    static D Action(params object?[] prms) => M("verb", "air.book", "resource", "EURUSD", "params", M(prms));
    static OracleFacts.WorldResult DecideWorld(L facts, D policy, object? now, D action) =>
        OracleFacts.DecideIntentWorld(M("now", now, "aud", AUD, "session", SESSION, "action", action,
            "committed", M("facts", new L(facts.Select(f => (object?)OracleFacts.FactRef((D)IntentJs.Normalize(f)!)))), "facts", facts, "policy", policy));

    [Fact]
    public void WorldMedianFreshnessClockAndRefusals()
    {
        var pol3 = M("worlds", Li(World(3, 1, 60_000L)));
        var r = DecideWorld(Li(Fact("fx", "EURUSD", 7L, NOW, "o1", "wb/o1"), Fact("fx", "EURUSD", 1L, NOW, "o2", "wb/o2"), Fact("fx", "EURUSD", 9L, NOW, "o3", "wb/o3")), pol3, NOW, Action());
        Assert.True(r.Ok, r.Reason);
        Assert.Equal("7", ((Num)r.World!["fx"]!).Raw);
        var pol2 = M("worlds", Li(World(2, 0, 60_000L)));
        Assert.Equal("1", ((Num)DecideWorld(Li(Fact("fx", "EURUSD", 9L, NOW, "o1", "wb/o1"), Fact("fx", "EURUSD", 1L, NOW, "o2", "wb/o2")), pol2, NOW, Action()).World!["fx"]!).Raw);
        Assert.True(DecideWorld(Li(Fact("fx", "EURUSD", 1L, NOW - 60_000, "o1", "wb/o1"), Fact("fx", "EURUSD", 1L, NOW + 60_000, "o2", "wb/o2")), pol2, NOW, Action()).Ok);
        Assert.False(DecideWorld(Li(Fact("fx", "EURUSD", 1L, NOW - 60_001, "o1", "wb/o1"), Fact("fx", "EURUSD", 1L, NOW, "o2", "wb/o2")), pol2, NOW, Action()).Ok);
        Assert.False(DecideWorld(Li(Fact("fx", "EURUSD", 1L, NOW + 60_001, "o1", "wb/o1"), Fact("fx", "EURUSD", 1L, NOW, "o2", "wb/o2")), pol2, NOW, Action()).Ok);
        foreach (var badNow in new object?[] { NOW.ToString(), new Num("1800000000000.5"), null })
            Assert.False(DecideWorld(Li(Fact("fx", "EURUSD", 1L, NOW, "o1", "wb/o1"), Fact("fx", "EURUSD", 1L, NOW, "o2", "wb/o2")), pol2, badNow, Action()).Ok);
        Assert.False(DecideWorld(Li(Fact("fx", "EURUSD", "up", NOW, "o1", "wb/o1"), Fact("fx", "EURUSD", 1L, NOW, "o2", "wb/o2")), pol2, NOW, Action()).Ok);
        Assert.Equal(new List<string> { "fx" }, DecideWorld(Li(Fact("fx", "EURUSD", 1L, NOW, "o1", "wb/o1")), M("worlds", Li(World(1, 0, 60_000L))), NOW, Action()).SingleSource);
        var f1 = Fact("fx", "EURUSD", 1L, NOW, "o1", "wb/o1");
        Assert.False(DecideWorld(Li(f1, Fact("fx", "EURUSD", 1L, NOW, "o1", "wb/o1x")), pol2, NOW, Action()).Ok);
        Assert.False(DecideWorld(Li(f1, Fact("fx", "GBPUSD", 1L, NOW, "o2", "wb/o2")), pol2, NOW, Action()).Ok);
        Assert.False(DecideWorld(Li(f1, Fact("fx", "EURUSD", 2L, NOW + 1, "o1", "wb/o1")), pol2, NOW, Action()).Ok);
        Assert.False(DecideWorld(Li(), M("worlds", Li(World(2, 1, 60_000L))), NOW, Action()).Ok);
        // closed and typed policies; null is malformed; an unimplemented fact suite is unsupported_suite
        Assert.False(DecideWorld(Li(), M("extra", 1L), NOW, Action()).Ok);
        Assert.False(DecideWorld(Li(), M("worlds", null), NOW, Action()).Ok);
        Assert.False(DecideWorld(Li(), M("skew_ms", "60000"), NOW, Action()).Ok);
        var w = World(2, 0, 60_000L); w["note"] = "x";
        Assert.False(DecideWorld(Li(), M("worlds", Li(w)), NOW, Action()).Ok);
        var algFact = Fact("fx", "EURUSD", 1L, NOW, "o1", "wb/o1"); algFact["alg"] = "no-such-suite";
        Assert.Contains("unsupported_suite", DecideWorld(Li(algFact, Fact("fx", "EURUSD", 1L, NOW, "o2", "wb/o2")), pol2, NOW, Action()).Reason);
    }

    [Fact]
    public void Relational()
    {
        var pol = M("relational", Li(M("name", "d", "fn", "sub", "a", "action.params.a", "b", "action.params.b"), M("name", "r", "fn", "ratio_ppm", "a", "env.world.d", "b", "action.params.b")));
        var ok = DecideWorld(Li(), pol, NOW, Action("a", 3L, "b", 2L));
        Assert.True(ok.Ok, ok.Reason);
        Assert.Equal("500000", ((Num)ok.World!["r"]!).Raw);
        Assert.False(DecideWorld(Li(), pol, NOW, Action("a", 3L, "b", 0L)).Ok);
        Assert.False(DecideWorld(Li(), pol, NOW, Action("a", 9007199254740991L, "b", -9007199254740991L)).Ok);
        Assert.True(DecideWorld(Li(), pol, "x", Action("a", 3L, "b", 2L)).Ok);
        Assert.Equal("1", ((Num)DecideWorld(Li(), M("relational", Li(M("name", "constructor", "fn", "sub", "a", "action.params.a", "b", "action.params.b"))), NOW, Action("a", 3L, "b", 2L)).World!["constructor"]!).Raw);
    }

    static D OfferSet(params object?[] over)
    {
        var body = M("v", 1L, "kind", "pca-offer-set", "site", AUD, "session", SESSION, "query", M("from", "SFO"), "rank", "price_asc", "complete", true,
            "offers", Li(M("offer_id", "A", "price", 100L, "cabin", "eco"), M("offer_id", "B", "price", 150L, "cabin", "eco"), M("offer_id", "C", "price", 90L, "cabin", "biz")),
            "issued_at", NOW - 1_000L, "kid", "s1");
        foreach (var (k, v) in M(over)) body[k] = v;
        return Signed(OracleFacts.OfferSetDomain, body, "wb/site");
    }
    static D OffersPolicy(long maxAge) => M("offers", M("name", "excess", "site_keys", Li(M("kid", "s1", "pk", Pub("wb/site"))), "max_age_ms", maxAge, "offer_param", "action.params.offer_id",
        "filter", M("query", M("from", "SFO"), "offer", M("cabin", "eco"))));
    static OracleFacts.WorldResult DecideOffers(D os, D pol, object? now, string chosen) =>
        OracleFacts.DecideIntentWorld(M("now", now, "aud", AUD, "session", SESSION, "action", Action("offer_id", chosen),
            "committed", M("offer_set", OracleFacts.OfferSetRef((D)IntentJs.Normalize(os)!)), "offer_set", os, "policy", pol));

    [Fact]
    public void OfferSets()
    {
        var ok = DecideOffers(OfferSet(), OffersPolicy(60_000L), NOW, "B");
        Assert.True(ok.Ok, ok.Reason);
        Assert.Equal("50", ((Num)ok.World!["excess"]!).Raw);
        Assert.False(DecideOffers(OfferSet(), OffersPolicy(60_000L), NOW, "C").Ok);
        Assert.True(DecideOffers(OfferSet(), OffersPolicy(1_000L), NOW, "A").Ok);
        Assert.False(DecideOffers(OfferSet(), OffersPolicy(999L), NOW, "A").Ok);
        Assert.False(DecideOffers(OfferSet(), OffersPolicy(60_000L), NOW.ToString(), "A").Ok);
        Assert.False(DecideOffers(OfferSet("complete", false), OffersPolicy(60_000L), NOW, "A").Ok);
        Assert.False(DecideOffers(OfferSet("query", M("from", "SFO", "to", "JFK")), OffersPolicy(60_000L), NOW, "A").Ok);
        Assert.True(DecideOffers(OfferSet("query", M()), OffersPolicy(60_000L), NOW, "A").Ok);
        Assert.False(DecideOffers(OfferSet("issued_at", NOW + 60_001L), OffersPolicy(120_000L), NOW, "A").Ok);
        Assert.True(DecideOffers(OfferSet("issued_at", NOW + 60_000L), OffersPolicy(120_000L), NOW, "A").Ok);
        Assert.False(OracleFacts.OfferMatches(M("x", 2L), M("x", "2")));
        Assert.True(OracleFacts.OfferMatches(M("x", 2L), M("x", new Num("2"))));
        Assert.Contains("unsupported_suite", DecideOffers(OfferSet("alg", "no-such-suite"), OffersPolicy(60_000L), NOW, "A").Reason);
        var pol = OffersPolicy(60_000L); ((D)pol["offers"]!)["extra"] = 1L;
        Assert.False(DecideOffers(OfferSet(), pol, NOW, "A").Ok);
    }

    static D Labels(string site, string kid, string key, D fields) =>
        Signed(ParamProvenance.LabelsDomain, M("v", 1L, "kind", "pca-labels", "site", site, "session", SESSION, "response_digest", B64Seed("wb/resp"), "fields", fields, "issued_at", NOW, "kid", kid), key);
    static ParamProvenance.ProvResult Prov(D prms, D prov, L receipts, D policy) =>
        ParamProvenance.Decide(M("aud", AUD, "session", SESSION, "action", M("params", prms), "prov", prov,
            "committed_labels", new L(receipts.Select(r => (object?)ParamProvenance.LabelsRef((D)IntentJs.Normalize(r)!))), "labels", receipts, "policy", policy));

    [Fact]
    public void ProvenanceLabelsAndFlows()
    {
        var reg = M("vouched", "trusted", "fp", "first_party", "web", "web");
        var pol = M("params", M("action.params.offer_id", "material", "action.params.total", "critical"), "registry", reg);
        Assert.Equal("pass", Prov(M("offer_id", "A", "total", 5L), M("action.params.offer_id", Li("fp"), "action.params.total", Li("vouched")), Li(), pol).Outcome);
        var q = Prov(M("offer_id", "A", "total", 5L), M("action.params.offer_id", Li("web"), "action.params.total", Li("vouched")), Li(), pol);
        Assert.Equal("question", q.Outcome); Assert.Equal("tap", q.Friction);
        Assert.Equal("typed", Prov(M("offer_id", "A", "total", 5L), M("action.params.offer_id", Li("fp"), "action.params.total", Li("web")), Li(), pol).Friction);
        Assert.Equal("agent", Prov(M("offer_id", "A", "total", 5L), M("action.params.offer_id", Li("fp")), Li(), pol).Labels["action.params.total"]);
        Assert.Equal("agent", Prov(M("offer_id", "A"), M("action.params.offer_id", Li("constructor")), Li(), M("params", M(), "registry", reg)).Labels["action.params.offer_id"]);
        var strict = new D(pol) { ["critical_max"] = "first_party" };
        Assert.Equal("deny", Prov(M("offer_id", "A", "total", 5L), M("action.params.offer_id", Li("fp"), "action.params.total", Li("web")), Li(), strict).Outcome);
        Assert.Equal("deny", Prov(M("offer_id", "A"), M(), Li(), new D(pol) { ["critical_tainted"] = "allow" }).Outcome);
        Assert.Equal("deny", Prov(M("offer_id", "A"), M(), Li(), new D(pol) { ["extra"] = 1L }).Outcome);
        Assert.Equal("deny", Prov(M("constructor", "x"), M("action.params.constructor", Li("fp")), Li(), M("params", M())).Outcome);
        var keys = M("params", M("action.params.offer_id", "material"), "label_keys", Li(M("site", AUD, "kid", "k1", "pk", Pub("wb/site")), M("site", "gov.example", "kid", "g1", "pk", Pub("wb/gov"))));
        var mine = Labels(AUD, "k1", "wb/site", M("offer", M("class", "pii.contact", "value_digest", Pca.HashCanonical("A"))));
        var reference = "pca-labels:" + ParamProvenance.LabelsRef((D)IntentJs.Normalize(mine)!) + "#offer";
        var fp = Prov(M("offer_id", "A"), M("action.params.offer_id", Li(reference)), Li(mine), keys);
        Assert.Equal("pass", fp.Outcome);
        Assert.Equal("first_party", fp.Labels["action.params.offer_id"]);
        Assert.Equal("question", Prov(M("offer_id", "B"), M("action.params.offer_id", Li(reference)), Li(mine), keys).Outcome);
        var gov = Labels("gov.example", "g1", "wb/gov", M("offer", M("class", "pii.contact", "value_digest", Pca.HashCanonical("A"))));
        var gref = "pca-labels:" + ParamProvenance.LabelsRef((D)IntentJs.Normalize(gov)!) + "#offer";
        Assert.Equal("deny", Prov(M("offer_id", "A"), M("action.params.offer_id", Li(gref)), Li(gov), keys).Outcome);
        Assert.Equal("question", Prov(M("offer_id", "A"), M("action.params.offer_id", Li(gref)), Li(gov), new D(keys) { ["flows"] = M("pii.*", Li(AUD)) }).Outcome);
        Assert.Equal("deny", Prov(M("offer_id", "A"), M("action.params.offer_id", Li(gref)), Li(gov), new D(keys) { ["flows"] = M("pii.*", Li(AUD), "pii.contact", Li("x.example")) }).Outcome);
        var rules = M("pii.*", Li("a"), "pii.contact.*", Li("b"), "*", Li("c"));
        Assert.Equal("pii.contact.*", ParamProvenance.FlowRuleFor(rules, "pii.contact.email"));
        Assert.Equal("pii.*", ParamProvenance.FlowRuleFor(rules, "pii.contact"));
        Assert.Equal("*", ParamProvenance.FlowRuleFor(rules, "piix"));
        var algLabels = Labels(AUD, "k1", "wb/site", M("offer", M("class", "pii.contact", "value_digest", Pca.HashCanonical("A")))); algLabels["alg"] = "no-such-suite";
        var aref = "pca-labels:" + ParamProvenance.LabelsRef((D)IntentJs.Normalize(algLabels)!) + "#offer";
        Assert.Contains("unsupported_suite", Prov(M("offer_id", "A"), M("action.params.offer_id", Li(aref)), Li(algLabels), keys).Reason);
    }

    static D Verdict(string label, string key, object content) =>
        Signed(IntentClassifier.IntentClassifierDomain, M("v", 1L, "kind", "pca-intent-classification", "classifier", "tone", "session", SESSION,
            "content_digest", Pca.HashCanonical(content), "label", label, "measurement", "m1", "judge", Pub(key)), key);
    static IntentClassifier.ClassResult Classify(L verdicts, long k, object? measurements, params object?[] extra)
    {
        var c = M("id", "tone", "param", "action.params.body", "labels", Li("apologetic", "neutral"), "keys", Li(Pub("wb/j1"), Pub("wb/j2"), Pub("wb/j3")), "k", k);
        if (measurements != null) c["measurements"] = measurements;
        foreach (var (key, v) in M(extra)) c[key] = v;
        return IntentClassifier.Decide(M("session", SESSION, "action", M("params", M("body", "sorry")),
            "committed", new L(verdicts.Select(v => (object?)IntentClassifier.VerdictRef((D)IntentJs.Normalize(v)!))), "verdicts", verdicts, "policy", M("classifiers", Li(c))));
    }

    [Fact]
    public void Classifiers()
    {
        var a1 = Verdict("apologetic", "wb/j1", "sorry"); var a2 = Verdict("apologetic", "wb/j2", "sorry"); var n3 = Verdict("neutral", "wb/j3", "sorry");
        var r = Classify(Li(a1, a2, n3), 2, null);
        Assert.True(r.Ok, r.Reason);
        Assert.Equal("apologetic", r.Classes!["tone"]);
        Assert.False(Classify(Li(a1, n3), 2, null).Ok);
        Assert.False(Classify(Li(a1, n3), 1, null).Ok);
        Assert.True(Classify(Li(a1), 1, null).Ok);
        Assert.False(Classify(Li(a1), 4, null).Ok);
        Assert.False(Classify(Li(a1), 0, null).Ok);
        Assert.False(Classify(Li(a1, Verdict("neutral", "wb/j1", "sorry")), 1, null).Ok);
        Assert.False(Classify(Li(Verdict("apologetic", "wb/stranger", "sorry")), 1, null).Ok);
        Assert.False(Classify(Li(Verdict("apologetic", "wb/j1", "other")), 1, null).Ok);
        Assert.True(Classify(Li(a1), 1, Li("m1")).Ok);
        Assert.False(Classify(Li(a1), 1, Li("m2")).Ok);
        Assert.False(Classify(Li(a1), 1, "m1").Ok);
        Assert.False(Classify(Li(a1), 1, null, "pq_keys", M(Pub("wb/stranger"), "x")).Ok);
        Assert.False(Classify(Li(a1), 1, null, "extra", 1L).Ok);
        var alg = Verdict("apologetic", "wb/j1", "sorry"); alg["alg"] = "no-such-suite";
        Assert.Contains("unsupported_suite", Classify(Li(alg), 1, null).Reason);
    }

    [Fact]
    public void ActivityAndUnit()
    {
        Assert.Equal((false, false, false), IntentWB.Active(M("intent_session", M(), "policy", M())));
        Assert.Equal((true, true, true), IntentWB.Active(M("intent_session", M("facts", Li(SESSION), "prov", M(), "classes", Li(SESSION)), "policy", M())));
        Assert.Equal((false, true, false), IntentWB.Active(M("intent_session", M("facts", Li(), "prov", null, "classes", Li()), "policy", M())));
        Assert.Equal((false, false, false), IntentWB.Active(M("intent_session", M(), "policy", M("world", M("worlds", M("length", 1L), "offers", Li()), "provenance", Li(), "classifiers", M("length", 1L)))));
        var r = IntentWB.Decide((D)IntentJs.Normalize(M("now", NOW, "aud", AUD, "session", SESSION, "action", Action(), "intent_session", M(),
            "policy", M("world", M("worlds", Li(M())), "provenance", M("params", M()), "classifiers", Li(M()))))!);
        Assert.Equal("deny", r.Outcome);
        Assert.Equal(new[] { "facts" }, r.Checks.Select(c => c.Key));
        var q = IntentWB.Decide((D)IntentJs.Normalize(M("now", NOW, "aud", AUD, "session", SESSION, "action", Action("x", "1"), "intent_session", M(),
            "policy", M("provenance", M("params", M("action.params.x", "material")), "classifiers", Li(M()))))!);
        Assert.Equal(new[] { "provenance", "classes" }, q.Checks.Select(c => c.Key));
        Assert.Equal("question", q.Check("provenance"));
        Assert.Equal("fail", q.Check("classes"));
        // a malformed W-B context fails facts
        var m = IntentWB.Decide((D)IntentJs.Normalize(M("now", NOW, "aud", AUD, "session", SESSION, "action", Action(), "intent_session", M(), "artifacts", null))!);
        Assert.Equal(new[] { "facts" }, m.Checks.Select(c => c.Key));
    }

    // ---- predicate DSL and the linear-time regex ----
    static D Ctx() => M("action", M("verb", "air.book", "resource", "skyair.example/bookings/7", "params",
        M("total", new Num("38900"), "name", "Ana", "tags", Li("a", "b"), "nested", M("x", new Num("1")), "astral", "\U0001F600")), "env", M("cur", "dev1"));
    static Predicates.Tri Leaf(string field, string op, object? value) => Predicates.EvaluateConditionTri(M("field", field, "op", op, "value", value), Ctx());

    [Fact]
    public void PredicateOperators()
    {
        Assert.Equal(Predicates.Tri.True, Leaf("action.params.total", "eq", new Num("38900.0")));
        Assert.Equal(Predicates.Tri.False, Leaf("action.params.total", "eq", "38900"));
        Assert.Equal(Predicates.Tri.True, Leaf("action.params.total", "lte", new Num("38900")));
        Assert.Equal(Predicates.Tri.False, Leaf("action.params.total", "lt", new Num("38900")));
        Assert.Equal(Predicates.Tri.Unknown, Leaf("action.params.total", "lt", "x"));
        Assert.Equal(Predicates.Tri.True, Leaf("action.params.astral", "gt", "￿"));
        Assert.Equal(Predicates.Tri.True, Leaf("action.params.nested", "eq", M("x", new Num("1.0"))));
        Assert.Equal(Predicates.Tri.True, Leaf("action.params.missing", "exists", false));
        Assert.Equal(Predicates.Tri.Unknown, Leaf("action.params.missing", "eq", "x"));
        Assert.Equal(Predicates.Tri.False, Leaf("action.params.__proto__", "exists", true));
        Assert.Equal(Predicates.Tri.True, Leaf("action.params.tags.1", "eq", "b"));
        Assert.Equal(Predicates.Tri.Unknown, Leaf("action.params.tags.01", "eq", "b"));
        Assert.Equal(Predicates.Tri.True, Leaf("action.params.name", "like", "A?a"));
        Assert.Equal(Predicates.Tri.Unknown, Leaf("action.params.name", "like", "A\\"));
        Assert.Equal(Predicates.Tri.True, Leaf("action.params.name", "matches", "A.a"));
        Assert.Equal(Predicates.Tri.Unknown, Leaf("action.params.name", "matches", "(a+)+"));
        var t = M("field", "action.verb", "op", "eq", "value", "air.book");
        var u = M("field", "action.params.zz", "op", "eq", "value", "x");
        Assert.Equal(Predicates.Tri.Unknown, Predicates.EvaluateConditionTri(M("not", u), Ctx()));
        Assert.Equal(Predicates.Tri.True, Predicates.EvaluateConditionTri(M("any_of", Li(u, t)), Ctx()));
        Assert.Equal(Predicates.Tri.Unknown, Predicates.EvaluateConditionTri(M("all_of", Li(t, u)), Ctx()));
        Assert.True(Predicates.EvaluatePredicates(Li(M("verb", "*", "resource", "re:skyair\\.example/bookings/\\d+")), Ctx()));
        Assert.False(Predicates.EvaluatePredicates(Li(M("verb", "*", "resource", "re:skyair")), Ctx()));
        Assert.False(Predicates.EvaluatePredicates(Li(), Ctx()));
        Assert.False(Predicates.EvaluatePredicates(Li(M("verb", "*", "resource", null)), Ctx()));
        var where = new L();
        for (int i = 0; i < 64; i++) where.Add(M("field", "action.params.name", "op", "matches", "value", "A.a"));
        Assert.True(Predicates.EvaluatePredicates(Li(M("verb", "*", "where", where)), Ctx()));
        where.Add(M("field", "action.params.name", "op", "matches", "value", "A.a"));
        Assert.False(Predicates.EvaluatePredicates(Li(M("verb", "*", "where", where)), Ctx()));
    }

    [Fact]
    public void RegexGuardAndEngine()
    {
        Assert.True(SafeRegex.IsSafeSource("/acct/[^/]+/items/\\d+"));
        Assert.False(SafeRegex.IsSafeSource("(a+)+"));
        Assert.False(SafeRegex.IsSafeSource("(a)\\1"));
        Assert.False(SafeRegex.IsSafeSource("a{65}"));
        Assert.True(SafeRegex.IsSafeSource("a{64}"));
        Assert.False(SafeRegex.IsSafeSource("[^](a+)+]"));
        Assert.True(SafeRegex.IsSafeSource(string.Concat(Enumerable.Repeat("a?", 22))));
        Assert.False(SafeRegex.IsSafeSource(string.Concat(Enumerable.Repeat("a?", 23))));
        Assert.Equal(6, SafeRegex.CeilLog2(64));
        Assert.Equal(7, SafeRegex.CeilLog2(65));
        Assert.Equal(true, SafeRegex.FullMatch("[]|x", "x"));
        Assert.Equal(true, SafeRegex.FullMatch("[^]", "\n"));
        Assert.Equal(false, SafeRegex.FullMatch(".", "\n"));
        Assert.Null(SafeRegex.FullMatch("[c-a]", "b"));
        Assert.Equal(true, SafeRegex.FullMatch("\\x41\\u0042\\cJ", "AB\n"));
        Assert.Equal(true, SafeRegex.FullMatch("..", "\U0001F600"));
        var c = SafeRegex.Compile("a*")!;
        int n = (int)(SafeRegex.MaxMatchSteps / c.Size);
        Assert.NotNull(SafeRegex.Run(c, new string('a', n - 1)));
        Assert.Null(SafeRegex.Run(c, new string('a', n)));
    }

    [Fact]
    public void Round3FactPairsAreKeyedByWorldAndOracleSeparately()
    {
        D W(string name, string kid, string key) => M("name", name, "subject_path", "action.resource", "freshness_ms", 60_000L, "min_oracles", 1L, "max_faulty", 0L,
            "oracles", Li(M("kid", kid, "pk", Pub(key))));
        var policy = M("worlds", Li(W("a", "bc", "wb/o1"), W("ab", "c", "wb/o2")));
        var r = DecideWorld(Li(Fact("a", "EURUSD", 1L, NOW, "bc", "wb/o1"), Fact("ab", "EURUSD", 2L, NOW, "c", "wb/o2")), policy, NOW, Action());
        Assert.True(r.Ok, r.Reason);
        Assert.Equal("1", ((Num)r.World!["a"]!).Raw); Assert.Equal("2", ((Num)r.World!["ab"]!).Raw);
        Assert.Equal("offer set must be an object", OracleFacts.ValidateOfferSetWire(new Num("5")));
        Assert.Equal("offer set must be an object", OracleFacts.ValidateOfferSetWire(null));
    }
}

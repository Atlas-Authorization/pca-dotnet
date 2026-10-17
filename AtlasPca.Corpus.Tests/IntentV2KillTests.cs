using System.Security.Cryptography;
using System.Text;
using AtlasPca;
using Org.BouncyCastle.Math.EC.Rfc8032;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>
/// Intent Layer v2 W-A mutation kills (mirrors IntentV2KillTest.java): the intent_session wire, session root, delta chain and
/// revocation (rule 13), the closed-world schema (rule 14), accumulators / monitors / receipts / sequencer key sets (rule 15),
/// the layers slot, the closed and typed verifier context, and the pipeline's reporting and order, signed end to end.
/// </summary>
public class IntentV2KillTests
{
    internal const long NOW = 1_800_000_000_000L;
    internal const string AUD = "skyair.example";

    internal static D M(params object?[] kv) { var d = new D(); for (int i = 0; i < kv.Length; i += 2) d[(string)kv[i]!] = kv[i + 1]; return d; }
    internal static L Li(params object?[] v) => new(v);
    static D Copy(D d) => new(d);

    internal static byte[] Seed(string label) => SHA256.HashData(Encoding.UTF8.GetBytes("atlas-pca-conformance/" + label));
    internal static string Pub(string label) { var pk = new byte[32]; Ed25519.GeneratePublicKey(Seed(label), 0, pk, 0); return Pca.B64u(pk); }
    internal static string Sign(string label, byte[] msg) { var sig = new byte[64]; Ed25519.Sign(Seed(label), 0, msg, 0, msg.Length, sig, 0); return Pca.B64u(sig); }
    internal static string B64Seed(string label) => Pca.B64u(Seed(label));

    const string PRINCIPAL = "v2/principal", AGENT = "v2/agent", SITE = "v2/site", SEQ_ROOT = "v2/sequencer-root", SEQ_KEY = "v2/sequencer", STRANGER = "v2/stranger";
    static readonly string REF = B64Seed("v2/ref"), MAP0 = B64Seed("v2/map0"), MAP1 = B64Seed("v2/map1"), SESSION = B64Seed("v2/session");

    static D UnsignedSchema() => M("v", 1L, "kind", "pca-action-schema", "site", "https://skyair.example", "aud", AUD, "version", "2026-10-01",
        "units", M("usd_cents", M("kind", "money", "currency", "USD", "exponent", 2L)),
        "verbs", Li(
            M("verb", "air.book", "kind", "write", "params", M(
                "action.params.offer_id", M("type", "string", "semantic", "product.ref", "sensitivity", "material"),
                "action.params.total", M("type", "integer", "unit", "usd_cents", "min", 0L, "max", 5_000_000L, "semantic", "money.amount", "sensitivity", "critical", "accumulates_into", Li("spend.usd_cents")),
                "action.params.add_ons", M("type", "set", "values", Li("none", "tripshield", "seat_plus"), "default", Li("none"), "principal_neutral_default", true, "semantic", "product.addon", "sensitivity", "material"),
                "action.params.refundable", M("type", "boolean", "semantic", "flag", "sensitivity", "material"),
                "action.params.passengers", M("type", "array", "max_items", 9L, "max_len", 64L, "semantic", "person.identity", "sensitivity", "critical", "required", false),
                "action.params.note", M("type", "string", "semantic", "text.note", "sensitivity", "free", "required", false, "max_len", 16L)),
                "reversibility_by", M("param", "action.params.refundable", "map", M("true", "reversible", "false", "irreversible"))),
            M("verb", "air.search", "kind", "read", "params", M(
                "action.params.from", M("type", "string", "values", Li("SFO", "JFK"), "semantic", "place.airport", "sensitivity", "material"),
                "action.params.date", M("type", "date", "semantic", "schedule.date", "sensitivity", "material"),
                "action.params.pax", M("type", "integer", "min", 1L, "max", 9L, "semantic", "quantity", "sensitivity", "material")), "reversibility", "reversible")));

    static D SignSchema(D unsigned, string kid, string key)
    {
        var s = Copy(unsigned);
        s["sig"] = M("alg", "ed25519", "kid", kid, "value", Sign(key, IntentJs.Message(ActionSchema.ActionSchemaDomain, unsigned)));
        return s;
    }
    static readonly D SCHEMA = SignSchema(UnsignedSchema(), "skyair-2026", SITE);
    static readonly L KEYS = Li(M("kid", "skyair-2026", "alg", "ed25519", "pk", Pub(SITE)));
    static readonly string SD = ActionSchema.Digest(SCHEMA);

    static D Trip() => M("id", "trip_spend", "agg", "sum", "unit", "usd_cents", "sel", M("accumulates_into", "spend.usd_cents"), "win", M("kind", "task"), "key", null,
        "domain_max", 500_000L, "holder", M("kind", "site_local"));
    static D Questions() => M("id", "questions", "agg", "count", "sel", M("event", "intent_required"), "win", M("kind", "task"), "key", null, "cap", 6L, "holder", M("kind", "wallet"));
    static D RootBody() => M("v", 1L, "kind", "pca-intent-session", "session", SESSION, "principals", Li(M("key", Pub(PRINCIPAL))), "intent_ref", REF,
        "schema", M("aud", AUD, "digest", SD), "layers", M("task", M("map_digest", MAP0)), "accumulators", Li(Trip(), Questions()), "monitors", Li(),
        "question_uri", "https://atlas.example/q", "expires_at", NOW + 86_400_000L);
    static D SignRoot(D body, string key)
    {
        var s = Copy(body);
        s["signer"] = Pub(key);
        s["sig"] = Sign(key, IntentJs.Message(IntentSession.IntentSessionSigDomain, s));
        return s;
    }
    static readonly D S = SignRoot(RootBody(), PRINCIPAL);
    static readonly string R = IntentSession.RootDigest(S);

    static D Mint(long seq, string? prev, string map, string salt, string signer, string root)
    {
        var env = M("type", "envelope", "goal_commit", Pca.IntentGoalCommitV2(SESSION, map, salt), "predicates", Li(M("verb", "air.book")), "caveats", Li(), "agent_binding", M());
        var sc = M("type", "intent_session", "session", SESSION, "seq", seq, "root", root);
        if (prev != null) sc["prev"] = prev;
        var body = M("issuer", Pub(signer), "holder", Pub(AGENT), "caveats", Li(env, sc), "parent", null);
        var digest = Pca.HashCanonical(body);
        var msg = Pca.Concat(Encoding.UTF8.GetBytes("atlas-pca/cap/v1\0"), Pca.B64uDecode(digest, 32)!);
        return M("id", digest, "issuer", Pub(signer), "holder", Pub(AGENT), "caveats", body["caveats"], "body_digest", digest, "sig", Sign(signer, msg));
    }
    static readonly D G0 = Mint(0, null, MAP0, "salt0", PRINCIPAL, R);
    static readonly D D1 = Mint(1, (string)G0["id"]!, MAP1, "salt1", PRINCIPAL, R);

    static D Params() => M("offer_id", "OF-1", "total", 38_900L, "add_ons", Li("none"), "refundable", false);

    static D Build(D grant, string salt, string map, D? isw, D prms, string reference)
    {
        var action = M("verb", "air.book", "resource", "skyair.example/bookings", "params_digest", Pca.ParamsDigest(prms), "reversibility_class", "irreversible");
        var leaf = Pca.PlanLeafOf("book", action, Pca.ConditionsDigestOf(null, null))!;
        var p = M("ver", 2L, "action", action, "grant_ref", grant["id"], "cap_chain", Li(grant),
            "plan", M("root", Pca.MerkleRoot(Li(leaf)), "inclusion_proof", M("index", 0L, "size", 1L, "path", Li()), "node_id", "book"),
            "attestation", M("quote_digest", "", "epoch", 0L, "model_id", "unattested", "measurement", "", "operator", "unattested"),
            "provenance", M("causal_hash", "", "taint_level", 0L, "trusted_refs", Li()),
            "freshness", M("beacon_ref", "", "epoch", 0L, "accumulator_witness", ""), "counter", 1L, "risk_claim", M("r", 0L, "inputs", M()),
            "aud", AUD, "iat", NOW, "exp", NOW + 600_000L,
            "intent", M("ref", reference, "map_digest", map, "goal_salt", salt, "fidelity_ppm", 1_000_000L, "residual_risk_ppm", 0L));
        if (isw != null) p["intent_session"] = isw;
        // the core verifier reads the wire form (numbers as parsed lexemes): round-trip through the strict parser
        return Resign((D)Pca.ParseStrict(Pca.Canonicalize(p))!);
    }
    static D Resign(D p) { p.Remove("sig"); p["sig"] = Sign(AGENT, Pca.ThresholdMessage(p)); return p; }
    static D Is0(params object?[] over) { var d = M("session", SESSION, "root", R, "seq", 0L, "schema", SD, "acc", Li(M("id", "trip_spend", "post", 38_900L))); var o = M(over); foreach (var (k, v) in o) d[k] = v; return d; }
    static D Ctx(params object?[] over)
    {
        var c = M("params", Params(), "schema", M("docs", Li(SCHEMA), "keys", KEYS), "session", M("root", S, "grants", Li()), "acc", M("state", M("trip_spend", M("sum", 0L)), "monitors", M()));
        foreach (var (k, v) in M(over)) c[k] = v;
        return c;
    }
    static Verdict Verify(D grant, D p, object? ctx) => Pca.VerifyPcactnCore(p, grant, NOW, AUD, null, null, IntentV2Context.FromJson(ctx));
    static readonly string[] CORE = { "wire", "version", "audience", "validity", "chain", "grant_ref_bound", "plan_inclusion", "leaf_signature", "counter", "intent" };
    static List<string> Keys(params string[] extra) => CORE.Concat(extra).ToList();
    static List<string> Failed(Verdict v) => v.Checks.Where(e => !e.Value).Select(e => e.Key).ToList();

    /// <summary>G_0 accepted end to end (the <c>session-g0</c> vector).</summary>
    public static Verdict G0Verdict() => Verify(G0, Build(G0, "salt0", MAP0, Is0(), Params(), REF), Ctx());

    [Fact]
    public void AcceptsG0AndD1()
    {
        var v = G0Verdict();
        Assert.True(v.Allow, v.Reason);
        Assert.Equal(Keys("schema", "intent_session", "accumulators"), v.Checks.Keys.ToList());
        var p1 = Build(D1, "salt1", MAP1, Is0("seq", 1L, "acc", Li(M("id", "trip_spend", "post", 77_800L))), Params(), REF);
        Assert.True(Verify(D1, p1, Ctx("session", M("root", S, "grants", Li(G0)), "acc", M("state", M("trip_spend", M("sum", 38_900L)), "monitors", M()))).Allow);
        Assert.Equal(new[] { "intent_session" }, Failed(Verify(D1, p1, Ctx("acc", M("state", M("trip_spend", M("sum", 38_900L)), "monitors", M())))));
    }

    [Fact]
    public void BackCompatPoliciesAndMalformedContext()
    {
        var plain = Build(G0, "salt0", MAP0, null, Params(), REF);
        var v = Verify(G0, plain, Ctx());
        Assert.Equal(CORE, v.Checks.Keys);
        Assert.Equal(new[] { "intent" }, Failed(v));
        Assert.Equal(CORE, Pca.VerifyPcactnCore(plain, G0, NOW, AUD, null, null, null).Checks.Keys);
        var req = Verify(G0, plain, Ctx("policy", M("session", M("require", true))));
        Assert.Equal(Keys("intent_session"), req.Checks.Keys.ToList());
        Assert.Equal(CORE, Verify(G0, plain, Ctx("policy", M("session", M("require", false)))).Checks.Keys);
        foreach (var notBool in new object?[] { "true", 1L, null })
            Assert.Equal(new[] { "intent", "schema", "intent_session" }, Failed(Verify(G0, plain, Ctx("policy", M("session", M("require", notBool))))));
        Assert.Equal(new[] { "intent", "schema", "intent_session" }, Failed(Verify(G0, plain, Ctx("policy", M("extra", true)))));
        Assert.Equal(new[] { "intent", "schema", "intent_session" }, Failed(Verify(G0, plain, Ctx("policy", M("schema", M("closed_world", "true"))))));
        Assert.Equal(new[] { "schema", "intent_session", "accumulators" }, Failed(Verify(G0, Build(G0, "salt0", MAP0, Is0(), Params(), REF), Ctx("params", null))));
        Assert.Equal(new[] { "intent", "schema", "intent_session" }, Failed(Verify(G0, plain, null))); // a present null context
        var cw = Verify(G0, plain, Ctx("policy", M("schema", M("closed_world", true))));
        Assert.Equal(Keys("schema"), cw.Checks.Keys.ToList());
        Assert.Equal(new[] { "intent" }, Failed(cw));
        // the clock must be a safe integer
        var p = Build(G0, "salt0", MAP0, Is0(), Params(), REF);
        var late = IntentV2.Decide(p, G0, IntentV2Context.FromJson(Ctx()), 9007199254740992L);
        Assert.All(late.Checks, c => { Assert.False(c.Ok); Assert.Contains("clock", c.Reason); });
        Assert.All(IntentV2.Decide(p, G0, IntentV2Context.FromJson(Ctx()), 9007199254740991L).Checks, c => Assert.DoesNotContain("clock", c.Reason ?? ""));
    }

    [Fact]
    public void Rule12V2GoalAndIndependence()
    {
        Assert.True(G0Verdict().Checks["intent"]);
        Assert.False(Verify(G0, Build(G0, "salt0", MAP0, Is0("session", B64Seed("v2/other-session")), Params(), REF), Ctx()).Checks["intent"]);
        Assert.NotEqual(Pca.IntentGoalCommitV2(SESSION, MAP0, "s"), Pca.IntentGoalCommit(SESSION, MAP0, "s"));
        Assert.Equal(new[] { "intent_session", "accumulators" }, Failed(Verify(G0, Build(G0, "salt0", MAP0, Is0(), Params(), REF), Ctx("session", M("grants", Li())))));
        var bad = Params(); bad["total"] = 1L;
        Assert.Equal(new[] { "schema", "accumulators" }, Failed(Verify(G0, Build(G0, "salt0", MAP0, Is0(), Params(), REF), Ctx("params", bad))));
        var t = Build(G0, "salt0", MAP0, Is0(), Params(), REF);
        t["intent_session"] = Is0("acc", Li(M("id", "trip_spend", "post", 1L)));
        Assert.Equal(new[] { "leaf_signature", "accumulators" }, Failed(Verify(G0, t, Ctx())));
    }

    [Fact]
    public void Rule13Failures()
    {
        var d1ctx = Ctx("session", M("root", S, "grants", Li(G0)), "acc", M("state", M("trip_spend", M("sum", 38_900L)), "monitors", M()));
        var is1 = Is0("seq", 1L, "acc", Li(M("id", "trip_spend", "post", 77_800L)));
        var forged = Mint(1, (string)G0["id"]!, MAP1, "salt1", AGENT, R);
        Assert.Equal(new[] { "intent_session" }, Failed(Verify(forged, Build(forged, "salt1", MAP1, is1, Params(), REF), d1ctx)));
        var loose = Mint(1, B64Seed("v2/nope"), MAP1, "salt1", PRINCIPAL, R);
        Assert.Equal(new[] { "intent_session" }, Failed(Verify(loose, Build(loose, "salt1", MAP1, is1, Params(), REF), d1ctx)));
        Assert.Equal(new[] { "intent_session" }, Failed(Verify(G0, Build(G0, "salt0", MAP0, Is0("seq", 1L), Params(), REF), Ctx("session", M("root", S, "grants", Li(G0))))));
        Assert.Equal(new[] { "intent_session" }, Failed(Verify(G0, Build(G0, "salt0", MAP0, Is0(), Params(), B64Seed("v2/x")), Ctx())));
        // held grants must be capabilities with string id / issuer and an implemented suite
        Assert.Equal(new[] { "intent_session" }, Failed(Verify(D1, Build(D1, "salt1", MAP1, is1, Params(), REF), Ctx("session", M("root", S, "grants", Li(M("id", 1L))), "acc", M("state", M("trip_spend", M("sum", 38_900L)), "monitors", M())))));
        var g0alg = Copy(G0); g0alg["alg"] = "no-such-suite";
        var held = Verify(D1, Build(D1, "salt1", MAP1, is1, Params(), REF), Ctx("session", M("root", S, "grants", Li(g0alg)), "acc", M("state", M("trip_spend", M("sum", 38_900L)), "monitors", M())));
        Assert.Contains("unsupported_suite", held.Reason);
        var eb = RootBody(); eb["expires_at"] = NOW;
        var eS = SignRoot(eb, PRINCIPAL); var eR = IntentSession.RootDigest(eS);
        var ge = Mint(0, null, MAP0, "salt0", PRINCIPAL, eR);
        Assert.Equal(new[] { "intent_session", "accumulators" }, Failed(Verify(ge, Build(ge, "salt0", MAP0, Is0("root", eR), Params(), REF), Ctx("session", M("root", eS, "grants", Li())))));
        var lb = RootBody(); lb["expires_at"] = NOW + 1;
        var lS = SignRoot(lb, PRINCIPAL); var lR = IntentSession.RootDigest(lS);
        var gl = Mint(0, null, MAP0, "salt0", PRINCIPAL, lR);
        Assert.True(Verify(gl, Build(gl, "salt0", MAP0, Is0("root", lR), Params(), REF), Ctx("session", M("root", lS, "grants", Li()))).Allow);
        // S.layers.org / std null is malformed; a root suite this SDK lacks is unsupported_suite
        var nb = RootBody(); ((D)nb["layers"]!)["org"] = null;
        Assert.NotNull(IntentSession.RootShapeError(SignRoot(nb, PRINCIPAL)));
        var ab = SignRoot(RootBody(), PRINCIPAL); ab["alg"] = "no-such-suite";
        Assert.Contains("unsupported_suite", IntentSession.VerifyRoot(ab));
    }

    [Fact]
    public void SessionWireBoundaries()
    {
        Assert.Null(IntentSession.ValidateWire(Is0()));
        Assert.Null(IntentSession.ValidateWire(Is0("seq", 2_147_483_647L)));
        Assert.NotNull(IntentSession.ValidateWire(Is0("seq", 2_147_483_648L)));
        Assert.NotNull(IntentSession.ValidateWire(Is0("seq", -1L)));
        Assert.NotNull(IntentSession.ValidateWire(Is0("seq", new Num("1.5"))));
        Assert.Equal("unknown field 'intent_session.note'", IntentSession.ValidateWire(Is0("note", "x")));
        var both = Is0("zz", 1L); both.Remove("root");
        Assert.Equal("unknown field 'intent_session.zz'", IntentSession.ValidateWire(both));
        var sixteen = new L(); var seventeen = new L();
        for (int i = 0; i < 17; i++) { if (i < 16) sixteen.Add(M("id", "a" + i, "post", 0L)); seventeen.Add(M("id", "a" + i, "post", 0L)); }
        Assert.Null(IntentSession.ValidateWire(Is0("acc", sixteen)));
        Assert.NotNull(IntentSession.ValidateWire(Is0("acc", seventeen)));
        Assert.NotNull(IntentSession.ValidateWire(Is0("acc", Li(M("id", "a", "post", 1L), M("id", "a", "post", 2L)))));
        Assert.Null(IntentSession.ValidateWire(Is0("acc", Li(M("id", new string('a', 64), "post", 1L)))));
        Assert.NotNull(IntentSession.ValidateWire(Is0("acc", Li(M("id", new string('a', 65), "post", 1L)))));
        foreach (var (name, max) in new[] { ("facts", 16), ("classes", 8), ("labels", 16) })
        {
            var ok = new L(); var over = new L();
            for (int i = 0; i <= max; i++) { var d = B64Seed("v2/d" + i); if (i < max) ok.Add(d); over.Add(d); }
            Assert.Null(IntentSession.ValidateWire(Is0(name, ok)));
            Assert.NotNull(IntentSession.ValidateWire(Is0(name, over)));
            Assert.NotNull(IntentSession.ValidateWire(Is0(name, Li(REF, REF))));
        }
        Assert.Null(IntentSession.ValidateWire(Is0("prov", M("action.params.total", Li(new string('r', 256))))));
        Assert.NotNull(IntentSession.ValidateWire(Is0("prov", M("action.params.total", Li(new string('r', 257))))));
        Assert.NotNull(IntentSession.ValidateWire(Is0("prov", M("env.x", Li("r")))));
        Assert.Equal(new[] { "wire" }, Verify(G0, Build(G0, "salt0", MAP0, Is0("seq", -1L), Params(), REF), Ctx()).Checks.Keys);
        // session caveat and rule 10
        var c = M("type", "intent_session", "session", SESSION, "seq", 0L, "root", R);
        Assert.Null(IntentSession.CaveatError(c));
        c["prev"] = REF;
        Assert.NotNull(IntentSession.CaveatError(c));
        Assert.True(Caveats.Satisfied(M("type", "intent_session", "session", SESSION, "seq", 0L, "root", R), M("now", NOW)));
        Assert.False(Caveats.Satisfied(M("type", "intent_session", "session", SESSION, "seq", 1L, "root", R), M("now", NOW)));
    }

    // ---- revocation ----
    const string REV = "v2/revocation-authority";
    static readonly string ID_SESSION = IntentRevocation.SessionRevocationId(SESSION);
    static List<string> Sorted(List<string> xs) { var s = new List<string>(xs); s.Sort(IntentJs.CompareUtf8); return s; }
    static D Epoch(List<string> revoked, long issued, string signer, string scope)
    {
        var sorted = Sorted(revoked);
        var body = M("instance_id", "ana", "grant_ref", scope, "epoch", (long)sorted.Count, "set_size", (long)sorted.Count, "root", IntentRevocation.RevsetRoot(sorted),
            "issued_at", issued, "not_after", issued + 300_000L);
        var ep = Copy(body);
        ep["guardian"] = Pub(signer);
        ep["sig"] = Sign(signer, Pca.Concat(Encoding.UTF8.GetBytes(IntentRevocation.RevepochDomain), IntentJs.CanonBytes(body)));
        return ep;
    }
    static D Evidence(List<string> revoked, long issued, string signer) =>
        M("epoch", Epoch(revoked, issued, signer, IntentRevocation.SessionRevocationScope(SESSION)), "revoked", Sorted(revoked).Cast<object?>().ToList());
    static string? Rev(D? ev, List<string> ids, double maxAge, D? last = null) =>
        IntentRevocation.CheckSessionRevocation(IntentJs.Normalize(ev), SESSION, Pub(REV), ids.Cast<object?>().ToList(), NOW, maxAge, null, null,
            last != null, last == null ? null : IntentJs.Normalize(last));

    [Fact]
    public void RevocationStepOrder()
    {
        var ids = new List<string> { ID_SESSION };
        var high = new List<string> { "pca-intent:zzz" };
        Assert.Null(Rev(Evidence(high, NOW - 10_000, REV), ids, 60_000));
        Assert.Null(Rev(Evidence(new(), NOW - 10_000, REV), ids, 60_000));
        Assert.Null(Rev(Evidence(high, NOW - 60_000, REV), ids, 60_000));
        Assert.NotNull(Rev(Evidence(high, NOW - 60_001, REV), ids, 60_000));
        Assert.Null(Rev(Evidence(high, NOW + 60_000, REV), ids, 60_000));
        Assert.Equal("revocation epoch issued in the future", Rev(Evidence(high, NOW + 60_001, REV), ids, 60_000));
        Assert.Equal($"'{ID_SESSION}' is revoked", Rev(Evidence(new() { ID_SESSION }, NOW - 1_000, REV), ids, 60_000));
        var shortList = Evidence(new() { "a", "b" }, NOW - 1_000, REV); shortList["revoked"] = Li("a");
        Assert.Equal("the epoch must be numbered by its set size and list exactly set_size ids", Rev(shortList, ids, 60_000));
        var swapped = Evidence(new() { "a", "b" }, NOW - 1_000, REV); swapped["revoked"] = Li("a", "c");
        Assert.Equal("the revoked list is not the signed set (root mismatch)", Rev(swapped, ids, 60_000));
        var unsorted = Evidence(new() { "a", "b" }, NOW - 1_000, REV); unsorted["revoked"] = Li("b", "a");
        Assert.Equal("revoked must be sorted by UTF-8 bytes and distinct", Rev(unsorted, ids, 60_000));
        var notList = Evidence(new() { "a" }, NOW - 1_000, REV); notList["revoked"] = M("0", "a");
        Assert.Equal("revoked must be an array of ids", Rev(notList, ids, 60_000));
        Assert.Equal("the revocation epoch is not signed by the session revocation authority", Rev(Evidence(high, NOW - 1_000, PRINCIPAL), ids, 60_000));
        Assert.Equal("revocation max age misconfigured (fail closed)", Rev(null, ids, -1));
        Assert.Equal("revocation max age misconfigured (fail closed)", Rev(null, ids, 0.5));
        Assert.Equal("no session revocation epoch supplied", Rev(null, ids, 0));
        var extra = Evidence(high, NOW - 1_000, REV); extra["proofs"] = M();
        Assert.Equal("the revocation evidence has the unknown member 'proofs' (it is exactly {epoch, revoked})", Rev(extra, ids, 60_000));
        var tampered = Evidence(high, NOW - 1_000, REV); ((D)tampered["epoch"]!)["instance_id"] = "bob";
        Assert.Equal("revocation epoch signature invalid", Rev(tampered, ids, 60_000));
        // strict typing: a numeric string, null, a fraction; an epoch suite this SDK lacks
        foreach (var bad in new object?[] { "1800000000000", null, new Num("1.5") })
        {
            var e = Evidence(high, NOW - 1_000, REV); ((D)e["epoch"]!)["issued_at"] = bad;
            Assert.NotNull(Rev(e, ids, 60_000));
        }
        var alg = Evidence(high, NOW - 1_000, REV); ((D)alg["epoch"]!)["alg"] = "no-such-suite";
        Assert.Contains("unsupported_suite", Rev(alg, ids, 60_000));
        // append-only against the tracked last epoch
        var last = Evidence(new() { "a" }, NOW - 30_000, REV);
        Assert.Null(Rev(Evidence(new() { "a", "b" }, NOW - 1_000, REV), ids, 60_000, last));
        Assert.Null(Rev(Evidence(new() { "a" }, NOW - 1_000, REV), ids, 60_000, last));
        Assert.Equal("revocation epoch rollback (older than the last accepted)", Rev(Evidence(new(), NOW - 1_000, REV), ids, 60_000, last));
        Assert.Equal("the epoch drops 'a', revoked in the last accepted epoch (not append-only)", Rev(Evidence(new() { "b" }, NOW - 1_000, REV), ids, 60_000, last));
        var badLast = Evidence(new() { "a" }, NOW - 30_000, REV); badLast["revoked"] = Li();
        Assert.Equal("the tracked last epoch is malformed (fail closed)", Rev(Evidence(new() { "a" }, NOW - 1_000, REV), ids, 60_000, badLast));
        Assert.NotEqual(IntentRevocation.RevsetRoot(new List<string> { "a", "b" }), IntentRevocation.RevsetRoot(new List<string> { "a", "c" }));
    }

    [Fact]
    public void RevocationThroughTheSession()
    {
        var body = RootBody(); body["revocation"] = M("epoch_uri", "https://atlas.example/rev", "max_age_s", 60L, "key", Pub(REV));
        var s4 = SignRoot(body, PRINCIPAL); var r4 = IntentSession.RootDigest(s4);
        var g = Mint(0, null, MAP0, "salt0", PRINCIPAL, r4);
        var p = Build(g, "salt0", MAP0, Is0("root", r4), Params(), REF);
        var ids = new List<string> { ID_SESSION, IntentRevocation.MapRevocationId(MAP0), IntentRevocation.DeltaRevocationId((string)g["id"]!) };
        var high = new List<string> { "pca-intent:zzz" };
        Verdict Run(D? ev, D? policy, D? last = null)
        {
            var sess = M("root", s4, "grants", Li());
            if (ev != null) sess["revocation"] = ev;
            if (last != null) sess["revocation_last"] = last;
            var c = Ctx("session", sess);
            if (policy != null) c["policy"] = policy;
            return Verify(g, p, c);
        }
        Assert.True(Run(Evidence(high, NOW - 30_000, REV), null).Allow);
        Assert.Equal(new[] { "intent_session" }, Failed(Run(null, null)));
        Assert.Equal(new[] { "intent_session" }, Failed(Run(Evidence(high, NOW - 61_000, REV), null)));
        foreach (var revoked in ids) Assert.Equal(new[] { "intent_session" }, Failed(Run(Evidence(new() { revoked }, NOW - 1_000, REV), null)));
        Assert.Equal(new[] { "intent_session" }, Failed(Run(Evidence(high, NOW - 1_000, PRINCIPAL), null)));
        Assert.Equal(new[] { "intent_session" }, Failed(Run(Evidence(high, NOW - 20_000, REV), M("session", M("max_revocation_age_s", 10L)))));
        Assert.True(Run(Evidence(high, NOW - 10_000, REV), M("session", M("max_revocation_age_s", 10L))).Allow);
        Assert.Equal(new[] { "schema", "intent_session", "accumulators" }, Failed(Run(Evidence(high, NOW - 1_000, REV), M("session", M("max_revocation_age_s", -1L)))));
        Assert.Equal(new[] { "intent_session" }, Failed(Run(Evidence(high, NOW - 1_000, REV), null, Evidence(new() { "pca-intent:yyy" }, NOW - 20_000, REV))));
        Assert.Equal(new[] { "intent_session" }, Failed(Verify(G0, Build(G0, "salt0", MAP0, Is0(), Params(), REF), Ctx("policy", M("session", M("max_revocation_age_s", 60L))))));
        var keyless = RootBody(); keyless["revocation"] = M("epoch_uri", "https://atlas.example/rev", "max_age_s", 60L);
        Assert.NotNull(IntentSession.RootShapeError(SignRoot(keyless, PRINCIPAL)));
        var principalKeyed = RootBody(); principalKeyed["revocation"] = M("epoch_uri", "https://atlas.example/rev", "max_age_s", 60L, "key", Pub(PRINCIPAL));
        Assert.Equal("revocation.key must not be a session principal (a dedicated revocation authority)", IntentSession.RootShapeError(SignRoot(principalKeyed, PRINCIPAL)));
    }

    // ---- rule 14 ----
    static ActionSchema.Conform Conform(string verb, object? prms) => ActionSchema.ConformAction(IntentJs.Normalize(SCHEMA), verb, IntentJs.Normalize(prms));
    static void Code(string code, string? path, ActionSchema.Conform c) { Assert.False(c.Ok); Assert.Equal(code, c.Code); Assert.Equal(path, c.Path); }

    [Fact]
    public void ConformanceOrderAndDomains()
    {
        Assert.True(Conform("air.book", Params()).Ok);
        Code("unknown_verb", null, Conform("air.cancel", Params()));
        Code("params_not_object", null, Conform("air.cancel", Li()));
        var two = Params(); two["zz"] = 1L; two["aa"] = 1L;
        Code("undeclared_param", "action.params.aa", Conform("air.book", two));
        Code("missing_param", "action.params.add_ons", Conform("air.book", M()));
        foreach (var (raw, want) in new[] { ("1.5", "bad_type"), ("-0", "bad_type"), ("-1", "out_of_domain"), ("5000001", "out_of_domain") })
        {
            var p = Params(); p["total"] = new Num(raw);
            Code(want, "action.params.total", Conform("air.book", p));
        }
        foreach (var raw in new[] { "0", "5000000" }) { var p = Params(); p["total"] = new Num(raw); Assert.True(Conform("air.book", p).Ok); }
        var dup = Params(); dup["add_ons"] = Li("none", "none");
        Code("out_of_domain", "action.params.add_ons", Conform("air.book", dup));
        var nine = new L(); var ten = new L();
        for (int i = 0; i < 10; i++) { if (i < 9) nine.Add("p" + i); ten.Add("p" + i); }
        var a9 = Params(); a9["passengers"] = nine; Assert.True(Conform("air.book", a9).Ok);
        var a10 = Params(); a10["passengers"] = ten; Code("out_of_domain", "action.params.passengers", Conform("air.book", a10));
        foreach (var (date, ok) in new[] { ("2028-02-29", true), ("2026-02-29", false), ("1900-02-29", false), ("2000-02-29", true), ("2026-1-05", false), ("0000-01-01", false), ("0001-01-01", true) })
        {
            var c = Conform("air.search", M("from", "SFO", "date", date, "pax", 2L));
            if (ok) Assert.True(c.Ok, date); else Code("out_of_domain", "action.params.date", c);
        }
        Assert.True(Verify(G0, Build(G0, "salt0", MAP0, Is0(), Params(), REF), Ctx()).Allow);
        var at16 = Params(); at16["note"] = new string('é', 8);
        Assert.True(Verify(G0, Build(G0, "salt0", MAP0, Is0(), at16, REF), Ctx("params", at16)).Allow);
        var at17 = Params(); at17["note"] = new string('é', 8) + "a";
        Assert.Equal(new[] { "schema" }, Failed(Verify(G0, Build(G0, "salt0", MAP0, Is0(), at17, REF), Ctx("params", at17))));
        // the schema context must be {docs: [...], keys: [...]}
        Assert.Equal(new[] { "schema", "accumulators" }, Failed(Verify(G0, Build(G0, "salt0", MAP0, Is0(), Params(), REF), Ctx("schema", M("docs", Li(SCHEMA))))));
    }

    [Fact]
    public void SchemaSignatureShapeAndCanon()
    {
        var n = (D)IntentJs.Normalize(SCHEMA)!;
        Assert.Null(ActionSchema.Verify(n, IntentJs.Normalize(KEYS)));
        Assert.Equal("sig.alg does not match the pinned key suite", ActionSchema.Verify(n, Li(M("kid", "skyair-2026", "alg", "ml-dsa-65", "pk", Pub(SITE)))));
        var tampered = Copy(n); tampered["version"] = "x";
        Assert.Equal("schema signature invalid", ActionSchema.Verify(tampered, KEYS));
        Assert.Equal("the schema keys must be an array", ActionSchema.Verify(n, M()));
        Assert.Contains("unsupported_suite", ActionSchema.Verify(n, Li(M("kid", "skyair-2026", "alg", "no-such-suite", "pk", Pub(SITE)))));
        var reserved = UnsignedSchema(); ((D)((D)((L)reserved["verbs"]!)[0]!)["params"]!)["action.params.constructor"] = M("type", "boolean", "semantic", "flag", "sensitivity", "free");
        Assert.Contains("reserved", ActionSchema.ShapeError(SignSchema(reserved, "skyair-2026", SITE)));
        var nullDefault = UnsignedSchema(); ((D)((D)((D)((L)nullDefault["verbs"]!)[0]!)["params"]!)["action.params.refundable"]!)["default"] = null;
        Assert.Contains("default", ActionSchema.ShapeError(SignSchema(nullDefault, "skyair-2026", SITE)));
        var p = Params(); p["add_ons"] = Li("tripshield", "none"); p["passengers"] = Li("b", "a");
        var canon = ActionSchema.CanonProjection(n, "air.book", (D)IntentJs.Normalize(p)!);
        Assert.Equal("[\"none\",\"tripshield\"]", canon["add_ons"]);
        Assert.Equal("[\"b\",\"a\"]", canon["passengers"]);
        Assert.Equal("false", canon["refundable"]);
        Assert.False(canon.ContainsKey("total"));
    }

    // ---- rule 15 ----
    static D RootWith(string k, object? v) { var b = RootBody(); b[k] = v; return SignRoot(b, PRINCIPAL); }

    [Fact]
    public void Rule15SiteLocalMonitorsAggregates()
    {
        List<string> Run(D isw, D c) => Failed(Verify(G0, Build(G0, "salt0", MAP0, isw, Params(), REF), c));
        Assert.Equal(new[] { "accumulators" }, Run(Is0("acc", Li(M("id", "trip_spend", "post", 38_899L))), Ctx()));
        Assert.Equal(new[] { "accumulators" }, Run(Is0("acc", Li()), Ctx()));
        Assert.Equal(new[] { "accumulators" }, Run(Is0("acc", Li(M("id", "trip_spend", "post", 38_900L), M("id", "questions", "post", 1L))), Ctx()));
        Assert.Equal(new[] { "accumulators" }, Run(Is0(), Ctx("acc", M("state", M(), "monitors", M()))));
        Assert.Equal(new[] { "accumulators" }, Run(Is0(), Ctx("acc", M("state", M("trip_spend", M("count", 0L)), "monitors", M()))));
        Assert.Equal(new[] { "accumulators" }, Run(Is0("acc", Li(M("id", "trip_spend", "post", 500_100L))), Ctx("acc", M("state", M("trip_spend", M("sum", 461_200L)), "monitors", M()))));
        Assert.Empty(Run(Is0("acc", Li(M("id", "trip_spend", "post", 500_000L))), Ctx("acc", M("state", M("trip_spend", M("sum", 461_100L)), "monitors", M()))));
        // the acc context is typed: a non-object state, a non-integer last_seq
        Assert.Equal(new[] { "accumulators" }, Run(Is0(), Ctx("acc", M("state", Li(), "monitors", M()))));
        Assert.Equal(new[] { "accumulators" }, Run(Is0(), Ctx("acc", M("state", M("trip_spend", M("sum", 0L)), "monitors", M(), "last_seq", M("x", "1")))));
        var mon = M("id", "hotel_after_flight", "kind", "requires_prior", "p", M("verb", "air.book"), "q", M("verb", "hotel.book"), "status", "committed");
        var rm = RootWith("monitors", Li(mon)); var rmR = IntentSession.RootDigest(rm);
        var gm = Mint(0, null, MAP0, "salt0", PRINCIPAL, rmR);
        var pm = Build(gm, "salt0", MAP0, Is0("root", rmR), Params(), REF);
        Verdict Cm(D mons) => Verify(gm, pm, Ctx("session", M("root", rm, "grants", Li()), "acc", M("state", M("trip_spend", M("sum", 0L)), "monitors", mons)));
        Assert.True(Cm(M("hotel_after_flight", "unmet")).Allow);
        Assert.Equal(new[] { "accumulators" }, Failed(Cm(M())));
        Assert.Equal(new[] { "accumulators" }, Failed(Cm(M("hotel_after_flight", "maybe"))));
        Assert.Equal(new List<string> { "idle", "pending:1", "pending:2", "missed" }, IntentAcc.MonitorStates(M("kind", "responds_within", "within", 2L)));
        // reserved ids
        var reservedAcc = Trip(); reservedAcc["id"] = "constructor";
        Assert.NotNull(IntentAcc.AccumulatorDeclError(reservedAcc));
        Assert.NotNull(IntentAcc.MonitorDeclError(M("id", "__proto__", "kind", "never", "p", M("verb", "a"))));
        // arithmetic seams
        Assert.Equal(9007199254740991L, IntentAcc.CombineAcc("sum", M("sum", 9007199254740990L), new IntentAcc.AccValue(null, 1, null)));
        Assert.Null(IntentAcc.CombineAcc("sum", M("sum", 9007199254740991L), new IntentAcc.AccValue(null, 1, null)));
        Assert.Equal(2L, IntentAcc.CombineAcc("distinct", M("values", Li("\"a\"")), new IntentAcc.AccValue(null, 1, "\"b\"")));
        Assert.Equal(1L, IntentAcc.CombineAcc("distinct", M("values", Li("\"a\"")), new IntentAcc.AccValue(null, 1, "\"a\"")));
        Assert.True(IntentAcc.ReceiptArithmeticOk("max", M("pre", 10L, "delta", 5L, "post", 10L), 5));
        Assert.False(IntentAcc.ReceiptArithmeticOk("distinct", M("pre", 10L, "delta", 2L, "post", 12L), 1));
    }

    static D KeySet(L keys, string rootKey) => KeySet(keys, rootKey, 1L, NOW - 100_000L);
    static D KeySet(L keys, string rootKey, long version, long issued)
    {
        var body = M("v", 1L, "kind", "pca-sequencer-keys", "sequencer", Pub(rootKey), "version", version, "issued_at", issued, "keys", keys);
        var k = Copy(body);
        k["sig"] = Sign(rootKey, IntentJs.Message(IntentAcc.SequencerKeysDomain, body));
        return k;
    }
    static D Receipt(D draft, string signer, string kid, params object?[] over)
    {
        var r = M("v", 1L, "kind", "pca-acc-receipt", "session", SESSION, "acc", "trip_spend", "seq", 3L, "pre", 10_000L, "delta", 38_900L, "post", 48_900L,
            "pcactn_digest", IntentAcc.PcactnReservationDigest(draft), "aud", AUD, "issued_at", NOW - 1_000L, "expires_at", NOW + 60_000L, "kid", kid,
            "ledger", M("index", 7L, "head", B64Seed("v2/head")));
        foreach (var (k, v) in M(over)) r[k] = v;
        r["signer"] = Pub(signer);
        r["sig"] = Sign(signer, IntentJs.Message(IntentAcc.AccReceiptDomain, r));
        return r;
    }

    [Fact]
    public void Rule15Freshness()
    {
        var holder = (D)IntentJs.Normalize(M("kind", "sequenced", "uri", "https://atlas.example/seq", "root", Pub(SEQ_ROOT)))!;
        var draft = Build(G0, "salt0", MAP0, null, Params(), REF);
        var k1 = Li(M("kid", "k1", "pk", Pub(SEQ_KEY), "not_before", NOW - 10_000L));
        var ks = KeySet(k1, SEQ_ROOT);
        double R = IntentAcc.DefaultMaxReceiptAgeMs, K = IntentAcc.DefaultMaxKeySetAgeMs;
        bool Ok(D rc, L sets, double r, double k, object? t) =>
            IntentAcc.VerifyReceiptAgainstHolder((D)IntentJs.Normalize(rc)!, holder, IntentJs.Normalize(sets), NOW, r, k, IntentJs.Normalize(t));
        var rc = Receipt(draft, SEQ_KEY, "k1");
        Assert.True(Ok(rc, Li(ks), R, K, null));
        Assert.Null(IntentAcc.ReceiptShapeError(IntentJs.Normalize(Receipt(draft, SEQ_KEY, "k1", "expires_at", NOW - 1_000L + 900_000L))));
        Assert.NotNull(IntentAcc.ReceiptShapeError(IntentJs.Normalize(Receipt(draft, SEQ_KEY, "k1", "expires_at", NOW - 1_000L + 900_001L))));
        Assert.NotNull(IntentAcc.ReceiptShapeError(IntentJs.Normalize(Receipt(draft, SEQ_KEY, "k1", "expires_at", NOW - 1_001L))));
        Assert.True(Ok(rc, Li(ks), 1_000, K, null));
        Assert.False(Ok(rc, Li(ks), 999, K, null));
        Assert.True(Ok(rc, Li(ks), R, 100_000, null));
        Assert.False(Ok(rc, Li(ks), R, 99_999, null));
        Assert.True(Ok(rc, Li(KeySet(k1, SEQ_ROOT, 1L, NOW + 60_000L)), R, K, null));
        Assert.False(Ok(rc, Li(KeySet(k1, SEQ_ROOT, 1L, NOW + 60_001L)), R, K, null));
        var v3 = KeySet(k1, SEQ_ROOT, 3L, NOW - 100_000L);
        var t3 = M("version", 3L, "digest", IntentAcc.KeySetDigest(IntentJs.Normalize(v3)));
        Assert.True(Ok(rc, Li(v3), R, K, t3));
        Assert.True(Ok(rc, Li(KeySet(k1, SEQ_ROOT, 4L, NOW - 100_000L)), R, K, t3));
        Assert.False(Ok(rc, Li(KeySet(k1, SEQ_ROOT, 2L, NOW - 100_000L)), R, K, t3));
        Assert.False(Ok(rc, Li(KeySet(k1, SEQ_ROOT, 3L, NOW - 99_000L)), R, K, t3));
        foreach (var bad in new object?[] { 3L, M("version", 3L), M("version", 0L, "digest", t3["digest"]), M("version", 3L, "digest", t3["digest"], "x", 1L) })
            Assert.False(Ok(rc, Li(v3), R, K, bad));
        Assert.NotNull(IntentAcc.KeySetShapeError(IntentJs.Normalize(KeySet(k1, SEQ_ROOT, 0L, NOW))));
        var noVersion = KeySet(k1, SEQ_ROOT); noVersion.Remove("version");
        Assert.NotNull(IntentAcc.KeySetShapeError(IntentJs.Normalize(noVersion)));
        var old = Receipt(draft, SEQ_KEY, "k1", "issued_at", NOW - 70_000L, "expires_at", NOW + 1_000L);
        Assert.True(Ok(old, Li(KeySet(Li(M("kid", "k1", "pk", Pub(SEQ_KEY), "not_before", NOW - 80_000L, "not_after", NOW - 60_000L)), SEQ_ROOT)), R, K, null));
        Assert.False(Ok(old, Li(KeySet(Li(M("kid", "k1", "pk", Pub(SEQ_KEY), "not_before", NOW - 80_000L, "not_after", NOW - 60_001L)), SEQ_ROOT)), R, K, null));
        Assert.False(Ok(rc, Li(ks), -1, K, null));
        Assert.False(Ok(rc, Li(ks), R, 0.5, null));
        var p = Build(G0, "salt0", MAP0, Is0(), Params(), REF);
        Assert.True(Verify(G0, p, Ctx("policy", M("acc", M("max_receipt_age_s", 60L, "max_keyset_age_s", 60L)))).Allow);
        Assert.Equal(new[] { "schema", "intent_session", "accumulators" }, Failed(Verify(G0, p, Ctx("policy", M("acc", M("max_receipt_age_s", "60"))))));
        Assert.Equal(new[] { "schema", "intent_session", "accumulators" }, Failed(Verify(G0, p, Ctx("policy", M("acc", M("other", 1L))))));
        var badVersions = Ctx(); ((D)badVersions["acc"]!)["keyset_versions"] = M(Pub(SEQ_ROOT), 1L);
        Assert.Equal(new[] { "accumulators" }, Failed(Verify(G0, p, badVersions)));
    }

    [Fact]
    public void Rule15Sequenced()
    {
        var seqAcc = Trip(); seqAcc["holder"] = M("kind", "sequenced", "uri", "https://atlas.example/seq", "root", Pub(SEQ_ROOT));
        var rs = RootWith("accumulators", Li(seqAcc)); var rsR = IntentSession.RootDigest(rs);
        var gs = Mint(0, null, MAP0, "salt0", PRINCIPAL, rsR);
        var draft = Build(gs, "salt0", MAP0, null, Params(), REF);
        var ks = KeySet(Li(M("kid", "k1", "pk", Pub(SEQ_KEY), "not_before", NOW - 10_000L)), SEQ_ROOT);
        Verdict Go(D rc, long post, L receipts, L keySets, long? last)
        {
            var p = Build(gs, "salt0", MAP0, Is0("root", rsR, "acc", Li(M("id", "trip_spend", "post", post, "receipt", IntentAcc.ReceiptDigest(rc)))), Params(), REF);
            var acc = M("receipts", receipts, "monitors", M(), "sequencer_keys", keySets);
            if (last != null) acc["last_seq"] = M("trip_spend", last.Value);
            return Verify(gs, p, Ctx("session", M("root", rs, "grants", Li()), "acc", acc));
        }
        var rc = Receipt(draft, SEQ_KEY, "k1");
        var okv = Go(rc, 48_900L, Li(rc), Li(ks), null);
        Assert.True(okv.Allow, okv.Reason);
        Assert.Equal(new[] { "accumulators" }, Failed(Go(rc, 48_900L, Li(), Li(ks), null)));
        Assert.Equal(new[] { "accumulators" }, Failed(Go(rc, 48_900L, Li(rc), Li(), null)));
        Assert.Equal(new[] { "accumulators" }, Failed(Go(rc, 48_900L, Li(rc), Li(ks), 3L)));
        Assert.True(Go(rc, 48_900L, Li(rc), Li(ks), 2L).Allow);
        var foreignSet = KeySet(Li(M("kid", "k1", "pk", Pub(SEQ_KEY), "not_before", NOW - 10_000L)), STRANGER);
        Assert.Equal(new[] { "accumulators" }, Failed(Go(rc, 48_900L, Li(rc), Li(foreignSet), null)));
        Assert.True(Go(rc, 48_900L, Li(rc), Li(foreignSet, ks), null).Allow);
        var bent = Receipt(draft, SEQ_KEY, "k1", "post", 48_901L);
        Assert.Equal(new[] { "accumulators" }, Failed(Go(bent, 48_901L, Li(bent), Li(ks), null)));
        var edge = Receipt(draft, SEQ_KEY, "k1", "expires_at", NOW);
        Assert.True(Go(edge, 48_900L, Li(edge), Li(ks), null).Allow);
        var late = Receipt(draft, SEQ_KEY, "k1", "expires_at", NOW - 1L);
        Assert.Equal(new[] { "accumulators" }, Failed(Go(late, 48_900L, Li(late), Li(ks), null)));
        var windowed = KeySet(Li(M("kid", "k1", "pk", Pub(SEQ_KEY), "not_before", NOW - 1_000L, "not_after", NOW - 1_000L)), SEQ_ROOT);
        Assert.True(Go(rc, 48_900L, Li(rc), Li(windowed), null).Allow);
        var retired = KeySet(Li(M("kid", "k1", "pk", Pub(SEQ_KEY), "not_before", NOW - 10_000L, "not_after", NOW - 1_001L)), SEQ_ROOT);
        Assert.Equal(new[] { "accumulators" }, Failed(Go(rc, 48_900L, Li(rc), Li(retired), null)));
        var wide = KeySet(Li(M("kid", "k1", "pk", Pub(SEQ_KEY), "not_before", 0L)), SEQ_ROOT);
        var future = Receipt(draft, SEQ_KEY, "k1", "issued_at", NOW + 60_001L);
        Assert.Equal(new[] { "accumulators" }, Failed(Go(future, 48_900L, Li(future), Li(wide), null)));
        var near = Receipt(draft, SEQ_KEY, "k1", "issued_at", NOW + 60_000L);
        Assert.True(Go(near, 48_900L, Li(near), Li(wide), null).Allow);
        var unsupported = Receipt(draft, SEQ_KEY, "k1", "alg", "no-such-suite");
        Assert.Contains("unsupported_suite", Go(unsupported, 48_900L, Li(unsupported), Li(ks), null).Reason);
    }

    [Fact]
    public void LayersAndWbThroughThePipeline()
    {
        var p = Build(G0, "salt0", MAP0, Is0(), Params(), REF);
        var site = M("site", M("predicates", Li(M("verb", "air.book", "where", Li(M("field", "env.canon.add_ons", "op", "eq", "value", "[\"none\"]"))))));
        var ok = Verify(G0, p, Ctx("layers", site));
        Assert.True(ok.Allow, ok.Reason);
        Assert.Equal(Keys("schema", "intent_session", "layers", "accumulators"), ok.Checks.Keys.ToList());
        var org = M("org", M("predicates", Li(M("verb", "air.book", "where", Li(M("field", "action.params.total", "op", "lte", "value", 10_000L))))));
        Assert.Equal(new[] { "layers" }, Failed(Verify(G0, p, Ctx("layers", org))));
        Assert.True(Verify(G0, p, Ctx("layers", M())).Allow);
        Assert.Equal(new[] { "schema", "intent_session", "accumulators" }, Failed(Verify(G0, p, Ctx("layers", M("std", M())))));
        Assert.Equal(new[] { "schema", "intent_session", "accumulators" }, Failed(Verify(G0, p, Ctx("layers", M("org", null)))));
        Assert.Equal(new[] { "layers" }, Failed(Verify(G0, p, Ctx("layers", M("site", M("predicates", Li(M("verb", "*")), "note", "x"))))));
        var bad = Params(); bad["total"] = 1L;
        Assert.Equal(new[] { "schema", "layers", "accumulators" }, Failed(Verify(G0, p, Ctx("params", bad, "layers", site))));
        var plain = Build(G0, "salt0", MAP0, null, Params(), REF);
        Assert.Equal(CORE, Verify(G0, plain, Ctx("layers", org)).Checks.Keys);
        // W-B unit
        var v = Verify(G0, p, Ctx("wb", M("policy", M("provenance", M("params", M())))));
        Assert.Equal(Keys("schema", "intent_session", "accumulators", "provenance"), v.Checks.Keys.ToList());
        var q = Verify(G0, p, Ctx("wb", M("policy", M("provenance", M("params", M("action.params.offer_id", "material"))))));
        Assert.Equal(new[] { "provenance" }, Failed(q));
        Assert.StartsWith("provenance: intent_required: ", q.Reason);
        var f = Verify(G0, p, Ctx("wb", M("policy", M("world", M("worlds", Li(M())), "provenance", M("params", M())))));
        Assert.Equal(Keys("schema", "intent_session", "accumulators", "facts"), f.Checks.Keys.ToList());
    }
}

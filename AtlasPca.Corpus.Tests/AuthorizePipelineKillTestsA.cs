using System.Globalization;
using System.Reflection;
using System.Text;
using System.Text.Json;
using AtlasPca;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>k05 Stryker survivors of Authorize.cs lines 770-1099: MissingAuthorizeComponents, the host-value JSON tree (its depth bound
/// observed by WHICH layer refuses), the PCActn decode (private Coerce / ParseObject driven by reflection), and the authorize pipeline's
/// stage refusals, the async grant / Intent v2 resolvers, the plan registry, the workflow admission, the wire early exit and the
/// zk / grant_ref / params_digest checks (a PCActn minted by this SDK's producer). The core verdict is edited through CoreHook.</summary>
public class AuthorizePipelineKillTestsA
{
    // ================= helpers =================

    static D Junk() => new() { ["grant_ref"] = "g" }; // decodes, names a grant, fails the wire check
    static D G() => new() { ["id"] = "g" };

    static AuthorizeInput Base() => new()
    {
        Operation = new Operation("v", "r", new D()), Audience = "aud", ResolveGrant = _ => G(), StateStore = new MemoryStateStore(),
        IsRevoked = (_, _) => false, Now = 1,
    };

    static string Fails(AuthorizeResult r) => string.Join(",", r.Checks.Select(kv => kv.Key + "=" + kv.Value));

    static void Refused(AuthorizeResult r, int status, string check, string reason)
    {
        Assert.False(r.Allow);
        Assert.Equal(status, r.Status);
        Assert.Equal(check + "=fail", Fails(r));
        Assert.Equal(reason, r.Reason);
        Assert.Equal(new[] { reason }, r.Reasons);
    }

    sealed class Hook : IDisposable
    {
        public Hook(Action<Verdict> h) => Pca.CoreHook = h;
        public void Dispose() => Pca.CoreHook = null;
    }

    // ---- a PCActn minted by this SDK (principal opt-out of the provenance gate, so only the rules under test decide)
    const long Now = 1_800_000_000_000L;
    const string Aud = "ins_kill_a";
    static readonly SuiteKey Principal = SuiteKey.Ed25519(EdKey.FromSeed(Enumerable.Repeat((byte)5, 32).ToArray()));
    static readonly SuiteKey Holder = SuiteKey.Ed25519(EdKey.FromSeed(Enumerable.Repeat((byte)6, 32).ToArray()));

    static D Env() => (D)Pca.ParseJson("""
        {"predicates":[{"resource":"*","verb":"*","where":[]}],"caveats":[],
         "risk_policy":{"bMax":1000,"kappa":1,"lambda":0,"rho":0,"theta1":0.5,"theta2":0.8,"weights":{"alpha":0,"beta":0,"delta":0,"epsilon":0,"gamma":0,"zeta":0}},
         "provenance":{"mode":"insecure_off"}}
        """)!;

    static D Params(long amount) => new() { ["amount"] = amount };
    static Operation Op(long amount = 5) => new("payments.send", "payments/acme", Params(amount));

    static (D Pcactn, D Grant) Minted()
    {
        var g = Issue.MintGrant(Principal, Holder.Id!, null, Env(), "kill a");
        var grant = (D)Pca.ParseStrict(Pca.Canonicalize(g.Grant))!;
        var act = new Agent(Holder, Aud, g.Grant) { Clock = () => Now }.Act("payments.send", "payments/acme", Params(5));
        return ((D)Pca.ParseStrict(Issue.Encode(act))!, grant);
    }

    static AuthorizeInput MintedInput(D grant) => new()
    {
        Operation = Op(), Audience = Aud, ResolveGrant = _ => grant, StateStore = new MemoryStateStore(), IsRevoked = (_, _) => false,
        Now = Now, Plan = "single-step",
    };

    [Fact]
    public void TheMintedHarnessAllows()
    {
        var (p, g) = Minted();
        var r = Pca.Authorize(p, MintedInput(g));
        Assert.True(r.Allow, r.Reason);
    }

    // ================= MissingAuthorizeComponents (L770, L776, L782) =================

    [Fact]
    public void SyncNeedsTheSyncResolver()
    {
        var i = Base();
        i.ResolveGrant = null;
        i.ResolveGrantAsync = _ => Task.FromResult<D?>(G());
        Assert.Equal(new[] { "ResolveGrant" }, Pca.MissingAuthorizeComponents(i)); // the async resolver does not satisfy the sync API
        var r = Pca.Authorize(Junk(), i); // L907: Prepare(.., async: false)
        Refused(r, 403, "authorize_config", "authorize_config: missing required component(s): ResolveGrant (fail closed)");
        Assert.Equal(new[] { "ResolveGrant" }, r.Missing);
    }

    [Fact]
    public async Task AsyncNeedsSomeResolver()
    {
        var i = Base();
        i.ResolveGrant = null;
        var r = await Pca.AuthorizeAsync(Junk(), i);
        Refused(r, 403, "authorize_config", "authorize_config: missing required component(s): ResolveGrant (fail closed)");
        i.ResolveGrantAsync = _ => Task.FromResult<D?>(G());
        Assert.Equal("wire=fail,malformed=fail", Fails(await Pca.AuthorizeAsync(Junk(), i)));
    }

    [Fact]
    public void InvalidStalenessPolicyIsNamed()
    {
        var i = Base();
        i.RevocationStaleness = new RevocationStalenessPolicy(MaxRevocationAgeMs: -1);
        i.RevocationState = (_, _) => null;
        Assert.Equal(new[] { "RevocationStaleness (invalid: maxRevocationAgeMs must be a positive number of milliseconds)" }, Pca.MissingAuthorizeComponents(i));
    }

    // ================= ToJsonTree (L809-L850) =================

    static object? Dicts(int n) { object? v = 1L; for (int i = 0; i < n; i++) v = new D { ["a"] = v }; return v; }
    static object? Lists(int n) { object? v = 1L; for (int i = 0; i < n; i++) v = new L { v }; return v; }
    static JsonElement Json(string text) => JsonDocument.Parse(text).RootElement;
    static JsonElement JsonObjects(int n) => Json(string.Concat(Enumerable.Repeat("{\"a\":", n)) + "1" + new string('}', n));
    static JsonElement JsonArrays(int n) => Json(new string('[', n) + "1" + new string(']', n));
    static string Thrown(Func<object?> f) => Assert.Throws<InvalidOperationException>(() => f()).Message;

    // n nested containers around a scalar: n = 32 is canonical; n = 33 is refused by the canonicalizer (MaxJsonDepth 32, the same
    // accept/refuse boundary as the TypeScript canonicalize); n = 34 is refused earlier by the host-value walk's own recursion bound
    // (MaxJsonDepth + 1: the scalar at depth 34), a resource bound that is kept and observed here by its message.
    public static TheoryData<string> Shapes => new() { "dict", "list", "json-object", "json-array" };

    static object? Nest(string shape, int n) => shape switch
    {
        "dict" => Dicts(n),
        "list" => Lists(n),
        "json-object" => JsonObjects(n),
        _ => JsonArrays(n),
    };

    [Theory]
    [MemberData(nameof(Shapes))]
    public void ParamsDepthBound(string shape)
    {
        var ok = Pca.JsonText(Nest(shape, 32));
        Assert.Contains("1", ok);
        Assert.Equal("canonicalize: nesting too deep", Thrown(() => Pca.JsonText(Nest(shape, 33))));
        Assert.Equal("params nesting too deep", Thrown(() => Pca.JsonText(Nest(shape, 34))));
        Assert.Equal("params nesting too deep", Thrown(() => Pca.JsonText(Nest(shape, 40))));
    }

    [Fact]
    public void UnsupportedValueType() =>
        Assert.Equal("params: unsupported value type Object", Thrown(() => Pca.JsonText(new D { ["x"] = new object() })));

    [Fact]
    public void JsonElementLiterals()
    {
        Assert.Equal("[true,false,null]", Pca.JsonText(Json("[true,false,null]")));
        Assert.Equal("{\"a\":1,\"b\":2}", Pca.JsonText(Json("{\"b\":2,\"a\":1}")));
        Assert.Equal("params: duplicate key", Thrown(() => Pca.JsonText(Json("{\"a\":1,\"a\":2}"))));
        Assert.Equal("params: undefined JSON value", Thrown(() => Pca.JsonText(default(JsonElement))));
    }

    // ================= Coerce / ParseObject (L859-L875), private: driven by reflection =================

    const BindingFlags NP = BindingFlags.NonPublic | BindingFlags.Static;
    static (D? P, string? Err) Coerce(object? x) => ((D?, string?))typeof(Pca).GetMethod("Coerce", NP)!.Invoke(null, new[] { x })!;
    static (D? P, string? Err) ParseObject(string x) => ((D?, string?))typeof(Pca).GetMethod("ParseObject", NP)!.Invoke(null, new object?[] { x })!;

    static string Doc(int bytes) => "{\"a\":\"" + new string('x', bytes - 8) + "\"}"; // exactly `bytes` UTF-8 bytes

    [Fact]
    public void CoerceStrings()
    {
        var (p, err) = Coerce("{\"a\":1}");
        Assert.Null(err);
        Assert.Equal("{\"a\":1}", Pca.Canonicalize(p));
        Assert.Equal(((D?)null, "undecodable"), Coerce(Doc(Pca.MaxArtifactBytes + 1))); // too large: refused before parsing
        Assert.NotNull(Coerce(Doc(Pca.MaxArtifactBytes)).P);
        Assert.Equal(((D?)null, "undecodable"), ParseObject("[1]"));
        Assert.Equal(((D?)null, "undecodable"), ParseObject("{"));
        Assert.Equal(((D?)null, "undecodable"), Coerce("[1]"));
    }

    [Fact]
    public void CoerceBytes()
    {
        Assert.NotNull(Coerce(Encoding.UTF8.GetBytes(Doc(Pca.MaxArtifactBytes))).P); // n == MaxArtifactBytes: decoded
        Assert.NotNull(Coerce(Encoding.UTF8.GetBytes(Doc(Pca.MaxArtifactBytes - 1))).P);
        Assert.Equal(((D?)null, "undecodable"), Coerce(Encoding.UTF8.GetBytes(Doc(Pca.MaxArtifactBytes + 1))));
        Assert.Equal("{}", Pca.Canonicalize(Coerce(Encoding.UTF8.GetBytes("{}")).P));
        // invalid UTF-8 is refused, never replaced with U+FFFD
        var bad = Encoding.UTF8.GetBytes("{\"a\":\"#\"}");
        bad[6] = 0xFF;
        Assert.Equal(((D?)null, "undecodable"), Coerce(bad));
    }

    [Fact]
    public void CoerceOthers()
    {
        Assert.Equal(((D?)null, "absent"), Coerce(null));
        Assert.Equal(((D?)null, "undecodable"), Coerce(42));
        var d = new D();
        Assert.Same(d, Coerce(d).P);
    }

    // ================= Prepare (L884-L895) =================

    [Fact]
    public void OnlySingleStepPlan()
    {
        var i = Base();
        i.Plan = "multi";
        var r = Pca.Authorize(Junk(), i);
        Refused(r, 403, "authorize_config", "authorize_config: missing required component(s): Plan (only 'single-step' or null) (fail closed)");
        Assert.Equal(new[] { "Plan (only 'single-step' or null)" }, r.Missing);
    }

    [Fact]
    public void NoOperation()
    {
        var i = Base();
        i.Operation = null;
        Refused(Pca.Authorize(Junk(), i), 403, "operation", "operation: authorize needs the operation to execute (verb, resource, params) (fail closed)");
    }

    [Fact]
    public void DecodeRefusals()
    {
        Refused(Pca.Authorize(null, Base()), 401, "wire", "wire: no PCActn presented");
        Refused(Pca.Authorize("not json", Base()), 401, "pcactn", "undecodable PCActn: could not be decoded");
        Refused(Pca.Authorize(42, Base()), 401, "pcactn", "undecodable PCActn: could not be decoded");
        var p = new D { ["grant_ref"] = 7L };
        var r = Pca.Authorize(p, Base());
        Refused(r, 401, "malformed", "malformed: grant_ref is not a string");
        Assert.Same(p, r.Pcactn);
    }

    // ================= grant resolution and the outer catch (L911-L943, L981) =================

    [Fact]
    public void GrantResolution()
    {
        var i = Base();
        i.ResolveGrant = _ => throw new InvalidOperationException("db");
        var p = Junk();
        var r = Pca.Authorize(p, i);
        Refused(r, 403, "resolve_grant", "resolve_grant: grant resolution failed (fail closed)");
        Assert.Same(p, r.Pcactn);
        i.ResolveGrant = _ => null;
        Refused(Pca.Authorize(p, i), 401, "grant_ref", "grant_ref: does not resolve to a known grant");
    }

    [Fact]
    public async Task AsyncGrantResolution()
    {
        var i = Base();
        i.ResolveGrant = null;
        i.ResolveGrantAsync = _ => throw new InvalidOperationException("db");
        Refused(await Pca.AuthorizeAsync(Junk(), i), 403, "resolve_grant", "resolve_grant: grant resolution failed (fail closed)");
        i.ResolveGrantAsync = _ => Task.FromException<D?>(new InvalidOperationException("db"));
        Refused(await Pca.AuthorizeAsync(Junk(), i), 403, "resolve_grant", "resolve_grant: grant resolution failed (fail closed)");
    }

    [Fact]
    public async Task AnEscapingErrorIsADenial()
    {
        using (new Hook(_ => throw new TimeoutException()))
        {
            Refused(Pca.Authorize(Junk(), Base()), 403, "authorize", "authorize: error (fail closed): TimeoutException");
            Refused(await Pca.AuthorizeAsync(Junk(), Base()), 403, "authorize", "authorize: error (fail closed): TimeoutException");
        }
    }

    // ================= Intent Layer v2 providers (L933-L939, L1012-L1016) =================

    const string V2Down = "intent_v2: verifier state unavailable (fail closed)";

    [Fact]
    public void SyncProviderFailureIsRefused()
    {
        var i = Base();
        i.IntentV2Provider = _ => throw new InvalidOperationException("down");
        Refused(Pca.Authorize(Junk(), i), 403, "intent_v2", V2Down);
        i.IntentV2Provider = _ => null; // a provider that answers "none" is not a failure
        Assert.Equal("wire=fail,malformed=fail", Fails(Pca.Authorize(Junk(), i)));
    }

    [Fact]
    public async Task AsyncProviderFailureIsRefused()
    {
        var i = Base();
        i.IntentV2ProviderAsync = _ => throw new InvalidOperationException("down");
        Refused(await Pca.AuthorizeAsync(Junk(), i), 403, "intent_v2", V2Down);
        i.IntentV2ProviderAsync = _ => Task.FromException<IntentV2Context?>(new InvalidOperationException("down"));
        Refused(await Pca.AuthorizeAsync(Junk(), i), 403, "intent_v2", V2Down);
        // the async provider wins over the sync one in AuthorizeAsync
        i.IntentV2Provider = _ => null;
        Refused(await Pca.AuthorizeAsync(Junk(), i), 403, "intent_v2", V2Down);
    }

    [Fact]
    public async Task AsyncProviderAnsweringNoneIsNotAFailure()
    {
        var i = Base();
        int calls = 0;
        i.IntentV2ProviderAsync = _ => { calls++; return Task.FromResult<IntentV2Context?>(null); };
        var r = await Pca.AuthorizeAsync(Junk(), i);
        Assert.Equal(1, calls);
        Assert.Equal("wire=fail,malformed=fail", Fails(r));
        // the sync provider is the one consulted when the async one is absent
        i.IntentV2ProviderAsync = null;
        i.IntentV2Provider = _ => throw new InvalidOperationException("down");
        Refused(await Pca.AuthorizeAsync(Junk(), i), 403, "intent_v2", V2Down);
    }

    // ================= context callback (L988) =================

    [Fact]
    public void ContextFailureIsRefused()
    {
        var i = Base();
        i.Context = _ => throw new InvalidOperationException("ctx");
        var p = Junk();
        var r = Pca.Authorize(p, i);
        Refused(r, 403, "context", "context: the context callback failed (fail closed)");
        Assert.Same(p, r.Pcactn);
    }

    // ================= plan registry (L994-L1008) =================

    sealed class Kv : IAtomicKv
    {
        public readonly List<string> Keys = new();
        public string? Text;
        public string? Get(string key) { Keys.Add(key); return Text; }
        public void Update(string key, Func<string?, string?> fn) { }
    }

    // a stored record with a lone surrogate in a node: the lenient store decode keeps it, PlanRegistry.Context's node copy cannot canonicalize it
    const string Poison = """{"grantRef":"g","root":"r","nodes":[{"id":"\ud800","verb":"v","resource":"r"}],"state":"draft","createdAt":0}""";

    [Fact]
    public void RegistryFailureIsRefused()
    {
        var i = Base();
        i.Plans = new PlanRegistry(new PlanRegistryOptions { Kv = new Kv { Text = Poison } });
        Refused(Pca.Authorize(Junk(), i), 403, "plan_state", "plan_state: the plan registry failed (fail closed)");
        // a context that supplies the plan: the registry is not consulted
        i.Context = _ => new D { ["plan"] = new L() };
        Assert.Equal("wire=fail,malformed=fail", Fails(Pca.Authorize(Junk(), i)));
    }

    [Fact]
    public void RegistryIsAskedForTheEmptyRootWhenThePcactnHasNone()
    {
        var kv = new Kv();
        var i = Base();
        i.Plans = new PlanRegistry(new PlanRegistryOptions { Kv = kv });
        Pca.Authorize(Junk(), i);
        Assert.Equal(new[] { "pca-plan:g:" }, kv.Keys);
    }

    [Fact]
    public void UnknownRegistryPlanIsReported()
    {
        var (p, g) = Minted();
        var i = MintedInput(g);
        i.Plan = null;
        i.Plans = new PlanRegistry();
        var r = Pca.Authorize(p, i);
        var root = (string)((D)p["plan"]!)["root"]!;
        Assert.Equal("fail", r.Checks["plan_state"]);
        Assert.Contains($"plan_state: plan {root} is unknown to the plan registry", r.Reasons);
    }

    // ================= workflow admission (L959-L968, L1031) =================

    static D Wf()
    {
        var f = Path.Combine(Conf.Dir(), "authorize-workflow-fixtures.json");
        Assert.True(File.Exists(f), "authorize-workflow-fixtures.json is missing (a fixture file is never skipped)");
        return (D)Pca.ParseJson(File.ReadAllText(f))!;
    }

    static D Step0(D F, string name) => (D)((L)((L)F["cases"]!).Cast<D>().First(c => (string)c["name"]! == name)["steps"]!)[0]!;

    static AuthorizeInput WfInput(D F, D step, object? units)
    {
        var op = (D)step["operation"]!;
        var grant = (D)F["grant"]!;
        var w = (D)step["workflow"]!;
        return new AuthorizeInput
        {
            Operation = new Operation((string)op["verb"]!, (string)op["resource"]!, op["params"]),
            Audience = (string)F["audience"]!, ResolveGrant = r => r == (string)grant["id"]! ? grant : null,
            StateStore = new MemoryStateStore(), IsRevoked = (_, _) => false, Now = long.Parse(((Num)F["now"]!).Raw, CultureInfo.InvariantCulture),
            Context = _ => new D { ["plan"] = F["plan"], ["plan_authorized"] = true },
            Workflow = new WorkflowGate((string)F["principal"]!, (string)F["rs_signer"]!),
            WorkflowCall = new WorkflowCall(w["commitment"], w["receipts"], w["step"] as string, units, w.GetValueOrDefault("goal_digest") as string),
        };
    }

    [Fact]
    public void WorkflowUnitsReachTheAdmission()
    {
        var F = Wf();
        var s = Step0(F, "pay-after-quote");
        var ok = Pca.Authorize(s["pcactn"], WfInput(F, s, null).WithProv()); // no units: {}
        Assert.True(ok.Allow, ok.Reason);
        var bad = Pca.Authorize(s["pcactn"], WfInput(F, s, "bogus").WithProv()); // units not an object: a malformed request, no step named
        Refused(bad, 403, "workflow", "workflow: bad_workflow");
        Assert.Equal("deny", bad.Decision);
    }

    [Fact]
    public void AThrowInWorkflowAdmissionFailsClosed()
    {
        var F = Wf();
        var s = Step0(F, "pay-after-quote");
        Pca.WorkflowHook = () => throw new InvalidOperationException("boom");
        try { Refused(Pca.Authorize(s["pcactn"], WfInput(F, s, null).WithProv()), 403, "workflow", "workflow: error (fail closed)"); }
        finally { Pca.WorkflowHook = null; }
    }

    [Fact]
    public void AnAdmittedStepIsThePrincipalsChoice()
    {
        var F = Wf();
        var s = Step0(F, "pay-after-quote");
        var i = WfInput(F, s, null);
        i.ProvenanceFlow = ProvHarness.Options; // no bundle: the values are the agent's, the choice of the step is the principal's
        var r = Pca.Authorize(s["pcactn"], i);
        Assert.Equal("fail", r.Checks["provenance_flow"]);
        Assert.Contains("provenance_flow: escalate: order derives from untrusted content [unlabelled]: the principal must confirm (prompt-injection path)", r.Reasons);
        Assert.DoesNotContain(r.Reasons, x => x.Contains("the choice of", StringComparison.Ordinal));
    }

    [Fact]
    public void AStepRemovedAfterPrepareIsRefused()
    {
        var F = Wf();
        var s = Step0(F, "pay-after-quote");
        var i = WfInput(F, s, null).WithProv();
        i.Workflow = i.Workflow! with { Required = true };
        var ctx = i.Context!;
        i.Context = p => { i.WorkflowCall = null; return ctx(p); }; // the step is gone by the time the workflow gate runs
        var pc = (D)s["pcactn"]!;
        var r = Pca.Authorize(pc, i);
        Refused(r, 403, "workflow", "workflow: this call carries no workflow step (fail closed)");
        Assert.Same(pc, r.Pcactn);
    }

    // ================= the wire early exit (L1039-L1044) and the core reason (L1057) =================

    [Fact]
    public void WireFailureExitsEarly()
    {
        var p = Junk();
        var r = Pca.Authorize(p, Base());
        Assert.False(r.Allow);
        Assert.Equal(401, r.Status);
        Assert.Equal("wire=fail,malformed=fail", Fails(r));
        Assert.NotNull(r.Verdict);
        Assert.NotEqual("", r.Verdict!.Reason);
        Assert.NotEqual("wire: malformed PCActn", r.Verdict.Reason);
        Assert.Equal(r.Verdict.Reason, r.Reason);
        Assert.Equal(new[] { r.Verdict.Reason }, r.Reasons);
        Assert.Same(p, r.Pcactn);
        Assert.Equal("deny", r.Decision);
    }

    [Fact]
    public void WireFailureWithoutAReasonGetsTheDefault()
    {
        using (new Hook(v => v.Reason = ""))
        {
            var r = Pca.Authorize(Junk(), Base());
            Assert.False(r.Allow);
            Assert.Equal(401, r.Status);
            Assert.Equal("wire=fail,malformed=fail", Fails(r));
            Assert.Equal("wire: malformed PCActn", r.Reason);
            Assert.Equal(new[] { "wire: malformed PCActn" }, r.Reasons);
        }
    }

    [Fact]
    public void AnEmptyCoreReasonIsNotReported()
    {
        var (p, g) = Minted();
        using (new Hook(v => { v.Allow = false; v.Checks["version"] = false; v.Reasons.Clear(); v.Reason = ""; }))
        {
            var r = Pca.Authorize(p, MintedInput(g));
            Assert.False(r.Allow);
            Assert.Equal("fail", r.Checks["version"]);
            Assert.DoesNotContain("", r.Reasons);
        }
    }

    // ================= zk_compliance, grant_ref, params_digest (L1077-L1096) =================

    [Fact]
    public void ACarriedZkProofIsRefused()
    {
        var (p, g) = Minted();
        p["zk_compliance"] = new D();
        var r = Pca.Authorize(p, MintedInput(g));
        Assert.False(r.Allow);
        Assert.Equal("fail", r.Checks["zk_compliance"]);
        Assert.Contains("zk_compliance: " + Pca.ZkUnenforced, r.Reasons);
        Assert.Equal(1, r.Reasons.Count(x => x.StartsWith("zk_compliance: ", StringComparison.Ordinal)));
        var (p2, g2) = Minted();
        Assert.False(Pca.Authorize(p2, MintedInput(g2)).Checks.ContainsKey("zk_compliance"));
    }

    static D WithSigned(D p, string member, object? value)
    {
        p[member] = value;
        p.Remove("sig");
        p["sig"] = Holder.Sign(Pca.ThresholdMessage(p)).Sig;
        return p;
    }

    // pcactn.ts:835-841: a carried proof fails at the core when no verifier enforces it, as the only failure and named once by Authorize
    [Fact]
    public void ASignedZkProofFailsAtTheCoreWithOneReason()
    {
        var (p, g) = Minted();
        WithSigned(p, "zk_compliance", new D());
        var core = Pca.VerifyPcactnCore(p, g, Now, Aud);
        Assert.False(core.Allow);
        Assert.False(core.Checks["zk_compliance"]);
        Assert.True(core.Checks["leaf_signature"]);
        Assert.Equal("zk_compliance: " + Pca.ZkUnenforced, core.Reason);
        var r = Pca.Authorize(p, MintedInput(g));
        Assert.False(r.Allow);
        Assert.Equal(new[] { "zk_compliance: " + Pca.ZkUnenforced }, r.Reasons);
    }

    // server/verify.ts:531-533: a carried feature this verifier does not implement is reported, never a pass, and denies unless allowed
    const string BondReason = "bond: unsupported: the PCActn carries a feature this verifier does not implement (list it in allowUnsupported to accept it)";

    [Fact]
    public void ABondRefDeniesAsUnsupportedWithoutSpendingTheCounter()
    {
        var (p, g) = Minted();
        WithSigned(p, "bond_ref", "bond-1");
        var input = MintedInput(g);
        var r = Pca.Authorize(p, input);
        Assert.False(r.Allow);
        Assert.Equal(403, r.Status);
        Assert.Equal("deny", r.Decision);
        Assert.Equal("unsupported", r.Checks["bond"]);
        Assert.Equal(new[] { BondReason }, r.Reasons);
        Assert.Equal(BondReason, r.Reason);
        input.AllowUnsupported = new[] { "bond" };
        var again = Pca.Authorize(p, input);
        Assert.True(again.Allow, again.Reason);
        Assert.Equal("unsupported", again.Checks["bond"]);
    }

    [Fact]
    public void AllowingAnotherCheckDoesNotAllowABond()
    {
        var (p, g) = Minted();
        WithSigned(p, "bond_ref", "bond-1");
        var input = MintedInput(g);
        input.AllowUnsupported = new[] { "other" };
        Assert.False(Pca.Authorize(p, input).Allow);
    }

    [Fact]
    public void ABondRefWithAnotherFailureIsStillDeniedAndBothAreReported()
    {
        var (p, g) = Minted();
        WithSigned(p, "bond_ref", "bond-1");
        var input = MintedInput(g);
        input.IsRevoked = (_, _) => true;
        input.AllowUnsupported = new[] { "bond" };
        var r = Pca.Authorize(p, input);
        Assert.False(r.Allow);
        Assert.Equal("unsupported", r.Checks["bond"]);
        Assert.Equal("fail", r.Checks["revocation"]);
    }

    [Fact]
    public void NoBondRefReportsNoBondCheck()
    {
        var (p, g) = Minted();
        Assert.False(Pca.Authorize(p, MintedInput(g)).Checks.ContainsKey("bond"));
    }

    [Fact]
    public void AnotherGrantIsNotReferenced()
    {
        var (p, _) = Minted();
        var (_, other) = Minted();
        var r = Pca.Authorize(p, MintedInput(other));
        Assert.False(r.Allow);
        Assert.Equal("fail", r.Checks["grant_ref"]);
        Assert.Contains("grant_ref: does not reference the supplied grant", r.Reasons);
    }

    [Fact]
    public void OtherParamsDoNotHashToTheSignedDigest()
    {
        var (p, g) = Minted();
        var i = MintedInput(g);
        i.Operation = Op(6);
        var r = Pca.Authorize(p, i);
        Assert.False(r.Allow);
        Assert.Equal("fail", r.Checks["params_digest"]);
        Assert.Contains("params_digest: supplied params do not hash to action.params_digest", r.Reasons);
    }
}

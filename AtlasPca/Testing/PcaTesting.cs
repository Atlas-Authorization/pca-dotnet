// Testing kit for Proof-Carrying Authority: factories, fakes and assertion helpers so an integrator can test their PCA wiring in
// process, with no backend and no network. TestAgent mints a real agent with test defaults, MakePCActn builds real PCActns from it, and
// FakeVerify runs the real core verifier against them.
//
// Nothing here authorizes anything: FakeVerify stands in for the resource server by rooting the check at the PCActn's own grant and
// accepting the PCActn's own audience by default, so a clean round trip verifies. It is the real verifier, not a weakened one: tampering
// is caught exactly as in production. A grant lifted from the artifact is never trusted for a post-quantum root (no pin exists).
using System.Collections.Concurrent;
using System.Globalization;
using System.Text.RegularExpressions;
using AtlasPca.Adapters;
using AtlasPca.Js;
using AtlasPca.InteropJs;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Testing;

/// <summary>Overrides for <see cref="PcaTesting.TestAgent"/>; anything left null falls back to a test default.</summary>
public sealed class TestAgentOverrides
{
    /// <summary>Connector to allowed actions. Default {stripe: [refund]}.</summary>
    public D? Permissions;
    /// <summary>Per-action limits. Default {refund: "$500/day"}; pass an empty map for none.</summary>
    public IReadOnlyDictionary<string, string>? Limits;
    public string? Goal;
    public string? Aud;
    public SuiteKey? Principal;
    public SuiteKey? Holder;
}

/// <summary>Options of FakeVerify / ExpectVerifies / ExpectDenied.</summary>
public sealed class FakeVerifyOptions
{
    /// <summary>The verifier's own audience, honoured only when <see cref="AudienceGiven"/> (a null then opts out: the PCActn's own audience).</summary>
    public string? Audience;
    public bool AudienceGiven;
    public long? Now;
    public D? Grant;
}

/// <summary>The verdict: allow, each check's pass/fail in the verifier's order, and the first failure's reason.</summary>
public sealed record FakeVerifyResult(bool Allow, Dictionary<string, bool> Checks, string Reason);

/// <summary>A PCActn and its wire encoding.</summary>
public sealed record MadePcactn(D Pcactn, string Encoded);

/// <summary>An in-memory per-holder state store; nothing persists beyond the process.</summary>
public sealed class TestStateStore
{
    readonly ConcurrentDictionary<string, D> _m = new(StringComparer.Ordinal);
    public D? Get(string key) => _m.TryGetValue(key, out var v) ? v : null;
    public void Put(string key, D state) => _m[key] = state;
}

/// <summary>One request as the adapter's framework would receive it.</summary>
public sealed record AcceptanceRequest(string Method, string Path, IReadOnlyDictionary<string, string> Headers, D Body);

/// <summary>What the harness observed for one request: the status, whether the handler ran and, for an allowed call, the operation the adapter attached.</summary>
public sealed record AcceptanceObservation(int Status, bool HandlerRan, AuthorizedOperation? Operation = null);

/// <summary>The <c>requireAuthorized</c>-shaped options of one scenario, to be passed to the adapter unchanged. <see cref="ToInput"/> builds the
/// <see cref="AuthorizeInput"/> of one request: the operation (from <see cref="PcaTesting.AcceptanceOperation"/>) and the presented provenance bundle.
/// <see cref="StateStore"/> and <see cref="IsRevoked"/> are null in the scenarios that leave them out; the adapter must then refuse (fail closed).</summary>
public sealed class AcceptanceOptions
{
    public string Audience { get; init; } = PcaTesting.AdapterAcceptanceAudience;
    public Func<string, D?> ResolveGrant { get; init; } = _ => null;
    public IStateStore? StateStore { get; init; }
    public Func<D, D, bool?>? IsRevoked { get; init; }
    public string Plan { get; init; } = "single-step";
    public Func<Operation, D, D, IReadOnlyDictionary<string, double>?> ServerRiskFor { get; init; } = (_, _, _) => null;
    public ArgProvenanceOptions? ProvenanceFlow { get; init; }

    public AuthorizeInput ToInput(Operation op, object? provenance) => new()
    {
        Operation = op, Audience = Audience, ResolveGrant = ResolveGrant, StateStore = StateStore, IsRevoked = IsRevoked, Plan = Plan,
        ServerRiskFor = ServerRiskFor, ProvenanceFlow = ProvenanceFlow, Provenance = provenance,
    };
}

/// <summary>Adapter-specific plumbing: build the adapter (middleware / wrapper) ONCE from the options with a handler spy and return a function that sends one request through it.</summary>
public delegate Func<AcceptanceRequest, AcceptanceObservation> AcceptanceHarness(AcceptanceOptions options);

public static class PcaTesting
{
    public const string AdapterAcceptanceAudience = "payments-rs";

    // ---- factories ----

    public static AgentHandle TestAgent(TestAgentOverrides? ov = null)
    {
        var o = ov ?? new TestAgentOverrides();
        var opts = new AgentOptions
        {
            Principal = o.Principal ?? SuiteKey.Ed25519(EdKey.Generate()),
            Goal = o.Goal ?? "test",
            Permissions = o.Permissions ?? new D { ["stripe"] = new L { "refund" } },
            Limits = o.Limits ?? new Dictionary<string, string> { ["refund"] = "$500/day" },
            Aud = o.Aud ?? "ins_test",
        };
        if (o.Holder != null) opts.Holder = o.Holder;
        return Agent.FromPrincipal(opts);
    }

    /// <summary>Build a PCActn for one action (counter auto-increments per holder when null; now is the clock in ms).</summary>
    public static MadePcactn MakePCActn(AgentHandle a, string verb, string resource, D? prms = null, long? counter = null, long? now = null)
    {
        var r = a.Act(verb, resource, prms, new ActOptions { Counter = counter, Now = now });
        return new MadePcactn(r.PCActn, r.Encoded);
    }

    // ---- fake verifier ----

    /// <summary>pcactn.cap_chain[0] as JavaScript reads it; throws where JavaScript would throw or find nothing.</summary>
    static object LiftGrant(object? pcactn)
    {
        const string Empty = "fakeVerify: PCActn has an empty cap_chain and no grant was supplied via opts.grant";
        if (pcactn is not D m) throw new ArgumentException(Empty);
        m.TryGetValue("cap_chain", out var chain);
        object? first = null;
        if (chain is L l && l.Count > 0) first = l[0];
        else if (chain is string s && s.Length > 0) first = s.Substring(0, 1);
        if (!JsX.Truthy(first)) throw new ArgumentException(Empty);
        return first!;
    }

    static FakeVerifyResult Denied(string check, string why) => new(false, new Dictionary<string, bool> { [check] = false }, check + ": " + why);

    /// <summary>Run the real core verifier against <paramref name="pcactn"/>, rooting the check at opts.Grant or the PCActn's own chain root
    /// and defaulting the audience to the PCActn's own. A lifted grant whose suite is not plain ed25519 is refused (no verifier-side pin).
    /// Throws when there is no grant to root at.</summary>
    public static FakeVerifyResult FakeVerify(object? pcactn, FakeVerifyOptions? opts = null)
    {
        var o = opts ?? new FakeVerifyOptions();
        // a PCActn built in process carries native integers; the verifier reads what a wire carries, so pass it through its JSON form (an object that has none is verified as it is)
        try { if (pcactn is D) pcactn = Pca.ParseStrict(Pca.Canonicalize(pcactn)); } catch (Exception) { }
        object grant = o.Grant != null ? o.Grant : LiftGrant(pcactn);
        bool lifted = o.Grant == null;
        string? audience;
        if (o.AudienceGiven && o.Audience != null) audience = o.Audience;
        else
        {
            if (!o.AudienceGiven && pcactn == null) throw new ArgumentException("fakeVerify: no PCActn");
            audience = pcactn is D pm && pm.GetValueOrDefault("aud") is string aud ? aud : null; // a non-string aud fails the wire check
        }
        if (grant is not D g) return Denied("wire", "the grant is not an object");
        if (lifted && g.ContainsKey("alg") && !(g["alg"] is string alg && alg == "ed25519"))
            return Denied("chain", "root suite needs a verifier-side PQ pin; a grant lifted from the artifact is never trusted for it");
        long now = o.Now ?? AtlasPca.ReplayClock.NowMs();
        var v = Pca.VerifyPcactnCore(pcactn, g, now, audience!, null, null, null, null, PlanRootPolicy.Skip);
        return new FakeVerifyResult(v.Allow, new Dictionary<string, bool>(v.Checks), v.Reason);
    }

    static string Failing(FakeVerifyResult r) => string.Join(", ", r.Checks.Where(e => !e.Value).Select(e => e.Key));

    /// <summary>Assert that the PCActn verifies; throws an InvalidOperationException naming the failing checks when it does not.</summary>
    public static FakeVerifyResult ExpectVerifies(object? pcactn, FakeVerifyOptions? opts = null)
    {
        var r = FakeVerify(pcactn, opts);
        if (!r.Allow)
            throw new InvalidOperationException("expectVerifies: PCActn was denied. failing checks: [" + Failing(r) + "]" + (r.Reason.Length > 0 ? " — " + r.Reason : ""));
        return r;
    }

    /// <summary>The inverse of <see cref="ExpectVerifies"/>: throws when the PCActn unexpectedly verifies.</summary>
    public static FakeVerifyResult ExpectDenied(object? pcactn, FakeVerifyOptions? opts = null)
    {
        var r = FakeVerify(pcactn, opts);
        if (r.Allow)
            throw new InvalidOperationException("expectDenied: PCActn verified but was expected to be denied. checks: " + JsJson.Stringify(r.Checks.ToDictionary(e => e.Key, e => (object?)e.Value)));
        return r;
    }

    public static TestStateStore MemoryStateStore() => new();

    // ---- tampering ----

    /// <summary>Decode an encoded PCActn (strict JSON profile, size-capped), let <paramref name="mutate"/> corrupt it in place, then re-decode and
    /// re-encode it so a test can assert the corruption is caught. A change touching the signed body breaks the leaf signature.</summary>
    public static string Tamper(string encoded, Action<D> mutate)
    {
        if (Pca.ArtifactTooLarge(encoded)) throw new ArgumentException(Pca.ArtifactSizeReason);
        if (Pca.ParseStrict(encoded) is not D v) throw new ArgumentException("decodePCActn: not an object");
        var rec = new D(v);
        mutate(rec);
        var text = JsJson.Stringify(rec);
        if (Pca.ArtifactTooLarge(text)) throw new ArgumentException(Pca.ArtifactSizeReason);
        if (Pca.ParseStrict(text) is not D back) throw new ArgumentException("decodePCActn: not an object");
        return Pca.Canonicalize(back);
    }

    // ---- adapter acceptance matrix (constants and the route mapping) ----

    static D Outcome(int status, bool ran, bool bound) => new() { ["status"] = status, ["handlerRan"] = ran, ["bound"] = bound };

    /// <summary>The outcome every adapter must produce per scenario: status, whether the handler ran, whether the attached operation matches.</summary>
    public static D AdapterAcceptanceExpected()
    {
        var m = new D();
        foreach (var k in new[] { "over_limit_predicate", "over_limit_max_spend", "body_differs", "other_operation", "escalate_unanswered", "missing_revocation", "missing_store" })
            m[k] = Outcome(403, false, false);
        m["valid_first"] = Outcome(200, true, true);
        m["replay_second"] = Outcome(403, false, false);
        return m;
    }

    static bool IsSpecial(string scheme) => scheme is "http" or "https" or "ftp" or "ws" or "wss" or "file";

    static readonly Regex Scheme = new("^[A-Za-z][A-Za-z0-9+.\\-]*:", RegexOptions.CultureInvariant);

    /// <summary>The pathname of <paramref name="url"/> resolved against a base origin, as a WHATWG URL parser yields it, for the shapes a request
    /// carries: absolute and scheme-relative URLs with an authority, rooted and relative paths, dot segments, query and fragment. Only a pathname
    /// equal to a route can match, so any other spelling needs no further normalisation. shortcut: percent-encoding of the path is not
    /// reproduced (an encoded spelling never equals a route), upgrade if routes ever contain non-ASCII.</summary>
    internal static string PathnameOf(string url)
    {
        var s = Regex.Replace(Regex.Replace(url, "^[\\u0000-\\u0020]+|[\\u0000-\\u0020]+$", ""), "[\\t\\n\\r]", "");
        int cut = s.Length;
        for (int i = 0; i < s.Length; i++) if (s[i] == '?' || s[i] == '#') { cut = i; break; }
        var rest = s.Substring(0, cut);
        var sm = Scheme.Match(rest);
        string path;
        if (sm.Success)
        {
            var scheme = sm.Value.Substring(0, sm.Length - 1).ToLowerInvariant();
            rest = rest.Substring(sm.Length);
            if (!IsSpecial(scheme))
            {
                if (rest.StartsWith("//", StringComparison.Ordinal))
                {
                    int end = rest.IndexOf('/', 2);
                    path = end < 0 ? "" : rest.Substring(end);
                }
                else if (rest.StartsWith('/')) path = rest;
                else return rest; // opaque path: never a route
            }
            else if (scheme == "file")
            {
                rest = rest.Replace('\\', '/');
                if (rest.StartsWith("//", StringComparison.Ordinal))
                {
                    int end = rest.IndexOf('/', 2);
                    path = end < 0 ? "/" : rest.Substring(end);
                }
                else path = rest.StartsWith('/') ? rest : "/" + rest;
            }
            else
            {
                rest = rest.Replace('\\', '/');
                if (scheme == "http" && !rest.StartsWith("//", StringComparison.Ordinal)) path = rest.StartsWith('/') ? rest : "/" + rest; // same scheme as the base: relative
                else
                {
                    int slashes = 0;
                    while (slashes < rest.Length && rest[slashes] == '/') slashes++;
                    rest = rest.Substring(slashes);
                    int end = rest.IndexOf('/');
                    if ((end < 0 ? rest : rest.Substring(0, end)).Length == 0) throw new AtlasPca.Jose.InvalidUrlException();
                    path = end < 0 ? "/" : rest.Substring(end);
                }
            }
        }
        else
        {
            rest = rest.Replace('\\', '/');
            if (rest.StartsWith("//", StringComparison.Ordinal))
            {
                var t = rest.Substring(2).TrimStart('/');
                int end = t.IndexOf('/');
                if ((end < 0 ? t : t.Substring(0, end)).Length == 0) throw new AtlasPca.Jose.InvalidUrlException();
                path = end < 0 ? "/" : t.Substring(end);
            }
            else path = rest.StartsWith('/') ? rest : "/" + rest;
        }
        if (path.Length == 0) return "";
        var outSegs = new List<string>();
        var segs = path.Substring(1).Split('/');
        for (int i = 0; i < segs.Length; i++)
        {
            var seg = segs[i];
            var low = seg.ToLowerInvariant();
            bool last = i == segs.Length - 1;
            if (low is ".." or ".%2e" or "%2e." or "%2e%2e")
            {
                if (outSegs.Count > 0) outSegs.RemoveAt(outSegs.Count - 1);
                if (last) outSegs.Add("");
            }
            else if (low is "." or "%2e")
            {
                if (last) outSegs.Add("");
            }
            else outSegs.Add(seg);
        }
        return "/" + string.Join("/", outSegs);
    }

    /// <summary>The server's mapping from request to operation: a route table on method and path with the JSON body as params. Returns null for an
    /// unknown route or a body that is not an object; otherwise {verb, resource, params}.</summary>
    public static D? AcceptanceOperation(D req)
    {
        var url = req.GetValueOrDefault("url");
        var path = url is string us ? PathnameOf(us) : "";
        var method = req.TryGetValue("method", out var mv) ? JsJson.ToJsString(mv) : "undefined";
        var key = method.ToUpperInvariant() + " " + path;
        string verb;
        if (key == "POST /payments") verb = "payments.send";
        else if (key == "POST /refunds") verb = "payments.refund";
        else return null;
        var body = req.GetValueOrDefault("body");
        if (body is not D) return null;
        return new D { ["verb"] = verb, ["resource"] = "payments", ["params"] = body };
    }

    // ---- the acceptance matrix runner ----

    sealed record Fixture(Func<string, int, string, int, AcceptanceRequest> Request, Func<AcceptanceOptions> Options, Func<AcceptanceOptions, AcceptanceOptions> WithoutRevocation, Func<AcceptanceOptions, AcceptanceOptions> WithoutStore);

    static Fixture MakeFixture(string limit)
    {
        using var principal = SuiteKey.Ed25519(EdKey.Generate());
        var holder = SuiteKey.Ed25519(EdKey.Generate());
        var where = limit is "predicate" or "escalate" ? new L { new D { ["field"] = "action.params.amount", ["op"] = "lte", ["value"] = 100L } } : new L();
        var envelope = new D
        {
            ["predicates"] = new L { new D { ["verb"] = new L { "payments.send", "payments.refund" }, ["resource"] = "payments", ["where"] = where } },
            ["caveats"] = new L(), ["agent_binding"] = new D(),
            // "spend = risk": each call is priced at amount / 100 and debits the amount from a far-away budget
            ["risk_policy"] = new D
            {
                ["weights"] = new D { ["alpha"] = 0L, ["beta"] = 0L, ["gamma"] = 1L, ["delta"] = 0L, ["epsilon"] = 0L, ["zeta"] = 0L },
                ["theta1"] = 1L, ["theta2"] = 1L, ["kappa"] = 100L, ["lambda"] = 0L, ["rho"] = new Num("0.5"), ["bMax"] = 1_000_000L,
            },
        };
        // escalate: a payment over 50 asks the principal (decision escalate); with no answer it is refused
        if (limit == "escalate")
            envelope["tighten"] = new L { new D { ["id"] = "big_payment", ["when"] = new D { ["field"] = "action.params.amount", ["op"] = "gt", ["value"] = 50L }, ["signal"] = "escalate" } };
        var minted = Issue.MintGrant(principal, holder.Id!, null, envelope, "pay invoices").Grant;
        // max_spend as a ROOT caveat (outside the envelope): enforced like a delegated one
        var grant = limit == "max_spend"
            ? Issue.MintRoot(principal, holder.Id!, null, new L((L)minted["caveats"]!) { new D { ["type"] = "max_spend", ["usd"] = 100L } })
            : minted;
        // provenance by default: a principal-direct bundle from a recorder the server pins (the matrix is about limits, binding, replay and configuration)
        var provKey = SuiteKey.Ed25519(EdKey.FromSeed(Enumerable.Repeat((byte)3, 32).ToArray()));
        ProvenanceRecorder Recorder() => new("adapter-acceptance", "k1", provKey);
        var pin = Recorder().Pin;
        long counter = 0;
        AcceptanceRequest Request(string verb, int signedAmount, string path, int sentAmount)
        {
            var prms = new D { ["payee"] = "acme", ["amount"] = new Num(signedAmount.ToString(CultureInfo.InvariantCulture)) };
            var node = new D { ["id"] = "n1", ["verb"] = verb, ["resource"] = "payments", ["params_digest"] = Pca.ParamsDigest(prms), ["reversibility_class"] = "irreversible" };
            var p = Issue.BuildPCActn(new ActSpec { Grant = grant, Chain = new L { grant }, Plan = Issue.CommitPlan(new[] { node }), NodeId = "n1", Params = prms, Counter = ++counter, Signer = holder, Aud = AdapterAcceptanceAudience });
            var prov = ArgProvenance.PrincipalDirect(Recorder(), verb, "payments", prms);
            var headers = new Dictionary<string, string>(PcaAdapters.PcaHeaders(Issue.Encode(p), prov)) { ["content-type"] = "application/json" };
            return new AcceptanceRequest("POST", path, headers, new D { ["payee"] = "acme", ["amount"] = new Num(sentAmount.ToString(CultureInfo.InvariantCulture)) });
        }
        AcceptanceOptions Options(bool revocation = true, bool store = true) => new()
        {
            ResolveGrant = r => r == (string)grant["id"]! ? grant : null,
            StateStore = store ? new MemoryStateStore() : null,
            IsRevoked = revocation ? (_, _) => false : null,
            ServerRiskFor = (o, _, _) =>
            {
                var a = o.Params is D od && od.GetValueOrDefault("amount") is { } av ? IntentJs.NumOf(av) : null;
                var blast = a is double ad && double.IsFinite(ad) ? Math.Min(1, ad / 100) : 1;
                return new Dictionary<string, double> { ["blastRadius"] = blast, ["semanticDistance"] = 0, ["reversibility"] = 0, ["taint"] = 0, ["confidence"] = 1, ["age"] = 0 };
            },
            ProvenanceFlow = new ArgProvenanceOptions { Mediators = new[] { pin } },
        };
        return new Fixture((verb, signedAmount, path, sentAmount) => Request(verb, signedAmount, path, sentAmount), () => Options(), _ => Options(revocation: false), _ => Options(store: false));
    }

    static D Settle(AcceptanceRequest req, AcceptanceObservation o)
    {
        var ranD = AcceptanceOperation(new D { ["method"] = req.Method, ["url"] = req.Path, ["body"] = req.Body });
        var ran = ranD == null ? null : new Operation((string)ranD["verb"]!, (string)ranD["resource"]!, ranD["params"]);
        var bound = o.Operation != null && ran != null && Pca.IsAuthorizedFor(new AuthorizeResult { Allow = true, Operation = o.Operation }, ran);
        return Outcome(o.Status, o.HandlerRan, bound);
    }

    /// <summary>Run the matrix through <paramref name="harness"/> and return the outcome per scenario; compare it with <see cref="AdapterAcceptanceExpected"/>.
    /// The harness builds the adapter once from the options (pass them through unchanged: <see cref="AcceptanceOptions.ToInput"/> makes the per-request
    /// <see cref="AuthorizeInput"/>), derives the operation with <see cref="AcceptanceOperation"/> (<c>method</c>, <c>url</c> = the path, <c>body</c>), takes the
    /// proof from the <c>PCA-Action</c> header and the bundle from <c>PCA-Provenance</c>, and every refusal must happen before the handler runs.</summary>
    public static D RunAdapterAcceptance(AcceptanceHarness harness)
    {
        var outD = new D();
        void Once(string name, Fixture f, AcceptanceRequest req, AcceptanceOptions o) => outD[name] = Settle(req, harness(o)(req));
        var pred = MakeFixture("predicate");
        var spend = MakeFixture("max_spend");
        var esc = MakeFixture("escalate");
        Once("over_limit_predicate", pred, pred.Request("payments.send", 400, "/payments", 400), pred.Options());
        Once("over_limit_max_spend", spend, spend.Request("payments.send", 400, "/payments", 400), spend.Options());
        Once("body_differs", pred, pred.Request("payments.send", 50, "/payments", 400), pred.Options());
        Once("other_operation", pred, pred.Request("payments.send", 50, "/refunds", 50), pred.Options());
        Once("escalate_unanswered", esc, esc.Request("payments.send", 70, "/payments", 70), esc.Options());
        Once("missing_revocation", pred, pred.Request("payments.send", 50, "/payments", 50), pred.WithoutRevocation(pred.Options()));
        Once("missing_store", pred, pred.Request("payments.send", 50, "/payments", 50), pred.WithoutStore(pred.Options()));
        var send = harness(pred.Options());
        var valid = pred.Request("payments.send", 50, "/payments", 50);
        outD["valid_first"] = Settle(valid, send(valid));
        outD["replay_second"] = Settle(valid, send(valid));
        return outD;
    }
}

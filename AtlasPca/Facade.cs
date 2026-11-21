// The facade: Agent.FromPrincipal compiles human-level inputs (permissions, limits) into the real primitives (a policy envelope, a
// risk policy, a signed root intent grant naming the harness's provenance recorder) and returns a handle that builds one
// proof-carrying action per tool call. Nothing here authorizes anything: the resource server's verifier decides, and every field
// the facade emits is covered by a signature. Same compile-down and wire as the TypeScript reference's agent(), byte for byte.
//
//   var a = Agent.FromPrincipal(new AgentOptions { Principal = principal, Goal = "refund order 1",
//       Permissions = new() { ["stripe"] = new JL { "refund" } }, Limits = new() { ["refund"] = "$500/day" }, Aud = "ins_123" });
//   var r = a.Act("stripe.refund", "charge:ch_1", new() { ["amount"] = 42L, ["currency"] = "usd" });
//   foreach (var (k, v) in r.Headers) request.Headers.Add(k, v);   // PCA-Action (+ PCA-Provenance)
//
// Keep the provenance recorder in the harness, out of the model's reach (never expose AgentHandle.Provenance as a tool).
using System.Globalization;
using System.Text.RegularExpressions;
using JD = System.Collections.Generic.Dictionary<string, object?>;
using JL = System.Collections.Generic.List<object?>;

namespace AtlasPca;

/// <summary>One action definition: the verb <c>connector.action</c>, its reversibility class (reversible &lt; rate_limited &lt;
/// irreversible), a blast-radius preset in [0, 1], and for a money-moving action the params field that carries the amount.</summary>
public sealed record CatalogAction(string Connector, string Action, string Verb, string Reversibility, double BlastRadius, string? AmountField,
    string Description, IReadOnlyList<string> Aliases, IReadOnlyList<string> Traits, string? Resource = null);

/// <summary>Resolves verbs (and aliases) to action definitions; a later definition of a verb replaces an earlier one.</summary>
public sealed partial class Catalog
{
    readonly Dictionary<string, CatalogAction> _byVerb = new();

    public Catalog(IEnumerable<CatalogAction> actions) { foreach (var a in actions) _byVerb[a.Verb] = a; }

    /// <summary>The catalog of the built-in actions.</summary>
    public static Catalog Default => new(Builtin);

    public CatalogAction? Get(string verb) => _byVerb.GetValueOrDefault(verb);

    /// <summary><c>connector.action</c>, else the ONE action of the connector that has <paramref name="action"/> as an alias (never a guess).</summary>
    public CatalogAction? Resolve(string connector, string action)
    {
        if (_byVerb.TryGetValue(connector + "." + action, out var a)) return a;
        var hits = _byVerb.Values.Where(x => x.Connector == connector && x.Aliases.Contains(action)).ToList();
        return hits.Count == 1 ? hits[0] : null;
    }

    /// <summary>The definition of a verb; an uncatalogued verb counts as irreversible with blast radius 0.8.</summary>
    public CatalogAction SpecFor(string verb)
    {
        if (Get(verb) is { } s) return s;
        var dot = verb.IndexOf('.');
        if (dot > 0 && Resolve(verb[..dot], verb[(dot + 1)..]) is { } via) return via;
        var parts = verb.Split('.');
        var action = string.Join(".", parts.Skip(1));
        return new CatalogAction(parts[0], action.Length > 0 ? action : verb, verb, "irreversible", 0.8, null, "(uncatalogued) " + verb,
            Array.Empty<string>(), Array.Empty<string>());
    }
}

/// <summary>A parsed limit: <c>Unit</c> "usd" (<c>$N</c>) or "count" (<c>N</c>), and the window it names in ms (null: none).</summary>
public sealed record ParsedLimit(double Amount, string Unit, long? PeriodMs)
{
    /// <summary>The reference's ParsedLimit object: <c>{amount, unit, periodMs?}</c>.</summary>
    public JD ToJson()
    {
        var m = new JD { ["amount"] = Facade.JsNumber(Amount), ["unit"] = Unit };
        if (PeriodMs is long p) m["periodMs"] = p;
        return m;
    }
}

/// <summary>What <see cref="Facade.CompilePolicy"/> compiles. <c>Permissions</c> maps a connector to its granted actions (a JSON object).
/// <c>Limits</c> are keyed by full verb (<c>stripe.refund</c>), bare action (<c>refund</c>) or alias; the verb wins.</summary>
public sealed class PolicyOptions
{
    public JD Permissions = new();
    public IReadOnlyDictionary<string, string>? Limits;
    public Catalog? Catalog;
    /// <summary>"auto" (or null), "dollars" or "risk".</summary>
    public string? BudgetModel;
    /// <summary>Members that override the derived risk policy (weights merge member by member).</summary>
    public JD? RiskPolicy;
    /// <summary>Epoch ms of the limit windows; null: the wall clock.</summary>
    public long? Now;
}

/// <summary>The policy envelope material <see cref="Facade.CompilePolicy"/> derives.</summary>
public sealed class CompiledPolicy
{
    public JL Predicates { get; init; } = new();
    public JL Caveats { get; init; } = new();
    public JD RiskPolicy { get; init; } = new();
    public IReadOnlyList<CatalogAction> Actions { get; init; } = Array.Empty<CatalogAction>();
    /// <summary>"dollars" or "risk".</summary>
    public string BudgetModel { get; init; } = "risk";
    /// <summary>Per verb, in first-seen order, the limits that matched a granted action.</summary>
    public IReadOnlyList<KeyValuePair<string, ParsedLimit>> Limits { get; init; } = Array.Empty<KeyValuePair<string, ParsedLimit>>();
    public IReadOnlyDictionary<string, string> InputLimits { get; init; } = new Dictionary<string, string>();
    /// <summary>Limits this offline compiler only approximates (a <c>$N/period</c> is a per-call ceiling plus a one-period lifetime).</summary>
    public IReadOnlyList<string> Approximations { get; init; } = Array.Empty<string>();

    /// <summary>The reference's CompiledPolicy object without its action specs and raw inputs:
    /// <c>{predicates, caveats, riskPolicy, budgetModel, limits, approximations}</c>.</summary>
    public JD ToJson()
    {
        var lim = new JD();
        foreach (var (v, l) in Limits) lim[v] = l.ToJson();
        return new JD
        {
            ["predicates"] = Predicates, ["caveats"] = Caveats, ["riskPolicy"] = RiskPolicy, ["budgetModel"] = BudgetModel, ["limits"] = lim,
            ["approximations"] = Approximations.Select(a => (object?)a).ToList(),
        };
    }
}

public static class Facade
{
    /// <summary>The longest limit string accepted, in UTF-16 code units.</summary>
    public const int MaxLimitLength = 64;

    static Dictionary<string, long> Periods => new()
    {
        ["s"] = 1000, ["sec"] = 1000, ["second"] = 1000, ["seconds"] = 1000,
        ["m"] = 60_000, ["min"] = 60_000, ["minute"] = 60_000, ["minutes"] = 60_000,
        ["h"] = 3_600_000, ["hr"] = 3_600_000, ["hour"] = 3_600_000, ["hours"] = 3_600_000,
        ["d"] = 86_400_000, ["day"] = 86_400_000, ["days"] = 86_400_000,
        ["w"] = 604_800_000, ["week"] = 604_800_000, ["weeks"] = 604_800_000,
        ["mo"] = 2_592_000_000, ["month"] = 2_592_000_000, ["months"] = 2_592_000_000,
    };

    // JavaScript's \s and String.prototype.trim set
    const string JsWs = "\t\n\v\f\r \u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000\ufeff"; // ECMAScript \s
    static Regex LimitRe => Rx.Get(@"\A(\$)?[" + JsWs + @"]*([0-9]+(?:\.[0-9]+)?)[" + JsWs + @"]*(?:/[" + JsWs + @"]*([a-zA-Z]+))?\z", RegexOptions.CultureInvariant);

    static string JsTrim(string s) => s.Trim(Actions.JsSpace);

    /// <summary>A JSON number for a binary64 value: a long when it is a safe integer, else its JavaScript spelling.</summary>
    internal static object JsNumber(double d) =>
        d == Math.Floor(d) && Math.Abs(d) <= Pca.MaxSafeInt ? (object)(long)d : new Num(JsCanon.NumberString(d));

    /// <summary>Parse <c>"$500/day"</c>, <c>"$500"</c>, <c>"10/hour"</c> or <c>"10"</c> (periods s, m, h, d, w, mo and their long forms).</summary>
    public static ParsedLimit ParseLimit(string s)
    {
        var t = JsTrim(s ?? "");
        if (t.Length == 0) throw new ArgumentException("parseLimit: empty limit");
        if (s!.Length > MaxLimitLength) throw new ArgumentException($"parseLimit: limit is longer than {MaxLimitLength} characters");
        var m = LimitRe.Match(t);
        if (!m.Success) throw new ArgumentException($"parseLimit: cannot parse limit '{s}'");
        var amount = double.Parse(m.Groups[2].Value, NumberStyles.AllowDecimalPoint, CultureInfo.InvariantCulture);
        if (!double.IsFinite(amount)) throw new ArgumentException($"parseLimit: bad amount in '{s}'");
        long? period = null;
        if (m.Groups[3].Success)
        {
            if (!Periods.TryGetValue(m.Groups[3].Value.ToLowerInvariant(), out var p)) throw new ArgumentException($"parseLimit: unknown period '{m.Groups[3].Value}' in '{s}'");
            period = p;
        }
        return new ParsedLimit(amount, m.Groups[1].Success ? "usd" : "count", period);
    }

    static int Severity(string cls) => Array.IndexOf(new[] { "reversible", "rate_limited", "irreversible" }, cls);

    /// <summary>Compile permissions and limits into predicates, caveats and a risk policy. Pure: no keys, no signing. A <c>$N</c> limit becomes a
    /// per-call ceiling on the action's amount field (refused on a verb with none); the strictest reversibility class becomes a
    /// <c>reversibility_max</c> caveat, the shortest limit period the grant lifetime, and every <c>N/period</c> limit one rate caveat.</summary>
    public static CompiledPolicy CompilePolicy(PolicyOptions o)
    {
        var catalog = o.Catalog ?? Catalog.Default;
        var now = o.Now ?? DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        var perms = o.Permissions ?? throw new ArgumentException("compilePolicy: permissions must be an object");
        var actions = new List<CatalogAction>();
        foreach (var connector in IntentJs.JsKeys(perms.Keys))
        {
            if (perms[connector] is not JL names) throw new ArgumentException($"compilePolicy: permissions.{connector} must be an array");
            foreach (var a in names) actions.Add(catalog.SpecFor(connector + "." + IntentRevocation.JsText(a, true)));
        }
        if (actions.Count == 0) throw new ArgumentException("compilePolicy: no permissions granted");

        var raw = o.Limits ?? new Dictionary<string, string>();
        var limits = new List<KeyValuePair<string, ParsedLimit>>();
        ParsedLimit? LimitFor(CatalogAction s)
        {
            string? text = null;
            foreach (var k in new[] { s.Verb, s.Action }.Concat(s.Aliases))
                if (text == null && raw.TryGetValue(k, out var v)) text = v;
            if (text == null) return null;
            var pl = ParseLimit(text);
            var at = limits.FindIndex(x => x.Key == s.Verb);
            if (at < 0) limits.Add(new(s.Verb, pl)); else limits[at] = new(s.Verb, pl);
            return pl;
        }

        var predicates = new JL();
        foreach (var s in actions)
        {
            var lim = LimitFor(s);
            var pred = new JD { ["verb"] = s.Verb, ["resource"] = s.Resource ?? "*" };
            if (lim is { Unit: "usd" })
            {
                if (s.AmountField == null)
                    throw new ArgumentException($"compilePolicy: '$' limit on '{s.Verb}' but the catalog gives that verb no amount field, so the limit could not be enforced");
                var f = "action.params." + s.AmountField;
                pred["where"] = new JL { new JD { ["field"] = f, ["op"] = "lte", ["value"] = JsNumber(lim.Amount) }, new JD { ["field"] = f, ["op"] = "gte", ["value"] = 0L } };
            }
            predicates.Add(pred);
        }

        var strictest = "reversible";
        foreach (var s in actions) if (Severity(s.Reversibility) > Severity(strictest)) strictest = s.Reversibility;
        var irreversible = actions.Any(s => s.Reversibility == "irreversible");
        var caveats = new JL { new JD { ["type"] = "reversibility_max", ["class"] = strictest } };
        var periods = limits.Where(x => x.Value.PeriodMs != null).Select(x => x.Value.PeriodMs!.Value).ToList();
        if (periods.Count > 0) caveats.Add(new JD { ["type"] = "expires", ["at"] = now + periods.Min() });
        foreach (var (_, l) in limits)
            if (l.Unit == "count" && l.PeriodMs is long p)
                caveats.Add(new JD { ["type"] = "rate", ["max"] = JsNumber(l.Amount), ["per_secs"] = Math.Max(1L, (long)Math.Floor(p / 1000.0 + 0.5)) });

        var dollars = limits.Where(x => x.Value.Unit == "usd").Select(x => x.Value.Amount).ToList();
        var model = o.BudgetModel is "dollars" or "risk" ? o.BudgetModel! : dollars.Count > 0 ? "dollars" : "risk";
        var def = Issue.DefaultRiskPolicy();
        var rp = def;
        if (model == "dollars" && dollars.Count > 0)
        {
            var kappa = dollars.Max();
            var bMax = 0.0;
            foreach (var d in dollars) bMax += d; // in order, as the reference sums
            rp = new JD
            {
                ["weights"] = new JD { ["alpha"] = 0L, ["beta"] = 0L, ["gamma"] = 1L, ["delta"] = 0L, ["epsilon"] = 0L, ["zeta"] = 0L },
                // within-cap actions auto-approve only when nothing granted is irreversible; otherwise the default co-sign tiers stay
                ["theta1"] = irreversible ? def["theta1"] : 1L, ["theta2"] = irreversible ? def["theta2"] : 1L,
                ["kappa"] = JsNumber(kappa > 0 ? kappa : 1), ["lambda"] = 0L, ["rho"] = def["rho"], ["bMax"] = JsNumber(bMax > 0 ? bMax : 1),
            };
        }
        if (o.RiskPolicy != null)
        {
            var w = new JD((JD)rp["weights"]!);
            if (o.RiskPolicy.GetValueOrDefault("weights") is JD ow) foreach (var (k, v) in ow) w[k] = v;
            rp = new JD(rp);
            foreach (var (k, v) in o.RiskPolicy) rp[k] = v;
            rp["weights"] = w;
        }
        var rpN = Issue.NormJ(rp);
        if (Pca.ValidateRiskPolicy(rpN) is { } bad) throw new ArgumentException("compilePolicy: derived risk policy invalid: " + bad);
        var approx = limits.Where(x => x.Value.Unit == "usd" && x.Value.PeriodMs != null)
            .Select(x => $"{x.Key}: ${JsCanon.NumberString(x.Value.Amount)}/period is a per-call ceiling plus a one-period grant lifetime, not a renewing window cap").ToList();
        return new CompiledPolicy
        {
            Predicates = Issue.NormL(predicates), Caveats = Issue.NormL(caveats), RiskPolicy = rpN, Actions = actions, BudgetModel = model, Limits = limits,
            InputLimits = new Dictionary<string, string>(raw), Approximations = approx,
        };
    }
}

/// <summary>The provenance recorder options of <see cref="AgentOptions"/> (mediator "agent-harness", kid "k1", a fresh key and session by default).</summary>
public sealed class ProvenanceOptions
{
    public string Mediator = "agent-harness";
    public string Kid = "k1";
    /// <summary>The mediator key; generated when null. Keep it out of the model's reach: the grant names it.</summary>
    public SuiteKey? Signer;
    /// <summary>b64u of 32 bytes; random when null.</summary>
    public string? Session;
    public Func<long>? Now;
}

/// <summary>What <see cref="Agent.FromPrincipal"/> builds an agent from. Principal, Goal and Permissions are required.</summary>
public sealed class AgentOptions
{
    /// <summary>The human's key: signs and roots the grant.</summary>
    public SuiteKey Principal = null!;
    /// <summary>The plaintext goal; only its salted commitment goes in the grant.</summary>
    public string Goal = "";
    /// <summary>Connector to granted actions, e.g. <c>{"stripe": ["refund"]}</c>.</summary>
    public JD Permissions = new();
    public IReadOnlyDictionary<string, string>? Limits;
    /// <summary>The agent key that signs actions (generated Ed25519 when null). Under a post-quantum or hybrid suite its PQ key is committed in
    /// the grant as <c>holder_pq</c>.</summary>
    public SuiteKey? Holder;
    public JD? AgentBinding;
    public JD? RiskPolicy;
    public string? BudgetModel;
    public Catalog? Catalog;
    /// <summary>The default audience of <see cref="AgentHandle.Act"/>.</summary>
    public string? Aud;
    /// <summary>Epoch ms of minting and of the limit windows; null: the wall clock.</summary>
    public long? Now;
    public ProvenanceOptions? Provenance;
    /// <summary>base64url salt of the goal commitment; null draws one (set it only to reproduce a grant).</summary>
    public string? GoalSalt;
}

/// <summary>Per-call options of <see cref="AgentHandle.Act"/>.</summary>
public sealed class ActOptions
{
    /// <summary>The replay counter; null: one more than the highest so far.</summary>
    public long? Counter;
    public string? Aud;
    /// <summary>Issued-at in epoch ms; null: the wall clock.</summary>
    public long? Now;
    public long? TtlMs;
    /// <summary>Signed when given (no nonce by default).</summary>
    public string? Nonce;
    /// <summary>The agent's own uncertainty in [0, 1]: it can only raise the server's risk.</summary>
    public double? Caution;
    /// <summary>Overrides the claimed risk (else from the amount or the blast radius).</summary>
    public double? Risk;
}

/// <summary>A local, NON-authoritative check of the grant's own predicates and caveats; <c>T</c> is the risk tier the policy would assign
/// (1 automatic, 2 guardian co-sign, 3 human).</summary>
public sealed record DryRunResult(bool Allowed, string? Reason = null, int? T = null);

/// <summary>One built action: the PCActn, its encoded JSON, the headers to send (<c>PCA-Action</c>, and <c>PCA-Provenance</c> when the bundle
/// fits a header; else send <see cref="Provenance"/> as the body member <c>pca_provenance</c>), the local dry run and the provenance bundle.</summary>
public sealed record ActResult(JD PCActn, string Encoded, IReadOnlyDictionary<string, string> Headers, DryRunResult DryRun, JD Provenance);

/// <summary>What <see cref="Agent.FromPrincipal"/> returns: the signed grant and chain, the compiled policy, the holder key, the starting trust
/// budget, and <see cref="Act"/> / <see cref="DryRun"/> / <see cref="SubAgent"/>. <see cref="Provenance"/> is the session's recorder: record
/// the principal's message and every tool, retrieval or web result entering the model's context; <see cref="Act"/> appends the action.
/// Safe for concurrent use.</summary>
public sealed class AgentHandle
{
    public JD Grant { get; }
    public IReadOnlyList<JD> Chain { get; }
    public string GoalSalt { get; }
    public string GoalCommit { get; }
    public CompiledPolicy Policy { get; }
    public SuiteKey Holder { get; }
    public string PrincipalPublic { get; }
    /// <summary>The starting trust budget (B = bMax); the server meters it.</summary>
    public TrustBudget Budget { get; }
    /// <summary>The most this agent can do between human co-signs.</summary>
    public double AutonomyBound { get; }
    public ProvenanceRecorder Provenance { get; }

    readonly Catalog _catalog;
    readonly string? _aud;
    readonly long _startNow;
    readonly object _lock = new();
    long _counter;

    internal AgentHandle(JD grant, IReadOnlyList<JD> chain, string goalSalt, string goalCommit, CompiledPolicy policy, SuiteKey holder, string principal,
        Catalog catalog, string? aud, long startNow, ProvenanceRecorder recorder)
    {
        Grant = grant; Chain = chain; GoalSalt = goalSalt; GoalCommit = goalCommit; Policy = policy; Holder = holder; PrincipalPublic = principal;
        _catalog = catalog; _aud = aud; _startNow = startNow; Provenance = recorder;
        var bMax = IntentJs.NumOf(policy.RiskPolicy["bMax"])!.Value;
        var kappa = IntentJs.NumOf(policy.RiskPolicy["kappa"])!.Value;
        Budget = new TrustBudget(bMax, startNow, startNow);
        AutonomyBound = Risk.SafetyBound(bMax, kappa) * kappa;
    }

    internal static AgentHandle Create(AgentOptions o)
    {
        if (o.Principal == null) throw new ArgumentException("agent: principal required");
        if (o.Principal.Ed == null) throw new ArgumentException("agent: the principal needs an Ed25519 identity");
        var catalog = o.Catalog ?? Catalog.Default;
        var now = o.Now ?? DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        var holder = o.Holder ?? SuiteKey.Ed25519(EdKey.Generate());
        if (holder.Ed == null) throw new ArgumentException("agent: the holder needs an Ed25519 identity");
        var policy = Facade.CompilePolicy(new PolicyOptions
        {
            Permissions = o.Permissions, Limits = o.Limits, Catalog = catalog, BudgetModel = o.BudgetModel, RiskPolicy = o.RiskPolicy, Now = now,
        });
        var po = o.Provenance ?? new ProvenanceOptions();
        var rec = new ProvenanceRecorder(po.Mediator, po.Kid, po.Signer, po.Session, po.Now);
        var env = new JD
        {
            ["predicates"] = policy.Predicates, ["caveats"] = policy.Caveats, ["agent_binding"] = o.AgentBinding ?? new JD(), ["risk_policy"] = policy.RiskPolicy,
            // the principal designates the harness's mediator key: a verifier trusts its labels with no extra configuration
            ["provenance"] = new JD { ["mediators"] = new JL { rec.Pin.ToJson() } },
        };
        var g = Issue.MintGrant(o.Principal, holder.Ed.Id, holder.PqPk, env, o.Goal, o.GoalSalt);
        return new AgentHandle(g.Grant, new[] { g.Grant }, g.GoalSalt, g.GoalCommit, policy, holder, o.Principal.Ed.Id, catalog, o.Aud, now, rec);
    }

    RiskPolicy RiskOf() => Risk.PolicyOf(Policy.RiskPolicy)!;

    /// <summary>The override clamped to [0, 1], else amount / kappa in the dollars model, else the catalog's blast radius.</summary>
    double RiskFor(CatalogAction spec, JD? prms, double? overrideR)
    {
        static double Clamp(double x) => Math.Max(0, Math.Min(1, x));
        if (overrideR is double r) return Clamp(r);
        if (Policy.BudgetModel == "dollars" && spec.AmountField is { } f)
        {
            var amt = Actions.JsNumber(prms?.GetValueOrDefault(f), prms != null && prms.ContainsKey(f));
            if (double.IsFinite(amt) && RiskOf().Kappa > 0) return Clamp(amt / RiskOf().Kappa);
        }
        return Clamp(spec.BlastRadius);
    }

    /// <summary>Check the grant's own predicates and caveats for an action, locally and without authority (the server decides).</summary>
    public DryRunResult DryRun(string verb, string resource, JD? prms = null, long? now = null)
    {
        var spec = _catalog.SpecFor(verb);
        var at = now ?? DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        var p = prms == null ? new JD() : Issue.NormJ(prms);
        var ctx = new JD { ["action"] = new JD { ["verb"] = verb, ["resource"] = resource, ["params"] = p, ["reversibility_class"] = spec.Reversibility } };
        if (Pca.EnvelopePredicates(Policy.Predicates, ctx) is { } why) return new DryRunResult(false, why);
        var cav = Caveats.EvaluateCaveats(Policy.Caveats, new JD
        {
            ["now"] = at, ["blast_radius"] = Facade.JsNumber(spec.BlastRadius), ["reversibility_class"] = spec.Reversibility, ["delegation_depth"] = (long)(Chain.Count - 1),
            // the local handle has no admitted-action history (the server meters it), so a rate caveat can hold
            ["recent_action_times"] = new JL(),
        });
        if (!cav.Ok) return new DryRunResult(false, "caveat(s) failed: " + string.Join(", ", cav.Failed));
        return new DryRunResult(true, null, Risk.Admit(RiskFor(spec, p, null), Budget, RiskOf()).T);
    }

    /// <summary>Build the proof-carrying action for one tool call (it does NOT authorize): a one-node plan (node <c>n0</c>, the catalog's
    /// reversibility class, the params digest) signed by the holder with a risk claim, and the provenance bundle of the action.</summary>
    public ActResult Act(string verb, string resource, JD? prms = null, ActOptions? o = null)
    {
        o ??= new ActOptions();
        var aud = o.Aud ?? _aud;
        if (string.IsNullOrEmpty(aud)) throw new ArgumentException("act: aud (resource-server / instance id) is required (pass ActOptions.Aud or AgentOptions.Aud)");
        var spec = _catalog.SpecFor(verb);
        // the node commits the SAME params digest the action carries, else plan inclusion fails
        var node = new JD { ["id"] = "n0", ["verb"] = verb, ["resource"] = resource, ["reversibility_class"] = spec.Reversibility, ["params_digest"] = Pca.ParamsDigest(prms) };
        var p = prms == null ? null : Issue.NormJ(prms);
        var r = Facade.JsNumber(RiskFor(spec, p, o.Risk));
        long counter;
        lock (_lock)
        {
            if (o.Counter is long c) { counter = c; _counter = Math.Max(_counter, c); }
            else counter = ++_counter;
        }
        var pcactn = Issue.BuildPCActn(new ActSpec
        {
            Grant = Grant, Chain = Chain.Select(x => (object?)x).ToList(), Plan = Issue.CommitPlan(new[] { node }), NodeId = "n0", Params = p, Counter = counter,
            Signer = Holder, Aud = aud, Iat = o.Now, TtlMs = o.TtlMs, Nonce = o.Nonce, Caution = o.Caution is double cu ? Facade.JsNumber(cu) : null,
            RiskClaim = new JD { ["r"] = r, ["inputs"] = new JD { ["blastRadius"] = r } },
        });
        var bundle = Provenance.ForAction(verb, resource, p ?? new JD());
        return new ActResult(pcactn, Issue.Encode(pcactn), Issue.Headers(pcactn, provenance: bundle), DryRun(verb, resource, prms, o.Now), bundle);
    }

    /// <summary>An agent one hop down: the hop (signed by this agent) rebinds the chain to <paramref name="holder"/> (a fresh key when null) with
    /// the added caveats, sharing the policy, catalog and provenance recorder. Under a post-quantum suite the sub-agent gets its own PQ key
    /// (generated when no holder is given), committed in the hop; it never signs with this agent's PQ key.</summary>
    public AgentHandle SubAgent(SuiteKey? holder = null, JL? addedCaveats = null)
    {
        var sub = holder ?? (Holder.Alg == "ed25519" ? SuiteKey.Ed25519(EdKey.Generate()) : SuiteKey.Create(Holder.Alg, EdKey.Generate(), PqKey.Generate(Holder.Pq!.Prim)));
        if (sub.Ed == null) throw new ArgumentException("subAgent: the sub-agent needs an Ed25519 identity");
        if (sub.Alg != Holder.Alg) throw new ArgumentException($"subAgent: the sub-agent's key does not match the suite {Holder.Alg}");
        var hop = Issue.Delegate(Chain[^1], sub.Ed.Id, addedCaveats ?? new JL(), Holder, sub.PqPk);
        return new AgentHandle(Grant, Chain.Append(hop).ToList(), GoalSalt, GoalCommit, Policy, sub, PrincipalPublic, _catalog, _aud, _startNow, Provenance);
    }

    /// <summary>The grant's canonical JSON (for transport or inspection).</summary>
    public string EncodeGrant() => Pca.Canonicalize(Grant);
}

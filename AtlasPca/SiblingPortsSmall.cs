// Single-export ports of the reference core (each is the TypeScript function of the same name): the revocation signing message and the revocation checker hook,
// the catalog-derived risk inputs, the public discovery-document builder, the PQ binding pin, the objective-risk commitment reader, the intent revocation helpers, a
// defensive connection copy, the AP2 key generator and the few public constants. Where the SDK already holds the logic (RevocationFreshness.Gate, Catalog, StoredConnection.Copy)
// these are the reference-named entry points over it.
using System.Globalization;
using JD = System.Collections.Generic.Dictionary<string, object?>;
using JL = System.Collections.Generic.List<object?>;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca;

public static partial class PcaConstants
{
    /// <summary>The legal required thresholds: 1 agent only, 2 plus the guardian, 3 plus the principal.</summary>
    public static IReadOnlyList<int> ValidThresholds { get; } = new[] { 1, 2, 3 };

    /// <summary>The version of the signed policy-template and overlay documents.</summary>
    public const int TemplateVersion = 1;

    /// <summary>The <c>type</c> of the carried budget-allocation caveat.</summary>
    public const string BudgetAllocCaveat = "budget_alloc";
}

public static partial class PcaHelpers
{
    /// <summary>The carried-allocation caveat <c>{type: "budget_alloc", limit}</c> of a delegation hop. The limit must be finite (a non-finite number cannot be canonicalized or signed).</summary>
    public static JD BudgetAllocCaveat(double limit)
    {
        if (!double.IsFinite(limit)) throw new ArgumentException("budgetAllocCaveat: limit must be finite");
        return new JD { ["type"] = PcaConstants.BudgetAllocCaveat, ["limit"] = IntentJs.Normalize(limit) };
    }
}

public static partial class IntentRevocation
{
    /// <summary>The prefix of every intent-layer revocation id.</summary>
    public const string IntentRevocationPrefix = "pca-intent:";

    /// <summary>The <c>grant_ref</c> of a profile's revocation epoch.</summary>
    public static string ProfileRevocationScope(string profileId) => "pca-intent-profile:" + profileId;

    /// <summary>The default maximum age of revocation state in seconds by tier: 60 for payment tiers, 300 otherwise.</summary>
    public static IReadOnlyDictionary<string, int> DefaultRevocationMaxAgeS { get; } = new Dictionary<string, int> { ["payment"] = 60, ["default"] = 300 };

    /// <summary>The last instant at which a verifier that accepts revocation state at most <paramref name="maxAgeMs"/> old can still miss a revocation made at <paramref name="tRevoked"/>:
    /// <c>tRevoked + maxAgeMs + skewMs</c>. Hosts use it to report the exposure bound.</summary>
    public static double RevocationExposureEnd(double tRevoked, double maxAgeMs, double skewMs = 60_000) => tRevoked + maxAgeMs + skewMs;
}

public static partial class Pca
{
    /// <summary>The domain-separated bytes a principal signs to revoke a capability under their own grant: <c>"atlas-pca/revoke/v1\0" || canonical({grant_ref, revoked_cap_id})</c>.</summary>
    public static byte[] RevokeMessage(string grantRef, string revokedCapId) =>
        Cat(System.Text.Encoding.UTF8.GetBytes("atlas-pca/revoke/v1\0"), Canon(new JD { ["grant_ref"] = grantRef, ["revoked_cap_id"] = revokedCapId }));
}

/// <summary>What <see cref="RevocationChecker.Create"/> reads. Every callback receives the verification context (PCActn, grant, clock).</summary>
public sealed class RevocationCheckerOptions
{
    /// <summary>The verifier-side staleness policy; the default value turns it off.</summary>
    public RevocationStalenessPolicy Staleness { get; set; } = new();
    /// <summary>The trusted current revocation root. With <see cref="Epoch"/> it is optional (the signed epoch's root is used and must equal this one when both are given).</summary>
    public Func<PcaCore.CoreContext, string?>? Root { get; set; }
    /// <summary>The guardian-signed revocation epoch (parsed JSON). When set the checker REQUIRES it to verify and checks non-membership against its root.</summary>
    public Func<PcaCore.CoreContext, JD?>? Epoch { get; set; }
    public string? GuardianPublic { get; set; }
    /// <summary>PQ-key pins for the epoch guardian (required for a pure-PQ or hybrid epoch).</summary>
    public IReadOnlyDictionary<string, string>? PqPins { get; set; }
    /// <summary>The newest epoch number already accepted for this grant (the verifier-side monotonic pin).</summary>
    public Func<PcaCore.CoreContext, double?>? LastAcceptedEpoch { get; set; }
    /// <summary>Called with an epoch that passed every check (persist it as the new pin).</summary>
    public Action<JD, PcaCore.CoreContext>? OnEpochAccepted { get; set; }
    /// <summary>The non-membership proof (<c>{size, lo?, hi?}</c>) for a capability id; null denies that id. Required.</summary>
    public Func<string, PcaCore.CoreContext, JD?>? ProofFor { get; set; }
    /// <summary>The capability ids to check; default every <c>id</c> in the PCActn's <c>cap_chain</c> (a revoked ancestor kills its descendants).</summary>
    public Func<PcaCore.CoreContext, IReadOnlyList<string>>? Ids { get; set; }
    /// <summary>With a staleness policy and no signed epoch: when the bare root was issued by your trusted source (epoch ms); unknown is denied.</summary>
    public Func<PcaCore.CoreContext, double?>? RootIssuedAt { get; set; }
    /// <summary>Your authoritative reversibility class for the action; the PCActn's signed class can only make it stricter.</summary>
    public Func<PcaCore.CoreContext, string?>? ReversibilityClass { get; set; }
}

/// <summary>The reference <c>createRevocationChecker</c>: the <see cref="PcaCore.Hooks.Revocation"/> hook backed by non-membership proofs.</summary>
public static class RevocationChecker
{
    /// <summary>Build the hook. The configuration is read once here (later edits to <paramref name="o"/> change nothing). Throws <see cref="ArgumentException"/> on an invalid staleness
    /// policy or a missing <see cref="RevocationCheckerOptions.ProofFor"/>. The hook fails closed: no root, no proof, a revoked id (which has no valid proof) and any state check
    /// error all reject.</summary>
    public static PcaCore.Hook Create(RevocationCheckerOptions o)
    {
        var policy = o.Staleness;
        policy.Validate();
        var proofFor = o.ProofFor ?? throw new ArgumentException("createRevocationChecker: proofFor is required");
        var root = o.Root; var epoch = o.Epoch; var guardian = o.GuardianPublic;
        var pins = o.PqPins == null ? null : new Dictionary<string, string>(o.PqPins);
        var last = o.LastAcceptedEpoch; var accepted = o.OnEpochAccepted; var ids = o.Ids; var issuedAt = o.RootIssuedAt; var klass = o.ReversibilityClass;
        return ctx =>
        {
            var p = ctx.Pcactn;
            var g = new RevocationGateInput
            {
                Policy = policy, GuardianPublic = guardian, Pins = pins, Now = ctx.NowEpoch,
                ServerClass = klass?.Invoke(ctx), SignedClass = IntentJs.Get(IntentJs.Get(p, "action"), "reversibility_class"),
                GrantRef = IntentJs.Get(p, "grant_ref") as string ?? "", Root = root?.Invoke(ctx), RootIssuedAt = issuedAt?.Invoke(ctx),
                ProofFor = id => proofFor(id, ctx),
            };
            if (IntentJs.NumOf(IntentJs.Get(IntentJs.Get(p, "freshness"), "epoch")) is double fe) g.PcactnEpoch = fe;
            JD? ep = null;
            if (epoch != null)
            {
                ep = epoch(ctx);
                g.EpochSource = true; g.Epoch = ep; g.LastAcceptedEpoch = last?.Invoke(ctx);
            }
            if (ids != null) g.Ids = ids(ctx);
            else
            {
                var chain = IntentJs.Get(p, "cap_chain") as JL ?? new JL();
                var list = new List<string>();
                foreach (var c in chain)
                {
                    if (IntentJs.Get(c, "id") is not string id) return PcaCore.HookResult.Of(false, "cap_chain entry without an id (fail closed)");
                    list.Add(id);
                }
                g.Ids = list;
            }
            var r = RevocationFreshness.Gate(g);
            if (r.Ok && ep != null) accepted?.Invoke(ep, ctx);
            return PcaCore.HookResult.Of(r.Ok, r.Reason);
        };
    }
}

public sealed partial class Catalog
{
    /// <summary>The reversibility score per class (1 is fully reversible), the scale the hosted adjudicator uses.</summary>
    public static IReadOnlyDictionary<string, double> ReversibilityScore { get; } =
        new Dictionary<string, double> { ["reversible"] = 1, ["rate_limited"] = 0.4, ["costly"] = 0.4, ["irreversible"] = 0 };

    static double Unit(double x) => Math.Min(1, Math.Max(0, x));

    /// <summary>The risk inputs a server can vouch for from its own data (the reference <c>catalogRisk</c>): the catalog's reversibility score and blast radius for <paramref name="verb"/>,
    /// confidence 1, and for a money-moving verb the blast radius <c>amount / kappa</c> from the operation's verified amount and the grant's signed risk policy. An unknown verb returns
    /// <c>{}</c> (every input is then priced at the worst case). A money verb whose amount is missing or not a finite number &gt;= 0, or whose grant has no positive kappa, gets blast radius 1.
    /// <paramref name="taint"/> is the server-observed taint in [0, 1]; absent or non-finite, the key is omitted. Nothing the agent claims is read.</summary>
    public static JD CatalogRisk(string verb, JD? parameters, object? grant, Catalog? catalog = null, double? taint = null)
    {
        var spec = (catalog ?? Default).Get(verb);
        var outp = new JD();
        if (spec == null) return outp;
        var reversibility = ReversibilityScore.TryGetValue(spec.Reversibility, out var rs) ? rs : 0;
        var blast = Unit(spec.BlastRadius);
        if (spec.AmountField != null)
        {
            double? amount = parameters != null && parameters.TryGetValue(spec.AmountField, out var av) ? IntentJs.NumOf(av) : null;
            double? kappa = IntentJs.NumOf(IntentJs.Get(Pca.ReadEnvelope(grant)?.GetValueOrDefault("risk_policy"), "kappa"));
            blast = amount is double a && double.IsFinite(a) && a >= 0 && kappa is double k && double.IsFinite(k) && k > 0 ? Unit(a / k) : 1;
        }
        outp["reversibility"] = IntentJs.Normalize(reversibility);
        outp["blastRadius"] = IntentJs.Normalize(blast);
        outp["confidence"] = IntentJs.Normalize(1.0);
        if (taint is double t && double.IsFinite(t)) outp["taint"] = IntentJs.Normalize(Unit(t));
        return outp;
    }
}

/// <summary>What <see cref="PcaDiscovery.BuildDiscoveryDocument"/> reads; every member but <see cref="Audience"/> is optional.</summary>
public sealed class BuildDiscoveryOptions
{
    public string Audience { get; set; } = "";
    public IReadOnlyList<string>? SignatureSuites { get; set; }
    public IReadOnlyList<long>? PcaVersions { get; set; }
    public string? ActionHeader { get; set; }
    public IReadOnlyList<string>? RequiredChecks { get; set; }
    public JD? Endpoints { get; set; }
    public IReadOnlyList<string>? TrustedRoots { get; set; }
    public JD? Metadata { get; set; }
    /// <summary>The intent block; it is validated by <see cref="PcaDiscovery.ParseDiscoveryIntent"/> (an invalid one throws).</summary>
    public JD? Intent { get; set; }
    public IReadOnlyList<string>? ObligationsSupported { get; set; }
}

public static partial class PcaDiscovery
{
    static IReadOnlyList<string> DefaultSuites => new[] { "ed25519", "ml-dsa-65", "hybrid-ed25519-ml-dsa-65" };
    static IReadOnlyList<string> DefaultRequired => new[] { "counter_format", "replay", "revocation", "plan_root_authorized", "audience", "validity", "grant_ref_bound" };

    /// <summary>Build a well-formed discovery document (the reference <c>buildDiscoveryDocument</c>). Throws <see cref="ArgumentException"/> on an empty audience or an invalid intent block.</summary>
    public static D BuildDiscoveryDocument(BuildDiscoveryOptions o)
    {
        if (string.IsNullOrEmpty(o.Audience)) throw new ArgumentException("buildDiscoveryDocument: audience is required");
        var d = new D
        {
            ["audience"] = o.Audience,
            ["pca_versions"] = new L((o.PcaVersions ?? new long[] { 2 }).Select(v => (object?)new Num(v.ToString(CultureInfo.InvariantCulture)))),
            ["signature_suites"] = new L((o.SignatureSuites ?? DefaultSuites).Cast<object?>()),
            ["action_header"] = o.ActionHeader ?? "PCA-Action",
            ["required_checks"] = new L((o.RequiredChecks ?? DefaultRequired).Cast<object?>()),
        };
        if (o.Endpoints != null) d["endpoints"] = o.Endpoints;
        if (o.TrustedRoots != null) d["trusted_roots"] = new L(o.TrustedRoots.Cast<object?>());
        if (o.Metadata != null) d["metadata"] = o.Metadata;
        if (o.Intent != null) d["intent"] = ParseDiscoveryIntent(o.Intent);
        if (o.ObligationsSupported != null) d["obligations_supported"] = new L(o.ObligationsSupported.Cast<object?>());
        return d;
    }
}

public static partial class Signers
{
    /// <summary>The one-entry PQ pin <c>{ed: pq}</c> of a PQ binding that verifies for the audience <paramref name="aud"/>, else null (the reference <c>pqPinFor</c>). Null when the binding is
    /// not for <paramref name="aud"/> (which is required: a verifier states which audience it is), carries a malformed PQ key or a non-positive epoch, or its signature does not verify. Never throws.</summary>
    public static IReadOnlyDictionary<string, string>? PqPinFor(object? binding, string? aud)
    {
        try
        {
            if (binding is not JD b || b.GetValueOrDefault("ed") is not string ed || b.GetValueOrDefault("sig") is not string sig) return null;
            if (string.IsNullOrEmpty(aud) || b.GetValueOrDefault("aud") as string != aud) return null;
            if (IntentJs.NumOf(b.GetValueOrDefault("epoch")) is not double e || e != Math.Floor(e) || e < 1 || e > Pca.MaxSafeInt) return null;
            if (b.GetValueOrDefault("pq") is not string pq || !PqSuites.IsWellFormedPqPublicKey(pq)) return null;
            var msg = Pca.Cat(Utf8(PqBindingDomain), Utf8($"{ed}\0{pq}\0{((long)e).ToString(CultureInfo.InvariantCulture)}\0{aud}"));
            return Pca.VerifyEdInternal(ed, msg, sig) ? new Dictionary<string, string> { [ed] = pq } : null;
        }
        catch (Exception) { return null; }
    }
}

/// <summary>The result of <see cref="ObjectiveBinding.ReadObjectiveCommitment"/>: the committed <c>objective_risk</c> object, or the reason it is malformed; both null when the grant commits nothing.</summary>
public sealed record ObjectiveCommitmentRead(JD? Commitment, string? Malformed);

/// <summary>The binding of the objective-risk functional to the grant envelope (the reference objective-binding module).</summary>
public static partial class ObjectiveBinding
{
    static bool IsStr(object? v) => v is string s && s.Length > 0;

    /// <summary>Read the committed <c>objective_risk</c> off a grant's envelope (pure). Absent: <c>(null, null)</c>. Present but malformed: the reason.</summary>
    public static ObjectiveCommitmentRead ReadObjectiveCommitment(object? grant)
    {
        var env = Pca.ReadEnvelope(grant);
        if (env == null || !env.TryGetValue("objective_risk", out var rawO)) return new(null, null);
        if (rawO is not JD raw || IntentJs.NumOf(raw.GetValueOrDefault("v")) != 1) return new(null, "objective_risk: unsupported shape/version");
        if (raw.GetValueOrDefault("embedder") is not JD emb || emb.GetValueOrDefault("scheme") as string != "native" || !IsStr(emb.GetValueOrDefault("model_id")) || emb.GetValueOrDefault("config") is not JD)
            return new(null, "objective_risk.embedder must be { scheme: \"native\", model_id, config }");
        if (raw.GetValueOrDefault("goal") is not JD goal || !IsStr(goal.GetValueOrDefault("commit"))) return new(null, "objective_risk.goal must be a goal commitment");
        if (!IsStr(raw.GetValueOrDefault("registry_digest")) || !IsStr(raw.GetValueOrDefault("graph_digest"))) return new(null, "objective_risk needs registry_digest and graph_digest");
        if (raw.ContainsKey("calibration_digest") && !IsStr(raw["calibration_digest"])) return new(null, "objective_risk.calibration_digest must be a string");
        if (raw.GetValueOrDefault("authorized_kinds") is not JL kinds || !kinds.All(k => k is string)) return new(null, "objective_risk.authorized_kinds must be string[]");
        if (raw.ContainsKey("denominations") && raw["denominations"] is not JL) return new(null, "objective_risk.denominations must be an array");
        if (raw.ContainsKey("on_mismatch") && raw["on_mismatch"] is not ("deny" or "heuristic")) return new(null, "objective_risk.on_mismatch must be \"deny\" or \"heuristic\"");
        return new(raw, null);
    }
}

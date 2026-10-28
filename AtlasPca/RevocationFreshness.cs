// Revocation staleness (T9): a verifier-side cap on how old the revocation state may be, per reversibility class, the guardian-signed
// revocation epoch (Ed25519 and every suite this build verifies, under the pin rules of the ledger verifiers) and the gate that
// combines them. Mirrors the reference revocation module (checkRevocationAge, revocationMaxAgeMs, effectiveReversibility,
// checkRevocationEpoch and the staleness branch of the revocation checker). Inputs are parsed JSON values; nothing here throws on a
// hostile epoch.
using System.Globalization;
using Org.BouncyCastle.Math.EC.Rfc8032;
using D = System.Collections.Generic.Dictionary<string, object?>;

namespace AtlasPca;

/// <summary>Per-class maximum ages in ms (null keeps the default). Each is capped by <see cref="RevocationStalenessPolicy.MaxRevocationAgeMs"/>.</summary>
public sealed record StalenessWindows(double? Irreversible = null, double? Costly = null);

/// <summary>The verifier-side staleness policy. It is ON when <see cref="MaxRevocationAgeMs"/> or <see cref="Staleness"/> is set
/// (<see cref="IsOn"/>); the default value changes nothing. The class is the stricter of the server's authoritative class and the
/// PCActn's signed class; a missing or unknown class counts as irreversible.</summary>
/// <param name="MaxRevocationAgeMs">Maximum age for any action (null: five minutes).</param>
/// <param name="Staleness">Per-class windows (irreversible default two minutes; costly and rate_limited default <paramref name="MaxRevocationAgeMs"/>).</param>
/// <param name="AllowUnsignedRootForIrreversible">Accept revocation state that is not guardian-signed for an irreversible action.</param>
public sealed record RevocationStalenessPolicy(double? MaxRevocationAgeMs = null, StalenessWindows? Staleness = null, bool AllowUnsignedRootForIrreversible = false)
{
    /// <summary>True when the policy turns the staleness check on.</summary>
    public bool IsOn => MaxRevocationAgeMs != null || Staleness != null;

    /// <summary>Null when every window that is set is a finite positive number of milliseconds, else the configuration error.</summary>
    public string? Error()
    {
        static string? Chk(string name, double? v) => v is double d && !(double.IsFinite(d) && d > 0) ? name + " must be a positive number of milliseconds" : null;
        return Chk("maxRevocationAgeMs", MaxRevocationAgeMs) ?? Chk("staleness.irreversible", Staleness?.Irreversible) ?? Chk("staleness.costly", Staleness?.Costly);
    }

    /// <summary>Throws <see cref="ArgumentException"/> on an invalid policy (a configuration error, raised at construction, never at request time).</summary>
    public void Validate()
    {
        var e = Error();
        if (e != null) throw new ArgumentException(e);
    }

    /// <summary>Reads <c>{maxRevocationAgeMs?, staleness?: {irreversible?, costly?}, allowUnsignedRootForIrreversible?}</c> from parsed JSON.
    /// A window that is set but not a number becomes NaN (<see cref="Error"/> refuses it).</summary>
    public static RevocationStalenessPolicy FromJson(object? o)
    {
        var m = o as D ?? new D();
        static double? Win(D obj, string k) => obj.TryGetValue(k, out var x) ? IntentJs.NumOf(x) ?? double.NaN : null;
        StalenessWindows? w = null;
        if (m.TryGetValue("staleness", out var s))
        {
            var sm = s as D ?? new D();
            w = new StalenessWindows(Win(sm, "irreversible"), Win(sm, "rate_limited") ?? Win(sm, "costly"));
        }
        return new RevocationStalenessPolicy(Win(m, "maxRevocationAgeMs"), w, m.GetValueOrDefault("allowUnsignedRootForIrreversible") is true);
    }
}

/// <summary>The answer of <see cref="RevocationFreshness.CheckAge"/>, <see cref="RevocationFreshness.CheckEpoch"/> and <see cref="RevocationFreshness.Gate"/>.</summary>
public sealed record RevocationCheck(bool Ok, string? Reason = null, string? Root = null);

/// <summary>Options of <see cref="RevocationFreshness.CheckEpoch"/>.</summary>
public sealed class EpochCheckOptions
{
    /// <summary>The pinned Ed25519 identity (base64url) of the guardian.</summary>
    public string GuardianPublic { get; set; } = "";
    /// <summary>The PQ key a PQ or hybrid guardian is pinned to ({Ed25519 b64u: ML-DSA public key b64u}); without it such an epoch is refused.</summary>
    public IReadOnlyDictionary<string, string>? Pins { get; set; }
    /// <summary>The epoch-ms clock (required: no implicit clock).</summary>
    public double Now { get; set; }
    /// <summary>When set, must equal the epoch's <c>grant_ref</c>.</summary>
    public string? GrantRef { get; set; }
    /// <summary>The newest epoch number already accepted for the grant; an older one is a rollback.</summary>
    public double? LastAcceptedEpoch { get; set; }
    /// <summary>The PCActn's signed <c>freshness.epoch</c>; it must be &gt;= the epoch (no pre-revocation action).</summary>
    public double? PcactnEpoch { get; set; }
    /// <summary>Verifier-side maximum age (<c>now - issued_at</c>); null: only the signed <c>not_after</c> bounds it.</summary>
    public double? MaxAgeMs { get; set; }
}

/// <summary>The body a guardian signs (<see cref="RevocationFreshness.SignEpoch"/>).</summary>
public sealed record RevocationEpochBody(string InstanceId, string GrantRef, long Epoch, long SetSize, string Root, long IssuedAt, long NotAfter);

/// <summary>One decision of the staleness gate (<see cref="RevocationFreshness.Gate"/>).</summary>
public sealed class RevocationGateInput
{
    public RevocationStalenessPolicy Policy { get; set; } = new();
    /// <summary>The epoch guardian: its Ed25519 identity and (for a PQ guardian) the pins.</summary>
    public string? GuardianPublic { get; set; }
    public IReadOnlyDictionary<string, string>? Pins { get; set; }
    /// <summary>From the PCActn: <c>grant_ref</c> and <c>freshness.epoch</c>.</summary>
    public string GrantRef { get; set; } = "";
    public double? PcactnEpoch { get; set; }
    public double Now { get; set; }
    /// <summary>The authoritative reversibility class (null = none) and the PCActn's signed <c>action.reversibility_class</c>.</summary>
    public object? ServerClass { get; set; }
    public object? SignedClass { get; set; }
    /// <summary>A signed epoch is the expected source of revocation state; <see cref="Epoch"/> is the one presented (null: none).</summary>
    public bool EpochSource { get; set; }
    public object? Epoch { get; set; }
    public double? LastAcceptedEpoch { get; set; }
    /// <summary>A bare revocation root (with <see cref="EpochSource"/> it must equal the signed epoch's root) and the time your trusted
    /// source issued it (null: unknown, denied under a staleness policy).</summary>
    public string? Root { get; set; }
    public double? RootIssuedAt { get; set; }
    /// <summary>The capability ids that each need a non-membership proof against the root (null or empty: none, the freshness step alone).</summary>
    public IReadOnlyList<string>? Ids { get; set; }
    /// <summary>The non-membership proof ({size, lo?, hi?}) for an id; null (or no source) denies that id.</summary>
    public Func<string, Dictionary<string, object?>?>? ProofFor { get; set; }
}

/// <summary>The revocation state an <see cref="AuthorizeInput.RevocationState"/> source returns for a grant: a guardian-signed
/// <see cref="Epoch"/> (parsed JSON), or a bare <see cref="Root"/> with the time <see cref="RootIssuedAt"/> it was issued.</summary>
public sealed record RevocationState(Dictionary<string, object?>? Epoch = null, string? Root = null, double? RootIssuedAt = null, double? LastAcceptedEpoch = null);

public static class RevocationFreshness
{
    public const string EpochDomain = "atlas-pca/revepoch/v1\0";
    /// <summary>The server re-signs the epoch at least this often.</summary>
    public const long EpochRefreshMs = 60_000;
    /// <summary>How long a signed epoch is acceptable (longer than the refresh period).</summary>
    public const long EpochValidityMs = 5 * 60_000;
    /// <summary>The default maximum age of revocation state for an irreversible action (two refresh periods).</summary>
    public const long IrreversibleMaxAgeMs = 2 * EpochRefreshMs;
    /// <summary>How far in the future an issue time may lie.</summary>
    public const long SkewMs = 60_000;

    static readonly string[] EpochBodyKeys = { "instance_id", "grant_ref", "epoch", "set_size", "root", "issued_at", "not_after" };

    /// <summary>The stricter of the server's class (null = none) and the signed one: "reversible", "rate_limited" or "irreversible". Shared class
    /// table: reversible 0, rate_limited 1, costly 1, irreversible 2; an unknown class is irreversible.</summary>
    public static string EffectiveReversibility(object? serverClass, object? signedClass)
    {
        int rank = Math.Max(serverClass == null ? 0 : Pca.ClassRank(serverClass), Pca.ClassRank(signedClass));
        return rank >= 2 ? "irreversible" : rank == 1 ? "rate_limited" : "reversible";
    }

    /// <summary>The maximum age of revocation state the policy allows for an action of class <paramref name="cls"/>. A NaN window stays NaN, so the age check then fails closed.</summary>
    public static double MaxAgeMs(RevocationStalenessPolicy p, string cls)
    {
        double max = p.MaxRevocationAgeMs ?? EpochValidityMs;
        return cls switch
        {
            "irreversible" => Math.Min(max, p.Staleness?.Irreversible ?? IrreversibleMaxAgeMs),
            "costly" or "rate_limited" => Math.Min(max, p.Staleness?.Costly ?? max),
            _ => max,
        };
    }

    /// <summary>Checks revocation state issued at <paramref name="issuedAt"/> (null or non-finite: unknown, denied). A time more than 60 s in the future denies.</summary>
    public static RevocationCheck CheckAge(double? issuedAt, double now, double maxAgeMs, string what = "revocation state")
    {
        if (string.IsNullOrEmpty(what)) what = "revocation state";
        if (issuedAt is not double at || !double.IsFinite(at)) return new RevocationCheck(false, what + " age is unknown (unverifiable revocation state)");
        if (!(at <= now + SkewMs)) return new RevocationCheck(false, what + " issued in the future");
        if (!(now - at <= maxAgeMs))
            return new RevocationCheck(false, $"{what} is {Js(now - at)} ms old, over the verifier's maximum of {Js(maxAgeMs)} ms (stale revocation state)");
        return new RevocationCheck(true);
    }

    /// <summary>Number::toString for the message numbers (NaN and the infinities included).</summary>
    static string Js(double d) => double.IsNaN(d) ? "NaN" : double.IsPositiveInfinity(d) ? "Infinity" : double.IsNegativeInfinity(d) ? "-Infinity" : JsCanon.NumberString(d);

    static RevocationCheck Refuse(string reason) => new(false, reason);

    /// <summary>Verifies a signed revocation epoch (parsed JSON): the guardian, a suite this build verifies, shape, signature, grant
    /// binding, <c>not_after</c>, issue time, the verifier's age cap, rollback and the PCActn's freshness. Never throws.</summary>
    public static RevocationCheck CheckEpoch(object? epoch, EpochCheckOptions o)
    {
        try
        {
            const string notPinned = "revocation epoch not signed by the pinned guardian";
            if (epoch is not D m) return Refuse(notPinned);
            if (m.GetValueOrDefault("guardian") is not string g || g != o.GuardianPublic) return Refuse(notPinned);
            // an alg this build does not register is refused as not signed by the pinned guardian (the reference's resolveSigAlg)
            if (IntentJs.SuiteOf(m) == null) return Refuse(notPinned);
            if (!IntentJs.IsSafeInteger(m.GetValueOrDefault("epoch")) || IntentJs.NumOf(m["epoch"])! < 0
                || !IntentJs.IsSafeInteger(m.GetValueOrDefault("set_size")) || IntentJs.NumOf(m["set_size"])! < 0
                || !IntentJs.IsSafeInteger(m.GetValueOrDefault("issued_at")) || !IntentJs.IsSafeInteger(m.GetValueOrDefault("not_after")))
                return Refuse("malformed revocation epoch");
            double ep = IntentJs.NumOf(m["epoch"])!.Value, issued = IntentJs.NumOf(m["issued_at"])!.Value, notAfter = IntentJs.NumOf(m["not_after"])!.Value;
            var body = Ledger.Pick(m, EpochBodyKeys);
            if (body == null) return Refuse("revocation epoch check error");
            if (!Ledger.Signed(o.GuardianPublic, EpochDomain, body, m, o.Pins)) return Refuse("revocation epoch signature invalid");
            if (o.GrantRef != null && !(m.GetValueOrDefault("grant_ref") is string gr && gr == o.GrantRef)) return Refuse("revocation epoch is for a different grant");
            if (!(o.Now <= notAfter)) return Refuse("revocation epoch expired (stale revocation root)");
            if (!(issued <= o.Now + SkewMs)) return Refuse("revocation epoch issued in the future");
            if (o.MaxAgeMs is double cap)
            {
                var age = CheckAge(issued, o.Now, cap, "revocation epoch");
                if (!age.Ok) return age;
            }
            if (o.LastAcceptedEpoch is double last && ep < last)
                return Refuse($"revocation epoch {Js(ep)} is older than the last accepted {Js(last)} (rollback)");
            if (o.PcactnEpoch is double pe && !(pe >= ep))
                return Refuse($"PCActn freshness.epoch {Js(pe)} predates the revocation epoch {Js(ep)}");
            return new RevocationCheck(true);
        }
        catch (Exception) { return Refuse("revocation epoch check error"); }
    }

    /// <summary>Signs an Ed25519 revocation epoch with the guardian's 32-byte seed, in the wire form <see cref="CheckEpoch"/> verifies
    /// (a PQ or hybrid guardian signs with its own tooling).</summary>
    public static Dictionary<string, object?> SignEpoch(byte[] guardianSeed, RevocationEpochBody b)
    {
        if (guardianSeed is null || guardianSeed.Length != 32) throw new ArgumentException($"SignEpoch: the guardian seed must be {32} bytes");
        var body = new D
        {
            ["instance_id"] = b.InstanceId, ["grant_ref"] = b.GrantRef, ["epoch"] = IntentJs.OfLong(b.Epoch), ["set_size"] = IntentJs.OfLong(b.SetSize),
            ["root"] = b.Root, ["issued_at"] = IntentJs.OfLong(b.IssuedAt), ["not_after"] = IntentJs.OfLong(b.NotAfter),
        };
        var msg = IntentJs.Message(EpochDomain, body);
        var pk = new byte[32];
        Ed25519.GeneratePublicKey(guardianSeed, 0, pk, 0);
        var sig = new byte[64];
        Ed25519.Sign(guardianSeed, 0, msg, 0, msg.Length, sig, 0);
        body["guardian"] = Pca.B64u(pk);
        body["sig"] = Pca.B64u(sig);
        return body;
    }

    /// <summary>The whole reference revocation checker: first the staleness step, then, for every id in <see cref="RevocationGateInput.Ids"/>,
    /// a valid non-membership proof against the (signed-epoch or bare) root. Fail closed: a missing signed epoch, an
    /// unverifiable one, a mismatching root or no root at all is a refusal. Never throws.</summary>
    public static RevocationCheck Gate(RevocationGateInput g)
    {
        try
        {
            var invalid = g.Policy.Error();
            if (invalid != null) return Refuse("revocation staleness policy invalid: " + invalid);
            bool staleness = g.Policy.IsOn;
            var root = g.Root;
            double? maxAge = null;
            string cls = "";
            if (staleness)
            {
                cls = EffectiveReversibility(g.ServerClass, g.SignedClass);
                maxAge = MaxAgeMs(g.Policy, cls);
            }
            if (g.EpochSource)
            {
                if (g.Epoch == null || string.IsNullOrEmpty(g.GuardianPublic)) return Refuse("no signed revocation epoch");
                var chk = CheckEpoch(g.Epoch, new EpochCheckOptions
                {
                    GuardianPublic = g.GuardianPublic!, Pins = g.Pins, Now = g.Now, GrantRef = g.GrantRef, LastAcceptedEpoch = g.LastAcceptedEpoch,
                    PcactnEpoch = g.PcactnEpoch, MaxAgeMs = maxAge,
                });
                if (!chk.Ok) return chk;
                var epRoot = (g.Epoch as D)?.GetValueOrDefault("root") as string;
                if (!string.IsNullOrEmpty(root) && root != epRoot) return Refuse("revocation root does not match the signed epoch");
                root = epRoot;
            }
            else if (staleness)
            {
                if (cls == "irreversible" && !g.Policy.AllowUnsignedRootForIrreversible)
                    return Refuse("unsigned revocation root refused for an irreversible action (needs a guardian-signed epoch)");
                var age = CheckAge(g.RootIssuedAt, g.Now, maxAge!.Value, "revocation root");
                if (!age.Ok) return age;
            }
            if (string.IsNullOrEmpty(root)) return Refuse("no revocation root");
            foreach (var id in g.Ids ?? Array.Empty<string>())
            {
                var proof = g.ProofFor?.Invoke(id);
                if (proof == null) return Refuse($"no non-membership proof for {id}");
                if (!Mesh.NonMembership(root, proof, id)) return Refuse($"capability {id} is revoked or proof invalid");
            }
            return new RevocationCheck(true, null, root);
        }
        catch (Exception) { return Refuse("revocation state check error (fail closed)"); }
    }

    /// <summary>Every <c>id</c> in the PCActn's <c>cap_chain</c> (a revoked ancestor kills its descendants).</summary>
    static List<string> DefaultIds(D p) =>
        (IntentJs.Get(p, "cap_chain") as List<object?> ?? new()).Select(c => c is D d ? IntentJs.Get(d, "id") as string : null).Where(x => x != null).Select(x => x!).ToList();

    /// <summary>The gate for one <see cref="Pca.Authorize"/> decision (policy on): null when fresh, else the reason. <paramref name="state"/> may be null (the source had nothing).</summary>
    internal static string? ForAuthorize(AuthorizeInput input, D ctx, D p, RevocationState? state, long now)
    {
        var action = IntentJs.Get(p, "action") as D;
        var policy = input.RevocationStaleness!;
        var g = new RevocationGateInput
        {
            Policy = policy, GuardianPublic = input.GuardianPublic, Pins = input.GuardianPins, Now = now,
            ServerClass = IntentJs.Get(ctx, "reversibility_class"), SignedClass = action == null ? null : IntentJs.Get(action, "reversibility_class"),
            GrantRef = IntentJs.Get(p, "grant_ref") as string ?? "",
        };
        g.Ids = input.RevocationIds != null ? input.RevocationIds(p) : DefaultIds(p);
        g.ProofFor = id => input.RevocationProofFor?.Invoke(p, id);
        if (IntentJs.Get(p, "freshness") is D fr && IntentJs.NumOf(IntentJs.Get(fr, "epoch")) is double e) g.PcactnEpoch = e;
        if (state == null || (state.Epoch == null && string.IsNullOrEmpty(state.Root)))
        {
            if (EffectiveReversibility(g.ServerClass, g.SignedClass) == "irreversible" && !policy.AllowUnsignedRootForIrreversible)
                return "no verifiable (guardian-signed) revocation state for an irreversible action";
            return "no signed revocation epoch";
        }
        g.LastAcceptedEpoch = state.LastAcceptedEpoch;
        g.Root = state.Root;
        g.RootIssuedAt = state.RootIssuedAt;
        if (state.Epoch != null) { g.EpochSource = true; g.Epoch = state.Epoch; }
        var r = Gate(g);
        return r.Ok ? null : r.Reason;
    }
}

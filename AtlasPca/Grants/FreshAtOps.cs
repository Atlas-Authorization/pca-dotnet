// Consistency-token operations: the verifier-side issuer that advances its counters and mints the token, the field-wise merge and the
// decision gate (packages/pca fresh-at.ts). Token verification and the policy check are AtlasPca.FreshAt.
using System.Globalization;
using JD = System.Collections.Generic.Dictionary<string, object?>;

namespace AtlasPca.Grants;

public static class FreshAtOps
{
    static readonly string[] Numeric = { "revocation_epoch", "ledger_tree_size", "budget_version", "policy_revision" };

    static double Val(object? n) => n is Num x && double.TryParse(x.Raw, NumberStyles.Float, CultureInfo.InvariantCulture, out var d) ? d : double.NaN;

    /// <summary>Field-wise maximum of two states (each <c>{revocation_epoch, ledger_tree_size, budget_version, policy_revision, policy_digest}</c>).
    /// Equal revisions with different digests keep <paramref name="a"/>'s digest.</summary>
    public static JD MergeFreshAt(JD a, JD b)
    {
        var o = new JD();
        foreach (var k in Numeric) o[k] = Val(a.GetValueOrDefault(k)) >= Val(b.GetValueOrDefault(k)) ? a.GetValueOrDefault(k) : b.GetValueOrDefault(k);
        o["policy_digest"] = Val(b.GetValueOrDefault("policy_revision")) > Val(a.GetValueOrDefault("policy_revision")) ? b.GetValueOrDefault("policy_digest") : a.GetValueOrDefault("policy_digest");
        return o;
    }

    /// <summary>Compose a freshness verdict into a decision: it can only tighten (allow to escalate or deny), never loosen.</summary>
    public static string GateDecision(string decision, string verdict)
    {
        if (decision == "deny") return "deny";
        if (verdict == "deny") return "deny";
        if (verdict == "escalate") return "escalate";
        return decision;
    }
}

/// <summary>Verifier-side state holder: advance on every write, mint the token for the write, check incoming tokens. State is held as
/// doubles (a malformed patch moves it before the token refuses to sign, exactly like the reference).</summary>
public sealed class FreshAtIssuer
{
    static readonly string[] Numeric = { "revocation_epoch", "ledger_tree_size", "budget_version", "policy_revision" };
    readonly EdKey key;
    public string Scope { get; }
    readonly double[] n = new double[4];
    object? digest;

    static double Val(object? x) => x is Num v && double.TryParse(v.Raw, NumberStyles.Float, CultureInfo.InvariantCulture, out var d) ? d : double.NaN;

    /// <param name="initial"><c>{revocation_epoch, ledger_tree_size, budget_version, policy_revision, policy_digest}</c>; a missing counter reads as undefined (NaN).</param>
    public FreshAtIssuer(EdKey key, string scope, JD initial)
    {
        this.key = key; Scope = scope;
        for (int i = 0; i < 4; i++) n[i] = Val(initial.GetValueOrDefault(Numeric[i]));
        digest = initial.GetValueOrDefault("policy_digest");
    }

    static object? NumOut(double d) => double.IsFinite(d) ? new Num(IntentJs.Shortest(d)) : null;

    /// <summary>The current state (a copy).</summary>
    public JD Current
    {
        get
        {
            var o = new JD();
            for (int i = 0; i < 4; i++) o[Numeric[i]] = NumOut(n[i]);
            o["policy_digest"] = digest;
            return o;
        }
    }

    static bool SafeInt(double d) => double.IsFinite(d) && d == Math.Floor(d) && d >= 0 && d <= 9007199254740991.0 && !(d == 0 && double.IsNegative(d));

    /// <summary>Apply a write (any subset of counters; each only moves forward) and return its token. Throws when the resulting state cannot be signed
    /// (the state has already moved).</summary>
    public JD Advance(JD patch, long now)
    {
        var next = new double[4];
        for (int i = 0; i < 4; i++) next[i] = patch.ContainsKey(Numeric[i]) ? Val(patch[Numeric[i]]) : n[i];
        var nextDigest = patch.ContainsKey("policy_digest") ? patch["policy_digest"] : digest;
        // mergeFreshAt(state, {...state, ...patch})
        var merged = new double[4];
        for (int i = 0; i < 4; i++) merged[i] = Math.Max(n[i], next[i]);
        var mergedDigest = next[3] > n[3] ? nextDigest : digest;
        Array.Copy(merged, n, 4);
        digest = mergedDigest;
        if (!G.Str(Scope, 256) || !G.Str(digest, 128) || !n.All(SafeInt) || now < 0) throw new ArgumentException("signFreshAt: a malformed state");
        var body = new JD { ["v"] = new Num("1"), ["scope"] = Scope };
        for (int i = 0; i < 4; i++) body[Numeric[i]] = NumOut(n[i]);
        body["policy_digest"] = digest;
        body["issued_at"] = G.N(now);
        body["signer"] = key.Id;
        var t = new JD(body);
        t["sig"] = Sig.SignBody(FreshAt.Domain, body, key);
        return t;
    }

    /// <summary>May this issuer decide against its state for a request carrying <paramref name="token"/>? Each step fails closed.</summary>
    public FreshAtVerdict Check(object? token, long now, long? maxTokenAgeMs = null)
    {
        static FreshAtVerdict Deny(string c) => new("deny", c, Array.Empty<string>());
        if (!FreshAt.Verify(token, key.Id)) return Deny("bad_token");
        var t = (JD)token!;
        if ((string)t["scope"]! != Scope) return Deny("wrong_scope");
        Pca.SafeNat(t["issued_at"], out var issued);
        if (!(issued <= now + FreshAt.MaxFutureSkewMs)) return Deny("token_from_the_future");
        if (maxTokenAgeMs is long max && !(now - issued <= max)) return Deny("token_too_old");
        if (Val(t["policy_revision"]) == n[3] && !Equals(t["policy_digest"], digest)) return Deny("policy_fork");
        var behind = new List<string>();
        for (int i = 0; i < 4; i++) if (!(n[i] >= Val(t[Numeric[i]]))) behind.Add(Numeric[i]);
        return behind.Count == 0 ? new FreshAtVerdict("ok", null, Array.Empty<string>()) : new FreshAtVerdict("escalate", "stale_state", behind);
    }
}

// Intent capture and commitment: the principal's own words plus their structured reading, with provenance pointers, signed by the principal
// (Ed25519; a PQ-suite artifact verifies only under a PQ key the verifier pins). IntentRef is the content address a grant binds to through the
// intent goal string.
using static AtlasPca.IntentPkg.IntentOmega;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.IntentPkg;

public static class IntentStatement
{
    public const string IntentSigDomain = "atlas-pca/intent/v1\0";
    public const string IntentRefDomain = "atlas-pca/intent-ref/v1";
    public const string IntentGoalPrefix = "pca-intent:v1:";
    public static readonly string[] IntentSourceKinds = { "conversation", "ticket", "document", "form", "other" };

    static readonly string[] BodyKeys = { "v", "principal", "text", "slots", "sources", "created_at", "nonce" };

    static D StatementBody(D s)
    {
        var b = new D();
        foreach (var k in BodyKeys) if (s.ContainsKey(k)) b[k] = s[k];
        return (D)IntentJs.Normalize(b)!;
    }

    /// <summary>Content address of a statement: suite fields and signatures excluded.</summary>
    public static string IntentRef(object? s) => Pca.HashCanonical(new D { ["d"] = IntentRefDomain, ["s"] = StatementBody((D)s!) });

    /// <summary>The first shape problem of a statement, or null.</summary>
    internal static string? StatementShapeError(object? so)
    {
        if (so is not D s) return "intent statement is not an object";
        var v = IntentJs.NumOf(s.GetValueOrDefault("v"));
        if (v == null || v != 1) return "unsupported intent statement version";
        if (!IntentJs.B32(s.GetValueOrDefault("principal"))) return "principal is not canonical base64url (32 bytes)";
        if (s.GetValueOrDefault("text") is not string text || text.Length == 0) return "text must be a non-empty string";
        if (s.GetValueOrDefault("slots") is not D) return "slots must be an object";
        if (s.GetValueOrDefault("sources") is not L sources) return "sources must be an array";
        for (int i = 0; i < sources.Count; i++)
        {
            if (sources[i] is not D sm || sm.GetValueOrDefault("kind") is not string kind || !IntentSourceKinds.Contains(kind)) return "sources[" + i + "] has an unknown kind";
            if (sm.ContainsKey("uri") && sm["uri"] is not string) return "sources[" + i + "].uri must be a string";
            if (!IntentJs.B32(sm.GetValueOrDefault("digest"))) return "sources[" + i + "].digest is not canonical base64url (32 bytes)";
        }
        var ca = s.GetValueOrDefault("created_at");
        if (!IntentJs.IsInt(ca) || IntentJs.NumOf(ca)!.Value < 0) return "created_at must be a non-negative safe integer (epoch ms)";
        if (s.GetValueOrDefault("nonce") is not string nonce || nonce.Length == 0) return "nonce must be a non-empty string";
        return null;
    }

    /// <summary>Sign body under the key's suite: the message binds alg and pq_pk for a non-ed25519 suite; the result is body plus sig (and alg, pq_pk, pq_sig).</summary>
    internal static D SignSuite(D body, SuiteKey key, string domain)
    {
        if (key.Ed == null) throw new ArgumentException("signer needs an Ed25519 identity key");
        var bound = new D(body);
        if (key.Alg != "ed25519") { bound["alg"] = key.Alg; bound["pq_pk"] = key.PqPk; }
        var (sig, pqSig) = key.Sign(IntentJs.Message(domain, bound));
        var o = new D(bound) { ["sig"] = sig };
        if (pqSig != null) o["pq_sig"] = pqSig;
        return o;
    }

    /// <summary>Sign a statement as its principal with the principal's Ed25519 seed (principal defaults to the key's identity; must match when given).</summary>
    public static D SignIntent(D s, byte[] principalSeed) => SignIntent(s, SuiteKey.Ed25519(EdKey.FromSeed(principalSeed)));

    /// <summary>Sign under any registry suite (ML-DSA, hybrid, ...): alg and pq_pk are signed into the statement.</summary>
    public static D SignIntent(D s, SuiteKey suiteKey)
    {
        var principal = suiteKey.Ed?.Id ?? throw new ArgumentException("signIntentStatement: signer needs an Ed25519 identity key");
        if (s.ContainsKey("principal") && !(s["principal"] is string sp && sp == principal)) throw new ArgumentException("signIntentStatement: principal key mismatch");
        var withP = new D(s) { ["principal"] = principal };
        var body = StatementBody(withP);
        var bad = StatementShapeError(body);
        if (bad != null) throw new ArgumentException("signIntentStatement: " + bad);
        return SignSuite(body, suiteKey, IntentSigDomain);
    }

    static D Verdict(string? reason)
    {
        var r = new D { ["ok"] = reason == null };
        if (reason != null) r["reason"] = reason;
        return r;
    }

    /// <summary>{ok: true} or {ok: false, reason}. pqPins maps a principal to the PQ key the verifier pins for it. Never throws.</summary>
    /// <summary>The reference's <c>verifyIntentStatement</c>: <see cref="VerifyIntent"/>.</summary>
    public static D VerifyIntentStatement(object? so, string? expectedSigner = null, D? pqPins = null) => VerifyIntent(so, expectedSigner, pqPins);

    public static D VerifyIntent(object? so, string? expectedSigner = null, D? pqPins = null)
    {
        try
        {
            var bad = StatementShapeError(so);
            if (bad != null) return Verdict(bad);
            var st = (D)so!;
            if (expectedSigner != null && !(st["principal"] is string pr && pr == expectedSigner)) return Verdict("principal mismatch");
            bool algPresent = st.ContainsKey("alg");
            var suite = IntentJs.SuiteOf(st.GetValueOrDefault("alg"), algPresent);
            if (suite == null) return Verdict("unknown signature suite");
            if (suite == "ed25519" && (st.ContainsKey("pq_pk") || st.ContainsKey("pq_sig"))) return Verdict("an ed25519 artifact must not carry pq_pk / pq_sig");
            var body = IntentJs.BindSuiteFields(StatementBody(st), st.GetValueOrDefault("alg"), algPresent, st.GetValueOrDefault("pq_pk"), st.ContainsKey("pq_pk"));
            var msg = IntentJs.Message(IntentSigDomain, body);
            Dictionary<string, string>? pins = null;
            if (pqPins != null)
            {
                pins = new Dictionary<string, string>();
                foreach (var e in pqPins) if (e.Value is string pv) pins[e.Key] = pv;
            }
            if (!IntentJs.VerifyPinnedSuite(st.GetValueOrDefault("alg"), algPresent, (string)st["principal"]!, st.GetValueOrDefault("pq_pk"), msg, st.GetValueOrDefault("sig"), st.GetValueOrDefault("pq_sig"), pins))
                return Verdict("bad signature");
            return Verdict(null);
        }
        catch (Exception e)
        {
            return Verdict("malformed intent statement: " + e.Message);
        }
    }

    /// <summary>The goal string that binds a grant to an intent statement (and optionally an Intent Map).</summary>
    public static string IntentGoal(string reference, string? mapDigest = null) => Pca.IntentGoal(reference, mapDigest);

    /// <summary>Parse an intent goal string: {intentRef, mapDigest?}, or null when it is not one.</summary>
    public static D? ParseIntentGoal(object? goal)
    {
        if (goal is not string g || !g.StartsWith(IntentGoalPrefix, StringComparison.Ordinal)) return null;
        var parts = g.Substring(IntentGoalPrefix.Length).Split(':');
        var reference = parts[0];
        var map = parts.Length > 1 ? parts[1] : null;
        if (reference.Length == 0 || parts.Length > 2) return null;
        var r = new D { ["intentRef"] = reference };
        if (!string.IsNullOrEmpty(map)) r["mapDigest"] = map;
        return r;
    }
}

// Escalation on the wire: a port of packages/pca/src/escalation.ts (security contract C-51). A decision of escalate is admitted
// only with a principal-signed answer bound to (policy digest, action digest, history head), spent by the replay counter,
// never upgrading a deny. Every signature suite this SDK verifies is accepted (a PQ / hybrid answer under a PQ key the
// verifier pins); a suite it cannot verify is refused as unsupported_suite.
using JD = System.Collections.Generic.Dictionary<string, object?>;
using JL = System.Collections.Generic.List<object?>;

namespace AtlasPca;

/// <summary>A principal key the verifier pins for escalation answers: its Ed25519 identity and, for a PQ / hybrid suite, the
/// PQ key it pins for it.</summary>
public sealed record PinnedSigner(string Pk, string? PqPk = null)
{
    public static implicit operator PinnedSigner(string pk) => new(pk);
}

/// <summary>What an answer must be bound to.</summary>
public sealed record EscalationBinding(string PolicyDigest, string ActionDigest, string HistoryHead);

/// <summary>The result of <see cref="Escalation.Verify"/>. A valid deny answer is <c>Ok</c> with <c>Decision == "deny"</c>:
/// the caller must not admit it.</summary>
public sealed record EscalationVerdict(bool Ok, string? Principal = null, string? Decision = null, string? Reason = null);

public static class Escalation
{
    public const string AnswerDomain = "atlas-pca/escalation-answer/v1\0";
    public const string PolicyDomain = "atlas-pca/escalation-policy/v1";
    public const string ActionDomain = "atlas-pca/escalation-action/v1";
    public const string HistoryDomain = "atlas-pca/escalation-history/v1";
    /// <summary>An answer lives at most 24 hours.</summary>
    public const long MaxLifetimeMs = 86_400_000;

    /// <summary>The digest of the grant in force.</summary>
    public static string PolicyDigest(JD grant) => Pca.HashCanonical(new JD { ["d"] = PolicyDomain, ["grant"] = grant });

    /// <summary>The digest of the exact PCActn (counter and signature included): one answer, one action.</summary>
    public static string ActionDigest(JD pcactn) => Pca.HashCanonical(new JD { ["d"] = ActionDomain, ["pcactn"] = pcactn });

    /// <summary>The head of the holder's history: its highest admitted replay counter (null: none yet).</summary>
    public static string HistoryHead(long? lastCounter) =>
        Pca.HashCanonical(new JD { ["d"] = HistoryDomain, ["last_counter"] = lastCounter is long l ? IntentJs.OfLong(l) : null });

    /// <summary>The request a refused escalate carries for the principal.</summary>
    public static JD BuildRequest(string? aud, JD grant, JD pcactn, long? lastCounter, IEnumerable<string> reasons, long now, long ttlMs = 0)
    {
        var act = IntentJs.Get(pcactn, "action");
        string Str(string k) => JsStr(IntentJs.Get(act, k));
        return new JD
        {
            ["v"] = IntentJs.OfLong(1), ["kind"] = "pca-escalation-request", ["aud"] = aud ?? "",
            ["policy_digest"] = PolicyDigest(grant), ["action_digest"] = ActionDigest(pcactn), ["history_head"] = HistoryHead(lastCounter),
            ["verb"] = Str("verb"), ["resource"] = Str("resource"),
            ["reasons"] = new JL(reasons.Take(16).Select(r => (object?)TruncUtf16(r, 512))),
            ["expires_at"] = IntentJs.OfLong(now + (ttlMs > 0 ? ttlMs : 3_600_000)),
        };
    }

    /// <summary><c>s.slice(0, n)</c> of a JavaScript string: at most n UTF-16 code units (a surrogate pair is never split: a lone surrogate
    /// is not representable on the wire).</summary>
    internal static string TruncUtf16(string s, int n)
    {
        if (s.Length <= n) return s;
        return char.IsHighSurrogate(s[n - 1]) ? s[..(n - 1)] : s[..n];
    }

    static string JsStr(object? v) => v switch { null => "undefined", string s => s, bool b => b ? "true" : "false", _ => Pca.Canonicalize(v) };

    static readonly string[] Required = { "v", "kind", "principal", "policy_digest", "action_digest", "history_head", "decision", "iat", "expires_at", "nonce", "sig" };
    static readonly string[] Optional = { "alg", "pq_pk", "pq_sig" };

    /// <summary>Null = well-formed (closed members, canonical digests, safe-integer times, sane lifetime).</summary>
    public static string? AnswerShapeError(object? answer)
    {
        if (answer is not JD a) return "not an object";
        var e = IntentArtifacts.ClosedMembers(a, Required, Optional, "answer");
        if (e != null) return e;
        if (!(IntentJs.Get(a, "v") is { } v && IntentJs.IsInt(v) && IntentJs.NumOf(v) == 1) || a["kind"] is not "pca-escalation-answer") return "not a pca-escalation-answer v1";
        if (!IntentArtifacts.IsBoundedString(a["principal"], 64) || Pca.B64uDecode(a["principal"], 32) == null) return "principal must be canonical base64url (32 bytes)";
        foreach (var k in new[] { "policy_digest", "action_digest", "history_head" })
            if (!IntentArtifacts.IsDigest(a[k])) return $"{k} must be canonical base64url (32 bytes)";
        if (a["decision"] is not ("allow" or "deny")) return "decision must be 'allow' or 'deny'";
        if (!IntentJs.IsNonNeg(a["iat"]) || !IntentJs.IsNonNeg(a["expires_at"])) return "iat and expires_at must be non-negative safe integers";
        long iat = IntentJs.Lng(a["iat"]), exp = IntentJs.Lng(a["expires_at"]);
        if (!(exp > iat)) return "expires_at must be greater than iat";
        if (exp - iat > MaxLifetimeMs) return $"an answer lives at most {MaxLifetimeMs} ms";
        var nb = a["nonce"] is string ns ? Pca.B64uDecode(ns) : null;
        if (nb == null || nb.Length < 16) return "nonce must be canonical base64url of at least 16 bytes";
        if (a["sig"] is not string) return "sig must be a string";
        return IntentArtifacts.ArtifactSuiteError(a);
    }

    /// <summary>Verify an answer against the verifier's pinned principals and the binding of THIS decision. Total; every
    /// failure is <c>Ok == false</c>.</summary>
    public static EscalationVerdict Verify(object? answer, IReadOnlyList<PinnedSigner>? principals, EscalationBinding bind, long now)
    {
        static EscalationVerdict No(string r) => new(false, Reason: r);
        try
        {
            if (Math.Abs(now) > Pca.MaxSafeInt) return No("the verifier clock is not a safe integer (fail closed)");
            var e = AnswerShapeError(answer);
            if (e != null) return No("malformed escalation answer: " + e);
            var a = (JD)answer!;
            if (principals == null || principals.Count == 0) return No("no principal is pinned for escalation answers");
            var pin = principals.FirstOrDefault(p => p != null && p.Pk == (string)a["principal"]!);
            if (pin == null) return No("the answering principal is not pinned by this verifier");
            if (!IntentArtifacts.VerifyArtifactSig(AnswerDomain, a, pin.Pk, pin.PqPk)) return No("escalation answer signature invalid");
            if (!Equals(a["policy_digest"], bind.PolicyDigest)) return No("the answer is bound to another policy");
            if (!Equals(a["action_digest"], bind.ActionDigest)) return No("the answer is bound to another action");
            if (!Equals(a["history_head"], bind.HistoryHead)) return No("the answer is bound to another state of the history");
            if (now < IntentJs.Lng(a["iat"])) return No("the answer is from the future");
            if (now > IntentJs.Lng(a["expires_at"])) return No("the answer has expired");
            return new EscalationVerdict(true, (string)a["principal"]!, (string)a["decision"]!);
        }
        catch (Exception ex) { return No("escalation answer error (fail closed): " + ex.Message); }
    }
}

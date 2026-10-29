// The A2A binding (verification side): typed needs (pca_need), per-hop chain extension, the pure gate of AUTH_REQUIRED resumption,
// push-token binding and signed task-update receipts. Total. Per-hop PCActn verification is the ordinary verifier's job; this is what
// surrounds it. Replays packages/pca/conformance/a2a-vectors.json.
using System.Globalization;
using System.Text;
using JD = System.Collections.Generic.Dictionary<string, object?>;

namespace AtlasPca;

public sealed record A2aChainResult(bool Ok, int FailedHop = -1, string? Reason = null);

public sealed record A2aReceiptChain(bool Ok, string? Code = null, int At = -1, bool Terminal = false, string? LastState = null);

public static class A2a
{
    public const string ReceiptDomain = "atlas-pca/a2a-receipt/v1\0";
    static readonly HashSet<string> NeedMembers = new() { "v", "kind", "verb", "resource", "scopes", "grant_ref", "limits", "discharges", "tier", "policy_digest" };
    static readonly HashSet<string> Terminal = new() { "TASK_STATE_COMPLETED", "TASK_STATE_FAILED", "TASK_STATE_CANCELED", "TASK_STATE_REJECTED" };
    static readonly HashSet<string> States = new(Terminal) { "TASK_STATE_SUBMITTED", "TASK_STATE_WORKING", "TASK_STATE_INPUT_REQUIRED", "TASK_STATE_AUTH_REQUIRED" };

    static bool Str(object? x, int max) => x is string s && s.Length > 0 && s.Length <= max;
    static bool NumOf(object? x, out double d)
    {
        d = 0;
        return x is Num n && double.TryParse(n.Raw, NumberStyles.Float, CultureInfo.InvariantCulture, out d) && double.IsFinite(d);
    }

    /// <summary>null when valid, else the refusal code.</summary>
    public static string? NeedError(object? v)
    {
        if (v is not JD x) return "bad_shape";
        if (x.Keys.Any(k => !NeedMembers.Contains(k))) return "unknown_member";
        if (!NumOf(x.GetValueOrDefault("v"), out var ver) || ver != 1) return "bad_version";
        var kind = x.GetValueOrDefault("kind") as string;
        if (kind is not ("scope" or "grant" or "discharge" or "escalate")) return "bad_kind";
        if (!Str(x.GetValueOrDefault("verb"), 128) || !Str(x.GetValueOrDefault("resource"), 512)) return "bad_field";
        if (x.TryGetValue("scopes", out var sc) && !(sc is List<object?> sl && sl.Count <= 16 && sl.All(s => Str(s, 128) && !((string)s!).Any(char.IsWhiteSpace)))) return "bad_field";
        foreach (var k in new[] { "grant_ref", "policy_digest" }) if (x.TryGetValue(k, out var g) && !Str(g, 128)) return "bad_field";
        if (x.TryGetValue("tier", out var t) && !(NumOf(t, out var tv) && (tv == 2 || tv == 3) && kind == "escalate")) return "bad_field";
        if (x.TryGetValue("limits", out var lim) && !(lim is JD ld && ld.Count <= 16 && ld.All(e => Str(e.Key, 64) && NumOf(e.Value, out var n) && n >= 0))) return "bad_field";
        if (x.TryGetValue("discharges", out var dis) && !(dis is List<object?> dl && dl.Count <= 16 && dl.All(e => e is JD d && d.Keys.All(k => k == "issuer" || k == "claim") && Str(d.GetValueOrDefault("issuer"), 512) && Str(d.GetValueOrDefault("claim"), 256)))) return "bad_field";
        if (kind == "escalate" && !x.ContainsKey("tier")) return "bad_field";
        return null;
    }

    /// <summary>The decoded need, or the refusal code.</summary>
    public static (JD? Need, string? Code) DecodeNeed(object? value)
    {
        if (value is not string s || s.Length == 0) return (null, "bad_base64");
        if (s.Length > 2048) return (null, "too_long");
        var raw = Pca.B64uDecode(s);
        if (raw == null) return (null, "bad_base64");
        string text;
        try { text = new UTF8Encoding(false, true).GetString(raw); } catch (Exception) { return (null, "bad_utf8"); }
        object? parsed;
        try { parsed = Pca.ParseStrict(text); } catch (Exception) { return (null, "bad_json"); }
        var code = NeedError(parsed);
        return code == null ? ((JD)parsed!, null) : (null, code);
    }

    public static string NeedDigest(JD need) => Pca.HashCanonical(new JD { ["d"] = "atlas-pca/need/v1", ["need"] = need });

    public static A2aChainResult CheckChainExtension(IReadOnlyList<IReadOnlyList<string>> chains)
    {
        for (var i = 0; i < chains.Count; i++)
        {
            var ids = chains[i];
            if (ids.Count == 0) return new(false, i, "no_chain");
            if (i > 0)
            {
                var prev = chains[i - 1];
                if (ids.Count < prev.Count || !prev.SequenceEqual(ids.Take(prev.Count))) return new(false, i, "chain_does_not_extend_previous_hop");
            }
        }
        return new(true);
    }

    /// <summary>null when the full verifier may now be asked, else the refusal code.</summary>
    public static string? ResumeGate(object? state, object? needEncoded, object? answerDigest, object? proofAction)
    {
        if (state as string is not ("TASK_STATE_AUTH_REQUIRED" or "auth-required")) return "task_not_auth_required";
        var need = needEncoded == null ? null : DecodeNeed(needEncoded).Need;
        if (need == null) return "no_valid_need";
        if (answerDigest as string != NeedDigest(need)) return "answer_not_bound_to_need";
        if (proofAction is not JD pa) return "no_proof";
        if (pa.GetValueOrDefault("verb") as string != (string)need["verb"]! || pa.GetValueOrDefault("resource") as string != (string)need["resource"]!) return "action_mismatch";
        return null;
    }

    /// <summary>null where the reference throws (a salt shorter than 16 characters).</summary>
    public static string? PushToken(string taskId, IReadOnlyList<string> chainIds, object? salt)
    {
        if (salt is not string s || s.Length < 16) return null;
        return Pca.HashCanonical(new JD { ["d"] = "atlas-pca/a2a-push/v1", ["task_id"] = taskId, ["chain"] = PcaGrant.ChainDigest(chainIds), ["salt"] = s });
    }

    /// <summary>null when ok, else the reason.</summary>
    public static string? CheckPush(string taskId, IReadOnlyList<string> chainIds, string salt, object? token, object? payload)
    {
        if (token is not string t || t.Length == 0) return "no_token";
        var want = PushToken(taskId, chainIds, salt);
        if (want == null || want != t) return "token_mismatch";
        if (payload is JD p)
        {
            foreach (var (key, field) in new[] { ("task", "id"), ("statusUpdate", "taskId"), ("artifactUpdate", "taskId") })
            {
                if (p.GetValueOrDefault(key) is JD c && c.GetValueOrDefault(field) is { } v) return v as string == taskId ? null : "task_mismatch";
            }
        }
        return "task_mismatch";
    }

    public static string ReceiptDigest(object? r) => Pca.HashCanonical(new JD { ["d"] = "atlas-pca/a2a-receipt-ref/v1", ["r"] = r });

    public static bool VerifyReceipt(object? v, string signer)
    {
        if (v is not JD r || !NumOf(r.GetValueOrDefault("v"), out var ver) || ver != 1 || r.GetValueOrDefault("signer") as string != signer) return false;
        if (!Str(r.GetValueOrDefault("task_id"), 4096) || r.GetValueOrDefault("state") is not string st || !States.Contains(st)) return false;
        if (!Pca.SafeNat(r.GetValueOrDefault("seq"), out var seq) || !Pca.SafeNat(r.GetValueOrDefault("issued_at"), out _)) return false;
        if (r.GetValueOrDefault("chain") is not string c || Pca.B64uDecode(c, 32) == null) return false;
        var prev = r.GetValueOrDefault("prev");
        if (!(prev == null || (prev is string ps && Pca.B64uDecode(ps, 32) != null)) || (seq == 0) != (prev == null)) return false;
        var body = new JD();
        foreach (var k in new[] { "v", "task_id", "state", "seq", "prev", "chain", "issued_at", "signer" }) body[k] = r.GetValueOrDefault(k);
        return Pca.VerifyDomain(ReceiptDomain, body, signer, r.GetValueOrDefault("sig"));
    }

    public static A2aReceiptChain CheckReceiptChain(IReadOnlyList<object?> receipts, string signer, string taskId, IReadOnlyList<string> chainIds)
    {
        if (receipts.Count == 0) return new(false, "empty");
        var chain = PcaGrant.ChainDigest(chainIds);
        JD? prev = null;
        for (var i = 0; i < receipts.Count; i++)
        {
            if (!VerifyReceipt(receipts[i], signer)) return new(false, "bad_receipt", i);
            var r = (JD)receipts[i]!;
            if ((string)r["task_id"]! != taskId) return new(false, "wrong_task", i);
            if ((string)r["chain"]! != chain) return new(false, "wrong_chain", i);
            Pca.SafeNat(r["seq"], out var seq);
            if (prev == null)
            {
                if (seq != 0) return new(false, "bad_start", i);
            }
            else
            {
                if (Terminal.Contains((string)prev["state"]!)) return new(false, "after_terminal", i);
                Pca.SafeNat(prev["seq"], out var pseq);
                if (seq != pseq + 1 || r["prev"] as string != ReceiptDigest(prev)) return new(false, "broken_link", i);
            }
            prev = r;
        }
        var last = (string)prev!["state"]!;
        return new(true, null, -1, Terminal.Contains(last), last);
    }

    public static bool MayTriggerNext(IReadOnlyList<object?> receipts, string signer, string taskId, IReadOnlyList<string> chainIds)
    {
        var r = CheckReceiptChain(receipts, signer, taskId, chainIds);
        return r.Ok && r.LastState == "TASK_STATE_COMPLETED";
    }
}

// Agent blueprints (verification side): a record signed by an operator for a blueprint KEY; an instance is a chain with a hop issued
// by that key. BlueprintRegistry keeps the newest record per key (pinned operators, a strictly higher epoch replaces, the same epoch
// with different content is a fork). A non-empty ceiling is never evaluated here: it denies (ceiling_unevaluable). Total.
using JD = System.Collections.Generic.Dictionary<string, object?>;

namespace AtlasPca;

public sealed record BlueprintAccept(bool Ok, bool Replaced, string? Code);

public sealed record BlueprintDecision(string Decision, string? Code = null, string? Blueprint = null, IReadOnlyList<string>? Governed = null, long Have = 0, long Need = 0);

public sealed class BlueprintRegistry
{
    internal readonly Dictionary<string, JD> Store = new();
    readonly IReadOnlyList<string> operators;
    public BlueprintRegistry(IReadOnlyList<string> operators) { this.operators = operators; }

    public long Epoch() { long m = 0; foreach (var b in Store.Values) { Pca.SafeNat(b["epoch"], out var e); m = Math.Max(m, e); } return m; }

    public BlueprintAccept Accept(object? v)
    {
        if (!Blueprint.Verify(v)) return new(false, false, "bad_record");
        var b = (JD)v!;
        if (!operators.Contains((string)b["operator"]!)) return new(false, false, "unknown_operator");
        var key = (string)b["key"]!;
        if (Store.TryGetValue(key, out var cur))
        {
            if ((string)cur["operator"]! != (string)b["operator"]!) return new(false, false, "operator_changed");
            Pca.SafeNat(cur["epoch"], out var ce); Pca.SafeNat(b["epoch"], out var be);
            if (be < ce) return new(false, false, "stale_epoch");
            if (be == ce) return (string)cur["sig"]! == (string)b["sig"]! ? new(true, false, null) : new(false, false, "epoch_fork");
        }
        Store[key] = b;
        return new(true, true, null);
    }
}

public static class Blueprint
{
    public const string Domain = "atlas-pca/agent-blueprint/v1\0";
    static readonly string[] BodyKeys = { "v", "id", "key", "ceiling", "max_depth", "expires_at", "epoch", "status", "issued_at", "operator" };

    static bool Str(object? x, int max) => x is string s && s.Length > 0 && s.Length <= max;

    static bool WellFormed(object? v)
    {
        if (v is not JD b || !b.TryGetValue("v", out var one) || !Pca.SafeNat(one, out var ov) || ov != 1) return false;
        if (!Str(b.GetValueOrDefault("id"), 128) || !Str(b.GetValueOrDefault("key"), 128) || !Str(b.GetValueOrDefault("operator"), 128)) return false;
        if (!Pca.SafeNat(b.GetValueOrDefault("epoch"), out _) || !Pca.SafeNat(b.GetValueOrDefault("issued_at"), out _)) return false;
        if (b.GetValueOrDefault("status") is not string st || (st != "active" && st != "disabled")) return false;
        if (b.TryGetValue("max_depth", out var d) && !(Pca.SafeNat(d, out var dv) && dv >= 1)) return false;
        if (b.TryGetValue("expires_at", out var e) && !Pca.SafeNat(e, out _)) return false;
        return b.GetValueOrDefault("ceiling") is List<object?> c && c.Count <= 32 && c.All(x => x is JD m && m.GetValueOrDefault("type") is string);
    }

    public static bool Verify(object? v)
    {
        if (!WellFormed(v)) return false;
        var b = (JD)v!;
        var body = new JD();
        foreach (var k in BodyKeys) if (b.TryGetValue(k, out var x)) body[k] = x;
        return Pca.VerifyDomain(Domain, body, b["operator"], b.GetValueOrDefault("sig"));
    }

    static BlueprintDecision Deny(string code, string? bp = null) => new("deny", code, bp);

    /// <summary>Gate a chain (hops with issuer and holder, root first). mode is "require" or "any"; minEpoch is the revocation_epoch of the newest fresh_at token shown.</summary>
    public static BlueprintDecision Check(object? chain, BlueprintRegistry reg, object? now, string mode, long? minEpoch = null)
    {
        if (chain is not List<object?> hops || hops.Count == 0 || !Pca.SafeNat(now, out var nowMs)) return Deny("bad_input");
        var hs = new List<(string issuer, string holder)>();
        foreach (var h in hops)
        {
            if (h is not JD m || !Str(m.GetValueOrDefault("issuer"), 128) || !Str(m.GetValueOrDefault("holder"), 128)) return Deny("bad_input");
            hs.Add(((string)m["issuer"]!, (string)m["holder"]!));
        }
        if (minEpoch is long me && reg.Epoch() < me) return new("escalate", "stale_blueprint_state", null, null, reg.Epoch(), me);
        var governed = new List<string>();
        for (var i = 0; i < hs.Count; i++)
        {
            if (!reg.Store.TryGetValue(hs[i].issuer, out var bp)) continue;
            var id = (string)bp["id"]!;
            if (i == 0 || hs[i - 1].holder != (string)bp["key"]!) return Deny("broken_link", id);
            if ((string)bp["status"]! != "active") return Deny("blueprint_disabled", id);
            if (bp.TryGetValue("expires_at", out var ex) && Pca.SafeNat(ex, out var at) && nowMs >= at) return Deny("blueprint_expired", id);
            if (bp.TryGetValue("max_depth", out var md) && Pca.SafeNat(md, out var depth) && hs.Count - i > depth) return Deny("too_deep", id);
            if (((List<object?>)bp["ceiling"]!).Count > 0) return Deny("ceiling_unevaluable", id);
            governed.Add(id);
        }
        if (governed.Count == 0 && mode == "require") return Deny("no_blueprint");
        return new("allow", null, null, governed);
    }
}

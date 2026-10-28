// The `pca_grant` OAuth authorization-details type (RFC 9396): validation and the resource-server presentation check. The type is a
// pointer to a PCA grant, not authority: a verified per-action PCActn is still required. Every function is total.
using JD = System.Collections.Generic.Dictionary<string, object?>;

namespace AtlasPca;

/// <summary>Outcome of Parse / Check: <c>Code</c> is null on success; <c>Details</c> (Parse) or <c>Index</c> (Check) carry the value.</summary>
public sealed record PcaGrantResult(string? Code, IReadOnlyList<JD> Details, int Index);

public static class PcaGrant
{
    public const string Type = "pca_grant";
    public const string Domain = "atlas-pca/pca-grant-chain/v1";

    static readonly HashSet<string> Members = new() { "type", "chain_digest", "chain_len", "chain_ref", "bundle_revision", "locations" };
    static readonly HashSet<string> Refused = new() { "actions", "datatypes", "identifier", "privileges" };

    /// <summary>https://, printable ASCII without '#' or '\', at most 2048 characters, non-empty authority (to the first '/' or '?') without '@'.</summary>
    public static bool IsHttpsUrl(object? o)
    {
        if (o is not string u || u.Length > 2048 || !u.StartsWith("https://", StringComparison.Ordinal)) return false;
        foreach (var c in u) if (c < 0x21 || c > 0x7e || c == '#' || c == '\\') return false;
        var rest = u.Substring(8);
        var cut = rest.IndexOfAny(new[] { '/', '?' });
        var authority = cut < 0 ? rest : rest.Substring(0, cut);
        return authority.Length > 0 && !authority.Contains('@');
    }

    public static string ChainDigest(IReadOnlyList<string> ids) =>
        Pca.HashCanonical(new JD { ["d"] = Domain, ["ids"] = ids.Select(s => (object?)s).ToList() });

    /// <summary>null when accepted, else the refusal code.</summary>
    public static string? Validate(object? x)
    {
        if (x is not JD m) return "bad_entry";
        if (!m.TryGetValue("type", out var t) || t as string != Type) return "bad_type";
        foreach (var k in m.Keys)
        {
            if (Refused.Contains(k)) return "refused_member";
            if (!Members.Contains(k)) return "unknown_member";
        }
        if (!m.TryGetValue("chain_digest", out var d) || d is not string ds || Pca.B64uDecode(ds, 32) == null) return "bad_chain_digest";
        if (!m.TryGetValue("chain_len", out var n) || !Pca.SafeNat(n, out var len) || len < 1 || len > 16) return "bad_chain_len";
        if (m.TryGetValue("chain_ref", out var r) && !IsHttpsUrl(r)) return "bad_chain_ref";
        if (m.TryGetValue("bundle_revision", out var b) && !Pca.SafeNat(b, out _)) return "bad_bundle_revision";
        if (m.TryGetValue("locations", out var l))
        {
            if (l is not List<object?> list || list.Count == 0 || list.Count > 8 || !list.All(IsHttpsUrl)) return "bad_locations";
        }
        return null;
    }

    public static PcaGrantResult Parse(object? arr)
    {
        if (arr is not List<object?> l) return new("not_an_array", Array.Empty<JD>(), -1);
        if (l.Count > 16) return new("too_many_details", Array.Empty<JD>(), -1);
        var outp = new List<JD>();
        foreach (var e in l)
        {
            if (e is not JD m || !m.TryGetValue("type", out var t) || t is not string ts) return new("bad_entry", Array.Empty<JD>(), -1);
            if (ts != Type) continue;
            var code = Validate(m);
            if (code != null) return new(code, Array.Empty<JD>(), -1);
            outp.Add(m);
        }
        return new(null, outp, -1);
    }

    /// <summary>Allow only with a verified per-action proof and a detail naming a prefix of the presented chain (and this resource).</summary>
    public static PcaGrantResult Check(IReadOnlyList<JD> details, string resource, IReadOnlyList<string> chainIds, bool proofVerified)
    {
        if (details.Count == 0) return new("no_detail", Array.Empty<JD>(), -1);
        if (!proofVerified) return new("proof_required", Array.Empty<JD>(), -1);
        var reason = "chain_mismatch";
        for (var i = 0; i < details.Count; i++)
        {
            var d = details[i];
            Pca.SafeNat(d["chain_len"], out var n);
            if (chainIds.Count < n || ChainDigest(chainIds.Take((int)n).ToList()) != (string?)d["chain_digest"]) continue;
            if (d.TryGetValue("locations", out var loc) && !((List<object?>)loc!).Any(u => u as string == resource))
            {
                reason = "wrong_location";
                continue;
            }
            return new(null, Array.Empty<JD>(), i);
        }
        return new(reason, Array.Empty<JD>(), -1);
    }
}

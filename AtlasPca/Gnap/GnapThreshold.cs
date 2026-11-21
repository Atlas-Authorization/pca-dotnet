using System.Globalization;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Gnap;

/// <summary>
/// The t-of-n distinct-role count of the reference's <c>verifyThreshold</c> (without the agent-leaf baseline), for the explicit Ed25519
/// shares a GNAP continuation folds into a PCActn. The signer set is validated first and the whole verification fails closed if it is
/// malformed; a share counts iff its role and key are registered and its signature verifies over the role / signer-set / t-bound share
/// message. A share that names a suite other than Ed25519 is refused as an unknown algorithm (the continuation only produces Ed25519 shares).
/// </summary>
static class GnapThreshold
{
    static readonly HashSet<string> Roles = new() { "agent", "guardian", "principal" };
    static readonly HashSet<int> PqPkLengths = new() { 1952, 2592, 32, 64, 897, 1793, 97484 };

    /// <summary>Reason text for a possibly hostile value: primitives as String(v), containers by kind only.</summary>
    static string Show(object? v) => v is D ? "<object>" : v is L ? "<array>" : GnapJs.Str(v);

    static bool PqPkOk(object? v) => v is string && Pca.B64uDecode(v) is { } b && PqPkLengths.Contains(b.Length);

    static D Verdict(bool ok, int count, List<string> roles, string? reason)
    {
        var m = new D { ["ok"] = ok, ["count"] = (long)count, ["roles"] = new L(roles.Select(r => (object?)r)) };
        if (reason != null) m["reason"] = reason;
        return m;
    }

    internal static D Verify(D threshold, byte[] message, L signerSet, int t)
    {
        if (t < 1 || t > 3) return Verdict(false, 0, new List<string>(), "invalid threshold t=" + t.ToString(CultureInfo.InvariantCulture) + " (must be 1, 2 or 3)");
        // ---- the signer set (role -> key, key -> role, role -> registered pq_pk)
        var keyOfRole = new Dictionary<string, string>();
        var roleOfKey = new Dictionary<string, string>();
        var pqOfRole = new Dictionary<string, string>();
        var seenEntry = new Dictionary<string, string?>();
        foreach (var s in signerSet)
        {
            var ro = GnapJs.Member(s, "role"); var ko = GnapJs.Member(s, "publicKey");
            var role = ro is string rs && Roles.Contains(rs) ? rs : null;
            bool keyOk = s != null && Pca.B64uDecode(ko, 32) != null;
            bool hasPq = GnapJs.Has(s, "pq_pk"); // a present pq_pk (JSON null is present)
            bool pqOk = !hasPq || PqPkOk(GnapJs.Member(s, "pq_pk"));
            if (role != null && keyOk && pqOk)
            {
                var id = role + "\0" + ko;
                var pq = GnapJs.Member(s, "pq_pk") as string;
                // a duplicate (role, key) entry is harmless only if it registers the SAME pq_pk (or none on both)
                if (seenEntry.TryGetValue(id, out var prevPq) && prevPq != pq) pqOk = false;
                else seenEntry[id] = pq;
                if (pqOk && !pqOfRole.ContainsKey(role) && !keyOfRole.ContainsKey(role) && pq != null) pqOfRole[role] = pq;
            }
            if (role == null || !keyOk) return Verdict(false, 0, new List<string>(), "malformed signer set");
            if (!pqOk) return Verdict(false, 0, new List<string>(), "malformed signer set (pq_pk)");
            var key = (string)ko!;
            if (keyOfRole.TryGetValue(role, out var prevKey) && prevKey != key) return Verdict(false, 0, new List<string>(), "signer set registers more than one key for role " + Show(ro));
            if (roleOfKey.TryGetValue(key, out var prevRole) && prevRole != role) return Verdict(false, 0, new List<string>(), "signer set registers one key under two roles");
            if (prevKey == null) { keyOfRole[role] = key; roleOfKey[key] = role; }
        }

        // ---- the shares, in order
        var shares = threshold.GetValueOrDefault("shares") as L ?? new L();
        var keys = new List<string>();
        var roles = new List<string>();
        string? reason = null;
        foreach (var share in shares)
        {
            bool wellFormed = share is D && GnapJs.Member(share, "role") is string && GnapJs.Member(share, "publicKey") is string;
            if (!wellFormed) { reason ??= "malformed share"; continue; }
            var pub = (string)GnapJs.Member(share, "publicKey")!;
            if (keys.Contains(pub)) continue;
            var roleName = (string)GnapJs.Member(share, "role")!;
            string? regKey = Roles.Contains(roleName) && keyOfRole.TryGetValue(roleName, out var rk) ? rk : null;
            string? fail = null;
            if (regKey == null) fail = "role " + Show(roleName) + " is not in the signer set";
            else if (regKey != pub) fail = "share for role " + Show(roleName) + " uses a key not registered for that role";
            else if (GnapJs.Has(share, "alg") && GnapJs.Member(share, "alg") != null && GnapJs.Member(share, "alg") is not "ed25519")
                fail = "share for role " + Show(roleName) + " declares an unknown signature alg";
            else if (GnapJs.Has(share, "pq_pk") && !(GnapJs.Member(share, "pq_pk") is string sp && pqOfRole.TryGetValue(roleName, out var rp) && sp == rp))
                fail = "share for role " + Show(roleName) + " names a pq_pk that is not the key its role registers";
            else if (pqOfRole.ContainsKey(roleName) || !ShareOk(roleName, message, signerSet, t, (D)share!))
                fail = "invalid signature for role " + Show(roleName); // a role that registers a pq_pk needs a PQ share
            if (fail != null) { reason ??= fail; continue; }
            keys.Add(pub);
            roles.Add(roleName);
        }
        int count = keys.Count;
        if (count >= t) return Verdict(true, count, roles, null);
        return Verdict(false, count, roles, reason ?? "only " + count.ToString(CultureInfo.InvariantCulture) + " distinct valid key(s), need " + t.ToString(CultureInfo.InvariantCulture));
    }

    /// <summary>The bound share check of the wire form: the message and signer set are recomputed, nothing precomputed is trusted.</summary>
    static bool ShareOk(string role, byte[] message, L signerSet, int t, D share) =>
        Pca.VerifyThresholdShare(new D
        {
            ["role"] = role, ["t"] = new Num(t.ToString(CultureInfo.InvariantCulture)), ["signer_set"] = signerSet,
            ["threshold_message"] = Pca.B64u(message), ["share"] = share,
        });
}

// t-of-n threshold multi-signatures (the reference threshold.ts verifyThreshold, assembleThreshold and createThresholdVerifier). The signer set is
// validated FIRST (known roles, canonical 32-byte keys, one key per role, one role per key, a conflicting pq_pk refused); a share counts iff its
// role+key are registered and its signature verifies over that role's signerSetHash || t || suite bound share message; the count is of DISTINCT keys.
// The PCActn's own leaf signature is admitted as the agent's effective t=1 baseline. The decision follows the proved fold (Threshold.dfy: Verify):
// signer set, then each share in order (first failure kept), then the baseline, then the t rule. Total: never throws.
using System.Text;
using JD = System.Collections.Generic.Dictionary<string, object?>;
using JL = System.Collections.Generic.List<object?>;

namespace AtlasPca;

/// <summary>The outcome of <see cref="Pca.VerifyThreshold"/>: <c>Count</c> distinct valid keys, the <c>Roles</c> that contributed in first-seen order.</summary>
public sealed record ThresholdVerdict(bool Ok, int Count, IReadOnlyList<string> Roles, string? Reason = null);

/// <summary>The PCActn leaf signature admitted as the agent's effective t=1 share: the leaf holder, its <c>sig</c> over the BARE threshold message under
/// the PCActn's suite (<c>alg</c>, <c>pq_pk</c>, <c>pq_sig</c>) and the leaf capability's <c>holder_pq</c> commitment.</summary>
public sealed record AgentLeafBaseline(string? Holder, object? Sig, object? Alg = null, object? PqPk = null, object? PqSig = null, string? HolderPq = null);

public static partial class Pca
{
    /// <summary>Collect shares into a threshold signature <c>{shares}</c> (defensively copied).</summary>
    public static JD AssembleThreshold(IEnumerable<object?>? shares) => new() { ["shares"] = shares == null ? new JL() : new JL(shares) };

    static bool PqPkOfSomeSuite(object? v) => B64uDecode(v) is { } b && PqPkLengths.Contains(b.Length);

    static JD BaselineArtifact(AgentLeafBaseline b)
    {
        var d = new JD();
        if (b.Alg != null) d["alg"] = b.Alg;
        if (b.PqPk != null) d["pq_pk"] = b.PqPk;
        return d;
    }

    static bool SuiteHasPq(object? alg) => alg is string a && Pq.RegisteredSuites.Contains(a) && a != "ed25519";

    static string Shown(object? v) => v switch { null => "null", JD => "<object>", List<object?> => "<array>", _ => IntentJs.NumOf(v) is { } d ? JsonNum(d) : AtlasPca.Js.JsJson.ToJsString(v) };
    static string JsonNum(double d) => AtlasPca.Js.JsJson.NumberToString(d);

    /// <summary>Verify a t-of-n multi-signature over <paramref name="message"/> (= <see cref="ThresholdMessage"/>) with the signer set <c>[{role, publicKey, pq_pk?}]</c>.
    /// <paramref name="t"/> must be 1, 2 or 3; <paramref name="baseline"/> admits the PCActn leaf signature as the agent's effective t=1 share.</summary>
    public static ThresholdVerdict VerifyThreshold(object? sig, byte[] message, object? signerSet, object? t, AgentLeafBaseline? baseline = null)
    {
        try { return VerifyThresholdUnchecked(sig, message, signerSet, t, baseline); }
        catch (Exception e) { return new(false, 0, Array.Empty<string>(), "threshold error (fail closed): " + e.GetType().Name); }
    }

    static ThresholdVerdict VerifyThresholdUnchecked(object? sig, byte[] message, object? signerSetO, object? tO, AgentLeafBaseline? baseline)
    {
        ThresholdVerdict Fail(string r, int count = 0, IReadOnlyList<string>? roles = null) => new(false, count, roles ?? Array.Empty<string>(), r);
        var set = signerSetO as JL ?? new JL();
        var shares = (sig as JD)?.GetValueOrDefault("shares") as JL ?? new JL();
        if (!(IntentJs.IsSafeInteger(tO) && IntentJs.NumOf(tO) is 1.0 or 2.0 or 3.0)) return Fail($"invalid threshold t={Shown(tO)} (must be 1, 2 or 3)");
        var t = (int)IntentJs.NumOf(tO)!.Value;

        // ---- signer set (BuildReg): registered key per role, first reason wins in entry order
        var pqKeyOfRole = new Dictionary<string, string?>();
        var seenEntry = new Dictionary<string, string?>();
        var reg = new List<(string Role, string Key)>();
        for (var i = 0; i < set.Count; i++)
        {
            var s = set[i] as JD;
            var role = s != null && Get(s, "role") is string r && SignerRoles.Contains(r) ? r : null;
            var keyOk = s != null && B64uDecode(Get(s, "publicKey"), 32) != null;
            var pqOk = s == null || !Has(s, "pq_pk") || PqPkOfSomeSuite(Get(s, "pq_pk"));
            var key = s != null ? Get(s, "publicKey") as string : null;
            if (role != null && keyOk && pqOk)
            {
                var id = role + "\0" + key;
                var pq = Get(s, "pq_pk") as string;
                if (seenEntry.TryGetValue(id, out var prevPq) && prevPq != pq) pqOk = false; else seenEntry[id] = pq;
            }
            if (role != null && keyOk && pqOk && !pqKeyOfRole.ContainsKey(role)) pqKeyOfRole[role] = Get(s, "pq_pk") as string;
            if (role == null || !keyOk) return Fail("malformed signer set");
            if (!pqOk) return Fail("malformed signer set (pq_pk)");
            var prevKey = reg.FirstOrDefault(x => x.Role == role).Key;
            if (prevKey != null && prevKey != key) return Fail("signer set registers more than one key for role " + role);
            var prevRole = reg.FirstOrDefault(x => x.Key == key).Role;
            if (prevRole != null && prevRole != role) return Fail("signer set registers one key under two roles");
            if (prevKey == null) reg.Add((role, key!));
        }
        string? KeyOf(string? role) => role == null ? null : reg.FirstOrDefault(x => x.Role == role).Key;

        // ---- shares, in order
        var keys = new List<string>();
        var roles = new List<string>();
        string? reason = null;
        for (var i = 0; i < shares.Count; i++)
        {
            var sh = shares[i] as JD;
            if (sh == null || Get(sh, "role") is not string srole || Get(sh, "publicKey") is not string skey) { reason ??= "malformed share"; continue; }
            if (keys.Contains(skey)) continue;
            var roleKnown = SignerRoles.Contains(srole) ? srole : null;
            var rk = KeyOf(roleKnown);
            if (rk == null) { reason ??= $"role {srole} is not in the signer set"; continue; }
            if (rk != skey) { reason ??= $"share for role {srole} uses a key not registered for that role"; continue; }
            var algOk = !Has(sh, "alg") ? true : Get(sh, "alg") is string al && Pq.RegisteredSuites.Contains(al);
            if (!algOk) { reason ??= $"share for role {srole} declares an unknown signature alg"; continue; }
            var registeredPq = pqKeyOfRole.GetValueOrDefault(srole);
            var pqPkOk = !Has(sh, "pq_pk") || (Get(sh, "pq_pk") is string spk && spk == registeredPq);
            if (!pqPkOk) { reason ??= $"share for role {srole} names a pq_pk that is not the key its role registers"; continue; }
            var alg = Get(sh, "alg") as string;
            bool sigOk;
            if (registeredPq != null && !SuiteHasPq(alg)) sigOk = false;
            else
            {
                var tag = alg == null || alg == "ed25519" ? Array.Empty<byte>() : Encoding.UTF8.GetBytes(ShareSuiteTag + alg);
                var ssh = SignerSetHash(set);
                var signed = Cat(Encoding.UTF8.GetBytes(ShareDomainPrefix + srole + "\0"), Sha(message), ssh!, new[] { (byte)t }, tag);
                sigOk = Get(sh, "sig") is string && VerifySuiteSig(alg, skey, registeredPq, signed, Get(sh, "sig"), Get(sh, "pq_sig"));
            }
            if (!sigOk) { reason ??= $"invalid signature for role {srole}"; continue; }
            keys.Add(skey); roles.Add(srole);
        }

        // ---- the agent-leaf baseline (effective t=1)
        var agentKey = KeyOf("agent");
        if (baseline != null && baseline.Holder != null && agentKey != null && baseline.Holder == agentKey && !keys.Contains(agentKey))
        {
            var agentPq = pqKeyOfRole.GetValueOrDefault("agent");
            var pqKeyOk = agentPq != null || PqBindingError(BaselineArtifact(baseline), baseline.HolderPq, "threshold baseline") == null;
            if (pqKeyOk && !(agentPq != null && !SuiteHasPq(baseline.Alg)))
            {
                var pqKey = agentPq ?? PinnedPq.Resolve(agentKey, baseline.PqPk, baseline.HolderPq)?.Key;
                if (baseline.Alg is null or string && VerifySuiteSig(baseline.Alg as string, agentKey, pqKey, message, baseline.Sig, baseline.PqSig)) { keys.Add(agentKey); roles.Add("agent"); }
            }
        }
        if (keys.Count >= t) return new(true, keys.Count, roles);
        return Fail(reason ?? $"only {keys.Count} distinct valid key(s), need {t}", keys.Count, roles);
    }
}

/// <summary>What <see cref="ThresholdVerifiers.Create"/> needs. Exactly one of <see cref="T"/> / <see cref="RequiredT"/>: there is deliberately NO default derived from
/// the PCActn's <c>risk_claim.r</c> (the agent's own claim; finding F-1). <see cref="Scheme"/> is the assurance label: <c>multisig</c> (default), or <c>frost</c> /
/// <c>frost_dkg</c> / <c>mpc</c> (reported as awaiting audit).</summary>
public sealed class ThresholdVerifierOptions
{
    public object? SignerSet { get; set; }
    public int? T { get; set; }
    public Func<JD, JD, int>? RequiredT { get; set; }
    public string Scheme { get; set; } = "multisig";
}

/// <summary>A threshold hook for <see cref="AuthorizeInput.ThresholdHook"/> and the assurance label it carries.</summary>
public sealed record ThresholdVerifier(Func<JD, JD, ThresholdHookResult?> Hook, AssuranceLabel Label);

public static class ThresholdVerifiers
{
    /// <summary>Build the hook: it recomputes the canonical signed message (<see cref="Pca.ThresholdMessage"/>), verifies the explicit bound shares in
    /// <c>pcactn.threshold.shares</c>, admits the PCActn's own leaf signature as the agent's effective-t=1 baseline, resolves the required <c>t</c> from SERVER-held data
    /// and returns an ENFORCED pass or fail that reports the <c>t</c> it enforced. The configuration is snapshotted: later edits do not change what it enforces.</summary>
    public static ThresholdVerifier Create(ThresholdVerifierOptions opts)
    {
        if (opts.RequiredT == null && opts.T == null)
            throw new ArgumentException("createThresholdVerifier: supply `t` or `requiredT` derived from SERVER-held data. The risk_claim.r-derived default was removed (F-1): it is the agent's own claim.");
        object? set;
        try { set = Issue.Norm(opts.SignerSet); } catch (Exception) { set = opts.SignerSet; }
        var fixedT = opts.T;
        var resolve = opts.RequiredT ?? ((_, _) => fixedT!.Value);
        var scheme = opts.Scheme;
        ThresholdHookResult? Hook(JD p, JD grant)
        {
            var message = Pca.ThresholdMessage(p);
            var explicitShares = (p.GetValueOrDefault("threshold") as JD)?.GetValueOrDefault("shares") as JL ?? new JL();
            var chain = p.GetValueOrDefault("cap_chain") as JL;
            var leaf = chain is { Count: > 0 } ? chain[^1] as JD : null;
            var baseline = leaf != null && leaf.GetValueOrDefault("holder") is string holder && p.GetValueOrDefault("sig") is string
                ? new AgentLeafBaseline(holder, p["sig"], p.GetValueOrDefault("alg"), p.GetValueOrDefault("pq_pk"), p.GetValueOrDefault("pq_sig"), leaf.GetValueOrDefault("holder_pq") as string)
                : null;
            var t = resolve(p, grant);
            var v = Pca.VerifyThreshold(new JD { ["shares"] = explicitShares }, message, set, new Num(t.ToString()), baseline);
            return v.Ok ? new ThresholdHookResult(true, true, t) : new ThresholdHookResult(true, false, t, v.Reason ?? "threshold not met");
        }
        return new ThresholdVerifier(Hook, new AssuranceLabel(scheme, AwaitingAudit: scheme is "frost" or "frost_dkg" or "mpc"));
    }
}

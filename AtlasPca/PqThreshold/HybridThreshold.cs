// The signing and PCActn-verifier side of the hybrid post-quantum threshold step-up: sign with a FROST quorum plus ML-DSA-65 co-signers, fold the
// classical aggregate into a PCActn's threshold container, and enforce both halves through the core threshold hook. The artifact formats and the
// standalone verifier live in PqThreshold.
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.PqThreshold;

public static class HybridThreshold
{
    /// <summary>The classical FROST quorum supplied to <see cref="HybridThresholdSign"/>; <c>GroupPublicKey</c> is 32 bytes or canonical b64u(32).</summary>
    public sealed record FrostQuorumInput(object? GroupPublicKey, List<Frost.FrostParticipantShare> Quorum, int T);

    static byte[] GroupKeyBytes(object? k)
    {
        if (k is byte[] b)
            return b.Length == 32 ? b : throw new ArgumentException("hybridThresholdSign: FROST group public key must be 32 bytes");
        return (k is string s ? Pca.B64uDecode(s, 32) : null) ?? throw new ArgumentException("hybridThresholdSign: FROST group public key is not canonical b64u(32)");
    }

    /// <summary>One ML-DSA-65 co-signature per key over DOMAIN || sha256(message), as the pq block <c>{v, alg, pqT, signers}</c>.</summary>
    public static D SignPqQuorum(byte[] message, IReadOnlyList<PqKey> keys, int? pqT = null)
    {
        var rep = PqThreshold.PqQuorumRepresentative(message);
        var signers = new L();
        foreach (var k in keys)
        {
            if (k.Prim != Pq.Prim.MlDsa65) throw new ArgumentException("signPqQuorum: co-signers must be ML-DSA-65 keys");
            signers.Add(new D { ["pk"] = Pca.B64u(k.Pk), ["sig"] = Pca.B64u(k.Sign(rep)) });
        }
        return new D { ["v"] = IntentJs.OfLong(PqThreshold.PqQuorumVersion), ["alg"] = PqThreshold.PqQuorumAlg, ["pqT"] = IntentJs.OfLong(pqT ?? signers.Count), ["signers"] = signers };
    }

    /// <summary>Assemble a hybrid artifact from a FROST aggregate and the ML-DSA co-signers. Fails closed: a sub-threshold quorum count, no co-signer,
    /// a non-canonical group key, or an aggregate that does not verify under the group key all throw.</summary>
    public static D HybridThresholdAssemble(D action, byte[] groupPublicKey, byte[] frostAggregate, int t, int quorum, IReadOnlyList<PqKey> pqSigners, int? pqT = null)
    {
        if (t < 1) throw new ArgumentException($"hybridThresholdAssemble: t must be a positive integer (got {t})");
        if (quorum < t) throw new ArgumentException($"hybridThresholdAssemble: FROST quorum of {quorum} is below the threshold t={t}");
        if (pqSigners.Count == 0) throw new ArgumentException("hybridThresholdAssemble: at least one ML-DSA co-signer is required");
        if (groupPublicKey == null || groupPublicKey.Length != 32) throw new ArgumentException("hybridThresholdAssemble: FROST group public key must be 32 bytes");
        var message = Pca.ThresholdMessage(action);
        if (frostAggregate == null || !Pca.VerifyEdInternal(Pca.B64u(groupPublicKey), message, Pca.B64u(frostAggregate)))
            throw new ArgumentException("hybridThresholdAssemble: the FROST aggregate does not verify under the group key");
        return new D
        {
            ["v"] = IntentJs.OfLong(PqThreshold.HybridArtifactVersion),
            ["digest"] = Pca.B64u(Pca.Sha256Of(message)),
            ["frost"] = new D { ["alg"] = PqThreshold.HybridClassicalAlg, ["group_pk"] = Pca.B64u(groupPublicKey), ["sig"] = Pca.B64u(frostAggregate), ["t"] = IntentJs.OfLong(t), ["quorum"] = IntentJs.OfLong(quorum) },
            ["pq"] = SignPqQuorum(message, pqSigners, pqT),
        };
    }

    /// <summary>A hybrid artifact for <paramref name="action"/>: the FROST t-of-n aggregate over thresholdMessage(action) (produced by <see cref="Frost.Cosign"/>,
    /// which throws on a short quorum or an invalid share) plus one ML-DSA-65 co-signature per signer over the same message.</summary>
    public static D HybridThresholdSign(D action, FrostQuorumInput frost, IReadOnlyList<PqKey> pqSigners, int? pqT = null)
    {
        if (frost.T < 1) throw new ArgumentException($"hybridThresholdSign: frost.t must be a positive integer (got {frost.T})");
        if (frost.Quorum.Count < frost.T) throw new ArgumentException($"hybridThresholdSign: FROST quorum of {frost.Quorum.Count} is below the threshold t={frost.T}");
        if (pqSigners.Count == 0) throw new ArgumentException("hybridThresholdSign: at least one ML-DSA co-signer is required");
        var message = Pca.ThresholdMessage(action);
        var groupKey = GroupKeyBytes(frost.GroupPublicKey);
        var aggregate = Frost.Cosign(groupKey, frost.Quorum, message, frost.T);
        return HybridThresholdAssemble(action, groupKey, aggregate, frost.T, frost.Quorum.Count, pqSigners, pqT);
    }

    /// <summary>The PCActn with the classical aggregate folded into its threshold container, and the PQ block that travels alongside it.</summary>
    public sealed record StepUp(D Pcactn, object? Pq);

    /// <summary>Fold a hybrid artifact into a PCActn step-up: the FROST aggregate becomes a 'guardian' share (publicKey = the group key, sig = the aggregate) in
    /// <c>threshold.shares</c>; thresholdMessage excludes <c>threshold</c>, so neither quorum's signed bytes change. The PQ block rides alongside.</summary>
    public static StepUp FoldHybridStepUp(D action, D artifact)
    {
        if (artifact.GetValueOrDefault("frost") is not D f) throw new ArgumentException("foldHybridStepUp: artifact has no FROST part");
        var share = new D { ["role"] = "guardian" };
        if (f.TryGetValue("group_pk", out var gpk)) share["publicKey"] = gpk; // an absent member stays absent (JSON drops undefined)
        if (f.TryGetValue("sig", out var sig)) share["sig"] = sig;
        var shares = new L();
        if (action.GetValueOrDefault("threshold") is D th && th.GetValueOrDefault("shares") is L old) shares.AddRange(old);
        shares.Add(share);
        var pcactn = new D(action) { ["threshold"] = new D { ["shares"] = shares } };
        return new StepUp(pcactn, artifact.GetValueOrDefault("pq"));
    }

    /// <summary>Configuration of <see cref="CreateHybridThresholdVerifier"/>; values are wire/config values (keys may be string or byte[]).</summary>
    public sealed record VerifierOpts(object? GroupKey, object? PqPublicKeys, object? T, object? PqT, object? PqBlock, object? GroupDescriptor, object? TrustedAuthorities, string? SignerSetCommitment = null);

    static string? AsB64u(object? k) => k is byte[] b ? Pca.B64u(b) : k as string;

    /// <summary>The core threshold hook enforcing the hybrid step-up: the FROST aggregate folded into <c>pcactn.threshold</c> (a plain Ed25519 signature under the
    /// TRUSTED group key) AND the ML-DSA quorum block. Enforced and ok only when both hold; every other outcome is an enforced refusal.</summary>
    public static Func<D, D, ThresholdHookResult?> CreateHybridThresholdVerifier(VerifierOpts o)
    {
        var trustedGroupKey = AsB64u(o.GroupKey) is { } g && Pca.B64uDecode(g, 32) != null ? g : null;
        var pool = PqThreshold.NormalizePqQuorumPool(o.PqPublicKeys);
        var expect = new D { ["groupKey"] = o.GroupKey, ["t"] = o.T, ["trustedAuthorities"] = o.TrustedAuthorities };
        if (o.SignerSetCommitment != null) expect["signerSetCommitment"] = o.SignerSetCommitment;
        static ThresholdHookResult Refuse(string why) => new(true, false, null, why);
        return (pcactn, _) =>
        {
            var d = PqThreshold.VerifyGroupDescriptor(o.GroupDescriptor, expect);
            if (d["ok"] is not true) return Refuse((string)d["reason"]!);
            var message = Pca.ThresholdMessage(pcactn);
            if (trustedGroupKey == null) return Refuse("trusted FROST group key is not a canonical b64u(32) point");
            string? sig = null;
            if (pcactn.GetValueOrDefault("threshold") is D th && th.GetValueOrDefault("shares") is L shares)
                foreach (var s in shares)
                    if (s is D sd && sd.GetValueOrDefault("sig") is string ss && sd.GetValueOrDefault("publicKey") is string pk && pk == trustedGroupKey) { sig = ss; break; }
            if (sig == null) return Refuse("no FROST aggregate for the trusted group key in the step-up");
            if (!Pca.VerifyEdInternal(trustedGroupKey, message, sig)) return Refuse("FROST aggregate does not verify under the trusted group key (quorum short or forged)");
            var pq = PqThreshold.VerifyPqQuorum(o.PqBlock, message, pool, o.PqT);
            if (pq["ok"] is not true) return Refuse(pq.GetValueOrDefault("reason") as string ?? "post-quantum quorum short");
            return new ThresholdHookResult(true, true);
        };
    }

    /// <summary>Options of <see cref="VerifyHybridStepUp"/>. <c>Audience</c>: a string is the resource server id; <c>AudienceGiven</c> false (absent) refuses a PCActn that
    /// carries a signed <c>aud</c>; <c>AudienceGiven</c> true with a null <c>Audience</c> explicitly accepts any.</summary>
    public sealed record StepUpOpts(D Grant, VerifierOpts Verifier, string? Audience, bool AudienceGiven, long? NowEpoch = null);

    /// <summary>The full step-up verification: the core PCActn checks (plan-root check skipped, the caller decides the plan) with the hybrid hook as the threshold check, plus the
    /// standalone post-quantum quorum verdict. <c>Allow</c> only when every core check and the hook pass. Never throws on a malformed PCActn: that is a wire failure.</summary>
    public sealed record StepUpResult(bool Allow, D Pq, string? Reason, Dictionary<string, string> Checks);

    public static StepUpResult VerifyHybridStepUp(StepUp stepUp, StepUpOpts opts)
    {
        var o = opts.Verifier;
        var pool = PqThreshold.NormalizePqQuorumPool(o.PqPublicKeys);
        var pqVerdict = PqThreshold.VerifyPqQuorum(stepUp.Pq, Pca.ThresholdMessage(stepUp.Pcactn), pool, o.PqT);
        var hook = CreateHybridThresholdVerifier(o with { PqBlock = stepUp.Pq });
        var now = opts.NowEpoch ?? DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        var aud = stepUp.Pcactn.GetValueOrDefault("aud") as string;
        // The core takes a string audience: hand it the PCActn's own when the caller gave none, and report the audience check from the caller's intent below.
        var v = Pca.VerifyPcactnCore(stepUp.Pcactn, opts.Grant, now, opts.AudienceGiven && opts.Audience != null ? opts.Audience : aud ?? "", planRoots: PlanRootPolicy.Skip);
        var checks = new Dictionary<string, string>();
        if (v.Checks.Count == 1 && v.Checks.TryGetValue("wire", out var w) && !w)
            return new StepUpResult(false, pqVerdict, v.Reason, new Dictionary<string, string> { ["wire"] = "fail" });
        var reason = v.Reason == "" ? null : v.Reason;
        string? Cap(string? r) => r != null && r.StartsWith("chain: ", StringComparison.Ordinal) ? "cap_" + r : r;
        reason = Cap(reason);
        foreach (var (k, ok) in v.Checks) checks[k == "chain" ? "cap_chain" : k] = ok ? "pass" : "fail";
        checks["plan_root_authorized"] = "not-enforced";
        if (aud != null && !opts.AudienceGiven)
        {
            checks["audience"] = "fail";
            if (v.Checks.GetValueOrDefault("version", true)) // version is checked first
                reason = "audience: PCActn carries a signed aud but this verifier supplied no audience (pass your audience, or audience: null to accept any)";
        }
        else if (opts.AudienceGiven && opts.Audience == null) checks["audience"] = "not-enforced";
        checks["taint_gate"] = "not-enforced";
        checks["attestation"] = "not-enforced";
        var th = "not-enforced";
        try
        {
            var hr = hook(stepUp.Pcactn, opts.Grant);
            if (hr is { Enforced: true }) { th = hr.Ok ? "pass" : "fail"; if (!hr.Ok) reason ??= "threshold: " + (hr.Reason ?? "rejected"); }
        }
        catch (Exception) { th = "fail"; reason ??= "threshold: threshold hook error (fail closed)"; }
        checks["threshold"] = th;
        checks["revocation"] = "not-enforced";
        var allow = checks.Values.All(x => x != "fail");
        return new StepUpResult(allow, pqVerdict, allow ? null : reason, checks);
    }
}

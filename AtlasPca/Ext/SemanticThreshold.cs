// The signing, attestation-gate and hook side of the k-of-n semantic judge threshold (semantic-threshold.ts). The statement, the quantisation, the verdict check, the conformal cutoff and the plain threshold
// are IntentSemantic; this adds the signed judge message, the verdict digest, verdict signing under the Ed25519, ML-DSA and hybrid suites, the judge attestation gate (a judge's hardware attestation must be
// bound, measured, equal to the signed judgeMeasurement and approved by the agent binding), the threshold with that gate and the pipeline hook. The legacy option that accepts an unpinned post-quantum judge key
// does not exist here: a post-quantum verdict counts only under a pin of the verifier.
using AtlasPca.IntentPkg;
using AtlasPca.Js;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca;

/// <summary>The attestation requirement of a semantic ensemble: <c>Resolve</c> finds the hardware attestation result of a verdict's judge (null: none), <c>Approved</c> is the agent binding a measured judge must
/// satisfy, and with <c>Require</c> a judge whose attestation fails does not vote.</summary>
public sealed record SemanticAttestation(Func<D, object?> Resolve, D? Approved, bool Require);

public static class SemanticThreshold
{
    /// <summary>Returned by a hook accessor for a member the context does not carry (JavaScript <c>undefined</c>).</summary>
    public static readonly object Absent = new();

    /// <summary>The published constants of the module.</summary>
    public static D Constants() => new() { ["SEMANTIC_JUDGE_DOMAIN"] = IntentSemantic.SemanticJudgeDomain, ["SCORE_SCALE"] = IntentJs.OfLong(1_000_000) };

    /// <summary><c>"atlas-pca/semantic-judge/v1\0" || strictCanonical(statement)</c>. Throws on a member the strict canonical form refuses (non-integer, negative zero, non-finite).</summary>
    public static byte[] SemanticJudgeMessage(D statement) => IntentJs.Message(IntentSemantic.SemanticJudgeDomain, statement);

    /// <summary>The strict content hash of a verdict.</summary>
    public static string VerdictDigest(object? verdict) => IntentRuntime.VerdictDigest(verdict);

    /// <summary>A judge verdict signed by <paramref name="secret"/>: <c>v</c> = {actionDigest, goalCommitment, faithful, score, judgeMeasurement?}. <paramref name="alg"/> null is ed25519; another suite needs its PQ
    /// key in <paramref name="keys"/>. The score is quantised before signing and the suite is bound into the signed statement. Throws on an unknown alg.</summary>
    public static D SignJudgeVerdict(byte[] secret, D v, string? alg = null, SuiteSecretKeys? keys = null)
    {
        if (IntentJs.SuiteOf(alg, alg != null) is not { } resolved) throw new ArgumentException($"signJudgeVerdict: unknown signature alg '{alg}'");
        var judgeMeasurement = (string)IntentSemantic.StatementOf(new D { ["judgeMeasurement"] = v.GetValueOrDefault("judgeMeasurement") })["judgeMeasurement"]!;
        var pqPk = PqSuites.SuitePqPublicKey(alg, keys);
        var forStatement = new D(v) { ["judgeMeasurement"] = judgeMeasurement };
        if (resolved != "ed25519") { forStatement["alg"] = resolved; if (pqPk != null) forStatement["pq_pk"] = pqPk; }
        var statement = IntentSemantic.StatementOf(forStatement);
        var fields = PqSuites.SignSuiteArtifact(alg, PqSuites.SuiteKeysOf(secret, keys), SemanticJudgeMessage(statement));
        using var key = EdKey.FromSeed(secret);
        var o = new D
        {
            ["judge"] = key.Id, ["actionDigest"] = v.GetValueOrDefault("actionDigest"), ["goalCommitment"] = v.GetValueOrDefault("goalCommitment"), ["faithful"] = v.GetValueOrDefault("faithful") is true,
            ["score"] = v.GetValueOrDefault("score"), ["judgeMeasurement"] = judgeMeasurement, ["sig"] = fields.Sig,
        };
        if (fields.Alg != null) o["alg"] = fields.Alg;
        if (fields.PqPk != null) o["pq_pk"] = fields.PqPk;
        if (fields.PqSig != null) o["pq_sig"] = fields.PqSig;
        return o;
    }

    /// <summary>Whether a judge's hardware attestation vouches for its verdicts: <c>{ok, reason?, measured?}</c>. It must be ok and bound, carry a measured identity whose runtime measurement equals the signed
    /// <paramref name="judgeMeasurement"/> (a non-empty string) and satisfy the <paramref name="approved"/> agent binding.</summary>
    public static D VerifyJudgeAttestation(object? judgeMeasurement, object? attestation, object? approved)
    {
        static D No(object? reason) => new() { ["ok"] = false, ["reason"] = reason };
        if (attestation is not D a || a.GetValueOrDefault("ok") is not true)
            return No(attestation is D ad && ad.GetValueOrDefault("reason") is { } r ? r : "no verified attestation for this judge (fail-closed)");
        if (a.GetValueOrDefault("bound") is not true) return No("judge attestation not bound to a TEE report (report_data binding unconfirmed)");
        if (a.GetValueOrDefault("measured") is not D measured) return No("judge attestation carries no measured identity");
        if (judgeMeasurement is not string { Length: > 0 } jm) return No("verdict carries no judgeMeasurement to bind to the attested identity");
        if (!Equals(measured.GetValueOrDefault("runtime_measurement"), jm)) return No("attested enclave measurement does not match the signed judgeMeasurement");
        var appraisal = AttestationSoft.MatchAgentBinding(measured, approved);
        if (appraisal != null) return No(appraisal);
        return new D { ["ok"] = true, ["measured"] = measured };
    }

    static Func<D, bool>? Gate(SemanticAttestation? att) =>
        att is { Require: true } ? v => VerifyJudgeAttestation(v.GetValueOrDefault("judgeMeasurement"), att.Resolve(v), att.Approved)["ok"] is true : null;

    /// <summary>The k-of-n threshold (see <see cref="IntentSemantic.VerifySemanticThreshold"/>) with the attestation gate: with <c>att.Require</c> a verdict whose judge attestation fails does not vote.</summary>
    public static IntentSemantic.ThresholdResult VerifySemanticThreshold(object? verdicts, D opts, SemanticAttestation? att = null) => IntentSemantic.VerifySemanticThreshold(verdicts, opts, Gate(att));

    /// <summary>The pipeline hook over the threshold. Options: <c>judgeKeys</c>, <c>k</c>, <c>calibration</c>?, <c>optionalWhenAbsent</c>, <c>verdicts</c> (Func&lt;object?, object?&gt;: ctx to the verdicts, or
    /// <see cref="Absent"/>), <c>goalCommitment</c> (ctx to the goal commitment, or <see cref="Absent"/>), <c>actionDigest</c> (Func&lt;object?, string&gt;; default the strict hash of <c>ctx.pcactn.action</c>) and
    /// <c>attestation</c> (Func&lt;object?, SemanticAttestation?&gt;). The hook answers <c>{enforced: false}</c> (optional and absent) or <c>{enforced: true, ok, reason?}</c>; an absent ensemble is refused.</summary>
    public static Func<object?, D> CreateSemanticVerifier(D opts)
    {
        var o = new D(opts);
        var verdictsOf = (Func<object?, object?>)o["verdicts"]!;
        var goalOf = (Func<object?, object?>)o["goalCommitment"]!;
        var digestOf = o.GetValueOrDefault("actionDigest") as Func<object?, string> ?? (ctx => Pca.HashCanonical(((D)((D)((D)ctx!)["pcactn"]!)["action"]!)));
        var attOf = o.GetValueOrDefault("attestation") as Func<object?, SemanticAttestation?>;
        bool optional = o.GetValueOrDefault("optionalWhenAbsent") is true;
        return ctx =>
        {
            var goal = goalOf(ctx);
            var verdicts = verdictsOf(ctx);
            if (goal is not string || ReferenceEquals(verdicts, Absent))
                return optional ? new D { ["enforced"] = false } : new D { ["enforced"] = true, ["ok"] = false, ["reason"] = "no semantic ensemble available for this action (fail-closed)" };
            var att = attOf?.Invoke(ctx);
            var t = new D { ["judgeKeys"] = o.GetValueOrDefault("judgeKeys"), ["k"] = o.GetValueOrDefault("k"), ["goalCommitment"] = goal, ["actionDigest"] = digestOf(ctx) };
            if (o.GetValueOrDefault("calibration") != null) t["calibration"] = o["calibration"];
            var res = VerifySemanticThreshold(verdicts, t, att);
            return res.Ok ? new D { ["enforced"] = true, ["ok"] = true } : new D { ["enforced"] = true, ["ok"] = false, ["reason"] = res.Reason ?? "semantic threshold not met" };
        };
    }
}

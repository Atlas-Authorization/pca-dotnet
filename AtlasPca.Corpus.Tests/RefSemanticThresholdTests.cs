using AtlasPca;
using AtlasPca.IntentPkg;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Replay of the semantic judge threshold (test-data/ref-semantic-threshold.json.gz, 186 cases): the judge statement and its signed message, verdict signing under ed25519, ml-dsa-65 and the hybrid
/// (deterministic), the verdict digest and verification, the judge attestation gate, the k-of-n threshold with the attestation gate and key pins, the verifier hook and the risk contribution. A reference throw
/// requires a refusal. The reference's legacy option that accepts an unpinned post-quantum key (allowUnboundPq) does not exist here: the cases the reference accepts only through it are asserted REFUSED, by count.</summary>
public class RefSemanticThresholdTests
{
    const string M = "ref-semantic-threshold";
    static int Ruled;

    static object? Nums(object? v) => v switch
    {
        D m when m.Count == 1 && m.TryGetValue("$num", out var t) && t is string s => s == "NaN" ? double.NaN : s == "Infinity" ? double.PositiveInfinity : double.NegativeInfinity,
        D m => m.ToDictionary(e => e.Key, e => Nums(e.Value)),
        L l => l.Select(Nums).ToList(),
        _ => v,
    };

    static object? OutNum(double d) => double.IsNaN(d) ? new D { ["$num"] = "NaN" } : double.IsPositiveInfinity(d) ? new D { ["$num"] = "Infinity" } : double.IsNegativeInfinity(d) ? new D { ["$num"] = "-Infinity" } : d;

    static SemanticAttestation? Att(object? v)
    {
        if (v is not D m) return null;
        var by = m.GetValueOrDefault("byJudge") as D ?? new D();
        return new SemanticAttestation(verdict => verdict.GetValueOrDefault("judge") is string j ? by.GetValueOrDefault(j) : null, m.GetValueOrDefault("approved") as D, m.GetValueOrDefault("require") is true);
    }

    static object? Result(IntentSemantic.ThresholdResult t)
    {
        var r = t.ToJson();
        if (t.Cutoff != null) r["cutoff"] = OutNum(t.Cutoff.Value);
        return r;
    }

    static object? Threshold(L a)
    {
        var opts = (D)Nums(a[1])!;
        var plain = opts.Where(e => e.Key != "attestation").ToDictionary(e => e.Key, e => e.Value);
        return Result(SemanticThreshold.VerifySemanticThreshold(Nums(a[0]), plain, Att(opts.GetValueOrDefault("attestation"))));
    }

    static object? SignVerdict(L a)
    {
        string? alg = null;
        SuiteSecretKeys? keys = null;
        if (a.Count > 2 && a[2] is D su)
        {
            alg = su.GetValueOrDefault("alg") as string;
            if (su.GetValueOrDefault("pqSeed") is { } seed) keys = new SuiteSecretKeys { MlDsa = PqSuites.MlDsa65Keygen(Base.Bytes(seed)) };
        }
        return SemanticThreshold.SignJudgeVerdict(Base.Bytes(a[0]), (D)Nums(a[1])!, alg, keys);
    }

    static object? Hook(L a)
    {
        var o = (D)Nums(a[0])!;
        var opts = new D { ["judgeKeys"] = o["judgeKeys"], ["k"] = o["k"], ["optionalWhenAbsent"] = o.GetValueOrDefault("optionalWhenAbsent") is true };
        if (o.GetValueOrDefault("calibration") != null) opts["calibration"] = o["calibration"];
        opts["verdicts"] = (Func<object?, object?>)(ctx => ((D)ctx!).TryGetValue("verdicts", out var v) ? v : SemanticThreshold.Absent);
        opts["goalCommitment"] = (Func<object?, object?>)(ctx => ((D)ctx!).TryGetValue("goal", out var v) ? v : SemanticThreshold.Absent);
        opts["attestation"] = (Func<object?, SemanticAttestation?>)(ctx => Att(((D)ctx!).GetValueOrDefault("attestation")));
        if (o.GetValueOrDefault("actionDigestMode") is string mode && mode.StartsWith("fixed:", StringComparison.Ordinal))
        {
            var d = mode[6..];
            opts["actionDigest"] = (Func<object?, string>)(_ => d);
        }
        var hook = SemanticThreshold.CreateSemanticVerifier(opts);
        var outp = new L();
        foreach (var co in (L)a[1]!)
        {
            var raw = (D)co!;
            var ctx = new D { ["pcactn"] = raw["pcactn"] };
            foreach (var k in new[] { "verdicts", "goal", "attestation" }) if (raw.TryGetValue(k, out var v)) ctx[k] = Nums(v);
            outp.Add(hook(ctx));
        }
        return outp;
    }

    static bool UnboundOpt(object? pins) => pins is D p && p.GetValueOrDefault("allowUnboundPq") is true;

    static bool EqRuled(D c, int argIndex, object? have)
    {
        var want = c["out"];
        var pins = Base.Args(c).Count > argIndex ? Base.Args(c)[argIndex] : null;
        if (Base.Show(want) == Base.Show(have)) return true;
        if (UnboundOpt(pins) && (want is true || want is D w && w.GetValueOrDefault("ok") is true)) { Ruled++; return true; }
        return false;
    }

    /// <summary>A result with the non-finite doubles spelled as the corpus does ({"$num"}).</summary>
    static object? OutNums(object? v) => v switch
    {
        double d when !double.IsFinite(d) => OutNum(d),
        D m => m.ToDictionary(e => e.Key, e => OutNums(e.Value)),
        L l => l.Select(OutNums).ToList(),
        _ => v,
    };

    static void Fn(string fn, Func<L, object?> run, int min) => Base.Check(M, fn, a => Base.Json(OutNums(run(a))), null, null, min);

    [Fact] public void Constants() => Fn("constants", _ => SemanticThreshold.Constants(), 1);
    [Fact] public void QuantizeScore() => Fn("quantizeScore", a => IntentSemantic.QuantizeScore(IntentJs.NumOf(Nums(a[0])) ?? double.NaN), 26);
    [Fact] public void StatementOf() => Fn("statementOf", a => IntentSemantic.StatementOf((D)Nums(a[0])!), 21);
    [Fact] public void SemanticJudgeMessage() => Fn("semanticJudgeMessage", a => SemanticThreshold.SemanticJudgeMessage((D)Nums(a[0])!), 11);
    [Fact] public void VerdictDigest() => Fn("verdictDigest", a => SemanticThreshold.VerdictDigest(Nums(a[0])), 4);
    [Fact] public void SignJudgeVerdict() => Fn("signJudgeVerdict", SignVerdict, 13);
    [Fact] public void VerifyJudgeAttestation() => Fn("verifyJudgeAttestation", a => SemanticThreshold.VerifyJudgeAttestation(a[0], a.Count > 1 ? a[1] : null, a.Count > 2 ? a[2] : null), 18);
    [Fact] public void SemanticVerifierHook() => Fn("semanticVerifier", Hook, 12);
    [Fact] public void SemanticRiskContribution() => Fn("semanticRiskContribution", a => IntentRuntime.SemanticRiskContribution(IntentJs.NumOf(Nums(a[0])) ?? double.NaN), 14);

    [Fact]
    public void VerifyJudgeVerdictAndThreshold()
    {
        Ruled = 0;
        Base.Check(M, "verifyJudgeVerdict", a =>
        {
            var e = (D)a[1]!;
            var pins = a.Count > 2 && a[2] is D o ? o.GetValueOrDefault("pqPins") as D : null;
            return IntentSemantic.VerifyJudgeVerdict(a[0], e.GetValueOrDefault("actionDigest") as string, e.GetValueOrDefault("goalCommitment") as string, pins);
        }, (c, have) => EqRuled(c, 2, Base.Json(have)), null, 27);
        Base.Check(M, "verifySemanticThreshold", a => Base.Json(Threshold(a)), (c, have) => EqRuled(c, 1, have), null, 39);
        Assert.Equal(2, Ruled);
    }

    [Fact]
    public void Covers()
    {
        Base.Covers(M, new[]
        {
            "constants", "quantizeScore", "statementOf", "semanticJudgeMessage", "verdictDigest", "signJudgeVerdict", "verifyJudgeVerdict", "verifyJudgeAttestation", "verifySemanticThreshold",
            "semanticVerifier", "semanticRiskContribution",
        });
        Assert.Equal(186, Base.Total(M));
        var counts = Base.Cases(M).GroupBy(c => (string)c["fn"]!).ToDictionary(g => g.Key, g => g.Count());
        Assert.Equal(new Dictionary<string, int>
        {
            ["verifySemanticThreshold"] = 39, ["verifyJudgeVerdict"] = 27, ["quantizeScore"] = 26, ["statementOf"] = 21, ["verifyJudgeAttestation"] = 18, ["semanticRiskContribution"] = 14, ["signJudgeVerdict"] = 13,
            ["semanticVerifier"] = 12, ["semanticJudgeMessage"] = 11, ["verdictDigest"] = 4, ["constants"] = 1,
        }, counts);
    }
}

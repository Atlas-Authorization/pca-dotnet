using AtlasPca;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Differential oracle of the prohibition plane (test-data/k05-prohibitions.json.gz, TS reference packages/pca/src/prohibitions.ts): constitution and state
/// validation, the monitor grids around every boundary, advance, evidence, signed evidence and check-and-advance. Secrets are the base64url of a 32-byte Ed25519 seed.
/// Cases named <c>fn/x:</c> hold a value the canonical hash refuses (-0, an integer beyond 2^53-1, a lone surrogate) and replay together in <see cref="ExoticCases"/>.</summary>
public class ProhibitionsDiffTests
{
    const string M = "prohibitions";

    static D Verdict((bool Ok, string? Reason) v) => v.Ok ? new D { ["ok"] = true } : new D { ["ok"] = false, ["reason"] = v.Reason };
    static D Step((bool Ok, D? State, string? Reason) r) => r.Ok ? new D { ["ok"] = true, ["state"] = r.State } : new D { ["ok"] = false, ["reason"] = r.Reason };

    static D Row(InvariantEval e)
    {
        var d = new D { ["id"] = e.Id, ["kind"] = e.Kind, ["result"] = e.Result };
        if (e.ReasonValue != null) d["reason"] = e.ReasonValue;
        else if (e.Reason != null) d["reason"] = e.Reason;
        return d;
    }

    static D Res(ProhibitionResult r) => new() { ["ok"] = r.Ok, ["violated"] = r.Violated, ["reasons"] = r.Reasons, ["evaluated"] = r.Evaluated.Select(Row).ToList() };

    static byte[] Seed(object? a) => Pca.B64uDecode(a) ?? throw new InvalidDataException("bad seed");

    // a JS number argument that is not a number never satisfies the finite check
    static double NumArg(object? a) => IntentJs.NumOf(a) ?? double.NaN;

    static object? CheckAndAdvance(L a)
    {
        var o = a.Count > 4 ? (D)a[4]! : null;
        long? seq = null; string? dg = null;
        if (o != null)
        {
            // a head that is not an integer (null, text, fractional) never equals a state's seq: MinValue is no valid seq
            if (o.TryGetValue("expectedSeq", out var es)) seq = K05.IsJsonInt(es) ? IntentJs.Lng(es) : long.MinValue;
            dg = o.GetValueOrDefault("expectedStateDigest") as string;
        }
        var state = a[3] as D;
        var r = Prohibitions.CheckAndAdvance((bool)a[0]!, a[1] as D, a[2], state!, seq, dg);
        Assert.True(r.Allow || ReferenceEquals(r.Next, state), "a refusal keeps the input state");
        var res = new D
        {
            ["allow"] = r.Allow, ["decidedBy"] = r.DecidedBy, ["evidence"] = SafetyEvidence.Prove(a[1], a[2] as D, state), ["prohibition"] = Res(r.Prohibition),
            ["next"] = r.Allow ? r.Next : a[3],
        };
        if (r.Reason != null) res["reason"] = r.Reason;
        return res;
    }

    static object? Sign(L a)
    {
        using var key = EdKey.FromSeed(Seed(a[1]));
        return SafetyEvidence.Sign(a[0], key, a[2]);
    }

    static readonly Dictionary<string, Func<L, object?>> Impl = new()
    {
        ["validateInvariant"] = a => Prohibitions.ValidateInvariant(a[0]),
        ["validateConstitution"] = a => Prohibitions.ValidateConstitution(a[0]),
        ["stateProblem"] = a => Prohibitions.StateProblem(a[0]),
        ["canonicalState"] = a => a[0] is D s ? Prohibitions.CanonicalState(s) : K05.Refused,
        ["stateDigest"] = a => a[0] is D s ? Prohibitions.StateDigest(s) : K05.Refused,
        ["tickState"] = a => Step(Prohibitions.Tick(a[0] as D ?? null!, NumArg(a[1]))),
        ["emptyState"] = a => Prohibitions.EmptyState(IntentJs.Lng(a[0])),
        ["checkProhibitions"] = a => Res(Prohibitions.Check(a[0] as D, a[1], a[2])),
        ["advanceStateStrict"] = a => Step(Prohibitions.AdvanceStrict(a[0] as D, a[1], a[2] as D ?? null!, a.Count > 3 ? NumArg(a[3]) : null)),
        ["proveSafety"] = a => SafetyEvidence.Prove(a[0], a[1] as D, a[2] as D),
        ["verifySafetyEvidence"] = a => Verdict(SafetyEvidence.Verify(a[0], a[1], a[2] as D, a[3] as D)),
        ["safetyBindingId"] = a => a[0] is D e ? SafetyEvidence.BindingId(e, (string)a[1]!) : K05.Refused,
        ["signSafetyEvidence"] = Sign,
        ["verifySignedSafetyEvidence"] = a => Verdict(SafetyEvidence.VerifySigned(a[0], a[1])),
        ["checkAndAdvance"] = CheckAndAdvance,
        ["verifyConstitution"] = a => Verdict(SafetyEvidence.VerifyConstitution(a[0], a.Count > 1 ? (string?)a[1] : null)),
        ["constitutionId"] = a => SafetyEvidence.ConstitutionId((D)a[0]!),
        ["whenAffirmative"] = a => Prohibitions.WhenAffirmative(a[0], a[1] as D),
    };

    static bool IsExotic(D c, string fn) => ((string)c["name"]!).StartsWith(fn + "/x:", StringComparison.Ordinal);

    static int Replay(string fn, bool exotic = false, int min = 1) =>
        K05.Check(M, fn, Impl[fn], skip: c => IsExotic(c, fn) != exotic ? "other group" : null, min: min);

    // a typed long parameter takes only a plain JSON integer (not -0)
    static string? NotALong(D c) => K05.Args(c)[0] is Num n && K05.IsJsonInt(n) && n.Raw != "-0" ? null : "the typed API takes a long";

    [Fact] public void ValidateInvariant() => Replay("validateInvariant");
    [Fact] public void ValidateConstitution() => Replay("validateConstitution");
    [Fact] public void StateProblem() => Replay("stateProblem");
    [Fact] public void CanonicalState() => Replay("canonicalState");
    [Fact] public void StateDigest() => Replay("stateDigest");
    [Fact] public void TickState() => Replay("tickState");
    [Fact] public void EmptyState() => K05.Check(M, "emptyState", Impl["emptyState"], skip: NotALong, min: 3);
    [Fact] public void CheckProhibitions() => Replay("checkProhibitions");
    [Fact] public void AdvanceStateStrict() => Replay("advanceStateStrict");
    [Fact] public void ProveSafety() => Replay("proveSafety");
    [Fact] public void VerifySafetyEvidence() => Replay("verifySafetyEvidence");
    [Fact] public void SafetyBindingId() => Replay("safetyBindingId");
    [Fact] public void SignSafetyEvidence() => Replay("signSafetyEvidence");
    [Fact] public void VerifySignedSafetyEvidence() => Replay("verifySignedSafetyEvidence");
    [Fact] public void CheckAndAdvanceReplay() => Replay("checkAndAdvance");
    [Fact] public void VerifyConstitution() => Replay("verifyConstitution");
    [Fact] public void ConstitutionId() => Replay("constitutionId");
    [Fact] public void WhenAffirmative() => Replay("whenAffirmative");

    /// <summary>Inputs the canonical hash refuses, every fn replayed together.</summary>
    [Fact]
    public void ExoticCases()
    {
        int ran = 0;
        foreach (var fn in Impl.Keys.Where(f => f != "emptyState")) ran += Replay(fn, true, 0);
        Assert.True(ran > 0, "no exotic cases");
    }

    [Fact] public void EveryFn() => K05.Covers(M, Impl.Keys);
}

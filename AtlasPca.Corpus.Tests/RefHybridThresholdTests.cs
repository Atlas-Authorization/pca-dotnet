using AtlasPca;
using AtlasPca.PqThreshold;
using Xunit;
using T = AtlasPca.PqThreshold.PqThreshold;
using H = AtlasPca.PqThreshold.HybridThreshold;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Hybrid PQ threshold signer, step-up fold and core threshold hook (oracle: the reference's hybridThresholdSign, foldHybridStepUp, createHybridThresholdVerifier).
/// verifyHybridStepUp (fn "stepUp") runs the core verifier with the hybrid hook as its threshold check.</summary>
public class RefHybridThresholdTests
{
    const string M = "ref-pq-threshold-java-extra";

    static D O(object? o) => o as D ?? throw new ArgumentException("expected object");
    static L Lst(object? o) => o as L ?? throw new ArgumentException("expected array");
    static long Whole(object? o) => o is Num n ? (long)decimal.Parse(n.Raw, System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture) : throw new ArgumentException("expected number");

    /// <summary>{"$bytes": b64url} nodes become byte[] everywhere (the reference wrapper's un).</summary>
    static object? Un(object? a) => a switch
    {
        D m when Base.IsBytes(m) => Base.Bytes(m),
        D m => m.ToDictionary(e => e.Key, e => Un(e.Value)),
        L l => l.Select(Un).ToList(),
        _ => a,
    };

    [Fact]
    public void Fold() => Base.Check(M, "fold", a =>
    {
        var s = H.FoldHybridStepUp(O(a[0]), O(a[1]));
        var m = new D { ["pcactn"] = s.Pcactn };
        if (s.Pq != null) m["pq"] = s.Pq;
        return m;
    });

    [Fact]
    public void Hook() => Base.Check(M, "hook", a =>
    {
        var o = O(Un(a[0]));
        var v = new H.VerifierOpts(o.GetValueOrDefault("groupKey"), o.GetValueOrDefault("pqPublicKeys"), o.GetValueOrDefault("t"), o.GetValueOrDefault("pqT"), o.GetValueOrDefault("pqBlock"),
            o.GetValueOrDefault("groupDescriptor"), o.GetValueOrDefault("trustedAuthorities"), o.GetValueOrDefault("signerSetCommitment") as string);
        var r = H.CreateHybridThresholdVerifier(v)(O(a[1]), new D())!;
        var m = new D { ["enforced"] = r.Enforced, ["ok"] = r.Ok };
        if (r.Reason != null) m["reason"] = r.Reason;
        return m;
    });

    [Fact]
    public void StepUp() => Base.Check(M, "stepUp", a =>
    {
        var su = O(Un(a[0]));
        var o = O(Un(a[1]));
        var v = new H.VerifierOpts(o.GetValueOrDefault("groupKey"), o.GetValueOrDefault("pqPublicKeys"), o.GetValueOrDefault("t"), o.GetValueOrDefault("pqT"), su.GetValueOrDefault("pq"),
            o.GetValueOrDefault("groupDescriptor"), o.GetValueOrDefault("trustedAuthorities"), o.GetValueOrDefault("signerSetCommitment") as string);
        long? now = o.GetValueOrDefault("nowEpoch") is Num n ? Whole(n) : null;
        var r = H.VerifyHybridStepUp(new H.StepUp(O(su["pcactn"]), su.GetValueOrDefault("pq")),
            new H.StepUpOpts(O(o["grant"]), v, o.GetValueOrDefault("audience") as string, o.ContainsKey("audience"), now));
        var m = new D { ["allow"] = r.Allow, ["pq"] = r.Pq };
        if (r.Reason != null) m["reason"] = r.Reason;
        m["checks"] = r.Checks.ToDictionary(e => e.Key, e => (object?)e.Value);
        return m;
    });

    [Fact]
    public void HybridSign() => Base.Check(M, "hybridSign", a =>
    {
        var x = O(Un(a[0]));
        int t = (int)Whole(x["t"]), n = (int)Whole(x["n"]);
        var kg = Frost.TrustedDealerKeygen(t, n, new Frost.FrostKeygenOpts { Secret = (byte[])x["secret"]!, Coefficients = Lst(x["coefficients"]).Select(c => (byte[])c!).ToList() });
        var quorum = Lst(x["quorum"]).Select(id => kg.ParticipantShares.First(s => s.Identifier == Whole(id))).ToList();
        var keys = Lst(x["pqSeeds"]).Select(sd => PqKey.FromSeed(Pq.Prim.MlDsa65, (byte[])sd!)).ToList();
        var signers = Lst(x["pq"]).Select(i => keys[(int)Whole(i)]).ToList();
        int? pqT = x.GetValueOrDefault("pqT") == null ? null : (int)Whole(x["pqT"]);
        var signT = x.GetValueOrDefault("signT") == null ? t : (int)Whole(x["signT"]);
        object group = x.GetValueOrDefault("groupAsString") is true ? Pca.B64u(kg.GroupPublicKey) : kg.GroupPublicKey;
        var action = O(x["action"]);
        var artifact = H.HybridThresholdSign(action, new H.FrostQuorumInput(group, quorum, signT), signers, pqT);

        var parts = kg.ParticipantShares.Select(s => (object?)new D { ["identifier"] = new Num(s.Identifier.ToString()), ["publicKey"] = Pca.B64u(s.PublicKey) }).ToList();
        var authSeed = (byte[])x["authSeed"]!;
        var descriptor = T.IssueGroupDescriptor(authSeed, Pca.B64u(kg.GroupPublicKey), new Num(t.ToString()), parts);
        var opts = new D
        {
            ["groupKey"] = Pca.B64u(kg.GroupPublicKey), ["pqPublicKeys"] = keys.Select(k => (object?)k.PkB64u).ToList(), ["t"] = new Num(t.ToString()),
            ["pqT"] = new Num((pqT ?? signers.Count).ToString()), ["groupDescriptor"] = descriptor, ["trustedAuthorities"] = new L { EdKey.FromSeed(authSeed).Id },
        };
        var verdict = T.VerifyHybridThreshold(action, artifact, opts);

        var frost = new D(O(artifact["frost"]));
        var sig = (string)frost["sig"]!;
        frost.Remove("sig");
        frost["sigLen"] = sig.Length;
        var shown = new D(artifact) { ["frost"] = frost };
        return new D { ["artifact"] = shown, ["verdict"] = verdict };
    });

    [Fact]
    public void SignFoldRoundTrip()
    {
        var kg = Frost.TrustedDealerKeygen(2, 3, new Frost.FrostKeygenOpts { Secret = [9, 8, 7, 6, 5, 4, 3, 2, 1], Coefficients = [[1, 1, 2, 3, 5, 8, 13]] });
        var k = PqKey.FromSeed(Pq.Prim.MlDsa65, new byte[32]);
        var action = new D { ["ver"] = new Num("2"), ["aud"] = "rs", ["counter"] = new Num("1") };
        var artifact = H.HybridThresholdSign(action, new H.FrostQuorumInput(kg.GroupPublicKey, kg.ParticipantShares.GetRange(1, 2), 2), [k]);
        var folded = H.FoldHybridStepUp(action, artifact);
        Assert.Equal(Pca.ThresholdMessage(action), Pca.ThresholdMessage(folded.Pcactn)); // folding does not change the signed bytes
        Assert.Throws<ArgumentException>(() => H.HybridThresholdSign(action, new H.FrostQuorumInput(kg.GroupPublicKey, kg.ParticipantShares.GetRange(0, 1), 2), [k]));
    }

    [Fact] public void EveryFn() { Base.Covers(M, new[] { "fold", "hook", "hybridSign", "stepUp" }); Assert.Equal(100, Base.Total(M)); }
}

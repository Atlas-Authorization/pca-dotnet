using System.Globalization;
using System.Numerics;
using AtlasPca;
using AtlasPca.Ratchet;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Differential replay of the TypeScript reference for the capability ratchet package (test-data/ref-ratchet.json.gz). The reference provers draw
/// fresh randomness, so a recorded proof is replayed through the verifier (valid, out of range, over budget, tampered) and a prover is checked by
/// its refusals; the deterministic functions are compared exactly.</summary>
public class RefRatchetTests
{
    const string M = "ref-ratchet";

    // bytes {"$bytes"} and bigints {"$bigint"} arrive as JSON objects; revive them like the reference generator does
    static object? Rv(object? x)
    {
        if (x is L l) return new L(l.Select(Rv));
        if (x is D d)
        {
            if (d.Count == 1 && d.TryGetValue("$bytes", out var b)) return Base.Bytes(new D { ["$bytes"] = b });
            if (d.Count == 1 && d.TryGetValue("$bigint", out var n)) return BigInteger.Parse((string)n!, CultureInfo.InvariantCulture);
            var o = new D();
            foreach (var (k, v) in d) o[k] = Rv(v);
            return o;
        }
        return x;
    }

    static L Args(L a) => (L)Rv(a)!;
    static D Big(BigInteger b) => new() { ["$bigint"] = b.ToString(CultureInfo.InvariantCulture) };

    [Fact] public void LeafNullifier() => Base.Check(M, "leafNullifier", a => CapabilityRatchet.LeafNullifier((string)a[0]!, a[1]));
    [Fact] public void CounterToLeafIndex() => Base.Check(M, "counterToLeafIndex", a => RatchetAdapters.CounterToLeafIndex(a[0], a[1]));
    [Fact] public void LeafIndexToCounter() => Base.Check(M, "leafIndexToCounter", a => RatchetAdapters.LeafIndexToCounter(a[0]));
    [Fact] public void LeafIndexForAction() => Base.Check(M, "leafIndexForAction", a => RatchetAdapters.LeafIndexForAction(a[0], a[1]));
    [Fact] public void RiskToUnits() => Base.Check(M, "riskToUnits", a => Big(RatchetAdapters.RiskToUnits(a[0])));
    [Fact] public void BudgetCeilingUnits() => Base.Check(M, "budgetCeilingUnits", a => Big(RatchetAdapters.BudgetCeilingUnits(a[0])));

    [Fact]
    public void Quantizer() => Base.Check(M, "quantizer", a =>
    {
        var q = new RatchetAdapters.RiskQuantizer();
        var o = new L();
        foreach (var r in (L)a[0]!)
        {
            try { o.Add(Big(q.Next(r))); }
            catch (Exception) { o.Add(new D { ["$err"] = true }); }
        }
        o.Add(Big(q.TotalUnits));
        return o;
    });

    // ---- the ratchet scenario ----
    sealed class ThrowingStore : ISpentLeafStore
    {
        public Task<LeafClaim> ClaimAsync(string nullifier, string record) => throw new InvalidOperationException("boom");
    }

    static object? Child(object? t, object? k) => t switch
    {
        D d when k is string s => d.GetValueOrDefault(s),
        L l when IntentJs.NumOf(k) is double i && i >= 0 && i < l.Count && Math.Floor(i) == i => l[(int)i],
        _ => null,
    };

    // JSON.parse(JSON.stringify(v)) then t?.[...]... = value (or delete); an empty path sets the member named "undefined"
    static object? ClonePath(object? v, L path, object? value)
    {
        var c = Base.Deep(v);
        object? t = c;
        for (int i = 0; i < path.Count - 1; i++) t = Child(t, path[i]);
        var last = path.Count == 0 ? "undefined" : path[^1];
        if (t is D d)
        {
            string? key = last as string ?? (IntentJs.NumOf(last) is double n ? n.ToString(CultureInfo.InvariantCulture) : null);
            if (key != null)
            {
                if (value is string s && s == "__DEL__") d.Remove(key); else d[key] = value;
            }
        }
        else if (t is L l && IntentJs.NumOf(last) is double ix && ix >= 0 && ix < l.Count && Math.Floor(ix) == ix)
        {
            if (value is string s2 && s2 == "__DEL__") l.RemoveAt((int)ix); else l[(int)ix] = value;
        }
        return c;
    }

    static L Avail(RatchetState s) => new(CapabilityRatchet.AvailableLeaves(s).Select(x => (object?)x));

    static object? Scenario(L args)
    {
        var spec = (D)args[0]!;
        RatchetState? state = null;
        string? root = null;
        var sigs = new List<D>();
        ISpentLeafStore store = spec.GetValueOrDefault("store") as string == "throws" ? new ThrowingStore() : new MemorySpentLeafStore();
        var outp = new L();
        foreach (var s0 in (L)spec["ops"]!)
        {
            var s = (D)s0!;
            try
            {
                switch ((string)s["op"]!)
                {
                    case "derive":
                        {
                            var dr = CapabilityRatchet.DeriveRatchetRoot(s["seed"], s["depth"]);
                            state = dr.State; root = dr.RootCommitment;
                            outp.Add(new D { ["root"] = dr.RootCommitment, ["leafPubKeys"] = new L(dr.State.LeafPubKeys.Select(x => (object?)x)), ["available"] = Avail(dr.State) });
                            break;
                        }
                    case "sign":
                        {
                            var r = CapabilityRatchet.SignAtLeaf(state ?? throw new InvalidOperationException("no ratchet"), s["leaf"], (byte[])s["msg"]!);
                            state = r.NewState; sigs.Add(r.Signature);
                            outp.Add(new D { ["signature"] = r.Signature });
                            break;
                        }
                    case "avail": outp.Add(Avail(state!)); break;
                    case "isAvail": outp.Add(CapabilityRatchet.IsLeafAvailable(state!, IntentJs.NumOf(s["leaf"])!.Value)); break;
                    case "verify":
                    case "once":
                        {
                            object? sig = IntentJs.NumOf(s["sigRef"]) is double si && si >= 0 && si < sigs.Count ? sigs[(int)si] : null;
                            if (s.GetValueOrDefault("set") is L set)
                                foreach (var pv in set) { var pair = (L)pv!; sig = ClonePath(sig, (L)pair[0]!, pair[1]); }
                            var rc = s.GetValueOrDefault("root") as string == "other" ? "other-root" : root ?? "";
                            var msg = (byte[])s["msg"]!;
                            if ((string)s["op"]! == "verify") outp.Add(CapabilityRatchet.VerifyLeafSignature(rc, s["leaf"], msg, sig));
                            else outp.Add(RatchetBinding.VerifyLeafSignatureOnceAsync(rc, s["leaf"], msg, sig, store).GetAwaiter().GetResult().ToJson());
                            break;
                        }
                    default: throw new InvalidOperationException("bad op");
                }
            }
            catch (Exception e) { outp.Add(new D { ["$err"] = e is RatchetError re ? re.Code : true }); }
        }
        return outp;
    }

    [Fact] public void RatchetScenarios() => Base.Check(M, "ratchet", a => Scenario(Args(a)));

    // ---- accumulator ----
    [Fact]
    public void CommitRisk() => Base.Check(M, "commitRisk", a =>
    {
        var x = Args(a);
        if (x[1] is not BigInteger b) return Base.Refused; // the reference rejects a non-bigint blinding (a mixed-type modulo)
        var c = RiskAccumulator.CommitRisk(x[0], b);
        return new D { ["commitment"] = c.Commitment, ["blinding"] = Big(c.Blinding) };
    });

    [Fact] public void AddCommitments() => Base.Check(M, "addCommitments", a => RiskAccumulator.AddCommitments(Args(a)[0]));
    [Fact] public void OpenCommitment() => Base.Check(M, "openCommitment", a => { var x = Args(a); return RiskAccumulator.OpenCommitment(x[0], x[1], x[2]); });
    [Fact] public void VerifyRiskRange() => Base.Check(M, "verifyRiskRange", a => { var x = Args(a); return RiskAccumulator.VerifyRiskRange(x[0], x[1]); });
    [Fact] public void VerifyBudget() => Base.Check(M, "verifyBudget", a => { var x = Args(a); return RiskAccumulator.VerifyBudget(x[0], x[1], x[2]); });
    [Fact] public void VerifyBoundedBudget() => Base.Check(M, "verifyBoundedBudget", a => { var x = Args(a); return RiskAccumulator.VerifyBoundedBudget(x[0], x[1], x[2], x[3]); });

    // provers: the reference records only their refusals (the proofs are random); a native must refuse with the same code
    [Fact] public void ProveBudgetRefuses() => Base.Check(M, "proveBudget", a => { var x = Args(a); return RiskAccumulator.ProveBudget((L)x[0]!, (L)x[1]!, x[2]); });
    [Fact] public void ProveRiskRangeRefuses() => Base.Check(M, "proveRiskRange", a => { var x = Args(a); return RiskAccumulator.ProveRiskRange(x[0], x[1]); });

    [Fact]
    public void IssueRiskCommitmentRefuses() => Base.Check(M, "issueRiskCommitment", a =>
    {
        var x = Args(a);
        var key = x.Count > 2 && x[2] as string == "short" ? new byte[3] : new byte[32];
        return RatchetBinding.IssueRiskCommitment(x[0], x[1] as string ?? "", key).Commitment;
    });

    // ---- attestations ----
    [Fact] public void VerifyRiskAttestation() => Base.Check(M, "verifyRiskAttestation", a => { var x = Args(a); return RatchetBinding.VerifyRiskAttestation(x[0], x[1], x[2]); });
    [Fact] public void VerifyAttestedBudget() => Base.Check(M, "verifyAttestedBudget", a => { var x = Args(a); return RatchetBinding.VerifyAttestedBudget(x[0], x[1], x[2], x[3], x[4]); });

    // ---- the provers end to end (the corpus replays only verifiers): honest proofs verify, over-budget / altered ones do not ----
    [Fact]
    public void ProversRoundTrip()
    {
        var authority = new byte[32]; authority[0] = 7;
        using var key = EdKey.FromSeed(authority);
        var i1 = RatchetBinding.IssueRiskCommitment(3, "digest-1", authority);
        var i2 = RatchetBinding.IssueRiskCommitment(4, "digest-2", authority);
        Assert.True(RiskAccumulator.VerifyRiskRange(i1.Commitment, i1.RangeProof));
        Assert.False(RiskAccumulator.VerifyRiskRange(i2.Commitment, i1.RangeProof));
        Assert.True(RatchetBinding.VerifyRiskAttestation(i1.Commitment, i1.Attestation, key.Id));
        var blinds = new L { i1.Blinding, i2.Blinding };
        var ok = RiskAccumulator.ProveBudget(new L { 3, 4 }, blinds, 10);
        var over = RiskAccumulator.ProveBudget(new L { 3, 4 }, blinds, 6);
        var items = new L
        {
            new D { ["commitment"] = i1.Commitment, ["rangeProof"] = i1.RangeProof, ["attestation"] = i1.Attestation },
            new D { ["commitment"] = i2.Commitment, ["rangeProof"] = i2.RangeProof, ["attestation"] = i2.Attestation },
        };
        var digests = new L { "digest-1", "digest-2" };
        Assert.True(RatchetBinding.VerifyAttestedBudget(items, digests, key.Id, 10, ok));
        Assert.False(RatchetBinding.VerifyAttestedBudget(items, digests, key.Id, 6, over));
        Assert.False(RatchetBinding.VerifyAttestedBudget(items, new L { "digest-2", "digest-1" }, key.Id, 10, ok));
        var sum = RiskAccumulator.AddCommitments(new L { i1.Commitment, i2.Commitment });
        Assert.True(RiskAccumulator.VerifyBudget(sum, 7, RiskAccumulator.ProveBudget(new L { 3, 4 }, blinds, 7)));
        Assert.False(RiskAccumulator.VerifyBudget(sum, 6, RiskAccumulator.ProveBudget(new L { 3, 4 }, blinds, 6)));
    }

    [Fact]
    public void EveryFn() { Base.Covers(M, new[]
    {
        "leafNullifier", "counterToLeafIndex", "leafIndexToCounter", "leafIndexForAction", "riskToUnits", "budgetCeilingUnits", "quantizer", "ratchet",
        "commitRisk", "addCommitments", "openCommitment", "verifyRiskRange", "verifyBudget", "verifyBoundedBudget", "proveBudget", "proveRiskRange",
        "issueRiskCommitment", "verifyRiskAttestation", "verifyAttestedBudget",
    }); Assert.Equal(1095, Base.Total(M)); }
}

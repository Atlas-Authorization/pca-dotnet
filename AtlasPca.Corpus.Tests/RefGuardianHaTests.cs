using AtlasPca;
using AtlasPca.Js;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Replay of the guardian high-availability module over test-data/ref-ha.json.gz: liveness, quorum, degrade mode, signer selection and failover over guardian sets of
/// every malformed shape, the fence guard, the lease scripts (one fresh in-memory store per case, the store clock an operation, faults injected between the lease functions and
/// the store) and the raw compare-and-swap of the key/value lease store. A non-finite number is {"$num": text} in the corpus and a double here. The id tie-break of the signer
/// order is the platform's culture-invariant collation (ICU root on Linux), the order JavaScript's localeCompare gives.</summary>
public class RefGuardianHaTests
{
    const string M = "ref-ha", Key = "ha/lease";

    static object? Nums(object? v) => v switch
    {
        D m when m.Count == 1 && m.TryGetValue("$num", out var t) && t is string s => s == "NaN" ? double.NaN : s == "Infinity" ? double.PositiveInfinity : double.NegativeInfinity,
        D m => m.ToDictionary(e => e.Key, e => Nums(e.Value)),
        L l => l.Select(Nums).ToList(),
        _ => v,
    };

    static object? Out(object? v) => v switch
    {
        double d when double.IsNaN(d) => new D { ["$num"] = "NaN" },
        double d when double.IsPositiveInfinity(d) => new D { ["$num"] = "Infinity" },
        double d when double.IsNegativeInfinity(d) => new D { ["$num"] = "-Infinity" },
        D m => m.ToDictionary(e => e.Key, e => Out(e.Value)),
        L l => l.Select(Out).ToList(),
        _ => v,
    };

    // a clock reading: a number is itself, anything else (the corpus passes text) is not a usable time, which every function treats as NaN
    static double Time(object? x) => IntentJs.NumOf(x) ?? double.NaN;

    static object? Opts(L a, int i) => a.Count > i && a[i] != null ? Nums(a[i]) : null;

    [Fact] public void LiveGuardians() => Base.Check(M, "liveGuardians", a => Out(GuardianHa.LiveGuardians(Nums(a[0]), Time(Nums(a[1])), Opts(a, 2))), min: 144);
    [Fact] public void QuorumStatus() => Base.Check(M, "quorumStatus", a => Out(GuardianHa.QuorumStatus(Nums(a[0]), Time(Nums(a[1])), Opts(a, 2))), min: 144);
    [Fact] public void SelectSigners() => Base.Check(M, "selectSigners", a => Out(GuardianHa.SelectSigners(Nums(a[0]), Time(Nums(a[1])), Opts(a, 2))), min: 144);
    [Fact] public void FailoverPlan() => Base.Check(M, "failoverPlan", a => Out(GuardianHa.FailoverPlan(Nums(a[0]), Time(Nums(a[1])), Opts(a, 2))), min: 144);
    [Fact] public void DegradeMode() => Base.Check(M, "degradeMode", a => GuardianHa.DegradeMode(Nums(a[0]), Opts(a, 1)), min: 70);
    [Fact] public void ValidateGuardianSet() => Base.Check(M, "validateGuardianSet", a => GuardianHa.ValidateGuardianSet(Nums(a[0])), min: 33);

    [Fact]
    public void FenceGuard() => Base.Check(M, "fenceGuard", a =>
    {
        var g = new FenceGuard(Nums(a[0]));
        var admits = ((L)Nums(a[1])!).Select(e => (object?)g.Admit(e)).ToList();
        return new D { ["admits"] = admits, ["highest"] = g.Highest() };
    }, min: 11);

    [Fact]
    public void Constants() => Base.Check(M, "constants", _ => new D { ["MAX_LEASE_TTL_MS"] = GuardianHa.MaxLeaseTtlMs, ["DEFAULT_LEASE_SKEW_MS"] = GuardianHa.DefaultLeaseSkewMs }, min: 1);

    // the reference's fault injection: a store whose members throw "boom" on demand, or whose next compare-and-swap loses
    sealed class FaultStore : ILeaseStore
    {
        public readonly KvLeaseStore Inner;
        public string Fault = "none";
        public bool LoseOnce;
        public FaultStore(KvLeaseStore inner) { Inner = inner; }
        public D? Read() { if (Fault == "read") throw new InvalidOperationException("boom"); return Inner.Read(); }
        public double Now() { if (Fault == "now") throw new InvalidOperationException("boom"); return Inner.Now(); }
        public bool Cas(object? expected, object? next)
        {
            if (Fault == "cas") throw new InvalidOperationException("boom");
            if (LoseOnce) { LoseOnce = false; return false; }
            return Inner.Cas(expected, next);
        }
    }

    static object? Stored(MemoryAtomicKv kv) => kv.Get(Key) is { } t ? Pca.ParseJson(t) : null;

    [Fact]
    public void Lease() => Base.Check(M, "lease", a =>
    {
        var kv = new MemoryAtomicKv();
        double clock = 0;
        var store = new FaultStore(new KvLeaseStore(kv, null, () => clock));
        var refs = new Dictionary<string, D>();
        object? Res(object? x) => x is string s ? refs.GetValueOrDefault(s) : x;
        var res = new L();
        foreach (var oo in (L)Nums(a[0])!)
        {
            var op = (L)oo!;
            try
            {
                switch ((string)op[0]!)
                {
                    case "clock": clock = Time(op[1]); res.Add(null); break;
                    case "fault": if (op[1] is "loseCas") store.LoseOnce = true; else store.Fault = (string)op[1]!; res.Add(null); break;
                    case "raw": { var text = JsJson.Stringify(op[1]); kv.Update(Key, _ => text); res.Add(null); break; }
                    case "read": res.Add(Stored(kv)); break;
                    case "acquire":
                    {
                        var r = GuardianHa.AcquireLease(store, op[2], op[3]);
                        if (r["ok"] is true) refs[(string)op[1]!] = (D)r["lease"]!;
                        res.Add(r);
                        break;
                    }
                    case "renew":
                    {
                        var r = GuardianHa.RenewLease(store, Res(op[1]), op[2]);
                        if (r["ok"] is true && op[1] is string s) refs[s] = (D)r["lease"]!;
                        res.Add(r);
                        break;
                    }
                    case "release":
                    {
                        var r = GuardianHa.ReleaseLease(store, Res(op[1]));
                        if (r["ok"] is true && op[1] is string s) refs[s] = (D)r["lease"]!;
                        res.Add(r);
                        break;
                    }
                    case "fence": res.Add(op[2] == null ? GuardianHa.AssertFence(store, Res(op[1])) : GuardianHa.AssertFence(store, Res(op[1]), op[2])); break;
                    case "signer":
                    {
                        var l = op[1] == null ? null : Res(op[1]) as D;
                        Func<string> sign = () => { clock += Time(op[3]); if (op[4] is true) throw new InvalidOperationException("sign"); return "signed"; };
                        try
                        {
                            var r = op[2] == null ? GuardianHa.FencedSign(store, () => l, sign) : GuardianHa.FencedSign(store, () => l, sign, op[2]);
                            res.Add(new D { ["ok"] = true, ["result"] = r.Result, ["epoch"] = r.Epoch });
                        }
                        catch (FenceError fe) { res.Add(new D { ["ok"] = false, ["reason"] = fe.Reason }); }
                        catch (Exception e) { res.Add(new D { ["ok"] = false, ["error"] = e.Message }); }
                        break;
                    }
                    default: throw new InvalidOperationException("bad op");
                }
            }
            catch (Exception e) { res.Add(new D { ["$err"] = e.Message }); }
        }
        return Out(res);
    }, min: 45);

    [Fact]
    public void KvCas() => Base.Check(M, "kvCas", a =>
    {
        var kv = new MemoryAtomicKv();
        if (a[0] != null) { var text = JsJson.Stringify(Nums(a[0])); kv.Update(Key, _ => text); }
        var s = new KvLeaseStore(kv, null, () => 0);
        var ok = s.Cas(a[1] == null ? null : Nums(a[1]), Nums(a[2]));
        return Out(new D { ["ok"] = ok, ["stored"] = Stored(kv) });
    }, min: 17);

    [Fact]
    public void Covers()
    {
        Base.Covers(M, new[] { "liveGuardians", "quorumStatus", "degradeMode", "selectSigners", "failoverPlan", "validateGuardianSet", "fenceGuard", "lease", "kvCas", "constants" });
        Assert.Equal(753, Base.Total(M));
    }
}

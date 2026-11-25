using AtlasPca;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Replay of the liveness beacons (test-data/ref-beacons.json.gz, 174 cases): the signed message, issuing under the Ed25519, ML-DSA and hybrid suites, the beacon reference, verification with every reason, replay
/// acceptance, the frozen-liveness check and the durable acceptor over one fresh in-memory store per case (a stored junk value and a failing store included). The reference's legacy unbound-PQ opt-out does not exist
/// here: the one case it accepts only through that option is asserted REFUSED, by count. Every fn has a handler and the totals are asserted.</summary>
public class RefBeaconsTests
{
    const string M = "ref-beacons";
    static int Ruled;

    static object? Nums(object? v) => v switch
    {
        D m when m.Count == 1 && m.TryGetValue("$num", out var t) && t is string s => s == "NaN" ? double.NaN : s == "Infinity" ? double.PositiveInfinity : double.NegativeInfinity,
        D m => m.ToDictionary(e => e.Key, e => Nums(e.Value)),
        L l => l.Select(Nums).ToList(),
        _ => v,
    };

    static object? Issue(L a)
    {
        var o = (D)Nums(a[0])!;
        string? alg = null;
        SuiteSecretKeys? keys = null;
        if (o.GetValueOrDefault("suite") is D su)
        {
            alg = su.GetValueOrDefault("alg") as string;
            if (su.GetValueOrDefault("pqSeed") is { } seed) keys = new SuiteSecretKeys { MlDsa = PqSuites.MlDsa65Keygen(Base.Bytes(seed)) };
        }
        return BeaconOps.IssueLivenessBeacon(Base.Bytes(o["issuerSecret"]), o.TryGetValue("instance", out var inst) ? inst : AttestationSoft.Undef, o.GetValueOrDefault("scope"), o.GetValueOrDefault("seq"),
            o.GetValueOrDefault("issuedAt"), o.GetValueOrDefault("validityMs"), alg, keys);
    }

    sealed class TestKv : IAtomicKv
    {
        readonly MemoryAtomicKv _inner = new();
        public bool FailNext;
        public string? Get(string key) => _inner.Get(key);
        public void Update(string key, Func<string?, string?> fn)
        {
            if (FailNext) { FailNext = false; throw new InvalidOperationException("kv down"); }
            _inner.Update(key, fn);
        }
        public void Raw(string key, string text) => _inner.Update(key, _ => text);
    }

    static object? Acceptor(L a)
    {
        var kv = new TestKv();
        var acceptor = new BeaconAcceptor(kv);
        var outp = new L();
        foreach (var opo in (L)a[0]!)
        {
            var op = (L)opo!;
            switch ((string)op[0]!)
            {
                case "accept": outp.Add(acceptor.Accept(Nums(op[1]), (D)Nums(op[2])!)); break;
                case "raw": kv.Raw(BeaconAcceptor.SlotKey((D)op[1]!), JsCanon.Lenient(op[2])!); outp.Add(null); break;
                case "fail": kv.FailNext = true; outp.Add(null); break;
                default: outp.Add(new D { ["$err"] = "op" }); break;
            }
        }
        return outp;
    }

    static object? Ctor(L a)
    {
        var spec = a[0];
        IAtomicKv? kv = spec is "ok" || (spec is D d && d.GetValueOrDefault("update") is "fn") ? new MemoryAtomicKv() : null;
        try { _ = new BeaconAcceptor(kv); return new D { ["built"] = true }; }
        catch (ArgumentException) { return new D { ["built"] = false }; }
    }

    static bool EqRuled(D c, object? have)
    {
        if (Base.Show(c["out"]) == Base.Show(have)) return true;
        var chk = Base.Args(c).Count > 1 ? Base.Args(c)[1] : null;
        if (chk is D k && k.GetValueOrDefault("allowUnboundPq") is true && c["out"] is D w && w.GetValueOrDefault("ok") is true) { Ruled++; return true; }
        return false;
    }

    static void Fn(string fn, Func<L, object?> run, int min) => Base.Check(M, fn, a => Base.Json(run(a)), null, null, min);

    [Fact] public void Constants() => Fn("constants", _ => BeaconOps.Constants(), 1);
    [Fact] public void IssueLivenessBeacon() => Fn("issueLivenessBeacon", Issue, 36);
    [Fact] public void LivenessBeaconMessage() => Fn("livenessBeaconMessage", a => BeaconOps.LivenessBeaconMessage((D)Nums(a[0])!), 12);
    [Fact] public void BeaconRef() => Fn("beaconRef", a => BeaconOps.BeaconRef(Nums(a[0])), 8);
    [Fact] public void AcceptBeacon() => Fn("acceptBeacon", a => BeaconOps.AcceptBeacon(Nums(a[0]), Nums(a[1])), 18);
    [Fact] public void IsFrozenLiveness() => Fn("isFrozenLiveness", a => BeaconOps.IsFrozenLiveness(Nums(a[0]), (D)Nums(a[1])!), 8);
    [Fact] public void AcceptorOps() => Fn("acceptor", Acceptor, 19);
    [Fact] public void CtorCases() => Fn("ctor", Ctor, 5);

    [Fact]
    public void VerifyLivenessBeacon()
    {
        Ruled = 0;
        Base.Check(M, "verifyLivenessBeacon", a => Base.Json(BeaconOps.VerifyLivenessBeacon(Nums(a[0]), (D)Nums(a[1])!)), (c, have) => EqRuled(c, have), null, 67);
        Assert.Equal(1, Ruled);
    }

    [Fact]
    public void Covers()
    {
        Base.Covers(M, new[] { "constants", "issueLivenessBeacon", "livenessBeaconMessage", "beaconRef", "verifyLivenessBeacon", "acceptBeacon", "isFrozenLiveness", "acceptor", "ctor" });
        Assert.Equal(174, Base.Total(M));
        var counts = Base.Cases(M).GroupBy(c => (string)c["fn"]!).ToDictionary(g => g.Key, g => g.Count());
        Assert.Equal(new Dictionary<string, int>
        {
            ["verifyLivenessBeacon"] = 67, ["issueLivenessBeacon"] = 36, ["acceptor"] = 19, ["acceptBeacon"] = 18, ["livenessBeaconMessage"] = 12, ["beaconRef"] = 8, ["isFrozenLiveness"] = 8, ["ctor"] = 5, ["constants"] = 1,
        }, counts);
    }
}

using AtlasPca.Js;
using AtlasPca.Revoke;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Differential oracle of the revocation registry, the chain check and the CAEP bridge (test-data/ref-revoke.json.gz, TypeScript reference pca-revoke).
/// A scenario drives one registry through a script of steps; every step's result (or {"$err": true} when it threw) is compared.</summary>
public class RefRevokeTests
{
    const string M = "ref-revoke";

    /// <summary>An in-memory store whose get() or all() throws, like the reference's failing stores.</summary>
    sealed class FailingStore(IRevocationStore inner, bool failGet, bool failAll) : IRevocationStore
    {
        public Task Add(D entry) => inner.Add(entry);
        public Task<bool> Remove(string kind, string value) => inner.Remove(kind, value);
        public Task<D?> Get(string kind, string value) => failGet ? throw new InvalidOperationException("boom") : inner.Get(kind, value);
        public Task<IReadOnlyList<D>> All() => failAll ? throw new InvalidOperationException("boom") : inner.All();
        public Task Clear() => inner.Clear();
    }

    /// <summary>The frozen clock the corpus generator ran under (its header's clockMs).</summary>
    static readonly double Clock = Base.ClockMs(M);

    // an entry whose revokedAt is within two minutes of the wall clock, or of the corpus generator's frozen clock, is printed "<now>" on both sides
    static bool IsNow(double ms) => Math.Abs(ms - Clock) < 120_000;

    static object? Norm(object? v)
    {
        switch (v)
        {
            case L l: return l.Select(Norm).ToList();
            case D d:
                var o = new D();
                foreach (var (k, x) in d)
                    o[k] = k == "revokedAt" && x is Num n && IsNow(IntentJs.NumOf(n)!.Value) ? "<now>" : Norm(x);
                return o;
            default: return v;
        }
    }

    // JSON.parse(JSON.stringify(x)): numbers print as JavaScript prints them (-0 becomes 0)
    static object? Roundtrip(object? v) => Pca.ParseJson(JsJson.Stringify(v));

    static async Task<object?> Step(RevocationRegistry reg, D s)
    {
        D? Opts() => s.GetValueOrDefault("opts") as D;
        switch ((string)s["op"]!)
        {
            case "revoke": return await reg.Revoke(s.GetValueOrDefault("input") as D);
            case "revokeSubtree": return await reg.RevokeSubtree(s.GetValueOrDefault("target"), Opts());
            case "unrevoke": return await reg.Unrevoke(s.GetValueOrDefault("key") as D);
            case "list": return await reg.List();
            case "lookup": return await reg.Lookup((string)s["kind"]!, (string)s["value"]!);
            case "prefixes": return await reg.Prefixes();
            case "clear": await reg.Clear(); return null;
            case "killAgent": return await reg.KillAgent(s.GetValueOrDefault("holder"), Opts());
            case "killSubtree": return await reg.KillSubtree(s.GetValueOrDefault("root"), Opts());
            case "check": return await RevokeApi.CheckRevocation(s.GetValueOrDefault("p"), reg, Opts());
            case "verify": return await RevokeApi.VerifyWithRevocation(s.GetValueOrDefault("p"), s.GetValueOrDefault("core"), reg, Opts());
            case "ingest": return await RevokeApi.IngestCaepEvent(s.GetValueOrDefault("event"), reg);
            default: throw new InvalidOperationException("bad op");
        }
    }

    static async Task<L> Scenario(D spec)
    {
        var mem = new InMemoryRevocationStore();
        var store = (spec.GetValueOrDefault("store") as string) switch
        {
            "failGet" => new FailingStore(mem, true, false),
            "failAll" => new FailingStore(mem, false, true),
            _ => (IRevocationStore)mem,
        };
        var reg = new RevocationRegistry(store, () => Clock);
        var outp = new L();
        foreach (var raw in (L)spec["ops"]!)
        {
            try { outp.Add(Norm(Roundtrip(await Step(reg, (D)raw!)))); }
            catch (Exception) { outp.Add(new D { ["$err"] = true }); }
        }
        return outp;
    }

    [Fact] public void ScenarioReplay() => Base.Check(M, "scenario", a => Scenario((D)a[0]!).GetAwaiter().GetResult());
    [Fact] public void IsActiveAt() => Base.Check(M, "isActiveAt", a => RevokeApi.IsActiveAt((D)a[0]!, a[1]));
    [Fact] public void CaepEventTypes() => Base.Check(M, "caepEventTypes", a => RevokeApi.CaepEventTypes());

    [Fact] public void EveryFn() { Base.Covers(M, new[] { "scenario", "isActiveAt", "caepEventTypes" }); Assert.Equal(1921, Base.Total(M)); }
}

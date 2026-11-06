using AtlasPca;
using Xunit;
using static AtlasPca.Corpus.Tests.Conf;

namespace AtlasPca.Corpus.Tests;

// caveat-lang-vectors.json (caveat language v2, track K1): discharge verification, the K1 evaluator over grants and chains, caveat
// shapes, max_uses slot keys and reservations, SPIFFE ID syntax. Exact outcomes; a refusal reason is compared by `reason_contains`.
public class CaveatLangVectorTests
{
    static List<object?> Table(string name) => L(D(Load("caveat-lang-vectors.json")["primitives"])[name]);

    static readonly HashSet<string> Supported = new(Pq.SupportedSuites());

    // a non-integer or out-of-range clock is refused by the safe-integer check
    static long Clock(object? n)
    {
        var d = IntentJs.NumOf(n)!.Value;
        return d == Math.Floor(d) && Math.Abs(d) <= Pca.MaxSafeInt ? (long)d : long.MaxValue;
    }

    static List<DischargePin> Pins(object? o) => L(o).Select(p =>
    {
        var m = D(p);
        return new DischargePin((string)m["label"]!, (string)m["class"]!, (string)m["pk"]!, m.GetValueOrDefault("pq_pk") as string, m.GetValueOrDefault("spiffe_id") as string);
    }).ToList();

    static K1Input K1Of(Dictionary<string, object?> k)
    {
        var pins = k.ContainsKey("pins") ? Pins(k["pins"]) : null;
        var dis = k.ContainsKey("discharges") ? L(k["discharges"]) : null;
        var hist = k.ContainsKey("history") ? L(k["history"]) : null;
        var ad = k.GetValueOrDefault("action_digest") as string;
        var sp = k.GetValueOrDefault("spiffe_id") as string;
        var rev = k.ContainsKey("revoked_discharges") ? L(k["revoked_discharges"]).Cast<string>().ToList() : null;
        return k.ContainsKey("narrow")
            ? new K1Input { Pins = pins, Discharges = dis, History = hist, ActionDigest = ad, SpiffeId = sp, RevokedDischarges = rev, Narrow = k["narrow"] }
            : new K1Input { Pins = pins, Discharges = dis, History = hist, ActionDigest = ad, SpiffeId = sp, RevokedDischarges = rev };
    }

    [Fact]
    public void DischargeVerifyVectors()
    {
        var t = Table("discharge_verify");
        Assert.True(t.Count >= 54);
        int ran = 0;
        foreach (var x in t)
        {
            var v = D(x);
            var n = (string)v["name"]!;
            var i = D(v["input"]);
            var b = D(i["binding"]);
            var bind = new DischargeBinding((string)b["cap_hash"]!, Pins(b["pins"]), Clock(b["now"]), b.GetValueOrDefault("action_digest") as string,
                b.ContainsKey("revoked") ? L(b["revoked"]).Cast<string>().ToList() : null);
            var r = CaveatLang.VerifyDischarge(i["discharge"], i["caveat"], bind);
            var e = D(v["expect"]);
            if (v.GetValueOrDefault("requires_suite") is string need && !Supported.Contains(need))
            {
                Assert.True(!r.Ok && r.Reason!.Contains(IntentJs.UnsupportedSuite, StringComparison.Ordinal), $"{n}: suite {need} is not built: want {IntentJs.UnsupportedSuite}, got {r}");
                continue;
            }
            Assert.True((bool)e["ok"]! == r.Ok, $"{n}: ok={r.Ok} ({r.Reason})");
            if (r.Ok)
            {
                Assert.True((string)e["digest"]! == r.Digest, $"{n}: digest {r.Digest}");
                Assert.True(IntentJs.JsonEquals(e["claims"], r.Claims), $"{n}: claims");
            }
            else Assert.True(r.Reason!.Contains((string)e["reason_contains"]!, StringComparison.Ordinal), $"{n}: reason '{r.Reason}' lacks '{e["reason_contains"]}'");
            ran++;
        }
        Assert.True(ran >= 50, $"only {ran} discharge vectors ran");
    }

    [Fact]
    public void K1EvalVectors()
    {
        var t = Table("k1_eval");
        Assert.True(t.Count >= 102);
        foreach (var x in t)
        {
            var v = D(x);
            var n = (string)v["name"]!;
            var i = D(v["input"]);
            var k1 = i.ContainsKey("k1") && i["k1"] is Dictionary<string, object?> km ? K1Of(km) : null;
            var (allow, failed) = CaveatLang.EvaluateCaveatsK1(i["grant"], i["chain"], k1, D(i["context"]));
            var e = D(v["expect"]);
            Assert.True((bool)e["allow"]! == allow, $"{n}: allow={allow} failed=[{string.Join(",", failed)}]");
            Assert.True(L(e["failed"]).Cast<string>().SequenceEqual(failed), $"{n}: failed=[{string.Join(",", failed)}] want [{string.Join(",", L(e["failed"]))}]");
        }
    }

    [Fact]
    public void CaveatShapeVectors()
    {
        var t = Table("caveat_shape");
        Assert.True(t.Count >= 50);
        foreach (var x in t)
        {
            var v = D(x);
            var c = D(v["input"])["caveat"];
            string? err = IntentJs.Get(c, "type") switch
            {
                "needs_discharge" => CaveatLang.NeedsDischargeError(c),
                "max_uses" => CaveatLang.MaxUsesError(c),
                "derive" => CaveatLang.DeriveError(c),
                "spiffe_bound" => CaveatLang.SpiffeBoundError(c),
                _ => "unexpected type",
            };
            Assert.True((bool)D(v["expect"])["valid"]! == (err == null), $"{v["name"]}: error={err}");
        }
    }

    [Fact]
    public void UsesKeyVectors()
    {
        var t = Table("uses_key");
        Assert.True(t.Count >= 5);
        foreach (var x in t)
        {
            var v = D(x);
            var i = D(v["input"]);
            Assert.True((string)D(v["expect"])["key"]! == CaveatLang.MaxUsesSlotKey((string)i["cap_hash"]!, (string)i["id"]!, (int)N(i["i"])), (string)v["name"]!);
        }
    }

    [Fact]
    public void UsesReserveVectors()
    {
        var t = Table("uses_reserve");
        Assert.True(t.Count >= 12);
        foreach (var x in t)
        {
            var v = D(x);
            var n = (string)v["name"]!;
            var i = D(v["input"]);
            var bound = L(i["bound"]).Select(b => new BoundCaveat(D(b)["caveat"], 0, (string)D(b)["cap_hash"]!)).ToList();
            var want = L(D(v["expect"])["results"]);
            var calls = L(i["calls"]);
            Assert.Equal(want.Count, calls.Count);
            var store = new MemoryStateStore();
            for (int k = 0; k < calls.Count; k++)
            {
                var r = CaveatLang.ReserveMaxUses(store, bound, Clock(D(calls[k])["now"]));
                var e = D(want[k]);
                Assert.True((bool)e["ok"]! == r.Ok, $"{n}[{k}]: ok={r.Ok} ({r.Reason})");
                if (r.Ok) Assert.True(N(e["spent"]) == r.Spent, $"{n}[{k}]: spent {r.Spent}");
                else Assert.True(r.Reason!.Contains((string)e["reason_contains"]!, StringComparison.Ordinal), $"{n}[{k}]: reason '{r.Reason}' lacks '{e["reason_contains"]}'");
            }
        }
    }

    [Fact]
    public void SpiffeIdVectors()
    {
        var t = Table("spiffe_id");
        Assert.True(t.Count >= 24);
        foreach (var x in t)
        {
            var v = D(x);
            Assert.True((bool)D(v["expect"])["valid"]! == (CaveatLang.SpiffeIdError(D(v["input"])["id"]) == null), (string)v["name"]!);
        }
    }

    [Fact]
    public void K1UnconfiguredVectors()
    {
        var t = Table("k1_unconfigured");
        Assert.True(t.Count >= 9);
        foreach (var x in t)
        {
            var v = D(x);
            var i = D(v["input"]);
            var (allow, failed) = CaveatLang.EvaluateCaveatsK1(i["grant"], i["chain"], null, D(i["context"]));
            var e = D(v["expect"]);
            Assert.True((bool)e["allow"]! == allow && L(e["failed"]).Cast<string>().SequenceEqual(failed), $"{v["name"]}: allow={allow} failed=[{string.Join(",", failed)}]");
        }
    }

    [Fact]
    public void EmptyK1IsConfiguredAndAbsentK1RefusesEveryType()
    {
        var i = D(D(Table("k1_unconfigured").First(x => (string)D(x)["name"]! == "un-sealed"))["input"]);
        var ctx = new K1Context(N(D(i["context"])["now"]));
        var absent = CaveatLang.EvaluateK1(i["grant"], i["chain"], null, ctx);
        Assert.False(absent.Ok);
        Assert.Equal(new[] { "the caveat language is not configured (no k1 input)" }, absent.Reasons.ToArray());
        Assert.True(CaveatLang.EvaluateK1(i["grant"], i["chain"], new K1Input(), ctx).Ok);
    }

    [Fact]
    public void ConsumeOnceTtlVectors()
    {
        var t = Table("consume_once_ttl");
        Assert.True(t.Count >= 9);
        foreach (var x in t)
        {
            var v = D(x);
            var store = new MemoryStateStore();
            var got = L(D(v["input"])["steps"]).Select(st =>
            {
                var m = D(st);
                try { return store.ConsumeOnce((string)m["key"]!, N(m["retain_until"]), N(m["now"])) ? "true" : "false"; }
                catch (ArgumentException) { return "error"; }
            }).ToList();
            Assert.True(L(D(v["expect"])["results"]).Cast<string>().SequenceEqual(got), $"{v["name"]}: [{string.Join(",", got)}]");
        }
    }

    [Fact]
    public void ReserveMaxUsesSlotsExpire()
    {
        var cv = new Dictionary<string, object?> { ["type"] = "max_uses", ["id"] = "u", ["n"] = IntentJs.OfLong(1), ["until"] = IntentJs.OfLong(100) };
        var bound = new[] { new BoundCaveat(cv, 0, "c") };
        var store = new MemoryStateStore();
        Assert.True(CaveatLang.ReserveMaxUses(store, bound, 1).Ok);
        Assert.False(CaveatLang.ReserveMaxUses(store, bound, 2).Ok);
        // the slot is remembered until `until` only
        Assert.True(store.ConsumeOnce(CaveatLang.MaxUsesSlotKey("c", "u", 0), 200, 101));
    }

    [Fact]
    public void K1HeadersVectors()
    {
        var t = Table("k1_headers");
        Assert.True(t.Count >= 15);
        foreach (var x in t)
        {
            var v = D(x);
            var hs = D(D(v["input"])["headers"]).Select(kv => KeyValuePair.Create(kv.Key, (string)kv.Value!)).ToList();
            var r = CaveatLang.PresentedK1Of(hs);
            var e = D(v["expect"]);
            Assert.True((bool)e["ok"]! == r.Ok, $"{v["name"]}: ok={r.Ok} ({r.Reason})");
            if (!r.Ok) continue;
            var got = new Dictionary<string, object?>();
            if (r.Discharges != null) got["discharges"] = r.Discharges;
            if (r.HasNarrow) got["narrow"] = r.Narrow;
            Assert.True(IntentJs.JsonEquals(e["value"], got), $"{v["name"]}: value");
        }
    }

    [Fact]
    public void MergePresentedOwnWins()
    {
        var pr = new PresentedK1(true, new List<object?> { "a" }, true, "n");
        var own = new K1Input { Discharges = new List<object?> { "b" } };
        var m = CaveatLang.MergePresented(pr, own);
        Assert.Equal("b", m.Discharges![0]);
        Assert.True(m.HasNarrow && (string?)m.Narrow == "n");
        var bad = CaveatLang.MergePresented(new PresentedK1(false, Reason: "x"), null);
        Assert.Null(bad.Discharges);
        Assert.False(bad.HasNarrow);
    }

    [Fact]
    public void HostileInputsAreRefusedNotThrown()
    {
        var bind = new DischargeBinding("x", null, 1);
        foreach (var junk in new object?[] { null, "x", 5L, new List<object?>(), new Dictionary<string, object?>(), true })
        {
            Assert.False(CaveatLang.VerifyDischarge(junk, junk, bind).Ok);
            Assert.False(CaveatLang.VerifyNarrow(junk, junk, junk, new NarrowBinding(1)).Ok);
            Assert.NotNull(CaveatLang.NeedsDischargeError(junk));
            Assert.NotNull(CaveatLang.DischargeShapeError(junk));
            Assert.NotNull(CaveatLang.NarrowShapeError(junk));
            Assert.NotNull(CaveatLang.MaxUsesError(junk));
            Assert.NotNull(CaveatLang.DeriveError(junk));
            Assert.NotNull(CaveatLang.SpiffeBoundError(junk));
            Assert.NotNull(CaveatLang.SpiffeIdError(junk));
            Assert.Null(CaveatLang.BoundCaveats(junk, junk));
            var k = CaveatLang.EvaluateK1(junk, junk, null, new K1Context(1));
            Assert.False(k.Ok);
            Assert.Equal(new[] { "<malformed>" }, k.Failed.Distinct().ToArray());
            Assert.False(CaveatLang.EvaluateCaveatsK1(junk, junk, null, new Dictionary<string, object?>()).Allow);
        }
    }

    [Fact]
    public void ClockAndStoreFailuresFailClosed()
    {
        var cv = new Dictionary<string, object?> { ["type"] = "max_uses", ["id"] = "u", ["n"] = IntentJs.OfLong(1), ["until"] = IntentJs.OfLong(100) };
        var bound = new[] { new BoundCaveat(cv, 0, "c") };
        Assert.Equal(new UsesVerdict(false, 0, "the verifier clock is not a safe integer (fail closed)"), CaveatLang.ReserveMaxUses(new MemoryStateStore(), bound, long.MaxValue));
        Assert.True(CaveatLang.ReserveMaxUses(new ThrowingStore(), bound, 1).Reason!.StartsWith("max_uses error (fail closed)", StringComparison.Ordinal));
        Assert.True(CaveatLang.ReserveMaxUses(new NullStore(), bound, 1).Reason!.Contains("is exhausted", StringComparison.Ordinal));
        var bind = new DischargeBinding("x", Array.Empty<DischargePin>(), long.MaxValue);
        Assert.Contains("not a safe integer", CaveatLang.VerifyDischarge(null, null, bind).Reason);
        Assert.False(CaveatLang.EvaluateK1(null, null, null, new K1Context(long.MaxValue)).Ok);
    }

    sealed class ThrowingStore : IStateStore { public ClaimResult? Claim(string key, long counter) => throw new InvalidOperationException("boom"); }
    sealed class NullStore : IStateStore { public ClaimResult? Claim(string key, long counter) => null; }
}

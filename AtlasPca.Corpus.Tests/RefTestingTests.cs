using AtlasPca.Testing;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Replays the pca-testing oracle: acceptance constants and route mapping, the fake verifier and its assertions, tamper, the in-memory store.</summary>
public class RefTestingTests
{
    const string M = "ref-testing";

    static FakeVerifyOptions Opts(object? o)
    {
        var src = (D)o!;
        var r = new FakeVerifyOptions();
        if (src.ContainsKey("audience")) { r.Audience = src["audience"] as string; r.AudienceGiven = true; }
        if (src.GetValueOrDefault("now") != null) r.Now = Base.Long(src["now"]);
        if (src.GetValueOrDefault("grant") is D g) r.Grant = g;
        return r;
    }

    [Fact] public void Consts() => Base.Check(M, "consts", _ => new D { ["aud"] = PcaTesting.AdapterAcceptanceAudience, ["expected"] = PcaTesting.AdapterAcceptanceExpected() });
    [Fact] public void AcceptanceOperation() => Base.Check(M, "acceptanceOperation", a => PcaTesting.AcceptanceOperation((D)a[0]!));
    [Fact] public void FakeVerifyAllow() => Base.Check(M, "fakeVerifyAllow", a => PcaTesting.FakeVerify(a[0], Opts(a[1])).Allow);
    [Fact] public void ExpectVerifies() => Base.Check(M, "expectVerifies", a => PcaTesting.ExpectVerifies(a[0], Opts(a[1])).Allow);
    [Fact] public void ExpectDenied() => Base.Check(M, "expectDenied", a => PcaTesting.ExpectDenied(a[0], Opts(a[1])).Allow);

    [Fact]
    public void Tamper() => Base.Check(M, "tamper", a =>
    {
        var mut = (D)a[1]!;
        return PcaTesting.Tamper((string)a[0]!, rec =>
        {
            var op = (string)mut["op"]!;
            if (op == "none") return;
            var path = (L)mut["path"]!;
            object? cur = rec;
            for (int i = 0; i < path.Count - 1; i++) cur = ((D)cur!)[(string)path[i]!]; // a missing parent throws, as the reference does
            var holder = cur as D ?? throw new InvalidOperationException("Cannot set properties of undefined");
            var last = (string)path[^1]!;
            if (op == "set") holder[last] = mut["value"];
            else holder.Remove(last);
        });
    });

    [Fact]
    public void MemorySession() => Base.Check(M, "memorySession", a =>
    {
        var s = PcaTesting.MemoryStateStore();
        var outL = new L();
        foreach (var op in (L)a[0]!)
        {
            var o = (L)op!;
            if ((string)o[0]! == "put") s.Put((string)o[1]!, (D)o[2]!);
            else outL.Add(s.Get((string)o[1]!));
        }
        return outL;
    });

    /// <summary>A real agent built with the defaults verifies; a tampered one does not.</summary>
    [Fact]
    public void RoundTrip()
    {
        var a = PcaTesting.TestAgent();
        var made = PcaTesting.MakePCActn(a, "stripe.refund", "charge:ch_1", new D { ["amount"] = new Num("42") });
        Assert.True(PcaTesting.ExpectVerifies(made.Pcactn).Allow);
        var bad = Pca.ParseStrict(PcaTesting.Tamper(made.Encoded, r => ((D)r["action"]!)["verb"] = "stripe.payout"));
        Assert.Throws<InvalidOperationException>(() => PcaTesting.ExpectVerifies(bad));
        Assert.False(PcaTesting.ExpectDenied(bad).Allow);
    }

    [Fact] public void AllFnsCovered() { Base.Covers(M, new[] { "consts", "acceptanceOperation", "fakeVerifyAllow", "expectVerifies", "expectDenied", "tamper", "memorySession" }); Assert.Equal(2594, Base.Total(M)); }
}

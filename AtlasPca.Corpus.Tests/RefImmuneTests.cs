using System.Security.Cryptography;
using System.Text;
using AtlasPca.Research;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>The immune system (read side, adaptation, signed tightening proposals, durable store) against the TypeScript reference.</summary>
public class RefImmuneTests
{
    const string M = "ref-immune-java";
    const string R = "ref-core-research-java";

    static byte[] Seed(object? label) => SHA256.HashData(Encoding.UTF8.GetBytes("atlas-pca-conformance/immune/" + (string)label!));

    // the pinned guardian "@g" is the public key of the seed labelled g
    static D? Pin(object? opts)
    {
        if (opts is not D o) return null;
        if (o.GetValueOrDefault("guardian") is not string g || g != "@g") return o;
        var c = new D(o);
        using var key = EdKey.FromSeed(Seed("g"));
        c["guardian"] = key.Id;
        return c;
    }

    static D Err() => new() { ["$err"] = "Error" };

    [Fact] public void Assess() => Base.Check(R, "assess", a => Immune.Assess(a[0]));
    [Fact] public void ValidateState() => Base.Check(R, "validateImmuneState", a => Immune.ValidateImmuneState(a[0]));
    [Fact] public void Observe() => Base.Check(R, "observe", a => Immune.Observe((D)a[0]!, (D)a[1]!));
    [Fact] public void UpdateBaseline() => Base.Check(R, "updateBaseline", a => Immune.UpdateBaseline((D)a[0]!, Dbl(a[1])));
    [Fact] public void BaselineStd() => Base.Check(R, "baselineStd", a => Immune.BaselineStd((D)a[0]!));

    static double Dbl(object? o) => AtlasPca.Analyzer.Jx.ToNumber(o);

    [Fact] public void Adapt() => Base.Check(M, "adapt", a => Immune.Adapt(a[0], (D)a[1]!));
    [Fact] public void NoWiden() => Base.Check(M, "noWidenViolation", a => Immune.NoWidenViolation((D)a[0]!, (D)a[1]!));

    [Fact]
    public void Digests()
    {
        Base.Check(M, "policyDigest", a => Immune.PolicyDigest((D)a[0]!));
        Base.Check(M, "immuneStateDigest", a => Immune.ImmuneStateDigest((D)a[0]!));
    }

    [Fact] public void Issue() => Base.Check(M, "issueTighteningProposal", a => Immune.IssueTighteningProposal((D)a[0]!, (D)a[1]!, a[2], a[3], Seed(a[4])));
    [Fact] public void Apply() => Base.Check(M, "applyTightening", a => Immune.ApplyTightening((D)a[0]!, a[1] as D, Pin(a[2])!));

    [Fact]
    public void Store() => Base.Check(M, "store", a =>
    {
        var kv = new MemoryAtomicKv();
        var subject = (string)a[0]!;
        var st = Immune.CreateImmuneStore(kv, subject);
        var res = new L();
        foreach (var o in (L)a[1]!)
        {
            var op = (L)o!;
            try
            {
                switch ((string)op[0]!)
                {
                    case "seed": kv.Update("immune/state/" + subject, _ => Base.Show(op[1])); res.Add(null); break;
                    case "get": res.Add(st.Get()); break;
                    case "observe": res.Add(st.Observe((D)op[1]!)); break;
                    case "lastEpoch": res.Add(st.LastEpoch()); break;
                    case "apply": res.Add(st.Apply((D)op[1]!, op[2] as D, Pin(op[3])!)); break;
                    default: throw new InvalidOperationException("op " + op[0]);
                }
            }
            catch (Exception) { res.Add(Err()); }
        }
        return res;
    });

    [Fact]
    public void DefaultConfigs()
    {
        Assert.Equal(new[] { 0.3, 3_600_000.0, 3.0, 5.0, 3.0 }, Immune.DefaultImmuneConfig.Values.ToArray());
        Assert.Equal(new[] { 3.0, 0.4 }, Immune.DefaultAdaptConfig.Values.ToArray());
    }

    [Fact]
    public void Covers()
    {
        Base.Covers(M, new[] { "adapt", "noWidenViolation", "policyDigest", "immuneStateDigest", "issueTighteningProposal", "applyTightening", "store" });
        Assert.Equal(559, Base.Total(M));
    }
}

using System.Globalization;
using AtlasPca.GoalPkg;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Differential replay of the runtime drift monitor and the conformal risk control numerics.</summary>
public class RefGoalDriftTests
{
    const string M = "ref-goal-drift";
    static D O(object? o) => (D)o!;
    static L A(object? o) => (L)o!;
    static string S(object? o) => (string)o!;
    static double Dbl(object? o) => double.Parse(o is Num n ? n.Raw : S(o), CultureInfo.InvariantCulture);
    static byte[] Key(object? b64) => S(b64).Length == 0 ? Array.Empty<byte>() : Pca.B64uDecode(b64) ?? throw new InvalidDataException("key");

    [Fact]
    public void Flow() => Base.Check(M, "flow", a =>
    {
        var goal = O(a[0]);
        var opts = a[1] as D;
        var mon = new GoalDrift.Monitor(goal, opts);
        D? last = null;
        var outp = new L();
        foreach (var so in A(a[2]))
        {
            var s = O(so);
            switch (S(s["op"]))
            {
                case "observe": outp.Add(mon.observe(O(s["act"]), s["t"])); break;
                case "state": outp.Add(Base.Deep(mon.state())); break;
                case "seal": last = (D)Base.Deep(mon.seal(Key(s["key"])))!; outp.Add(Base.Deep(last)); break;
                case "restoreLast":
                    {
                        var sealedM = (D)Base.Deep(last)!;
                        var mode = S(s["mode"]);
                        if (mode == "state")
                        {
                            var st = new D((D)sealedM["state"]!);
                            st["strikes"] = new Num("0");
                            sealedM["state"] = st;
                        }
                        if (mode == "mac") { var mac = S(sealedM["mac"]); sealedM["mac"] = (mac[0] == '0' ? "1" : "0") + mac.Substring(1); }
                        if (mode == "badmac") sealedM["mac"] = "zz";
                        mon = GoalDrift.Monitor.Restore(goal, sealedM, Key(s["key"]), opts);
                        outp.Add(Base.Deep(mon.state()));
                        break;
                    }
                default:
                    outp.Add(Base.Deep(GoalDrift.GuardedDecide(goal, O(s["ont"]), mon, O(s["case"]), s["t"])));
                    break;
            }
        }
        return outp;
    });
    [Fact] public void ApplyDrift() => Base.Check(M, "applyDrift", a => GoalDrift.ApplyDrift(S(a[0]), O(a[1])));
    [Fact] public void AlphaOf() => Base.Check(M, "alphaOf", a => GoalCrc.AlphaOf(Dbl(a[0])));
    [Fact]
    public void Calibrate() => Base.Check(M, "calibrate", a =>
    {
        var gate = S(a[2]);
        double cap = gate == "none" ? 0 : Dbl(gate.Substring(2)) / 1e5;
        return GoalCrc.Calibrate(A(a[0]), O(a[1]), gate == "none" ? null : (k, n) => GoalCrc.CpUpper95(k, n) <= cap);
    });
    [Fact] public void AssertMonotone() => Base.Check(M, "assertMonotone", a => { GoalCrc.AssertMonotone(A(a[0])); return null; });
    [Fact] public void CpUpper95() => Base.Check(M, "cpUpper95", a => GoalCrc.CpUpper95(long.Parse(((Num)a[0]!).Raw, CultureInfo.InvariantCulture), long.Parse(((Num)a[1]!).Raw, CultureInfo.InvariantCulture)));
    [Fact] public void RenderReportMarkdown() => Base.Check(M, "renderReportMarkdown", a => GoalCrc.RenderReportMarkdown(A(a[0]), S(O(a[1])["source"]), S(O(a[1])["modelSet"])));

    [Fact]
    public void Covers() { Base.Covers(M, new[] { "flow", "applyDrift", "alphaOf", "calibrate", "assertMonotone", "cpUpper95", "renderReportMarkdown" }); Assert.Equal(152, Base.Total(M)); }
}

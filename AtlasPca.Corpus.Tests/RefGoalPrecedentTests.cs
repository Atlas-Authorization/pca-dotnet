using System.Globalization;
using AtlasPca.GoalPkg;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Differential replay of the hash-chained precedent log over signed escalation answers.</summary>
public class RefGoalPrecedentTests
{
    const string M = "ref-goal-precedent";
    static D O(object? o) => (D)o!;
    static L A(object? o) => (L)o!;
    static string S(object? o) => (string)o!;
    static byte[] Seed(object? o) => Pca.B64uDecode(o) ?? throw new InvalidDataException("seed");

    static object? EntryOut(D r, bool withCell)
    {
        if (r.GetValueOrDefault("ok") is not true) return r;
        var e = O(r["entry"]);
        var o = new D { ["ok"] = true, ["digest"] = e["digest"] };
        if (withCell) o["cell"] = e["cell"];
        o["seq"] = e["seq"];
        return o;
    }

    [Fact]
    public void Flow() => Base.Check(M, "flow", a =>
    {
        D goal = O(a[0]), ont = O(a[1]), grant = O(a[2]);
        var log = new GoalPrecedent.Log(A(a[3]));
        var space = GoalExamples.BuildSpace(new List<D> { goal }, new List<string>());
        var outp = new L();
        foreach (var so in A(a[4]))
        {
            var s = O(so);
            var op = S(s["op"]);
            long now = s.GetValueOrDefault("now") == null ? 0 : long.Parse(((Num)s["now"]!).Raw, CultureInfo.InvariantCulture);
            switch (op)
            {
                case "append": outp.Add(EntryOut(log.append(O(s["answer"]), O(s["answered"]), grant, space, now), true)); break;
                case "revoke": outp.Add(EntryOut(log.revoke(O(s["rev"])), false)); break;
                case "verifyChain": outp.Add(log.verifyChain(space)); break;
                case "lookup":
                    {
                        var h = log.lookup(S(s["policyDigest"]), space, O(s["case"]), now);
                        outp.Add(h == null ? null : new D { ["decision"] = h["decision"], ["digest"] = O(h["entry"])["digest"] });
                        break;
                    }
                case "authorize":
                    {
                        var r = GoalPrecedent.AuthorizeWithPrecedents(goal, ont, S(s["policyDigest"]), log, O(s["case"]), now);
                        var o2 = new D { ["decision"] = r["decision"], ["via"] = r["via"] };
                        if (r.GetValueOrDefault("precedent") != null) o2["digest"] = O(r["precedent"])["digest"];
                        outp.Add(o2);
                        break;
                    }
                case "tamper":
                    {
                        var e = log.entries()[int.Parse(((Num)s["index"]!).Raw, CultureInfo.InvariantCulture)];
                        if (s.GetValueOrDefault("del") is true) e.Remove(S(s["key"])); else e[S(s["key"])] = s.GetValueOrDefault("value");
                        outp.Add(true);
                        break;
                    }
                default: outp.Add(log.head()); break;
            }
        }
        return outp;
    });
    [Fact] public void CeilingsOf() => Base.Check(M, "ceilingsOf", a => GoalPrecedent.CeilingsOf(O(a[0])));
    [Fact]
    public void AnswerBodyFor() => Base.Check(M, "answerBodyFor", a =>
    {
        var o = O(a[1]);
        return GoalPrecedent.AnswerBodyFor(O(a[0]), S(o["principal"]), S(o["decision"]), o["iat"], o["expires_at"], S(o["nonce"]));
    });
    [Fact] public void SignRevocationSeed() => Base.Check(M, "signRevocationSeed", a => GoalPrecedent.SignRevocation(O(a[0]), Seed(a[1])));

    [Fact]
    public void Covers() { Base.Covers(M, new[] { "flow", "ceilingsOf", "answerBodyFor", "signRevocationSeed" }); Assert.Equal(34, Base.Total(M)); }
}

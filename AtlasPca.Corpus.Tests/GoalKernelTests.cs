using AtlasPca.GoalPkg;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>
/// Replay of the proved goal kernel (GoalKernel over the Dafny translation in AtlasPca/GoalKernel/Generated). (1) the kernel tape
/// corpus (the goal-kernel corpus in test-data, from the reference's extracted JavaScript kernel on the goal conformance vectors):
/// every op's output tape must be identical; (2) the typed front door on the goal conformance vectors when the layout has them.
/// Without the translation the kernel tests pass vacuously, unless PCA_GOAL_KERNEL_REQUIRE=1 (CI after extraction), where they fail.
/// </summary>
public class GoalKernelTests
{
    const string M = "ref-goal-kernel";

    static bool Kernel()
    {
        if (GoalKernel.Available()) return true;
        Assert.False(Environment.GetEnvironmentVariable("PCA_GOAL_KERNEL_REQUIRE") == "1", "PCA_GOAL_KERNEL_REQUIRE=1 but the extracted goal kernel is missing");
        return false;
    }

    static L Tape(object? s)
    {
        var t = GoalKernel.TapeFromText((string)s!);
        Assert.Equal((string)s!, GoalKernel.TapeToText(t));
        return t;
    }

    [Fact]
    public void TapeText()
    {
        var cases = Base.Of(M, "kernel").ToList();
        Base.Covers(M, new[] { "kernel" });
        Assert.Equal(203, cases.Count);
        foreach (var c in cases) { Tape(Base.Args(c)[0]); Tape(Base.Args(c)[1]); }
        var x = GoalKernel.TapeFromText("k5 i-3 s s68.1f600");
        Assert.Equal("k5 i-3 s s68.1f600", GoalKernel.TapeToText(x));
        Assert.Equal("h\U0001F600", ((L)x[3]!)[1]);
    }

    [Fact]
    public void KernelTapes()
    {
        if (!Kernel()) return;
        var bad = new List<string>();
        foreach (var c in Base.Of(M, "kernel"))
        {
            var args = Base.Args(c);
            var want = (D)c["out"]!;
            L g = Tape(args[0]), o = Tape(args[1]);
            foreach (var op in new[] { "typecheck", "compile", "render" })
                if (GoalKernel.TapeToText(GoalKernel.Call(op, g, o)) != (string)want[op]!) bad.Add($"{c["name"]} {op}");
            var probes = (L)args[2]!;
            var outs = (L)want["probes"]!;
            Assert.Equal(probes.Count, outs.Count);
            for (int i = 0; i < probes.Count; i++)
            {
                var p = (L)probes[i]!;
                var w = (L)outs[i]!;
                L a = Tape(p[0]), h = Tape(p[1]);
                if (GoalKernel.TapeToText(GoalKernel.Call("decideg", g, o, a, h)) != (string)w[0]!) bad.Add($"{c["name"]}#{i} decideg");
                if (GoalKernel.TapeToText(GoalKernel.Call("decidep", g, o, a, h)) != (string)w[1]!) bad.Add($"{c["name"]}#{i} decidep");
            }
        }
        Assert.True(bad.Count == 0, $"{bad.Count} divergent tape(s): " + string.Join(", ", bad.Take(25)));
    }

    /// <summary>The typed front door's RenderTape is the kernel's: same tape as the corpus render of every canonical goal tape.</summary>
    [Fact]
    public void CompilerRenderTapeReplaysCorpus()
    {
        if (!Kernel()) return;
        var bad = new List<string>();
        foreach (var c in Base.Of(M, "kernel"))
        {
            var g = Tape(Base.Args(c)[0]);
            D goal;
            try { goal = GoalCodec.DecodeGoal(g); } catch (Exception) { continue; }  // a malformed goal tape has no typed goal
            if (GoalKernel.TapeToText(GoalCodec.EncodeGoal(goal)) != GoalKernel.TapeToText(g)) continue;  // not canonical
            if (GoalKernel.TapeToText(GoalCompiler.RenderTape(goal)) != System.Text.RegularExpressions.Regex.Replace((string)((D)c["out"]!)["render"]!, "^i0 ?", "")) bad.Add((string)c["name"]!);
        }
        Assert.True(bad.Count == 0, $"{bad.Count} divergent render(s): " + string.Join(", ", bad.Take(25)));
    }

    /// <summary>A string token of a million characters crosses the bridge and the proved code without a stack overflow.</summary>
    [Fact]
    public void HugeStringDoesNotOverflow()
    {
        if (!Kernel()) return;
        var big = new L { new L { "s", new string('a', 1 << 20) } };
        foreach (var op in new[] { "typecheck", "compile", "render" })
            Assert.Equal("i", (string)((L)GoalKernel.Call(op, big, new L())[0]!)[0]!);
    }

    [Fact]
    public void MalformedIsRefused()
    {
        if (!Kernel()) return;
        var bad = GoalKernel.TapeFromText("i7");
        Assert.Equal("i9", GoalKernel.TapeToText(GoalKernel.Call("typecheck", bad, new L())));
        Assert.Throws<ArgumentException>(() => GoalKernel.Call("nope", bad, bad));
        Assert.ThrowsAny<Exception>(() => GoalKernel.Call("typecheck", GoalKernel.TapeFromText("k9007199254740992"), bad));
    }

    static bool SameWitness(object? a, object? b)
    {
        if (a == null || b == null) return a == null && b == null;
        D x = (D)a, y = (D)b;
        return (string?)x["gid"] == (string?)y["gid"] && ((L)x["bids"]!).Cast<string>().SequenceEqual(((L)y["bids"]!).Cast<string>());
    }

    static int Rank(string d) => d switch { "deny" => 0, "escalate" => 1, "allow" => 2, _ => throw new ArgumentException("decision " + d) };

    /// <summary>Strip (formal GoalCompile): drop every grant a hole depends on (a global hole, or one that lists the grant's gid in affects) and empty the holes.</summary>
    static D Strip(D goal)
    {
        var holes = (L)goal["holes"]!;
        bool Depends(string gid) => holes.Cast<D>().Any(h => (h["global"] as bool? ?? false) || ((L)h["affects"]!).Cast<string>().Contains(gid));
        var o = new D(goal)
        {
            ["grants"] = new L(((L)goal["grants"]!).Where(g => !Depends((string)((D)g!)["gid"]!))),
            ["holes"] = new L(),
        };
        return o;
    }

    [Fact]
    public void TypedFrontDoorOnConformanceVectors()
    {
        if (!Kernel()) return;
        string dir;
        try { dir = Conf.GoalDir(); } catch (Exception) { return; } // the conformance vectors are not in this layout
        var bad = new List<string>();
        foreach (var f in Directory.GetFiles(dir, "*.json").Where(f => Path.GetFileName(f) != "index.json").OrderBy(f => f, StringComparer.Ordinal))
        {
            var v = (D)FixtureJson.Parse(File.ReadAllText(f))!;
            if ((v.GetValueOrDefault("kind") as string) == "fn") continue;
            D goal = (D)v["goal"]!, ont = (D)v["ontology"]!, comp = (D)v["compile"]!;
            var id = (string)v["id"]!;
            if (!GoalKernel.Typecheck(goal, ont).SequenceEqual(((L)comp["reasons"]!).Cast<string>())) bad.Add(id + ": reasons");
            var r = GoalKernel.CompileGoal(goal, ont);
            var pd = (bool)r["ok"]! ? GoalCompiler.PolicyDigest((D)r["policy"]!) : null;
            if (pd != (v["policy_digest"] as string)) bad.Add(id + ": policy_digest");
            var rt = GoalKernel.RenderTape(goal);
            if (GoalKernel.TapeToText(rt) != GoalKernel.TapeToText(GoalCodec.EncodeGoal(GoalCodec.DecodeGoal(rt)))) bad.Add(id + ": render");
            if (!(bool)comp["ok"]!) continue;
            var probes = (L)v["probes"]!;
            for (int i = 0; i < probes.Count; i++)
            {
                var p = (D)probes[i]!;
                var exp = (D)p["expect"]!;
                D act = (D)p["action"]!, hist = (D)p["history"]!;
                var d = GoalKernel.DecidePolicy(goal, ont, act, hist);
                bool ok = (bool)d["ok"]!;
                var dec = ok ? (string)d["decision"]! : "deny";
                if (dec != (string)exp["decision"]! || !SameWitness(ok ? d["witness"] : null, exp["witness"])) bad.Add($"{id}#{i}: {dec}");
                if (ok && dec == "allow" && !(bool)d["witnessChecked"]!) bad.Add($"{id}#{i}: witness not checked");
                if (ok)
                {
                    // the compiler lowers Strip(goal) (grants a hole touches dropped, holes emptied): the policy equals the goal decision of the stripped goal exactly,
                    // and is never more permissive than the goal's own decision (a hole-free goal strips to itself, so that is the strict equality)
                    var stripped = Strip(goal);
                    if (GoalKernel.DecideGoal(stripped, ont, act, hist) != dec) bad.Add($"{id}#{i}: DecideGoal(Strip) != DecidePolicy");
                    if (Rank(dec) > Rank(GoalKernel.DecideGoal(goal, ont, act, hist))) bad.Add($"{id}#{i}: policy more permissive than DecideGoal");
                }
            }
        }
        Assert.True(bad.Count == 0, $"{bad.Count} divergence(s): " + string.Join(", ", bad.Take(25)));
    }

    [Fact]
    public void ProvedKernelPlugsIntoReview()
    {
        if (!Kernel()) return;
        Assert.True(GoalKernel.ProvedKernel().CanDecide());
    }
}

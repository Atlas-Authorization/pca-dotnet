using System.IO.Compression;
using System.Text;
using AtlasPca;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Differential tests of IntentWB (the W-B unit, rules 16-18): every case of test-data/k042-wbmisc.json.gz (the TS reference
/// decideIntentWB, written by tools/pca-audit/java-mutate/k042-wbmisc-oracle.mjs) compares the FULL result with the reference:
/// outcome, checks in order, exact reason, friction, world / prov / class env members and single_source.</summary>
public class WbMiscOracleTests
{
    /// <summary>The fail-closed evaluation-error text reports the .NET exception type where TS reports its message; the deny and every
    /// other member still match.</summary>
    static readonly Dictionary<string, string> EvalErrorText = new()
    {
        ["lift/cls/content-too-deep"] = "classes: evaluation error (fail closed): ",
    };

    static readonly Lazy<L> Cases = new(() =>
    {
        var d = AppContext.BaseDirectory;
        for (int i = 0; i < 12 && d != null; i++, d = Path.GetDirectoryName(d))
        {
            var f = Path.Combine(d, "test-data", "k042-wbmisc.json.gz");
            if (!File.Exists(f)) f = Path.Combine(d, "AtlasPca.Corpus.Tests", "test-data", "k042-wbmisc.json.gz");
            if (!File.Exists(f)) continue;
            using var gz = new GZipStream(File.OpenRead(f), CompressionMode.Decompress);
            using var sr = new StreamReader(gz, new UTF8Encoding(false));
            return (L)((D)Pca.ParseJson(sr.ReadToEnd())!)["cases"]!;
        }
        throw new FileNotFoundException("test-data/k042-wbmisc.json.gz");
    });

    static D Got(IntentWB.Result r) => new()
    {
        ["outcome"] = r.Outcome,
        ["checks"] = r.Checks.Select(e => (object?)new L { e.Key, e.Value }).ToList(),
        ["reason"] = r.Reason,
        ["friction"] = r.Friction,
        ["world"] = r.World,
        ["prov"] = r.Prov,
        ["class"] = r.Class,
        ["single_source"] = r.SingleSource?.Cast<object?>().ToList(),
    };

    static int Run(params string[] prefixes)
    {
        var bad = new List<string>(); int n = 0;
        foreach (D c in Cases.Value)
        {
            var name = (string)c["name"]!;
            if (!prefixes.Any(p => name.StartsWith(p, StringComparison.Ordinal))) continue;
            n++;
            var input = (D)IntentJs.Normalize(c["input"])!;
            IntentWB.Result r;
            try { r = IntentWB.Decide(input); } catch (Exception e) { bad.Add(name + ": threw " + e); continue; }
            var want = (D)IntentJs.Normalize(c["expect"])!;
            var have = Got(r);
            if (EvalErrorText.TryGetValue(name, out var pre))
            {
                if (have["reason"] is string hr && hr.StartsWith(pre, StringComparison.Ordinal)) have["reason"] = want["reason"];
            }
            var w = Pca.Canonicalize(want); var h = Pca.Canonicalize(have);
            if (w != h) bad.Add($"{name}\n   want {w}\n   have {h}");
        }
        Assert.True(bad.Count == 0, bad.Count + " mismatches:\n" + string.Join("\n", bad.Take(40)));
        return n;
    }

    [Fact] public void ContextShape() => Assert.True(Run("ctx/", "wb/ctx-") > 60);
    [Fact] public void GoUnitCases() => Assert.True(Run("wb/") >= 30);
    [Fact] public void LiftedWorld() => Assert.True(Run("lift/world/") > 100);
    [Fact] public void LiftedProvenance() => Assert.True(Run("lift/prov/") > 100);
    [Fact] public void LiftedClassifiers() => Assert.True(Run("lift/cls/") > 40);
    [Fact] public void DroppedMembers() => Assert.True(Run("drop-", "other-") > 150);
    [Fact] public void DenyClearsEarlierEnv() => Assert.True(Run("then-") >= 20);

    [Fact]
    public void EveryCaseIsRun()
    {
        int total = 0;
        foreach (var p in new[] { "ctx/", "wb/", "lift/world/", "lift/prov/", "lift/cls/", "drop-", "other-", "then-" })
            total += Cases.Value.Count(o => ((string)((D)o!)["name"]!).StartsWith(p, StringComparison.Ordinal));
        Assert.Equal(Cases.Value.Count, total);
    }
}

using System.Text;
using AtlasPca;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Rule 15 (accumulators / monitors, pre-states, reservation receipts, sequencer key sets, receipts against the sequenced
/// holder) differential tests against the TS reference intent-acc.ts: test-data/k042-intentacc.json is written by
/// tools/pca-audit/java-mutate/k042-intentacc-oracle.mjs; every case compares the EXACT reason / verdict / value as canonical JSON.</summary>
public class IntentAccOracleTests
{
    static readonly Lazy<L> Cases = new(() =>
    {
        var d = AppContext.BaseDirectory;
        for (int i = 0; i < 12 && d != null; i++, d = Path.GetDirectoryName(d))
        {
            var f = Path.Combine(d, "test-data", "k042-intentacc.json");
            if (!File.Exists(f)) f = Path.Combine(d, "AtlasPca.Corpus.Tests", "test-data", "k042-intentacc.json");
            if (File.Exists(f)) return (L)Pca.ParseJson(File.ReadAllText(f, new UTF8Encoding(false)))!;
        }
        throw new FileNotFoundException("test-data/k042-intentacc.json");
    });

    static L Args(D c) => (L)c["args"]!;
    static D M(object? o) => (D)o!;
    static string S(object? o) => (string)o!;
    static double Dbl(object? o) => IntentJs.NumOf(o)!.Value;

    internal static object? ToJson(object? o) => o switch
    {
        long v => new Num(v.ToString()),
        int v => new Num(v.ToString()),
        IntentAcc.AccValue v => v.Reason != null
            ? new D { ["ok"] = false, ["reason"] = v.Reason }.Also(r => { if (v.Val != 0 || v.Key != null) r["leaked"] = v.Val + "/" + v.Key; })
            : new D { ["ok"] = true, ["val"] = new Num(v.Val.ToString()), ["key"] = v.Key },
        List<string> v => v.Cast<object?>().ToList(),
        _ => o,
    };

    internal static void Run(string fn, Func<L, object?> f, L? cases = null)
    {
        var bad = new List<string>(); int n = 0;
        foreach (D c in cases ?? Cases.Value)
        {
            if ((string)c["fn"]! != fn) continue;
            n++;
            object? got;
            try { got = f(Args(c)); } catch (Exception e) { got = "THREW " + e.GetType().Name; }
            var want = Pca.Canonicalize(c["out"]); var g = Pca.Canonicalize(ToJson(got));
            if (want != g) bad.Add($"{c["name"]}\n    want {want}\n    got  {g}");
        }
        Assert.True(n > 0, "no cases for " + fn);
        Assert.True(bad.Count == 0, $"{bad.Count}/{n} {fn} cases differ from the TS reference:\n  " + string.Join("\n  ", bad.Take(40)));
    }

    [Fact] public void CorpusLoaded() => Assert.True(Cases.Value.Count > 1500);
    [Fact] public void AccumulatorDeclError() => Run("accumulatorDeclError", a => IntentAcc.AccumulatorDeclError(a[0]));
    [Fact] public void MonitorDeclError() => Run("monitorDeclError", a => IntentAcc.MonitorDeclError(a[0]));
    [Fact] public void MonitorStates() => Run("monitorStates", a => IntentAcc.MonitorStates(M(a[0])));
    [Fact] public void TrackedKeySetError() => Run("trackedKeySetError", a => IntentAcc.TrackedKeySetError(a[0]));
    [Fact]
    public void PreState()
    {
        Run("preStateError", a => IntentAcc.PreStateError(a[0] as string, a[1]));
        Run("preValue", a => IntentAcc.PreValue(a[0] as string, M(a[1])));
        Run("combineAcc", a => IntentAcc.CombineAcc(a[0] as string, M(a[1]), new IntentAcc.AccValue(null, IntentJs.Lng(IntentJs.Get(a[2], "val")), IntentJs.Get(a[2], "key") as string)));
    }
    [Fact]
    public void SelectionAndValues()
    {
        Run("accSelects", a => IntentAcc.AccSelects(M(a[0]), S(a[1]), a[2]));
        Run("accValueOf", a => IntentAcc.AccValueOf(M(a[0]), S(a[1]), M(a[2]), a[3]));
    }
    [Fact] public void ReceiptArithmeticOk() => Run("receiptArithmeticOk", a => IntentAcc.ReceiptArithmeticOk(a[0] as string, M(a[1]), IntentJs.Lng(a[2])));
    [Fact] public void PcactnReservationDigest() => Run("pcactnReservationDigest", a => IntentAcc.PcactnReservationDigest(M(a[0])));
    [Fact] public void ReceiptShapeError() => Run("receiptShapeError", a => IntentAcc.ReceiptShapeError(a[0]));
    [Fact] public void KeySetShapeError() => Run("keySetShapeError", a => IntentAcc.KeySetShapeError(a[0]));
    [Fact] public void VerifyKeySet() => Run("verifyKeySet", a => IntentAcc.VerifyKeySet(a[0], S(a[1]), a[2], (bool)a[3]!));
    [Fact]
    public void VerifyReceiptSignature() =>
        Run("verifyReceiptSignature", a => a[0] is D r ? IntentAcc.VerifyReceiptSignature(r, S(a[1]), a[2] == null ? null : Pin(M(a[2]))) : false);
    [Fact]
    public void VerifyReceiptAgainstHolder() =>
        Run("verifyReceiptAgainstHolder", a => IntentAcc.VerifyReceiptAgainstHolder(M(a[0]), M(a[1]), a[2], Dbl(a[3]), Dbl(a[4]), Dbl(a[5]), a[6]));

    static IReadOnlyDictionary<string, string> Pin(D d) => d.ToDictionary(kv => kv.Key, kv => (string)kv.Value!);
}


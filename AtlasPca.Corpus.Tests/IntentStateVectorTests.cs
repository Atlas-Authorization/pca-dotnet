using AtlasPca;
using Xunit;
using static AtlasPca.Corpus.Tests.Conf;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>The Intent Layer v2 state vectors (packages/pca/conformance/intent-state-vectors.json): accumulator and monitor
/// declarations, values and pre-states, the session-history window and fold, sequencer key sets and reservation receipts. Every
/// case is run through this verifier's implementation and compared (as canonical JSON) to the reference output.</summary>
public class IntentStateVectorTests
{
    static readonly Lazy<L> Cases = new(() => L(Load("intent-state-vectors.json")["cases"]));

    static D M(object? o) => (D)o!;
    static string S(object? o) => (string)o!;
    static double Dbl(object? o) => IntentJs.NumOf(o)!.Value;
    static IReadOnlyDictionary<string, string> Pin(D d) => d.ToDictionary(kv => kv.Key, kv => (string)kv.Value!);

    static readonly Dictionary<string, Func<L, object?>> Fns = new()
    {
        ["accumulatorDeclError"] = a => IntentAcc.AccumulatorDeclError(a[0]),
        ["monitorDeclError"] = a => IntentAcc.MonitorDeclError(a[0]),
        ["monitorStates"] = a => IntentAcc.MonitorStates(M(a[0])),
        ["trackedKeySetError"] = a => IntentAcc.TrackedKeySetError(a[0]),
        ["preStateError"] = a => IntentAcc.PreStateError(a[0] as string, a[1]),
        ["preValue"] = a => IntentAcc.PreValue(a[0] as string, M(a[1])),
        ["combineAcc"] = a => IntentAcc.CombineAcc(a[0] as string, M(a[1]), new IntentAcc.AccValue(null, IntentJs.Lng(IntentJs.Get(a[2], "val")), IntentJs.Get(a[2], "key") as string)),
        ["accSelects"] = a => IntentAcc.AccSelects(M(a[0]), S(a[1]), a[2]),
        ["accValueOf"] = a => IntentAcc.AccValueOf(M(a[0]), S(a[1]), M(a[2]), a[3]),
        ["receiptArithmeticOk"] = a => IntentAcc.ReceiptArithmeticOk(a[0] as string, M(a[1]), IntentJs.Lng(a[2])),
        ["pcactnReservationDigest"] = a => IntentAcc.PcactnReservationDigest(M(a[0])),
        ["receiptShapeError"] = a => IntentAcc.ReceiptShapeError(a[0]),
        ["keySetShapeError"] = a => IntentAcc.KeySetShapeError(a[0]),
        ["verifyKeySet"] = a => IntentAcc.VerifyKeySet(a[0], S(a[1]), a[2], (bool)a[3]!),
        ["verifyReceiptSignature"] = a => a[0] is D r ? IntentAcc.VerifyReceiptSignature(r, S(a[1]), a[2] == null ? null : Pin(M(a[2]))) : false,
        ["verifyReceiptAgainstHolder"] = a => IntentAcc.VerifyReceiptAgainstHolder(M(a[0]), M(a[1]), a[2], Dbl(a[3]), Dbl(a[4]), Dbl(a[5]), a[6]),
        // the session-history cases (IntentHistory)
        ["inWindow"] = a => IntentHistory.InWindow(M(a[0]), a[1], a[2]),
        ["accKeyOf"] = a => IntentHistory.AccKeyOf(M(a[0]), a[1] as D),
        ["accPreState"] = a =>
        {
            var cand = M(a[2]);
            return (object?)IntentHistory.AccPreState(M(a[0]), a[1] as L, cand["params"] as D, cand["t"], a[3]) ?? new D { ["throws"] = true };
        },
        ["accPost"] = a =>
        {
            var cand = M(a[2]);
            var post = IntentHistory.AccPost(M(a[0]), a[1] as L, S(cand["verb"]), M(cand["params"]), cand["t"], a[3]);
            return post is long p ? (object?)p : new D { ["throws"] = true };
        },
        ["monitorStep"] = a => IntentHistory.MonitorStep(M(a[0]), S(a[1]), M(a[2])),
        ["monitorState"] = a => IntentHistory.MonitorState(M(a[0]), a[1] as L),
    };

    [Fact]
    public void TheCorpusFileIsFullyRun()
    {
        var doc = Load("intent-state-vectors.json");
        Assert.Equal("pca-intent-state-vectors", doc["format"]);
        Assert.Equal(1L, N(doc["ver"]));
        Assert.True(Cases.Value.Count > 3000, "corpus too small");
        var seen = Cases.Value.Select(c => (string)D(c)["fn"]!).ToHashSet();
        Assert.Equal(Fns.Keys.OrderBy(x => x, StringComparer.Ordinal), seen.OrderBy(x => x, StringComparer.Ordinal));
    }

    public static IEnumerable<object[]> Functions() => Fns.Keys.Select(k => new object[] { k });

    [Theory]
    [MemberData(nameof(Functions))]
    public void MatchesTheReference(string fn) => IntentAccOracleTests.Run(fn, Fns[fn], Cases.Value);
}

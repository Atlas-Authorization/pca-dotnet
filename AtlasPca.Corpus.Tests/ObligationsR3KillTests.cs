using System.Collections;
using AtlasPca;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

// Exact refusal texts and boundaries of Obligations.cs, pinned to packages/pca/src/obligations.ts.
public class ObligationsR3KillTests
{
    /// <summary>A list whose enumeration throws, the only way into the fail-closed catches: Count and the indexer still work.</summary>
    sealed class ThrowingList : L, IEnumerable<object?>
    {
        IEnumerator<object?> IEnumerable<object?>.GetEnumerator() => throw new InvalidOperationException("enumeration refused");
        IEnumerator IEnumerable.GetEnumerator() => throw new InvalidOperationException("enumeration refused");
    }

    static D Ob(string kind, D? p = null)
    {
        var o = new D { ["kind"] = kind };
        if (p != null) o["params"] = p;
        return o;
    }

    static D Log(object? sink) => Ob("log", new D { ["sink"] = sink });
    static D Mark(int i) => Ob("watermark", new D { ["id"] = "w" + i });
    static L Marks(int from, int count) => Enumerable.Range(from, count).Select(i => (object?)Mark(i)).ToList();
    static L Fields(int count) => Enumerable.Range(0, count).Select(i => (object?)("f" + i)).ToList();
    static D Redact(L fields) => Ob("redact", new D { ["fields"] = fields });

    const string SinkMsg = "log.sink must be a non-empty string of at most 128 characters";
    const string RedactMsg = "redact.fields must be 1..32 dotted field paths";

    [Fact]
    public void LogSinkIsCheckedOnlyWhenPresent()
    {
        Assert.Equal(SinkMsg, Obligations.ObligationError(Log("")));
        Assert.Equal(SinkMsg, Obligations.ObligationError(Log(new string('s', 129))));
        Assert.Equal(SinkMsg, Obligations.ObligationError(Log(null)));
        Assert.Null(Obligations.ObligationError(Log(new string('s', 128))));
        Assert.Null(Obligations.ObligationError(Ob("log", new D())));
    }

    [Fact]
    public void NotifyAndWatermarkRefusalTexts()
    {
        Assert.Equal("notify.to is required (a non-empty string of at most 256 characters)", Obligations.ObligationError(Ob("notify")));
        Assert.Equal("watermark.id is required (a non-empty string of at most 128 characters)", Obligations.ObligationError(Ob("watermark")));
    }

    [Fact]
    public void RedactFieldCountBoundaryIsThirtyTwo()
    {
        Assert.Null(Obligations.ObligationError(Redact(Fields(32))));
        Assert.Equal(RedactMsg, Obligations.ObligationError(Redact(Fields(33))));
    }

    [Fact]
    public void RedactRefusesWhenAnyOneFieldIsBad()
    {
        Assert.Equal(RedactMsg, Obligations.ObligationError(Redact(new L { "good", "1bad" })));
        Assert.Equal(RedactMsg, Obligations.ObligationError(Redact(new L { "1bad", "good" })));
    }

    [Fact]
    public void RedactDuplicateRefusalText() =>
        Assert.Equal("redact.fields has a duplicate", Obligations.ObligationError(Redact(new L { "a", "a" })));

    [Fact]
    public void ObligationShapeRefusalTexts()
    {
        Assert.Equal("an obligation must be an object", Obligations.ObligationError("x"));
        Assert.Equal("unknown member 'extra'", Obligations.ObligationError(new D { ["kind"] = "log", ["extra"] = true }));
        Assert.Equal("due must be a non-negative safe integer", Obligations.ObligationError(new D { ["kind"] = "log", ["due"] = "soon" }));
        Assert.Equal("params must be an object", Obligations.ObligationError(new D { ["kind"] = "log", ["params"] = "x" }));
    }

    [Fact]
    public void UnknownKindTextIsJavaScriptStringOfTheValue()
    {
        Assert.Equal("unknown obligation kind 'nope'", Obligations.ObligationError(new D { ["kind"] = "nope" }));
        Assert.Equal("unknown obligation kind 'undefined'", Obligations.ObligationError(new D()));
        Assert.Equal("unknown obligation kind 'null'", Obligations.ObligationError(new D { ["kind"] = null }));
        Assert.Equal("unknown obligation kind 'true'", Obligations.ObligationError(new D { ["kind"] = true }));
        Assert.Equal("unknown obligation kind '5'", Obligations.ObligationError(Issue.NormJ(new D { ["kind"] = 5L })));
        Assert.Equal("unknown obligation kind '1,a,'", Obligations.ObligationError(Issue.NormJ(new D { ["kind"] = new L { 1L, "a", null } })));
        Assert.Equal("unknown obligation kind '[object Object]'", Obligations.ObligationError(new D { ["kind"] = new D() }));
    }

    [Fact]
    public void ListRefusalTexts()
    {
        Assert.Equal("obligations must be an array", Obligations.ObligationsError("x"));
        Assert.Equal("more than 16 obligations", Obligations.ObligationsError(Marks(0, 17)));
        Assert.Equal("obligations[1]: an obligation must be an object", Obligations.ObligationsError(new L { Mark(0), "x" }));
        Assert.Equal("obligations[1] duplicates an earlier obligation", Obligations.ObligationsError(new L { Mark(0), Mark(0) }));
    }

    // Stricter than the reference: obligations.ts:81 lets this throw although its header says total. Both refuse.
    [Fact]
    public void LoneSurrogateIsNotCanonicalizableAndRefusedByValue()
    {
        var bad = Ob("notify", new D { ["to"] = "\uD800" });
        Assert.Null(Obligations.ObligationError(bad));
        Assert.Equal("obligations[1]: not canonicalizable", Obligations.ObligationsError(new L { Mark(0), bad }));
    }

    [Fact]
    public void ObligationKeyIsTheExactCanonicalIdentity()
    {
        Assert.Equal("{\"kind\":\"log\",\"params\":{}}", Obligations.ObligationKey(Ob("log")));
        Assert.Equal("{\"due\":5,\"kind\":\"notify\",\"params\":{\"to\":\"a\"}}",
            Obligations.ObligationKey(Issue.NormJ(new D { ["kind"] = "notify", ["params"] = new D { ["to"] = "a" }, ["due"] = 5L })));
    }

    [Fact]
    public void MergeLimitBoundaryIsSixteenAfterMerging()
    {
        var ok = Obligations.Merge(new L { Marks(0, 8), Marks(8, 8) });
        Assert.True(ok.Ok);
        Assert.Equal(16, ok.Obligations.Count);
        Assert.Null(ok.Reason);

        var over = Obligations.Merge(new L { Marks(0, 16), Marks(16, 1) });
        Assert.False(over.Ok);
        Assert.Empty(over.Obligations);
        Assert.Equal("more than 16 obligations after merging", over.Reason);
    }

    [Fact]
    public void MergeFailsClosedOnAnEvaluationError()
    {
        var got = Obligations.Merge(null!);
        Assert.False(got.Ok);
        Assert.Empty(got.Obligations);
        Assert.Equal("evaluation error (fail closed)", got.Reason);
    }

    [Fact]
    public void GateRefusalTexts()
    {
        var bad = Obligations.PepObligationGate("allow", false, "x", new L());
        Assert.Equal("deny", bad.Decision);
        Assert.Equal("malformed obligations: obligations must be an array", bad.Reason);

        const string SupMsg = "the supported obligation kinds are malformed";
        Assert.Equal(SupMsg, Obligations.PepObligationGate("allow", false, null, "x").Reason);
        Assert.Equal(SupMsg, Obligations.PepObligationGate("allow", false, null, new L { true }).Reason);
    }

    [Fact]
    public void GateNamesEveryUnsupportedKindSorted()
    {
        var got = Obligations.PepObligationGate("allow", false, new L { Ob("notify", new D { ["to"] = "a" }), Ob("log") }, new L());
        Assert.Equal("deny", got.Decision);
        Assert.Empty(got.Perform);
        Assert.True(got.Unsupported.SequenceEqual(new[] { "log", "notify" }));
        Assert.Equal("the enforcement point does not support obligation(s) log, notify", got.Reason);
    }

    [Fact]
    public void GateFailsClosedOnAnEvaluationError()
    {
        var got = Obligations.PepObligationGate("allow", false, null, new ThrowingList());
        Assert.Equal("deny", got.Decision);
        Assert.Empty(got.Perform);
        Assert.Empty(got.Unsupported);
        Assert.Equal("evaluation error (fail closed)", got.Reason);
    }

    [Fact]
    public void OutcomeOfAbsentObligationsIsOk()
    {
        var got = Obligations.Outcome(null, new L(), Issue.Norm(5L));
        Assert.Equal("ok", got.Outcome);
        Assert.Empty(got.Overdue);
        Assert.Null(got.Status);
    }

    [Fact]
    public void OutcomeEscalatesWithNoIndexesOnAnEvaluationError()
    {
        var got = Obligations.Outcome(new L { Ob("log") }, new ThrowingList(), Issue.Norm(5L));
        Assert.Equal("escalate", got.Outcome);
        Assert.Empty(got.Overdue);
        Assert.Equal("obligation_unmet", got.Status);
    }
}

using AtlasPca;
using Xunit;
using JD = System.Collections.Generic.Dictionary<string, object?>;
using JL = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

// Direct checks of the prohibition trigger and plane around what the TS-reference replay (ProhibitionsDiffTests) cannot express: host-object failures
// (a dictionary whose key hashing throws), exact messages of every trigger shape, the size bounds of a state and the ledger overflow rules.
public class ProhibitionsDirectKillTests
{
    static JD J(params (string K, object? V)[] kv) { var d = new JD(); foreach (var (k, v) in kv) d[k] = v; return d; }
    static JL A(params object?[] x) => x.ToList();
    static JD Ctx(string verb = "pay", string resource = "/r", JD? prms = null)
    {
        var a = J(("verb", verb), ("resource", resource));
        if (prms != null) a["params"] = prms;
        return J(("action", a));
    }

    /// <summary>A key comparer that throws once armed (for every key, or only for <see cref="Key"/>): a dictionary built with it fails on lookup, as a hostile host object would.</summary>
    sealed class Trap : IEqualityComparer<string>
    {
        public volatile bool Armed;
        public string? Key;
        public bool Equals(string? x, string? y) => string.Equals(x, y, StringComparison.Ordinal);
        public int GetHashCode(string s)
        {
            if (Armed && (Key == null || s == Key)) throw new InvalidOperationException("trap");
            return StringComparer.Ordinal.GetHashCode(s);
        }
    }

    static readonly JD Leaf = J(("field", "f"), ("op", "eq"));
    static string? Cond(object? c) => Prohibitions.ValidateWhen(J(("verb", "v"), ("where", A(c))), "L");
    static JD Constitution(params JD[] inv) => J(("version", 1L), ("principal", "p"), ("invariants", inv.Cast<object?>().ToList()));
    static JD Never(string id = "n", string verb = "delete") => J(("id", id), ("kind", "never"), ("when", J(("verb", verb))));

    // ---- the shape of a trigger ----

    [Fact]
    public void ATriggerNeedsAnObjectAndANonEmptyVerb()
    {
        Assert.Equal("L: not an object", Prohibitions.ValidateWhen(null, "L"));
        Assert.Equal("L: not an object", Prohibitions.ValidateWhen(A(), "L"));
        Assert.Equal("L: not an object", Prohibitions.ValidateWhen("v", "L"));
        Assert.Equal("L: bad verb", Prohibitions.ValidateWhen(J(), "L"));
        Assert.Equal("L: bad verb", Prohibitions.ValidateWhen(J(("verb", "")), "L"));
        Assert.Equal("L: bad verb", Prohibitions.ValidateWhen(J(("verb", 5L)), "L"));
        Assert.Equal("L: bad verb", Prohibitions.ValidateWhen(J(("verb", A())), "L"));
        Assert.Equal("L: bad verb", Prohibitions.ValidateWhen(J(("verb", A("a", ""))), "L"));
        Assert.Equal("L: bad verb", Prohibitions.ValidateWhen(J(("verb", A("a", 5L))), "L"));
        Assert.Null(Prohibitions.ValidateWhen(J(("verb", "v")), "L"));
        Assert.Null(Prohibitions.ValidateWhen(J(("verb", A("a"))), "L"));
        Assert.Null(Prohibitions.ValidateWhen(J(("verb", A("a", "b"))), "L"));
    }

    [Fact]
    public void AResourceIsAStringAndARegexOneMustBeSafeAndShort()
    {
        JD R(object? r) => J(("verb", "v"), ("resource", r));
        Assert.Equal("L: bad resource", Prohibitions.ValidateWhen(R(5L), "L"));
        Assert.Equal("L: bad resource", Prohibitions.ValidateWhen(R(null), "L"));
        Assert.Null(Prohibitions.ValidateWhen(R("/x"), "L"));
        Assert.Null(Prohibitions.ValidateWhen(R(""), "L"));
        Assert.Null(Prohibitions.ValidateWhen(R("re:a+"), "L"));
        Assert.Equal("L: unsafe regex resource", Prohibitions.ValidateWhen(R("re:(a+)+"), "L"));
        Assert.Null(Prohibitions.ValidateWhen(R("(a+)+"), "L")); // no prefix: a literal
        Assert.Null(Prohibitions.ValidateWhen(R("(a+)+re:"), "L")); // the prefix, not the suffix, makes it a regex
        Assert.Null(Prohibitions.ValidateWhen(R("re:" + new string('a', 200)), "L"));
        Assert.Equal("L: unsafe regex resource", Prohibitions.ValidateWhen(R("re:" + new string('a', 201)), "L"));
    }

    [Fact]
    public void TheWhereListIsAnArrayOfWellFormedConditions()
    {
        Assert.Equal("L: where not an array", Prohibitions.ValidateWhen(J(("verb", "v"), ("where", J())), "L"));
        Assert.Equal("L: where not an array", Prohibitions.ValidateWhen(J(("verb", "v"), ("where", null)), "L"));
        Assert.Null(Prohibitions.ValidateWhen(J(("verb", "v"), ("where", A())), "L"));
        Assert.Equal("L: condition not an object", Cond(5L));
        Assert.Equal("L: condition not an object", Cond(null));
        Assert.Null(Cond(Leaf));
        Assert.Equal("L: condition.field missing", Cond(J(("op", "eq"))));
        Assert.Equal("L: condition.field missing", Cond(J(("field", ""), ("op", "eq"))));
        Assert.Equal("L: condition.field missing", Cond(J(("field", 5L), ("op", "eq"))));
    }

    [Fact]
    public void AnUnknownOpIsNamedTheWayJavaScriptPrintsIt()
    {
        string? Op(params (string, object?)[] kv) => Cond(J(kv.Prepend(("field", "f")).ToArray()));
        Assert.Equal("L: unknown condition op bogus", Op(("op", "bogus")));
        Assert.Equal("L: unknown condition op undefined", Op());
        Assert.Equal("L: unknown condition op null", Op(("op", null)));
        Assert.Equal("L: unknown condition op 5", Op(("op", 5L)));
        Assert.Equal("L: unknown condition op true", Op(("op", true)));
        Assert.Equal("L: unknown condition op false", Op(("op", false)));
        Assert.Equal("L: unknown condition op a,", Op(("op", A("a", null))));
        Assert.Equal("L: unknown condition op 1,2", Op(("op", A(1L, A(2L)))));
        Assert.Equal("L: unknown condition op [object Object]", Op(("op", J())));
        Assert.Equal("L: unknown condition op 1e+21", Op(("op", new Num("1e21"))));
        Assert.Equal("L: unknown condition op ", Op(("op", "")));
        foreach (var op in new[] { "eq", "ne", "in", "nin", "lt", "lte", "gt", "gte", "prefix", "exists", "like", "matches", "is_a", "member_of" })
            Assert.Null(Op(("op", op)));
        Assert.Equal("L: unknown condition op EQ", Op(("op", "EQ")));
    }

    [Fact]
    public void ARefAndACollectionMustBeNonEmptyStrings()
    {
        JD C(params (string, object?)[] more) => J(more.Prepend(("op", "eq")).Prepend(("field", "f")).ToArray());
        Assert.Equal("L: bad condition.ref", Cond(C(("ref", ""))));
        Assert.Equal("L: bad condition.ref", Cond(C(("ref", 5L))));
        Assert.Equal("L: bad condition.ref", Cond(C(("ref", null))));
        Assert.Null(Cond(C(("ref", "r"))));
        JD M(params (string, object?)[] more) => J(more.Prepend(("op", "member_of")).Prepend(("field", "f")).ToArray());
        Assert.Equal("L: bad condition.collection", Cond(M(("collection", ""))));
        Assert.Equal("L: bad condition.collection", Cond(M(("collection", 5L))));
        Assert.Null(Cond(M(("collection", "c"))));
        Assert.Null(Cond(M()));
        Assert.Null(Cond(C(("collection", "")))); // only a member_of reads it
    }

    [Fact]
    public void AGroupingValidatesItsChildrenAndPrefersNotThenAllOf()
    {
        Assert.Equal("L: condition.all_of must be a non-empty array", Cond(J(("all_of", A()))));
        Assert.Equal("L: condition.any_of must be a non-empty array", Cond(J(("any_of", A()))));
        Assert.Equal("L: condition.all_of must be a non-empty array", Cond(J(("all_of", 5L))));
        Assert.Equal("L: condition.any_of must be a non-empty array", Cond(J(("any_of", null))));
        Assert.Null(Cond(J(("any_of", A(Leaf)))));
        Assert.Null(Cond(J(("all_of", A(Leaf, Leaf)))));
        Assert.Equal("L: unknown condition op bogus", Cond(J(("all_of", A(Leaf, J(("field", "f"), ("op", "bogus")))))));
        Assert.Equal("L: unknown condition op bogus", Cond(J(("any_of", A(Leaf, J(("field", "f"), ("op", "bogus")))))));
        Assert.Equal("L: condition not an object", Cond(J(("all_of", A(5L)))));
        Assert.Null(Cond(J(("not", Leaf))));
        Assert.Equal("L: condition not an object", Cond(J(("not", 5L))));
        Assert.Null(Cond(J(("not", Leaf), ("all_of", A())))); // not is read first
        Assert.Equal("L: condition.all_of must be a non-empty array", Cond(J(("all_of", A()), ("any_of", A(Leaf))))); // then all_of before any_of
        Assert.Null(Cond(J(("any_of", A(Leaf)), ("all_of", A(Leaf)))));
    }

    [Fact]
    public void AGroupingMayNestAThirtyTwoDeepAndNoDeeper()
    {
        object? Wrap(string key, int n)
        {
            object? c = Leaf;
            for (int i = 0; i < n; i++) c = key == "not" ? J(("not", c)) : J((key, A(c)));
            return c;
        }
        foreach (var key in new[] { "not", "all_of", "any_of" })
        {
            Assert.Null(Cond(Wrap(key, 32)));
            Assert.Equal("L: condition nesting too deep", Cond(Wrap(key, 33)));
        }
    }

    // ---- matching ----

    [Fact]
    public void AnUndecidableTriggerOrActionCountsAsMatched()
    {
        var w = J(("verb", "pay"));
        Assert.True(Prohibitions.WhenMatches(w, Ctx("pay")));
        Assert.False(Prohibitions.WhenMatches(w, Ctx("refund")));
        Assert.True(Prohibitions.WhenMatches(J(("verb", "")), Ctx("refund"))); // a malformed trigger: the veto applies
        Assert.True(Prohibitions.WhenMatches(5L, Ctx("refund")));
        Assert.True(Prohibitions.WhenMatches(w, null));
        Assert.True(Prohibitions.WhenMatches(w, J()));
        Assert.True(Prohibitions.WhenMatches(w, J(("action", 5L))));
        Assert.True(Prohibitions.WhenMatches(w, J(("action", J(("verb", "refund"))))));
        Assert.True(Prohibitions.WhenMatches(w, J(("action", J(("resource", "/r"))))));
        Assert.True(Prohibitions.WhenMatches(w, J(("action", J(("verb", 5L), ("resource", "/r"))))));
        Assert.True(Prohibitions.WhenMatches(w, J(("action", J(("verb", "refund"), ("resource", 5L))))));
    }

    [Fact]
    public void ARegexResourceIsNotMatchedAgainstASubjectBeyondFiveHundredTwelveCharacters()
    {
        var re = J(("verb", "pay"), ("resource", "re:b+"));
        Assert.False(Prohibitions.WhenMatches(re, Ctx("pay", new string('a', 512))));
        Assert.True(Prohibitions.WhenMatches(re, Ctx("pay", new string('a', 513)))); // too long to decide: the veto applies
        Assert.True(Prohibitions.WhenMatches(re, Ctx("pay", new string('b', 512))));
        // a resource that is no regex is compared exactly whatever the subject's length
        var plain = J(("verb", "pay"), ("resource", "/x"));
        Assert.False(Prohibitions.WhenMatches(plain, Ctx("pay", "/" + new string('a', 600))));
        Assert.True(Prohibitions.WhenMatches(plain, Ctx("pay", "/x")));
        // a longer subject for the wrong verb is still a miss
        Assert.False(Prohibitions.WhenMatches(J(("verb", "refund"), ("resource", "re:b+")), Ctx("pay", new string('a', 513))));
    }

    [Fact]
    public void TheWhereConditionsOnlyClearAMatchWhenProvablyFalse()
    {
        JD WhereOf(object? v, string field = "action.params.x") => J(("verb", "pay"), ("where", A(J(("field", field), ("op", "eq"), ("value", v)))));
        var ctx = Ctx("pay", "/r", J(("x", 2L)));
        Assert.True(Prohibitions.WhenMatches(WhereOf(2L), ctx));
        Assert.False(Prohibitions.WhenMatches(WhereOf(1L), ctx));
        Assert.True(Prohibitions.WhenMatches(WhereOf(1L, "action.params.missing"), ctx)); // cannot decide: matched
        Assert.True(Prohibitions.WhenAffirmative(WhereOf(2L), ctx));
        Assert.False(Prohibitions.WhenAffirmative(WhereOf(1L), ctx));
        Assert.False(Prohibitions.WhenAffirmative(WhereOf(1L, "action.params.missing"), ctx)); // cannot decide: not matched
        Assert.False(Prohibitions.WhenAffirmative(J(("verb", "")), ctx));
        Assert.True(Prohibitions.WhenAffirmative(J(("verb", "pay")), ctx));
    }

    [Fact]
    public void AHostObjectThatFailsWhileReadingNeverMakesAVetoLapse()
    {
        var trap = new Trap();
        var w = new JD(trap) { ["verb"] = "pay" };
        trap.Armed = true;
        Assert.True(Prohibitions.WhenMatches(w, Ctx("pay"))); // cannot evaluate: the veto applies
        Assert.False(Prohibitions.WhenAffirmative(w, Ctx("pay"))); // cannot evaluate: not a match
    }

    // ---- the monitor ----

    [Fact]
    public void AnInvariantThatThrowsWhileEvaluatingIsAViolation()
    {
        var trap = new Trap();
        var inv = new JD(trap) { ["id"] = "n", ["kind"] = "never", ["when"] = J(("verb", "pay")) };
        trap.Key = "description"; // validation never reads it, evaluation does
        trap.Armed = true;
        var r = Prohibitions.Check(Ctx("pay"), Constitution(inv), Prohibitions.EmptyState(1000));
        Assert.False(r.Ok);
        Assert.Equal(new[] { "n" }, r.Violated);
        Assert.Equal(new[] { "n: evaluation error (fail closed)" }, r.Reasons);
        Assert.Equal(new[] { new InvariantEval("n", "never", "violated", "evaluation error (fail closed)") }, r.Evaluated);
    }

    [Fact]
    public void AnActionThatFailsWhileBeingReadIsAMonitorError()
    {
        var trap = new Trap();
        var action = new JD(trap) { ["action"] = J(("verb", "pay"), ("resource", "/r")) };
        trap.Armed = true;
        var r = Prohibitions.Check(action, Constitution(Never()), Prohibitions.EmptyState(1000));
        Assert.False(r.Ok);
        Assert.Equal(new[] { "<monitor>" }, r.Violated);
        Assert.Equal(new[] { "monitor error (fail closed)" }, r.Reasons); // the reference carries the bare reason here, no id prefix
        Assert.Equal(new[] { new InvariantEval("<monitor>", "structural", "violated", "monitor error (fail closed)") }, r.Evaluated);
    }

    [Fact]
    public void AStateThatFailsWhileBeingReadRefusesTheHeadGuardFailClosed()
    {
        var trap = new Trap();
        var st = new JD(trap) { ["now"] = 1000L, ["seq"] = 0L, ["parent"] = null, ["ledger"] = new JD(), ["latched"] = new JD() };
        trap.Armed = true;
        var r = Prohibitions.CheckAndAdvance(true, Ctx("pay"), Constitution(Never()), st, expectedSeq: 0);
        Assert.False(r.Allow);
        Assert.Equal("state", r.DecidedBy);
        Assert.Equal("check-and-advance error (fail closed)", r.Reason);
        Assert.Same(st, r.Next);
    }

    [Fact]
    public void AnActionThatCannotBeDigestedIsNotAttestableAndIsRefusedByTheProhibition()
    {
        var action = Ctx("pay", "/r", J(("note", "\ud800"))); // a lone surrogate has no canonical form
        var r = Prohibitions.CheckAndAdvance(true, action, Constitution(Never()), Prohibitions.EmptyState(1000));
        Assert.False(r.Allow);
        Assert.Equal(("prohibition", "evidence not attestable"), (r.DecidedBy, r.Reason));
        Assert.True(r.Prohibition.Ok);
        var ok = Prohibitions.CheckAndAdvance(true, Ctx("pay"), Constitution(Never()), Prohibitions.EmptyState(1000));
        Assert.True(ok.Allow);
        Assert.Equal(("none", (string?)null), (ok.DecidedBy, ok.Reason));
        Assert.Equal(1.0, IntentJs.NumOf(ok.Next!["seq"]));
    }

    [Fact]
    public void ATickKeepsAFractionalNowDigestibleAndRefusesARegression()
    {
        var st = Prohibitions.EmptyState(1000);
        Assert.Equal((true, 1000.0), (Prohibitions.Tick(st, 1000).Ok, IntentJs.NumOf(Prohibitions.Tick(st, 1000).State!["now"])!.Value));
        Assert.Equal((false, (JD?)null, (string?)"clock regression"), Prohibitions.Tick(st, 999));
        Assert.Equal((false, (JD?)null, (string?)"clock regression"), Prohibitions.Tick(st, double.NaN));
        Assert.Equal((false, (JD?)null, (string?)"clock regression"), Prohibitions.Tick(st, double.PositiveInfinity));
        Assert.Equal((false, (JD?)null, (string?)"malformed monitor state"), Prohibitions.Tick(J(), 1000));
        var frac = Prohibitions.Tick(st, 1000.5);
        Assert.True(frac.Ok);
        Assert.Equal(1000.5, IntentJs.NumOf(frac.State!["now"]));
        Assert.NotEmpty(Prohibitions.StateDigest(frac.State!)); // a state with a fractional now still has a canonical form
        Assert.Equal(1000.0, IntentJs.NumOf(Prohibitions.Tick(st, 1000.0).State!["now"]));
    }

    [Fact]
    public void AdvancingAtAFractionalTimeKeepsTheStateDigestible()
    {
        var inv = J(("id", "c"), ("kind", "cap"), ("when", J(("verb", "pay"))), ("amount", "action.params.amount"), ("max", 100L));
        var r = Prohibitions.AdvanceStrict(Ctx("pay", "/r", J(("amount", 5L))), Constitution(inv), Prohibitions.EmptyState(1000), 1000.5);
        Assert.True(r.Ok, r.Reason);
        Assert.Equal(1000.5, IntentJs.NumOf(r.State!["now"]));
        Assert.NotEmpty(Prohibitions.StateDigest(r.State!));
        var entry = (JD)((JL)((JD)r.State!["ledger"]!)["c"]!)[0]!;
        Assert.Equal(1000.5, IntentJs.NumOf(entry["t"]));
    }

    // ---- the bounds of a state and the ledger overflow rules ----

    static JD Cap(string id, string verb) => J(("id", id), ("kind", "cap"), ("when", J(("verb", verb))), ("amount", "action.params.amount"), ("max", 1_000_000_000_000L));

    static JL Entries(int n, long from = 1) { var l = new JL(); for (int i = 0; i < n; i++) l.Add(J(("t", from + i), ("amount", 1L))); return l; }

    [Fact]
    public void AStateWhoseLedgerWouldGrowPastTheTotalLimitIsRefused()
    {
        var invs = new List<JD>();
        for (int i = 0; i < 10; i++) invs.Add(Cap("c" + i, "other"));
        invs.Add(Cap("c10", "pay"));
        var ledger = new JD();
        for (int i = 0; i < 10; i++) ledger["c" + i] = Entries(10_000);
        var st = Prohibitions.EmptyState(1_000_000);
        st["ledger"] = ledger;
        Assert.Null(Prohibitions.StateProblem(st)); // exactly 100000 entries is allowed
        var r = Prohibitions.AdvanceStrict(Ctx("pay", "/r", J(("amount", 1L))), Constitution(invs.ToArray()), st);
        Assert.Equal((false, (JD?)null, (string?)"resulting state invalid"), r);
        ledger["c10"] = Entries(1);
        Assert.Equal("malformed monitor state: too many entries", Prohibitions.StateProblem(st));
    }

    [Fact]
    public void ACapLedgerPastItsLimitMergesTheOldestTwoAndKeepsTheLaterTime()
    {
        var st = Prohibitions.EmptyState(1_000_000);
        st["ledger"] = J(("c", Entries(10_000)));
        var r = Prohibitions.AdvanceStrict(Ctx("pay", "/r", J(("amount", 5L))), Constitution(Cap("c", "pay")), st);
        Assert.True(r.Ok, r.Reason);
        var l = (JL)((JD)r.State!["ledger"]!)["c"]!;
        Assert.Equal(10_000, l.Count);
        var first = (JD)l[0]!; var second = (JD)l[1]!; var last = (JD)l[^1]!;
        Assert.Equal((2.0, 2.0), (IntentJs.NumOf(first["t"])!.Value, IntentJs.NumOf(first["amount"])!.Value)); // entries 1 and 2 merged at time 2
        Assert.Equal((3.0, 1.0), (IntentJs.NumOf(second["t"])!.Value, IntentJs.NumOf(second["amount"])!.Value));
        Assert.Equal((1_000_000.0, 5.0), (IntentJs.NumOf(last["t"])!.Value, IntentJs.NumOf(last["amount"])!.Value));
        Assert.NotEmpty(Prohibitions.StateDigest(r.State!)); // the merged amount is a canonical number
    }

    [Fact]
    public void ARateLedgerPastItsLimitIsRefusedAndOneAtItsLimitIsNot()
    {
        var rate = J(("id", "r"), ("kind", "rate"), ("when", J(("verb", "call"))), ("max", 10_000L), ("window_secs", 1_000_000L));
        var full = Prohibitions.EmptyState(1_000_000);
        full["ledger"] = J(("r", Entries(10_000)));
        Assert.Equal((false, (JD?)null, (string?)"r: rate ledger overflow"), Prohibitions.AdvanceStrict(Ctx("call"), Constitution(rate), full));
        var below = Prohibitions.EmptyState(1_000_000);
        below["ledger"] = J(("r", Entries(9_999)));
        var ok = Prohibitions.AdvanceStrict(Ctx("call"), Constitution(rate), below);
        Assert.True(ok.Ok, ok.Reason);
        Assert.Equal(10_000, ((JL)((JD)ok.State!["ledger"]!)["r"]!).Count);
    }

    [Fact]
    public void ADescriptionOfAnyTypeIsCarriedAsTheReasonWhenItIsTruthy()
    {
        JD Desc(object? d) => J(("id", "n"), ("kind", "never"), ("when", J(("verb", "pay"))), ("description", d));
        ProhibitionResult Run(object? d) => Prohibitions.Check(Ctx("pay"), Constitution(Desc(d)), Prohibitions.EmptyState(1000));
        var five = Run(5L);
        Assert.Equal("n: 5", five.Reasons[0]);
        Assert.Equal(("5", (double?)5.0), (five.Evaluated[0].Reason, IntentJs.NumOf(five.Evaluated[0].ReasonValue)));
        Assert.Equal("n: a,b", Run(A("a", "b")).Reasons[0]);
        Assert.Equal("n: [object Object]", Run(J()).Reasons[0]);
        Assert.Equal("n: true", Run(true).Reasons[0]);
        Assert.Equal("n: why", Run("why").Reasons[0]);
        Assert.Null(Run("why").Evaluated[0].ReasonValue);
        foreach (var falsy in new object?[] { 0L, false, "" })
        {
            var r = Run(falsy);
            Assert.Equal("n: violated", r.Reasons[0]);
            Assert.Null(r.Evaluated[0].Reason);
            Assert.Null(r.Evaluated[0].ReasonValue);
        }
        Assert.Equal("n: forbidden action", Run(null).Reasons[0]);
    }

    // ---- the evidence of the plane ----

    [Fact]
    public void TheShortSignatureSignsUnderTheKeysOwnIdAndVerifiesAgainstWhatTheVerifierKnows()
    {
        using var key = EdKey.FromSeed(Enumerable.Repeat((byte)0x11, 32).ToArray());
        var cons = Constitution(Never());
        var ctx = Ctx("pay");
        var state = Prohibitions.EmptyState(1000);
        var ev = SafetyEvidence.Prove(ctx, cons, state);
        Assert.True((bool)ev["ok"]!);
        var signed = SafetyEvidence.Sign(ev, key);
        Assert.Equal(key.Id, signed["signer"]);
        var expected = J(("signer", key.Id), ("action", ctx), ("constitution", cons), ("state", state));
        var v = SafetyEvidence.VerifySigned(signed, expected);
        Assert.True(v.Ok, v.Reason);
        Assert.Equal((false, (string?)"signer not trusted"), SafetyEvidence.VerifySigned(signed, J(("signer", "other"), ("action", ctx), ("constitution", cons), ("state", state))));
        // the reference form: a signer that is no non-empty string refuses, a missing bound member refuses
        Assert.Equal("signSafetyEvidence: signer missing", Assert.Throws<ArgumentException>(() => SafetyEvidence.Sign(ev, key, "")).Message);
        Assert.Equal("signSafetyEvidence: signer missing", Assert.Throws<ArgumentException>(() => SafetyEvidence.Sign(ev, key, 5L)).Message);
        Assert.Equal("signSafetyEvidence: signer missing", Assert.Throws<ArgumentException>(() => SafetyEvidence.Sign(ev, key, null)).Message);
        Assert.Equal("signSafetyEvidence: unsupported evidence", Assert.Throws<ArgumentException>(() => SafetyEvidence.Sign(null, key, key.Id)).Message);
        var unbound = new JD(ev) { ["state_digest"] = "<unhashable>" };
        Assert.Equal("signSafetyEvidence: unbound evidence", Assert.Throws<ArgumentException>(() => SafetyEvidence.Sign(unbound, key)).Message);
        var missing = new JD(ev); missing.Remove("constitution");
        Assert.Throws<InvalidOperationException>(() => SafetyEvidence.BindingId(missing, key.Id));
        // a signature made for one signer id does not verify under another
        using var key2 = EdKey.FromSeed(Enumerable.Repeat((byte)0x33, 32).ToArray());
        var other = SafetyEvidence.Sign(ev, key, key2.Id);
        Assert.Equal(key2.Id, other["signer"]);
        Assert.Equal((false, (string?)"bad signature"), SafetyEvidence.VerifySigned(other, J(("signer", key2.Id), ("action", ctx), ("constitution", cons), ("state", state))));
    }

    [Fact]
    public void APinnedPrincipalThatIsNotAStringMatchesNoConstitution()
    {
        using var key = EdKey.FromSeed(Enumerable.Repeat((byte)0x22, 32).ToArray());
        var cons = Constitution(Never());
        cons["principal"] = key.Id;
        var id = SafetyEvidence.ConstitutionId(cons);
        cons["id"] = id;
        cons["sig"] = Pca.B64u(key.Sign(System.Text.Encoding.UTF8.GetBytes(SafetyEvidence.ConstitutionSigDomain).Concat(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(id))).ToArray()));
        Assert.True(SafetyEvidence.VerifyConstitution(cons).Ok);
        Assert.True(SafetyEvidence.VerifyConstitution(cons, key.Id).Ok);
        Assert.Equal((false, (string?)"principal mismatch"), SafetyEvidence.VerifyConstitution(cons, "someone-else"));
        Assert.Equal((false, (string?)"principal mismatch"), SafetyEvidence.VerifyConstitution(cons, true, 5L));
        Assert.Equal((false, (string?)"principal mismatch"), SafetyEvidence.VerifyConstitution(cons, true, null));
        Assert.True(SafetyEvidence.VerifyConstitution(cons, false, 5L).Ok);
    }
}

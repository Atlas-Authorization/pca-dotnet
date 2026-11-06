using System.Reflection;
using AtlasPca;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Direct mutation-kill tests of K5 workflow admission (AtlasPca/Workflow.cs): strict shape helpers, body / edge / receipt
/// validation boundaries, DAG error strings, receipt ordering, edge relations, bind, and the fail-closed catches.</summary>
public class WorkflowKillTests
{
    static readonly EdKey P = EdKey.FromSeed(Enumerable.Repeat((byte)21, 32).ToArray());
    static readonly EdKey RS = EdKey.FromSeed(Enumerable.Repeat((byte)22, 32).ToArray());
    static readonly string B32 = Pca.HashCanonical("workflow-kill");
    const long T0 = 100, TEnd = 1000, NOW = 500;

    static readonly MethodInfo RShape = typeof(Workflow).GetMethod("ReceiptShape", BindingFlags.NonPublic | BindingFlags.Static)!;

    // ---- builders -------------------------------------------------------------------------------------------------------------
    static L Li(params object?[] v) => new(v);
    static D StepD(string id, params string[] deps) => new()
    {
        ["id"] = id, ["verb"] = "call", ["resource"] = "res", ["params_digest"] = null, ["deps"] = deps.Select(x => (object?)x).ToList(),
        ["sink"] = null, ["deny_labels"] = new L(), ["escalate_labels"] = new L(), ["fresh_ms"] = null, ["cost"] = new D(),
    };
    static D EdgeD(string from, string to, string op = "le", string? promise = null, string[]? deny = null) => new()
    {
        ["from"] = new D { ["step"] = from, ["field"] = "out" }, ["to"] = new D { ["step"] = to, ["param"] = "x" }, ["op"] = op, ["unit"] = null,
        ["deny_labels"] = (deny ?? Array.Empty<string>()).Select(x => (object?)x).ToList(), ["promise"] = promise,
    };
    static D BodyD(L steps, L edges) => Issue.NormJ(new D
    {
        ["v"] = 1L, ["id"] = "wf1", ["principal"] = P.Id, ["goal_digest"] = null, ["plan_root"] = null, ["issued_at"] = T0, ["expires_at"] = TEnd,
        ["steps"] = steps, ["edges"] = edges, ["budget"] = new D { ["max_steps"] = 10L, ["caps"] = new D() },
    });
    static D Wf(D body) => Issue.SignWorkflow(P, body);
    static D BodyOf(D wf) => (D)wf["body"]!;
    static D Req(string step, D? prms = null) => Issue.NormJ(new D
    {
        ["step"] = step, ["verb"] = "call", ["resource"] = "res", ["params"] = prms ?? new D(), ["units"] = new D(), ["goal_digest"] = null, ["plan_root"] = null,
    });
    static D Out5(params string[] labels) => new() { ["out"] = Issue.WfOutput(5L, labels, null, true) };
    static D Rc(D wf, string step, long issued, D? prev, D? outputs = null, string? pd = null) =>
        Issue.SignStepReceipt(RS, BodyOf(wf), step, "ok", pd ?? B32, outputs ?? new D(), issued, prev);
    static WfResult Admit(object? wf, object? receipts, long now, object? req, string? principal = null, string? rs = null) =>
        Workflow.AdmitStep(new AdmitInput(wf, principal ?? P.Id, rs ?? RS.Id, receipts, now, req));

    static void Is(WfResult r, string decision, string? code, string? step, int? at = null)
    {
        Assert.Equal(decision, r.Decision);
        Assert.Equal(code, r.Code);
        Assert.Equal(step, r.Step);
        Assert.Equal(at, r.At);
    }

    static bool ValidWith(Action<D> mut, L? steps = null, L? edges = null)
    {
        var b = BodyD(steps ?? Li(StepD("a"), StepD("b", "a")), edges ?? Li(EdgeD("a", "b")));
        mut(b);
        return Workflow.ValidWorkflowBody(b);
    }

    // ---- K5Strict (L45-L66) ---------------------------------------------------------------------------------------------------
    [Fact]
    public void TryIntAcceptsOnlyExactSafeIntegerLexemes()
    {
        Assert.True(K5Strict.TryInt(new Num("5"), out var n) && n == 5);
        Assert.True(K5Strict.TryInt(new Num("9007199254740991"), out n) && n == K5Strict.MaxSafe);
        Assert.True(K5Strict.TryInt(new Num("-9007199254740991"), out n) && n == -K5Strict.MaxSafe);
        Assert.False(K5Strict.TryInt(new Num("9007199254740992"), out _));
        Assert.False(K5Strict.TryInt(new Num("-9007199254740992"), out _));
        Assert.False(K5Strict.TryInt(new Num("-0"), out _));
        Assert.False(K5Strict.TryInt(new Num("01"), out _)); // long.TryParse would accept it; the lexeme check must not
        Assert.False(K5Strict.TryInt(new Num("+1"), out _));
        Assert.False(K5Strict.TryInt(5L, out _));
        Assert.False(K5Strict.TryInt(new Num("99999999999999999999"), out _)); // matches the lexeme but overflows long
    }

    [Fact]
    public void ShapeHelperBoundaries()
    {
        Assert.True(K5Strict.IsStr("aaaaa", 5));
        Assert.False(K5Strict.IsStr("aaaaaa", 5));
        Assert.False(K5Strict.IsStr("", 5));

        var m32 = new D();
        for (var i = 0; i < 32; i++) m32["k" + i] = "v";
        Assert.True(K5Strict.IsScalarMap(m32));
        m32["k32"] = "v";
        Assert.False(K5Strict.IsScalarMap(m32));

        Assert.True(K5Strict.OnlyKeys(new D { ["a"] = 1L, ["b"] = 1L }, "a", "b"));
        Assert.False(K5Strict.OnlyKeys(new D { ["a"] = 1L, ["c"] = 1L }, "a", "b"));

        Assert.True(K5Strict.SortedUnique(Li("a", "b"), K5Strict.IdRe, 16));
        Assert.False(K5Strict.SortedUnique(Li("b", "a"), K5Strict.IdRe, 16));
        Assert.False(K5Strict.SortedUnique(Li("a", "b"), K5Strict.IdRe, 1));
    }

    // ---- body validation (L97, L179-L207) ----------------------------------------------------------------------------------------
    [Fact]
    public void ValidBodyBaseline() => Assert.True(ValidWith(_ => { }));

    [Fact]
    public void EveryEdgeOpIsAcceptedAndNothingElse()
    {
        foreach (var op in new[] { "eq", "le", "ge", "lt", "gt" }) Assert.True(ValidWith(_ => { }, edges: Li(EdgeD("a", "b", op))), op);
        foreach (var op in new[] { "", "ne", "Stryker was here!" }) Assert.False(ValidWith(_ => { }, edges: Li(EdgeD("a", "b", op))), op);
    }

    static D Budget(D b) => (D)b["budget"]!;
    static D Edge0(D b) => (D)((L)b["edges"]!)[0]!;

    [Fact]
    public void CapsMapBoundaryAndBothConjuncts()
    {
        Assert.True(ValidWith(b => { var c = (D)Budget(b)["caps"]!; for (var i = 0; i < 8; i++) c["c" + i] = new Num("1"); }));
        Assert.False(ValidWith(b => { var c = (D)Budget(b)["caps"]!; for (var i = 0; i < 9; i++) c["c" + i] = new Num("1"); }));
        Assert.False(ValidWith(b => Budget(b)["caps"] = new D { ["bad key!"] = new Num("1") }));
        Assert.False(ValidWith(b => Budget(b)["caps"] = new D { ["a"] = "x" }));
    }

    [Fact]
    public void EachEdgeConjunctAloneRejects()
    {
        var cases = new (string, Action<D>)[]
        {
            ("from not object", e => e["from"] = "x"),
            ("from extra key", e => ((D)e["from"]!)["z"] = "x"),
            ("from.step", e => ((D)e["from"]!)["step"] = "bad id!"),
            ("from.field", e => ((D)e["from"]!)["field"] = "bad:field"),
            ("to not object", e => e["to"] = "x"),
            ("to extra key", e => ((D)e["to"]!)["z"] = "x"),
            ("to.step", e => ((D)e["to"]!)["step"] = "bad id!"),
            ("to.param", e => ((D)e["to"]!)["param"] = "bad:param"),
            ("op not string", e => e["op"] = new Num("1")),
            ("op unknown", e => e["op"] = "ne"),
            ("unit", e => e["unit"] = "bad unit!"),
            ("deny_labels", e => e["deny_labels"] = Li("B")),
            ("promise", e => e["promise"] = "bad id!"),
            ("edge extra key", e => e["z"] = "x"),
        };
        foreach (var (name, mut) in cases) Assert.False(ValidWith(b => mut(Edge0(b))), name);
    }

    [Fact]
    public void EachBodyFieldAloneRejects()
    {
        var cases = new (string, Action<D>)[]
        {
            ("v=2", b => b["v"] = new Num("2")),
            ("id", b => b["id"] = "bad id!"),
            ("principal", b => b["principal"] = "bad"),
            ("goal_digest", b => b["goal_digest"] = "bad"),
            ("plan_root", b => b["plan_root"] = "bad"),
            ("issued_at", b => b["issued_at"] = new Num("-1")),
            ("expires_at", b => b["expires_at"] = "x"),
            ("budget extra key", b => Budget(b)["z"] = new Num("1")),
            ("max_steps", b => Budget(b)["max_steps"] = new Num("-1")),
            ("caps", b => Budget(b)["caps"] = new D { ["bad key!"] = new Num("1") }),
            ("bad edge", b => Edge0(b)["op"] = "ne"),
        };
        foreach (var (name, mut) in cases) Assert.False(ValidWith(mut), name);
        // goal_digest / plan_root may be a b32 as well as null
        Assert.True(ValidWith(b => { b["goal_digest"] = B32; b["plan_root"] = B32; }));
    }

    [Fact]
    public void StepCountBoundaries()
    {
        static L Steps(int n) => Enumerable.Range(0, n).Select(i => (object?)StepD("s" + i.ToString("D2"))).ToList();
        Assert.False(ValidWith(_ => { }, steps: new L(), edges: new L()));
        Assert.True(ValidWith(_ => { }, steps: Steps(64), edges: new L()));
        Assert.False(ValidWith(_ => { }, steps: Steps(65), edges: new L()));
    }

    [Fact]
    public void EdgeCountBoundaries()
    {
        static L Edges(int n) => Enumerable.Range(0, n).Select(_ => (object?)EdgeD("a", "b")).ToList();
        Assert.True(ValidWith(_ => { }, edges: Edges(256)));
        Assert.False(ValidWith(_ => { }, edges: Edges(257)));
    }

    // ---- DAG errors (L219-L251) ----------------------------------------------------------------------------------------------
    [Fact]
    public void DagErrorStrings()
    {
        Assert.Equal("duplicate step id", Workflow.DagErrorOf(BodyD(Li(StepD("a"), StepD("a")), new L())));
        Assert.Equal("bad dependency", Workflow.DagErrorOf(BodyD(Li(StepD("a", "z")), new L())));
        Assert.Equal("bad dependency", Workflow.DagErrorOf(BodyD(Li(StepD("a", "a")), new L())));
        Assert.Equal("cycle", Workflow.DagErrorOf(BodyD(Li(StepD("a", "b"), StepD("b", "a")), new L())));
        Assert.Equal("edge does not follow a dependency", Workflow.DagErrorOf(BodyD(Li(StepD("a"), StepD("b")), Li(EdgeD("a", "b")))));
        Assert.Equal("edge does not follow a dependency", Workflow.DagErrorOf(BodyD(Li(StepD("a"), StepD("b", "a")), Li(EdgeD("zz", "b")))));
        Assert.Equal("edge does not follow a dependency", Workflow.DagErrorOf(BodyD(Li(StepD("a"), StepD("b", "a")), Li(EdgeD("a", "zz")))));
        Assert.Null(Workflow.DagErrorOf(BodyD(Li(StepD("a"), StepD("b", "a")), Li(EdgeD("a", "b")))));
    }

    [Fact]
    public void MalformedBodyIsMalformedWorkflow()
    {
        var b = BodyD(Li(StepD("a")), new L());
        b["v"] = new Num("2");
        Assert.Equal("malformed workflow", Workflow.DagErrorOf(b));
    }

    [Fact]
    public void AncestorsAreTransitive() =>
        Assert.Null(Workflow.DagErrorOf(BodyD(Li(StepD("a"), StepD("b", "a"), StepD("c", "b")), Li(EdgeD("a", "c")))));

    // ---- receipt shape (L270-L281) -------------------------------------------------------------------------------------------
    static D ValidReceipt() => Rc(Wf(BodyD(Li(StepD("a")), new L())), "a", 200, null, Out5());
    static bool ShapeOk(Action<D> mut)
    {
        var r = ValidReceipt();
        mut(r);
        return RShape.Invoke(null, new object?[] { r }) != null;
    }
    static D OutOf(D r) => (D)((D)r["outputs"]!)["out"]!;

    [Fact]
    public void ReceiptShapeBaseline() => Assert.True(ShapeOk(_ => { }));

    [Fact]
    public void EachReceiptFieldAloneRejects()
    {
        var cases = new (string, Action<D>)[]
        {
            ("extra key", r => r["z"] = "x"),
            ("v=2", r => r["v"] = new Num("2")),
            ("wf", r => r["wf"] = "bad"),
            ("step", r => r["step"] = "bad id!"),
            ("seq not int", r => r["seq"] = "x"),
            ("prev not b32", r => { r["seq"] = new Num("1"); r["prev"] = "x"; }),
            ("seq 0 with prev", r => r["prev"] = B32),
            ("seq 1 without prev", r => r["seq"] = new Num("1")),
            ("outcome", r => r["outcome"] = "maybe"),
            ("params_digest", r => r["params_digest"] = "bad"),
            ("issued_at", r => r["issued_at"] = new Num("-1")),
            ("signer", r => r["signer"] = "bad"),
            ("sig not string", r => r["sig"] = new Num("1")),
            ("output name", r => r["outputs"] = new D { ["bad key!"] = OutOf(r) }),
            ("output not object", r => r["outputs"] = new D { ["out"] = "x" }),
            ("output extra key", r => OutOf(r)["z"] = "x"),
            ("output digest", r => OutOf(r)["digest"] = "bad"),
            ("output num", r => OutOf(r)["num"] = new Num("-1")),
            ("output unit", r => OutOf(r)["unit"] = "bad unit!"),
            ("output labels", r => OutOf(r)["labels"] = Li("B")),
        };
        foreach (var (name, mut) in cases) Assert.False(ShapeOk(mut), name);
        Assert.True(ShapeOk(r => { r["seq"] = new Num("1"); r["prev"] = B32; }));
    }

    [Fact]
    public void OutputCountBoundary()
    {
        static D Outs(D r, int n) { var o = new D(); for (var i = 0; i < n; i++) o["o" + i] = OutOf(r); return o; }
        Assert.True(ShapeOk(r => r["outputs"] = Outs(r, 32)));
        Assert.False(ShapeOk(r => r["outputs"] = Outs(r, 33)));
    }

    static long? NumOf(D r)
    {
        var rc = RShape.Invoke(null, new object?[] { r })!;
        var outs = (System.Collections.IDictionary)rc.GetType().GetField("Outputs")!.GetValue(rc)!;
        var o = outs["out"]!;
        return (long?)o.GetType().GetField("Num")!.GetValue(o);
    }

    [Fact]
    public void NullOutputNumStaysNull()
    {
        var r = ValidReceipt();
        Assert.Equal(5L, NumOf(r));
        OutOf(r)["num"] = null;
        Assert.Null(NumOf(r));
    }

    // ---- admission ---------------------------------------------------------------------------------------------------------
    static D WfAB(params D[] edges) => Wf(BodyD(Li(StepD("a"), StepD("b", "a")), new L(edges.Cast<object?>().ToArray())));
    static D One() => Wf(BodyD(Li(StepD("a")), new L()));

    [Fact]
    public void EdgeRelationTable()
    {
        // output num 5 vs request param n
        var table = new (string op, long n, bool ok)[]
        {
            ("le", 4, true), ("le", 5, true), ("le", 6, false),
            ("ge", 4, false), ("ge", 5, true), ("ge", 6, true),
            ("lt", 4, true), ("lt", 5, false), ("lt", 6, false),
            ("gt", 4, false), ("gt", 5, false), ("gt", 6, true),
        };
        foreach (var (op, n, ok) in table)
        {
            var wf = WfAB(EdgeD("a", "b", op));
            var r = Admit(wf, Li(Rc(wf, "a", 200, null, Out5())), NOW, Req("b", new D { ["x"] = n }));
            if (ok) Is(r, "allow", null, "b");
            else Is(r, "deny", "edge_relation", "b", 0);
        }
    }

    [Fact]
    public void ReceiptIssuedExactlyNowIsAccepted()
    {
        var wf = WfAB(EdgeD("a", "b"));
        Is(Admit(wf, Li(Rc(wf, "a", NOW, null, Out5())), NOW, Req("b", new D { ["x"] = 5L })), "allow", null, "b");
        Is(Admit(wf, Li(Rc(wf, "a", NOW + 1, null, Out5())), NOW, Req("b", new D { ["x"] = 5L })), "deny", "bad_receipt", "b", 0);
    }

    [Fact]
    public void ReceiptBeforeItsDependencyNeedsEveryEdgePromised()
    {
        // no edge from the missing dependency
        var none = WfAB();
        Is(Admit(none, Li(Rc(none, "b", 200, null)), NOW, Req("a")), "deny", "bad_receipt", "a", 0);
        // one promised, one not
        var mixed = WfAB(EdgeD("a", "b", promise: "p"), EdgeD("a", "b"));
        Is(Admit(mixed, Li(Rc(mixed, "b", 200, null)), NOW, Req("a")), "deny", "bad_receipt", "a", 0);
        // all promised: accepted
        var all = WfAB(EdgeD("a", "b", promise: "p"), EdgeD("a", "b", promise: "q"));
        Is(Admit(all, Li(Rc(all, "b", 200, null)), NOW, Req("a")), "allow", null, "a");
    }

    [Fact]
    public void ReceiptWithExtraKeyOrWrongVersionIsBad()
    {
        var two = Wf(BodyD(Li(StepD("a"), StepD("b")), new L()));
        var ra = Rc(two, "a", 200, null);
        ra["z"] = "x"; // the signature covers only the picked body keys, so only the shape check refuses it
        Is(Admit(two, Li(Rc(two, "a", 200, null)), NOW, Req("b")), "allow", null, "b");
        Is(Admit(two, Li(ra), NOW, Req("b")), "deny", "bad_receipt", "b", 0);
        // v = 2, correctly signed
        var v2 = new D(Rc(two, "a", 200, null));
        v2.Remove("sig");
        v2["v"] = new Num("2");
        v2["sig"] = Issue.SignBody(RS, Workflow.ReceiptDomain, v2);
        Is(Admit(two, Li(v2), NOW, Req("b")), "deny", "bad_receipt", "b", 0);
    }

    [Fact]
    public void IssuedAtBoundaryAndClockFloor()
    {
        Is(Admit(One(), new L(), T0, Req("a")), "allow", null, "a");
        Is(Admit(One(), new L(), T0 - 1, Req("a")), "deny", "not_yet", "a");
        Is(Admit(One(), new L(), 0, Req("a")), "deny", "not_yet", "a");
    }

    [Fact]
    public void PlanRootAuthorizedFromIssuedAt()
    {
        var b = BodyD(Li(StepD("a")), new L());
        b["plan_root"] = B32;
        var wf = Wf(b);
        Assert.True(Workflow.PlanRootAuthorized(wf, P.Id, T0, B32));
        Assert.False(Workflow.PlanRootAuthorized(wf, P.Id, T0 - 1, B32));
    }

    /// <summary>A key comparer that throws once armed: the only way to make the never-throws wrappers' catch observable.</summary>
    sealed class Boom : IEqualityComparer<string>
    {
        public bool Armed;
        public bool Equals(string? x, string? y) => Armed ? throw new InvalidOperationException("boom") : string.Equals(x, y, StringComparison.Ordinal);
        public int GetHashCode(string s) => Armed ? throw new InvalidOperationException("boom") : StringComparer.Ordinal.GetHashCode(s);
    }
    static D Armed(D src)
    {
        var cmp = new Boom();
        var d = new D(cmp);
        foreach (var (k, v) in src) d[k] = v;
        cmp.Armed = true;
        return d;
    }

    [Fact]
    public void PlanRootAuthorizedFailsClosedOnThrow()
    {
        var b = BodyD(Li(StepD("a")), new L());
        b["plan_root"] = B32;
        Assert.False(Workflow.PlanRootAuthorized(Armed(Wf(b)), P.Id, NOW, B32));
    }

    [Fact]
    public void AdmitAndBindFailClosedAsBadWorkflowOnThrow()
    {
        Is(Admit(Armed(One()), new L(), NOW, Req("a")), "deny", "bad_workflow", null);
        Is(Workflow.BindPromises(new AdmitInput(Armed(One()), P.Id, RS.Id, new L(), NOW, Req("a"))), "deny", "bad_workflow", null);
        // a lone surrogate passes the request shape but cannot be canonicalized for the params digest
        var q = Req("a");
        ((D)q["params"]!)["x"] = "\uD800";
        Is(Admit(One(), new L(), NOW, q), "deny", "bad_workflow", null);
        Is(Workflow.BindPromises(new AdmitInput(One(), P.Id, RS.Id, new L(), NOW, q)), "deny", "bad_workflow", null);
    }

    [Fact]
    public void RequestUnitsKeyAndValueAreBothChecked()
    {
        var bk = Req("a"); bk["units"] = new D { ["bad key!"] = "usd" };
        var bv = Req("a"); bv["units"] = new D { ["x"] = "bad unit!" };
        var ok = Req("a"); ok["units"] = new D { ["x"] = "usd" };
        Is(Admit(One(), new L(), NOW, bk), "deny", "bad_workflow", null);
        Is(Admit(One(), new L(), NOW, bv), "deny", "bad_workflow", null);
        Is(Admit(One(), new L(), NOW, ok), "allow", null, "a");
    }

    [Fact]
    public void EachAdmissionInputAloneIsBadWorkflow()
    {
        Is(Admit(One(), new L(), NOW, Req("a")), "allow", null, "a");
        var extra = One(); extra["z"] = "x";
        var badBody = One(); BodyOf(badBody)["v"] = new Num("2");
        var badReq = Req("a"); badReq["z"] = "x";
        var cases = new (string, WfResult)[]
        {
            ("workflow not object", Admit("x", new L(), NOW, Req("a"))),
            ("workflow extra key", Admit(extra, new L(), NOW, Req("a"))),
            ("body invalid", Admit(badBody, new L(), NOW, Req("a"))),
            ("request invalid", Admit(One(), new L(), NOW, badReq)),
            ("receipts not list", Admit(One(), "x", NOW, Req("a"))),
            ("principal", Admit(One(), new L(), NOW, Req("a"), principal: "bad")),
            ("rs signer", Admit(One(), new L(), NOW, Req("a"), rs: "bad")),
            ("now < 0", Admit(One(), new L(), -1, Req("a"))),
            ("now > max safe", Admit(One(), new L(), K5Strict.MaxSafe + 1, Req("a"))),
        };
        foreach (var (name, r) in cases)
        {
            Assert.True(r.Code == "bad_workflow", $"{name}: {r.Code}");
            Is(r, "deny", "bad_workflow", null);
        }
        // now == MaxSafe is a valid clock: admission proceeds and the workflow is simply expired
        Is(Admit(One(), new L(), K5Strict.MaxSafe, Req("a")), "deny", "expired", "a");
    }

    [Fact]
    public void MixedPromiseEdgesAreUnconstrained()
    {
        var mixed = WfAB(EdgeD("a", "b", promise: "p"), EdgeD("a", "b"));
        Is(Admit(mixed, new L(), NOW, Req("b")), "escalate", "pipeline_unconstrained", "b");
        var all = WfAB(EdgeD("a", "b", promise: "p"), EdgeD("a", "b", promise: "q"));
        var r = Admit(all, new L(), NOW, Req("b"));
        Is(r, "allow", null, "b");
        Assert.Equal(new[] { 0, 1 }, r.Pending.ToArray());
    }

    [Fact]
    public void TaintedOutputOnDenyLabelledEdge()
    {
        var wf = WfAB(EdgeD("a", "b", deny: new[] { "pii" }));
        Is(Admit(wf, Li(Rc(wf, "a", 200, null, Out5("pii"))), NOW, Req("b", new D { ["x"] = 5L })), "deny", "taint_flow", "b", 0);
    }

    [Fact]
    public void BindWithAPendingEdgeIsDepsUnmet()
    {
        // c's only direct dep is b (present); the a->c edge's source receipt does not exist yet
        var wf = Wf(BodyD(Li(StepD("a"), StepD("b", "a"), StepD("c", "b")), Li(EdgeD("a", "b", promise: "p"), EdgeD("a", "c"))));
        var rb = Rc(wf, "b", 200, null);
        var rc = Rc(wf, "c", 210, rb, pd: Pca.HashCanonical(new D()));
        Is(Workflow.BindPromises(new AdmitInput(wf, P.Id, RS.Id, Li(rb, rc), NOW, Req("c"))), "deny", "deps_unmet", "c");
    }
}

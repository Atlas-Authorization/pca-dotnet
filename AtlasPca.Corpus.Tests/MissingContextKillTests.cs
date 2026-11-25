using AtlasPca;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Mutation kills for MissingContext.cs: the supplier table, the leaf flattening depth cap, the stored-wins merge, the
/// condition walk (groups, depth cap, typed absence of action.params) and every deny reason.</summary>
public class MissingContextKillTests
{
    static D M(params object?[] kv) { var d = new D(); for (int i = 0; i < kv.Length; i += 2) d[(string)kv[i]!] = kv[i + 1]; return d; }
    static L Li(params object?[] v) => new(v);
    static D Act(object? prms = null) { var a = M("verb", "v", "resource", "r"); if (prms != null) a["params"] = prms; return a; }
    static D Leaf(string field, string value) => M("field", field, "op", "eq", "value", value);
    static D Undecidable(string field) => M("field", field, "op", "eq"); // no value/ref: Unknown although the field is present
    static TypedDecision Decide(L where, D bound, object? supplied = null, object? suppliers = null) =>
        MissingContext.DecideWithMissing(where, bound, supplied, suppliers);
    static void Escalates(TypedDecision d, string path)
    {
        Assert.Equal("escalate", d.Decision);
        Assert.Equal($"escalate: missing_context principal:{path}", d.Reason);
        Assert.Equal(new[] { new MissingItem(path, "principal") }, d.Missing);
    }
    static void Ill(TypedDecision d) { Assert.Equal("deny", d.Decision); Assert.Equal("ill_typed_context", d.Reason); Assert.Empty(d.Missing); }

    // ---- supplier table (L20 Forbidden entries, L34 message, L37 Any) ----
    [Fact]
    public void SupplierTableForbiddenSegmentsAndMessages()
    {
        foreach (var bad in new[] { "__proto__", "constructor", "prototype" })
        {
            Assert.Equal($"bad supplier path 'subject.{bad}'", MissingContext.SupplierTableError(M($"subject.{bad}", "principal")));
            Assert.Equal($"bad supplier path 'env.ok.{bad}'", MissingContext.SupplierTableError(M($"env.ok.{bad}", "principal")));
        }
        Assert.Null(MissingContext.SupplierTableError(M("subject.ok", "principal", "env", "rs_observation")));
        Assert.Equal("the supplier table must be an object", MissingContext.SupplierTableError("x"));
        var d = Decide(Li(Leaf("subject.x", "a")), M("action", Act()), null, "x");
        Assert.Equal("deny", d.Decision);
        Assert.Equal("bad supplier table: the supplier table must be an object", d.Reason);
    }

    // ---- Leaves (L20 forbidden keys skipped, L53 depth cap at 16, L54 empty object leaf, L56 depth step) ----
    [Fact]
    public void LeavesSkipForbiddenKeys()
    {
        var b = MissingContext.BindContext(M(), M("subject", M("__proto__", "x", "constructor", "y", "prototype", "z", "ok", "w")));
        Assert.True(IntentJs.JsonEquals(M("subject", M("ok", "w")), b.Context));
        Assert.Empty(b.Conflicts);
    }

    /// <summary>A subject tree whose object at key path a.a…a (n keys) is <paramref name="tail"/>.</summary>
    static D Chain(int n, D tail) { D cur = tail; for (int i = 0; i < n; i++) cur = M("a", cur); return cur; }
    static string ChainPath(int n) => "subject" + string.Concat(Enumerable.Repeat(".a", n));

    [Fact]
    public void LeavesDepthCapPastTheBound()
    {
        // the object 17 levels down is taken whole (depth 17 > 16): one conflict at the 17-key path, not deeper, not shallower
        var b = MissingContext.BindContext(M("subject", Chain(17, M("y", "w"))), M("subject", Chain(17, M("x", "v"))));
        Assert.Equal(new[] { ChainPath(17) }, b.Conflicts);
    }

    [Fact]
    public void LeavesDepthCapAtTheBound()
    {
        // 16 levels down is still walked (depth 16 is not > 16): x is merged next to the bound y, no conflict
        var b = MissingContext.BindContext(M("subject", Chain(16, M("y", "w"))), M("subject", Chain(16, M("x", "v"))));
        Assert.Empty(b.Conflicts);
        Assert.True(IntentJs.JsonEquals(M("subject", Chain(16, M("y", "w", "x", "v"))), b.Context));
    }

    [Fact]
    public void LeavesEmptyObjectIsALeaf()
    {
        var b = MissingContext.BindContext(M(), M("subject", M("e", M())));
        Assert.True(IntentJs.JsonEquals(M("subject", M("e", M())), b.Context));
        var c = MissingContext.BindContext(M("subject", M("e", "s")), M("subject", M("e", M())));
        Assert.Equal(new[] { "subject.e" }, c.Conflicts);
    }

    // ---- BindContext merge (L66 SetPath, L96 blocked walk, L102-L106 action defaults) ----
    [Fact]
    public void ABoundTopLevelThatIsNotAnObjectIsAConflictNotReplaced()
    {
        foreach (var root in new[] { "subject", "env" })
            foreach (var x in new object?[] { "str", 5L, new List<object?>(), null })
            {
                var b = MissingContext.BindContext(M(root, x), M(root, M("x", "v")));
                Assert.Equal(new[] { root + ".x" }, b.Conflicts);
                Assert.True(IntentJs.JsonEquals(M(root, x), b.Context));
            }
    }

    [Fact]
    public void BlockedByANonObjectPrefix()
    {
        var b = MissingContext.BindContext(M("subject", M("a", "s")), M("subject", M("a", M("b", "v"))));
        Assert.Equal(new[] { "subject.a.b" }, b.Conflicts);
        Assert.True(IntentJs.JsonEquals(M("subject", M("a", "s")), b.Context));
        var ok = MissingContext.BindContext(M("subject", M("a", M("c", "k"))), M("subject", M("a", M("b", "v"))));
        Assert.Empty(ok.Conflicts);
        Assert.True(IntentJs.JsonEquals(M("subject", M("a", M("c", "k", "b", "v"))), ok.Context));
    }

    [Fact]
    public void ActionDefaultsOnlyForParamsPaths()
    {
        var subj = MissingContext.BindContext(M(), M("subject", M("x", "v")));
        Assert.True(IntentJs.JsonEquals(M("subject", M("x", "v")), subj.Context));
        Assert.False(subj.Context.ContainsKey("action"));
        var prm = MissingContext.BindContext(M(), M("action", M("params", M("x", "v"))));
        Assert.True(IntentJs.JsonEquals(M("action", M("verb", "", "resource", "", "params", M("x", "v"))), prm.Context));
        var a = (D)prm.Context["action"]!;
        Assert.Equal(new[] { "params", "resource", "verb" }, a.Keys.OrderBy(k => k, StringComparer.Ordinal));
        Assert.Equal("", a["verb"]);
        Assert.Equal("", a["resource"]);
    }

    [Fact]
    public void ExistingParamsAreKept()
    {
        var b = MissingContext.BindContext(M("action", Act(M("a", "1"))), M("action", M("params", M("b", "2"))));
        Assert.Empty(b.Conflicts);
        Assert.True(IntentJs.JsonEquals(M("action", M("verb", "v", "resource", "r", "params", M("a", "1", "b", "2"))), b.Context));
    }

    [Fact]
    public void ABoundActionThatIsNotAnObjectIsAConflictNotReplaced()
    {
        // missing-context.ts (08f482520): the scan starts at depth 1, so a non-object bound action blocks the supplied params
        foreach (var a in new object?[] { "str", 5L, new List<object?>(), null })
        {
            var b = MissingContext.BindContext(M("action", a), M("action", M("params", M("x", "v"))));
            Assert.Equal(new[] { "action.params.x" }, b.Conflicts);
            Assert.True(IntentJs.JsonEquals(M("action", a), b.Context));
        }
    }

    // ---- Collect: groups (L114, L122) ----
    [Fact]
    public void NestedGroupsAreWalked()
    {
        var bound = M("action", Act());
        Escalates(Decide(Li(M("all_of", Li(Leaf("subject.x", "a")))), bound), "subject.x");
        Escalates(Decide(Li(M("any_of", Li(Leaf("subject.x", "a")))), bound), "subject.x");
        Escalates(Decide(Li(M("not", Leaf("subject.x", "a"))), bound), "subject.x");
    }

    // ---- Collect: depth cap at 64 (L118, L124) ----
    static D Nots(int n, D leaf) { D cur = leaf; for (int i = 0; i < n; i++) cur = M("not", cur); return cur; }

    [Fact]
    public void CollectDepthAtTheBound()
    {
        // the leaf sits at depth 64 (64 > 64 is false): collected
        Escalates(Decide(Li(Nots(64, Leaf("subject.x", "a"))), M("action", Act())), "subject.x");
    }

    [Fact]
    public void CollectDepthPastTheBound()
    {
        // a leaf at depth 65 marks the context ill even though another condition names a real missing path
        Ill(Decide(Li(Leaf("subject.x", "a"), Nots(65, Leaf("subject.y", "a"))), M("action", Act())));
    }

    // ---- Collect: decided leaves, typed absence, illness (L127, L128, L132, L139, L161) ----
    [Fact]
    public void DecidedLeafIsSkipped()
    {
        Escalates(Decide(Li(Leaf("subject.y", "w"), Leaf("subject.x", "a")), M("action", Act(), "subject", M("y", "w"))), "subject.x");
    }

    [Fact]
    public void UndecidablePresentLeafIsIll()
    {
        var bound = M("action", Act(), "subject", M("y", "w"));
        Ill(Decide(Li(Leaf("subject.x", "a"), Undecidable("subject.y")), bound));
        Ill(Decide(Li(Undecidable("subject.y")), bound));
    }

    [Fact]
    public void EmptyRefIsNotAPath()
    {
        Ill(Decide(Li(M("field", "subject.y", "op", "eq", "ref", "")), M("action", Act(), "subject", M("y", "w"))));
    }

    // ---- Collect: action.params unavailable (L133-L136) ----
    [Fact]
    public void ParamsNotAnObjectIsMissing()
    {
        Escalates(Decide(Li(M("field", "action.params", "op", "exists")), M("action", Act("str"))), "action.params");
    }

    [Fact]
    public void OnlyParamsRootedFieldsCountParams()
    {
        // ends with "action.params." but is not rooted there: present and undecidable, so ill
        var bound = M("action", Act("str"), "subject", M("action", M("params", M("", "z"))));
        Ill(Decide(Li(Undecidable("subject.action.params.")), bound));
        Ill(Decide(Li(Undecidable("subject.action")), bound));
    }

    [Fact]
    public void ParamsObjectIsNotMissing()
    {
        Ill(Decide(Li(Undecidable("action.params.x")), M("action", Act(M("x", "1")))));
        Ill(Decide(Li(Undecidable("action.params")), M("action", Act(M("x", "1")))));
    }

    // ---- reasons (L165, L168) ----
    [Fact]
    public void UntrustedMissingDenies()
    {
        var d = Decide(Li(Leaf("subject.x", "a")), M("action", Act()), null, M("subject.x", "agent_declared_untrusted"));
        Assert.Equal("deny", d.Decision);
        Assert.Equal("missing_context_untrusted: subject.x", d.Reason);
        Assert.Equal(new[] { new MissingItem("subject.x", "agent_declared_untrusted") }, d.Missing);
    }

    [Fact]
    public void EvaluationErrorFailsClosed()
    {
        // a lone surrogate cannot be canonicalized when the supplied value is compared against the bound one
        var d = Decide(Li(Leaf("subject.x", "a")), M("action", Act(), "subject", M("x", "a")), M("subject", M("x", "\uD800")));
        Assert.Equal("deny", d.Decision);
        Assert.Equal("evaluation error (fail closed)", d.Reason);
        Assert.Empty(d.Missing);
    }

    // ---- round 2: the depth caps stop the walk (resource bounds, matching missing-context.ts:58/108), empty group, two-path reason ----
    [Fact]
    public void LeavesStopsWalkingPastTheDepthCap()
    {
        // the 17-deep object is ONE leaf: its inner x is never walked, so the conflict leaves the context exactly as bound
        var bound = M("subject", Chain(17, M("y", "w")));
        var b = MissingContext.BindContext(bound, M("subject", Chain(17, M("x", "v"))));
        Assert.True(IntentJs.JsonEquals(bound, b.Context));
    }

    [Fact]
    public void CollectStopsWalkingPastTheDepthCap()
    {
        var collect = typeof(MissingContext).GetMethod("Collect", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static)!;
        var output = new HashSet<string>(); var ill = new bool[1];
        collect.Invoke(null, new object?[] { Nots(65, Leaf("subject.y", "a")), M("action", Act()), output, ill, 0 });
        Assert.True(ill[0]);
        Assert.Empty(output); // the leaf past depth 64 is never reached
    }

    [Fact]
    public void AnEmptyGroupIsIllEvenNextToAMissingPath()
    {
        Ill(Decide(Li(M("all_of", Li()), Leaf("subject.x", "a")), M("action", Act())));
        Ill(Decide(Li(M("any_of", "x"), Leaf("subject.x", "a")), M("action", Act())));
    }

    [Fact]
    public void UntrustedMissingPathsAreCommaJoined()
    {
        var d = Decide(Li(Leaf("subject.x", "a"), Leaf("subject.y", "a")), M("action", Act()), null,
            M("subject.x", "agent_declared_untrusted", "subject.y", "agent_declared_untrusted"));
        Assert.Equal("missing_context_untrusted: subject.x,subject.y", d.Reason);
    }
}


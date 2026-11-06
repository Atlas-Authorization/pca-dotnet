using AtlasPca;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Pins PlanLifecycle.cs to the reference packages/pca/src/server/plan-lifecycle.ts: every state, message, boundary and key byte.
/// Tampered records go straight into the store (the registry never takes the root or a state from a caller, the store is the only way in).</summary>
public class PlanLifecycleKillTests
{
    const string G = "g";
    const string StoreFailed = "the plan store failed (fail closed): ";

    static D Node(string id, string verb = "v", string resource = "/r") => new() { ["id"] = id, ["verb"] = verb, ["resource"] = resource };
    static D NodeWith(string key, object? value) { var n = Node("n"); n[key] = value; return n; }
    static D NodeWithout(string key) { var n = Node("n"); n.Remove(key); return n; }
    static string Key(string root) => "pca-plan:g:" + root;
    static string C(object? v) => Pca.Canonicalize(v);

    static PlanRecord Rec(string root, IEnumerable<D> nodes, string state, PlanApproval? approval = null, string? revokedReason = null) =>
        new(G, root, nodes.ToList(), state, 1) { Approval = approval, RevokedReason = revokedReason };

    static void Store(IAtomicKv kv, string root, string text) => kv.Update(Key(root), _ => text);
    static void Seed(IAtomicKv kv, string root, IEnumerable<D> nodes, string state, PlanApproval? approval = null, string? revokedReason = null) =>
        Store(kv, root, C(Rec(root, nodes, state, approval, revokedReason).ToJson()));

    /// <summary>An authorized plan written directly to the store, its root computed from the (possibly odd) nodes.</summary>
    static (PlanRegistry Reg, string Root) Authorized(params D[] nodes)
    {
        var kv = new MemoryAtomicKv();
        var root = PlanRegistry.RootOf(nodes);
        Seed(kv, root, nodes, PlanStates.Authorized, new PlanApproval("p"));
        return (new PlanRegistry(new PlanRegistryOptions { Kv = kv, Now = () => 1000 }), root);
    }

    static string Walk(PlanRegistry reg, IEnumerable<D> nodes, string to, PlanApproval? approval = null)
    {
        var d = reg.Draft(G, nodes);
        Assert.True(d.Ok, d.Reason);
        var root = d.Record!.Root;
        if (to == PlanStates.Draft) return root;
        Assert.True(reg.Validate(G, root).Ok);
        if (to == PlanStates.Validated) return root;
        Assert.True(reg.Commit(G, root).Ok);
        if (to == PlanStates.Committed) return root;
        Assert.True(reg.Authorize(G, root, approval ?? new PlanApproval("p")).Ok);
        return root;
    }

    static List<D> One() => new() { Node("n1") };

    static void AssertRefused(PlanTransition t, string state, string reason)
    {
        Assert.False(t.Ok);
        Assert.Null(t.Record);
        Assert.Equal(state, t.State);
        Assert.Equal(reason, t.Reason);
    }

    sealed class SwitchKv : IAtomicKv
    {
        public readonly MemoryAtomicKv Inner = new();
        public bool GetThrows, UpdateThrows;
        public string? Get(string key) => GetThrows ? throw new InvalidOperationException("get down") : Inner.Get(key);
        public void Update(string key, Func<string?, string?> fn)
        {
            if (UpdateThrows) throw new InvalidOperationException("update down");
            Inner.Update(key, fn);
        }
    }

    // ---------- JSON shapes (L41-L72, L105) ----------

    [Fact]
    public void ApprovalJsonCarriesOnlyAFiniteExpiry()
    {
        Assert.Equal("""{"by":"p"}""", C(new PlanApproval("p").ToJson()));
        Assert.Equal("""{"by":"p","expiresAt":5000}""", C(new PlanApproval("p", 5000d).ToJson()));
        Assert.Equal("""{"by":"p"}""", C(new PlanApproval("p", double.NaN).ToJson()));
        Assert.Equal("""{"by":"p"}""", C(new PlanApproval("p", double.PositiveInfinity).ToJson()));
    }

    [Fact]
    public void RecordJsonOmitsAbsentOptionalsAndPrintsPresentOnes()
    {
        Assert.Equal("""{"createdAt":1,"grantRef":"g","nodes":[],"root":"r","state":"draft"}""",
            C(new PlanRecord("g", "r", new List<D>(), "draft", 1).ToJson()));
        var full = new PlanRecord("g", "r", new List<D> { new() { ["id"] = "n" } }, "revoked", 1)
        {
            ValidatedAt = 2, CommittedAt = 4, AuthorizedAt = 3, Approval = new PlanApproval("p"), RevokedAt = 5, RevokedReason = "why",
        };
        Assert.Equal("""{"approval":{"by":"p"},"authorizedAt":3,"committedAt":4,"createdAt":1,"grantRef":"g","nodes":[{"id":"n"}],"revokedAt":5,"revokedReason":"why","root":"r","state":"revoked","validatedAt":2}""",
            C(full.ToJson()));
    }

    [Fact]
    public void StatusJsonOmitsAbsentReasonAndRecord()
    {
        Assert.Equal("""{"executable":false,"state":"unknown"}""", C(new PlanStatus(PlanStates.Unknown, false).ToJson()));
        var rec = new PlanRecord("g", "r", new List<D>(), "draft", 1);
        Assert.Equal("""{"executable":true,"reason":"x","record":{"createdAt":1,"grantRef":"g","nodes":[],"root":"r","state":"draft"},"state":"draft"}""",
            C(new PlanStatus("draft", true, "x", rec).ToJson()));
    }

    // ---------- decoding a stored record (L74-L88, L164-L169) ----------

    static D Stored() => new() { ["grantRef"] = "g", ["root"] = "r", ["nodes"] = new L(), ["state"] = "draft" };
    static D StoredWith(string key, object? value) { var m = Stored(); m[key] = value; return m; }

    [Fact]
    public void FromJsonRefusesEveryMissingOrMistypedRequiredMember()
    {
        Assert.Null(PlanRecord.FromJson(null));
        Assert.Null(PlanRecord.FromJson("x"));
        Assert.Null(PlanRecord.FromJson(new L()));
        foreach (var k in new[] { "root", "nodes", "state", "grantRef" })
        {
            var missing = Stored();
            missing.Remove(k);
            Assert.Null(PlanRecord.FromJson(missing));
            Assert.Null(PlanRecord.FromJson(StoredWith(k, new Num("1"))));
        }
    }

    [Fact]
    public void FromJsonKeepsACompleteRecordWithoutNodes()
    {
        var r = PlanRecord.FromJson(Stored());
        Assert.NotNull(r);
        Assert.Equal(("g", "r", "draft"), (r!.GrantRef, r.Root, r.State));
        Assert.Empty(r.Nodes);
        Assert.True(r.CreatedAt == 0);
        Assert.Null(r.Approval);
        Assert.Null(r.RevokedReason);
    }

    [Fact]
    public void FromJsonRefusesANonObjectNodeAmongObjects()
    {
        Assert.Null(PlanRecord.FromJson(StoredWith("nodes", new L { new D { ["id"] = "n" }, new Num("1") })));
        Assert.Null(PlanRecord.FromJson(StoredWith("nodes", new L { new D { ["id"] = "n" }, null })));
        Assert.Null(PlanRecord.FromJson(StoredWith("nodes", new L { new Num("1") })));
        Assert.Single(PlanRecord.FromJson(StoredWith("nodes", new L { new D { ["id"] = "n" } }))!.Nodes);
    }

    [Fact]
    public void FromJsonReadsATimeOnlyFromAFiniteNumber()
    {
        var m = Stored();
        m["createdAt"] = new Num("6");
        m["validatedAt"] = new Num("7");
        m["committedAt"] = new Num("8");
        m["authorizedAt"] = new Num("9");
        m["revokedAt"] = new Num("10");
        m["revokedReason"] = "why";
        var r = PlanRecord.FromJson(m)!;
        Assert.True(r.CreatedAt == 6);
        Assert.True(r.ValidatedAt == 7);
        Assert.True(r.CommittedAt == 8);
        Assert.True(r.AuthorizedAt == 9);
        Assert.True(r.RevokedAt == 10);
        Assert.Equal("why", r.RevokedReason);

        Assert.Null(PlanRecord.FromJson(Stored())!.ValidatedAt);
        Assert.Null(PlanRecord.FromJson(StoredWith("validatedAt", "7"))!.ValidatedAt);
        Assert.Null(PlanRecord.FromJson(StoredWith("validatedAt", new Num("1e999")))!.ValidatedAt);
        Assert.True(PlanRecord.FromJson(StoredWith("createdAt", new Num("1e999")))!.CreatedAt == 0);
    }

    [Fact]
    public void FromJsonReadsTheApproval()
    {
        Assert.Null(PlanRecord.FromJson(StoredWith("approval", "x"))!.Approval);

        var noBy = PlanRecord.FromJson(StoredWith("approval", new D()))!.Approval!;
        Assert.Equal("", noBy.By);
        Assert.Null(noBy.ExpiresAt);
        Assert.Equal("", PlanRecord.FromJson(StoredWith("approval", new D { ["by"] = new Num("1") }))!.Approval!.By);

        var timed = PlanRecord.FromJson(StoredWith("approval", new D { ["by"] = "p", ["expiresAt"] = new Num("5") }))!.Approval!;
        Assert.Equal("p", timed.By);
        Assert.Equal(5d, timed.ExpiresAt!.Value);

        // a present non-number is not a time: NaN, which is never "before" any clock
        Assert.True(double.IsNaN(PlanRecord.FromJson(StoredWith("approval", new D { ["expiresAt"] = null }))!.Approval!.ExpiresAt!.Value));
        Assert.True(double.IsNaN(PlanRecord.FromJson(StoredWith("approval", new D { ["expiresAt"] = "5" }))!.Approval!.ExpiresAt!.Value));
    }

    [Fact]
    public void AnUndecodableStoredValueIsNoPlan()
    {
        var kv = new MemoryAtomicKv();
        var reg = new PlanRegistry(new PlanRegistryOptions { Kv = kv });
        Assert.Null(reg.Get(G, "r"));
        foreach (var text in new[] { "not json", "", "[1]", """{"root":"r"}""" })
        {
            Store(kv, "r", text);
            Assert.Null(reg.Get(G, "r"));
            AssertRefused(reg.Commit(G, "r"), PlanStates.Unknown, "plan r is unknown for this grant");
        }
    }

    [Fact]
    public void AValidStoredValueDecodes()
    {
        var kv = new MemoryAtomicKv();
        Seed(kv, "r", One(), PlanStates.Committed);
        var got = new PlanRegistry(new PlanRegistryOptions { Kv = kv }).Get(G, "r");
        Assert.NotNull(got);
        Assert.Equal(PlanStates.Committed, got!.State);
    }

    // ---------- options and keys (L155-L162) ----------

    [Fact]
    public void ThePrefixIsTheOptionVerbatimAndDefaultsOnlyWhenNull()
    {
        foreach (var (prefix, want) in new (string?, string)[] { (null, "pca-plan:g:"), ("t:", "t:g:"), ("", "g:") })
        {
            var kv = new MemoryAtomicKv();
            var root = new PlanRegistry(new PlanRegistryOptions { Kv = kv, Prefix = prefix }).Draft(G, One()).Record!.Root;
            Assert.NotNull(kv.Get(want + root));
            if (want != "pca-plan:g:") Assert.Null(kv.Get("pca-plan:g:" + root));
        }
    }

    [Fact]
    public void TheGrantIsEncodedLikeEncodeUriComponent()
    {
        var kv = new MemoryAtomicKv();
        var reg = new PlanRegistry(new PlanRegistryOptions { Kv = kv });
        var root = reg.Draft("a/b:c d!*'()~-_.é😀", One()).Record!.Root;
        Assert.NotNull(kv.Get("pca-plan:a%2Fb%3Ac%20d!*'()~-_.%C3%A9%F0%9F%98%80:" + root));
    }

    [Fact]
    public void AGrantDoesNotSeeAnotherGrantsPlan()
    {
        var reg = new PlanRegistry();
        var root = reg.Draft("a", One()).Record!.Root;
        Assert.Null(reg.Get("b", root));
        Assert.True(reg.Draft("b", One()).Ok);
    }

    // FAIL-OPEN regression: Uri.EscapeDataString folds a lone surrogate to U+FFFD, so "\uD800" read the plan of the grant "�".
    [Fact]
    public void ALoneSurrogateGrantHasNoKeyAndNeverReachesAnotherGrantsPlan()
    {
        var kv = new MemoryAtomicKv();
        var reg = new PlanRegistry(new PlanRegistryOptions { Kv = kv, Now = () => 1000 });
        var root = reg.Draft("�", One()).Record!.Root;
        Assert.True(reg.Validate("�", root).Ok);
        Assert.True(reg.Commit("�", root).Ok);
        Assert.True(reg.Authorize("�", root, new PlanApproval("p")).Ok);
        Assert.True(reg.IsPlanAuthorized("�", root));

        const string lone = "\uD800";
        var s = reg.Status(lone, root);
        Assert.Equal((PlanStates.Unknown, false), (s.State, s.Executable));
        Assert.Equal(StoreFailed + "URI malformed", s.Reason);
        Assert.False(reg.IsPlanAuthorized(lone, root));
        Assert.Null(reg.Context(lone, root));
        Assert.Equal("URI malformed", Assert.Throws<InvalidOperationException>(() => reg.Get(lone, root)).Message);
        AssertRefused(reg.Revoke(lone, root, "x"), PlanStates.Unknown, StoreFailed + "URI malformed");
        AssertRefused(reg.Validate(lone, root), PlanStates.Unknown, StoreFailed + "URI malformed");
        var d = reg.Draft(lone, One());
        Assert.False(d.Ok);
        Assert.StartsWith(StoreFailed, d.Reason);
        Assert.True(reg.IsPlanAuthorized("�", root));
    }

    // ---------- the root (L179-L183) ----------

    [Fact]
    public void RootOfRefusesAnEmptySetAndHashesTheLeaves()
    {
        var e = Assert.Throws<InvalidOperationException>(() => PlanRegistry.RootOf(new List<D>()));
        Assert.Equal("merkleRoot: empty leaf set", e.Message);
        var n = Node("n1");
        Assert.Equal(Pca.MerkleRoot(new L { Pca.NodeLeaf(n) }), PlanRegistry.RootOf(new List<D> { n }));
    }

    // ---------- draft (L227-L255) ----------

    [Fact]
    public void DraftRefusesWhatHasNoRoot()
    {
        var reg = new PlanRegistry();
        AssertRefused(reg.Draft("", One()), PlanStates.Unknown, "a plan needs a grant");
        AssertRefused(reg.Draft(null!, One()), PlanStates.Unknown, "a plan needs a grant");
        AssertRefused(reg.Draft(G, new List<D>()), PlanStates.Unknown, "the plan cannot be committed: merkleRoot: empty leaf set");
        AssertRefused(reg.Draft(G, null!), PlanStates.Unknown, "the plan cannot be committed: merkleRoot: empty leaf set");
        var unhashable = reg.Draft(G, new List<D> { Node("n", "\uD800") });
        Assert.False(unhashable.Ok);
        Assert.Equal(PlanStates.Unknown, unhashable.State);
        Assert.StartsWith("the plan cannot be committed: ", unhashable.Reason);
    }

    [Fact]
    public void DraftRecordsACopyAndRefusesAnExistingRootInAnyState()
    {
        long t = 10;
        var reg = new PlanRegistry(new PlanRegistryOptions { Now = () => t });
        var nodes = One();
        var d = reg.Draft(G, nodes);
        Assert.True(d.Ok);
        var root = d.Record!.Root;
        Assert.Equal(PlanStates.Draft, d.State);
        nodes[0]["verb"] = "changed";
        Assert.Equal("v", d.Record.Nodes[0]["verb"]);
        Assert.Equal("v", reg.Get(G, root)!.Nodes[0]["verb"]);

        t = 20;
        AssertRefused(reg.Draft(G, One()), PlanStates.Draft, $"plan {root} already exists (draft)");
        Assert.True(reg.Get(G, root)!.CreatedAt == 10);
        Assert.True(reg.Validate(G, root).Ok);
        AssertRefused(reg.Draft(G, One()), PlanStates.Validated, $"plan {root} already exists (validated)");
        Assert.Equal(PlanStates.Validated, reg.Get(G, root)!.State);
    }

    [Fact]
    public void ACorruptStoredValueIsOverwrittenByADraft()
    {
        var kv = new MemoryAtomicKv();
        var reg = new PlanRegistry(new PlanRegistryOptions { Kv = kv });
        var root = PlanRegistry.RootOf(One());
        Store(kv, root, "not json");
        Assert.True(reg.Draft(G, One()).Ok);
        Assert.Equal(PlanStates.Draft, reg.Get(G, root)!.State);
    }

    [Fact]
    public void DraftReportsAStoreFailure()
    {
        var kv = new SwitchKv { UpdateThrows = true };
        AssertRefused(new PlanRegistry(new PlanRegistryOptions { Kv = kv }).Draft(G, One()), PlanStates.Unknown, StoreFailed + "update down");
    }

    // ---------- validate: the structural checks (L189-L203) ----------

    static void AssertInvalid(string problem, params D[] nodes)
    {
        var kv = new MemoryAtomicKv();
        Seed(kv, "r", nodes, PlanStates.Draft);
        var reg = new PlanRegistry(new PlanRegistryOptions { Kv = kv });
        AssertRefused(reg.Validate(G, "r"), PlanStates.Draft, $"plan r is invalid: {problem}");
        Assert.Equal(PlanStates.Draft, reg.Get(G, "r")!.State);
    }

    [Fact]
    public void ValidateRefusesAPlanWithoutNodes() => AssertInvalid("a plan needs at least one node");

    [Fact]
    public void ValidateRefusesANodeWithoutAStringId()
    {
        AssertInvalid("every node needs an id", NodeWithout("id"));
        AssertInvalid("every node needs an id", NodeWith("id", new Num("1")));
        AssertInvalid("every node needs an id", NodeWith("id", ""));
    }

    [Fact]
    public void ValidateRefusesADuplicateId() => AssertInvalid("duplicate node id 'n1'", Node("n1"), Node("n2"), Node("n1"));

    [Fact]
    public void ValidateRefusesANodeWithoutAStringVerbAndResource()
    {
        const string problem = "node 'n' needs a verb and a resource";
        foreach (var member in new[] { "verb", "resource" })
        {
            AssertInvalid(problem, NodeWithout(member));
            AssertInvalid(problem, NodeWith(member, new Num("1")));
            AssertInvalid(problem, NodeWith(member, ""));
        }
    }

    [Fact]
    public void ValidateRefusesAnUnknownReversibilityClass()
    {
        const string k = "reversibility_class";
        AssertInvalid("node 'n' has an unknown reversibility class 'bogus'", NodeWith(k, "bogus"));
        AssertInvalid("node 'n' has an unknown reversibility class ''", NodeWith(k, ""));
        AssertInvalid("node 'n' has an unknown reversibility class 'null'", NodeWith(k, null));
        AssertInvalid("node 'n' has an unknown reversibility class '1'", NodeWith(k, new Num("1")));
        // stricter than plan-lifecycle.ts:134, whose hasOwnProperty coerces ["reversible"] to its key
        AssertInvalid("node 'n' has an unknown reversibility class 'reversible'", NodeWith(k, new L { "reversible" }));
    }

    [Theory]
    [InlineData("reversible")]
    [InlineData("rate_limited")]
    [InlineData("costly")]
    [InlineData("irreversible")]
    public void ValidateAcceptsEveryKnownReversibilityClass(string cls)
    {
        var reg = new PlanRegistry();
        var root = reg.Draft(G, new List<D> { NodeWith("reversibility_class", cls) }).Record!.Root;
        Assert.True(reg.Validate(G, root).Ok);
    }

    // ---------- validate: the flow (L258-L282) ----------

    [Fact]
    public void ValidateMovesADraftAndStampsTheTime()
    {
        long t = 10;
        var reg = new PlanRegistry(new PlanRegistryOptions { Now = () => t });
        var root = Walk(reg, new List<D> { Node("n1"), Node("n2") }, PlanStates.Draft);
        t = 20;
        var v = reg.Validate(G, root);
        Assert.True(v.Ok, v.Reason);
        Assert.Equal(PlanStates.Validated, v.State);
        Assert.True(v.Record!.ValidatedAt == 20);
        Assert.True(v.Record.CreatedAt == 10);
        Assert.Equal(PlanStates.Validated, reg.Get(G, root)!.State);
        AssertRefused(reg.Validate(G, root), PlanStates.Validated, $"plan {root} is validated: cannot validate");
    }

    [Fact]
    public void ValidateRefusesAnUnknownRootAndAFailedStore()
    {
        AssertRefused(new PlanRegistry().Validate(G, "r"), PlanStates.Unknown, "plan r is unknown for this grant");
        var kv = new SwitchKv { GetThrows = true };
        AssertRefused(new PlanRegistry(new PlanRegistryOptions { Kv = kv }).Validate(G, "r"), PlanStates.Unknown, StoreFailed + "get down");
    }

    [Fact]
    public void ValidateRefusesStoredNodesThatNoLongerHashToTheRoot()
    {
        AssertNoLongerHashes(C(Rec("r", One(), PlanStates.Draft).ToJson()));
        // a structurally fine node that cannot be hashed has no root
        AssertNoLongerHashes("""{"createdAt":1,"grantRef":"g","nodes":[{"id":"\ud800","resource":"/r","verb":"v"}],"root":"r","state":"draft"}""");

        static void AssertNoLongerHashes(string text)
        {
            var kv = new MemoryAtomicKv();
            Store(kv, "r", text);
            AssertRefused(new PlanRegistry(new PlanRegistryOptions { Kv = kv }).Validate(G, "r"), PlanStates.Draft,
                "plan r is invalid: the stored nodes no longer hash to the root");
        }
    }

    static (PlanRegistry Reg, string Root) WithValidator(Func<PlanRecord, PlanValidation> validator)
    {
        var reg = new PlanRegistry(new PlanRegistryOptions { Validator = validator });
        return (reg, Walk(reg, One(), PlanStates.Draft));
    }

    [Fact]
    public void ValidatorAnswersDecideAndTheReasonIsReported()
    {
        void Refuses(Func<PlanRecord, PlanValidation> validator, string problem)
        {
            var (reg, root) = WithValidator(validator);
            AssertRefused(reg.Validate(G, root), PlanStates.Draft, $"plan {root} is invalid: {problem}");
            Assert.Equal(PlanStates.Draft, reg.Get(G, root)!.State);
        }
        Refuses(_ => new PlanValidation(false, "nope"), "nope");
        Refuses(_ => new PlanValidation(false, ""), ""); // plan-lifecycle.ts:218 reports the reason as given
        Refuses(_ => new PlanValidation(false), "refused by the validator");
        Refuses(_ => null!, "refused by the validator");
        Refuses(_ => throw new InvalidOperationException("boom"), "validator error (fail closed): boom");

        var (okReg, okRoot) = WithValidator(_ => new PlanValidation(true));
        Assert.True(okReg.Validate(G, okRoot).Ok);
    }

    [Fact]
    public void TheValidatorSeesTheDraftAndCannotChangeTheStoredNodes()
    {
        PlanRecord? seen = null;
        var (reg, root) = WithValidator(r =>
        {
            seen = r;
            r.Nodes[0]["verb"] = "evil";
            return new PlanValidation(true);
        });
        var v = reg.Validate(G, root);
        Assert.True(v.Ok, v.Reason);
        Assert.Equal((G, root, PlanStates.Draft), (seen!.GrantRef, seen.Root, seen.State));
        Assert.Equal("v", reg.Get(G, root)!.Nodes[0]["verb"]);
    }

    // The state can change between the read and the atomic move: the move re-checks it and names the step.
    [Fact]
    public void ValidateLosesARaceAgainstARevocation()
    {
        PlanRegistry reg = null!;
        reg = new PlanRegistry(new PlanRegistryOptions
        {
            Validator = r =>
            {
                Assert.True(reg.Revoke(G, r.Root, "raced").Ok);
                return new PlanValidation(true);
            },
        });
        var root = Walk(reg, One(), PlanStates.Draft);
        AssertRefused(reg.Validate(G, root), PlanStates.Revoked, $"plan {root} is revoked: cannot validate");
    }

    // ---------- the other transitions (L206-L224, L285-L304) ----------

    [Fact]
    public void AForbiddenTransitionChangesNothingAndIsNamed()
    {
        var reg = new PlanRegistry();
        var root = Walk(reg, One(), PlanStates.Draft);
        AssertRefused(reg.Commit(G, root), PlanStates.Draft, $"plan {root} is draft: cannot commit");
        AssertRefused(reg.Authorize(G, root, new PlanApproval("p")), PlanStates.Draft, $"plan {root} is draft: cannot authorize");
        Assert.Equal(PlanStates.Draft, reg.Get(G, root)!.State);
        Assert.False(reg.Status(G, root).Executable);

        Assert.True(reg.Validate(G, root).Ok);
        AssertRefused(reg.Authorize(G, root, new PlanApproval("p")), PlanStates.Validated, $"plan {root} is validated: cannot authorize");
        Assert.True(reg.Commit(G, root).Ok);
        AssertRefused(reg.Commit(G, root), PlanStates.Committed, $"plan {root} is committed: cannot commit");
        Assert.True(reg.Authorize(G, root, new PlanApproval("p")).Ok);
        AssertRefused(reg.Authorize(G, root, new PlanApproval("q")), PlanStates.Authorized, $"plan {root} is authorized: cannot authorize");
        Assert.Equal("p", reg.Get(G, root)!.Approval!.By);
        Assert.True(reg.Revoke(G, root, "first").Ok);
        AssertRefused(reg.Revoke(G, root, "second"), PlanStates.Revoked, $"plan {root} is revoked: cannot revoke");
        Assert.Equal("first", reg.Get(G, root)!.RevokedReason);
    }

    [Fact]
    public void AMoveOnAnUnknownRootOrAFailedStoreIsRefused()
    {
        AssertRefused(new PlanRegistry().Commit(G, "r"), PlanStates.Unknown, "plan r is unknown for this grant");
        var kv = new SwitchKv { UpdateThrows = true };
        AssertRefused(new PlanRegistry(new PlanRegistryOptions { Kv = kv }).Commit(G, "r"), PlanStates.Unknown, StoreFailed + "update down");
    }

    [Fact]
    public void EveryTransitionStampsItsTimeAndKeepsThePrevious()
    {
        long t = 10;
        var reg = new PlanRegistry(new PlanRegistryOptions { Now = () => t });
        var root = Walk(reg, One(), PlanStates.Draft);
        t = 20; Assert.True(reg.Validate(G, root).Ok);
        t = 30; Assert.True(reg.Commit(G, root).Ok);
        t = 40; Assert.True(reg.Authorize(G, root, new PlanApproval("p", 5000d)).Ok);
        t = 50; Assert.True(reg.Revoke(G, root, "why").Ok);
        var r = reg.Get(G, root)!;
        Assert.True(r.CreatedAt == 10 && r.ValidatedAt == 20 && r.CommittedAt == 30 && r.AuthorizedAt == 40 && r.RevokedAt == 50);
        Assert.Equal(PlanStates.Revoked, r.State);
        Assert.Equal("why", r.RevokedReason);
        Assert.Equal("p", r.Approval!.By);
        Assert.Equal(5000d, r.Approval.ExpiresAt!.Value);
    }

    [Fact]
    public void AuthorizeRefusesAnApprovalWithoutAuthorAndReportsTheCurrentState()
    {
        const string noBy = "an approval names who approved (`by`)";
        var reg = new PlanRegistry();
        var root = Walk(reg, One(), PlanStates.Committed);
        AssertRefused(reg.Authorize(G, root, null), PlanStates.Committed, noBy);
        AssertRefused(reg.Authorize(G, root, new PlanApproval("")), PlanStates.Committed, noBy);
        AssertRefused(reg.Authorize(G, "other", null), PlanStates.Unknown, noBy);
        var kv = new SwitchKv { GetThrows = true };
        AssertRefused(new PlanRegistry(new PlanRegistryOptions { Kv = kv }).Authorize(G, root, null), PlanStates.Unknown, noBy);
        Assert.Equal(PlanStates.Committed, reg.Get(G, root)!.State);
    }

    [Fact]
    public void AuthorizeRefusesANonFiniteExpiryAndAcceptsAFiniteOrAbsentOne()
    {
        const string notATime = "approval.expiresAt must be a time (epoch ms)";
        var reg = new PlanRegistry();
        var root = Walk(reg, One(), PlanStates.Committed);
        foreach (var bad in new[] { double.NaN, double.PositiveInfinity, double.NegativeInfinity })
            AssertRefused(reg.Authorize(G, root, new PlanApproval("p", bad)), PlanStates.Committed, notATime);
        AssertRefused(reg.Authorize(G, "other", new PlanApproval("p", double.NaN)), PlanStates.Unknown, notATime);
        Assert.Equal(PlanStates.Committed, reg.Get(G, root)!.State);

        Assert.True(reg.Authorize(G, root, new PlanApproval("p", 5000d)).Ok);
        var other = new PlanRegistry();
        Assert.True(other.Authorize(G, Walk(other, One(), PlanStates.Committed), new PlanApproval("p")).Ok);
    }

    [Fact]
    public void ARevocationWorksFromEveryLiveStateAndKeepsTheReason()
    {
        foreach (var state in new[] { PlanStates.Draft, PlanStates.Validated, PlanStates.Committed, PlanStates.Authorized })
        {
            var reg = new PlanRegistry();
            var root = Walk(reg, One(), state);
            var t = reg.Revoke(G, root, "why");
            Assert.True(t.Ok, t.Reason);
            Assert.Equal("why", t.Record!.RevokedReason);
            Assert.False(reg.Status(G, root).Executable);
        }
        var nullReason = new PlanRegistry();
        var r2 = Walk(nullReason, One(), PlanStates.Draft);
        Assert.Equal("", nullReason.Revoke(G, r2, null!).Record!.RevokedReason); // String(reason ?? '')
    }

    // ---------- status (L307-L330) ----------

    [Fact]
    public void StatusOfAnUnknownPlanOrAFailedStore()
    {
        var unknown = new PlanRegistry().Status(G, "r");
        Assert.Equal((PlanStates.Unknown, false), (unknown.State, unknown.Executable));
        Assert.Equal("plan r is unknown for this grant", unknown.Reason);
        Assert.Null(unknown.Record);

        var kv = new SwitchKv { GetThrows = true };
        var failed = new PlanRegistry(new PlanRegistryOptions { Kv = kv }).Status(G, "r");
        Assert.Equal((PlanStates.Unknown, false), (failed.State, failed.Executable));
        Assert.Equal(StoreFailed + "get down", failed.Reason);
        Assert.Null(failed.Record);
    }

    [Fact]
    public void StatusNamesEveryNotAuthorizedState()
    {
        void Why(string state, string? revokedReason, string why)
        {
            var kv = new MemoryAtomicKv();
            Seed(kv, "r", One(), state, null, revokedReason);
            var s = new PlanRegistry(new PlanRegistryOptions { Kv = kv }).Status(G, "r", 1);
            Assert.Equal((state, false), (s.State, s.Executable));
            Assert.Equal($"plan r is {why}", s.Reason);
            Assert.NotNull(s.Record);
        }
        Why(PlanStates.Draft, null, "draft, not authorized");
        Why(PlanStates.Validated, null, "validated, not authorized");
        Why(PlanStates.Committed, null, "committed but not authorized by the principal");
        Why(PlanStates.Revoked, "why", "revoked (why)");
        Why(PlanStates.Revoked, "", "revoked ()"); // plan-lifecycle.ts:174: only an absent reason gets the default
        Why(PlanStates.Revoked, null, "revoked (no reason given)");
        Why("other", null, "other, not authorized");
    }

    [Fact]
    public void TheApprovalExpiresAtItsInstant()
    {
        var reg = new PlanRegistry();
        var root = Walk(reg, One(), PlanStates.Authorized, new PlanApproval("p", 5000d));
        var before = reg.Status(G, root, 4999);
        Assert.True(before.Executable, before.Reason);
        Assert.Null(before.Reason);
        Assert.NotNull(before.Record);
        foreach (long at in new long[] { 5000, 5001 })
        {
            var s = reg.Status(G, root, at);
            Assert.Equal((PlanStates.Authorized, false), (s.State, s.Executable));
            Assert.Equal($"plan {root}: the principal's approval expired at 5000", s.Reason);
            Assert.NotNull(s.Record);
        }
    }

    [Fact]
    public void AnApprovalWithoutExpiryNeverLapses()
    {
        var reg = new PlanRegistry();
        var root = Walk(reg, One(), PlanStates.Authorized);
        Assert.True(reg.Status(G, root, 1_000_000_000_000_000).Executable);
    }

    [Fact]
    public void AStoredExpiryThatIsNotANumberIsExpired()
    {
        var kv = new MemoryAtomicKv();
        var root = PlanRegistry.RootOf(One());
        var j = Rec(root, One(), PlanStates.Authorized).ToJson();
        j["approval"] = new D { ["by"] = "p", ["expiresAt"] = null };
        Store(kv, root, C(j));
        var s = new PlanRegistry(new PlanRegistryOptions { Kv = kv }).Status(G, root, 1);
        Assert.False(s.Executable);
        Assert.Contains("the principal's approval expired at", s.Reason);
    }

    [Fact]
    public void StatusUsesAnExplicitTimeOverTheClockAndTheClockOtherwise()
    {
        long t = 4999;
        var reg = new PlanRegistry(new PlanRegistryOptions { Now = () => t });
        var root = Walk(reg, One(), PlanStates.Authorized, new PlanApproval("p", 5000d));
        Assert.True(reg.Status(G, root).Executable);
        Assert.False(reg.Status(G, root, 5000).Executable);
        t = 5000;
        Assert.False(reg.Status(G, root).Executable);
        Assert.True(reg.Status(G, root, 4999).Executable);
    }

    [Fact]
    public void AnExplicitTimeNeverAsksTheClock()
    {
        var kv = new MemoryAtomicKv();
        var root = PlanRegistry.RootOf(One());
        Seed(kv, root, One(), PlanStates.Authorized, new PlanApproval("p"));
        var reg = new PlanRegistry(new PlanRegistryOptions { Kv = kv, Now = () => throw new InvalidOperationException("clock down") });
        Assert.True(reg.Status(G, root, 1).Executable);
        Assert.Throws<InvalidOperationException>(() => reg.Status(G, root));
    }

    [Fact]
    public void AnAuthorizedPlanWhoseNodesDoNotHashIsNotExecutable()
    {
        var kv = new MemoryAtomicKv();
        Seed(kv, "r", One(), PlanStates.Authorized, new PlanApproval("p"));
        var reg = new PlanRegistry(new PlanRegistryOptions { Kv = kv });
        var s = reg.Status(G, "r", 1);
        Assert.Equal((PlanStates.Authorized, false), (s.State, s.Executable));
        Assert.Equal("plan r: the stored nodes no longer hash to the root", s.Reason);

        Store(kv, "r", """{"approval":{"by":"p"},"createdAt":1,"grantRef":"g","nodes":[{"id":"\ud800","resource":"/r","verb":"v"}],"root":"r","state":"authorized"}""");
        var u = reg.Status(G, "r", 1);
        Assert.Equal((PlanStates.Authorized, false), (u.State, u.Executable));
        Assert.Equal("plan r: the stored nodes no longer hash to the root", u.Reason);
    }

    // ---------- check (L333-L356) ----------

    static PlanCheckOptions Op(string verb, string resource, object? parameters = null, string? nodeId = null) =>
        new() { Now = 1, NodeId = nodeId, Operation = new Operation(verb, resource, parameters) };

    static string NotApproved(string root, string verb, string resource) =>
        $"plan {root}: the operation ({verb} on {resource} with these params) is not what the principal approved";

    static void AssertStale(PlanStatus s, string reason)
    {
        Assert.False(s.Executable);
        Assert.Equal(PlanStates.Authorized, s.State);
        Assert.Equal(reason, s.Reason);
        Assert.NotNull(s.Record);
    }

    static void AssertRuns(PlanStatus s)
    {
        Assert.True(s.Executable, s.Reason);
        Assert.Null(s.Reason);
        Assert.NotNull(s.Record);
    }

    [Fact]
    public void CheckOfANonExecutablePlanReturnsItsStatusBeforeLookingAtTheAction()
    {
        var reg = new PlanRegistry();
        var root = Walk(reg, One(), PlanStates.Committed);
        var want = $"plan {root} is committed but not authorized by the principal";
        Assert.Equal(want, reg.Check(G, root, new PlanCheckOptions { NodeId = "missing" }).Reason);
        Assert.Equal(want, reg.Check(G, root, Op("other", "/other")).Reason);
        Assert.Equal(want, reg.Check(G, root).Reason);
        Assert.Equal("plan x is unknown for this grant", reg.Check(G, "x", new PlanCheckOptions { NodeId = "n1" }).Reason);
    }

    [Fact]
    public void CheckWithoutAnActionIsTheStatus()
    {
        var (reg, root) = Authorized(Node("n1"));
        AssertRuns(reg.Check(G, root));
        AssertRuns(reg.Check(G, root, new PlanCheckOptions()));
    }

    [Fact]
    public void CheckUsesItsTime()
    {
        var reg = new PlanRegistry();
        var root = Walk(reg, One(), PlanStates.Authorized, new PlanApproval("p", 5000d));
        AssertRuns(reg.Check(G, root, new PlanCheckOptions { Now = 4999 }));
        Assert.False(reg.Check(G, root, new PlanCheckOptions { Now = 5000 }).Executable);
    }

    [Fact]
    public void CheckFindsTheNamedNodeById()
    {
        var (reg, root) = Authorized(Node("n1"), Node("n2"));
        AssertRuns(reg.Check(G, root, new PlanCheckOptions { NodeId = "n1" }));
        AssertRuns(reg.Check(G, root, new PlanCheckOptions { NodeId = "n2" }));
        AssertStale(reg.Check(G, root, new PlanCheckOptions { NodeId = "n3" }), $"plan {root} has no node 'n3'");

        var (numReg, numRoot) = Authorized(new D { ["id"] = new Num("1"), ["verb"] = "v", ["resource"] = "/r" });
        AssertStale(numReg.Check(G, numRoot, new PlanCheckOptions { NodeId = "1" }), $"plan {numRoot} has no node '1'");
    }

    [Fact]
    public void TheOperationMustMatchVerbAndResource()
    {
        var (reg, root) = Authorized(Node("n1", "v", "/r"));
        AssertRuns(reg.Check(G, root, Op("v", "/r")));
        AssertRuns(reg.Check(G, root, Op("v", "/r", nodeId: "n1")));
        AssertStale(reg.Check(G, root, Op("w", "/r")), NotApproved(root, "w", "/r"));
        AssertStale(reg.Check(G, root, Op("v", "/s")), NotApproved(root, "v", "/s"));
        AssertStale(reg.Check(G, root, Op("w", "/s")), NotApproved(root, "w", "/s"));
        AssertStale(reg.Check(G, root, Op("v", "/r", new D { ["a"] = new Num("1") })), NotApproved(root, "v", "/r"));
    }

    [Fact]
    public void ANonStringVerbOrResourceNeverMatches()
    {
        var (vReg, vRoot) = Authorized(new D { ["id"] = "n", ["verb"] = new Num("1"), ["resource"] = "/r" });
        AssertStale(vReg.Check(G, vRoot, Op("1", "/r")), NotApproved(vRoot, "1", "/r"));
        var (rReg, rRoot) = Authorized(new D { ["id"] = "n", ["verb"] = "v", ["resource"] = new Num("1") });
        AssertStale(rReg.Check(G, rRoot, Op("v", "1")), NotApproved(rRoot, "v", "1"));
    }

    [Fact]
    public void AnyCandidateMatchesUnlessTheNodeIsNamed()
    {
        var (reg, root) = Authorized(Node("n1", "v1", "/r1"), Node("n2", "v2", "/r2"));
        AssertRuns(reg.Check(G, root, Op("v1", "/r1")));
        AssertRuns(reg.Check(G, root, Op("v2", "/r2")));
        AssertRuns(reg.Check(G, root, Op("v2", "/r2", nodeId: "n2")));
        AssertStale(reg.Check(G, root, Op("v2", "/r2", nodeId: "n1")), NotApproved(root, "v2", "/r2"));
        AssertStale(reg.Check(G, root, Op("v1", "/r2")), NotApproved(root, "v1", "/r2")); // the verb of one, the resource of the other
    }

    [Fact]
    public void TheParamsDigestIsComparedAndDefaultsToTheEmptyParams()
    {
        var parameters = new D { ["a"] = new Num("1") };
        var (reg, root) = Authorized(NodeWith("params_digest", Pca.ParamsDigest(parameters)));
        AssertRuns(reg.Check(G, root, Op("v", "/r", parameters)));
        AssertStale(reg.Check(G, root, Op("v", "/r")), NotApproved(root, "v", "/r"));
        AssertStale(reg.Check(G, root, Op("v", "/r", new D { ["a"] = new Num("2") })), NotApproved(root, "v", "/r"));

        var (plain, plainRoot) = Authorized(Node("n"));
        AssertRuns(plain.Check(G, plainRoot, Op("v", "/r")));
        AssertRuns(plain.Check(G, plainRoot, Op("v", "/r", new D())));
        AssertStale(plain.Check(G, plainRoot, Op("v", "/r", parameters)), NotApproved(plainRoot, "v", "/r"));

        var (nul, nulRoot) = Authorized(NodeWith("params_digest", null));
        AssertRuns(nul.Check(G, nulRoot, Op("v", "/r")));

        var (num, numRoot) = Authorized(NodeWith("params_digest", new Num("1")));
        AssertStale(num.Check(G, numRoot, Op("v", "/r")), NotApproved(numRoot, "v", "/r"));
    }

    [Fact]
    public void UnhashableParamsAreRefused()
    {
        var (reg, root) = Authorized(Node("n"));
        AssertStale(reg.Check(G, root, Op("v", "/r", new D { ["x"] = "\uD800" })), $"plan {root}: the operation's params cannot be hashed");
        AssertStale(reg.Check(G, root, Op("v", "/r", new object())), $"plan {root}: the operation's params cannot be hashed");
    }

    // ---------- isPlanAuthorized and context (L359-L371) ----------

    [Fact]
    public void IsPlanAuthorizedIsTheExecutableBitAndFailsClosed()
    {
        var reg = new PlanRegistry();
        var root = Walk(reg, One(), PlanStates.Committed);
        Assert.False(reg.IsPlanAuthorized(G, root));
        Assert.False(reg.IsPlanAuthorized(G, "other"));
        Assert.True(reg.Authorize(G, root, new PlanApproval("p")).Ok);
        Assert.True(reg.IsPlanAuthorized(G, root));

        var kv = new MemoryAtomicKv();
        Seed(kv, root, One(), PlanStates.Authorized, new PlanApproval("p"));
        var noClock = new PlanRegistry(new PlanRegistryOptions { Kv = kv, Now = () => throw new InvalidOperationException("clock down") });
        Assert.False(noClock.IsPlanAuthorized(G, root));
    }

    [Fact]
    public void ContextCarriesAClonedPlanAndTheExecutableBit()
    {
        var reg = new PlanRegistry();
        Assert.Null(reg.Context(G, "other"));
        var root = Walk(reg, new List<D> { Node("n1"), Node("n2") }, PlanStates.Committed);

        var committed = reg.Context(G, root, 1)!;
        Assert.False(committed.PlanAuthorized);
        Assert.Equal(2, committed.Plan.Count);
        Assert.Equal(PlanStates.Committed, committed.Status.State);

        Assert.True(reg.Authorize(G, root, new PlanApproval("p", 5000d)).Ok);
        var live = reg.Context(G, root, 4999)!;
        Assert.True(live.PlanAuthorized);
        Assert.Equal("n1", ((D)live.Plan[0]!)["id"]);
        Assert.Equal("n2", ((D)live.Plan[1]!)["id"]);
        ((D)live.Plan[0]!)["verb"] = "changed";
        Assert.Equal("v", live.Status.Record!.Nodes[0]["verb"]);

        var expired = reg.Context(G, root, 5000)!;
        Assert.False(expired.PlanAuthorized);
        Assert.Equal(2, expired.Plan.Count);
    }
}

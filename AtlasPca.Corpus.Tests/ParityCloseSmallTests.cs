using AtlasPca.Grants;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>The smaller public functions added for parity: action scope derivation, assurance refresh, blueprint admission over a vendor verifier, the shadow decision-record field.</summary>
public class ParityCloseSmallTests
{
    static D Act(params string[] scopes) => new()
    {
        ["verb"] = "v", ["def_digest"] = "d", ["confirmed"] = true,
        ["upstream"] = new D { ["provider"] = "p", ["scopes_min"] = scopes.Cast<object?>().ToList() },
    };

    static string Code(D r) => (string)r["code"]!;

    [Fact]
    public void ScopesAreSortedDedupedAndPinnedToTheGrant()
    {
        var r = ActionScopes.Derive(Act("b", "a", "b"), "p", new[] { "a", "b", "c" });
        Assert.Equal(true, r["ok"]);
        Assert.Equal(new object?[] { "a", "b" }, ((L)r["scopes"]!).ToArray());
        Assert.Equal("p", r["provider"]);
        Assert.Equal("d", r["def_digest"]);
        Assert.Equal("exceeds_grant", Code(ActionScopes.Derive(Act("a", "z"), null, new[] { "a" })));
        Assert.Equal(true, ActionScopes.Derive(Act("a"))["ok"]);
    }

    [Fact]
    public void ScopeDerivationRefusesEverythingDoubtful()
    {
        Assert.Equal("unknown_action", Code(ActionScopes.Derive(null)));
        var un = Act("a"); un["confirmed"] = false;
        Assert.Equal("unconfirmed", Code(ActionScopes.Derive(un)));
        Assert.Equal("provider_mismatch", Code(ActionScopes.Derive(Act("a"), "other")));
        Assert.Equal("no_scopes", Code(ActionScopes.Derive(Act())));
        Assert.Equal("bad_scope", Code(ActionScopes.Derive(Act("has space"))));
        Assert.Equal("bad_scope", Code(ActionScopes.Derive(Act("q\"uote"))));
        Assert.Equal("bad_scope", Code(ActionScopes.Derive(Act(new string('x', 257)))));
        var noUp = Act("a"); noUp.Remove("upstream");
        Assert.Equal("no_scopes", Code(ActionScopes.Derive(noUp)));
        Assert.Equal("provider_mismatch", Code(ActionScopes.Derive(noUp, "p")));
    }

    [Fact]
    public void RefreshDropsTheLevelOfAFailedCheckAndKeepsUnsupported()
    {
        var rep = new AssuranceReport();
        rep.Set("a", new CheckAssurance("pass") { Level = "hardware" });
        rep.Set("u", new CheckAssurance("unsupported") { Reason = "no" });
        rep.Set("k", new CheckAssurance("pass") { Level = "x" });
        Assurance.Refresh(rep, new Dictionary<string, string> { ["a"] = "fail", ["u"] = "pass", ["n"] = "pass", ["k"] = "pass" });
        Assert.Equal("fail", rep.Get("a")!.Outcome);
        Assert.Null(rep.Get("a")!.Level);
        Assert.Equal("unsupported", rep.Get("u")!.Outcome);
        Assert.Equal("pass", rep.Get("n")!.Outcome);
        Assert.Equal("x", rep.Get("k")!.Level);
        Assert.True(Assurance.IsAwaitingAuditScheme("frost"));
        Assert.False(Assurance.IsAwaitingAuditScheme("multisig"));
    }

    sealed class FakeVerifier(HardwareResult r) : IVendorVerifier
    {
        public string Vendor => "fake";
        public HardwareResult Verify(D? evidence, AttestationBinding? expected, long nowMs) => r;
    }

    static D Bp(params D[] pins) => new() { ["key"] = "bp", ["epoch"] = 1L, ["runtime_pins"] = pins.Cast<object?>().ToList() };

    [Fact]
    public void AdmissionNeedsOkBoundAndAMatchingMeasuredPin()
    {
        var expected = new AttestationBinding("h", "g", 1, "n");
        var pin = new D { ["runtime_measurement"] = "m1" };
        var meas = new D { ["runtime_measurement"] = "m1", ["operator"] = "o" };
        var good = Blueprints.AdmitBlueprintInstance(Bp(pin), new D(), new FakeVerifier(new HardwareResult(true, true, null, meas)), expected, 1);
        Assert.Equal(true, good["admitted"]);
        Assert.Equal("not_bound", (string)Blueprints.AdmitBlueprintInstance(Bp(pin), new D(), new FakeVerifier(new HardwareResult(true, false, null, meas)), expected, 1)["code"]!);
        Assert.Equal("not_ok", (string)Blueprints.AdmitBlueprintInstance(Bp(pin), new D(), new FakeVerifier(HardwareResult.Fail("bad quote")), expected, 1)["code"]!);
        Assert.Equal("no_identity", (string)Blueprints.AdmitBlueprintInstance(Bp(pin), new D(), new FakeVerifier(new HardwareResult(true, true)), expected, 1)["code"]!);
        var other = new D { ["runtime_measurement"] = "m2" };
        Assert.Equal("no_matching_pin", (string)Blueprints.AdmitBlueprintInstance(Bp(other), new D(), new FakeVerifier(new HardwareResult(true, true, null, meas)), expected, 1)["code"]!);
        Assert.Equal("no_pins", (string)Blueprints.AdmitBlueprintInstance(new D { ["key"] = "bp" }, new D(), new FakeVerifier(HardwareResult.Fail("x")), expected, 1)["code"]!);
        var noDoc = Blueprints.AdmitBlueprintInstance(Bp(pin), null, new FakeVerifier(HardwareResult.Fail("x")), expected, 1);
        Assert.Equal("no evidence", noDoc["reason"]);
    }

    [Fact]
    public void ShadowRecordFieldKeepsDigestDecisionAndDivergence()
    {
        var f = Shadow.RecordField(new[] { new ShadowOutcome("d1", "deny", true, false), new ShadowOutcome("d2", "error", false, false) });
        Assert.Equal(2, f.Count);
        var first = (D)f[0]!;
        Assert.Equal(new[] { "digest", "decision", "diverged" }, first.Keys.ToArray());
        Assert.Equal("deny", first["decision"]);
        Assert.Equal(true, first["diverged"]);
    }

    [Fact]
    public void UndoAdmissionErrorNamesTheFirstProblem()
    {
        var ok = new D { ["id"] = "a", ["window_end"] = 5L, ["compensation"] = new D { ["verb"] = "undo" } };
        Assert.Null(PcaServer.UndoAdmissionError((object?)ok));
        Assert.Null(PcaServer.UndoAdmissionError(new UndoAdmission("a", 0, new UndoCompensationRef("undo", "/r"))));
        Assert.Contains("must be an object", PcaServer.UndoAdmissionError((object?)new L()));
        Assert.Contains("admission id", PcaServer.UndoAdmissionError(new UndoAdmission("", 1, new UndoCompensationRef("u", "/"))));
        Assert.Contains("admission id", PcaServer.UndoAdmissionError(new UndoAdmission(new string('x', 129), 1, new UndoCompensationRef("u", "/"))));
        Assert.Contains("window_end", PcaServer.UndoAdmissionError(new UndoAdmission("a", -1, new UndoCompensationRef("u", "/"))));
        Assert.Contains("compensation.verb", PcaServer.UndoAdmissionError(new UndoAdmission("a", 1, new UndoCompensationRef("", "/"))));
        Assert.Contains("window_end", PcaServer.UndoAdmissionError((object?)new D { ["id"] = "a", ["window_end"] = "5", ["compensation"] = new D { ["verb"] = "u" } }));
    }

    [Fact]
    public void BuiltinReviewOptsIsNullBeforeAReleaseSigning() => Assert.Null(ActionsKit.ActionBuiltin.BuiltinReviewOpts());

    [Fact]
    public void GeneratedEatKeysSignAndVerify()
    {
        foreach (var alg in new[] { "EdDSA", "ES256" })
        {
            var k = AttestEat.EatKey.Generate(alg);
            Assert.Equal(alg, k.Alg);
            var eat = AttestEat.EatToken.BuildEat(new D { ["issuer"] = "iss", ["nonce"] = "n", ["channelId"] = "ch", ["alg"] = alg }, k);
            var claims = AttestEat.EatToken.VerifyEat(eat, k.PublicOnly());
            Assert.Equal("iss", claims["iss"]);
            Assert.Equal("n", claims["eat_nonce"]);
            Assert.ThrowsAny<Exception>(() => AttestEat.EatToken.VerifyEat(eat, AttestEat.EatKey.Generate(alg).PublicOnly()));
        }
        Assert.Throws<ArgumentException>(() => AttestEat.EatKey.Generate("RS256"));
    }

    [Fact]
    public void IssuedNoncesAreRandomTimestampedAndAtLeastSixteenBytes()
    {
        var a = AttestEat.EatToken.IssueNonce(36 * 36 + 1);
        var b = AttestEat.EatToken.IssueNonce(36 * 36 + 1, 4);
        Assert.NotEqual(a.Value, b.Value);
        Assert.EndsWith(".101", a.Value);
        Assert.Equal(36 * 36 + 1, a.IssuedAt);
        Assert.True(Pca.B64uDecode(b.Value.Split('.')[0])!.Length >= 16);
        Assert.Equal(43, a.Value.Split('.')[0].Length);
        Assert.EndsWith(".0", AttestEat.EatToken.IssueNonce(0).Value);
        Assert.True(AttestEat.EatToken.IssueNonce().IssuedAt > 1e12);
    }

    [Fact]
    public void ToolCallComesFromTheActionAndTheBindingIsSigned()
    {
        var ctx = new D { ["action"] = new D { ["verb"] = "pay", ["params"] = new D { ["amount"] = 5L } }, ["toolBinding"] = "dg" };
        var tc = Pca.ToolCallOf(ctx);
        Assert.Equal("pay", tc.Tool);
        Assert.Equal(5L, ((D)tc.Args!)["amount"]);
        Assert.Equal("dg", tc.ToolSignatureDigest);
        var bare = Pca.ToolCallOf(new D { ["action"] = new D { ["verb"] = 3L, ["params"] = new L() } });
        Assert.Equal("", bare.Tool);
        Assert.Empty((D)bare.Args!);
        Assert.Null(bare.ToolSignatureDigest);
        Assert.Equal("", Pca.ToolCallOf(null).Tool);
    }

    [Fact]
    public void TheAgentContextCopiesTheBaseAndTheActionWinsLast()
    {
        var @base = new D { ["now"] = 1L, ["action"] = new D { ["verb"] = "forged" } };
        var act = new D { ["action"] = new D { ["verb"] = "real" } };
        var (ctx, call) = Pca.AgentCaveatContext(@base, act);
        Assert.Same(act, ctx["action"]);
        Assert.Equal(1L, ctx["now"]);
        Assert.Equal("real", call.Tool);
        Assert.Equal("forged", (string)((D)@base["action"]!)["verb"]!);
    }

    [Fact]
    public void ReversibilityClassPrefersTheActionThenTheBoundPlanNodeThenNothing()
    {
        var plan = new L { new D { ["id"] = "n1", ["reversibility_class"] = "irreversible" }, new D { ["reversibility_class"] = "reversible" } };
        Assert.Equal("rate_limited", Pca.ResolveReversibilityClass(new D { ["action"] = new D { ["reversibility_class"] = "rate_limited" } }, plan, "n1"));
        Assert.Equal("irreversible", Pca.ResolveReversibilityClass(new D { ["action"] = new D() }, plan, "n1"));
        Assert.Null(Pca.ResolveReversibilityClass(new D { ["action"] = new D() }, plan, null));
        Assert.Null(Pca.ResolveReversibilityClass(new D { ["action"] = new D() }, plan, "missing"));
        Assert.Null(Pca.ResolveReversibilityClass(null, null, "n1"));
        Assert.False(Pca.IsPinnedPqKey("a key"));
        Assert.False(Pca.IsPinnedPqKey(null));
    }

    [Fact]
    public void TheUnmetLimitNamesTheLimitAndTheAction()
    {
        var preds = new L { new D { ["verb"] = "read", ["where"] = new L { new D { ["field"] = "action.params.amount", ["op"] = "lte", ["value"] = 10L } } } };
        var over = new D { ["action"] = new D { ["verb"] = "read", ["resource"] = "/x", ["params"] = new D { ["amount"] = 50L } } };
        Assert.EndsWith(" not satisfied for read on /x", Predicates.NamedUnmetLimitReason(preds, over));
        var ok = new D { ["action"] = new D { ["verb"] = "read", ["resource"] = "/x", ["params"] = new D { ["amount"] = 5L } } };
        Assert.Null(Predicates.NamedUnmetLimitReason(preds, ok));
        Assert.Null(Predicates.NamedUnmetLimitReason(preds, new D { ["action"] = new D { ["verb"] = "write", ["resource"] = "/x" } }));
        Assert.Null(Predicates.NamedUnmetLimitReason(null, null));
    }

    [Fact]
    public void TheGuardDecisionIsTernary()
    {
        Assert.Equal("allow", PcaServer.DecisionOfResult(true, "deny"));
        Assert.Equal("escalate", PcaServer.DecisionOfResult(false, "escalate"));
        Assert.Equal("deny", PcaServer.DecisionOfResult(false, null));
        Assert.Equal("deny", PcaServer.DecisionOfResult(false, "allow"));
        Assert.Equal("escalate", PcaServer.DecisionOfResult(new AuthorizeResult { Allow = false, Decision = "escalate" }));
        Assert.True(PcaServer.IsAtomicStateStore(new MemoryStateStore()));
        Assert.False(PcaServer.IsAtomicStateStore(null));
    }

    [Fact]
    public void TheEscalationAnswerIsReadFromTheHeaderThenTheBody()
    {
        var json = "{\"a\":1}";
        var hdr = Pca.B64u(System.Text.Encoding.UTF8.GetBytes(json));
        Assert.Equal("1", ((Num)((D)PcaServer.DefaultEscalationAnswer(hdr, null)!)["a"]!).Raw);
        Assert.Equal("x", PcaServer.DefaultEscalationAnswer(null, "{\"escalation_answer\":\"x\"}"));
        Assert.Null(PcaServer.DefaultEscalationAnswer(null, "not json"));
        Assert.Null(PcaServer.DefaultEscalationAnswer(null, null));
        Assert.Throws<FormatException>(() => PcaServer.DefaultEscalationAnswer("!!!", null));
    }

    [Fact]
    public void ActionDefConstantsAreTheVersionOneSchema()
    {
        Assert.Equal(1, ActionsKit.ActionDefConstants.ActionDefVersion);
        Assert.Equal(9, ActionsKit.ActionDefConstants.ParamTypesV1.Count);
        Assert.Equal(new[] { "free", "material", "critical" }, ActionsKit.ActionDefConstants.SensitivityLevels.ToArray());
        Assert.Matches(ActionsKit.ActionDefConstants.TaintContextRe, "session_taint_max:pii");
        Assert.DoesNotMatch(ActionsKit.ActionDefConstants.TaintContextRe, "session_taint_max:pii\n");
        Assert.DoesNotMatch(ActionsKit.ActionDefConstants.TaintContextRe, "session_taint_max:");
        Assert.Equal(PqThreshold.PqThreshold.MaxPqQuorumEntries, PqThreshold.PqThreshold.MaxPqSignerEntries);
        Assert.Null(ActionsKit.ActionBuiltin.BuiltinReleaseCtx());
    }

    [Fact]
    public void WorkflowCommitmentRefusesAMalformedOrUnsignedWorkflow()
    {
        Assert.Equal("bad_workflow", Workflow.WorkflowCommitmentError(null, "x", 1));
        Assert.Equal("bad_workflow", Workflow.WorkflowCommitmentError(new D(), Pca.B64u(new byte[32]), 1));
        Assert.Throws<ArgumentException>(() => Workflow.WorkflowReceiptError(new D(), Pca.B64u(new byte[32]), new List<object?>(), 1));
    }

    [Fact]
    public void LayerCeilingsNameTheFirstCeilingThatRefuses()
    {
        var ctx = new D { ["action"] = new D { ["verb"] = "read", ["resource"] = "/x" } };
        var allow = new D { ["predicates"] = new L { new D { ["verb"] = "read" } } };
        var deny = new D { ["predicates"] = new L { new D { ["verb"] = "write" } } };
        Assert.True(IntentPkg.IntentLayers.DecideLayerCeilings(new D(), ctx).Pass);
        Assert.True(IntentPkg.IntentLayers.DecideLayerCeilings(new D { ["org"] = allow, ["site"] = allow }, ctx).Pass);
        var r = IntentPkg.IntentLayers.DecideLayerCeilings(new D { ["org"] = allow, ["site"] = deny, ["std"] = deny }, ctx);
        Assert.False(r.Pass);
        Assert.Equal("site", r.Layer);
        Assert.Contains("outside the site ceiling", r.Reason);
        Assert.Equal("org", IntentPkg.IntentLayers.DecideLayerCeilings(new D { ["bogus"] = allow }, ctx).Layer);
        Assert.Contains("malformed", IntentPkg.IntentLayers.DecideLayerCeilings(new D { ["std"] = null }, ctx).Reason);
        Assert.Contains("malformed", IntentPkg.IntentLayers.DecideLayerCeilings(new D { ["std"] = new D { ["predicates"] = new L(), ["x"] = 1L } }, ctx).Reason);
        Assert.False(IntentPkg.IntentLayers.DecideLayerCeilings(new D { ["org"] = new D { ["predicates"] = new L() } }, ctx).Pass);
        Assert.False(IntentPkg.IntentLayers.DecideLayerCeilings(new L(), ctx).Pass);
    }

    [Fact]
    public void TheLayerDecisionFollowsCeilingDeniedTaskOrQuestion()
    {
        var ctx = new D { ["action"] = new D { ["verb"] = "read", ["resource"] = "/x" } };
        D P(string verb) => new() { ["predicates"] = new L { new D { ["verb"] = verb } } };
        var d = IntentPkg.IntentLayers.DecideLayers(new D { ["task"] = new L { P("write"), P("read") } }, ctx);
        Assert.Equal(("admit", 1L), (d.Decision, d.By));
        Assert.Equal("intent_required", IntentPkg.IntentLayers.DecideLayers(new D { ["task"] = new L { P("write") } }, ctx).Decision);
        Assert.Equal("intent_denied", IntentPkg.IntentLayers.DecideLayers(new D { ["task"] = new L { P("read") }, ["denied"] = new L { P("read") } }, ctx).Decision);
        var c = IntentPkg.IntentLayers.DecideLayers(new D { ["org"] = P("write"), ["task"] = new L { P("read") } }, ctx);
        Assert.Equal(("ceiling", "org"), (c.Decision, c.Layer));
        Assert.Equal("intent_denied", IntentPkg.IntentLayers.DecideLayers(new D { ["task"] = new L(), ["extra"] = 1L }, ctx).Decision);
        Assert.Equal("intent_denied", IntentPkg.IntentLayers.DecideLayers(new D(), ctx).Decision);
        Assert.Equal("intent_denied", IntentPkg.IntentLayers.DecideLayers(new D { ["task"] = new L { new D() } }, ctx).Decision);
        Assert.Equal("intent_denied", IntentPkg.IntentLayers.DecideLayers(new D { ["task"] = new L(), ["denied"] = "no" }, ctx).Decision);
        Assert.Equal("ceiling", IntentPkg.IntentLayers.DecideLayers(null, ctx).Decision);
    }

    [Fact]
    public void CalibrationScalesTheMeasuredRateByTheAdvantageAndTheDuration()
    {
        var t = new Queue<double>(new[] { 0.0, 100.0 });
        var c = Vdf.Timelock.CalibrateSteps(101, 2, 1000, 10, () => t.Dequeue());
        Assert.Equal(10_000, c.MeasuredSquaringsPerSecond, 6);
        Assert.Equal(100_000, c.AssumedAdversarySquaringsPerSecond, 6);
        Assert.Equal(200_000, c.Steps);
        var tiny = new Queue<double>(new[] { 0.0, 1e9 });
        Assert.Equal(1, Vdf.Timelock.CalibrateSteps(101, 1e-9, 1, 1, () => tiny.Dequeue()).Steps);
        Assert.Throws<ArgumentOutOfRangeException>(() => Vdf.Timelock.CalibrateSteps(3, 1));
        Assert.Throws<ArgumentOutOfRangeException>(() => Vdf.Timelock.CalibrateSteps(101, 0));
        Assert.Throws<ArgumentOutOfRangeException>(() => Vdf.Timelock.CalibrateSteps(101, 1, 0));
        Assert.Throws<ArgumentOutOfRangeException>(() => Vdf.Timelock.CalibrateSteps(101, 1, 10, 0.5));
        Assert.True(Vdf.Timelock.CalibrateSteps(1000003, 1, 100).Steps >= 1);
    }

    [Fact]
    public void ImportedMcpToolsBecomeUnreviewedDefsAndSuggestCanBeSwitchedOff()
    {
        var tools = new L { new D { ["name"] = "get_thing", ["description"] = "d", ["inputSchema"] = new D { ["type"] = "object", ["properties"] = new D { ["id"] = new D { ["type"] = "string" } } } } };
        var r = Mcp.Mcp.ImportActionDefsFromMcp(tools, new D { ["ns"] = "demo", ["suggest"] = "none" });
        Assert.Equal(new[] { "defs", "todo", "source" }, r.Keys.ToArray());
        Assert.Single((L)r["defs"]!);
    }

    [Fact]
    public void TheLatticeToySharesAdditivelyAndNeedsEveryShare()
    {
        var key = new System.Numerics.BigInteger[] { 1, 2, 3, 4 };
        var ctr = 0;
        var shares = PqThreshold.LatticeThresholdExperimental.AdditiveShareLatticeKey(key, 3, true, null, q => (++ctr * 1000003) % q);
        Assert.Equal(3, shares.Count);
        Assert.Equal(new[] { 1, 2, 3 }, shares.Select(s => s.Index).ToArray());
        Assert.Equal(key, PqThreshold.LatticeThresholdExperimental.ReconstructLatticeKey(shares, true).ToArray());
        Assert.NotEqual(key, PqThreshold.LatticeThresholdExperimental.ReconstructLatticeKey(shares.Take(2).ToList(), true).ToArray());
        var os = PqThreshold.LatticeThresholdExperimental.AdditiveShareLatticeKey(new System.Numerics.BigInteger[] { -5, 0, 8380417, 9 }, 2, true);
        Assert.Equal(new System.Numerics.BigInteger[] { 8380412, 0, 0, 9 }, PqThreshold.LatticeThresholdExperimental.ReconstructLatticeKey(os, true).ToArray());
    }

    [Fact]
    public void TheLatticeToyRefusesWithoutTheOptInAndOnBadInput()
    {
        var key = new System.Numerics.BigInteger[] { 1, 2, 3, 4 };
        var ex = Assert.Throws<InvalidOperationException>(() => PqThreshold.LatticeThresholdExperimental.AdditiveShareLatticeKey(key, 2, false));
        Assert.StartsWith("EXPERIMENTAL", ex.Message);
        Assert.Throws<InvalidOperationException>(() => PqThreshold.LatticeThresholdExperimental.ReconstructLatticeKey(new List<PqThreshold.LatticeKeyShare>(), false));
        Assert.Throws<ArgumentOutOfRangeException>(() => PqThreshold.LatticeThresholdExperimental.AdditiveShareLatticeKey(key, 0, true));
        Assert.Throws<ArgumentOutOfRangeException>(() => PqThreshold.LatticeThresholdExperimental.AdditiveShareLatticeKey(key, 1025, true));
        Assert.Throws<ArgumentOutOfRangeException>(() => PqThreshold.LatticeThresholdExperimental.AdditiveShareLatticeKey(new System.Numerics.BigInteger[] { 1 }, 2, true));
        var shares = PqThreshold.LatticeThresholdExperimental.AdditiveShareLatticeKey(key, 2, true);
        Assert.Throws<ArgumentOutOfRangeException>(() => PqThreshold.LatticeThresholdExperimental.ReconstructLatticeKey(new List<PqThreshold.LatticeKeyShare>(), true));
        Assert.Throws<ArgumentException>(() => PqThreshold.LatticeThresholdExperimental.ReconstructLatticeKey(new[] { shares[0], shares[0] }, true));
        Assert.Throws<ArgumentException>(() => PqThreshold.LatticeThresholdExperimental.ReconstructLatticeKey(new[] { new PqThreshold.LatticeKeyShare(1, new System.Numerics.BigInteger[] { 1 }) }, true));
    }

    [Fact]
    public void TheDesignIsDataThatClaimsNoProductionReadiness()
    {
        var d = PqThreshold.LatticeThresholdExperimental.RaccoonDesign();
        Assert.Equal(false, d["productionReady"]);
        Assert.Equal("research-prototype", d["status"]);
        Assert.Equal(PqThreshold.LatticeThresholdExperimental.ExperimentalBanner, d["banner"]);
        Assert.Equal(5, ((L)d["construction"]!).Count);
        Assert.Equal(2, ((L)d["parameterSets"]!).Count);
    }

    [Fact]
    public void TheInProcessDoctorProbeDecidesARootMaxSpend()
    {
        var cav = new D { ["type"] = "max_spend", ["usd"] = 100L };
        Assert.False(Doctor.PcaDoctor.ProbeDecision(cav, 150, 1000).Allowed);
        Assert.True(Doctor.PcaDoctor.ProbeDecision(cav, 50, 1000).Allowed);
        var unknown = Doctor.PcaDoctor.ProbeDecision(new D { ["type"] = "pca-doctor-unknown-caveat" }, 50, 1000);
        Assert.False(unknown.Allowed);
        Assert.Equal(new[] { "pca-doctor-unknown-caveat" }, unknown.Reasons.ToArray());
    }

    [Fact]
    public void TheActionSpendIsTheOwnAmountInUsdOrNothing()
    {
        D Act(object? amount, object? currency = null, bool hasCurrency = false)
        {
            var p = new D { ["amount"] = amount };
            if (hasCurrency) p["currency"] = currency;
            return new D { ["action"] = new D { ["params"] = p } };
        }
        Assert.Equal(12.5, Caveats.ActionSpendUsd(Act(12.5)));
        Assert.Equal(0.0, Caveats.ActionSpendUsd(Act(0L)));
        Assert.Equal(7.0, Caveats.ActionSpendUsd(Act(new Num("7"), "USD", true)));
        Assert.Equal(7.0, Caveats.ActionSpendUsd(Act(7L, "usd", true)));
        Assert.Null(Caveats.ActionSpendUsd(Act(7L, "eur", true)));
        Assert.Null(Caveats.ActionSpendUsd(Act(-1L)));
        Assert.Null(Caveats.ActionSpendUsd(Act("7")));
        Assert.Null(Caveats.ActionSpendUsd(Act(double.NaN)));
        Assert.Null(Caveats.ActionSpendUsd(new D { ["action"] = new D() }));
        Assert.Null(Caveats.ActionSpendUsd(null));
    }

    static AuthorizeExecutionOptions ExecOpts() => new()
    {
        Audience = "rs", Grant = new D { ["id"] = "g" }, State = new MemoryStateStore(), IsRevoked = (_, _) => false,
    };

    static D Signed(string verb, string resource) => new() { ["grant_ref"] = "g", ["action"] = new D { ["verb"] = verb, ["resource"] = resource } };

    [Fact]
    public void ExecutionRefusesAnIncompleteConfigurationBeforeAnythingElse()
    {
        Assert.Equal(new[] { "audience", "grant or resolveGrant", "state", "isRevoked" }, PcaExecution.MissingExecutionComponents(new AuthorizeExecutionOptions()).ToArray());
        Assert.Equal(new[] { "audience", "grant or resolveGrant", "state", "isRevoked" }, PcaExecution.MissingExecutionComponents(null).ToArray());
        Assert.Empty(PcaExecution.MissingExecutionComponents(ExecOpts()));
        var d = PcaExecution.AuthorizeExecution(Signed("a", "r"), new ExecutionOperation("a", null, new D()), new AuthorizeExecutionOptions { Audience = "rs" });
        Assert.False(d.Allow);
        Assert.Equal("config", d.Kind);
        Assert.Equal(403, d.Status);
        Assert.Equal("full policy mode is missing grant or resolveGrant, state, isRevoked (fail closed)", d.Reason);
    }

    [Fact]
    public void ExecutionBindsTheProofToTheOperationBeforeTouchingState()
    {
        var o = ExecOpts();
        var d = PcaExecution.AuthorizeExecution(Signed("payments.send", "payments"), new ExecutionOperation("payments.refund", null, new D()), o);
        Assert.Equal(("binding", 403), (d.Kind, d.Status));
        Assert.Equal("the proof is for payments.send on payments, but this call is payments.refund", d.Reason);
        d = PcaExecution.AuthorizeExecution(Signed("payments.send", "payments"), new ExecutionOperation("payments.send", "other", new D()), o);
        Assert.Equal("the proof is for payments.send on payments, but this call is payments.send on other", d.Reason);
        d = PcaExecution.AuthorizeExecution(null, new ExecutionOperation("a", null, new D()), o);
        Assert.Equal("the proof is for undefined on undefined, but this call is a", d.Reason);
    }

    [Fact]
    public void ExecutionRefusesAnUnknownGrantReferenceAndFailsClosedOnAFault()
    {
        var o = ExecOpts();
        o.Grant = null;
        o.ResolveGrant = (_, _) => null;
        var d = PcaExecution.AuthorizeExecution(Signed("a", "r"), new ExecutionOperation("a", "r", new D()), o);
        Assert.Equal(("authn", 401, "unknown grant_ref"), (d.Kind, d.Status, d.Reason));
        o.ResolveGrant = (_, _) => throw new InvalidOperationException("store down");
        d = PcaExecution.AuthorizeExecution(Signed("a", "r"), new ExecutionOperation("a", "r", new D()), o);
        Assert.Equal(("policy", 403, "authorization error (fail closed): store down"), (d.Kind, d.Status, d.Reason));
    }
}

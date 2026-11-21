using AtlasPca.Dataflow;
using AtlasPca.Js;
using Xunit;
using J = AtlasPca.Jose.Jose;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Differential replay of the small public surface of core pca against the TypeScript reference (test-data/ref-core-small-surface.json.gz): workflow commitment and
/// receipt checks, membership proofs, the canonical compact-JWS gate, goal commitments, cheap claims, discharge requests, threshold assembly, decision meet, detector
/// receipts, the replay guard, obligations, the cheap chain check, discovery documents, policy links and the small policy-layer helpers.</summary>
public class RefCoreSmallSurfaceTests
{
    const string M = "ref-core-small-surface";

    static long N(object? o) => (long)JsJson.ToJsNumber(o);
    static D Ok(object? v) => new() { ["ok"] = true, ["v"] = v };
    static D Okf() => new() { ["ok"] = false };

    [Fact] public void WorkflowCommitmentError() => Base.Check(M, "workflowCommitmentError", a => Workflow.WorkflowCommitmentError(a[0], a[1] as string, N(a[2])));

    [Fact]
    public void WorkflowReceiptError() => Base.Check(M, "workflowReceiptError", a =>
    {
        var r = Workflow.WorkflowReceiptError(a[0], (string)a[1]!, (L)a[2]!, N(a[3]));
        return r == null ? null : (long)r; // the oracle reports the failing index, or null
    });

    [Fact] public void VerifyMembership() => Base.Check(M, "verifyMembership", a => Mesh.VerifyMembership(a[0] as string ?? "", a[1] as D, a[2] as string ?? ""));

    [Fact] public void IsCanonicalCompactJws() => Base.Check(M, "isCanonicalCompactJws", a => J.IsCanonicalCompactJws(a[0]));
    [Fact] public void IsCanonicalCompactJwsOpaque() => Base.Check(M, "isCanonicalCompactJwsOpaque", a => J.IsCanonicalCompactJws(a[0], 3, J.DefaultMaxJwsBytes, false));
    [Fact] public void IsCanonicalCompactJwsFive() => Base.Check(M, "isCanonicalCompactJwsFive", a => J.IsCanonicalCompactJws(a[0], 5));
    [Fact] public void IsCanonicalCompactJwsMax() => Base.Check(M, "isCanonicalCompactJwsMax", a => J.IsCanonicalCompactJws(a[0], 3, 40));

    [Fact]
    public void AssertCanonicalJwsSegments() => Base.Check(M, "assertCanonicalJwsSegments", a =>
    {
        try { return new D { ["ok"] = true, ["header"] = J.AssertCanonicalJwsSegments(a[0], a[1]) }; }
        catch (Exception) { return Okf(); }
    });

    [Fact] public void GoalCommitOf() => Base.Check(M, "goalCommitOf", a => Issue.GoalCommit((string)a[0]!, (string)a[1]!));
    [Fact] public void VerifyGoalCommit() => Base.Check(M, "verifyGoalCommit", a => PcaHelpers.VerifyGoalCommit(a[0] as string ?? "", a[1] as string ?? "", a[2] as string ?? ""));

    [Fact]
    public void PcactnCheapClaims() => Base.Check(M, "pcactnCheapClaims", a =>
    {
        var r = Pca.PcactnCheapClaims((D)a[0]!, (string)a[1]!, IntentJs.NumOf(a[2]) ?? double.NaN);
        return r == null ? null : new D { ["check"] = r.Check, ["reason"] = r.Reason };
    });

    [Fact] public void DischargeRequests() => Base.Check(M, "dischargeRequests", a => CaveatLang.DischargeRequests(a[0], a[1], a[2] as string));
    [Fact] public void AssembleThreshold() => Base.Check(M, "assembleThreshold", a => Pca.AssembleThreshold(a[0] as L));
    [Fact] public void IsBudgetAllocCaveat() => Base.Check(M, "isBudgetAllocCaveat", a => PcaHelpers.IsBudgetAllocCaveat(a[0]));
    [Fact] public void MeetAll() => Base.Check(M, "meetAll", a => PcaHelpers.MeetAll(((L)a[0]!).Select(x => x as string)));

    [Fact]
    public void EscalateThreshold() => Base.Check(M, "escalateThreshold", a =>
    {
        var t = (D)a[0]!;
        var r = Risk.Escalate(new RequiredThreshold((int)N(t["t"]), (string)t["proof"]!, t["optimisticAllowed"] is true), (int)N(a[1]));
        return new D { ["t"] = (long)r.T, ["proof"] = r.Proof, ["optimisticAllowed"] = r.OptimisticAllowed };
    });

    [Fact] public void DetectorReceiptShapeError() => Base.Check(M, "detectorReceiptShapeError", a => DetectorReceipts.ShapeError(a[0]));
    [Fact] public void DetectorReceiptRef() => Base.Check(M, "detectorReceiptRef", a => DetectorReceipts.Ref(a[0]));
    [Fact] public void DetectorPolicyError() => Base.Check(M, "detectorPolicyError", a => DetectorReceipts.PolicyError(a[0]));

    [Fact]
    public void GuardSeq() => Base.Check(M, "guardSeq", a =>
    {
        var o = (D)a[0]!;
        var store = new InMemoryReplayStore();
        var opts = new ReplayGuardOptions((string)o["aud"]!, 0, o.TryGetValue("clockSkewMs", out var sk) && sk != null ? JsJson.ToJsNumber(sk) : (double?)null, o.GetValueOrDefault("requireNonce") is not false, o.GetValueOrDefault("counters") is true ? store : null);
        var outp = new L();
        foreach (var st in (L)a[1]!)
        {
            var step = (D)st!;
            var v = PcaReplay.GuardPCActnReplay(store, step["p"], opts with { Now = JsJson.ToJsNumber(step["now"]) }).GetAwaiter().GetResult();
            outp.Add(v.Ok ? new D { ["ok"] = true } : new D { ["ok"] = false, ["code"] = v.Code, ["reason"] = v.Reason });
        }
        return outp;
    });

    [Fact]
    public void CollectObligations() => Base.Check(M, "collectObligations", a =>
    {
        var r = Obligations.CollectObligations(a[0], a[1] as D);
        return r.Ok ? new D { ["ok"] = true, ["obligations"] = r.Obligations.ToList() } : new D { ["ok"] = false, ["reason"] = r.Reason };
    });

    [Fact]
    public void VerifyChainCheap() => Base.Check(M, "verifyChainCheap", a =>
    {
        var r = Pca.VerifyChainCheap(a[0], a.Count > 1 ? a[1] as string : null, a.Count > 2 && a[2] is L s ? s.OfType<string>().ToList() : null);
        return r.Ok ? new D { ["ok"] = true, ["pqHops"] = (long)r.PqHops } : new D { ["ok"] = false, ["reason"] = r.Reason };
    });

    [Fact] public void HolderPqKey() => Base.Check(M, "holderPqKey", a => Pca.HolderPqKey(a[0], (string)a[1]!, a[2], a.Count > 3 ? a[3] as string : null));

    [Fact] public void ParseDiscoveryDocument() => Base.Check(M, "parseDiscoveryDocument", a => PcaDiscovery.ParseDiscoveryDocument(a[0]));
    [Fact] public void ParseDiscoveryIntent() => Base.Check(M, "parseDiscoveryIntent", a => PcaDiscovery.ParseDiscoveryIntent(a[0]));
    [Fact] public void AcceptsSuite() => Base.Check(M, "acceptsSuite", a => PcaDiscovery.AcceptsSuite((D)a[0]!, (string)a[1]!));

    [Fact]
    public void CreateLink() => Base.Check(M, "createLink", a =>
    {
        try { return new D { ["ok"] = true, ["ref"] = PolicyAuthoring.CreateLink((D)a[0]!, (D)a[1]!, a.Count > 2 && a[2] is true) }; }
        catch (Exception) { return Okf(); }
    });

    [Fact] public void SlotsDigest() => Base.Check(M, "slotsDigest", a => PolicyAuthoring.SlotsDigest(a[0]));
    [Fact] public void LinkDigest() => Base.Check(M, "linkDigest", a => PolicyAuthoring.LinkDigest((D)a[0]!));

    [Fact] public void ResolveReversibilityClass() => Base.Check(M, "resolveReversibilityClass", a => Pca.ResolveReversibilityClass(a[0] as D, a[1] as L, a[2] as string));

    [Fact]
    public void AgentCaveatContext() => Base.Check(M, "agentCaveatContext", a =>
    {
        var (ctx, call) = Pca.AgentCaveatContext((D)a[0]!, (D)a[1]!);
        var tc = new D { ["tool"] = call.Tool, ["args"] = call.Args };
        if (call.ToolSignatureDigest != null) tc["toolSignatureDigest"] = call.ToolSignatureDigest;
        return new D(ctx) { ["toolCall"] = tc };
    });

    [Fact] public void NamedUnmetLimitReason() => Base.Check(M, "namedUnmetLimitReason", a => Predicates.NamedUnmetLimitReason(a[0], a[1] as D));

    [Fact]
    public void CatalogReversibilityScore() => Base.Check(M, "catalogReversibilityScore", _ =>
        Catalog.ReversibilityScore.ToDictionary(kv => kv.Key, kv => (object?)new Num(JsJson.NumberToString(Convert.ToDouble(kv.Value, System.Globalization.CultureInfo.InvariantCulture)))));

    [Fact]
    public void ValidateRevocationStaleness() => Base.Check(M, "validateRevocationStaleness", a =>
    {
        try { RevocationStalenessPolicy.FromJson(a[0]).Validate(); return new D { ["ok"] = true }; }
        catch (Exception) { return Okf(); }
    });

    [Fact]
    public void SpcExpectation() => Base.Check(M, "spcExpectation", a =>
    {
        try { return Ok(Approval.SpcExpectation((D)a[0]!, "https://shop.example", a.Count > 1 && a[1] is string p ? p : "name")); }
        catch (Exception) { return Okf(); }
    });

    [Fact]
    public void CibaApprovalDetails() => Base.Check(M, "cibaApprovalDetails", a =>
    {
        try { return Ok(Approval.CibaApprovalDetails((D)a[0]!)); }
        catch (Exception) { return Okf(); }
    });

    [Fact]
    public void EveryFnIsHandledOrNamedAsNotReplayed() { Base.Covers(M, new[]
    {
        "workflowCommitmentError", "workflowReceiptError", "verifyMembership", "isCanonicalCompactJws", "isCanonicalCompactJwsOpaque", "isCanonicalCompactJwsFive", "isCanonicalCompactJwsMax",
        "assertCanonicalJwsSegments", "goalCommitOf", "verifyGoalCommit", "pcactnCheapClaims", "dischargeRequests", "assembleThreshold", "isBudgetAllocCaveat", "meetAll", "escalateThreshold",
        "detectorReceiptShapeError", "detectorReceiptRef", "detectorPolicyError", "guardSeq", "collectObligations", "verifyChainCheap", "holderPqKey", "parseDiscoveryDocument",
        "parseDiscoveryIntent", "acceptsSuite", "createLink", "validateRevocationStaleness", "spcExpectation", "cibaApprovalDetails", "slotsDigest", "linkDigest", "resolveReversibilityClass", "agentCaveatContext", "namedUnmetLimitReason", "catalogReversibilityScore",
        // not replayed here: the detector fold, discovery build / fetch, template and builder listings, limits constants and catalog risk have a .NET shape that differs from
        // the reference's (typed handles, injected fetch); the undo lifecycle and store belong to the undo work
        "detectorSignal", "buildDiscoveryDocument", "fetchDiscovery", "listTemplates", "fromTemplate", "policyBuilder", "limits", "catalogRisk", "undoLifecycle", "undoStore",
    }); Assert.Equal(1113, Base.Total(M)); }
}

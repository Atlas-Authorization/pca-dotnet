using AtlasPca.IntentPkg;
using AtlasPca.Js;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Differential replay of the pure parity surface of core pca against the TypeScript reference (test-data/ref-core-parity-pure.json.gz): hash-suite agility, the
/// multi-agent budget algebra, the receipt chain, discovery documents, cheap claims, the policy-layer helpers and the layer decisions.</summary>
public class RefCoreParityPureTests
{
    const string M = "ref-core-parity-pure";

    internal static double F(object? o) => JsJson.ToJsNumber(o);
    internal static long N(object? o) => (long)F(o);

    internal static TrustBudget Budget(object? o)
    {
        var b = (D)o!;
        // a missing member is undefined: every comparison with it is false, as with NaN
        return new TrustBudget(b.TryGetValue("B", out var bb) ? F(bb) : double.NaN, b.TryGetValue("tau", out var tt) ? F(tt) : double.NaN, b.GetValueOrDefault("asOf") is { } a ? F(a) : (double?)null);
    }

    internal static D BudgetJson(TrustBudget b)
    {
        var o = new D();
        if (!double.IsNaN(b.B)) o["B"] = b.B; // an undefined member is left out of the JSON
        if (!double.IsNaN(b.Tau)) o["tau"] = b.Tau;
        if (b.AsOf != null) o["asOf"] = b.AsOf;
        return o;
    }

    internal static IReadOnlyDictionary<string, string>? Checks(object? verdict) =>
        (verdict as D)?.GetValueOrDefault("checks") is D c ? c.ToDictionary(kv => kv.Key, kv => (string)kv.Value!) : null;

    internal static bool Allow(object? verdict) => (verdict as D)?.GetValueOrDefault("allow") is true;

    internal static List<D> Log(object? o) => ((L)o!).Cast<D>().ToList();

    [Fact] public void HashCanonical() => Base.Check(M, "hashCanonical", a => HashSuites.HashCanonical(a[0], (string)a[1]!));
    [Fact] public void B64uLen() => Base.Check(M, "b64uLen", a => HashSuites.B64uLen((int)N(a[0])));
    [Fact] public void IsHashSuite() => Base.Check(M, "isHashSuite", a => HashSuites.IsHashSuite(a[0]));
    [Fact] public void IsCanonicalB64u() => Base.Check(M, "isCanonicalB64u", a => HashSuites.IsCanonicalB64u(a[0], a.Count > 1 && a[1] != null ? (int?)N(a[1]) : null));
    [Fact] public void MeetAll() => Base.Check(M, "meetAll", a => PcaHelpers.MeetAll(((L)a[0]!).Select(x => x as string)));
    [Fact] public void IsBudgetAllocCaveat() => Base.Check(M, "isBudgetAllocCaveat", a => PcaHelpers.IsBudgetAllocCaveat(a[0]));

    [Fact]
    public void SubBudget() => Base.Check(M, "subBudget", a =>
    {
        var r = Risk.SubBudget(Budget(a[0]), F(a[1]));
        return r.Ok ? new D { ["ok"] = true, ["sub"] = BudgetJson(r.Nodes![0]) } : new D { ["ok"] = false, ["reason"] = r.Reason };
    });

    [Fact]
    public void DebitConsolidated() => Base.Check(M, "debitConsolidated", a =>
    {
        var r = Risk.DebitConsolidated(Budget(a[0]), Budget(a[1]), F(a[2]));
        return r.Ok ? new D { ["ok"] = true, ["parent"] = BudgetJson(r.Nodes![0]), ["sub"] = BudgetJson(r.Nodes![1]) } : new D { ["ok"] = false, ["reason"] = r.Reason };
    });

    [Fact]
    public void DebitConsolidatedPath() => Base.Check(M, "debitConsolidatedPath", a =>
    {
        var r = Risk.DebitConsolidatedPath(((L)a[0]!).Select(Budget).ToList(), F(a[1]));
        return r.Ok ? new D { ["ok"] = true, ["nodes"] = r.Nodes!.Select(b => (object?)BudgetJson(b)).ToList() } : new D { ["ok"] = false, ["reason"] = r.Reason };
    });

    [Fact] public void Recharge() => Base.Check(M, "recharge", a => BudgetJson(Risk.Recharge(Budget(a[0]), F(a[1]), F(a[2]), F(a[3]))));
    [Fact] public void RechargeFull() => Base.Check(M, "rechargeFull", a => BudgetJson(Risk.RechargeFull(F(a[1]), F(a[2]))));

    [Fact]
    public void ReceiptFor() => Base.Check(M, "receiptFor", a =>
        ActionReceipts.ReceiptFor((string)a[0]!, N(a[1]), (D)a[2]!, Allow(a[3]), Checks(a[3]), a.Count > 4 && a[4] != null ? N(a[4]) : (long?)null));

    [Fact]
    public void AppendReceipt() => Base.Check(M, "appendReceipt", a =>
        ActionReceipts.AppendReceipt(Log(a[0]), (D)a[1]!, Allow(a[2]), Checks(a[2]), a.Count > 3 && a[3] != null ? N(a[3]) : (long?)null));

    [Fact]
    public void VerifyReceiptChain() => Base.Check(M, "verifyReceiptChain", a =>
    {
        var r = ActionReceipts.VerifyReceiptChain(Log(a[0]));
        if (r.Ok) return new D { ["ok"] = true };
        var o = new D { ["ok"] = false };
        if (r.BrokenAt != null) o["brokenAt"] = r.BrokenAt;
        o["reason"] = r.Reason;
        return o;
    });

    [Fact] public void ReceiptHead() => Base.Check(M, "receiptHead", a => ActionReceipts.ReceiptHead(Log(a[0])));

    [Fact] public void ParseDiscoveryDocument() => Base.Check(M, "parseDiscoveryDocument", a => PcaDiscovery.ParseDiscoveryDocument(a[0]));
    [Fact] public void ParseDiscoveryIntent() => Base.Check(M, "parseDiscoveryIntent", a => PcaDiscovery.ParseDiscoveryIntent(a[0]));
    [Fact] public void AcceptsSuite() => Base.Check(M, "acceptsSuite", a => PcaDiscovery.AcceptsSuite((D)a[0]!, (string)a[1]!));
    [Fact] public void DetectorPolicyError() => Base.Check(M, "detectorPolicyError", a => Dataflow.DetectorReceipts.PolicyError(a[0]));
    [Fact] public void DetectorReceiptShapeError() => Base.Check(M, "detectorReceiptShapeError", a => Dataflow.DetectorReceipts.ShapeError(a[0]));

    [Fact]
    public void PcactnCheapClaims() => Base.Check(M, "pcactnCheapClaims", a =>
    {
        var r = Pca.PcactnCheapClaims((D)a[0]!, (string)a[1]!, IntentJs.NumOf(a[2]) ?? double.NaN);
        return r == null ? null : new D { ["check"] = r.Check, ["reason"] = r.Reason };
    });

    [Fact] public void ResolveReversibilityClass() => Base.Check(M, "resolveReversibilityClass", a => Pca.ResolveReversibilityClass(a[0] as D, a[1] as L, a[2] as string));

    [Fact]
    public void AgentCaveatContext() => Base.Check(M, "agentCaveatContext", a =>
    {
        var (ctx, call) = Pca.AgentCaveatContext((D)a[0]!, (D)a[1]!);
        var tc = new D { ["tool"] = call.Tool, ["args"] = call.Args };
        if (call.ToolSignatureDigest != null) tc["toolSignatureDigest"] = call.ToolSignatureDigest;
        return new D(ctx) { ["toolCall"] = tc };
    });

    [Fact]
    public void EnforceRequired() => Base.Check(M, "enforceRequired", a =>
    {
        var v = (D)a[0]!;
        var r = PcaServer.EnforceRequired(v["allow"] is true, ((D)v["checks"]!).Select(kv => new KeyValuePair<string, string>(kv.Key, (string)kv.Value!)),
            ((L)v["reasons"]!).Select(x => (string)x!), ((L)a[1]!).Select(x => (string)x!));
        var checks = new D();
        foreach (var kv in r.Checks) checks[kv.Key] = kv.Value;
        return new D { ["allow"] = r.Allow, ["checks"] = checks, ["reasons"] = r.Reasons.Cast<object?>().ToList() };
    });

    [Fact]
    public void CollectObligations() => Base.Check(M, "collectObligations", a =>
    {
        var r = Obligations.CollectObligations(a[0], a[1] as D);
        return r.Ok ? new D { ["ok"] = true, ["obligations"] = r.Obligations.ToList() } : new D { ["ok"] = false, ["reason"] = r.Reason };
    });

    [Fact]
    public void DecideLayers() => Base.Check(M, "decideLayers", a =>
    {
        var d = IntentLayers.DecideLayers(a[0], (D)a[1]!);
        var o = new D { ["decision"] = d.Decision };
        if (d.Decision == "admit") o["by"] = d.By;
        if (d.Layer != null) o["layer"] = d.Layer;
        return o;
    });

    [Fact]
    public void DecideLayerCeilings() => Base.Check(M, "decideLayerCeilings", a =>
    {
        var r = IntentLayers.DecideLayerCeilings(a[0], (D)a[1]!);
        return r.Pass ? new D { ["status"] = "pass" } : new D { ["status"] = "fail", ["layer"] = r.Layer, ["reason"] = r.Reason };
    });

    [Fact]
    public void EveryFnIsHandledOrNamedAsNotReplayed() { Base.Covers(M, new[]
    {
        "hashCanonical", "b64uLen", "isHashSuite", "isCanonicalB64u", "meetAll", "isBudgetAllocCaveat", "subBudget", "debitConsolidated", "debitConsolidatedPath", "recharge", "rechargeFull",
        "receiptFor", "appendReceipt", "verifyReceiptChain", "receiptHead", "parseDiscoveryDocument", "parseDiscoveryIntent", "acceptsSuite", "detectorPolicyError", "detectorReceiptShapeError",
        "pcactnCheapClaims", "resolveReversibilityClass", "agentCaveatContext", "collectObligations", "decideLayers", "decideLayerCeilings", "enforceRequired",
        // the strict-number rule takes a binary64 value in the reference; the .NET rule reads the number's text (checked by the strict-number vectors)
        "strictNumberError",
    }); Assert.Equal(405, Base.Total(M)); }
}

using System.Text.RegularExpressions;
using AtlasPca;
using AtlasPca.Gateway;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Differential replay of the PCA gateway (canonical query, request binding, path hardening, replay guard, provenance log, presented
/// artifacts, authorize / create over real signed proofs, the Envoy HTTP / gRPC shapes and the Lambda authorizers) against the TypeScript
/// reference (test-data/ref-gateway.json.gz). Compared after masking: verdict objects print "&lt;verdict&gt;" and the strict-JSON parser's own
/// message in "undecodable PCA-Action header: ..." prints "&lt;json&gt;".</summary>
public class RefGatewayTests
{
    const string M = "ref-gateway";

    internal static object? Mask(object? s)
    {
        switch (s)
        {
            case string t: return Regex.Replace(t, @"undecodable PCA-Action header: (?!PCA-Action header)[\s\S]*", "undecodable PCA-Action header: <json>");
            case L l: return l.Select(Mask).ToList();
            case D m:
                var o = new D();
                foreach (var (k, v) in m) o[k] = k is "x-pca-verdict" or "pcaVerdict" && v is string vs && vs != "" ? "<verdict>" : Mask(v);
                if (o.GetValueOrDefault("header") is D h && h.GetValueOrDefault("key") is "x-pca-verdict" && h.GetValueOrDefault("value") is string hv && hv != "")
                    o["header"] = new D(h) { ["value"] = "<verdict>" };
                return o;
            default: return s;
        }
    }

    sealed class Fixed(bool v) : IReplayGuard { public bool Claim(string key, double exp, double? now) => v; }
    sealed class Raising : IReplayGuard { public bool Claim(string key, double exp, double? now) => throw new InvalidOperationException("store down"); }

    internal static GatewayOptions Build(D spec)
    {
        var now = (long)IntentJs.NumOf(spec["now"])!.Value;
        var grants = (D)spec["grants"]!;
        var o = new GatewayOptions
        {
            Audience = (string)spec["audience"]!,
            Routes = ((L)spec["routes"]!).Select(r => (D)r!).ToList(),
            ResolveGrant = (gref, _) => gref is string s && grants.GetValueOrDefault(s) is D g ? g : null,
            Now = () => now,
        };
        var b = spec.GetValueOrDefault("bindRequest");
        if (b is "off") o.BindRequest = false;
        else if (b != null) o.BindRequest = b;
        if (spec.GetValueOrDefault("unmatched") is string um) o.UnmatchedRoute = um;
        if (spec.GetValueOrDefault("pathPolicy") is string pp) o.PathPolicy = pp;
        if (spec.GetValueOrDefault("requireChecks") is L rc) o.RequireChecks = rc.Select(x => (string)x!).ToList();
        if (spec.GetValueOrDefault("realm") is string realm) o.Realm = realm;
        if (spec.GetValueOrDefault("skipPlan") is true) o.InsecureSkipPlanRootCheck = true;
        if (spec.GetValueOrDefault("planRoots") is L pr) o.AuthorizedPlanRoots = pr.Select(x => (string)x!).ToList();
        o.ReplayGuard = (string)spec["replay"]! switch
        {
            "always" => new Fixed(true),
            "false" => new Fixed(false),
            "throws" => new Raising(),
            "memory" => new MemoryReplayGuard(100000, () => now),
            "memory-full" => new MemoryReplayGuard(1, () => now),
            _ => null,
        };
        o.Revocation = (string)spec["revocation"]! switch
        {
            "ok" => _ => new D { ["enforced"] = true, ["ok"] = true },
            "revoked" => _ => new D { ["enforced"] = true, ["ok"] = false, ["reason"] = "grant revoked" },
            "revoked-noreason" => _ => new D { ["enforced"] = true, ["ok"] = false },
            "notEnforced" => _ => new D { ["enforced"] = false },
            "throws" => _ => throw new InvalidOperationException("rev down"),
            _ => null,
        };
        if (spec.GetValueOrDefault("checkProof") is string cp)
            o.CheckProof = cp switch
            {
                "true" => _ => true,
                "false" => _ => false,
                "obj-true" => _ => new D { ["allow"] = true },
                "obj-false" => _ => new D { ["allow"] = false },
                "obj-false-reason" => _ => new D { ["allow"] = false, ["reason"] = "over limit" },
                _ => _ => throw new InvalidOperationException("policy down"),
            };
        switch ((string)spec["policy"]!)
        {
            case "sig": o.PolicyMode = "signature-only"; break;
            case "bogus": o.PolicyMode = "bogus"; break;
            case "full-missing": o.PolicyMode = "full"; o.Full = new FullPolicy(); break;
        }
        return o;
    }

    static object? Proj(GatewayDecision d)
    {
        var o = new D { ["allow"] = d.Allow, ["status"] = d.Status, ["code"] = d.Code, ["reason"] = d.Reason, ["headers"] = d.Headers.ToDictionary(e => e.Key, e => (object?)e.Value) };
        if (d.Matched != null) o["matched"] = d.Matched;
        if (d.Pcactn?.GetValueOrDefault("grant_ref") is { } g) o["grant"] = g;
        if (d.Verdict != null) o["verdictAllow"] = d.Verdict["allow"];
        return Mask(o);
    }

    static object? Authorize(D spec)
    {
        Func<D, GatewayDecision> gw;
        try { gw = PcaGateway.CreateGateway(Build(spec)); }
        catch (ArgumentException e) { return new D { ["create"] = e.Message }; }
        return ((L)spec["requests"]!).Select(r => Proj(gw((D)r!))).ToList();
    }

    static object? Adapter(D spec, Func<GatewayOptions, Func<D, D>> make)
    {
        Func<D, D> fn;
        try { fn = make(Build(spec)); }
        catch (ArgumentException e) { return new D { ["create"] = e.Message }; }
        return Mask(fn((D)((L)spec["events"]!)[0]!));
    }

    static object? LambdaLone(D spec, Func<GatewayOptions, Func<D, D>> make)
    {
        try { return Mask(make(Build(spec))((D)((L)spec["events"]!)[0]!)); }
        catch (FormatException e) { return new D { ["threw"] = e.Message }; }
    }

    static object? Replay(D spec)
    {
        double clock = IntentJs.NumOf(spec.GetValueOrDefault("clock") ?? new Num("0"))!.Value;
        var g = new MemoryReplayGuard((int)IntentJs.NumOf(spec["max"])!.Value, () => clock);
        var o = new L();
        foreach (var op0 in (L)spec["ops"]!)
        {
            var op = (D)op0!;
            if (op.TryGetValue("setClock", out var sc)) { clock = IntentJs.NumOf(sc)!.Value; continue; }
            try { o.Add(g.Claim((string)op["key"]!, IntentJs.NumOf(op["exp"])!.Value, op.GetValueOrDefault("now") is { } n ? IntentJs.NumOf(n) : null)); }
            catch (Exception e) { o.Add(new D { ["threw"] = e.Message }); }
        }
        return o;
    }

    static object? ProvLog(D spec)
    {
        var log = new MemoryProvenanceLog((int)IntentJs.NumOf(spec["max"])!.Value);
        var o = new L();
        foreach (var op0 in (L)spec["ops"]!)
        {
            var op = (D)op0!;
            if (Jt(op.GetValueOrDefault("add"))) { log.Add((string)op["session"]!, (D)op["o"]!); o.Add("added"); }
            else o.Add(log.Seen((string)op["session"]!));
        }
        return o;
    }

    static bool Jt(object? v) => v is not (null or false or "") && !(v is Num n && IntentJs.NumOf(n) is 0.0);

    static D Req(D rq)
    {
        var o = new D { ["method"] = "POST", ["path"] = "/" };
        foreach (var (k, v) in rq) o[k] = v;
        return o;
    }

    static FullPolicy Policy(object? kind) => (string)kind! == "body" ? new FullPolicy() : new FullPolicy { ParamsFn = _ => new D() };

    static object? Presented(object? rq, object? kind) =>
        PcaGateway.PresentedProvenance(Req((D)rq!), Policy(kind)) is var v && ReferenceEquals(v, PcaGateway.Absent) ? new D { ["undef"] = true } : v;

    [Fact] public void CanonicalQuery() => Base.Check(M, "canonicalQuery", a => PcaGateway.CanonicalQuery(a[0] as string ?? throw new ArgumentException("query is not a string")));

    [Fact]
    public void RequestBinding() => Base.Check(M, "requestBinding", a =>
    {
        var r = new D((D)a[0]!) { ["headers"] = new D() };
        return PcaGateway.RequestBinding(r, a.Count > 1 ? a[1] as D : null);
    });

    [Fact] public void BindParams() => Base.Check(M, "bindParams", a => PcaGateway.BindParams((D)a[0]!, a.Count > 1 ? a[1] as D : null));

    [Fact] public void AmbiguousPathReason() => Base.Check(M, "ambiguousPathReason", a => PcaGateway.AmbiguousPathReason((string)a[0]!));

    [Fact] public void ReplayScenario() => Base.Check(M, "replayScenario", a => Replay((D)a[0]!));

    [Fact] public void ProvenanceLogScenario() => Base.Check(M, "provenanceLogScenario", a => ProvLog((D)a[0]!));

    [Fact] public void PresentedProvenance() => Base.Check(M, "presentedProvenance", a => Presented(a[0], a[1]));

    [Fact]
    public void PresentedArtifacts() => Base.Check(M, "presentedArtifacts", a => PcaGateway.PresentedArtifacts(Req((D)a[0]!), Policy(a[1])));

    [Fact] public void AuthorizeScenario() => Base.Check(M, "authorizeScenario", a => Authorize((D)a[0]!));

    [Fact] public void EnvoyScenario() => Base.Check(M, "envoyScenario", a => Adapter((D)a[0]!, PcaGateway.EnvoyExtAuthz));

    [Fact] public void GrpcScenario() => Base.Check(M, "grpcScenario", a => Adapter((D)a[0]!, PcaGateway.EnvoyGrpcExtAuthz));

    [Fact] public void LambdaScenario() => Base.Check(M, "lambdaScenario", a => LambdaLone((D)a[0]!, PcaGateway.LambdaAuthorizer));

    [Fact] public void LambdaSimpleScenario() => Base.Check(M, "lambdaSimpleScenario", a => LambdaLone((D)a[0]!, PcaGateway.LambdaSimpleAuthorizer));

    [Fact]
    public void AllFnsHandled() { Base.Covers(M, new[] { "canonicalQuery", "requestBinding", "bindParams", "ambiguousPathReason", "replayScenario", "provenanceLogScenario", "presentedProvenance", "presentedArtifacts", "authorizeScenario", "envoyScenario", "grpcScenario", "lambdaScenario", "lambdaSimpleScenario" }); Assert.Equal(444, Base.Total(M)); }
}

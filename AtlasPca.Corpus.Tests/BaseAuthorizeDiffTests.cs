using AtlasPca;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>base differential oracle of the authorize pipeline's 0.5 additions and its pure pieces (test-data/base-authorize.json.gz, TS
/// reference packages/pca/src/server/authorize.ts + require-pca.ts, agent-native.ts tool_schema, risk.ts, envelope.ts).</summary>
public class BaseAuthorizeDiffTests
{
    const string M = "authorize";

    [Fact] public void ValidateArgSchema() => Base.Check(M, "validateArgSchema", a => Pca.ValidateArgSchema(a[0]));

    [Fact]
    public void EvaluateToolSchema() => Base.Check(M, "evaluateToolSchema", a =>
    {
        var call = a[1] as D;
        var (ok, reason) = Pca.EvaluateToolSchema(a[0], call == null ? null : new ToolCall(call.GetValueOrDefault("tool") as string, call.GetValueOrDefault("args"),
            call.GetValueOrDefault("toolSignatureDigest") as string, call.GetValueOrDefault("toolSignature")));
        return ok ? new D { ["ok"] = true } : new D { ["ok"] = false, ["reason"] = reason };
    }, min: 10000,
        // typed port: a present-but-null toolSignature / toolSignatureDigest is the reference's "a null was presented" (refused);
        // a .NET caller's null means "none supplied", so such a call cannot be expressed here
        skip: c => Base.Args(c).Count > 1 && Base.Args(c)[1] is D cl && ((cl.ContainsKey("toolSignature") && cl["toolSignature"] == null)
            || (cl.ContainsKey("toolSignatureDigest") && cl["toolSignatureDigest"] is not string)) ? "typed port: a null / non-string tool signature cannot be presented" : null);

    [Fact] public void ValidateRiskPolicy() => Base.Check(M, "validateRiskPolicy", a => Pca.ValidateRiskPolicy(a[0]));
    [Fact] public void RequiresAttestation() => Base.Check(M, "requiresAttestation", a => Pca.RequiresAttestation(a[0]), min: 20);
    [Fact] public void ReadEnvelope() => Base.Check(M, "readEnvelope", a => Pca.ReadEnvelope(a[0]));

    // ---- authorize() scenarios: {grant, config, steps}; per step the projection the generator records ----
    static readonly string[] Key = { "wire", "version", "audience", "validity", "cap_chain", "grant_ref_bound", "plan_inclusion", "plan_root_authorized", "leaf_signature",
        "counter_format", "fresh_at", "attestation", "revocation", "grant_ref", "operation", "params_digest", "delegated_caveats", "policy", "replay", "provenance_flow",
        "undo_window", "escalation" };
    static readonly string[] Own = { "provenance_flow: ", "undo_window: ", "escalation: ", "fresh_at: " };

    static Operation OpOf(object? o) { var d = (D)o!; return new Operation((string)d["verb"]!, (string)d["resource"]!, d["params"]); }

    /// <summary>The coordinator's JSON admission as the typed callback result: a value the record cannot hold (a non-string id, a
    /// non-integer window_end, a compensation that is not an object with string members) is no admission.</summary>
    static UndoAdmission? Admission(object? o)
    {
        if (o is not D a || a.GetValueOrDefault("id") is not string id || !Base.IsJsonInt(a.GetValueOrDefault("window_end"))) return null;
        if (a.GetValueOrDefault("compensation") is not D c || c.GetValueOrDefault("verb") is not string v || c.GetValueOrDefault("resource") is not string r) return null;
        return new UndoAdmission(id, Base.Long(a["window_end"]), new UndoCompensationRef(v, r));
    }

    static L Scenario(D sc, bool verify = false)
    {
        var grant = (D)sc["grant"]!;
        var cfg = (D)sc["config"]!;
        var revoked = false;
        var input = new AuthorizeInput
        {
            Audience = (string)cfg["audience"]!,
            ResolveGrant = id => id == (string)grant["id"]! ? grant : null,
            StateStore = new MemoryStateStore(),
            IsRevoked = (_, _) => revoked,
            Plan = "single-step",
            Now = Base.Long(cfg["now"]),
            ProvenanceFlow = new ArgProvenanceOptions
            {
                Mediators = ((L)cfg["mediators"]!).Cast<D>().Select(p => new ProvMediatorPin((string)p["mediator"]!, (string)p["kid"]!, (string)p["pk"]!, p.GetValueOrDefault("pq_pk") as string)).ToList(),
                Actions = cfg.GetValueOrDefault("actions") is D acts ? (Func<Operation, D?>)(op => acts.GetValueOrDefault(op.Verb) as D) : null,
                Observed = cfg.GetValueOrDefault("observed") is L obs
                    ? (Func<D, Operation, string?, IReadOnlyList<ProvObservation>?>)((_, _, _) => obs.Cast<D>().Select(o => new ProvObservation((string)o["origin"]!, (string)o["source"]!)).ToList())
                    : null,
            },
        };
        if (cfg.GetValueOrDefault("freshAt") is D fa)
            input.FreshAt = new FreshAtPolicy((string)fa["signer"]!, (string)fa["scope"]!, FreshAtState.FromJson(fa["local"])!, require: fa.GetValueOrDefault("require") is true);
        if (cfg.GetValueOrDefault("undo") is D undo)
            input.Undo = (_, _, op) => undo.TryGetValue(op.Verb, out var adm) ? Admission(adm) : null;
        if (cfg.GetValueOrDefault("escalation") is D esc)
        {
            input.EscalationPrincipals = ((L)esc["principals"]!).Select(x => new PinnedSigner((string)x!)).ToList();
            if (esc.GetValueOrDefault("render_digest") is string rd) input.EscalationRender = _ => rd;
            input.InsecureUnboundApproval = esc.GetValueOrDefault("insecureUnboundApproval") is true;
        }
        var out_ = new L();
        foreach (D s in (L)sc["steps"]!)
        {
            revoked = s.GetValueOrDefault("revoked") is true;
            input.Operation = OpOf(s["operation"]);
            input.Provenance = s.GetValueOrDefault("provenance");
            input.EscalationAnswer = s.GetValueOrDefault("escalationAnswer");
            if (verify)
            {
                // the reference verdict shape over the same pipeline: allow, checks, failed checks and the reasons the pipeline stages own
                var v = Pca.VerifyPcactn(s["pcactn"], grant, input);
                var vc = ((D)v["checks"]!).ToDictionary(e => e.Key, e => (string)e.Value!);
                Assert.True(v["r"] is double && v["requiredThreshold"] is D { Count: 3 });
                out_.Add(new D
                {
                    ["allow"] = v["allow"],
                    ["checks"] = Key.Where(vc.ContainsKey).ToDictionary(k => k, k => (object?)vc[k]),
                    ["failed"] = Key.Where(k => vc.GetValueOrDefault(k) == "fail").Cast<object?>().ToList(),
                    ["reasons"] = ((L)v["reasons"]!).Cast<string>().Where(x => Own.Any(o => x.StartsWith(o, StringComparison.Ordinal))).Cast<object?>().ToList(),
                });
                continue;
            }
            var r = Pca.Authorize(s["pcactn"], input);
            // .NET names the capability chain check "chain" (the reference "cap_chain")
            var ck = r.Checks.ToDictionary(e => e.Key == "chain" ? "cap_chain" : e.Key, e => e.Value);
            out_.Add(new D
            {
                ["allow"] = r.Allow, ["decision"] = r.Decision, ["status"] = (long)r.Status,
                ["checks"] = Key.Where(ck.ContainsKey).ToDictionary(k => k, k => (object?)ck[k]),
                ["failed"] = Key.Where(k => ck.GetValueOrDefault(k) == "fail").Cast<object?>().ToList(),
                ["reasons"] = r.Reasons.Where(x => Own.Any(o => x.StartsWith(o, StringComparison.Ordinal))).Cast<object?>().ToList(),
                ["escalation"] = r.Escalation == null ? null : r.Allow ? r.Escalation : new D { ["request"] = true },
                ["undo"] = r.Undo == null ? null : new D
                {
                    ["id"] = r.Undo.Id, ["window_end"] = r.Undo.WindowEnd,
                    ["compensation"] = new D { ["verb"] = r.Undo.Compensation.Verb, ["resource"] = r.Undo.Compensation.Resource },
                },
            });
        }
        return out_;
    }

    // The reference reports attestation "not-enforced" on every verdict; .NET reports that check only when it applies (it fails closed),
    // so a want check that is "not-enforced" and absent from .NET is dropped before the exact comparison. Everything else compares exactly.
    // the escalation-render refusal names the option a caller sets; .NET spells it with its own property names
    const string DotnetOpts = "(set EscalationRender, or InsecureUnboundApproval)", RefOpts = "(set escalation.render, or insecureUnboundApproval)";
    static object? DropUnreported(object? want, object? have)
    {
        if (want is not L wl || have is not L hl || wl.Count != hl.Count) return want;
        return wl.Select((w, i) =>
        {
            if (w is not D wd || wd.GetValueOrDefault("checks") is not D wc || hl[i] is not D hd || hd.GetValueOrDefault("checks") is not D hc) return w;
            var kept = wc.Where(e => !(e.Value as string == "not-enforced" && !hc.ContainsKey(e.Key))).ToDictionary(e => e.Key, e => e.Value);
            return (object?)new D(wd) { ["checks"] = kept };
        }).ToList();
    }

    [Fact]
    public void Authorize() => Base.Check(M, "authorize", a => Scenario((D)a[0]!), min: 800,
        eq: (c, h) => { var have = Base.Json(h); return Base.Show(DropUnreported(c["out"], have)) == Base.Show(have).Replace(DotnetOpts, RefOpts); });

    static readonly string[] Shape = { "allow", "checks", "failed", "reasons" };

    /// <summary>The verifyPCActn verdict (allow, checks, failed checks, own reasons) of the same scenarios as the authorize replay above.</summary>
    [Fact]
    public void VerifyPcactnVerdict() => Base.Check(M, "authorize", a => Scenario((D)a[0]!, verify: true), min: 800,
        eq: (c, h) =>
        {
            var want = DropUnreported(c["out"], Base.Json(h)) as L;
            if (want == null) return false;
            var proj = want.Select(w => (object?)Shape.Where(((D)w!).ContainsKey).ToDictionary(k => k, k => ((D)w!)[k])).ToList();
            return Base.Show(proj) == Base.Show(Base.Json(h)).Replace(DotnetOpts, RefOpts);
        });

    [Fact]
    public void EveryFn() { Base.Covers(M, new[]
    {
        "validateArgSchema", "evaluateToolSchema", "validateRiskPolicy", "readEnvelope", "authorize", "requiresAttestation",
    }); Assert.Equal(13320, Base.Total(M)); }
}

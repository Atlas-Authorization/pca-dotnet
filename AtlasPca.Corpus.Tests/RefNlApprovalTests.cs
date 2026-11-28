using System.Security.Cryptography;
using System.Text;
using AtlasPca;
using AtlasPca.IntentPkg;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Replay of the approval half of natural-language policy authoring (test-data/ref-nl-approval.json.gz, 206 cases): the NL catalog digest, the draft binding and digests, the grounded draft, the reviewer's approval
/// (v2 and the legacy v1 form), loading an approved policy with every rejection code and the agent minted from one. The model is a fixed completion text ("THROWS" is a completion that throws). The agent's grant is minted
/// with a random goal salt, so only the deterministic envelope members are compared. A reference throw requires a refusal. Every fn has a handler and the totals are asserted.</summary>
public class RefNlApprovalTests
{
    const string M = "ref-nl-approval";

    static Catalog CatalogOf(object? extras)
    {
        if (extras == null) return Catalog.Default;
        var specs = new List<CatalogAction>(Catalog.Builtin);
        foreach (var eo in (L)extras)
        {
            var e = (D)eo!;
            string connector = (string)e["connector"]!, action = (string)e["action"]!;
            var aliases = e.GetValueOrDefault("aliases") is L al ? al.Select(x => (string)x!).ToList() : new List<string>();
            specs.Add(new CatalogAction(connector, action, connector + "." + action, (string)e["reversibility"]!, IntentOmega.Dbl(e["blastRadius"]), e.GetValueOrDefault("amountField") as string,
                (string)e["description"]!, aliases, Array.Empty<string>()));
        }
        return new Catalog(specs);
    }

    static Func<string, string> Model(string raw) => _ => raw == "THROWS" ? throw new InvalidOperationException("llm down") : raw;

    static double? Num(object? o) => o switch
    {
        null => null,
        D m when m.Count == 1 && m.TryGetValue("$num", out var t) && t is string s => s == "NaN" ? double.NaN : s == "Infinity" ? double.PositiveInfinity : double.NegativeInfinity,
        _ => IntentJs.NumOf(o) ?? double.NaN, // not a number: never finite in the reference
    };

    static object? Approve(L a, bool legacy)
    {
        var o = a.Count > 2 ? a[2] as D : null;
        var secret = Base.Bytes(a[1]);
        return legacy ? NlApproval.ApproveDraftLegacyV1((D)a[0]!, secret, Num(o?.GetValueOrDefault("now")), Num(o?.GetValueOrDefault("ttlMs")))
            : NlApproval.ApproveDraft((D)a[0]!, secret, Num(o?.GetValueOrDefault("now")), Num(o?.GetValueOrDefault("ttlMs")));
    }

    static object? Load(L a)
    {
        var o = (D)a[2]!;
        return NlApproval.LoadApprovedPolicy(a[0], a[1], o.GetValueOrDefault("reviewers"), CatalogOf(o.GetValueOrDefault("extras")), Num(o.GetValueOrDefault("now")));
    }

    static byte[] SeedOf(string label) => SHA256.HashData(Encoding.UTF8.GetBytes("atlas-pca-conformance/" + label));

    static object? AgentFrom(L a)
    {
        var x = (D)a[0]!;
        var o = (D)x["opts"]!;
        var principal = SuiteKey.Ed25519(EdKey.FromSeed(SeedOf((string)x["principalSeed"]!)));
        var holder = x.GetValueOrDefault("holderSeed") is string hs ? SuiteKey.Ed25519(EdKey.FromSeed(SeedOf(hs))) : null;
        var (agent, reviewer, legacy) = NlApproval.AgentFromApprovedNL((D)x["draft"]!, (D)x["approval"]!, o.GetValueOrDefault("reviewers"), principal, (string)x["goal"]!, CatalogOf(o.GetValueOrDefault("extras")),
            x.GetValueOrDefault("aud") as string, holder, Num(o.GetValueOrDefault("now")));
        var env = Pca.ReadEnvelope(agent.Grant) ?? throw new InvalidOperationException("no envelope");
        return new D
        {
            ["reviewer"] = reviewer, ["legacy_unbound_instruction"] = legacy,
            ["envelope"] = new D { ["predicates"] = env["predicates"], ["caveats"] = env["caveats"], ["risk_policy"] = env["risk_policy"], ["agent_binding"] = env["agent_binding"] },
        };
    }

    static Dictionary<string, Func<L, object?>> Fns => new()
    {
        ["constants"] = _ => NlApproval.Constants(),
        ["catalogDigest"] = a => NlApproval.CatalogDigest(CatalogOf(a[0])),
        ["draftBinding"] = a => NlApproval.DraftBinding((string)a[0]!, CatalogOf(a[1]), a[2] as string),
        ["draftDigestV2"] = a => NlApproval.DraftDigestV2(a[0], a[1], (string)a[2]!, (D)a[3]!),
        ["draftDigest"] = a => NlApproval.DraftDigest(a[0], a[1], (string)a[2]!),
        ["policyFromNL"] = a => NlApproval.PolicyFromNL((string)a[0]!, Model((string)a[1]!), CatalogOf(a[2])),
        ["draftPolicyFromNL"] = a => NlApproval.DraftPolicyFromNL((string)a[0]!, Model((string)a[1]!), CatalogOf(a[2]), a[3] as string),
        ["approveDraft"] = a => Approve(a, false),
        ["approveDraftLegacy"] = a => Approve(a, true),
        ["loadApproved"] = Load,
        ["agentFromApproved"] = AgentFrom,
    };

    static void Fn(string fn, int min) => Base.Check(M, fn, a => Base.Json(Fns[fn](a)), null, null, min);

    [Fact] public void Constants() => Fn("constants", 1);
    [Fact] public void CatalogDigest() => Fn("catalogDigest", 3);
    [Fact] public void DraftBinding() => Fn("draftBinding", 6);
    [Fact] public void DraftDigestV2() => Fn("draftDigestV2", 10);
    [Fact] public void DraftDigest() => Fn("draftDigest", 7);
    [Fact] public void PolicyFromNL() => Fn("policyFromNL", 40);
    [Fact] public void DraftPolicyFromNL() => Fn("draftPolicyFromNL", 42);
    [Fact] public void ApproveDraft() => Fn("approveDraft", 24);
    [Fact] public void ApproveDraftLegacy() => Fn("approveDraftLegacy", 5);
    [Fact] public void LoadApproved() => Fn("loadApproved", 58);
    [Fact] public void AgentFromApproved() => Fn("agentFromApproved", 10);

    [Fact]
    public void Covers()
    {
        Base.Covers(M, Fns.Keys);
        Assert.Equal(206, Base.Total(M));
        Assert.Equal(new Dictionary<string, int>
        {
            ["loadApproved"] = 58, ["draftPolicyFromNL"] = 42, ["policyFromNL"] = 40, ["approveDraft"] = 24, ["draftDigestV2"] = 10, ["agentFromApproved"] = 10, ["draftDigest"] = 7, ["draftBinding"] = 6,
            ["approveDraftLegacy"] = 5, ["catalogDigest"] = 3, ["constants"] = 1,
        }, Base.Cases(M).GroupBy(c => (string)c["fn"]!).ToDictionary(g => g.Key, g => g.Count()));
    }
}

using AtlasPca.ActionsKit;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Replays the second hosted-registry reference corpus (test-data/ref-actions-hosted-py.json.gz). <c>hostedView</c> is a probe: over the first
/// seven core definitions and one unknown verb it records every lookup, every provenance, the floor under four fixed grants and three call contexts, and
/// the undo plan of a sample call of each definition.</summary>
public class RefActionsHostedPyTests
{
    const string M = "ref-actions-hosted-py";
    static IEnumerable<D> Ds(object? l) => ((L)l!).Select(x => (D)x!);

    static D Grant(int maxEsc, int preauth, params string[] caveats) =>
        new() { ["caveats"] = caveats.Cast<object?>().ToList(), ["max_esc"] = IntentJs.OfLong(maxEsc), ["preauth_esc"] = IntentJs.OfLong(preauth) };

    static readonly D[] Grants =
    {
        Grant(3, 0), Grant(3, 3, "amount_cap", "window", "bogus"),
        Grant(1, 1, "amount_cap", "count_cap", "resource_scope", "recipient_scope", "approval_ref", "short_expiry", "rate_cap"), Grant(0, 0),
    };
    static readonly string[][] Ctxs = { Array.Empty<string>(), new[] { "fresh_revocation" }, new[] { "fresh_revocation", "idempotency", "approval_ref", "revocable", "dry_run_first" } };

    // one value per parameter that is not optional
    static D Sample(D def)
    {
        var o = new D();
        foreach (var (k, pv) in (D)def["params"]!)
        {
            var p = (D)pv!;
            if (p.GetValueOrDefault("required") is false) continue;
            var t = p.GetValueOrDefault("type") as string;
            o[k] = p.GetValueOrDefault("role") is string role && role.StartsWith("id.", StringComparison.Ordinal) ? "abc12345"
                : t == "integer" ? IntentJs.OfLong(7)
                : t == "boolean" ? true
                : p.GetValueOrDefault("values") is L vals ? vals[0]
                : t == "array" ? new L { "x" }
                : t == "set" ? new L()
                : t == "datetime" ? "2030-01-01T00:00:00Z"
                : "val";
        }
        return o;
    }

    static D Probe(L a)
    {
        var defs = ActionBuiltin.CorePackDefs().Take(7).Select(x => (D)x!).ToList();
        var verbs = defs.Select(d => (string)d["verb"]!).Append("unknown.verb").ToList();
        var v = ActionHosted.HostedViewOf(Ds(a[0]), a[1]);
        return new D
        {
            ["versions"] = v.Versions.Cast<object?>().ToList(),
            ["lookups"] = verbs.Select(x => (object?)v.Lookup(x)).ToList(),
            ["prov"] = verbs.Select(x => (object?)v.Provenance(new D { ["verb"] = x })).ToList(),
            ["floors"] = verbs.SelectMany(x => Grants.SelectMany(g => Ctxs.Select(c => (object?)v.Floor(x, g, c)))).ToList(),
            ["undo"] = defs.Select(d => (object?)v.UndoPlan(new D { ["verb"] = d["verb"], ["params"] = Sample(d) })).ToList(),
        };
    }

    [Fact] public void PublishGate() => Base.Check(M, "publishGate", a => ActionHosted.PublishGate((D)a[0]!), min: 50);
    [Fact] public void VersionDigest() => Base.Check(M, "hostedVersionDigest", a => ActionHosted.HostedVersionDigest((D)a[0]!), min: 3);
    [Fact] public void RulesDocError() => Base.Check(M, "rulesDocError", a => ActionHosted.RulesDocError(a[0], (string)a[1]!, Ds(a[2])), min: 2);
    [Fact] public void RegistryOfTraits() => Base.Check(M, "registryOfTraits", a => new D { ["digest"] = Actions.TraitsDigest(ActionHosted.RegistryOfTraits((L)a[0]!)) }, min: 3);
    [Fact] public void HostedView() => Base.Check(M, "hostedView", Probe, min: 10);
    [Fact] public void GrantFacts() => Base.Check(M, "grantFactsOf", a => ActionHosted.GrantFactsOf(a[0]), min: 9);
    [Fact] public void CallContext() => Base.Check(M, "hostedCallContext", a => ActionHosted.HostedCallContext(a[0] as D, a[1] as D), min: 7);
    [Fact] public void RateKeys() => Base.Check(M, "rateKeysOf", a => ActionHosted.RateKeysOf((D)a[0]!, (D)a[1]!), min: 7);

    [Fact]
    public void Covers()
    {
        Base.Covers(M, new[] { "publishGate", "hostedVersionDigest", "rulesDocError", "registryOfTraits", "hostedView", "grantFactsOf", "hostedCallContext", "rateKeysOf" });
        Assert.Equal(91, Base.Cases(M).Count);
    }
}

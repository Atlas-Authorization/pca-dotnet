using System.Text.RegularExpressions;
using AtlasPca;
using Xunit;
using static AtlasPca.Corpus.Tests.Conf;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

// Rules 20 (units) and 21 (tighten-only) END TO END through Authorize: the shared vectors packages/pca/conformance/model-rules-vectors.json
// (signed grants, decided by the TypeScript reference). A grant's tighten[] rules, unit tags and polarity are signed policy: ignoring them
// would let a model move a decision up, so every case must decide the same as the reference, reason text included.
public class ModelRulesVectorTests
{
    static readonly Regex ModelReason = new(@"^(units|tighten|schema|intent_session): ", RegexOptions.CultureInvariant);

    static AuthorizeResult Run(D doc, D c, Action<AuthorizeInput>? extra = null)
    {
        var grant = D(c["grant"]);
        var op = D(c["operation"]);
        var input = new AuthorizeInput
        {
            Audience = (string)doc["audience"]!, Now = N(doc["now"]), Plan = "single-step", StateStore = new MemoryStateStore(),
            Operation = new Operation((string)op["verb"]!, (string)op["resource"]!, op["params"]),
            ResolveGrant = _ => grant, IsRevoked = (_, _) => false,
        };
        if (c.TryGetValue("intent_v2", out var v2)) input.IntentV2 = IntentV2Context.FromJson(v2);
        if (c.GetValueOrDefault("context") is D cx) input.Context = _ => new D { ["env"] = cx.GetValueOrDefault("env") };
        extra?.Invoke(input);
        return Pca.Authorize(c["pcactn"], input);
    }

    [Fact]
    public void EveryCaseDecidesLikeTheReference()
    {
        var doc = Load("model-rules-vectors.json");
        Assert.Equal("pca-model-rules-vectors/1", doc["format"]);
        var cases = L(doc["cases"]);
        Assert.True(cases.Count >= 32, $"only {cases.Count} cases");
        var decisions = new HashSet<string>();
        foreach (var x in cases)
        {
            var c = D(x);
            var name = (string)c["name"]!;
            var e = D(c["expect"]);
            decisions.Add((string)e["decision"]!);
            var r = Run(doc, c);
            Assert.True(r.Allow == (bool)e["allow"]! && r.Decision == (string)e["decision"]! && r.Status == N(e["status"]), $"{name}: got allow={r.Allow} decision={r.Decision} status={r.Status}, want {e["allow"]} {e["decision"]} {e["status"]}: {string.Join(" | ", r.Reasons)}");
            var failed = r.Checks.Where(kv => kv.Value == "fail").Select(kv => kv.Key).OrderBy(k => k, StringComparer.Ordinal).ToList();
            var wantFailed = L(e["failed"]).Cast<string>().ToList();
            Assert.True(failed.SequenceEqual(wantFailed), $"{name}: failed checks [{string.Join(",", failed)}], want [{string.Join(",", wantFailed)}] ({string.Join(" | ", r.Reasons)})");
            var got = r.Reasons.Where(x2 => ModelReason.IsMatch(x2)).ToList();
            var want = L(e["reasons"]).Cast<string>().ToList();
            Assert.True(got.SequenceEqual(want), $"{name}: model reasons [{string.Join(" | ", got)}], want [{string.Join(" | ", want)}]");
            foreach (var k in new[] { "units", "tighten" })
            {
                var w = e.GetValueOrDefault(k) as string;
                Assert.True(r.Checks.GetValueOrDefault(k) == w, $"{name}: check {k} = '{r.Checks.GetValueOrDefault(k)}', want '{w}'");
            }
            var wantDeg = (e.GetValueOrDefault("degraded") as D ?? new D()).ToDictionary(kv => kv.Key, kv => (string)kv.Value!);
            var gotDeg = r.Degraded?.ToDictionary(kv => kv.Key, kv => kv.Value) ?? new Dictionary<string, string>();
            Assert.True(gotDeg.Count == wantDeg.Count && gotDeg.All(kv => wantDeg.TryGetValue(kv.Key, out var wv) && wv == kv.Value), $"{name}: degraded {string.Join(",", gotDeg.Keys)}, want {string.Join(",", wantDeg.Keys)}");
        }
        foreach (var dec in new[] { "allow", "escalate", "deny" }) Assert.True(decisions.Contains(dec), $"no {dec} case in the vectors");
    }

    [Fact]
    public void ASignedTightenRuleNeverLetsAModelRaiseADecision()
    {
        // every case whose reference decision is not allow must stay refused when the verifier ALSO has an answerless escalation path
        var doc = Load("model-rules-vectors.json");
        foreach (var x in L(doc["cases"]))
        {
            var c = D(x);
            var e = D(c["expect"]);
            if ((bool)e["allow"]!) continue;
            var r = Run(doc, c);
            Assert.False(r.Allow, (string)c["name"]!);
            Assert.NotNull(r.Reasons.FirstOrDefault(s => ModelReason.IsMatch(s)));
        }
    }
}

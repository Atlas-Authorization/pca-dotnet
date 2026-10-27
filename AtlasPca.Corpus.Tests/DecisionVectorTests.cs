using AtlasPca;
using Xunit;
using static AtlasPca.Corpus.Tests.Conf;

namespace AtlasPca.Corpus.Tests;

// decision-vectors.json: rules 20 (units) and 21 (tighten), the ternary decision lattice and escalation answers (shared with the
// TypeScript reference, Go, Rust and Python). Exact outcomes; a reason is compared by the vector's `reason_contains` where it gives one.
public class DecisionVectorTests
{
    /// <summary><c>input_text</c> is raw JSON text each runner parses itself (spellings such as 2.0 / 2e0 are part of the input); else <c>input</c>.</summary>
    static object? InputOf(Dictionary<string, object?> v) => v.GetValueOrDefault("input_text") is string raw ? Pca.ParseJson(raw) : v["input"];

    static List<object?> Table(string name) => L(D(Load("decision-vectors.json")["primitives"])[name]);

    [Fact]
    public void TableSizes()
    {
        Assert.True(Table("intent_units").Count >= 85);
        Assert.True(Table("intent_tighten").Count >= 73);
        Assert.True(Table("decision_of").Count >= 25);
        Assert.Equal(31, Table("decision_lattice").Count);
        Assert.True(Table("escalation_fold").Count >= 18);
        Assert.True(Table("escalation_answer").Count >= 85);
    }

    [Fact]
    public void UnitsVectors()
    {
        foreach (var x in Table("intent_units"))
        {
            var v = D(x);
            var (ok, why) = PcaDecision.DecideUnits(D(InputOf(v)!));
            var e = D(v["expect"]);
            Assert.True((bool)e["ok"]! == ok, $"{v["name"]}: ok={ok} ({why})");
            Assert.True(ok == (why == null), $"{v["name"]}: reason iff refused");
            if (e.TryGetValue("reason", out var wantReason)) Assert.True((string)wantReason! == why, $"{v["name"]}: reason '{why}', want '{wantReason}'");
        }
    }

    [Fact]
    public void TightenVectors()
    {
        foreach (var x in Table("intent_tighten"))
        {
            var v = D(x);
            var r = PcaDecision.DecideTighten(D(InputOf(v)!));
            var e = D(v["expect"]);
            Assert.True((string)e["outcome"]! == r.Outcome && (bool)e["legacy"]! == r.Legacy, $"{v["name"]}: got {r.Outcome} legacy={r.Legacy} ({r.Reason})");
            Assert.Equal(L(e["offending"]).Cast<string>().ToArray(), r.Offending.ToArray());
            // the reason is part of the contract, byte for byte (an ok outcome has none)
            Assert.True(((string?)e.GetValueOrDefault("reason") ?? "") == (r.Reason ?? ""), $"{v["name"]}: reason '{r.Reason}', want '{e.GetValueOrDefault("reason")}'");
        }
    }

    [Fact]
    public void DecisionOfVectors()
    {
        foreach (var x in Table("decision_of"))
        {
            var v = D(x);
            Assert.True((string)D(v["expect"])["decision"]! == PcaDecision.DecisionOf(v["input"]), (string)v["name"]!);
        }
    }

    [Fact]
    public void LatticeVectors()
    {
        foreach (var x in Table("decision_lattice"))
        {
            var v = D(x);
            var n = (string)v["name"]!;
            var i = D(InputOf(v)!);
            string got = n[..3] switch
            {
                "mee" => PcaDecision.Meet(i["a"] as string, i["b"] as string),
                "pep" => PcaDecision.PepDecision(i["decision"] as string, (bool)i["answered"]!),
                _ => PcaDecision.Tighten(i["decision"] as string, i["signal"]),
            };
            Assert.True((string)D(v["expect"])["decision"]! == got, $"{n}: got {got}");
        }
    }

    [Fact]
    public void EscalationAnswerVectors()
    {
        var ranSuites = new HashSet<string>();
        foreach (var x in Table("escalation_answer"))
        {
            var v = D(x);
            var n = (string)v["name"]!;
            var i = D(InputOf(v)!);
            var pins = L(i["principals"]).Select(p => p is string s ? new PinnedSigner(s) : new PinnedSigner((string)D(p)["pk"]!, D(p).GetValueOrDefault("pq_pk") as string)).ToList();
            var b = D(i["bind"]);
            var nowD = IntentJs.NumOf(i["now"])!.Value;
            long now = nowD == Math.Floor(nowD) ? (long)nowD : long.MaxValue; // a non-integer clock is refused by the safe-integer check
            var r = Escalation.Verify(i["answer"], pins, new EscalationBinding((string)b["policy_digest"]!, (string)b["action_digest"]!, (string)b["history_head"]!), now);
            var e = D(v["expect"]);
            if (v.GetValueOrDefault("requires_suite") is string need && !Supported.Contains(need))
            {
                // a suite this build cannot run is refused, never accepted and never mistaken for a bad signature
                Assert.True(!r.Ok && r.Reason!.Contains(IntentJs.UnsupportedSuite, StringComparison.Ordinal), $"{n}: suite {need} is not built: want {IntentJs.UnsupportedSuite}, got {r}");
                continue;
            }
            if (v.GetValueOrDefault("requires_suite") is string ran && (bool)e["ok"]!) ranSuites.Add(ran);
            Assert.True((bool)e["ok"]! == r.Ok, $"{n}: ok={r.Ok} ({r.Reason})");
            if (r.Ok) Assert.True((string)e["principal"]! == r.Principal && (string)e["decision"]! == r.Decision, $"{n}: got {r.Principal} {r.Decision}");
            else Assert.True(r.Reason!.Contains((string)e["reason_contains"]!, StringComparison.Ordinal), $"{n}: reason '{r.Reason}' lacks '{e["reason_contains"]}'");
        }
        // every suite this build verifies ran its positive vector (a runner that skipped them all would pass vacuously)
        foreach (var alg in Pq.SupportedSuites())
            if (alg != "ed25519" && !alg.Contains("less", StringComparison.Ordinal)) Assert.True(ranSuites.Contains(alg), $"suite {alg} is built but no escalation_answer vector exercised it");
    }

    static readonly HashSet<string> Supported = new(Pq.SupportedSuites());

    [Fact]
    public void EscalationFoldVectors()
    {
        foreach (var x in Table("escalation_fold"))
        {
            var v = D(x);
            var i = D(v["input"]);
            var v2 = L(i["v2"]).Select(m => new PcaDecision.V2CheckResult((string)D(m)["name"]!, D(m)["ok"] is true, D(m).GetValueOrDefault("reason") as string)).ToList();
            var got = PcaDecision.FoldV2Reasons(L(i["core_reasons"]).Cast<string>(), v2);
            var e = D(v["expect"]);
            Assert.True(L(e["reasons"]).Cast<string>().SequenceEqual(got), $"{v["name"]}: reasons {string.Join(" | ", got)}");
            var checks = D(i["checks"]);
            var failing = checks.Where(kv => kv.Value is "fail").Select(kv => kv.Key).ToList();
            var decision = failing.Count == 0 ? "allow" : PcaDecision.Of(failing, got);
            Assert.True((string)e["decision"]! == decision, $"{v["name"]}: decision {decision}");
        }
    }

    // ---- exact reason strings (the TypeScript wording) on the edges the vectors only check loosely

    static Dictionary<string, object?> J(string json) => D(Pca.ParseJson(json));

    [Fact]
    public void NullTightenIsRejectedAsTheReferenceDoes()
    {
        var r = PcaDecision.DecideTighten(J("{\"tighten\":null}"));
        Assert.Equal("deny", r.Outcome);
        Assert.Equal("malformed tighten list: tighten must be an array", r.Reason);
        Assert.Equal("allow", PcaDecision.Tighten("allow", "ok"));
        Assert.Equal("ok", PcaDecision.DecideTighten(J("{}")).Outcome);
        Assert.Equal("deny", PcaDecision.DecideTighten(J("{\"polarity\":null}")).Outcome);
        Assert.Equal("model_polarity must be 'legacy' when present", PcaDecision.DecideTighten(J("{\"polarity\":\"strict\"}")).Reason);
    }

    [Fact]
    public void ModelPolarityLegacyIsReportedDegraded()
    {
        var input = J("{\"polarity\":\"legacy\",\"predicates\":[[{\"verb\":\"*\",\"where\":[{\"field\":\"env.class.tone\",\"op\":\"eq\",\"value\":\"x\"}]}]]}");
        var r = PcaDecision.DecideTighten(input);
        Assert.Equal(("ok", true), (r.Outcome, r.Legacy));
        Assert.Equal(new[] { "env.class.tone" }, r.Offending.ToArray());
        Assert.Equal("a grant's where reads model-derived path(s) env.class.tone: a model may only tighten (move them into tighten[]) (rule 21)",
            PcaDecision.DecideTighten(J("{\"predicates\":[[{\"verb\":\"*\",\"where\":[{\"field\":\"env.class.tone\",\"op\":\"eq\",\"value\":\"x\"}]}]]}")).Reason);
    }

    [Fact]
    public void TightenRulesTakeTheMeetOfTheirSignals()
    {
        var t = "{\"tighten\":[{\"id\":\"a\",\"when\":{\"field\":\"env.k\",\"op\":\"eq\",\"value\":1},\"signal\":\"escalate\",\"reason\":\"why\"},"
              + "{\"id\":\"b\",\"when\":{\"field\":\"env.k\",\"op\":\"eq\",\"value\":1},\"signal\":\"deny\"},"
              + "{\"id\":\"c\",\"when\":{\"field\":\"env.missing\",\"op\":\"eq\",\"value\":1},\"signal\":\"deny\"}],\"context\":{\"env\":{\"k\":1}}}";
        var r = PcaDecision.DecideTighten(J(t));
        Assert.Equal(("deny", "denied by tighten rule 'b'"), (r.Outcome, r.Reason));
        var u = PcaDecision.DecideTighten(J(t.Replace("\"signal\":\"deny\"},{\"id\":\"c\"", "\"signal\":\"escalate\"},{\"id\":\"c\"").Replace("\"id\":\"c\",\"when\":{\"field\":\"env.missing\",\"op\":\"eq\",\"value\":1},\"signal\":\"deny\"", "\"id\":\"c\",\"when\":{\"field\":\"env.missing\",\"op\":\"eq\",\"value\":1},\"signal\":\"escalate\"")));
        Assert.Equal(("escalate", "escalate: asked by tighten rule 'a' (why)"), (u.Outcome, u.Reason));
        Assert.Equal("malformed tighten list: tighten[1].id 'a' is a duplicate",
            PcaDecision.DecideTighten(J("{\"tighten\":[{\"id\":\"a\",\"when\":{},\"signal\":\"deny\"},{\"id\":\"a\",\"when\":{},\"signal\":\"deny\"}]}")).Reason);
    }

    [Fact]
    public void UnitsRefusalReasons()
    {
        var input = J("{\"units\":{\"action.params.amount\":{\"kind\":\"money\",\"currency\":\"EUR\",\"exponent\":2}},\"verb\":\"pay\",\"schema_units\":{\"usd_cents\":{\"kind\":\"money\",\"currency\":\"USD\",\"exponent\":2}},"
            + "\"verb_params\":{\"action.params.amount\":{\"unit\":\"usd_cents\"}}}");
        var (ok, why) = PcaDecision.DecideUnits(input);
        Assert.False(ok);
        Assert.Equal("'action.params.amount' is declared as money/USD/e2 by the action schema but the policy term is tagged money/EUR/e2 (unit confusion)", why);
        Assert.Equal((false, "the verb is missing"), PcaDecision.DecideUnits(J("{\"units\":{}}")));
        Assert.Equal((false, "units must be an object"), PcaDecision.DecideUnits(J("{}")));
    }

    [Fact]
    public void MeetNeverRaisesAndUnknownIsDeny()
    {
        foreach (var a in new[] { "deny", "escalate", "allow" })
            foreach (var b in new[] { "deny", "escalate", "allow" })
                Assert.Equal(new[] { "deny", "escalate", "allow" }[Math.Min(Array.IndexOf(new[] { "deny", "escalate", "allow" }, a), Array.IndexOf(new[] { "deny", "escalate", "allow" }, b))], PcaDecision.Meet(a, b));
        Assert.Equal("deny", PcaDecision.Meet("allow", "bogus"));
        Assert.Equal("deny", PcaDecision.PepDecision("deny", true));
        Assert.Equal("allow", PcaDecision.PepDecision("escalate", true));
        Assert.Equal("escalate", PcaDecision.PepDecision("escalate", false));
    }
}

using AtlasPca;
using Xunit;
using JD = System.Collections.Generic.Dictionary<string, object?>;
using JL = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

// Exact outcomes of the agent facade, pinned to the reference facade.ts: catalog resolution, the limit grammar and its edges, the
// compiled predicates, caveats and risk policy, the budget model, the grant envelope, riskFor, dryRun, act and sub-agents.
public class FacadeKillTests
{
    static string J(object? v) => Pca.Canonicalize(v);

    static string Refusal(Action f) => Assert.Throws<ArgumentException>(f).Message;

    static SuiteKey Key(byte b) => SuiteKey.Ed25519(EdKey.FromSeed(Enumerable.Repeat(b, 32).ToArray()));

    static SuiteKey PqOnly() => SuiteKey.Create("ml-dsa-65", null, PqKey.FromSeed(Pq.Prim.MlDsa65, new byte[32]));

    static CatalogAction Def(string connector, string action, string cls, double blast, string? amount = null, string[]? aliases = null, string? resource = null) =>
        new(connector, action, connector + "." + action, cls, blast, amount, "test action", aliases ?? Array.Empty<string>(), Array.Empty<string>(), resource);

    // a reversible money verb with its own resource, an irreversible money verb, a rate-limited verb, one of an unknown class and one of the class ""
    static Catalog Shop() => new(new[]
    {
        Def("shop", "tip", "reversible", 0.3, "amount", new[] { "gratuity" }, "tips/*"),
        Def("shop", "wire", "irreversible", 0.9, "amount"),
        Def("shop", "restock", "rate_limited", 0.4),
        Def("shop", "odd", "weird", 0.1),
        Def("shop", "blank", "", 0.1),
    });

    static Dictionary<string, string> Lim(params (string K, string V)[] kv) => kv.ToDictionary(x => x.K, x => x.V);

    static CompiledPolicy C(JD perms, Dictionary<string, string>? limits = null, Catalog? catalog = null, string? model = null, JD? rp = null) =>
        Facade.CompilePolicy(new PolicyOptions { Permissions = perms, Limits = limits, Catalog = catalog, BudgetModel = model, RiskPolicy = rp, Now = 1000 });

    static JD ShopPerms(params string[] actions) => new() { ["shop"] = new JL(actions) };

    const string DefaultRp = "{\"bMax\":1,\"kappa\":1,\"lambda\":0.0005,\"rho\":0.5,\"theta1\":0.25,\"theta2\":0.6,"
        + "\"weights\":{\"alpha\":0.25,\"beta\":0.2,\"delta\":0.2,\"epsilon\":0.1,\"gamma\":0.2,\"zeta\":0.05}}";
    const string DollarWeights = "\"weights\":{\"alpha\":0,\"beta\":0,\"delta\":0,\"epsilon\":0,\"gamma\":1,\"zeta\":0}";
    static string DollarRp(string bMax, string kappa, string theta1, string theta2) =>
        $"{{\"bMax\":{bMax},\"kappa\":{kappa},\"lambda\":0,\"rho\":0.5,\"theta1\":{theta1},\"theta2\":{theta2},{DollarWeights}}}";

    static string Where(string amount) =>
        $"\"where\":[{{\"field\":\"action.params.amount\",\"op\":\"lte\",\"value\":{amount}}},{{\"field\":\"action.params.amount\",\"op\":\"gte\",\"value\":0}}]";

    // ---- catalog ----

    [Fact]
    public void CatalogResolveAndSpecFor()
    {
        // the full verb is looked up first: gmail.draft has no alias "draft", so only the verb lookup finds it
        Assert.Equal("gmail.draft", Catalog.Default.Resolve("gmail", "draft")!.Verb);
        // the alias lookup splits at the FIRST dot: crm + export.all
        var crm = new Catalog(new[] { Def("crm", "export", "reversible", 0.1, aliases: new[] { "export.all" }) });
        Assert.Equal("crm.export", crm.SpecFor("crm.export.all").Verb);
        // a leading dot is no connector: no alias lookup with the empty connector
        var empty = new Catalog(new[] { new CatalogAction("", "real", ".real", "reversible", 0.1, null, "d", new[] { "x" }, Array.Empty<string>()) });
        var dot = empty.SpecFor(".x");
        Assert.Equal((".x", "", "x", "irreversible"), (dot.Verb, dot.Connector, dot.Action, dot.Reversibility));
        // an uncatalogued verb without a dot names itself as the action
        var bare = Catalog.Default.SpecFor("zzz");
        Assert.Equal(("zzz", "zzz", "zzz", 0.8, "(uncatalogued) zzz"), (bare.Verb, bare.Connector, bare.Action, bare.BlastRadius, bare.Description));
        Assert.Equal("x.", Catalog.Default.SpecFor("x.").Action);
    }

    [Fact]
    public void Defaults()
    {
        Assert.Equal("risk", new CompiledPolicy().BudgetModel);
        Assert.Equal("", new AgentOptions().Goal);
    }

    // ---- limit grammar ----

    [Theory]
    [InlineData("s", 1000L), InlineData("sec", 1000L), InlineData("second", 1000L), InlineData("seconds", 1000L)]
    [InlineData("m", 60_000L), InlineData("min", 60_000L), InlineData("minute", 60_000L), InlineData("minutes", 60_000L)]
    [InlineData("h", 3_600_000L), InlineData("hr", 3_600_000L), InlineData("hour", 3_600_000L), InlineData("hours", 3_600_000L)]
    [InlineData("d", 86_400_000L), InlineData("day", 86_400_000L), InlineData("days", 86_400_000L)]
    [InlineData("w", 604_800_000L), InlineData("week", 604_800_000L), InlineData("weeks", 604_800_000L)]
    [InlineData("mo", 2_592_000_000L), InlineData("month", 2_592_000_000L), InlineData("months", 2_592_000_000L)]
    public void EveryPeriodName(string name, long ms)
    {
        Assert.Equal(new ParsedLimit(3, "count", ms), Facade.ParseLimit("3/" + name));
        Assert.Equal(new ParsedLimit(3, "usd", ms), Facade.ParseLimit("$3 / " + name.ToUpperInvariant()));
    }

    [Fact]
    public void LimitEdges()
    {
        Assert.Equal(new ParsedLimit(500, "usd", 86_400_000L), Facade.ParseLimit("$500/day"));
        Assert.Equal(new ParsedLimit(2.5, "count", null), Facade.ParseLimit("2.5"));
        Assert.Equal("parseLimit: empty limit", Refusal(() => Facade.ParseLimit(null!)));
        Assert.Equal("parseLimit: empty limit", Refusal(() => Facade.ParseLimit("  ")));
        // the length cap counts the untrimmed string: 64 characters pass, 65 do not
        Assert.Equal(new ParsedLimit(1234, "count", null), Facade.ParseLimit(new string(' ', 60) + "1234"));
        Assert.Equal("parseLimit: limit is longer than 64 characters", Refusal(() => Facade.ParseLimit(new string(' ', 61) + "1234")));
        Assert.Equal("parseLimit: unknown period 'fortnight' in '5/fortnight'", Refusal(() => Facade.ParseLimit("5/fortnight")));
    }

    [Fact]
    public void JsNumberKeepsSafeIntegersIntegral()
    {
        Assert.Equal(5L, Assert.IsType<long>(Facade.JsNumber(5)));
        Assert.Equal(9007199254740991L, Assert.IsType<long>(Facade.JsNumber(9007199254740991.0)));
        Assert.Equal(-9007199254740991L, Assert.IsType<long>(Facade.JsNumber(-9007199254740991.0)));
        Assert.Equal("9007199254740992", Assert.IsType<Num>(Facade.JsNumber(9007199254740992.0)).Raw);
        Assert.Equal("2.5", Assert.IsType<Num>(Facade.JsNumber(2.5)).Raw);
    }

    // ---- compilePolicy ----

    [Fact]
    public void CompilesEveryLimitKind()
    {
        var p = C(ShopPerms("tip", "restock", "wire"), Lim(("tip", "$5/day"), ("shop.restock", "3/min"), ("wire", "$7")), Shop());
        Assert.Equal("[{\"resource\":\"tips/*\",\"verb\":\"shop.tip\"," + Where("5") + "},{\"resource\":\"*\",\"verb\":\"shop.restock\"},"
            + "{\"resource\":\"*\",\"verb\":\"shop.wire\"," + Where("7") + "}]", J(p.Predicates));
        // the shortest period is the lifetime; one rate caveat per count limit with a period, per_secs = round(period / 1000)
        Assert.Equal("[{\"class\":\"irreversible\",\"type\":\"reversibility_max\"},{\"at\":61000,\"type\":\"expires\"},{\"max\":3,\"per_secs\":60,\"type\":\"rate\"}]",
            J(p.Caveats));
        Assert.Equal("dollars", p.BudgetModel);
        // kappa = the largest cap, bMax = the sum; something irreversible is granted, so the default co-sign tiers stay
        Assert.Equal(DollarRp("12", "7", "0.25", "0.6"), J(p.RiskPolicy));
        Assert.Equal(new[] { "shop.tip", "shop.restock", "shop.wire" }, p.Limits.Select(x => x.Key));
        Assert.Equal("{\"shop.restock\":{\"amount\":3,\"periodMs\":60000,\"unit\":\"count\"},\"shop.tip\":{\"amount\":5,\"periodMs\":86400000,\"unit\":\"usd\"},"
            + "\"shop.wire\":{\"amount\":7,\"unit\":\"usd\"}}", J(p.ToJson()["limits"]));
        Assert.Equal(new[] { "shop.tip: $5/period is a per-call ceiling plus a one-period grant lifetime, not a renewing window cap" }, p.Approximations);
        Assert.Equal(new[] { "shop.tip", "shop.restock", "shop.wire" }, p.Actions.Select(a => a.Verb));
        Assert.Equal(3, p.InputLimits.Count);
        Assert.Equal("$7", p.InputLimits["wire"]);
    }

    [Fact]
    public void LimitsWithoutAPeriodAddNoLifetime()
    {
        var p = C(ShopPerms("tip"), Lim(("tip", "$5")), Shop());
        Assert.Equal("[{\"class\":\"reversible\",\"type\":\"reversibility_max\"}]", J(p.Caveats));
        Assert.Empty(p.Approximations);
        var c = C(ShopPerms("restock"), Lim(("restock", "3")), Shop());
        Assert.Equal("[{\"class\":\"rate_limited\",\"type\":\"reversibility_max\"}]", J(c.Caveats));
        Assert.Equal("[{\"resource\":\"*\",\"verb\":\"shop.restock\"}]", J(c.Predicates));
        // a one-second window is per_secs 1
        Assert.Equal("[{\"class\":\"rate_limited\",\"type\":\"reversibility_max\"},{\"at\":2000,\"type\":\"expires\"},{\"max\":2,\"per_secs\":1,\"type\":\"rate\"}]",
            J(C(ShopPerms("restock"), Lim(("restock", "2/s")), Shop()).Caveats));
        // no limits at all
        Assert.Empty(C(ShopPerms("restock")).Limits);
    }

    [Fact]
    public void LimitKeyPrecedence()
    {
        var perms = new JD { ["stripe"] = new JL { "refund" } };
        static string Cap(CompiledPolicy p) => J(((JL)((JD)p.Predicates[0]!)["where"]!)[0]);
        Assert.Equal("{\"field\":\"action.params.amount\",\"op\":\"lte\",\"value\":5}",
            Cap(C(perms, Lim(("reimburse", "$9"), ("refund", "$7"), ("stripe.refund", "$5")))));
        Assert.Equal("{\"field\":\"action.params.amount\",\"op\":\"lte\",\"value\":7}", Cap(C(perms, Lim(("reimburse", "$9"), ("refund", "$7")))));
        Assert.Equal("{\"field\":\"action.params.amount\",\"op\":\"lte\",\"value\":9}", Cap(C(perms, Lim(("reimburse", "$9")))));
    }

    [Fact]
    public void AVerbGrantedTwiceKeepsOneLimit()
    {
        var p = C(new JD { ["stripe"] = new JL { "refund", "refund" } }, Lim(("refund", "$5")));
        Assert.Single(p.Limits);
        Assert.Equal(DollarRp("5", "5", "0.25", "0.6"), J(p.RiskPolicy));
        Assert.Equal(2, p.Predicates.Count);
    }

    [Fact]
    public void StrictestReversibilityClass()
    {
        static string Cls(params string[] actions) => (string)((JD)C(ShopPerms(actions), null, Shop()).Caveats[0]!)["class"]!;
        Assert.Equal("reversible", Cls("tip"));
        Assert.Equal("rate_limited", Cls("restock"));
        Assert.Equal("irreversible", Cls("wire"));
        Assert.Equal("rate_limited", Cls("restock", "tip"));
        Assert.Equal("irreversible", Cls("tip", "wire", "restock"));
        // a class that is not a known reversibility class never counts as stricter than "reversible"
        Assert.Equal("reversible", Cls("odd"));
        Assert.Equal("reversible", Cls("blank"));
        Assert.Equal("rate_limited", Cls("blank", "restock", "odd"));
    }

    [Fact]
    public void BudgetModelSelection()
    {
        var dollar = Lim(("tip", "$5"));
        var count = Lim(("restock", "3/min"));
        Assert.Equal("dollars", C(ShopPerms("tip"), dollar, Shop()).BudgetModel);
        Assert.Equal("dollars", C(ShopPerms("tip"), dollar, Shop(), "auto").BudgetModel);
        Assert.Equal("dollars", C(ShopPerms("tip"), dollar, Shop(), "bogus").BudgetModel);
        var forcedRisk = C(ShopPerms("tip"), dollar, Shop(), "risk");
        Assert.Equal(("risk", DefaultRp), (forcedRisk.BudgetModel, J(forcedRisk.RiskPolicy)));
        var countOnly = C(ShopPerms("restock"), count, Shop());
        Assert.Equal(("risk", DefaultRp), (countOnly.BudgetModel, J(countOnly.RiskPolicy)));
        Assert.Equal("risk", C(ShopPerms("restock"), count, Shop(), "auto").BudgetModel);
        // a forced dollars model without any dollar limit keeps the default policy
        var forcedDollars = C(ShopPerms("restock"), count, Shop(), "dollars");
        Assert.Equal(("dollars", DefaultRp), (forcedDollars.BudgetModel, J(forcedDollars.RiskPolicy)));
        var noLimits = C(ShopPerms("restock"), null, Shop(), "dollars");
        Assert.Equal(("dollars", DefaultRp), (noLimits.BudgetModel, J(noLimits.RiskPolicy)));
        // a zero cap is still a dollar limit: kappa and bMax fall back to 1; a fractional cap is kept
        var zero = C(ShopPerms("tip"), Lim(("tip", "$0")), Shop());
        Assert.Equal(("dollars", DollarRp("1", "1", "1", "1")), (zero.BudgetModel, J(zero.RiskPolicy)));
        Assert.Equal("[{\"resource\":\"tips/*\",\"verb\":\"shop.tip\"," + Where("0") + "}]", J(zero.Predicates));
        Assert.Equal(DollarRp("0.5", "0.5", "1", "1"), J(C(ShopPerms("tip"), Lim(("tip", "$0.5")), Shop()).RiskPolicy));
    }

    [Fact]
    public void AnIrreversibleGrantKeepsTheCoSignTiers()
    {
        Assert.Equal(DollarRp("5", "5", "1", "1"), J(C(ShopPerms("tip"), Lim(("tip", "$5")), Shop()).RiskPolicy));
        Assert.Equal(DollarRp("5", "5", "0.25", "0.6"), J(C(ShopPerms("tip", "wire"), Lim(("tip", "$5")), Shop()).RiskPolicy));
        Assert.Equal(DollarRp("5", "5", "0.25", "0.6"), J(C(ShopPerms("wire"), Lim(("wire", "$5")), Shop()).RiskPolicy));
    }

    [Fact]
    public void RiskPolicyOverride()
    {
        var perms = ShopPerms("restock");
        Assert.Equal("{\"bMax\":1,\"kappa\":3,\"lambda\":0.0005,\"rho\":0.5,\"theta1\":0.25,\"theta2\":0.6,"
            + "\"weights\":{\"alpha\":0,\"beta\":0.2,\"delta\":0.2,\"epsilon\":0.1,\"gamma\":0.2,\"zeta\":0.05}}",
            J(C(perms, null, Shop(), null, new JD { ["weights"] = new JD { ["alpha"] = 0L }, ["kappa"] = 3L }).RiskPolicy));
        Assert.Equal(DefaultRp.Replace("\"kappa\":1", "\"kappa\":3"), J(C(perms, null, Shop(), null, new JD { ["kappa"] = 3L }).RiskPolicy));
        Assert.Equal("compilePolicy: derived risk policy invalid: risk_policy.kappa must be > 0",
            Refusal(() => C(perms, null, Shop(), null, new JD { ["kappa"] = -1L })));
    }

    [Fact]
    public void CompileRefusals()
    {
        Assert.Equal("compilePolicy: permissions must be an object", Refusal(() => Facade.CompilePolicy(new PolicyOptions { Permissions = null!, Now = 1 })));
        Assert.Equal("compilePolicy: no permissions granted", Refusal(() => C(new JD())));
        Assert.Equal("compilePolicy: no permissions granted", Refusal(() => C(new JD { ["stripe"] = new JL() })));
        Assert.Equal("compilePolicy: permissions.stripe must be an array", Refusal(() => C(new JD { ["stripe"] = "refund" })));
        Assert.Equal("compilePolicy: '$' limit on 'gmail.send' but the catalog gives that verb no amount field, so the limit could not be enforced",
            Refusal(() => C(new JD { ["gmail"] = new JL { "send" } }, Lim(("send", "$5")))));
        // a granted action is rendered as the reference's template literal renders it
        Assert.Equal("files.null", C(new JD { ["files"] = new JL { null } }).Actions[0].Verb);
    }

    [Fact]
    public void WallClockLifetime()
    {
        var before = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        var p = Facade.CompilePolicy(new PolicyOptions { Permissions = ShopPerms("restock"), Limits = Lim(("restock", "3/hour")), Catalog = Shop() });
        var after = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        Assert.InRange(long.Parse(J(((JD)p.Caveats[1]!)["at"])), before + 3_600_000, after + 3_600_000);
    }

    // ---- the agent ----

    static AgentHandle Shopper(Dictionary<string, string>? limits = null, long? now = 1000, JD? binding = null, ProvenanceOptions? prov = null) =>
        Agent.FromPrincipal(new AgentOptions
        {
            Principal = Key(1), Holder = Key(2), Goal = "tip couriers", Permissions = ShopPerms("tip", "restock"), Limits = limits ?? Lim(("tip", "$100")),
            Catalog = Shop(), Aud = "rs", Now = now, AgentBinding = binding, Provenance = prov,
        });

    [Fact]
    public void AgentRefusals()
    {
        Assert.Equal("agent: principal required", Refusal(() => Agent.FromPrincipal(new AgentOptions { Goal = "g", Permissions = ShopPerms("tip") })));
        Assert.Equal("agent: the principal needs an Ed25519 identity",
            Refusal(() => Agent.FromPrincipal(new AgentOptions { Principal = PqOnly(), Goal = "g", Permissions = new JD { ["files"] = new JL { "read" } }, Now = 1 })));
        Assert.Equal("agent: the holder needs an Ed25519 identity",
            Refusal(() => Agent.FromPrincipal(new AgentOptions { Principal = Key(1), Holder = PqOnly(), Goal = "g", Permissions = new JD { ["files"] = new JL { "read" } }, Now = 1 })));
        Assert.Equal("subAgent: the sub-agent needs an Ed25519 identity", Refusal(() => Shopper().SubAgent(PqOnly())));
    }

    [Fact]
    public void GrantEnvelopeAndHandle()
    {
        var holder = Key(2);
        var mediator = Key(5);
        var ag = Agent.FromPrincipal(new AgentOptions
        {
            Principal = Key(1), Holder = holder, Goal = "tip couriers", Permissions = ShopPerms("tip", "restock"), Limits = Lim(("tip", "$5")),
            Catalog = Shop(), Aud = "rs", Now = 1000, AgentBinding = new JD { ["model"] = "m1" },
            Provenance = new ProvenanceOptions { Mediator = "m-x", Kid = "k9", Signer = mediator },
        });
        Assert.Same(holder, ag.Holder);
        Assert.Equal(holder.Ed!.Id, ag.Grant["holder"]);
        Assert.Equal(Key(1).Ed!.Id, ag.PrincipalPublic);
        var env = Pca.ReadEnvelope(ag.Grant)!;
        Assert.Equal("[{\"resource\":\"tips/*\",\"verb\":\"shop.tip\"," + Where("5") + "},{\"resource\":\"*\",\"verb\":\"shop.restock\"}]", J(env["predicates"]));
        Assert.Equal(J(ag.Policy.Predicates), J(env["predicates"]));
        Assert.Equal("[{\"class\":\"rate_limited\",\"type\":\"reversibility_max\"}]", J(env["caveats"]));
        Assert.Equal(DollarRp("5", "5", "1", "1"), J(env["risk_policy"]));
        Assert.Equal("{\"model\":\"m1\"}", J(env["agent_binding"]));
        Assert.Equal(J(new JD { ["mediators"] = new JL { new JD { ["kid"] = "k9", ["mediator"] = "m-x", ["pk"] = mediator.Ed!.Id } } }), J(env["provenance"]));
        Assert.Equal("dollars", ag.Policy.BudgetModel);
        Assert.Equal(new TrustBudget(5, 1000, 1000), ag.Budget);
        Assert.Equal(5.0, ag.AutonomyBound);

        // defaults: an empty binding and the harness mediator
        var plain = Shopper();
        var penv = Pca.ReadEnvelope(plain.Grant)!;
        Assert.Equal("{}", J(penv["agent_binding"]));
        var pin = (JD)((JL)((JD)penv["provenance"]!)["mediators"]!)[0]!;
        Assert.Equal(("agent-harness", "k1", plain.Provenance.Pin.Pk), ((string)pin["mediator"]!, (string)pin["kid"]!, (string)pin["pk"]!));
    }

    [Fact]
    public void WallClockMint()
    {
        var before = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        var ag = Shopper(now: null);
        var after = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        Assert.InRange(ag.Budget.Tau, before, after);
    }

    static string RiskClaim(ActResult r) => J(((JD)r.PCActn["risk_claim"]!)["r"]);

    [Fact]
    public void ActAudienceCautionAndRiskClaim()
    {
        var ag = Shopper();
        var o = new ActOptions { Now = 2000 };
        Assert.Equal("rs", ag.Act("shop.restock", "s", null, o).PCActn["aud"]);
        Assert.Equal("other", ag.Act("shop.restock", "s", null, new ActOptions { Now = 2000, Aud = "other" }).PCActn["aud"]);
        Assert.False(ag.Act("shop.restock", "s", null, o).PCActn.ContainsKey("caution"));
        Assert.Equal("0.3", J(ag.Act("shop.restock", "s", null, new ActOptions { Now = 2000, Caution = 0.3 }).PCActn["caution"]));
        // the catalog's class goes in the action
        Assert.Equal("reversible", ((JD)ag.Act("shop.tip", "t", new JD { ["amount"] = 1L }, o).PCActn["action"]!)["reversibility_class"]);

        // dollars model: amount / kappa; no amount or a non-finite one falls back to the blast radius
        Assert.Equal("{\"inputs\":{\"blastRadius\":0.42},\"r\":0.42}", J(ag.Act("shop.tip", "t", new JD { ["amount"] = 42L }, o).PCActn["risk_claim"]));
        Assert.Equal("0.3", RiskClaim(ag.Act("shop.tip", "t", null, o)));
        Assert.Equal("0.3", RiskClaim(ag.Act("shop.tip", "t", new JD { ["amount"] = "Infinity" }, o)));
        Assert.Equal("1", RiskClaim(ag.Act("shop.tip", "t", new JD { ["amount"] = 250L }, o)));
        // a verb without an amount field uses its blast radius
        Assert.Equal("0.4", RiskClaim(ag.Act("shop.restock", "s", new JD { ["amount"] = 42L }, o)));
        // an override wins, clamped to [0, 1]
        Assert.Equal("1", RiskClaim(ag.Act("shop.tip", "t", new JD { ["amount"] = 42L }, new ActOptions { Now = 2000, Risk = 1.5 })));
        Assert.Equal("0", RiskClaim(ag.Act("shop.tip", "t", new JD { ["amount"] = 42L }, new ActOptions { Now = 2000, Risk = -0.5 })));
        // the risk model ignores the amount
        var risk = Shopper(Lim(("restock", "3/min")));
        Assert.Equal("risk", risk.Policy.BudgetModel);
        Assert.Equal("0.3", RiskClaim(risk.Act("shop.tip", "t", new JD { ["amount"] = 42L }, o)));
    }

    [Fact]
    public void DryRunClockAndCaveatContext()
    {
        var perms = new JD { ["files"] = new JL { "read" } };
        var lim = Lim(("read", "5/day"));
        var ag = Agent.FromPrincipal(new AgentOptions { Principal = Key(1), Holder = Key(2), Goal = "g", Permissions = perms, Limits = lim, Aud = "rs", Now = 1_000_000 });
        // inside the window (the wall clock is long past it): the reversibility, expiry and rate caveats all hold
        Assert.Equal(new DryRunResult(true, null, 1), ag.DryRun("files.read", "f", null, 2_000_000));
        Assert.Equal(new DryRunResult(false, "caveat(s) failed: expires"), ag.DryRun("files.read", "f", null, 1_000_000 + 86_400_000));
        Assert.Equal(new DryRunResult(false, "no predicate permits github.read on r"), ag.DryRun("github.read", "r", null, 2_000_000));
        // no explicit time: the wall clock
        var live = Agent.FromPrincipal(new AgentOptions
        {
            Principal = Key(1), Holder = Key(2), Goal = "g", Permissions = perms, Limits = lim, Aud = "rs", Now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
        });
        Assert.Equal(new DryRunResult(true, null, 1), live.DryRun("files.read", "f"));
        Assert.Equal(new DryRunResult(false, "caveat(s) failed: expires"), ag.DryRun("files.read", "f"));
    }

    // A handle over a hand-made policy (placeholder grant and chain: the dry run reads only the chain length).
    static AgentHandle Handle(JL predicates, JL caveats, int hops = 1) => new(
        new JD(), Enumerable.Range(0, hops).Select(_ => new JD()).ToList(), "s", "c",
        new CompiledPolicy { Predicates = Issue.NormL(predicates), Caveats = Issue.NormL(caveats), RiskPolicy = Issue.DefaultRiskPolicy() },
        Key(3), "pk", Catalog.Default, "rs", 0, new ProvenanceRecorder("agent-harness", "k1", Key(4)));

    static JL ReadAnything() => new() { new JD { ["verb"] = "files.read", ["resource"] = "*" } };

    [Fact]
    public void DryRunBlastRadiusAndDelegationDepth()
    {
        // files.read has blast radius 0.05
        Assert.Equal(new DryRunResult(true, null, 1),
            Handle(ReadAnything(), new JL { new JD { ["type"] = "max_blast_radius", ["max"] = new Num("0.05") } }).DryRun("files.read", "f", null, 0));
        Assert.Equal(new DryRunResult(false, "caveat(s) failed: max_blast_radius"),
            Handle(ReadAnything(), new JL { new JD { ["type"] = "max_blast_radius", ["max"] = new Num("0.04") } }).DryRun("files.read", "f", null, 0));
        // delegation depth = hops - 1
        var d0 = new JL { new JD { ["type"] = "delegation_depth", ["max"] = 0L } };
        Assert.Equal(new DryRunResult(true, null, 1), Handle(ReadAnything(), d0).DryRun("files.read", "f", null, 0));
        Assert.Equal(new DryRunResult(false, "caveat(s) failed: delegation_depth"), Handle(ReadAnything(), d0, 2).DryRun("files.read", "f", null, 0));
        Assert.Equal(new DryRunResult(true, null, 1), Handle(ReadAnything(), new JL { new JD { ["type"] = "delegation_depth", ["max"] = 1L } }, 2).DryRun("files.read", "f", null, 0));
    }

    [Fact]
    public void DryRunWithoutParamsSeesAnEmptyObject()
    {
        // the reference evaluates `params ?? {}`: a params-rooted condition is decided, not unknown
        // and the action carries the catalog's reversibility class
        var absent = new JL
        {
            new JD
            {
                ["verb"] = "files.read", ["resource"] = "*", ["where"] = new JL
                {
                    new JD { ["field"] = "action.params.x", ["op"] = "exists", ["value"] = false },
                    new JD { ["field"] = "action.reversibility_class", ["op"] = "eq", ["value"] = "reversible" },
                },
            },
        };
        Assert.Equal(new DryRunResult(true, null, 1), Handle(absent, new JL()).DryRun("files.read", "f", null, 0));
        Assert.Equal(new DryRunResult(true, null, 1), Handle(absent, new JL()).DryRun("files.read", "f", new JD { ["y"] = 1L }, 0));
        Assert.False(Handle(absent, new JL()).DryRun("files.read", "f", new JD { ["x"] = 1L }, 0).Allowed);
    }
}

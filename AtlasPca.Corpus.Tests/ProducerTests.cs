using AtlasPca;
using Xunit;
using JD = System.Collections.Generic.Dictionary<string, object?>;
using JL = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

// The producer side (Keys / Issue / Agent), round-tripped through this SDK's own verifier.
public class ProducerTests
{
    const long Now = 1_800_000_000_000L;
    const string Aud = "ins_producer_test";

    static byte[] Hex(string h) => Convert.FromHexString(h);
    static byte[] Seed(string b) => Hex(string.Concat(Enumerable.Repeat(b, 32)));
    static EdKey Ed(string b) => EdKey.FromSeed(Seed(b));

    static JD Envelope() => new()
    {
        ["predicates"] = new JL { new JD { ["verb"] = "*" } },
        ["caveats"] = new JL(),
        ["risk_policy"] = Issue.DefaultRiskPolicy(),
    };

    static Verdict Verify(JD pcactn, JD grant) => Pca.VerifyRaw(Issue.Encode(pcactn), Issue.NormJ(grant), Now, Aud);

    static Agent AgentFor(SuiteKey k, MintedGrant g) => new(k, Aud, g.Grant) { Clock = () => Now };

    static SuiteKey Principal() => SuiteKey.Ed25519(EdKey.FromSeed(new byte[32]));

    [Fact]
    public void Ed25519Rfc8032Vector1()
    {
        var k = EdKey.FromSeed(Hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"));
        Assert.Equal("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", Convert.ToHexString(k.Pub).ToLowerInvariant());
        Assert.Equal("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
            Convert.ToHexString(k.Sign(Array.Empty<byte>())).ToLowerInvariant());
    }

    [Fact]
    public void EdSuiteRoundTripAndHeader()
    {
        var p = Principal();
        var me = SuiteKey.Ed25519(Ed("01"));
        var salt = Pca.B64u(new byte[16]);
        var g = Issue.MintGrant(p, me.Id!, null, Envelope(), "pay invoices", salt);
        Assert.Equal(Issue.GoalCommit("pay invoices", salt), g.GoalCommit);
        Assert.True(Pca.VerifyChain(new JL { Issue.NormJ(g.Grant) }, p.Id, true).Ok);
        var a = AgentFor(me, g);
        var a1 = a.Act("pay", "invoice/7", new JD { ["amount"] = 1200L });
        var v = Verify(a1, g.Grant);
        Assert.True(v.Allow, v.Reason);
        Assert.Equal(1L, a1["counter"]);
        var a2 = a.Act("pay", "invoice/8");
        Assert.Equal(2L, a2["counter"]);
        Assert.NotEqual(a1["nonce"], a2["nonce"]);
        Assert.Equal(Issue.Encode(a1), Pca.DecodePcaHeader(Agent.HeaderValue(a1)));
        Assert.StartsWith("{\"pcactn\":{", Agent.ActionsBody(a1));
    }

    [Fact]
    public void TamperedActionIsRefused()
    {
        var me = SuiteKey.Ed25519(Ed("02"));
        var g = Issue.MintGrant(Principal(), me.Id!, null, Envelope(), "g");
        var a = AgentFor(me, g).Act("read", "x");
        ((JD)a["action"]!)["resource"] = "y";
        Assert.False(Verify(a, g.Grant).Allow);
    }

    [Fact]
    public void MultiNodePlanProofs()
    {
        var me = SuiteKey.Ed25519(Ed("03"));
        var g = Issue.MintGrant(Principal(), me.Id!, null, Envelope(), "g");
        var a = AgentFor(me, g);
        var nodes = Enumerable.Range(0, 5).Select(i => new JD { ["id"] = "s" + i, ["verb"] = "step", ["resource"] = "r/" + i }).ToList();
        var p = a.CommitPlan(nodes);
        for (var i = 0; i < 5; i++)
        {
            var v = Verify(a.ActNode("s" + i), g.Grant);
            Assert.True(v.Allow, $"node {i}: {v.Reason}");
        }
        Assert.Equal(p.Root, Pca.MerkleRoot(nodes.Select(n => (object?)Pca.PlanLeaf(n["id"], n, Pca.ConditionsDigest(null, null))).ToList()));
    }

    [Fact]
    public void DelegationNarrows()
    {
        var p = Principal();
        var me = SuiteKey.Ed25519(Ed("04"));
        var sub = SuiteKey.Ed25519(Ed("05"));
        var g = Issue.MintGrant(p, me.Id!, null, Envelope(), "g");
        var child = AgentFor(me, g).Delegate(sub, new JL { new JD { ["type"] = "max_uses", ["id"] = "u1", ["n"] = 3L, ["until"] = Now + 3_600_000L } });
        Assert.Equal(2, child.Chain.Count);
        Assert.True(Pca.VerifyChain(Issue.NormL(new JL(child.Chain)), p.Id, true).Ok);
        var v = Verify(child.Act("read", "x"), g.Grant);
        Assert.True(v.Allow, v.Reason);
    }

    // Set in CI (PCA_PRODUCER_OUT): this SDK's post-quantum PCActns, for the reference implementation to verify. Randomised
    // signatures cannot be byte vectors, so the reference checks them instead (packages/pca producer-native fixtures).
    static readonly JL Emitted = new();

    static void Emit(string alg, JD grant, JD pcactn)
    {
        lock (Emitted)
        {
            Emitted.Add(new JD { ["alg"] = alg, ["grant"] = Issue.Norm(grant), ["pcactn"] = Issue.Norm(pcactn) });
            var outPath = Environment.GetEnvironmentVariable("PCA_PRODUCER_OUT");
            if (string.IsNullOrEmpty(outPath)) return;
            File.WriteAllText(outPath, Pca.Canonicalize(new JD { ["lang"] = "dotnet", ["aud"] = Aud, ["now"] = Now, ["cases"] = new JL(Emitted) }));
        }
    }

    [Fact]
    public void HybridMlDsaLeafAndRoot()
    {
        var principal = SuiteKey.Create("hybrid-ed25519-ml-dsa-65", EdKey.FromSeed(new byte[32]), PqKey.Generate(Pq.Prim.MlDsa65));
        var aEd = Ed("06");
        var aPq = PqKey.Generate(Pq.Prim.MlDsa65);
        var me = SuiteKey.Create("hybrid-ed25519-ml-dsa-65", aEd, aPq);
        Assert.Equal(1952, aPq.Pk.Length);
        var g = Issue.MintGrant(principal, aEd.Id, aPq.PkB64u, Envelope(), "g");
        Assert.Equal("hybrid-ed25519-ml-dsa-65", g.Grant["alg"]);
        var a = AgentFor(me, g).Act("read", "x");
        Assert.Equal("hybrid-ed25519-ml-dsa-65", a["alg"]);
        var v = Verify(a, g.Grant);
        Assert.True(v.Allow, v.Reason);
        Emit("hybrid-ed25519-ml-dsa-65 (root and leaf)", g.Grant, a);
        // a key loaded from its encoding signs the same way
        var loaded = PqKey.Load(Pq.Prim.MlDsa65, aPq.Pk, aPq.Sk);
        Assert.Equal(aPq.PkB64u, loaded.PkB64u);
    }

    [Fact]
    public void EveryPqSuiteLeafRoundTrips()
    {
        var p = Principal();
        var cases = new (string Alg, Pq.Prim Prim)[]
        {
            ("ml-dsa-65", Pq.Prim.MlDsa65), ("hybrid-nested-ed25519-ml-dsa-65", Pq.Prim.MlDsa65), ("ml-dsa-87", Pq.Prim.MlDsa87),
            ("hybrid-ed25519-ml-dsa-87", Pq.Prim.MlDsa87), ("slh-dsa-sha2-128f", Pq.Prim.Slh128f), ("hybrid-ed25519-slh-dsa-sha2-128f", Pq.Prim.Slh128f),
        };
        foreach (var (alg, prim) in cases)
        {
            var ed = Ed("08");
            var pq = PqKey.Generate(prim);
            var me = SuiteKey.Create(alg, ed, pq);
            var g = Issue.MintGrant(p, ed.Id, pq.PkB64u, Envelope(), "g");
            var a = AgentFor(me, g).Act("read", "x");
            var v = Verify(a, g.Grant);
            Assert.True(v.Allow, $"{alg}: {v.Reason}");
            Emit(alg, g.Grant, a);
        }
    }

    [Fact]
    public void SuiteKeysFailClosed()
    {
        var ed = EdKey.Generate();
        Assert.Throws<ArgumentException>(() => SuiteKey.Create("ml-dsa-65", null, null));
        Assert.Throws<ArgumentException>(() => SuiteKey.Create("hybrid-ed25519-ml-dsa-65", ed, null));
        Assert.Throws<ArgumentException>(() => SuiteKey.Create("fn-dsa-512", ed, null));
        Assert.Throws<ArgumentException>(() => SuiteKey.Create("hybrid-ed25519-ml-dsa-65", null, PqKey.Generate(Pq.Prim.MlDsa65)));
        Assert.Throws<ArgumentException>(() => SuiteKey.Create("ml-dsa-87", ed, PqKey.Generate(Pq.Prim.MlDsa65)));
        Assert.Throws<ArgumentException>(() => EdKey.FromSeed(new byte[31]));
    }

    [Fact]
    public void EscalationAnswerVerifies()
    {
        var p = Principal();
        var me = SuiteKey.Ed25519(Ed("09"));
        var g = Issue.MintGrant(p, me.Id!, null, Envelope(), "g");
        var pa = Issue.NormJ(AgentFor(me, g).Act("read", "x"));
        var grant = Issue.NormJ(g.Grant);
        var ans = Issue.EscalationAnswer(p, grant, pa, null, true, Now, Now + 60_000);
        var b = new EscalationBinding(Escalation.PolicyDigest(grant), Escalation.ActionDigest(pa), Escalation.HistoryHead(null));
        var r = Escalation.Verify(ans, new PinnedSigner[] { p.Id! }, b, Now + 1);
        Assert.True(r.Ok, r.Reason);
        Assert.Equal("allow", r.Decision);
        Assert.False(Escalation.Verify(ans, new PinnedSigner[] { me.Id! }, b, Now + 1).Ok);
        Assert.False(Escalation.Verify(ans, new PinnedSigner[] { p.Id! }, b, Now + 120_000).Ok);
        Assert.Throws<ArgumentException>(() => Issue.EscalationAnswer(p, grant, pa, null, true, Now, Now + 90_000_000L));
    }

    [Fact]
    public void DischargeVerifies()
    {
        var me = SuiteKey.Ed25519(Ed("0a"));
        var oracle = SuiteKey.Ed25519(Ed("0b"));
        var g = Issue.MintGrant(Principal(), me.Id!, null, Envelope(), "g");
        var hop = Issue.NormJ(g.Grant);
        var d = Issue.Discharge(oracle, "kyc", "kyc-service", hop, "chain_hop", null, new JD { ["approved"] = true }, Now, Now + 60_000);
        var caveat = Issue.NormJ(new JD
        {
            ["type"] = "needs_discharge", ["id"] = "kyc", ["issuer"] = "kyc-service", ["issuer_class"] = "workload", ["bind"] = "chain_hop",
            ["ttl_ms"] = 3_600_000L, ["require"] = new JL { new JD { ["claim"] = "approved", ["op"] = "eq", ["value"] = true } },
        });
        var bind = new DischargeBinding(Pca.CapHash(hop), new[] { new DischargePin("kyc-service", "workload", oracle.Id!) }, Now + 1);
        var v = CaveatLang.VerifyDischarge(d, caveat, bind);
        Assert.True(v.Ok, v.Reason);
    }

    [Fact]
    public void NarrowVerifies()
    {
        var me = SuiteKey.Ed25519(Ed("0c"));
        var g = Issue.MintGrant(Principal(), me.Id!, null, Envelope(), "g");
        var hop = Issue.NormJ(g.Grant);
        var n = Issue.Narrow(me, hop, new JL { new JD { ["type"] = "max_uses", ["id"] = "u2", ["n"] = 2L, ["until"] = Now + 3_600_000L } }, null, Now, Now + 60_000);
        var v = CaveatLang.VerifyNarrow(n, hop, null, new NarrowBinding(Now + 1));
        Assert.True(v.Ok, v.Reason);
    }

    [Fact]
    public void PassportVerifies()
    {
        var issuer = SuiteKey.Ed25519(EdKey.FromSeed(new byte[32]));
        var agent = SuiteKey.Ed25519(Ed("0d"));
        var p = Issue.IssuePassport(new JD { ["model_id"] = "m1", ["operator"] = "acme", ["hardware_rooted"] = false, ["issued_at"] = Now });
        var sp = Issue.SignPassport(p, issuer, agent.Id!, Now, Now + 3_600_000L);
        var o = new PassportOptions { TrustedIssuers = new[] { issuer.Id! }, NowMs = Now + 1, Revoked = (_, _, _) => false };
        var r = Passports.Verify(sp, o);
        Assert.True(r.Reason == null, r.Reason);
        Assert.Throws<ArgumentException>(() => Issue.SignPassport(Issue.IssuePassport(new JD { ["model_id"] = "m", ["operator"] = "o", ["hardware_rooted"] = true, ["issued_at"] = Now }), issuer, agent.Id!, Now, Now + 1));
    }
}

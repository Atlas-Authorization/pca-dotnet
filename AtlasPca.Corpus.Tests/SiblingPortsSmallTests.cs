using System.Text;
using AtlasPca.Ap2;
using AtlasPca.Connect;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>The single-export ports: revocation message and checker, catalog risk, discovery builder, PQ pin, objective commitment reader, revocation helpers, connection copy, AP2 key generator, constants.</summary>
public class SiblingPortsSmallTests
{
    static D Grant(double kappa) => new()
    {
        ["caveats"] = new L
        {
            new D
            {
                ["type"] = "envelope", ["goal_commit"] = "g", ["predicates"] = new L(), ["caveats"] = new L(), ["agent_binding"] = new D(),
                ["risk_policy"] = new D
                {
                    ["weights"] = new D { ["alpha"] = new Num("0"), ["beta"] = new Num("0"), ["gamma"] = new Num("0"), ["delta"] = new Num("0"), ["epsilon"] = new Num("0"), ["zeta"] = new Num("0") },
                    ["theta1"] = new Num("0.3"), ["theta2"] = new Num("0.7"), ["kappa"] = IntentJs.Normalize(kappa), ["lambda"] = new Num("1"), ["rho"] = new Num("1"), ["bMax"] = new Num("1"),
                },
            },
        },
    };

    static double N(object? o) => IntentJs.NumOf(o)!.Value;

    [Fact]
    public void RevokeMessageIsTheDomainThenTheCanonicalBody()
    {
        var want = Encoding.UTF8.GetBytes("atlas-pca/revoke/v1\0{\"grant_ref\":\"g1\",\"revoked_cap_id\":\"c9\"}");
        Assert.Equal(want, Pca.RevokeMessage("g1", "c9"));
        Assert.NotEqual(want, Pca.RevokeMessage("g1", "c8"));
    }

    [Fact]
    public void ConstantsHaveTheReferenceValues()
    {
        Assert.Equal(new[] { 1, 2, 3 }, PcaConstants.ValidThresholds);
        Assert.Equal(1, PcaConstants.TemplateVersion);
        Assert.Equal("budget_alloc", PcaConstants.BudgetAllocCaveat);
        var cv = PcaHelpers.BudgetAllocCaveat(12.5);
        Assert.True(PcaHelpers.IsBudgetAllocCaveat(cv));
        Assert.Equal("12.5", ((Num)cv["limit"]!).Raw);
        Assert.Throws<ArgumentException>(() => PcaHelpers.BudgetAllocCaveat(double.NaN));
        Assert.Equal("pca-intent:", IntentRevocation.IntentRevocationPrefix);
        Assert.Equal(60, IntentRevocation.DefaultRevocationMaxAgeS["payment"]);
        Assert.Equal(300, IntentRevocation.DefaultRevocationMaxAgeS["default"]);
        Assert.Equal(1_000 + 5_000 + 60_000, IntentRevocation.RevocationExposureEnd(1_000, 5_000));
        Assert.Equal(1_000 + 5_000 + 7, IntentRevocation.RevocationExposureEnd(1_000, 5_000, 7));
        Assert.Equal("pca-intent-profile:p", IntentRevocation.ProfileRevocationScope("p"));
    }

    [Fact]
    public void CatalogRiskPricesFromTheCatalogue()
    {
        var r = Catalog.CatalogRisk("github.read", new D(), Grant(1), null, null);
        Assert.Equal(1, N(r["reversibility"]));
        Assert.Equal(0.05, N(r["blastRadius"]));
        Assert.Equal(1, N(r["confidence"]));
        Assert.False(r.ContainsKey("taint"));
        var w = Catalog.CatalogRisk("files.write", new D(), Grant(1));
        Assert.Equal(0.4, N(w["reversibility"]));
        Assert.Equal(0.5, N(w["blastRadius"]));
        var d = Catalog.CatalogRisk("gmail.delete", new D(), Grant(1));
        Assert.Equal(0, N(d["reversibility"]));
        Assert.Equal(0.8, N(d["blastRadius"]));
        Assert.Empty(Catalog.CatalogRisk("nope.nothing", new D(), Grant(1)));
    }

    [Fact]
    public void CatalogRiskMoneyVerbsUseAmountOverKappaAndFailToTheWorstCase()
    {
        D P(object? amount) => new() { ["amount"] = amount };
        Assert.Equal(0.25, N(Catalog.CatalogRisk("stripe.charge", P(new Num("25")), Grant(100))["blastRadius"]));
        Assert.Equal(1, N(Catalog.CatalogRisk("stripe.charge", P(new Num("500")), Grant(100))["blastRadius"]));
        Assert.Equal(1, N(Catalog.CatalogRisk("stripe.charge", P(new Num("-1")), Grant(100))["blastRadius"]));
        Assert.Equal(1, N(Catalog.CatalogRisk("stripe.charge", P("25"), Grant(100))["blastRadius"]));
        Assert.Equal(1, N(Catalog.CatalogRisk("stripe.charge", new D(), Grant(100))["blastRadius"]));
        Assert.Equal(1, N(Catalog.CatalogRisk("stripe.charge", null, Grant(100))["blastRadius"]));
        Assert.Equal(1, N(Catalog.CatalogRisk("stripe.charge", P(new Num("25")), Grant(0))["blastRadius"]));
        Assert.Equal(1, N(Catalog.CatalogRisk("stripe.charge", P(new Num("25")), new D())["blastRadius"]));
    }

    [Fact]
    public void CatalogRiskTaintIsClampedAndOmittedWhenNotFinite()
    {
        Assert.Equal(0.3, N(Catalog.CatalogRisk("github.read", new D(), Grant(1), null, 0.3)["taint"]));
        Assert.Equal(1, N(Catalog.CatalogRisk("github.read", new D(), Grant(1), null, 5)["taint"]));
        Assert.Equal(0, N(Catalog.CatalogRisk("github.read", new D(), Grant(1), null, -5)["taint"]));
        Assert.False(Catalog.CatalogRisk("github.read", new D(), Grant(1), null, double.NaN).ContainsKey("taint"));
    }

    [Fact]
    public void DiscoveryDocumentDefaultsAndMembers()
    {
        var d = PcaDiscovery.BuildDiscoveryDocument(new BuildDiscoveryOptions { Audience = "https://rs" });
        Assert.Equal("https://rs", d["audience"]);
        Assert.Equal("PCA-Action", d["action_header"]);
        Assert.Equal(new object?[] { "ed25519", "ml-dsa-65", "hybrid-ed25519-ml-dsa-65" }, ((L)d["signature_suites"]!).ToArray());
        Assert.Equal(7, ((L)d["required_checks"]!).Count);
        Assert.Equal("2", ((Num)((L)d["pca_versions"]!)[0]!).Raw);
        Assert.False(d.ContainsKey("endpoints") || d.ContainsKey("trusted_roots") || d.ContainsKey("metadata") || d.ContainsKey("intent") || d.ContainsKey("obligations_supported"));
        Assert.Equal(PcaDiscovery.ParseDiscoveryDocument(d).Keys, d.Keys);
        var full = PcaDiscovery.BuildDiscoveryDocument(new BuildDiscoveryOptions
        {
            Audience = "a", PcaVersions = new long[] { 2 }, ActionHeader = "X-A", TrustedRoots = new[] { "k" }, ObligationsSupported = new[] { "log" },
            Endpoints = new D { ["stepup"] = "https://rs/s" }, Metadata = new D { ["m"] = true },
            Intent = new D { ["versions"] = new L { new Num("2") } },
        });
        Assert.Equal("X-A", full["action_header"]);
        Assert.Equal(new object?[] { "k" }, ((L)full["trusted_roots"]!).ToArray());
        Assert.Equal(new object?[] { "log" }, ((L)full["obligations_supported"]!).ToArray());
        Assert.NotNull(PcaDiscovery.ParseDiscoveryDocument(full));
        Assert.Throws<ArgumentException>(() => PcaDiscovery.BuildDiscoveryDocument(new BuildDiscoveryOptions { Audience = "" }));
        Assert.Throws<ArgumentException>(() => PcaDiscovery.BuildDiscoveryDocument(new BuildDiscoveryOptions { Audience = "a", Intent = new D { ["versions"] = new L { new Num("3") } } }));
    }

    [Fact]
    public void PqPinForReturnsThePinOnlyForAVerifyingBindingOfTheAudience()
    {
        using var ed = EdKey.FromSeed(Enumerable.Repeat((byte)5, 32).ToArray());
        var pq = Pca.B64u(new byte[1952]);
        var b = Signers.SignPqBinding(ed, pq, 2, "aud-1");
        var pin = Signers.PqPinFor(b, "aud-1");
        Assert.NotNull(pin);
        Assert.Equal(pq, pin![ed.Id]);
        Assert.Single(pin);
        Assert.Null(Signers.PqPinFor(b, "aud-2"));
        Assert.Null(Signers.PqPinFor(b, ""));
        Assert.Null(Signers.PqPinFor(b, null));
        Assert.Null(Signers.PqPinFor(null, "aud-1"));
        Assert.Null(Signers.PqPinFor(new L(), "aud-1"));
        D With(string k, object? v) { var c = new D(b); c[k] = v; return c; }
        Assert.Null(Signers.PqPinFor(With("epoch", 0L), "aud-1"));
        Assert.Null(Signers.PqPinFor(With("epoch", 3L), "aud-1")); // the epoch is signed
        Assert.Null(Signers.PqPinFor(With("epoch", new Num("1.5")), "aud-1"));
        Assert.Null(Signers.PqPinFor(With("pq", Pca.B64u(new byte[10])), "aud-1"));
        Assert.Null(Signers.PqPinFor(With("sig", Pca.B64u(new byte[64])), "aud-1"));
        Assert.Null(Signers.PqPinFor(With("sig", 5), "aud-1"));
        Assert.NotNull(Signers.PqPinFor(With("epoch", new Num("2")), "aud-1"));
    }

    [Fact]
    public void ObjectiveCommitmentReaderSeparatesAbsentCommittedAndMalformed()
    {
        var g = Grant(1);
        Assert.Equal(new ObjectiveCommitmentRead(null, null), ObjectiveBinding.ReadObjectiveCommitment(g));
        Assert.Equal(new ObjectiveCommitmentRead(null, null), ObjectiveBinding.ReadObjectiveCommitment(new D()));
        D Good() => new()
        {
            ["v"] = new Num("1"), ["embedder"] = new D { ["scheme"] = "native", ["model_id"] = "m", ["config"] = new D() },
            ["goal"] = new D { ["commit"] = "c" }, ["registry_digest"] = "r", ["graph_digest"] = "gd", ["authorized_kinds"] = new L { "k" },
        };
        D With(Action<D> f) { var o = Good(); f(o); ((D)((L)g["caveats"]!)[0]!)["objective_risk"] = o; return g; }
        var ok = ObjectiveBinding.ReadObjectiveCommitment(With(_ => { }));
        Assert.Null(ok.Malformed);
        Assert.Equal("m", ((D)ok.Commitment!["embedder"]!)["model_id"]);
        string? Bad(Action<D> f) => ObjectiveBinding.ReadObjectiveCommitment(With(f)).Malformed;
        Assert.Contains("version", Bad(o => o["v"] = new Num("2"))!);
        Assert.Contains("embedder", Bad(o => ((D)o["embedder"]!)["scheme"] = "byo")!);
        Assert.Contains("embedder", Bad(o => ((D)o["embedder"]!)["model_id"] = "")!);
        Assert.Contains("goal", Bad(o => o["goal"] = new D())!);
        Assert.Contains("digest", Bad(o => o["graph_digest"] = "")!);
        Assert.Contains("calibration_digest", Bad(o => o["calibration_digest"] = 1)!);
        Assert.Contains("authorized_kinds", Bad(o => o["authorized_kinds"] = new L { 1 })!);
        Assert.Contains("denominations", Bad(o => o["denominations"] = "x")!);
        Assert.Contains("on_mismatch", Bad(o => o["on_mismatch"] = "allow")!);
        Assert.Null(Bad(o => { o["on_mismatch"] = "heuristic"; o["calibration_digest"] = "cd"; o["denominations"] = new L(); }));
        Assert.Contains("version", Bad(o => o["v"] = "1")!);
    }

    [Fact]
    public void CloneConnectionCopiesEverythingAndSharesNothing()
    {
        var c = new StoredConnection
        {
            AgentId = "a", Provider = "p", ConnectionId = "c", AccessToken = "t", RefreshToken = "r", ExpiresAt = 5, Scopes = new List<string> { "s" },
            Authority = new ConnectionAuthority { Provider = "p", Principal = "k", Scopes = new List<string> { "s" }, Audience = "u" }, CreatedAt = 1, LastUsedAt = 2, UseCount = 3,
        };
        var d = ConnectStore.CloneConnection(c);
        Assert.NotSame(c, d);
        Assert.Equal(c.ToJson().Keys, d.ToJson().Keys);
        Assert.Equal("r", d.RefreshToken);
        Assert.Equal(3, d.UseCount);
        d.Scopes.Add("x"); d.Authority.Scopes.Add("y");
        Assert.Single(c.Scopes);
        Assert.Single(c.Authority.Scopes);
    }

    [Fact]
    public void GeneratedAp2KeyPairIsAFreshPublicJwkAndAUsablePrivateScalar()
    {
        var a = Ap2.Ap2.GenerateAp2KeyPair("kid-1");
        var b = Ap2.Ap2.GenerateAp2KeyPair();
        Assert.Equal("kid-1", a.PublicJwk["kid"]);
        Assert.False(b.PublicJwk.ContainsKey("kid"));
        Assert.False(a.PublicJwk.ContainsKey("d"));
        Assert.Equal("P-256", a.PublicJwk["crv"]);
        Assert.NotEqual(a.PublicJwk["x"], b.PublicJwk["x"]);
        var back = Ap2.Ap2.Ap2KeyPairFromPrivateJwk(new D { ["kty"] = "EC", ["crv"] = "P-256", ["d"] = Pca.B64u(a.PrivateScalar), ["x"] = a.PublicJwk["x"], ["y"] = a.PublicJwk["y"] });
        Assert.Equal(a.PublicJwk["x"], back.PublicJwk["x"]);
        Assert.Equal(a.PublicJwk["y"], back.PublicJwk["y"]);
    }

    // ---- the revocation checker hook ----

    static PcaCore.CoreContext Ctx(params string[] caps) => new(
        new D
        {
            ["grant_ref"] = "g", ["action"] = new D { ["reversibility_class"] = "reversible" },
            ["cap_chain"] = new L(caps.Select(c => (object?)new D { ["id"] = c })),
        }, new D(), 1_000_000);

    [Fact]
    public void CheckerAcceptsEveryChainIdWithAValidNonMembershipProofAndRefusesTheRest()
    {
        var set = new MeshRevocationSet(new[] { "zz-revoked", "aa-other" });
        var hook = RevocationChecker.Create(new RevocationCheckerOptions
        {
            Root = _ => set.Root(),
            ProofFor = (id, _) => set.Has(id) ? null : set.NonMembershipProof(id),
        });
        var ok = hook(Ctx("c1", "c2"));
        Assert.True(ok.Enforced);
        Assert.True(ok.Ok);
        var revoked = hook(Ctx("c1", "zz-revoked"));
        Assert.False(revoked.Ok);
        Assert.Contains("zz-revoked", revoked.Reason);
        var empty = RevocationChecker.Create(new RevocationCheckerOptions { ProofFor = (id, _) => set.NonMembershipProof(id) })(Ctx("c1"));
        Assert.False(empty.Ok);
        Assert.Equal("no revocation root", empty.Reason);
        var other = RevocationChecker.Create(new RevocationCheckerOptions { Root = _ => "AAAA", ProofFor = (id, _) => set.NonMembershipProof(id) })(Ctx("c1"));
        Assert.False(other.Ok);
        Assert.NotNull(other.Reason);
    }

    [Fact]
    public void CheckerUsesTheExplicitIdsAndFailsClosedOnAnIdlessChainEntry()
    {
        var set = new MeshRevocationSet(new[] { "zz-revoked" });
        var seen = new List<string>();
        var hook = RevocationChecker.Create(new RevocationCheckerOptions
        {
            Root = _ => set.Root(), Ids = _ => new[] { "only" },
            ProofFor = (id, _) => { seen.Add(id); return set.NonMembershipProof(id); },
        });
        Assert.True(hook(Ctx("zz-revoked")).Ok);
        Assert.Equal(new[] { "only" }, seen);
        var chain = Ctx();
        ((L)chain.Pcactn["cap_chain"]!).Add(new D());
        var strict = RevocationChecker.Create(new RevocationCheckerOptions { Root = _ => set.Root(), ProofFor = (id, _) => set.NonMembershipProof(id) })(chain);
        Assert.False(strict.Ok);
    }

    [Fact]
    public void CheckerRequiresASignedEpochWhenAnEpochSourceIsConfigured()
    {
        var set = new MeshRevocationSet();
        var accepted = 0;
        var hook = RevocationChecker.Create(new RevocationCheckerOptions
        {
            Root = _ => set.Root(), Epoch = _ => null, GuardianPublic = "g", OnEpochAccepted = (_, _) => accepted++,
            ProofFor = (id, _) => set.NonMembershipProof(id),
        });
        var r = hook(Ctx("c1"));
        Assert.False(r.Ok);
        Assert.Equal("no signed revocation epoch", r.Reason);
        Assert.Equal(0, accepted);
        var noGuardian = RevocationChecker.Create(new RevocationCheckerOptions { Epoch = _ => new D(), ProofFor = (id, _) => null })(Ctx("c1"));
        Assert.Equal("no signed revocation epoch", noGuardian.Reason);
    }

    [Fact]
    public void CheckerVerifiesASignedEpochAndReportsItOnlyWhenAccepted()
    {
        var seed = Enumerable.Repeat((byte)9, 32).ToArray();
        var set = new MeshRevocationSet(new[] { "zz" });
        var epoch = RevocationFreshness.SignEpoch(seed, new RevocationEpochBody("i", "g", 4, 1, set.Root(), 999_000, 1_999_000));
        var accepted = new List<D>();
        var guardian = (string)epoch["guardian"]!;
        var hook = RevocationChecker.Create(new RevocationCheckerOptions
        {
            Epoch = _ => epoch, GuardianPublic = guardian, OnEpochAccepted = (e, _) => accepted.Add(e), LastAcceptedEpoch = _ => 3,
            ProofFor = (id, _) => set.NonMembershipProof(id),
        });
        Assert.True(hook(Ctx("c1")).Ok);
        Assert.Single(accepted);
        var rollback = RevocationChecker.Create(new RevocationCheckerOptions
        {
            Epoch = _ => epoch, GuardianPublic = guardian, LastAcceptedEpoch = _ => 5, ProofFor = (id, _) => set.NonMembershipProof(id),
        })(Ctx("c1"));
        Assert.False(rollback.Ok);
        var wrongRoot = RevocationChecker.Create(new RevocationCheckerOptions
        {
            Epoch = _ => epoch, GuardianPublic = guardian, Root = _ => "not-the-root", ProofFor = (id, _) => set.NonMembershipProof(id),
        })(Ctx("c1"));
        Assert.Equal("revocation root does not match the signed epoch", wrongRoot.Reason);
        var revoked = RevocationChecker.Create(new RevocationCheckerOptions { Epoch = _ => epoch, GuardianPublic = guardian, ProofFor = (id, _) => null, OnEpochAccepted = (e, _) => accepted.Add(e) })(Ctx("c1"));
        Assert.False(revoked.Ok);
        Assert.Single(accepted);
    }

    [Fact]
    public void CheckerRefusesAnUnsignedRootForAnIrreversibleActionUnderAStalenessPolicy()
    {
        var set = new MeshRevocationSet();
        var hook = RevocationChecker.Create(new RevocationCheckerOptions
        {
            Staleness = new RevocationStalenessPolicy(MaxRevocationAgeMs: 60_000), Root = _ => set.Root(), RootIssuedAt = _ => 999_000,
            ReversibilityClass = _ => "irreversible", ProofFor = (id, _) => set.NonMembershipProof(id),
        });
        Assert.Contains("irreversible", hook(Ctx("c1")).Reason);
        var reversible = RevocationChecker.Create(new RevocationCheckerOptions
        {
            Staleness = new RevocationStalenessPolicy(MaxRevocationAgeMs: 60_000), Root = _ => set.Root(), RootIssuedAt = _ => 999_000, ProofFor = (id, _) => set.NonMembershipProof(id),
        });
        Assert.True(reversible(Ctx("c1")).Ok);
        var stale = RevocationChecker.Create(new RevocationCheckerOptions
        {
            Staleness = new RevocationStalenessPolicy(MaxRevocationAgeMs: 1_000), Root = _ => set.Root(), RootIssuedAt = _ => 900_000, ProofFor = (id, _) => set.NonMembershipProof(id),
        });
        Assert.False(stale(Ctx("c1")).Ok);
    }

    [Fact]
    public void CheckerConfigurationErrorsAreRaisedAtConstruction()
    {
        Assert.Throws<ArgumentException>(() => RevocationChecker.Create(new RevocationCheckerOptions()));
        Assert.Throws<ArgumentException>(() => RevocationChecker.Create(new RevocationCheckerOptions
        {
            Staleness = new RevocationStalenessPolicy(MaxRevocationAgeMs: -1), ProofFor = (_, _) => null,
        }));
    }
}

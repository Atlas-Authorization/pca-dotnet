using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using AtlasPca;
using Xunit;
using JD = System.Collections.Generic.Dictionary<string, object?>;
using JL = System.Collections.Generic.List<object?>;

namespace AtlasPca.AspNetCore.Tests;

// Revocation staleness (T9) through Authorize: the `freshness` check is required when the policy is on, runs before the replay claim,
// leaves IsRevoked untouched, and fails closed on a missing, failing or too old state source.
public class StalenessAuthorizeTests
{
    static readonly JD Fix = (JD)Pca.ParseJson(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "test-data", "authorize-fixtures.json")))!;
    static readonly string Aud = (string)Fix["audience"]!;
    static readonly long Now = long.Parse(((Num)Fix["now"]!).Raw, CultureInfo.InvariantCulture);
    // the signed class of this PCActn is irreversible: the cap is the two-minute irreversible window
    static readonly JD Case = ((JL)Fix["cases"]!).Cast<JD>().First(c => (string)c["name"]! == "envelope-max-spend-within");
    static readonly JD Grant = (JD)Case["grant"]!;
    static readonly JD Step = (JD)((JL)Case["steps"]!)[0]!;
    static readonly JD Pcactn = (JD)Step["pcactn"]!;
    static readonly Operation Op = new((string)((JD)Step["operation"]!)["verb"]!, (string)((JD)Step["operation"]!)["resource"]!, ((JD)Step["operation"]!)["params"]);
    static readonly byte[] Seed = Enumerable.Repeat((byte)11, 32).ToArray();
    static string GrantRef => (string)Pcactn["grant_ref"]!;

    static JD Epoch(long issuedAgoMs) => RevocationFreshness.SignEpoch(Seed, new RevocationEpochBody("i", GrantRef, 0, 0, "root-1", Now - issuedAgoMs, Now + 300_000));
    static string Guardian => (string)Epoch(0)["guardian"]!;

    static AuthorizeInput Input(IStateStore store, RevocationStalenessPolicy? policy, Func<JD, JD, RevocationState?>? source, Func<JD, JD?>? ctx = null, bool freshnessOnly = true) => new AuthorizeInput
    {
        Operation = Op, Audience = Aud, ResolveGrant = r => r == (string)Grant["id"]! ? Grant : null, StateStore = store, IsRevoked = (_, _) => false,
        Now = Now, Plan = "single-step", RevocationStaleness = policy, RevocationState = source, GuardianPublic = Guardian, Context = ctx,
        // these tests exercise freshness only; the proofs have their own test below
        RevocationIds = freshnessOnly ? _ => Array.Empty<string>() : null,
    }.WithProv();

    static readonly RevocationStalenessPolicy On = new(MaxRevocationAgeMs: 300_000);

    [Fact]
    public void OffByDefaultNothingChanges()
    {
        var r = Pca.Authorize(Pcactn, Input(new MemoryStateStore(), null, null));
        Assert.True(r.Allow);
        Assert.False(r.Checks.ContainsKey("freshness"));
        var empty = Pca.Authorize(Pcactn, Input(new MemoryStateStore(), new RevocationStalenessPolicy(), null));
        Assert.True(empty.Allow);
    }

    [Fact]
    public void AFreshSignedEpochPasses()
    {
        var r = Pca.Authorize(Pcactn, Input(new MemoryStateStore(), On, (_, _) => new RevocationState(Epoch: Epoch(30_000))));
        Assert.True(r.Allow, r.Reason);
        Assert.Equal("pass", r.Checks["freshness"]);
    }

    [Fact]
    public void AnEpochOverTheIrreversibleWindowIsRefusedBeforeTheCounterIsSpent()
    {
        var store = new MemoryStateStore();
        var r = Pca.Authorize(Pcactn, Input(store, On, (_, _) => new RevocationState(Epoch: Epoch(180_000))));
        Assert.False(r.Allow);
        Assert.Equal("fail", r.Checks["freshness"]);
        Assert.Equal("freshness: revocation epoch is 180000 ms old, over the verifier's maximum of 120000 ms (stale revocation state)", r.Reason);
        Assert.Null(store.Last(Pca.StateKey((string)Grant["id"]!, (string)((JD)((JL)Pcactn["cap_chain"]!).Last()!)["holder"]!)));
    }

    [Fact]
    public void AReversibleServerClassCannotLoosenTheSignedIrreversibleClass()
    {
        var r = Pca.Authorize(Pcactn, Input(new MemoryStateStore(), On, (_, _) => new RevocationState(Epoch: Epoch(180_000)), _ => new JD { ["reversibility_class"] = "reversible" }));
        Assert.False(r.Allow);
        Assert.Equal("fail", r.Checks["freshness"]);
    }

    [Fact]
    public void AnUnsignedRootIsRefusedForAnIrreversibleActionUnlessAllowed()
    {
        RevocationState Bare() => new(Root: "root-1", RootIssuedAt: Now - 10_000);
        var refused = Pca.Authorize(Pcactn, Input(new MemoryStateStore(), On, (_, _) => Bare()));
        Assert.False(refused.Allow);
        Assert.Equal("freshness: unsigned revocation root refused for an irreversible action (needs a guardian-signed epoch)", refused.Reason);
        var allowed = Pca.Authorize(Pcactn, Input(new MemoryStateStore(), On with { AllowUnsignedRootForIrreversible = true }, (_, _) => Bare()));
        Assert.True(allowed.Allow, allowed.Reason);
    }

    [Fact]
    public void MissingFailingOrEmptyStateSourcesFailClosed()
    {
        var noSource = Pca.Authorize(Pcactn, Input(new MemoryStateStore(), On, null));
        Assert.False(noSource.Allow);
        Assert.Equal(new[] { "RevocationState (required by RevocationStaleness)" }, noSource.Missing);
        var bad = Pca.Authorize(Pcactn, Input(new MemoryStateStore(), new RevocationStalenessPolicy(MaxRevocationAgeMs: -1), (_, _) => null));
        Assert.False(bad.Allow);
        Assert.StartsWith("RevocationStaleness (invalid:", bad.Missing!.Single());
        var throws = Pca.Authorize(Pcactn, Input(new MemoryStateStore(), On, (_, _) => throw new InvalidOperationException("down")));
        Assert.False(throws.Allow);
        Assert.Equal("freshness: the revocation state source failed (fail closed)", throws.Reason);
        var none = Pca.Authorize(Pcactn, Input(new MemoryStateStore(), On, (_, _) => null));
        Assert.False(none.Allow);
        Assert.Equal("freshness: no verifiable (guardian-signed) revocation state for an irreversible action", none.Reason);
    }

    [Fact]
    public void EveryChainCapabilityNeedsANonMembershipProof()
    {
        // default ids = the PCActn's cap_chain: a gate with no proof source denies, fail closed
        var empty = IntentRevocation.RevsetRoot(Array.Empty<string>());
        JD Fresh() => RevocationFreshness.SignEpoch(Seed, new RevocationEpochBody("i", GrantRef, 0, 0, empty, Now - 1_000, Now + 300_000));
        var chain = ((JL)Pcactn["cap_chain"]!).Select(c => (string)((JD)c!)["id"]!).ToList();
        Assert.NotEmpty(chain);
        var denied = Pca.Authorize(Pcactn, Input(new MemoryStateStore(), On, (_, _) => new RevocationState(Epoch: Fresh()), freshnessOnly: false));
        Assert.False(denied.Allow);
        Assert.Equal("freshness: no non-membership proof for " + chain[0], denied.Reason);
        var input = Input(new MemoryStateStore(), On, (_, _) => new RevocationState(Epoch: Fresh()), freshnessOnly: false);
        input.RevocationProofFor = (_, _) => new JD { ["size"] = IntentJs.OfLong(0) };
        var ok = Pca.Authorize(Pcactn, input);
        Assert.True(ok.Allow, ok.Reason);
        // a proof that does not fold to the signed root is a revoked capability
        input = Input(new MemoryStateStore(), On, (_, _) => new RevocationState(Epoch: Fresh()), freshnessOnly: false);
        input.RevocationProofFor = (_, _) => new JD { ["size"] = IntentJs.OfLong(1) };
        var bad = Pca.Authorize(Pcactn, input);
        Assert.False(bad.Allow);
        Assert.Equal($"freshness: capability {chain[0]} is revoked or proof invalid", bad.Reason);
    }
}

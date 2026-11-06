using AtlasPca;
using Xunit;
using JD = System.Collections.Generic.Dictionary<string, object?>;
using JL = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>LeasePolicy.MaxTtlCeiling: packages/pca-grants/src/lease.ts:219 (constructor), :230 (prune), :245 (refusal),
/// lease-store-conformance.ts section 8.</summary>
public class LeaseCeilingTests
{
    const long T0 = 1_800_000_000_000L, DAY = 86_400_000L;
    static readonly EdKey Auth = EdKey.FromSeed(Enumerable.Repeat((byte)41, 32).ToArray());

    static JD Sign(JD body, string domain) { var b = Issue.NormJ(body); return new(b) { ["sig"] = Issue.SignBody(Auth, domain, b) }; }

    static JD Mk(string id, long maxTtl = DAY, long issued = T0, long expires = T0 + 1000) => Sign(new JD
    {
        ["v"] = 1L, ["lease_id"] = id, ["path"] = "svc/" + id, ["grant_ref"] = "g", ["holder"] = "h", ["requester"] = "r", ["approvers"] = new JL { "a" },
        ["justification_digest"] = "j", ["seq"] = 1L, ["issued_at"] = issued, ["renewed_at"] = issued, ["expires_at"] = expires, ["max_ttl"] = maxTtl, ["authority"] = Auth.Id,
    }, Lease.Domain);

    static JD Rev(string value, long revokedAt) => Sign(new JD { ["v"] = 1L, ["target"] = "prefix", ["value"] = value, ["revoked_at"] = revokedAt, ["authority"] = Auth.Id }, Lease.RevokeDomain);

    static LeasePolicy Policy(long? ceiling) => new(new[] { Auth.Id }, MaxTtlCeiling: ceiling);

    [Fact]
    public void AcceptsAtAndBelowTheCeilingAndRefusesAbove()
    {
        var reg = new LeaseRegistry(Policy(DAY));
        Assert.Equal(new LeaseAccept(false, "ttl_ceiling"), reg.Accept(Mk("big", DAY + 1)));
        Assert.True(reg.Accept(Mk("at", DAY)).Ok);
        Assert.True(reg.Accept(Mk("below", DAY - 1)).Ok);
    }

    [Fact]
    public void AnAbsentCeilingIsNoCeiling() => Assert.True(new LeaseRegistry(Policy(null)).Accept(Mk("big", DAY * 365)).Ok);

    [Fact]
    public void TheCapIsReportedBeforeTheCeiling() =>
        Assert.Equal("over_max_ttl", new LeaseRegistry(Policy(DAY)).Accept(Mk("over", DAY + 1, T0, T0 + DAY + 2)).Code);

    [Theory]
    [InlineData(0L)]
    [InlineData(-1L)]
    [InlineData(9007199254740992L)]
    public void AMalformedCeilingThrowsAtConstruction(long c) =>
        Assert.StartsWith("LeaseRegistry: maxTtlCeiling must be a positive integer", Assert.Throws<ArgumentOutOfRangeException>(() => new LeaseRegistry(Policy(c))).Message);

    [Theory]
    [InlineData(1L)]
    [InlineData(9007199254740991L)]
    public void TheCeilingBoundsAreValid(long c) => Assert.NotNull(new LeaseRegistry(Policy(c)));

    [Fact]
    public void ARevocationIsKeptUntilItsCeilingPassesThenPrunedOnAcceptOrRevoke()
    {
        long now = T0;
        var reg = new LeaseRegistry(Policy(DAY), () => now);
        Assert.True(reg.Revoke(Rev("svc/old", T0)).Ok);
        now = T0 + DAY; // revoked_at + ceiling == now: kept
        Assert.True(reg.Accept(Mk("trigger1", 5000, now, now + 1000)).Ok);
        Assert.Single(reg.Revocations);
        now = T0 + DAY + 1;
        Assert.True(reg.Accept(Mk("trigger2", 5000, now, now + 1000)).Ok);
        Assert.Empty(reg.Revocations);

        Assert.True(reg.Revoke(Rev("svc/a", T0)).Ok); // already past: pruned by the same call
        Assert.Empty(reg.Revocations);
        Assert.Equal(1, reg.Revoke(Rev("svc/trigger2", now)).Revoked);
        Assert.Single(reg.Revocations);
    }

    [Fact]
    public void WithoutACeilingNothingIsPruned()
    {
        var reg = new LeaseRegistry(Policy(null), () => T0 + DAY * 1000);
        Assert.True(reg.Revoke(Rev("svc/old", T0)).Ok);
        Assert.True(reg.Accept(Mk("x", 5000, T0, T0 + 1000)).Ok);
        Assert.Single(reg.Revocations);
    }
}

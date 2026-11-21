using AtlasPca.Ciba;
using AtlasPca.Revoke;
using Xunit;

namespace AtlasPca.Corpus.Tests;

/// <summary>The approval-store and revocation-store conformance kits pass on the reference in-memory stores and fail on a store that breaks the contract.</summary>
public class ConformanceKitsTests
{
    [Fact]
    public void TheMemoryApprovalStorePassesEveryCase()
    {
        var report = StoreConformance.RunApprovalStore(CibaApproval.CreateMemoryApprovalStore, s => s);
        Assert.True(report.Ok, report.ToString());
        Assert.Equal(15, report.Checks.Count);
    }

    sealed class ForgetfulStore : IApprovalStore
    {
        readonly IApprovalStore _inner = CibaApproval.CreateMemoryApprovalStore();
        public Versioned? Get(string key) => _inner.Get(key);
        // never refuses a stale version: the contract's whole point
        public bool Cas(string key, long expectedVersion, object? value) => _inner.Cas(key, _inner.Get(key)?.Version ?? 0, value);
    }

    [Fact]
    public void AStoreThatIgnoresTheExpectedVersionFails()
    {
        var report = StoreConformance.RunApprovalStore(() => new ForgetfulStore());
        Assert.False(report.Ok);
        Assert.Equal("fail", report.StatusOf("cas succeeds only at the current version and bumps it by exactly one"));
    }

    [Fact]
    public async Task TheMemoryRevocationStorePassesEveryCase()
    {
        var cases = RevocationConformance.RevocationStoreCases(() => new InMemoryRevocationStore(), s => s);
        Assert.Equal(10, cases.Count);
        foreach (var c in cases) await c.Run();
    }

    sealed class DuplicatingStore : IRevocationStore
    {
        readonly List<Dictionary<string, object?>> _all = new();
        public Task Add(Dictionary<string, object?> entry) { lock (_all) _all.Add(entry); return Task.CompletedTask; }
        public Task<bool> Remove(string kind, string value) { lock (_all) return Task.FromResult(_all.RemoveAll(e => (string?)e["kind"] == kind && (string?)e["value"] == value) > 0); }
        public Task<Dictionary<string, object?>?> Get(string kind, string value) { lock (_all) return Task.FromResult(_all.FirstOrDefault(e => (string?)e["kind"] == kind && (string?)e["value"] == value)); }
        public Task<IReadOnlyList<Dictionary<string, object?>>> All() { lock (_all) return Task.FromResult<IReadOnlyList<Dictionary<string, object?>>>(_all.ToList()); }
        public Task Clear() { lock (_all) _all.Clear(); return Task.CompletedTask; }
    }

    [Fact]
    public async Task AStoreThatDuplicatesOnReplaceFails()
    {
        var c = RevocationConformance.RevocationStoreCases(() => new DuplicatingStore()).Single(x => x.Name.StartsWith("add at an existing key"));
        await Assert.ThrowsAsync<InvalidOperationException>(c.Run);
    }
}

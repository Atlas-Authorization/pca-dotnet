using AtlasPca;
using Xunit;
using T = AtlasPca.PqThreshold.PqThreshold;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Differential oracle of the post-quantum threshold step-up (test-data/ref-pq-threshold.json.gz, TS reference packages/pca-pq-threshold).
/// The FROST aggregate in a hybrid artifact is an ordinary Ed25519 signature by the group key, which is exactly what the verifier checks.</summary>
public class RefPqThresholdTests
{
    const string M = "ref-pq-threshold";

    /// <summary>{"$bytes": b64url} nodes become byte[] (the reference passes Uint8Array there).</summary>
    static object? Un(object? a) => a switch
    {
        D m when Base.IsBytes(m) => Base.Bytes(m),
        D m => m.ToDictionary(e => e.Key, e => Un(e.Value)),
        L l => l.Select(Un).ToList(),
        _ => a,
    };

    [Fact] public void SignerSetCommitment() => Base.Check(M, "signerSetCommitment", a => T.SignerSetCommitment(Un(a[0])));

    [Fact]
    public void IssueGroupDescriptor() => Base.Check(M, "issueGroupDescriptor", a =>
    {
        var x = (D)a[0]!;
        byte[]? seed = x.TryGetValue("authoritySeed", out var s) && Base.IsBytes(s) ? Base.Bytes(s) : null;
        return T.IssueGroupDescriptor(seed, Un(x.GetValueOrDefault("groupPublicKey")), x.GetValueOrDefault("t"), Un(x.GetValueOrDefault("participants")));
    });

    [Fact] public void VerifyGroupDescriptor() => Base.Check(M, "verifyGroupDescriptor", a => T.VerifyGroupDescriptor(Un(a[0]), Un(a[1])));

    [Fact] public void PqQuorumRepresentative() => Base.Check(M, "pqQuorumRepresentative", a => T.PqQuorumRepresentative(Base.Bytes(a[0])));

    [Fact] public void NormalizePqQuorumPool() => Base.Check(M, "normalizePqQuorumPool", a =>
        T.NormalizePqQuorumPool(Un(a[0])).OrderBy(k => k, StringComparer.Ordinal).ToList());

    [Fact] public void VerifyPqQuorum() => Base.Check(M, "verifyPqQuorum", a =>
        T.VerifyPqQuorum(a[0], Base.Bytes(a[1]), T.NormalizePqQuorumPool(Un(a[2])), a[3]));

    [Fact] public void VerifyHybridThreshold() => Base.Check(M, "verifyHybridThreshold", a =>
        T.VerifyHybridThreshold((D)a[0]!, a[1], (D)Un(a[2])!));

    [Fact]
    public void EveryFn() { Base.Covers(M, new[]
    {
        "signerSetCommitment", "issueGroupDescriptor", "verifyGroupDescriptor", "pqQuorumRepresentative", "normalizePqQuorumPool", "verifyPqQuorum",
        "verifyHybridThreshold",
    }); Assert.Equal(212, Base.Total(M)); }
}

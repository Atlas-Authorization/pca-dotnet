using AtlasPca;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Replay of the in-core post-quantum quorum certificate (test-data/ref-pq-threshold-quorum.json.gz): quorum sets, the signed message, shares, proofs, rotation
/// certificates and chains, and the size model. A seed is the 32-byte seed as base64url (an ML-DSA key seed for <c>mlDsa</c> / <c>mlDsa87</c>); bytes are <c>{"$bytes"}</c>.</summary>
public class RefPqQuorumTests
{
    const string M = "ref-pq-threshold-quorum";

    static SuiteSecretKeys Keys(object? k)
    {
        if (k is not D d) throw new InvalidOperationException("Cannot read properties of " + (k == null ? "null" : "a non-object"));
        var s = new SuiteSecretKeys();
        if (d.GetValueOrDefault("edSecret") is string e) s.EdSecret = Pca.B64uDecode(e)!;
        if (d.GetValueOrDefault("mlDsa") is string m) s.MlDsa = PqSuites.MlDsa65Keygen(Pca.B64uDecode(m)!);
        if (d.GetValueOrDefault("mlDsa87") is string m87) s.MlDsa87 = PqSuites.MlDsa87Keygen(Pca.B64uDecode(m87)!);
        return s;
    }

    // the hash reads a string as its UTF-8 bytes (and refuses anything else that is not bytes)
    static byte[] Bytes(object? a) => Base.IsBytes(a) ? Base.Bytes(a) : a is string s ? System.Text.Encoding.UTF8.GetBytes(s) : throw new InvalidOperationException("Uint8Array expected");

    [Fact] public void Constants() => Base.Check(M, "constants", _ => PqQuorum.Constants());
    [Fact] public void BuildQuorumSet() => Base.Check(M, "buildQuorumSet", a => a.Count > 2 ? PqQuorum.BuildQuorumSet(a[0], a[1], a[2], true) : PqQuorum.BuildQuorumSet(a[0], a[1]), min: 76);
    [Fact] public void LoadQuorumSet() => Base.Check(M, "loadQuorumSet", a => PqQuorum.LoadQuorumSet(a[0]), min: 50);
    [Fact] public void QuorumMessage() => Base.Check(M, "quorumMessage", a => PqQuorum.QuorumMessage(a[0], a[1], a[2]), min: 19);
    [Fact] public void QuorumActionDigest() => Base.Check(M, "quorumActionDigest", a => PqQuorum.QuorumActionDigest(Bytes(a[0])), min: 7);
    [Fact] public void SignQuorumShare() => Base.Check(M, "signQuorumShare", a => PqQuorum.SignQuorumShare(a[0], a[1], a[2], a[3], Keys(a[4])), min: 17);
    [Fact] public void AssembleQuorumProof() => Base.Check(M, "assembleQuorumProof", a => PqQuorum.AssembleQuorumProof(a[0], a[1]), min: 5);
    [Fact] public void VerifyQuorum() => Base.Check(M, "verifyQuorum", a => PqQuorum.VerifyQuorum(a[0]), min: 102);

    [Fact]
    public void VerifyQuorumApproval() => Base.Check(M, "verifyQuorumApproval",
        a => PqQuorum.VerifyQuorumApproval(a[0], a[1], Base.IsBytes(a[2]) ? Base.Bytes(a[2]) : null, a[3], a.Count > 4 ? a[4] : null), min: 14);

    [Fact] public void RotationActionDigest() => Base.Check(M, "rotationActionDigest", a => PqQuorum.RotationActionDigest(a[0], a[1]), min: 9);
    [Fact] public void SignRotationShare() => Base.Check(M, "signRotationShare", a => PqQuorum.SignRotationShare(a[0], a[1], a[2], a[3], Keys(a[4])), min: 8);
    [Fact] public void BuildRotationCert() => Base.Check(M, "buildRotationCert", a => PqQuorum.BuildRotationCert(a[0], a[1], a[2], a[3]), min: 7);
    [Fact] public void VerifyRotationChain() => Base.Check(M, "verifyRotationChain", a => PqQuorum.VerifyRotationChain(a[0], a[1], a[2]), min: 44);
    [Fact] public void IsRotationFork() => Base.Check(M, "isRotationFork", a => PqQuorum.IsRotationFork(a[0], a[1]), min: 14);
    [Fact] public void QuorumProofSize() => Base.Check(M, "quorumProofSize", a => a.Count > 1 ? PqQuorum.QuorumProofSize(a[0], a[1], true) : PqQuorum.QuorumProofSize(a[0]), min: 16);

    [Fact]
    public void Covers()
    {
        Base.Covers(M, new[]
        {
            "constants", "buildQuorumSet", "loadQuorumSet", "quorumMessage", "quorumActionDigest", "signQuorumShare", "assembleQuorumProof", "verifyQuorum", "verifyQuorumApproval",
            "rotationActionDigest", "signRotationShare", "buildRotationCert", "verifyRotationChain", "isRotationFork", "quorumProofSize",
        });
        Assert.Equal(389, Base.Total(M));
    }
}

using System.Security.Cryptography;
using AtlasPca;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Consistency proofs refuse any node that is not a 32-byte hash. With oldSize 1 the old root is the starting hash, so
/// before the fix a 31/33-byte old root (or path element) plus newRoot = H(0x01 || a || b) verified (fail-open forgery).</summary>
public class ConsistencyNodeLengthTests
{
    static string B64u(byte[] b) => Convert.ToBase64String(b).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    static byte[] Bytes(int n, byte fill) => Enumerable.Repeat(fill, n).ToArray();
    static string Node(byte[] l, byte[] r) => B64u(SHA256.HashData(new byte[] { 0x01 }.Concat(l).Concat(r).ToArray()));
    static D Proof(string pathElem) => (D)Pca.ParseStrict($"{{\"oldSize\":1,\"newSize\":2,\"path\":[\"{pathElem}\"]}}")!;

    [Theory]
    [InlineData(31, true)] [InlineData(33, true)] [InlineData(32, true)] [InlineData(32, false)]
    [InlineData(31, false)] [InlineData(33, false)]
    public void BadLengthOldRootOrPathElementIsRefused(int len, bool badIsOldRoot)
    {
        var bad = Bytes(len, 0xab);
        var c = Bytes(32, 0x5c);
        var (oldR, elem, newR) = badIsOldRoot ? (B64u(bad), B64u(c), Node(bad, c)) : (B64u(c), B64u(bad), Node(c, bad));
        Assert.Equal(len == 32, Ledger.VerifyLedgerConsistency(oldR, newR, Proof(elem)));
    }

    [Theory]
    [InlineData(31, true)] [InlineData(33, true)] [InlineData(32, true)]
    [InlineData(31, false)] [InlineData(33, false)] [InlineData(32, false)]
    public void MeshCopyRefusesBadLengthNodesToo(int len, bool badIsOldRoot)
    {
        var bad = Bytes(len, 0xab);
        var c = Bytes(32, 0x5c);
        var (oldR, elem, newR) = badIsOldRoot ? (B64u(bad), B64u(c), Node(bad, c)) : (B64u(c), B64u(bad), Node(c, bad));
        var m = typeof(Mesh).GetMethod("Consistency", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static)!;
        Assert.Equal(len == 32, (bool)m.Invoke(null, new object?[] { oldR, newR, Proof(elem) })!);
    }
}

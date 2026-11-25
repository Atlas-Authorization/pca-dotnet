using System.Numerics;
using System.Globalization;
using AtlasPca.Bbs;
using BbsLib = AtlasPca.Bbs.Bbs; // the class shares its name with its namespace
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Replays the TypeScript-reference corpus (test-data/ref-bbs.json.gz) through the native BBS port.</summary>
public class RefBbsTests
{
    const string M = "ref-bbs";

    // the corpus carries {"$bbssk": n} for KeyGen(32 bytes of n, empty key info): installed before the first corpus read of this class
    // (a module initializer, not a static constructor: another test class may load the ref-bbs corpus first, and the placeholders are resolved as it loads)
    [System.Runtime.CompilerServices.ModuleInitializer]
    internal static void InstallBbsSecretKey() { Base.BbsSecretKey = n => Hex(BbsLib.KeyGen(Enumerable.Repeat((byte)n, 32).ToArray(), Array.Empty<byte>())); }

    static BigInteger Unhex(object? s) => BigInteger.Parse("0" + (string)s!, NumberStyles.HexNumber, CultureInfo.InvariantCulture);
    static string Hex(BigInteger n) => n.ToString("x64", CultureInfo.InvariantCulture);
    static List<byte[]> BytesList(object? o) => ((L)o!).Select(Base.Bytes).ToList();
    static List<int> Ints(object? o) => ((L)o!).Select(x => x == null ? int.MinValue : (int)Base.Long(x)).ToList(); // a JSON null is no valid index: it only has to count
    static object Result(BbsLib.Result r) { var o = new D { ["ok"] = r.Ok }; if (!r.Ok) o["reason"] = r.Reason; return o; }

    [Fact] public void HashToScalar() => Base.Check(M, "hashToScalar", a => Hex(BbsLib.HashToScalar(Base.Bytes(a[0]), (string)a[1]!)));
    [Fact] public void MapMessageToScalarAsHash() => Base.Check(M, "mapMessageToScalarAsHash", a => Hex(BbsLib.MapMessageToScalarAsHash(Base.Bytes(a[0]))));
    [Fact] public void CreateGenerators() => Base.Check(M, "createGenerators", a => BbsLib.CreateGenerators((int)Base.Long(a[0])));
    [Fact] public void KeyGen() => Base.Check(M, "keyGen", a => Hex(BbsLib.KeyGen(Base.Bytes(a[0]), Base.Bytes(a[1]))));
    [Fact] public void SkToPk() => Base.Check(M, "skToPk", a => BbsLib.SkToPk(Unhex(a[0])));
    [Fact] public void Sign() => Base.Check(M, "sign", a => BbsLib.Sign(Unhex(a[0]), Base.Bytes(a[1]), Base.Bytes(a[2]), BytesList(a[3])));
    [Fact] public void VerifyDetailed() => Base.Check(M, "verifyDetailed", a => Result(BbsLib.VerifyDetailed(Base.Bytes(a[0]), Base.Bytes(a[1]), Base.Bytes(a[2]), BytesList(a[3]))));

    [Fact]
    public void ProofGen() => Base.Check(M, "proofGen", a =>
        BbsLib.ProofGen(Base.Bytes(a[0]), Base.Bytes(a[1]), Base.Bytes(a[2]), Base.Bytes(a[3]), BytesList(a[4]), Ints(a[5]), ((L)a[6]!).Select(Unhex).ToList()));

    [Fact]
    public void ProofVerifyDetailed() => Base.Check(M, "proofVerifyDetailed", a =>
        Result(BbsLib.ProofVerifyDetailed(Base.Bytes(a[0]), Base.Bytes(a[1]), Base.Bytes(a[2]), Base.Bytes(a[3]), BytesList(a[4]), Ints(a[5]))));

    [Fact] public void CapabilityAttributes() => Base.Check(M, "capabilityAttributes", a => BbsCredential.CapabilityAttributes((D)a[0]!));

    [Fact]
    public void IssueCapabilityCredential() => Base.Check(M, "issueCapabilityCredential", a =>
        BbsCredential.IssueCapabilityCredential((D)a[0]!, Unhex(a[1]), Base.Bytes(a[2]), Base.Bytes(a[3])));

    [Fact] public void VerifyCredential() => Base.Check(M, "verifyCredential", a => BbsCredential.VerifyCredential((D)a[0]!));

    [Fact]
    public void VerifyPresentation() => Base.Check(M, "verifyPresentation", a =>
    {
        var opts = (D)a[1]!;
        return BbsCredential.VerifyPresentation((D)a[0]!,
            opts.ContainsKey("pk") ? Base.Bytes(opts["pk"]) : null,
            opts.ContainsKey("disclosed") ? (L)opts["disclosed"]! : null,
            opts.ContainsKey("presentationHeader") ? Base.Bytes(opts["presentationHeader"]) : null);
    });

    /// <summary>Presentation round trip through the randomized PresentCredential.</summary>
    [Fact]
    public void PresentRoundTrip()
    {
        var sk = BbsLib.KeyGen(new byte[32]);
        var pk = BbsLib.SkToPk(sk);
        var cap = new D { ["issuer"] = "i", ["holder"] = "h", ["caveats"] = new L { new D { ["type"] = "amount" } } };
        var cred = BbsCredential.IssueCapabilityCredential(cap, sk, pk, null);
        Assert.True(BbsCredential.VerifyCredential(cred));
        var pres = BbsCredential.PresentCredential(cred, new[] { "iss" }, new byte[] { 1 });
        Assert.True(BbsCredential.VerifyPresentation(pres, null, null, null));
        Assert.True(BbsCredential.VerifyPresentation(pres, pk, null, new byte[] { 1 }));
        Assert.False(BbsCredential.VerifyPresentation(pres, null, null, new byte[] { 2 }));
        Assert.Throws<ArgumentException>(() => BbsCredential.PresentCredential(cred, new[] { "nope" }, null));
    }

    [Fact]
    public void CoversEveryFn() { Base.Covers(M, new[]
    {
        "hashToScalar", "mapMessageToScalarAsHash", "createGenerators", "keyGen", "skToPk", "sign", "verifyDetailed", "proofGen",
        "proofVerifyDetailed", "capabilityAttributes", "issueCapabilityCredential", "verifyCredential", "verifyPresentation",
    }); Assert.Equal(278, Base.Total(M)); }
}

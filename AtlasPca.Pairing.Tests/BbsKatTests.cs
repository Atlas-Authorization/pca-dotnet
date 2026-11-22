using System.Globalization;
using System.Numerics;
using System.Text;
using AtlasPca.Bbs;
using BbsLib = AtlasPca.Bbs.Bbs; // the class shares its name with its namespace
using AtlasPca.Pairing;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>
/// The official fixtures of draft-irtf-cfrg-bbs-signatures (ciphersuite BLS12-381-SHA-256; byte-identical across draft revisions
/// -06 through -12), vendored in test-data with provenance, plus the RFC 9380 expand_message_xmd vector.
/// </summary>
public class BbsKatTests
{
    static D Load(string rel) => (D)FixtureJson.Parse(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "test-data", "draft-irtf-cfrg-bbs-signatures", "bls12-381-sha-256", rel), Encoding.UTF8))!;
    static byte[] H(object? s) => Convert.FromHexString((string)s!);
    static string Hx(byte[] b) => Convert.ToHexString(b).ToLowerInvariant();
    static List<byte[]> Hs(object? list) => ((L)list!).Select(H).ToList();
    static List<int> Ints(object? list) => ((L)list!).Select(o => int.Parse(((Num)o!).Raw, CultureInfo.InvariantCulture)).ToList();
    static BigInteger Unhex(object? s) => BigInteger.Parse("0" + (string)s!, NumberStyles.HexNumber, CultureInfo.InvariantCulture);

    [Fact]
    public void ExpandMessageXmdRfc9380() =>
        Assert.Equal("68a985b87eb6b46952128911f2a4412bbc302a9d759667f87f7a21d803f07235",
            Hx(Bls12.ExpandMessageXmd(Array.Empty<byte>(), Encoding.ASCII.GetBytes("QUUX-V01-CS02-with-expander-SHA256-128"), 0x20)));

    [Fact]
    public void KeyGenAndSkToPk()
    {
        var k = Load("keypair.json");
        var sk = BbsLib.KeyGen(H(k["keyMaterial"]), H(k["keyInfo"]));
        var kp = (D)k["keyPair"]!;
        Assert.Equal(kp["secretKey"], Hx(BbsLib.SkToBytes(sk)));
        Assert.Equal(kp["publicKey"], Hx(BbsLib.SkToPk(sk)));
    }

    [Fact]
    public void HashToScalar()
    {
        var f = Load("h2s.json");
        Assert.Equal(f["scalar"], Hx(Bls12.I2osp(BbsLib.HashToScalar(H(f["message"]), Encoding.ASCII.GetString(H(f["dst"]))), 32)));
    }

    [Fact]
    public void MapMessageToScalar()
    {
        foreach (var c in (L)Load("MapMessageToScalarAsHash.json")["cases"]!)
        {
            var m = (D)c!;
            Assert.Equal(m["scalar"], Hx(Bls12.I2osp(BbsLib.MapMessageToScalarAsHash(H(m["message"])), 32)));
        }
    }

    [Fact]
    public void CreateGenerators()
    {
        var f = Load("generators.json");
        var msg = (L)f["MsgGenerators"]!;
        var gens = BbsLib.CreateGenerators(msg.Count + 1);
        Assert.Equal(f["Q1"], Hx(gens[0]));
        for (int i = 0; i < msg.Count; i++) Assert.Equal(msg[i], Hx(gens[i + 1]));
    }

    [Fact]
    public void SignAndVerify()
    {
        for (int i = 1; i <= 10; i++)
        {
            var f = Load($"signature/signature{i:000}.json");
            var msgs = Hs(f["messages"]);
            var kp = (D)f["signerKeyPair"]!;
            var pk = H(kp["publicKey"]);
            var r = BbsLib.VerifyDetailed(pk, H(f["signature"]), H(f["header"]), msgs);
            var name = (string)f["caseName"]!;
            if (((D)f["result"]!)["valid"] is true)
            {
                Assert.True(r.Ok, name);
                Assert.Equal(H(f["signature"]), BbsLib.Sign(Unhex(kp["secretKey"]), pk, H(f["header"]), msgs));
            }
            else
            {
                Assert.False(r.Ok, name);
                Assert.Equal(BbsLib.PairingMismatch, r.Reason);
            }
        }
    }

    [Fact]
    public void ProofGenAndVerify()
    {
        for (int i = 1; i <= 15; i++)
        {
            var f = Load($"proof/proof{i:000}.json");
            var name = (string)f["caseName"]!;
            var msgs = Hs(f["messages"]);
            var idx = Ints(f["disclosedIndexes"]);
            var disclosed = idx.Select(k => k >= 0 && k < msgs.Count ? msgs[k] : Array.Empty<byte>()).ToList();
            var pk = H(f["signerPublicKey"]);
            var r = BbsLib.ProofVerifyDetailed(pk, H(f["proof"]), H(f["header"]), H(f["presentationHeader"]), disclosed, idx);
            if (((D)f["result"]!)["valid"] is true)
            {
                Assert.True(r.Ok, name);
                var rs = (D)((D)f["trace"]!)["random_scalars"]!;
                var scalars = new[] { "r1", "r2", "e_tilde", "r1_tilde", "r3_tilde" }.Select(key => Unhex(rs[key])).ToList();
                scalars.AddRange(((L)rs["m_tilde_scalars"]!).Select(Unhex));
                var regen = BbsLib.ProofGen(pk, H(f["signature"]), H(f["header"]), H(f["presentationHeader"]), msgs, idx, scalars);
                Assert.Equal(f["proof"], Hx(regen));
            }
            else Assert.False(r.Ok, name);
        }
    }

    [Fact]
    public void RandomizedProofVerifiesAndTamperingFails()
    {
        var f = Load("signature/signature004.json");
        var msgs = Hs(f["messages"]);
        var pk = H(((D)f["signerKeyPair"]!)["publicKey"]);
        var hdr = H(f["header"]);
        var ph = new byte[] { 1, 2, 3 };
        var idx = new List<int> { 0, 2 };
        var proof = BbsLib.ProofGen(pk, H(f["signature"]), hdr, ph, msgs, idx);
        var dis = new List<byte[]> { msgs[0], msgs[2] };
        Assert.True(BbsLib.ProofVerify(pk, proof, hdr, ph, dis, idx));
        Assert.False(BbsLib.ProofVerify(pk, proof, hdr, new byte[] { 9 }, dis, idx));
        Assert.False(BbsLib.ProofVerify(pk, proof, hdr, ph, new List<byte[]> { msgs[0], msgs[1] }, idx));
        var bad = (byte[])proof.Clone();
        bad[^1] ^= 1;
        Assert.False(BbsLib.ProofVerify(pk, bad, hdr, ph, dis, idx));
        // two proofs of one signature differ (unlinkability)
        Assert.NotEqual(proof, BbsLib.ProofGen(pk, H(f["signature"]), hdr, ph, msgs, idx));
    }
}

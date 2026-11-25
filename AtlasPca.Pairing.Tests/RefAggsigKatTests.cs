using System.Text.Json;
using System.Text.RegularExpressions;
using AtlasPca.Aggsig;
using Xunit;
using Ag = AtlasPca.Aggsig.Aggsig;

namespace AtlasPca.Pairing.Tests;

/// <summary>
/// Community-standard BLS12-381 vectors (ethereum/bls12-381-tests v0.1.2) for the PoP ciphersuite
/// BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_ (draft-irtf-cfrg-bls-signature has no vectors of its own), vendored in test-data
/// with provenance. The same fixtures the TypeScript package replays.
/// </summary>
public class RefAggsigKatTests
{
    static readonly string Root = Path.Combine(AppContext.BaseDirectory, "test-data", "ethereum-bls12-381-tests-v0.1.2");

    static byte[] H(string s) => Convert.FromHexString(s.StartsWith("0x", StringComparison.Ordinal) ? s[2..] : s);

    sealed record Case(string Name, JsonElement Input, JsonElement Output);

    static List<Case> Cases(string dir)
    {
        var files = Directory.GetFiles(Path.Combine(Root, dir)).OrderBy(f => f, StringComparer.Ordinal).ToList();
        var outp = new List<Case>();
        foreach (var f in files)
        {
            using var doc = JsonDocument.Parse(File.ReadAllText(f));
            outp.Add(new Case(Path.GetFileName(f), doc.RootElement.GetProperty("input").Clone(), doc.RootElement.GetProperty("output").Clone()));
        }
        Assert.NotEmpty(outp);
        return outp;
    }

    static List<byte[]> Hs(JsonElement list) => list.EnumerateArray().Select(e => H(e.GetString()!)).ToList();

    [Fact]
    public void Sign()
    {
        foreach (var c in Cases("sign"))
        {
            var sk = H(c.Input.GetProperty("privkey").GetString()!);
            var msg = H(c.Input.GetProperty("message").GetString()!);
            if (c.Output.ValueKind == JsonValueKind.Null) Assert.ThrowsAny<System.Exception>(() => AggsigCore.Sign(sk, msg));
            else Assert.True(H(c.Output.GetString()!).AsSpan().SequenceEqual(AggsigCore.Sign(sk, msg)), c.Name);
        }
    }

    [Fact]
    public void Verify()
    {
        foreach (var c in Cases("verify"))
        {
            var i = c.Input;
            var got = AggsigCore.Verify(H(i.GetProperty("pubkey").GetString()!), H(i.GetProperty("message").GetString()!), H(i.GetProperty("signature").GetString()!));
            Assert.True(c.Output.GetBoolean() == got, c.Name);
        }
    }

    [Fact]
    public void Aggregate()
    {
        foreach (var c in Cases("aggregate"))
        {
            var sigs = Hs(c.Input);
            if (c.Output.ValueKind == JsonValueKind.Null) Assert.Throws<ArgumentException>(() => AggsigCore.Aggregate(sigs));
            else Assert.True(H(c.Output.GetString()!).AsSpan().SequenceEqual(AggsigCore.Aggregate(sigs)), c.Name);
        }
    }

    [Fact]
    public void FastAggregateVerify()
    {
        foreach (var c in Cases("fast_aggregate_verify"))
        {
            var i = c.Input;
            var got = AggsigCore.FastAggregateVerify(Hs(i.GetProperty("pubkeys")), H(i.GetProperty("message").GetString()!), H(i.GetProperty("signature").GetString()!));
            Assert.True(c.Output.GetBoolean() == got, c.Name);
        }
    }

    [Fact]
    public void AggregateVerify()
    {
        foreach (var c in Cases("aggregate_verify"))
        {
            var i = c.Input;
            var got = AggsigCore.AggregateVerify(Hs(i.GetProperty("pubkeys")), Hs(i.GetProperty("messages")), H(i.GetProperty("signature").GetString()!));
            Assert.True(c.Output.GetBoolean() == got, c.Name);
        }
    }

    /// <summary>The fixtures test decoding + subgroup; KeyValidate additionally rejects the identity (draft 2.5).</summary>
    [Fact]
    public void KeyValidate()
    {
        foreach (var c in Cases("deserialization_G1"))
        {
            var pk = c.Input.GetProperty("pubkey").GetString()!;
            var inf = Regex.IsMatch(pk, "^c0+$");
            Assert.True((c.Output.GetBoolean() && !inf) == AggsigCore.KeyValidate(H(pk)), c.Name);
        }
    }

    [Fact]
    public void MalformedSignaturesNeverVerify()
    {
        var pk = H("a491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a");
        foreach (var c in Cases("deserialization_G2"))
            Assert.False(AggsigCore.Verify(pk, new byte[32], H(c.Input.GetProperty("signature").GetString()!)), c.Name);
    }

    [Fact]
    public void PopAndRogueKey()
    {
        var sk1 = H("263dbd792f5b1be47ed85f8938c0f29586af0d3ac7b977f21c278fe1462040e3");
        var sk2 = H("47b8192d77bf871b62e87859d653922725724a5c031afeabc60bcef5ff665138");
        var pk1 = AggsigCore.PublicKeyOf(sk1);
        var pk2 = AggsigCore.PublicKeyOf(sk2);
        var pop1 = AggsigCore.PopProve(sk1);
        Assert.True(AggsigCore.PopVerify(pk1, pop1));
        Assert.False(AggsigCore.PopVerify(pk2, pop1));
        // domain separation both ways
        Assert.False(AggsigCore.PopVerify(pk1, AggsigCore.Sign(sk1, pk1)));
        Assert.False(AggsigCore.Verify(pk1, pk1, pop1));
        // the public API admits only a verified proof of possession
        Assert.True(Ag.RegisterKey(pk1, pop1).Ok);
        Assert.False(Ag.RegisterKey(pk2, pop1).Ok);
        var reg = new KeyRegistry();
        Assert.True(reg.Register(pk1, pop1).Ok);
        Assert.True(reg.Has(pk1));
        Assert.False(reg.Has(pk2));
        // one signer cannot be counted twice
        var msg = new byte[32];
        var s = Ag.Sign(sk1, msg);
        var k = reg.Get(pk1);
        Assert.True(Ag.FastAggregateVerify(new List<RegisteredKey?> { k }, msg, s));
        Assert.False(Ag.FastAggregateVerify(new List<RegisteredKey?> { k, k, k }, msg, Ag.Aggregate(new List<byte[]> { s, s, s })));
    }
}

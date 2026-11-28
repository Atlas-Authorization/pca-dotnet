using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Digests;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Differential replay of the KEM module against the reference (test-data/ref-kem.json.gz, 464 cases): the hybrid X25519 + ML-KEM-768 / -1024 KEM, X-Wing
/// (with the three draft-09 vectors), the wire encodings and the FIPS 203 key checks. The reference's random draws are pinned by the corpus and fed to the
/// derandomized entry points in the reference's draw order; the random public calls are covered by the round trips below.</summary>
public class RefKemTests
{
    const string M = "ref-kem";

    /// <summary>{"$bytes"} as bytes; null (and any other JSON value) as null.</summary>
    static byte[]? B(object? a) => a is D d && Base.IsBytes(d) ? Base.Bytes(d) : null;

    /// <summary>The pinned random stream: one {"$bytes"} or a list of parts to concatenate; null stays null.</summary>
    static byte[]? Rng(object? a) => a is L l ? l.SelectMany(p => Base.Bytes(p)).ToArray() : B(a);

    static int Level(object? v) => v is string s ? int.Parse(s, System.Globalization.CultureInfo.InvariantCulture) : (int)(IntentJs.NumOf(v) ?? throw new ArgumentException("level"));

    static byte[] Sha3(byte[] data)
    {
        var d = new Sha3Digest(256);
        d.BlockUpdate(data, 0, data.Length);
        var o = new byte[32];
        d.DoFinal(o, 0);
        return o;
    }

    static void Patch(byte[] k, D spec)
    {
        if (spec.GetValueOrDefault("set") is L set)
            foreach (var e in set) { var p = (L)e!; k[(int)Base.Long(p[0])] = (byte)Base.Long(p[1]); }
    }

    /// <summary>A key argument: {"$bytes"}, {"$hybridSk": {level, x, d, z, trim?, pad?, set?}} = x || expanded dk of d || z (then trimmed, padded, patched), or
    /// {"$mlkemDk": {level, d, z, set?, rehash?}} = the expanded dk (patched; rehash rewrites the embedded H(ek) over the patched embedded ek). Anything else is null.</summary>
    static byte[]? Key(object? a)
    {
        if (a is not D d) return null;
        if (d.GetValueOrDefault("$hybridSk") is D h)
        {
            var dk = MlKemBc.Keygen(Level(h["level"]), B(h["d"])!.Concat(B(h["z"])!).ToArray()).Dk;
            var sk = B(h["x"])!.Concat(dk).ToArray();
            if (h.ContainsKey("trim")) sk = sk[..(sk.Length - (int)Base.Long(h["trim"]))];
            if (h.ContainsKey("pad")) sk = sk.Concat(new byte[(int)Base.Long(h["pad"])]).ToArray();
            Patch(sk, h);
            return sk;
        }
        if (d.GetValueOrDefault("$mlkemDk") is D m)
        {
            int level = Level(m["level"]), k = level == 768 ? 3 : 4;
            var dk = MlKemBc.Keygen(level, B(m["d"])!.Concat(B(m["z"])!).ToArray()).Dk;
            Patch(dk, m);
            if (m.GetValueOrDefault("rehash") is true) Sha3(dk[(384 * k)..(768 * k + 32)]).CopyTo(dk, 768 * k + 32);
            return dk;
        }
        return B(a);
    }

    static D KeyOut(byte[] publicKey, byte[] secretKey) => new()
    {
        ["publicKey"] = publicKey, ["secretKeySha256"] = Convert.ToHexString(SHA256.HashData(secretKey)).ToLowerInvariant(), ["secretKeyLen"] = secretKey.Length,
    };

    static D EncOut(byte[] ciphertext, byte[] sharedSecret) => new() { ["ciphertext"] = ciphertext, ["sharedSecret"] = sharedSecret };

    [Fact]
    public void Constants() => Base.Check(M, "constants", _ => new D
    {
        ["HYBRID_PUBLIC_KEY_LEN"] = Kem.HybridPublicKeyLen, ["HYBRID_CIPHERTEXT_LEN"] = Kem.HybridCiphertextLen, ["HYBRID_SHARED_SECRET_LEN"] = Kem.HybridSharedSecretLen,
        ["HYBRID_KEM_SUITE"] = Kem.HybridKemSuite, ["XWING_SUITE"] = Kem.XWingSuite, ["XWING_SEED_LEN"] = Kem.XWingSeedLen, ["XWING_SECRET_KEY_LEN"] = Kem.XWingSecretKeyLen,
        ["XWING_PUBLIC_KEY_LEN"] = Kem.XWingPublicKeyLen, ["XWING_CIPHERTEXT_LEN"] = Kem.XWingCiphertextLen, ["XWING_SHARED_SECRET_LEN"] = Kem.XWingSharedSecretLen,
        ["XWING_ESEED_LEN"] = Kem.XWingEseedLen, ["XWING_LABEL"] = Kem.XWingLabel, ["HYBRID1024_PUBLIC_KEY_LEN"] = Kem.Hybrid1024PublicKeyLen,
        ["HYBRID1024_CIPHERTEXT_LEN"] = Kem.Hybrid1024CiphertextLen, ["HYBRID1024_SHARED_SECRET_LEN"] = Kem.Hybrid1024SharedSecretLen, ["HYBRID1024_KEM_SUITE"] = Kem.Hybrid1024KemSuite,
    });

    // keygen stream: X25519 secret (32) || d (32) || z (32)
    static object? Keygen(int level, L a)
    {
        var r = Rng(a[0])!;
        var kp = Kem.KeygenDerand(level, r[..32], r[32..]);
        return KeyOut(kp.PublicKey, kp.SecretKey);
    }

    // encapsulation stream: ephemeral X25519 secret (32) || m (32)
    static object? Encapsulate(int level, L a)
    {
        var r = Rng(a[1])!;
        var e = Kem.EncapsulateDerand(level, B(a[0])!, r[..32], r[32..], "encapsulate");
        return EncOut(e.Ciphertext, e.SharedSecret);
    }

    [Fact] public void HybridKemKeygen() => Base.Check(M, "hybridKemKeygen", a => Keygen(768, a), min: 5);
    [Fact] public void HybridKem1024Keygen() => Base.Check(M, "hybridKem1024Keygen", a => Keygen(1024, a), min: 5);
    [Fact] public void HybridEncapsulate() => Base.Check(M, "hybridEncapsulate", a => Encapsulate(768, a), min: 22);
    [Fact] public void HybridEncapsulate1024() => Base.Check(M, "hybridEncapsulate1024", a => Encapsulate(1024, a), min: 22);
    [Fact] public void HybridDecapsulate() => Base.Check(M, "hybridDecapsulate", a => Kem.HybridDecapsulate(B(a[0])!, Key(a[1])!), min: 29);
    [Fact] public void HybridDecapsulate1024() => Base.Check(M, "hybridDecapsulate1024", a => Kem.HybridDecapsulate1024(B(a[0])!, Key(a[1])!), min: 29);

    [Fact]
    public void XWingKeygen() => Base.Check(M, "xwingKeygen", a =>
    {
        var kp = Kem.XWingKeygen(B(a[0]) ?? throw new ArgumentNullException("seed"));
        return KeyOut(kp.PublicKey, kp.SecretKey);
    }, min: 12);

    static object? XWingEnc(L a)
    {
        var e = Kem.XWingEncapsulateDerand(B(a[0])!, Rng(a[1])!);
        return EncOut(e.Ciphertext, e.SharedSecret);
    }

    [Fact] public void XWingEncapsulateDerand() => Base.Check(M, "xwingEncapsulateDerand", XWingEnc, min: 29);
    [Fact] public void XWingEncapsulate() => Base.Check(M, "xwingEncapsulate", XWingEnc, min: 12);
    [Fact] public void XWingDecapsulate() => Base.Check(M, "xwingDecapsulate", a => Kem.XWingDecapsulate(B(a[0])!, B(a[1])!), min: 30);

    [Fact]
    public void Encodings()
    {
        Base.Check(M, "encodeHybridPublicKey", a => Kem.EncodeHybridPublicKey(B(a[0])!), min: 9);
        Base.Check(M, "encodeHybridCiphertext", a => Kem.EncodeHybridCiphertext(B(a[0])!), min: 9);
        Base.Check(M, "encodeXWingPublicKey", a => Kem.EncodeXWingPublicKey(B(a[0])!), min: 9);
        Base.Check(M, "encodeXWingCiphertext", a => Kem.EncodeXWingCiphertext(B(a[0])!), min: 9);
        Base.Check(M, "decodeHybridPublicKey", a => Kem.DecodeHybridPublicKey((string)a[0]!), min: 36);
        Base.Check(M, "decodeHybridCiphertext", a => Kem.DecodeHybridCiphertext((string)a[0]!), min: 36);
        Base.Check(M, "decodeXWingPublicKey", a => Kem.DecodeXWingPublicKey((string)a[0]!), min: 36);
        Base.Check(M, "decodeXWingCiphertext", a => Kem.DecodeXWingCiphertext((string)a[0]!), min: 36);
    }

    [Fact] public void MlKemEncapsulationKeyCheck() => Base.Check(M, "mlKemEncapsulationKeyCheck", a => Kem.MlKemEncapsulationKeyCheck(Level(a[0]), Key(a[1])), min: 45);
    [Fact] public void MlKemDecapsulationKeyCheck() => Base.Check(M, "mlKemDecapsulationKeyCheck", a => Kem.MlKemDecapsulationKeyCheck(Level(a[0]), Key(a[1])), min: 43);

    [Fact]
    public void Covers()
    {
        Base.Covers(M, new[]
        {
            "constants", "hybridKemKeygen", "hybridKem1024Keygen", "hybridEncapsulate", "hybridEncapsulate1024", "hybridDecapsulate", "hybridDecapsulate1024", "xwingKeygen",
            "xwingEncapsulateDerand", "xwingEncapsulate", "xwingDecapsulate", "encodeHybridPublicKey", "encodeHybridCiphertext", "encodeXWingPublicKey", "encodeXWingCiphertext",
            "decodeHybridPublicKey", "decodeHybridCiphertext", "decodeXWingPublicKey", "decodeXWingCiphertext", "mlKemEncapsulationKeyCheck", "mlKemDecapsulationKeyCheck",
        });
        Assert.Equal(464, Base.Cases(M).Count);
    }

    // ---- the random public calls: both sides agree, two calls differ, a tampered ciphertext gives another secret ----

    [Fact]
    public void TheRandomHybridCallsRoundTrip()
    {
        var kp = Kem.HybridKemKeygen();
        Assert.Equal(Kem.HybridPublicKeyLen, kp.PublicKey.Length);
        Assert.Equal(2432, kp.SecretKey.Length);
        Assert.NotEqual(kp.PublicKey, Kem.HybridKemKeygen().PublicKey);
        var e = Kem.HybridEncapsulate(kp.PublicKey);
        Assert.Equal(Kem.HybridCiphertextLen, e.Ciphertext.Length);
        Assert.Equal(Kem.HybridSharedSecretLen, e.SharedSecret.Length);
        Assert.Equal(e.SharedSecret, Kem.HybridDecapsulate(e.Ciphertext, kp.SecretKey));
        Assert.NotEqual(e.Ciphertext, Kem.HybridEncapsulate(kp.PublicKey).Ciphertext);
        var bad = (byte[])e.Ciphertext.Clone();
        bad[^1] ^= 1;
        Assert.NotEqual(e.SharedSecret, Kem.HybridDecapsulate(bad, kp.SecretKey));
        Assert.True(Kem.MlKemEncapsulationKeyCheck(768, kp.PublicKey[32..]));
        Assert.True(Kem.MlKemDecapsulationKeyCheck(768, kp.SecretKey[32..]));
        Assert.Equal(kp.PublicKey, Kem.DecodeHybridPublicKey(Kem.EncodeHybridPublicKey(kp.PublicKey)));
        Assert.Equal(e.Ciphertext, Kem.DecodeHybridCiphertext(Kem.EncodeHybridCiphertext(e.Ciphertext)));
        // the two levels never mix
        var kp1024 = Kem.HybridKem1024Keygen();
        Assert.ThrowsAny<ArgumentException>(() => Kem.HybridEncapsulate(kp1024.PublicKey));
        Assert.ThrowsAny<ArgumentException>(() => Kem.HybridDecapsulate(e.Ciphertext, kp1024.SecretKey));
        Assert.ThrowsAny<ArgumentException>(() => Kem.HybridEncapsulate(null!));
    }

    [Fact]
    public void TheRandomHybrid1024CallsRoundTrip()
    {
        var kp = Kem.HybridKem1024Keygen();
        Assert.Equal(Kem.Hybrid1024PublicKeyLen, kp.PublicKey.Length);
        Assert.Equal(3200, kp.SecretKey.Length);
        Assert.NotEqual(kp.PublicKey, Kem.HybridKem1024Keygen().PublicKey);
        var e = Kem.HybridEncapsulate1024(kp.PublicKey);
        Assert.Equal(Kem.Hybrid1024CiphertextLen, e.Ciphertext.Length);
        Assert.Equal(Kem.Hybrid1024SharedSecretLen, e.SharedSecret.Length);
        Assert.Equal(e.SharedSecret, Kem.HybridDecapsulate1024(e.Ciphertext, kp.SecretKey));
        Assert.NotEqual(e.Ciphertext, Kem.HybridEncapsulate1024(kp.PublicKey).Ciphertext);
        Assert.True(Kem.MlKemEncapsulationKeyCheck(1024, kp.PublicKey[32..]));
        Assert.True(Kem.MlKemDecapsulationKeyCheck(1024, kp.SecretKey[32..]));
        Assert.False(Kem.MlKemDecapsulationKeyCheck(768, kp.SecretKey[32..]));
    }

    [Fact]
    public void TheRandomXWingCallsRoundTrip()
    {
        var kp = Kem.XWingKeygen();
        Assert.Equal(Kem.XWingSecretKeyLen, kp.SecretKey.Length);
        Assert.Equal(Kem.XWingPublicKeyLen, kp.PublicKey.Length);
        Assert.NotEqual(kp.SecretKey, Kem.XWingKeygen().SecretKey);
        Assert.Equal(kp.PublicKey, Kem.XWingKeygen(kp.SecretKey).PublicKey);
        var e = Kem.XWingEncapsulate(kp.PublicKey);
        Assert.Equal(Kem.XWingCiphertextLen, e.Ciphertext.Length);
        Assert.Equal(Kem.XWingSharedSecretLen, e.SharedSecret.Length);
        Assert.Equal(e.SharedSecret, Kem.XWingDecapsulate(e.Ciphertext, kp.SecretKey));
        Assert.NotEqual(e.Ciphertext, Kem.XWingEncapsulate(kp.PublicKey).Ciphertext);
        // the returned secret key is a copy of the caller's seed
        var seed = new byte[32];
        var fromSeed = Kem.XWingKeygen(seed);
        seed[0] = 1;
        Assert.Equal(new byte[32], fromSeed.SecretKey);
        Assert.Equal(kp.PublicKey, Kem.DecodeXWingPublicKey(Kem.EncodeXWingPublicKey(kp.PublicKey)));
        Assert.Equal(e.Ciphertext, Kem.DecodeXWingCiphertext(Kem.EncodeXWingCiphertext(e.Ciphertext)));
        Assert.Equal(new byte[] { 0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c }, Kem.XWingLabel);
        Assert.NotSame(Kem.XWingLabel, Kem.XWingLabel);
    }
}

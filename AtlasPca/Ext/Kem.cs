// Key encapsulation (the reference kem module): the hybrid X25519 + ML-KEM-768 KEM and its ML-KEM-1024 variant (HKDF-SHA256 combiner), X-Wing
// (draft-connolly-cfrg-xwing-kem-09, SHA3-256 combiner) and the FIPS 203 section 7.2 / 7.3 checks for imported ML-KEM keys. Every primitive is a library
// one: ML-KEM, X25519, SHA3-256 and SHAKE256 are BouncyCastle, HKDF is the platform's. All three KEMs establish a 32-byte shared secret; no cipher is here.
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Kems;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using BcX25519 = Org.BouncyCastle.Math.EC.Rfc7748.X25519;

namespace AtlasPca;

/// <summary>A hybrid key pair. PublicKey = X25519 public (32) || ML-KEM encapsulation key; SecretKey = X25519 secret (32) || ML-KEM expanded decapsulation key.</summary>
public sealed record HybridKemKeyPair(byte[] PublicKey, byte[] SecretKey);

/// <summary>A hybrid encapsulation. Ciphertext = ephemeral X25519 public (32) || ML-KEM ciphertext; SharedSecret is 32 bytes.</summary>
public sealed record HybridEncapsulation(byte[] Ciphertext, byte[] SharedSecret);

/// <summary>An X-Wing key pair. SecretKey is the 32-byte seed; PublicKey = ML-KEM-768 encapsulation key (1184) || X25519 public (32).</summary>
public sealed record XWingKeyPair(byte[] SecretKey, byte[] PublicKey);

/// <summary>An X-Wing encapsulation. Ciphertext = ML-KEM-768 ciphertext (1088) || ephemeral X25519 public (32); SharedSecret is 32 bytes.</summary>
public sealed record XWingEncapsulation(byte[] Ciphertext, byte[] SharedSecret);

/// <summary>ML-KEM (FIPS 203) at level 768 or 1024 on BouncyCastle with caller-supplied randomness: key generation from the 64-byte seed d || z, encapsulation
/// from the 32-byte message m, decapsulation from the expanded decapsulation key.</summary>
internal static class MlKemBc
{
    /// <summary>A SecureRandom that replays fixed bytes in order.</summary>
    sealed class Replay : SecureRandom
    {
        readonly byte[] _data;
        int _at;

        internal Replay(byte[] data) { _data = (byte[])data.Clone(); }

        void Take(Span<byte> o)
        {
            if (_at + o.Length > _data.Length) throw new InvalidOperationException("ml-kem: randomness exhausted");
            _data.AsSpan(_at, o.Length).CopyTo(o);
            _at += o.Length;
        }

        public override void NextBytes(byte[] buf) { lock (_data) Take(buf); }
        public override void NextBytes(byte[] buf, int off, int len) { lock (_data) Take(buf.AsSpan(off, len)); }
        public override void NextBytes(Span<byte> buffer) { lock (_data) Take(buffer); }
    }

    internal static MLKemParameters Params(int level) => level switch
    {
        768 => MLKemParameters.ml_kem_768,
        1024 => MLKemParameters.ml_kem_1024,
        _ => throw new ArgumentException("ml-kem: the level must be 768 or 1024"),
    };

    /// <summary>The key of the seed d || z.</summary>
    internal static MLKemPrivateKeyParameters Key(int level, byte[] seed64)
    {
        if (seed64.Length != 64) throw new ArgumentException("ml-kem keygen: seed must be exactly 64 bytes");
        return MLKemPrivateKeyParameters.FromSeed(Params(level), seed64);
    }

    /// <summary>(encapsulation key, expanded decapsulation key) of the seed d || z.</summary>
    internal static (byte[] Ek, byte[] Dk) Keygen(int level, byte[] seed64)
    {
        var sk = Key(level, seed64);
        return (sk.GetPublicKeyEncoded(), sk.GetEncoded());
    }

    /// <summary>(ciphertext, shared secret) for the message <paramref name="m32"/>. Refuses a key of the wrong length or one that fails the modulus check.</summary>
    internal static (byte[] Ct, byte[] Ss) Encapsulate(int level, byte[] ek, byte[] m32)
    {
        if (m32.Length != 32) throw new ArgumentException("ml-kem encapsulate: message must be exactly 32 bytes");
        var p = Params(level);
        var enc = new MLKemEncapsulator(p);
        enc.Init(new ParametersWithRandom(MLKemPublicKeyParameters.FromEncoding(p, ek), new Replay(m32)));
        var ct = new byte[enc.EncapsulationLength];
        var ss = new byte[enc.SecretLength];
        enc.Encapsulate(ct, 0, ct.Length, ss, 0, ss.Length);
        return (ct, ss);
    }

    internal static byte[] Decapsulate(int level, byte[] ct, MLKemPrivateKeyParameters sk)
    {
        var dec = new MLKemDecapsulator(Params(level));
        dec.Init(sk);
        if (ct.Length != dec.EncapsulationLength) throw new ArgumentException("ml-kem decapsulate: wrong ciphertext length");
        var ss = new byte[dec.SecretLength];
        dec.Decapsulate(ct, 0, ct.Length, ss, 0, ss.Length);
        return ss;
    }

    /// <summary>Decapsulation from the expanded key (dkPKE || ek || H(ek) || z); refuses a key of the wrong length. A ciphertext that does not open yields the
    /// implicit-rejection secret, as FIPS 203 says.</summary>
    internal static byte[] Decapsulate(int level, byte[] ct, byte[] dk) => Decapsulate(level, ct, MLKemPrivateKeyParameters.FromEncoding(Params(level), dk));
}

public static class Kem
{
    const int XLen = 32, SsLen = 32, MlKem768PkLen = 1184, MlKem768CtLen = 1088, MlKem1024PkLen = 1568, MlKem1024CtLen = 1568;

    public const int HybridPublicKeyLen = XLen + MlKem768PkLen;
    public const int HybridCiphertextLen = XLen + MlKem768CtLen;
    public const int HybridSharedSecretLen = SsLen;
    public const string HybridKemSuite = "x25519-ml-kem-768";
    public const string XWingSuite = "xwing";
    public const int XWingSeedLen = 32;
    public const int XWingSecretKeyLen = XWingSeedLen;
    public const int XWingPublicKeyLen = MlKem768PkLen + XLen;
    public const int XWingCiphertextLen = MlKem768CtLen + XLen;
    public const int XWingSharedSecretLen = SsLen;
    public const int XWingEseedLen = 64;
    public const int Hybrid1024PublicKeyLen = XLen + MlKem1024PkLen;
    public const int Hybrid1024CiphertextLen = XLen + MlKem1024CtLen;
    public const int Hybrid1024SharedSecretLen = SsLen;
    public const string Hybrid1024KemSuite = "x25519-ml-kem-1024";

    /// <summary>The X-Wing combiner label, the six bytes <c>5c 2e 2f 2f 5e 5c</c> (a fresh copy per access).</summary>
    public static byte[] XWingLabel => new byte[] { 0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c };

    static byte[] Domain(int level) => System.Text.Encoding.ASCII.GetBytes(level == 768 ? "atlas-pca/kem/x25519-ml-kem-768/v1\0" : "atlas-pca/kem/x25519-ml-kem-1024/v1\0");

    static byte[] Cat(params byte[][] parts)
    {
        var o = new byte[parts.Sum(p => p.Length)];
        int at = 0;
        foreach (var p in parts) { p.CopyTo(o, at); at += p.Length; }
        return o;
    }

    static byte[] XPublic(byte[] secret)
    {
        var r = new byte[XLen];
        BcX25519.ScalarMultBase(secret, 0, r, 0);
        return r;
    }

    /// <summary>X25519(secret, peer); an all-zero result (a low-order peer point) is refused.</summary>
    static byte[] XShared(byte[] secret, byte[] peer)
    {
        var r = new byte[XLen];
        if (!BcX25519.CalculateAgreement(secret, 0, peer, 0, r, 0)) throw new CryptographicException("x25519: the peer public key is a low-order point");
        return r;
    }

    static byte[] Sha3(byte[] data)
    {
        var d = new Sha3Digest(256);
        d.BlockUpdate(data, 0, data.Length);
        var o = new byte[32];
        d.DoFinal(o, 0);
        return o;
    }

    static byte[] Xof256(byte[] data, int outLen)
    {
        var d = new ShakeDigest(256);
        d.BlockUpdate(data, 0, data.Length);
        var o = new byte[outLen];
        d.OutputFinal(o, 0, outLen);
        return o;
    }

    /// <summary>HKDF-SHA256(ikm = ssMlkem || ssX25519 || ephemeral public || recipient X25519 public, no salt, info = the suite's domain, 32 bytes).</summary>
    static byte[] Combine(int level, byte[] ssMlkem, byte[] ssX, byte[] ephPub, byte[] recipX) =>
        HKDF.DeriveKey(HashAlgorithmName.SHA256, Cat(ssMlkem, ssX, ephPub, recipX), SsLen, null, Domain(level));

    /// <summary>FIPS 203 section 7.2 modulus check: every 12-bit coefficient of the first 384k bytes is below 3329.</summary>
    static bool CoefficientsReduced(byte[] ek, int k)
    {
        for (int i = 0; i < 384 * k; i += 3)
        {
            if ((ek[i] | ((ek[i + 1] & 0x0f) << 8)) >= 3329) return false;
            if (((ek[i + 1] >> 4) | (ek[i + 2] << 4)) >= 3329) return false;
        }
        return true;
    }

    static void RequireReducedEk(byte[] ek, int k, string who)
    {
        if (!CoefficientsReduced(ek, k)) throw new ArgumentException(who + ": ML-KEM encapsulation key fails the FIPS 203 modulus check");
    }

    static int K(int level) => level switch { 768 => 3, 1024 => 4, _ => throw new ArgumentException("ml-kem: the level must be 768 or 1024") };

    // ---- the hybrid KEM at either level ----

    /// <summary>Key generation from the X25519 secret (32 bytes) and the ML-KEM seed d || z (64 bytes).</summary>
    internal static HybridKemKeyPair KeygenDerand(int level, byte[] xSecret, byte[] dz)
    {
        if (xSecret.Length != XLen) throw new ArgumentException("hybrid keygen: the X25519 secret must be 32 bytes");
        var (ek, dk) = MlKemBc.Keygen(level, dz);
        return new HybridKemKeyPair(Cat(XPublic(xSecret), ek), Cat(xSecret, dk));
    }

    /// <summary>Encapsulation from the ephemeral X25519 secret (32 bytes) and the ML-KEM message m (32 bytes).</summary>
    internal static HybridEncapsulation EncapsulateDerand(int level, byte[] recipientPublicKey, byte[] ephSecret, byte[] m, string who)
    {
        ArgumentNullException.ThrowIfNull(recipientPublicKey);
        int k = K(level), pkLen = XLen + 384 * k + 32;
        if (recipientPublicKey.Length != pkLen) throw new ArgumentException($"{who}: public key must be {pkLen} bytes (got {recipientPublicKey.Length})");
        if (ephSecret.Length != XLen) throw new ArgumentException(who + ": the ephemeral X25519 secret must be 32 bytes");
        var recipX = recipientPublicKey[..XLen];
        var recipMlkem = recipientPublicKey[XLen..];
        var ephPub = XPublic(ephSecret);
        var ssX = XShared(ephSecret, recipX);
        RequireReducedEk(recipMlkem, k, who);
        var (ct, ssMlkem) = MlKemBc.Encapsulate(level, recipMlkem, m);
        return new HybridEncapsulation(Cat(ephPub, ct), Combine(level, ssMlkem, ssX, ephPub, recipX));
    }

    static byte[] Decapsulate(int level, byte[] ciphertext, byte[] secretKey, string who)
    {
        ArgumentNullException.ThrowIfNull(ciphertext);
        ArgumentNullException.ThrowIfNull(secretKey);
        int k = K(level), ctLen = level == 768 ? HybridCiphertextLen : Hybrid1024CiphertextLen;
        if (ciphertext.Length != ctLen) throw new ArgumentException($"{who}: ciphertext must be {ctLen} bytes (got {ciphertext.Length})");
        if (secretKey.Length != XLen + 768 * k + 96) throw new ArgumentException(who + ": malformed secret key");
        var ephPub = ciphertext[..XLen];
        var xPriv = secretKey[..XLen];
        var ssX = XShared(xPriv, ephPub);
        var ssMlkem = MlKemBc.Decapsulate(level, ciphertext[XLen..], secretKey[XLen..]);
        return Combine(level, ssMlkem, ssX, ephPub, XPublic(xPriv));
    }

    /// <summary>A fresh X25519 + ML-KEM-768 key pair (public 1216 bytes, secret 2432 bytes).</summary>
    public static HybridKemKeyPair HybridKemKeygen() => KeygenDerand(768, RandomNumberGenerator.GetBytes(XLen), RandomNumberGenerator.GetBytes(64));

    /// <summary>Encapsulate to a hybrid public key: a 1120-byte ciphertext and the 32-byte shared secret. Refuses a key of the wrong length, a low-order X25519
    /// point and an ML-KEM key that fails the modulus check.</summary>
    public static HybridEncapsulation HybridEncapsulate(byte[] recipientPublicKey) =>
        EncapsulateDerand(768, recipientPublicKey, RandomNumberGenerator.GetBytes(XLen), RandomNumberGenerator.GetBytes(32), "hybridEncapsulate");

    /// <summary>The shared secret of a hybrid ciphertext. Refuses a ciphertext or secret key of the wrong length and a low-order ephemeral point; a tampered
    /// ML-KEM ciphertext yields the implicit-rejection secret (a different 32 bytes), never an error.</summary>
    public static byte[] HybridDecapsulate(byte[] ciphertext, byte[] secretKey) => Decapsulate(768, ciphertext, secretKey, "hybridDecapsulate");

    /// <summary>A fresh X25519 + ML-KEM-1024 key pair (public 1600 bytes, secret 3200 bytes).</summary>
    public static HybridKemKeyPair HybridKem1024Keygen() => KeygenDerand(1024, RandomNumberGenerator.GetBytes(XLen), RandomNumberGenerator.GetBytes(64));

    /// <summary><see cref="HybridEncapsulate"/> at ML-KEM-1024 (its own domain separator; ciphertext 1600 bytes).</summary>
    public static HybridEncapsulation HybridEncapsulate1024(byte[] recipientPublicKey) =>
        EncapsulateDerand(1024, recipientPublicKey, RandomNumberGenerator.GetBytes(XLen), RandomNumberGenerator.GetBytes(32), "hybridEncapsulate1024");

    /// <summary><see cref="HybridDecapsulate"/> at ML-KEM-1024.</summary>
    public static byte[] HybridDecapsulate1024(byte[] ciphertext, byte[] secretKey) => Decapsulate(1024, ciphertext, secretKey, "hybridDecapsulate1024");

    // ---- X-Wing ----

    /// <summary>SHAKE256(seed, 96) = d (32) || z (32) || X25519 secret (32): the ML-KEM-768 key of d || z and the X25519 key.</summary>
    static (MLKemPrivateKeyParameters Mlkem, byte[] MlkemPublic, byte[] XSecret, byte[] XPub) ExpandXWingKey(byte[] seed)
    {
        ArgumentNullException.ThrowIfNull(seed);
        if (seed.Length != XWingSeedLen) throw new ArgumentException($"expandXWingKey: seed must be {XWingSeedLen} bytes (got {seed.Length})");
        var expanded = Xof256(seed, 96);
        var sk = MlKemBc.Key(768, expanded[..64]);
        var xSecret = expanded[64..96];
        return (sk, sk.GetPublicKeyEncoded(), xSecret, XPublic(xSecret));
    }

    /// <summary>SHA3-256(ssM || ssX || ctX || pkX || label); the ML-KEM ciphertext is deliberately not hashed in.</summary>
    static byte[] XWingCombiner(byte[] ssM, byte[] ssX, byte[] ctX, byte[] pkX) => Sha3(Cat(ssM, ssX, ctX, pkX, XWingLabel));

    /// <summary>An X-Wing key pair from a 32-byte seed (null: a fresh random seed). The secret key is the seed.</summary>
    public static XWingKeyPair XWingKeygen(byte[]? seed = null)
    {
        var sk = seed == null ? RandomNumberGenerator.GetBytes(XWingSeedLen) : (byte[])seed.Clone();
        var ex = ExpandXWingKey(sk);
        return new XWingKeyPair(sk, Cat(ex.MlkemPublic, ex.XPub));
    }

    /// <summary>X-Wing encapsulation from the 64-byte encapsulation seed m (32) || ephemeral X25519 secret (32).</summary>
    public static XWingEncapsulation XWingEncapsulateDerand(byte[] recipientPublicKey, byte[] eseed)
    {
        ArgumentNullException.ThrowIfNull(recipientPublicKey);
        ArgumentNullException.ThrowIfNull(eseed);
        if (recipientPublicKey.Length != XWingPublicKeyLen) throw new ArgumentException($"xwingEncapsulateDerand: public key must be {XWingPublicKeyLen} bytes (got {recipientPublicKey.Length})");
        if (eseed.Length != XWingEseedLen) throw new ArgumentException($"xwingEncapsulateDerand: eseed must be {XWingEseedLen} bytes (got {eseed.Length})");
        var pkM = recipientPublicKey[..MlKem768PkLen];
        var pkX = recipientPublicKey[MlKem768PkLen..];
        var ekX = eseed[32..64];
        RequireReducedEk(pkM, 3, "xwingEncapsulateDerand");
        var (ctM, ssM) = MlKemBc.Encapsulate(768, pkM, eseed[..32]);
        var ctX = XPublic(ekX);
        var ssX = XShared(ekX, pkX);
        return new XWingEncapsulation(Cat(ctM, ctX), XWingCombiner(ssM, ssX, ctX, pkX));
    }

    /// <summary>X-Wing encapsulation with a fresh random encapsulation seed.</summary>
    public static XWingEncapsulation XWingEncapsulate(byte[] recipientPublicKey) => XWingEncapsulateDerand(recipientPublicKey, RandomNumberGenerator.GetBytes(XWingEseedLen));

    /// <summary>The shared secret of an X-Wing ciphertext under the 32-byte seed secret key.</summary>
    public static byte[] XWingDecapsulate(byte[] ciphertext, byte[] secretKey)
    {
        ArgumentNullException.ThrowIfNull(ciphertext);
        if (ciphertext.Length != XWingCiphertextLen) throw new ArgumentException($"xwingDecapsulate: ciphertext must be {XWingCiphertextLen} bytes (got {ciphertext.Length})");
        var ex = ExpandXWingKey(secretKey);
        var ctX = ciphertext[MlKem768CtLen..];
        var ssM = MlKemBc.Decapsulate(768, ciphertext[..MlKem768CtLen], ex.Mlkem);
        var ssX = XShared(ex.XSecret, ctX);
        return XWingCombiner(ssM, ssX, ctX, ex.XPub);
    }

    // ---- wire encodings: unpadded base64url; decoding is strict (alphabet only, no padding, canonical trailing bits) and does not check the decoded length ----

    static byte[] Decode(string s, string who) => Pca.B64uDecode(s) ?? throw new FormatException(who + ": not canonical unpadded base64url");

    public static string EncodeHybridPublicKey(byte[] publicKey) => Pca.B64u(publicKey);
    public static byte[] DecodeHybridPublicKey(string s) => Decode(s, "decodeHybridPublicKey");
    public static string EncodeHybridCiphertext(byte[] ciphertext) => Pca.B64u(ciphertext);
    public static byte[] DecodeHybridCiphertext(string s) => Decode(s, "decodeHybridCiphertext");
    public static string EncodeXWingPublicKey(byte[] publicKey) => Pca.B64u(publicKey);
    public static byte[] DecodeXWingPublicKey(string s) => Decode(s, "decodeXWingPublicKey");
    public static string EncodeXWingCiphertext(byte[] ciphertext) => Pca.B64u(ciphertext);
    public static byte[] DecodeXWingCiphertext(string s) => Decode(s, "decodeXWingCiphertext");

    // ---- FIPS 203 key checks ----

    /// <summary>FIPS 203 section 7.2: the encapsulation key has the length of the level (768 or 1024; another level throws) and every coefficient is reduced.</summary>
    public static bool MlKemEncapsulationKeyCheck(int level, byte[]? ek)
    {
        int k = K(level);
        return ek != null && ek.Length == 384 * k + 32 && CoefficientsReduced(ek, k);
    }

    /// <summary>FIPS 203 section 7.3: the expanded decapsulation key has the length of the level (768 or 1024; another level throws), its embedded hash is
    /// SHA3-256 of its embedded encapsulation key, and that key passes <see cref="MlKemEncapsulationKeyCheck"/>. The decryption half and z are not checked.</summary>
    public static bool MlKemDecapsulationKeyCheck(int level, byte[]? dk)
    {
        int k = K(level);
        if (dk == null || dk.Length != 768 * k + 96) return false;
        var ek = dk[(384 * k)..(768 * k + 32)];
        return CryptographicOperations.FixedTimeEquals(Sha3(ek), dk.AsSpan(768 * k + 32, 32)) && MlKemEncapsulationKeyCheck(level, ek);
    }
}

// Agent-side keys: Ed25519 and every post-quantum / hybrid suite this SDK verifies (ML-DSA-65/87, SLH-DSA-SHA2-128f/256s, their
// hybrids and the SUF-CMA nested hybrid) through BouncyCastle. FN-DSA and LESS cannot be signed here and are refused.
// Ed25519 and ML-DSA signing are deterministic; SLH-DSA is signed in its deterministic variant.
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;

namespace AtlasPca;

/// <summary>An Ed25519 key: the 32-byte seed (RFC 8032 private key) and the 32-byte public key.</summary>
public sealed class EdKey
{
    public byte[] Seed { get; }
    public byte[] Pub { get; }
    EdKey(byte[] seed, byte[] pub) { Seed = seed; Pub = pub; }

    /// <summary>The b64u public key: the key id used as <c>issuer</c> / <c>holder</c> on the wire.</summary>
    public string Id => Pca.B64u(Pub);

    public static EdKey FromSeed(byte[] seed)
    {
        if (seed is not { Length: 32 }) throw new ArgumentException("an Ed25519 seed is 32 bytes");
        var s = (byte[])seed.Clone();
        return new EdKey(s, new Ed25519PrivateKeyParameters(s, 0).GeneratePublicKey().GetEncoded());
    }

    public static EdKey Generate() => FromSeed(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32));

    public byte[] Sign(byte[] msg)
    {
        var s = new Ed25519Signer();
        s.Init(true, new Ed25519PrivateKeyParameters(Seed, 0));
        s.BlockUpdate(msg, 0, msg.Length);
        return s.GenerateSignature();
    }
}

/// <summary>A post-quantum key pair of one primitive, in the byte encodings the wire uses (FIPS 204 / FIPS 205).</summary>
public sealed class PqKey
{
    public Pq.Prim Prim { get; }
    public byte[] Pk { get; }
    public byte[] Sk { get; }
    PqKey(Pq.Prim prim, byte[] pk, byte[] sk) { Prim = prim; Pk = pk; Sk = sk; }

    /// <summary>The b64u public key carried as <c>pq_pk</c>.</summary>
    public string PkB64u => Pca.B64u(Pk);

    static bool IsMl(Pq.Prim p) => p is Pq.Prim.MlDsa65 or Pq.Prim.MlDsa87;
    static MLDsaParameters Ml(Pq.Prim p) => p == Pq.Prim.MlDsa65 ? MLDsaParameters.ml_dsa_65 : MLDsaParameters.ml_dsa_87;
    static SlhDsaParameters Slh(Pq.Prim p) => p == Pq.Prim.Slh128f ? SlhDsaParameters.slh_dsa_sha2_128f : SlhDsaParameters.slh_dsa_sha2_256s;

    static void Check(Pq.Prim p)
    {
        if (p is not (Pq.Prim.MlDsa65 or Pq.Prim.MlDsa87 or Pq.Prim.Slh128f or Pq.Prim.Slh256s)) throw new ArgumentException($"cannot sign with {p} in this SDK");
    }

    public static PqKey Generate(Pq.Prim p)
    {
        Check(p);
        var rng = new SecureRandom();
        if (IsMl(p))
        {
            var g = new MLDsaKeyPairGenerator();
            g.Init(new MLDsaKeyGenerationParameters(rng, Ml(p)));
            var kp = g.GenerateKeyPair();
            return new PqKey(p, ((MLDsaPublicKeyParameters)kp.Public).GetEncoded(), ((MLDsaPrivateKeyParameters)kp.Private).GetEncoded());
        }
        var sg = new SlhDsaKeyPairGenerator();
        sg.Init(new SlhDsaKeyGenerationParameters(rng, Slh(p)));
        var skp = sg.GenerateKeyPair();
        return new PqKey(p, ((SlhDsaPublicKeyParameters)skp.Public).GetEncoded(), ((SlhDsaPrivateKeyParameters)skp.Private).GetEncoded());
    }

    /// <summary>Load a key pair from its encoded public and secret key (as produced by another implementation of the same suite).</summary>
    public static PqKey Load(Pq.Prim p, byte[] pk, byte[] sk)
    {
        Check(p);
        if (pk.Length != Pq.Lens(p).Pk) throw new ArgumentException($"wrong public key length for {p}");
        return new PqKey(p, (byte[])pk.Clone(), (byte[])sk.Clone());
    }

    internal byte[] Sign(byte[] msg)
    {
        ISigner s;
        if (IsMl(Prim))
        {
            var ps = Ml(Prim);
            s = new MLDsaSigner(ps, true); // pure ML-DSA, empty context, deterministic
            s.Init(true, MLDsaPrivateKeyParameters.FromEncoding(ps, Sk));
        }
        else
        {
            var ps = Slh(Prim);
            s = new SlhDsaSigner(ps, true);
            s.Init(true, SlhDsaPrivateKeyParameters.FromEncoding(ps, Sk));
        }
        s.BlockUpdate(msg, 0, msg.Length);
        return s.GenerateSignature();
    }
}

/// <summary>The key material one signature suite needs: the suite name, the Ed25519 key (every hybrid, and ed25519 itself) and the
/// post-quantum key (every non-ed25519 suite). The factory fails closed on a missing or mismatched key.</summary>
public sealed class SuiteKey
{
    public string Alg { get; }
    public EdKey? Ed { get; }
    public PqKey? Pq { get; }
    readonly AtlasPca.Pq.Suite _suite;
    SuiteKey(string alg, EdKey? ed, PqKey? pq, AtlasPca.Pq.Suite suite) { Alg = alg; Ed = ed; Pq = pq; _suite = suite; }

    /// <summary>Ed25519 only (the default suite).</summary>
    public static SuiteKey Ed25519(EdKey ed) => Create("ed25519", ed, null);

    public static SuiteKey Create(string alg, EdKey? ed, PqKey? pq)
    {
        if (!AtlasPca.Pq.Suites.TryGetValue(alg, out var s)) throw new ArgumentException(AtlasPca.Pq.Refusal(alg));
        bool hasEd = s.Pq == AtlasPca.Pq.Prim.None || s.NeedsPqSig;
        if (hasEd && ed == null) throw new ArgumentException($"'{alg}' requires an Ed25519 key");
        if (s.Pq != AtlasPca.Pq.Prim.None)
        {
            if (s.Pq == AtlasPca.Pq.Prim.Less) throw new ArgumentException("LESS cannot be signed in this SDK");
            if (pq == null) throw new ArgumentException($"'{alg}' requires a {s.Pq} key");
            if (pq.Prim != s.Pq) throw new ArgumentException($"'{alg}' needs a {s.Pq} key, got {pq.Prim}");
        }
        return new SuiteKey(alg, ed, pq, s);
    }

    /// <summary>The PQ public key bound into the signed body (<c>pq_pk</c>); null for ed25519.</summary>
    public string? PqPk => _suite.NeedsPqPk ? Pq!.PkB64u : null;

    /// <summary>The Ed25519 identity (key id) this signer is known by; null for a pure PQ suite.</summary>
    public string? Id => Ed?.Id;

    /// <summary>Sign: <c>Sig</c> is the primary signature, <c>PqSig</c> the PQ half of a hybrid (else null).</summary>
    public (string Sig, string? PqSig) Sign(byte[] msg)
    {
        if (_suite.Pq == AtlasPca.Pq.Prim.None) return (Pca.B64u(Ed!.Sign(msg)), null);
        if (!_suite.NeedsPqSig) return (Pca.B64u(Pq!.Sign(msg)), null);
        var edSig = Ed!.Sign(msg);
        var pqSig = Pq!.Sign(_suite.Nested ? Pca.Cat(msg, edSig) : msg);
        return (Pca.B64u(edSig), Pca.B64u(pqSig));
    }

    /// <summary>The verifier-side PQ pin for an identity: <c>{ ed25519 b64u: pq_pk }</c> (what <c>pqPins</c> holds).</summary>
    public Dictionary<string, string> PqPin() => Ed != null && Pq != null ? new() { [Ed.Id] = Pq.PkB64u } : new();
}

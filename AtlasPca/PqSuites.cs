// The public post-quantum suite surface of the TypeScript pq.ts: per-suite size constants, deterministic keygen from a seed, raw and b64u
// sign / verify, public-key encoders, the suite signing seam (SignWithSuite / SignSuiteArtifact / SuitePqPublicKey) and the LAMPS composite
// ML-DSA-65 + Ed25519 signature. Everything delegates to the suite machinery the verifier already uses (BouncyCastle for ML-DSA / SLH-DSA, the
// registered AtlasPca.Fndsa backend for FN-DSA, libatlas_less for LESS); nothing here hand-rolls a primitive. Verify functions never throw.
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using JD = System.Collections.Generic.Dictionary<string, object?>;

namespace AtlasPca;

/// <summary>A PQ key pair as raw bytes (the wire / PKI boundary).</summary>
public sealed record PqKeyPair(byte[] SecretKey, byte[] PublicKey);

/// <summary>FN-DSA signing material for the suite seam: the key pair and the 32-byte signing seed.</summary>
public sealed record FnDsaSuiteKey(byte[] VerifyingKey, byte[] SigningKey, byte[] SignSeed);

/// <summary>LESS signing material for the suite seam: the key pair and the 32-byte signing seed.</summary>
public sealed record LessSuiteKey(byte[] PublicKey, byte[] SecretKey, byte[] SignSeed);

/// <summary>The key material <see cref="PqSuites.SignWithSuite"/> may need; supply what the chosen suite uses.</summary>
public sealed class SuiteSecretKeys
{
    public byte[]? EdSecret;
    public PqKeyPair? MlDsa, SlhDsa, MlDsa87, SlhDsa256s;
    public FnDsaSuiteKey? FnDsa512, FnDsa1024;
    public LessSuiteKey? LessCat1;
}

/// <summary>The signature parts of a suite: <c>Sig</c> (b64u) and, for hybrids, <c>PqSig</c>.</summary>
public sealed record SuiteSignatureParts(string Sig, string? PqSig);

/// <summary>Every wire field a signed artifact carries for its suite: <c>Alg</c> and <c>PqPk</c> only for a non-default suite.</summary>
public sealed record SuiteArtifactFields(string Sig, string? Alg, string? PqPk, string? PqSig);

public static class PqSuites
{
    public const int MlDsa65PublicKeyBytes = 1952, MlDsa65SignatureBytes = 3309, MlDsa65SeedBytes = 32;
    public const int SlhDsaSha2128fPublicKeyBytes = 32, SlhDsaSha2128fSecretKeyBytes = 64, SlhDsaSha2128fSignatureBytes = 17088, SlhDsaSha2128fSeedBytes = 48;
    public const int Ed25519SignatureBytes = 64;
    public const int MlDsa87PublicKeyBytes = 2592, MlDsa87SignatureBytes = 4627, MlDsa87SeedBytes = 32;
    public const int SlhDsaSha2256sPublicKeyBytes = 64, SlhDsaSha2256sSecretKeyBytes = 128, SlhDsaSha2256sSignatureBytes = 29792, SlhDsaSha2256sSeedBytes = 96;
    public const int FnDsa512PublicKeyBytes = 897, FnDsa512SecretKeyBytes = 1345, FnDsa512SignatureBytes = 666;
    public const int FnDsa1024PublicKeyBytes = 1793, FnDsa1024SecretKeyBytes = 2369, FnDsa1024SignatureBytes = 1280;
    public const int FnDsaSeedBytes = 32;
    public const int LessCat1PublicKeyBytes = 97484, LessCat1SecretKeyBytes = 32, LessCat1SignatureMaxBytes = 1329, LessCat1SignatureMinBytes = 1153, LessCat1SignatureStepBytes = 16;
    public const int LessSeedBytes = 32;
    /// <summary>The suite used when <c>alg</c> is absent. Stays "ed25519" forever.</summary>
    public const string DefaultSigAlg = "ed25519";

    public const string CompositePrefix = "CompositeAlgorithmSignatures2025";
    public const string CompositeLabel = "COMPSIG-MLDSA65-Ed25519-SHA512";
    public const int CompositeSignatureBytes = MlDsa65SignatureBytes + Ed25519SignatureBytes;

    static readonly HashSet<int> PqPkLengths = new()
    {
        MlDsa65PublicKeyBytes, SlhDsaSha2128fPublicKeyBytes, MlDsa87PublicKeyBytes, SlhDsaSha2256sPublicKeyBytes,
        FnDsa512PublicKeyBytes, FnDsa1024PublicKeyBytes, LessCat1PublicKeyBytes,
    };

    /// <summary>True for a name in the closed suite registry (the registry, not what this runtime can verify).</summary>
    public static bool IsKnownSigAlg(object? x) => x is string s && Pq.RegisteredSuites.Contains(s);

    /// <summary>True when <paramref name="pq"/> is canonical b64u of a byte string with the public-key length of a registered PQ suite.</summary>
    public static bool IsWellFormedPqPublicKey(object? pq) => Pca.B64uDecode(pq) is { } b && PqPkLengths.Contains(b.Length);

    // ---- keygen / sign / verify per primitive ----------------------------------------------------------------------

    static PqKeyPair Pair(PqKey k) => new((byte[])k.Sk.Clone(), (byte[])k.Pk.Clone());

    /// <summary>Deterministic ML-DSA-65 key generation from a 32-byte seed (FIPS 204 key generation).</summary>
    public static PqKeyPair MlDsa65Keygen(byte[] seed) => Pair(PqKey.FromSeed(Pq.Prim.MlDsa65, seed));
    public static PqKeyPair MlDsa87Keygen(byte[] seed) => Pair(PqKey.FromSeed(Pq.Prim.MlDsa87, seed));
    /// <summary>Deterministic SLH-DSA-SHA2-128f key generation from a 48-byte seed.</summary>
    public static PqKeyPair SlhDsa128fKeygen(byte[] seed) => Pair(PqKey.FromSeed(Pq.Prim.Slh128f, seed));
    /// <summary>Deterministic SLH-DSA-SHA2-256s key generation from a 96-byte seed.</summary>
    public static PqKeyPair SlhDsa256sKeygen(byte[] seed) => Pair(PqKey.FromSeed(Pq.Prim.Slh256s, seed));
    /// <summary>Deterministic FN-DSA-512 key generation from a 32-byte seed. Throws while no FN-DSA backend is registered.</summary>
    public static PqKeyPair FnDsa512Keygen(byte[] seed) => Pair(PqKey.FromSeed(Pq.Prim.FnDsa512, seed));
    public static PqKeyPair FnDsa1024Keygen(byte[] seed) => Pair(PqKey.FromSeed(Pq.Prim.FnDsa1024, seed));
    /// <summary>Deterministic LESS key generation from a 32-byte seed. Throws when libatlas_less (with signing) is unavailable.</summary>
    public static PqKeyPair LessCat1Keygen(byte[] seed) { var (sk, pk) = LessNative.Keygen(seed); return new PqKeyPair(sk, pk); }

    /// <summary>Raw sign with a bare ML-DSA / SLH-DSA secret key: pure mode, empty context, deterministic.</summary>
    static byte[] SignRaw(Pq.Prim p, byte[] sk, byte[] msg)
    {
        ISigner s;
        if (p is Pq.Prim.MlDsa65 or Pq.Prim.MlDsa87)
        {
            var ps = p == Pq.Prim.MlDsa65 ? MLDsaParameters.ml_dsa_65 : MLDsaParameters.ml_dsa_87;
            s = new MLDsaSigner(ps, true);
            s.Init(true, MLDsaPrivateKeyParameters.FromEncoding(ps, sk));
        }
        else
        {
            var ps = p == Pq.Prim.Slh128f ? SlhDsaParameters.slh_dsa_sha2_128f : SlhDsaParameters.slh_dsa_sha2_256s;
            s = new SlhDsaSigner(ps, true);
            s.Init(true, SlhDsaPrivateKeyParameters.FromEncoding(ps, sk));
        }
        s.BlockUpdate(msg, 0, msg.Length);
        return s.GenerateSignature();
    }

    public static byte[] MlDsa65Sign(byte[] secretKey, byte[] msg) => SignRaw(Pq.Prim.MlDsa65, secretKey, msg);
    public static byte[] MlDsa87Sign(byte[] secretKey, byte[] msg) => SignRaw(Pq.Prim.MlDsa87, secretKey, msg);
    public static byte[] SlhDsa128fSign(byte[] secretKey, byte[] msg) => SignRaw(Pq.Prim.Slh128f, secretKey, msg);
    public static byte[] SlhDsa256sSign(byte[] secretKey, byte[] msg) => SignRaw(Pq.Prim.Slh256s, secretKey, msg);
    /// <summary>FN-DSA-512 signature over raw <paramref name="msg"/> with a 32-byte RNG seed. Throws without a signing backend.</summary>
    public static byte[] FnDsa512Sign(byte[] signingKey, byte[] msg, byte[] seed) => AtlasPca.Fndsa.Fndsa.FndsaSign("fn-dsa-512", signingKey, msg, seed);
    public static byte[] FnDsa1024Sign(byte[] signingKey, byte[] msg, byte[] seed) => AtlasPca.Fndsa.Fndsa.FndsaSign("fn-dsa-1024", signingKey, msg, seed);
    /// <summary>LESS detached signature with an explicit 32-byte RNG seed. Throws when unavailable.</summary>
    public static byte[] LessCat1Sign(byte[] secretKey, byte[] msg, byte[] seed) => LessNative.Sign(secretKey, msg, seed);

    public static bool MlDsa65Verify(byte[] publicKey, byte[] msg, byte[] sig) => Pq.Verify(Pq.Prim.MlDsa65, publicKey, msg, sig);
    public static bool MlDsa87Verify(byte[] publicKey, byte[] msg, byte[] sig) => Pq.Verify(Pq.Prim.MlDsa87, publicKey, msg, sig);
    public static bool SlhDsa128fVerify(byte[] publicKey, byte[] msg, byte[] sig) => Pq.Verify(Pq.Prim.Slh128f, publicKey, msg, sig);
    public static bool SlhDsa256sVerify(byte[] publicKey, byte[] msg, byte[] sig) => Pq.Verify(Pq.Prim.Slh256s, publicKey, msg, sig);
    public static bool FnDsa512Verify(byte[] publicKey, byte[] msg, byte[] sig) => Pq.Verify(Pq.Prim.FnDsa512, publicKey, msg, sig);
    public static bool FnDsa1024Verify(byte[] publicKey, byte[] msg, byte[] sig) => Pq.Verify(Pq.Prim.FnDsa1024, publicKey, msg, sig);
    public static bool LessCat1Verify(byte[] publicKey, byte[] msg, byte[] sig) => Pq.Verify(Pq.Prim.Less, publicKey, msg, sig);

    /// <summary>Verify over base64url key and signature; false on any decoding error. Never throws.</summary>
    public static bool VerifyB64u(Pq.Prim p, object? publicKeyB64u, byte[] msg, object? sigB64u)
    {
        try
        {
            var pk = Pca.B64uDecode(publicKeyB64u, Pq.Lens(p).Pk);
            var sg = Pca.B64uDecode(sigB64u);
            return pk != null && sg != null && Pq.Verify(p, pk, msg, sg);
        }
        catch { return false; }
    }

    public static bool MlDsa65VerifyB64u(object? pk, byte[] msg, object? sig) => VerifyB64u(Pq.Prim.MlDsa65, pk, msg, sig);
    public static bool MlDsa87VerifyB64u(object? pk, byte[] msg, object? sig) => VerifyB64u(Pq.Prim.MlDsa87, pk, msg, sig);
    public static bool SlhDsa128fVerifyB64u(object? pk, byte[] msg, object? sig) => VerifyB64u(Pq.Prim.Slh128f, pk, msg, sig);
    public static bool SlhDsa256sVerifyB64u(object? pk, byte[] msg, object? sig) => VerifyB64u(Pq.Prim.Slh256s, pk, msg, sig);
    public static bool FnDsa512VerifyB64u(object? pk, byte[] msg, object? sig) => VerifyB64u(Pq.Prim.FnDsa512, pk, msg, sig);
    public static bool FnDsa1024VerifyB64u(object? pk, byte[] msg, object? sig) => VerifyB64u(Pq.Prim.FnDsa1024, pk, msg, sig);
    public static bool LessCat1VerifyB64u(object? pk, byte[] msg, object? sig) => VerifyB64u(Pq.Prim.Less, pk, msg, sig);

    /// <summary>b64u of a PQ public key: the value of <c>pq_pk</c>.</summary>
    public static string EncodePublicKey(byte[] publicKey) => Pca.B64u(publicKey);
    public static string EncodeMlDsaPublicKey(byte[] publicKey) => Pca.B64u(publicKey);
    public static string EncodeMlDsa87PublicKey(byte[] publicKey) => Pca.B64u(publicKey);
    public static string EncodeSlhDsaPublicKey(byte[] publicKey) => Pca.B64u(publicKey);
    public static string EncodeSlhDsa256sPublicKey(byte[] publicKey) => Pca.B64u(publicKey);
    public static string EncodeFnDsaPublicKey(byte[] publicKey) => Pca.B64u(publicKey);
    public static string EncodeLessPublicKey(byte[] publicKey) => Pca.B64u(publicKey);

    /// <summary>Whether a signing-capable FN-DSA backend is registered (else every FN-DSA suite fails closed).</summary>
    public static bool IsFnDsaBackendActive() => AtlasPca.Fndsa.Fndsa.BackendRegistered;
    /// <summary>Whether libatlas_less is loaded (else every LESS suite fails closed).</summary>
    public static bool IsLessBackendActive() => LessNative.Available;
    /// <summary>Availability of the LESS backend and, when unavailable, the reason. Never throws.</summary>
    public static (bool Available, string? Reason) LessBackendStatus() =>
        LessNative.Available ? (true, null) : (false, "libatlas_less is not loaded (set ATLAS_PCA_LIBLESS or build sdks/pca-less-c)");

    // ---- the suite signing seam ------------------------------------------------------------------------------------

    static byte[] EdSign(byte[] secret, byte[] msg) { using var k = EdKey.FromSeed(secret); return k.Sign(msg); }

    /// <summary>Sign <paramref name="msg"/> under <paramref name="alg"/> (null: ed25519). FAIL-CLOSED: an unknown alg or missing key material throws.</summary>
    public static SuiteSignatureParts SignWithSuite(object? alg, SuiteSecretKeys keys, byte[] msg)
    {
        var name = alg ?? DefaultSigAlg;
        if (name is not string a || !Pq.RegisteredSuites.Contains(a)) throw new ArgumentOutOfRangeException(nameof(alg), $"signWithSuite: unknown signature alg '{alg}'");
        byte[] Ed() => keys.EdSecret is { } e ? EdSign(e, msg) : throw new ArgumentException($"signWithSuite: '{a}' requires edSecret");
        PqKeyPair Need(PqKeyPair? k, string n) => k ?? throw new ArgumentException($"signWithSuite: '{a}' requires {n} key material");
        string B(byte[] x) => Pca.B64u(x);
        switch (a)
        {
            case "ed25519": return new(B(Ed()), null);
            case "ml-dsa-65": return new(B(MlDsa65Sign(Need(keys.MlDsa, "mlDsa").SecretKey, msg)), null);
            case "hybrid-ed25519-ml-dsa-65": { var ed = Ed(); return new(B(ed), B(MlDsa65Sign(Need(keys.MlDsa, "mlDsa").SecretKey, msg))); }
            case "hybrid-nested-ed25519-ml-dsa-65":
            {
                // SUF-CMA nested hybrid: the PQ half signs message || the Ed25519 signature bytes
                var ed = Ed();
                return new(B(ed), B(MlDsa65Sign(Need(keys.MlDsa, "mlDsa").SecretKey, [.. msg, .. ed])));
            }
            case "slh-dsa-sha2-128f": return new(B(SlhDsa128fSign(Need(keys.SlhDsa, "slhDsa").SecretKey, msg)), null);
            case "hybrid-ed25519-slh-dsa-sha2-128f": { var ed = Ed(); return new(B(ed), B(SlhDsa128fSign(Need(keys.SlhDsa, "slhDsa").SecretKey, msg))); }
            case "ml-dsa-87": return new(B(MlDsa87Sign(Need(keys.MlDsa87, "mlDsa87").SecretKey, msg)), null);
            case "hybrid-ed25519-ml-dsa-87": { var ed = Ed(); return new(B(ed), B(MlDsa87Sign(Need(keys.MlDsa87, "mlDsa87").SecretKey, msg))); }
            case "slh-dsa-sha2-256s": return new(B(SlhDsa256sSign(Need(keys.SlhDsa256s, "slhDsa256s").SecretKey, msg)), null);
            case "hybrid-ed25519-slh-dsa-sha2-256s": { var ed = Ed(); return new(B(ed), B(SlhDsa256sSign(Need(keys.SlhDsa256s, "slhDsa256s").SecretKey, msg))); }
            case "fn-dsa-512": { var k = keys.FnDsa512 ?? throw new ArgumentException("signWithSuite: 'fn-dsa-512' requires fnDsa512 key material (signingKey + signSeed)"); return new(B(FnDsa512Sign(k.SigningKey, msg, k.SignSeed)), null); }
            case "fn-dsa-1024": { var k = keys.FnDsa1024 ?? throw new ArgumentException("signWithSuite: 'fn-dsa-1024' requires fnDsa1024 key material (signingKey + signSeed)"); return new(B(FnDsa1024Sign(k.SigningKey, msg, k.SignSeed)), null); }
            case "less-cat1": { var k = keys.LessCat1 ?? throw new ArgumentException("signWithSuite: 'less-cat1' requires lessCat1 key material (secretKey + signSeed)"); return new(B(LessCat1Sign(k.SecretKey, msg, k.SignSeed)), null); }
            case "hybrid-ed25519-less-cat1": { var k = keys.LessCat1 ?? throw new ArgumentException("signWithSuite: 'hybrid-ed25519-less-cat1' requires lessCat1 key material (secretKey + signSeed)"); var ed = Ed(); return new(B(ed), B(LessCat1Sign(k.SecretKey, msg, k.SignSeed))); }
        }
        throw new ArgumentOutOfRangeException(nameof(alg), $"signWithSuite: unknown signature alg '{alg}'");
    }

    /// <summary>Verify a suite signature over <paramref name="msg"/>: the Ed25519 half first, the PQ half only under <paramref name="pq"/>
    /// (caller-vouched, see <see cref="Pca.VerifySuiteSig"/>). FAIL-CLOSED; never throws.</summary>
    public static bool VerifyWithSuite(object? alg, string? edPub, string? pq, byte[] msg, object? sig, object? pqSig)
    {
        try { return (alg == null || alg is string) && Pca.VerifySuiteSig((string?)alg, edPub, pq, msg, sig, pqSig); }
        catch { return false; }
    }

    /// <summary>Verify the leaf signature of a PCActn under its suite (the same seam as <see cref="VerifyWithSuite"/>, holder = the Ed25519 key).</summary>
    public static bool VerifyLeafSuite(object? alg, string holder, string? pq, byte[] message, object? sig, object? pqSig) =>
        VerifyWithSuite(alg, holder, pq, message, sig, pqSig);

    /// <summary>The b64u <c>pq_pk</c> that <paramref name="alg"/> selects from <paramref name="keys"/>, or null for ed25519, an unknown alg or absent key material.</summary>
    public static string? SuitePqPublicKey(object? alg, SuiteSecretKeys? keys)
    {
        if (keys == null || alg is not string a || a == DefaultSigAlg || !Pq.RegisteredSuites.Contains(a)) return null;
        return a switch
        {
            "ml-dsa-65" or "hybrid-ed25519-ml-dsa-65" or "hybrid-nested-ed25519-ml-dsa-65" => keys.MlDsa is { } k ? EncodeMlDsaPublicKey(k.PublicKey) : null,
            "slh-dsa-sha2-128f" or "hybrid-ed25519-slh-dsa-sha2-128f" => keys.SlhDsa is { } k ? EncodeSlhDsaPublicKey(k.PublicKey) : null,
            "ml-dsa-87" or "hybrid-ed25519-ml-dsa-87" => keys.MlDsa87 is { } k ? EncodeMlDsa87PublicKey(k.PublicKey) : null,
            "slh-dsa-sha2-256s" or "hybrid-ed25519-slh-dsa-sha2-256s" => keys.SlhDsa256s is { } k ? EncodeSlhDsa256sPublicKey(k.PublicKey) : null,
            "fn-dsa-512" => keys.FnDsa512 is { } k ? EncodeFnDsaPublicKey(k.VerifyingKey) : null,
            "fn-dsa-1024" => keys.FnDsa1024 is { } k ? EncodeFnDsaPublicKey(k.VerifyingKey) : null,
            "less-cat1" or "hybrid-ed25519-less-cat1" => keys.LessCat1 is { } k ? EncodeLessPublicKey(k.PublicKey) : null,
            _ => null,
        };
    }

    /// <summary>The full secret keys for signing a surface artifact: the identity's Ed25519 secret plus the PQ material of <paramref name="suite"/>.</summary>
    public static SuiteSecretKeys SuiteKeysOf(byte[] edSecret, SuiteSecretKeys? suite) => new()
    {
        EdSecret = edSecret, MlDsa = suite?.MlDsa, SlhDsa = suite?.SlhDsa, MlDsa87 = suite?.MlDsa87, SlhDsa256s = suite?.SlhDsa256s,
        FnDsa512 = suite?.FnDsa512, FnDsa1024 = suite?.FnDsa1024, LessCat1 = suite?.LessCat1,
    };

    /// <summary>Sign <paramref name="msg"/> and return ALL the wire fields an artifact carries for its suite: only <c>sig</c> for the default suite
    /// (byte-identical to pre-agility), plus <c>alg</c>, <c>pq_pk</c> and (hybrid) <c>pq_sig</c> otherwise.</summary>
    public static SuiteArtifactFields SignSuiteArtifact(object? alg, SuiteSecretKeys keys, byte[] msg)
    {
        var parts = SignWithSuite(alg, keys, msg);
        var a = (string)(alg ?? DefaultSigAlg);
        if (a == DefaultSigAlg) return new(parts.Sig, null, null, null);
        return new(parts.Sig, a, SuitePqPublicKey(a, keys), parts.PqSig);
    }

    // ---- LAMPS composite ML-DSA-65 + Ed25519 ----------------------------------------------------------------------

    /// <summary>The composite message representative <c>M' = Prefix || Label || len(ctx) || ctx || SHA-512(message)</c>. Throws when ctx is over 255 bytes.</summary>
    public static byte[] CompositeRepresentative(byte[] message, byte[]? ctx = null)
    {
        ctx ??= Array.Empty<byte>();
        if (ctx.Length > 255) throw new ArgumentOutOfRangeException(nameof(ctx), "compositeRepresentative: ctx exceeds 255 bytes");
        return [.. Encoding.UTF8.GetBytes(CompositePrefix), .. Encoding.UTF8.GetBytes(CompositeLabel), (byte)ctx.Length, .. ctx, .. SHA512.HashData(message)];
    }

    public static byte[] CompositeRepresentative(byte[] message, string ctx) => CompositeRepresentative(message, Encoding.UTF8.GetBytes(ctx));

    /// <summary>A composite signature <c>mldsaSig || edSig</c> (3373 bytes): both components sign the composite representative.</summary>
    public static byte[] CompositeSign(byte[] ed25519Secret, PqKeyPair mlDsa, byte[] message, byte[]? ctx = null)
    {
        var m = CompositeRepresentative(message, ctx);
        return [.. MlDsa65Sign(mlDsa.SecretKey, m), .. EdSign(ed25519Secret, m)];
    }

    /// <summary>Verify a composite signature: BOTH components must verify over the same representative. A wrong total length or a ctx over 255
    /// bytes is false. Never throws.</summary>
    public static bool CompositeVerify(byte[] ed25519Pub, byte[] mlDsaPub, byte[] message, byte[] signature, byte[]? ctx = null)
    {
        try
        {
            if (signature.Length != CompositeSignatureBytes) return false;
            var m = CompositeRepresentative(message, ctx);
            var pqOk = MlDsa65Verify(mlDsaPub, m, signature[..MlDsa65SignatureBytes]);
            var edOk = Pca.VerifyEd25519Strict(ed25519Pub, m, signature[MlDsa65SignatureBytes..]);
            return pqOk && edOk;
        }
        catch { return false; }
    }
}

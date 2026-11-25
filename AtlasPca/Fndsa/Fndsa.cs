// FN-DSA / Falcon suite registry, PCA leaf framing and hybrid composition (mirrors @atlasauth/pca-fndsa). The lattice math is delegated to a
// pluggable backend, exactly as in the reference. The real backend is the AtlasPca.Fndsa package (P/Invoke over libfndsa, Pornin's fn-dsa 0.4.0):
// call NativeFnDsa.Register() to install it. FIPS 206 is unpublished, so that backend is a draft best-guess pinned in lockstep with the TypeScript
// reference; BouncyCastle's Falcon is the round-3 submission and is NOT interoperable. With no backend registered the default fails loud. The wire
// format, the exact-length enforcement, the leaf binding and the fail-closed hybrid rule are tested against the deterministic mock backend and,
// in AtlasPca.Fndsa.Tests, the real one.
using System.Text;
using D = System.Collections.Generic.Dictionary<string, object?>;

namespace AtlasPca.Fndsa;

/// <summary>An FN-DSA key pair as raw bytes (the wire/PKI boundary).</summary>
public sealed record FalconKeyPair(byte[] Pk, byte[] Sk);

/// <summary>A known-answer vector: the backend must map (Pk, Msg) to Sig.</summary>
public sealed record FalconKat(byte[] Pk, byte[] Msg, byte[] Sig);

/// <summary>The vetted FN-DSA primitive. Verify is mandatory (must return false, not throw, on a bad signature); Sign and Keygen are optional.
/// All byte arguments are the padded FIPS 206 encodings.</summary>
public sealed class FalconBackend
{
    public Func<byte[], byte[], byte[], bool> Verify { get; init; } = (_, _, _) => throw new InvalidOperationException(Fndsa.NoBackendMessage);
    public Func<byte[], byte[], byte[]>? Sign { get; init; }
    public Func<FalconKeyPair>? Keygen { get; init; }
    /// <summary>Optional: deterministic key generation (variant, 32-byte seed). Needed to derive FN-DSA keys from seeds and to mint 1024 keys.</summary>
    public Func<string, byte[], FalconKeyPair>? KeygenFromSeed { get; init; }
    /// <summary>Optional: signing with a caller-supplied 32-byte signing seed (secret key, message, seed); deterministic output.</summary>
    public Func<byte[], byte[], byte[], byte[]>? SignSeeded { get; init; }
}

public sealed record FnDsaSuite(string Alg, string Variant, bool HasEd25519, int SigBytes, bool NeedsPqPk, int PqPkBytes, bool NeedsPqSig, int PqSigBytes, int FnSigBytes)
{
    public D ToJson() => new()
    {
        ["alg"] = Alg, ["variant"] = Variant, ["hasEd25519"] = HasEd25519, ["sigBytes"] = SigBytes, ["needsPqPk"] = NeedsPqPk, ["pqPkBytes"] = PqPkBytes,
        ["needsPqSig"] = NeedsPqSig, ["pqSigBytes"] = PqSigBytes, ["fnSigBytes"] = FnSigBytes,
    };
}

public static class Fndsa
{
    public const int FnDsa512PublicKeyBytes = 897;
    public const int FnDsa512SignatureBytes = 666;
    public const int FnDsa1024PublicKeyBytes = 1793;
    public const int FnDsa1024SignatureBytes = 1280;
    public const string FnDsaLeafDomain = "atlas-pca/fn-dsa/leaf/v1\0";
    public const string NoBackendMessage = "no FN-DSA backend registered — install a vetted FN-DSA backend and supply it via SetFalconBackend()";
    const string MockSkTag = "atlas-pca/fn-dsa/mock-sk/v1\0";

    public static readonly IReadOnlyDictionary<string, FnDsaSuite> Suites = new Dictionary<string, FnDsaSuite>(StringComparer.Ordinal)
    {
        ["fn-dsa-512"] = new("fn-dsa-512", "fn-dsa-512", false, FnDsa512SignatureBytes, true, FnDsa512PublicKeyBytes, false, 0, FnDsa512SignatureBytes),
        ["fn-dsa-1024"] = new("fn-dsa-1024", "fn-dsa-1024", false, FnDsa1024SignatureBytes, true, FnDsa1024PublicKeyBytes, false, 0, FnDsa1024SignatureBytes),
        ["hybrid-ed25519-fn-dsa-512"] = new("hybrid-ed25519-fn-dsa-512", "fn-dsa-512", true, Pq.Ed25519SignatureBytes, true, FnDsa512PublicKeyBytes, true, FnDsa512SignatureBytes, FnDsa512SignatureBytes),
        ["hybrid-ed25519-fn-dsa-1024"] = new("hybrid-ed25519-fn-dsa-1024", "fn-dsa-1024", true, Pq.Ed25519SignatureBytes, true, FnDsa1024PublicKeyBytes, true, FnDsa1024SignatureBytes, FnDsa1024SignatureBytes),
    };

    public static bool IsKnownFnDsaAlg(object? x) => x is string s && Suites.ContainsKey(s);

    /// <summary>Resolve a suite by id; null (fail closed) for an unknown name or a non-string.</summary>
    public static FnDsaSuite? ResolveFnDsaAlg(object? alg) => alg is string s && Suites.TryGetValue(s, out var v) ? v : null;

    public static bool IsFnDsaVariant(object? v) => v is "fn-dsa-512" or "fn-dsa-1024";

    static int PkBytes(string variant) => variant == "fn-dsa-512" ? FnDsa512PublicKeyBytes : FnDsa1024PublicKeyBytes;
    static int SigBytes(string variant) => variant == "fn-dsa-512" ? FnDsa512SignatureBytes : FnDsa1024SignatureBytes;

    // ---- the pluggable backend seam (a process-wide slot, like the reference) ----
    static readonly FalconBackend DefaultBackend = new()
    {
        Verify = (_, _, _) => throw new InvalidOperationException(NoBackendMessage),
        Sign = (_, _) => throw new InvalidOperationException(NoBackendMessage),
        Keygen = () => throw new InvalidOperationException(NoBackendMessage),
    };
    static FalconBackend _current = DefaultBackend;

    public static void SetFalconBackend(FalconBackend backend) => _current = backend ?? throw new ArgumentNullException(nameof(backend));
    public static FalconBackend GetFalconBackend() => _current;
    /// <summary>True once a backend was installed with <see cref="SetFalconBackend"/> (the pure fn-dsa suites then join <see cref="Pq.Suites"/>).</summary>
    public static bool BackendRegistered => !ReferenceEquals(_current, DefaultBackend);
    public static void ResetFalconBackend() => _current = DefaultBackend;

    // ---- primitive wrappers ----
    /// <summary>Sign over raw bytes via the backend after the framing guards. Throws when no backend is registered, when it is verify-only, or when it returns a wrong-length signature.</summary>
    public static byte[] FndsaSign(string variant, byte[]? sk, byte[]? msg, byte[]? signSeed = null)
    {
        if (!IsFnDsaVariant(variant)) throw new ArgumentOutOfRangeException(nameof(variant), $"fndsaSign: unknown FN-DSA variant '{variant}'");
        if (sk == null || sk.Length == 0) throw new ArgumentException("fndsaSign: secret key must be a non-empty byte array");
        if (msg == null) throw new ArgumentException("fndsaSign: message must be a byte array");
        var backend = _current;
        if (backend.Sign == null) throw new InvalidOperationException("fndsaSign: FN-DSA backend is verify-only (no sign())");
        byte[] sig;
        if (signSeed != null)
        {
            if (signSeed.Length != 32) throw new ArgumentException("fndsaSign: the signing seed must be 32 bytes");
            if (backend.SignSeeded == null) throw new InvalidOperationException("fndsaSign: FN-DSA backend cannot sign with a supplied seed");
            sig = backend.SignSeeded(sk, msg, signSeed);
        }
        else sig = backend.Sign(sk, msg);
        var expected = SigBytes(variant);
        if (sig == null || sig.Length != expected)
            throw new InvalidOperationException($"fndsaSign: FN-DSA backend returned a {(sig == null ? "non-byte" : sig.Length.ToString())} signature; expected padded {expected} bytes for '{variant}'");
        return sig;
    }

    /// <summary>Deterministic key generation from a 32-byte seed through the registered backend (throws when none, or when it has no seeded keygen).</summary>
    public static FalconKeyPair FndsaKeygenFromSeed(string variant, byte[] seed)
    {
        if (!IsFnDsaVariant(variant)) throw new ArgumentOutOfRangeException(nameof(variant), $"fndsaKeygen: unknown FN-DSA variant '{variant}'");
        if (seed == null || seed.Length != 32) throw new ArgumentException("fndsaKeygen: the seed must be 32 bytes");
        if (!BackendRegistered) throw new InvalidOperationException(NoBackendMessage);
        var kg = _current.KeygenFromSeed ?? throw new InvalidOperationException("fndsaKeygen: FN-DSA backend has no seeded keygen");
        var kp = kg(variant, seed);
        if (kp == null || kp.Pk.Length != PkBytes(variant)) throw new InvalidOperationException("fndsaKeygen: FN-DSA backend returned a wrong-size public key");
        return kp;
    }

    /// <summary>Verify over raw bytes. The suite's key and signature lengths are enforced BEFORE the backend is called (a wrong length is false);
    /// a backend that throws is not swallowed.</summary>
    public static bool FndsaVerify(object? variant, byte[]? pk, byte[]? msg, byte[]? sig)
    {
        if (variant is not string v || !IsFnDsaVariant(v)) return false;
        if (pk == null || pk.Length != PkBytes(v)) return false;
        if (sig == null || sig.Length != SigBytes(v)) return false;
        if (msg == null) return false;
        return _current.Verify(pk, msg, sig);
    }

    // ---- PCA leaf framing ----
    /// <summary>thresholdMessage(leaf) || FN_DSA_LEAF_DOMAIN || utf8(alg) || 0x00 || utf8(pq_pk b64u): binds the suite and the PQ key into the signed bytes.</summary>
    public static byte[] FndsaLeafMessage(D leaf, string alg, string pqPkB64u) =>
        Pca.Cat(Pca.ThresholdMessage(leaf), Encoding.UTF8.GetBytes(FnDsaLeafDomain), Encoding.UTF8.GetBytes(alg), new byte[] { 0 }, Encoding.UTF8.GetBytes(pqPkB64u));

    /// <summary>Produce the wire fields {sig, alg, pq_pk, pq_sig?} of an FN-DSA leaf signature. Pure: sig is the FN-DSA signature. Hybrid: sig is the Ed25519
    /// signature (edSecret = the 32-byte seed) and pq_sig the FN-DSA one, both over the same leaf message. Throws fail-closed on any malformed input.</summary>
    public static D SignPcaWithFndsa(object? alg, D leaf, FalconKeyPair? fnDsa, byte[]? edSecret)
    {
        var suite = ResolveFnDsaAlg(alg) ?? throw new ArgumentOutOfRangeException(nameof(alg), $"signPcaWithFndsa: unknown FN-DSA alg '{alg}'");
        if (fnDsa?.Pk == null || fnDsa.Pk.Length != suite.PqPkBytes) throw new ArgumentException($"signPcaWithFndsa: '{suite.Alg}' requires a {suite.PqPkBytes}-byte FN-DSA public key");
        if (fnDsa.Sk == null || fnDsa.Sk.Length == 0) throw new ArgumentException($"signPcaWithFndsa: '{suite.Alg}' requires FN-DSA secret-key material");
        var pqPk = Pca.B64u(fnDsa.Pk);
        var msg = FndsaLeafMessage(leaf, suite.Alg, pqPk);
        var fnSig = FndsaSign(suite.Variant, fnDsa.Sk, msg);
        if (!suite.HasEd25519) return new D { ["sig"] = Pca.B64u(fnSig), ["alg"] = suite.Alg, ["pq_pk"] = pqPk };
        if (edSecret == null) throw new ArgumentException($"signPcaWithFndsa: '{suite.Alg}' requires edSecret (Ed25519 leaf-holder secret key)");
        using var ed = EdKey.FromSeed(edSecret);
        return new D { ["sig"] = Pca.B64u(ed.Sign(msg)), ["alg"] = suite.Alg, ["pq_pk"] = pqPk, ["pq_sig"] = Pca.B64u(fnSig) };
    }

    /// <summary>Verify an FN-DSA leaf signature. Fail closed and never throws for ordinary wire faults (unknown alg, wrong-length or absent key/signature, tampered
    /// action, suite/key downgrade); hybrid needs BOTH halves. A backend that itself throws is not caught. Inputs are untrusted (object?).</summary>
    public static bool VerifyPcaFndsa(object? alg, D leaf, object? holder, object? pqPk, object? sig, object? pqSig)
    {
        var suite = ResolveFnDsaAlg(alg);
        if (suite == null) return false;
        if (pqPk is not string pqPkS) return false;
        var pk = Pca.B64uDecode(pqPkS, suite.PqPkBytes);
        if (pk == null) return false;
        var msg = FndsaLeafMessage(leaf, suite.Alg, pqPkS);
        if (!suite.HasEd25519)
        {
            if (sig is not string) return false;
            var fnSig = Pca.B64uDecode(sig, suite.SigBytes);
            if (fnSig == null) return false;
            return FndsaVerify(suite.Variant, pk, msg, fnSig);
        }
        if (holder is not string || sig is not string) return false;
        if (Pca.B64uDecode(sig, suite.SigBytes) == null) return false;
        var edOk = Pca.VerifyEdInternal(holder, msg, sig);
        if (pqSig is not string) return false;
        var pqS = Pca.B64uDecode(pqSig, suite.PqSigBytes);
        if (pqS == null) return false;
        var pqOk = FndsaVerify(suite.Variant, pk, msg, pqS);
        return edOk && pqOk;
    }

    // ---- KAT / mock backend (test double: NOT Falcon; never register in production) ----
    /// <summary>Deterministic SHA-256 counter-mode stretch of seed to exactly outLen bytes.</summary>
    public static byte[] HashKat(byte[] seed, int outLen)
    {
        if (outLen < 0) throw new ArgumentOutOfRangeException(nameof(outLen));
        var o = new byte[outLen];
        int off = 0, counter = 0;
        while (off < outLen)
        {
            var block = Pca.Sha(Pca.Cat(seed, new[] { (byte)(counter >> 24), (byte)(counter >> 16), (byte)(counter >> 8), (byte)counter }));
            var take = Math.Min(block.Length, outLen - off);
            Array.Copy(block, 0, o, off, take);
            off += take;
            counter++;
        }
        return o;
    }

    static int? SigLenForPk(int pkLen) => pkLen == FnDsa512PublicKeyBytes ? FnDsa512SignatureBytes : pkLen == FnDsa1024PublicKeyBytes ? FnDsa1024SignatureBytes : null;

    static byte[]? DeriveMockSig(byte[] pk, byte[] msg) =>
        SigLenForPk(pk.Length) is int n ? HashKat(Pca.Cat(Encoding.UTF8.GetBytes("fn-dsa/mock-sig/v1\0"), pk, msg), n) : null;

    static string KatKey(byte[] pk, byte[] msg) => Pca.B64u(pk) + "|" + Pca.B64u(msg);

    /// <summary>Deterministically mint a MOCK key pair for a variant: the secret key is the mock tag || pk, the public key a stretch of the seed.
    /// seed is a string or byte[] (default "default").</summary>
    public static FalconKeyPair MockKeypair(string variant, object? seed = null)
    {
        if (!IsFnDsaVariant(variant)) throw new ArgumentOutOfRangeException(nameof(variant), $"mockKeypair: unknown FN-DSA variant '{variant}'");
        var seedBytes = (seed ?? "default") switch
        {
            string s => Encoding.UTF8.GetBytes($"{variant}/{s}"),
            byte[] b => Pca.Cat(Encoding.UTF8.GetBytes(variant + "/"), b),
            _ => throw new ArgumentException("mockKeypair: seed must be a string or bytes"),
        };
        var pk = HashKat(seedBytes, PkBytes(variant));
        return new FalconKeyPair(pk, Pca.Cat(Encoding.UTF8.GetBytes(MockSkTag), pk));
    }

    static byte[]? PkFromMockSk(byte[] sk)
    {
        var tag = Encoding.UTF8.GetBytes(MockSkTag);
        if (sk.Length <= tag.Length) return null;
        if (!System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(sk.AsSpan(0, tag.Length), tag)) return null;
        return sk[tag.Length..];
    }

    /// <summary>Install (and return) a deterministic mock backend keyed by (pk, msg) -> sig; explicit vectors take precedence, otherwise a reproducible derivation.</summary>
    public static FalconBackend RegisterTestBackend(IEnumerable<FalconKat>? vectors = null)
    {
        var table = new Dictionary<string, byte[]>(StringComparer.Ordinal);
        if (vectors != null) foreach (var v in vectors) table[KatKey(v.Pk, v.Msg)] = v.Sig;
        var backend = new FalconBackend
        {
            Verify = (pk, msg, sig) =>
            {
                var expected = table.TryGetValue(KatKey(pk, msg), out var t) ? t : DeriveMockSig(pk, msg);
                return expected != null && expected.Length == sig.Length && System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(sig, expected);
            },
            Sign = (sk, msg) =>
            {
                var pk = PkFromMockSk(sk) ?? throw new InvalidOperationException("mock FN-DSA backend: secret key was not minted by MockKeypair()");
                if (table.TryGetValue(KatKey(pk, msg), out var t)) return t;
                return DeriveMockSig(pk, msg) ?? throw new InvalidOperationException("mock FN-DSA backend: public key length matches no FN-DSA variant");
            },
            Keygen = () => MockKeypair("fn-dsa-512"),
        };
        SetFalconBackend(backend);
        return backend;
    }
}

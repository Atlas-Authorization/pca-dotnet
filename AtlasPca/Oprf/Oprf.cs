// RFC 9497 OPRF / VOPRF / POPRF on the ristretto255-SHA512 ciphersuite (mirrors @atlasauth/pca-oprf). The group is the careful ristretto255 port
// in Ristretto255.cs (BouncyCastle has no ristretto255); the DLEQ proof, composites, domain-separation tags and transcript framing follow the RFC so
// outputs match the reference byte for byte. Every refusal throws; nothing here swallows an error.
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using AtlasPca.Ratchet;

namespace AtlasPca.Oprf;

public sealed record KeyPair(byte[] SecretKey, byte[] PublicKey);
public sealed record BlindResult(byte[] Blind, byte[] BlindedElement);
public sealed record PoprfBlindResult(byte[] Blind, byte[] BlindedElement, byte[] TweakedKey);
/// <summary>A blind evaluation: the evaluated element and, for VOPRF/POPRF, the 64-byte DLEQ proof.</summary>
public sealed record EvaluateResult(byte[] EvaluatedElement, byte[]? Proof = null);

public static class Oprf
{
    public const int ElementBytes = 32, ScalarBytes = 32, OutputBytes = 64;
    public const string SuiteId = "ristretto255-SHA512";
    const int MaxFramed = 0xffff;
    static BigInteger Order => RPoint.Order;
    static byte[] U8(string s) => Encoding.UTF8.GetBytes(s);

    /// <summary>The RFC 9497 modes and the mode byte folded into every domain-separation tag.</summary>
    public static IReadOnlyDictionary<string, int> Mode { get; } = new Dictionary<string, int> { ["oprf"] = 0, ["voprf"] = 1, ["poprf"] = 2 };

    static int ModeByte(string mode) => mode switch
    {
        "oprf" => 0,
        "voprf" => 1,
        "poprf" => 2,
        _ => throw new ArgumentOutOfRangeException(nameof(mode), $"unknown OPRF mode '{mode}'"),
    };

    static byte[] ContextString(string mode) => Pca.Cat(U8("OPRFV1-"), new[] { (byte)ModeByte(mode) }, U8("-" + SuiteId));

    static byte[] I2osp(int n, int len)
    {
        if (n < 0 || (len == 1 && n > 0xff) || (len == 2 && n > 0xffff)) throw new ArgumentOutOfRangeException(nameof(n), "I2OSP: value does not fit");
        return len == 1 ? new[] { (byte)n } : new[] { (byte)(n >> 8), (byte)n };
    }

    static void AssertBytes(byte[]? v, string what, int max = int.MaxValue)
    {
        if (v == null) throw new ArgumentException($"{what}: expected a byte array");
        if (v.Length > max) throw new ArgumentOutOfRangeException(what, $"{what}: {v.Length} bytes exceeds the {max}-byte limit (RFC 9497 2-byte length framing)");
    }

    // every modulus here is the group order; secret scalars reduce through libsodium's constant-time routines
    static BigInteger Mod(BigInteger a, BigInteger n) => RistrettoScalar.Mod(a);
    static BigInteger LeInt(byte[] b) => new(b, isUnsigned: true, isBigEndian: false);

    // ---- encodings ----
        internal static RPoint Deserialize(byte[]? bytes)
    {
        AssertBytes(bytes, "DeserializeElement");
        var p = RPoint.Decode(bytes!) ?? throw new ArgumentException("DeserializeElement: not a canonical ristretto255 encoding");
        if (p.IsIdentity) throw new ArgumentException("DeserializeElement: identity element is not a valid input");
        return p;
    }

    /// <summary>Deserialize then re-serialize an element (rejects the identity and any non-canonical encoding).</summary>
    public static byte[] ReserializeElement(byte[] bytes) => Deserialize(bytes).Encode();

    /// <summary>The 32-byte little-endian encoding of s mod L.</summary>
    public static byte[] SerializeScalar(BigInteger s)
    {
        var b = Mod(s, Order).ToByteArray(isUnsigned: true, isBigEndian: false);
        var o = new byte[ScalarBytes];
        Array.Copy(b, o, b.Length);
        return o;
    }

    /// <summary>Decode a 32-byte little-endian scalar; rejects any value >= L (one valid encoding per scalar).</summary>
    public static BigInteger DeserializeScalar(byte[]? bytes)
    {
        AssertBytes(bytes, "DeserializeScalar");
        if (bytes!.Length != ScalarBytes) throw new ArgumentException($"DeserializeScalar: expected {ScalarBytes} bytes, got {bytes.Length}");
        var n = LeInt(bytes);
        if (n >= Order) throw new ArgumentException("DeserializeScalar: non-canonical scalar (value >= group order)");
        return n;
    }

    // ---- group helpers ----
    static RPoint HashToGroupPoint(byte[] input, string mode) =>
        RPoint.FromUniformBytes(RPoint.ExpandMessageXmd(input, Pca.Cat(U8("HashToGroup-"), ContextString(mode)), 64));

    /// <summary>HashToGroup(input): the serialized element for the mode's domain-separation tag.</summary>
    public static byte[] HashToGroup(byte[] input, string mode) => HashToGroupPoint(input, mode).Encode();

    static BigInteger HashToScalarWithDst(byte[] input, byte[] dst) => Mod(LeInt(RPoint.ExpandMessageXmd(input, dst, 64)), Order);
    static BigInteger HashToScalar(byte[] input, string mode) => HashToScalarWithDst(input, Pca.Cat(U8("HashToScalar-"), ContextString(mode)));
    static RPoint ScalarBaseMult(BigInteger k) => RPoint.Base.Mul(Mod(k, Order));

    static BigInteger RandomScalar()
    {
        for (int attempt = 0; attempt < 8; attempt++)
        {
            var s = Mod(LeInt(RandomNumberGenerator.GetBytes(64)), Order);
            if (!s.IsZero) return s;
        }
        throw new InvalidOperationException("randomScalar: entropy source returned zero repeatedly (RNG failure); refusing to continue");
    }

    static BigInteger ScalarInvert(BigInteger s)
    {
        try { return RistrettoScalar.Invert(s); }
        catch (DivideByZeroException) { throw new ArgumentException("scalarInvert: inverse of zero"); }
    }

    // ---- keys ----
    /// <summary>DeriveKeyPair(seed, info): deterministic from a 32-byte seed, rejection-sampling a non-zero scalar.</summary>
    public static KeyPair DeriveKeyPair(byte[] seed, byte[] info, string mode)
    {
        if (seed == null || seed.Length != ScalarBytes) throw new ArgumentOutOfRangeException(nameof(seed), $"DeriveKeyPair: seed must be exactly {ScalarBytes} bytes");
        AssertBytes(info, "info", MaxFramed);
        var dst = Pca.Cat(U8("DeriveKeyPair"), ContextString(mode));
        var deriveInput = Pca.Cat(seed, I2osp(info.Length, 2), info);
        for (int counter = 0; counter <= 255; counter++)
        {
            var skS = HashToScalarWithDst(Pca.Cat(deriveInput, I2osp(counter, 1)), dst);
            if (!skS.IsZero) return new KeyPair(SerializeScalar(skS), ScalarBaseMult(skS).Encode());
        }
        throw new InvalidOperationException("DeriveKeyPair: failed to derive a non-zero key after 256 attempts");
    }

    public static KeyPair RandomKeyPair() { var s = RandomScalar(); return new KeyPair(SerializeScalar(s), ScalarBaseMult(s).Encode()); }

    public static byte[] PublicKeyFor(byte[] secretKey) => ScalarBaseMult(DeserializeScalar(secretKey)).Encode();

    // ---- DLEQ proof (RFC 9497 section 2.2) ----
    static byte[] Framed(byte[] b) => Pca.Cat(I2osp(b.Length, 2), b);

    static byte[] CompositesSeed(byte[] bSer, string mode)
    {
        var seedDst = Pca.Cat(U8("Seed-"), ContextString(mode));
        return SHA512.HashData(Pca.Cat(I2osp(bSer.Length, 2), bSer, I2osp(seedDst.Length, 2), seedDst));
    }

    static BigInteger CompositeCoefficient(byte[] seed, int index, byte[] cSer, byte[] dSer, string mode) =>
        HashToScalar(Pca.Cat(I2osp(seed.Length, 2), seed, I2osp(index, 2), I2osp(cSer.Length, 2), cSer, I2osp(dSer.Length, 2), dSer, U8("Composite")), mode);

    /// <summary>ComputeComposites for a single (C, D) pair (verifier path): (M, Z).</summary>
    static (RPoint M, RPoint Z) Composites(RPoint b, RPoint c, RPoint d, string mode)
    {
        var seed = CompositesSeed(b.Encode(), mode);
        var coeff = CompositeCoefficient(seed, 0, c.Encode(), d.Encode(), mode);
        return (c.MulUnsafe(coeff).Add(RPoint.Zero), d.MulUnsafe(coeff).Add(RPoint.Zero));
    }

    static (RPoint M, RPoint Z) CompositesFast(BigInteger k, RPoint b, RPoint c, RPoint d, string mode)
    {
        var seed = CompositesSeed(b.Encode(), mode);
        var coeff = CompositeCoefficient(seed, 0, c.Encode(), d.Encode(), mode);
        var m = c.MulUnsafe(coeff).Add(RPoint.Zero);
        return (m, m.Mul(Mod(k, Order)));
    }

    static BigInteger Challenge(RPoint b, RPoint m, RPoint z, RPoint t2, RPoint t3, string mode) =>
        HashToScalar(Pca.Cat(Framed(b.Encode()), Framed(m.Encode()), Framed(z.Encode()), Framed(t2.Encode()), Framed(t3.Encode()), U8("Challenge")), mode);

    static byte[] GenerateProof(BigInteger k, RPoint a, RPoint b, RPoint c, RPoint d, string mode, byte[]? fixedRandomness)
    {
        var (m, z) = CompositesFast(k, b, c, d, mode);
        var r = fixedRandomness == null ? RandomScalar() : DeserializeScalar(fixedRandomness);
        var t2 = a.Mul(r);
        var t3 = m.Mul(r);
        var cc = Challenge(b, m, z, t2, t3, mode);
        var s = RistrettoScalar.Sub(r, RistrettoScalar.Mul(cc, k));
        return Pca.Cat(SerializeScalar(cc), SerializeScalar(s));
    }

    static bool VerifyProof(RPoint a, RPoint b, RPoint c, RPoint d, byte[] proof, string mode)
    {
        if (proof.Length != 2 * ScalarBytes) return false;
        var cc = DeserializeScalar(proof[..ScalarBytes]);
        var s = DeserializeScalar(proof[ScalarBytes..]);
        var (m, z) = Composites(b, c, d, mode);
        var t2 = a.MulUnsafe(s).Add(b.MulUnsafe(cc));
        var t3 = m.MulUnsafe(s).Add(z.MulUnsafe(cc));
        var expected = Challenge(b, m, z, t2, t3, mode);
        return Mod(expected - cc, Order).IsZero;
    }

    static byte[] FinalizeHash(byte[] input, byte[] issued) =>
        SHA512.HashData(Pca.Cat(I2osp(input.Length, 2), input, I2osp(issued.Length, 2), issued, U8("Finalize")));

    static byte[] FinalizeHashPoprf(byte[] input, byte[] info, byte[] issued) =>
        SHA512.HashData(Pca.Cat(I2osp(input.Length, 2), input, I2osp(info.Length, 2), info, I2osp(issued.Length, 2), issued, U8("Finalize")));

    // ---- OPRF / VOPRF ----
    /// <summary>Blind(input): r*HashToGroup(input) with r random (or the fixed 32-byte scalar). Throws when the input maps to the identity.</summary>
    public static BlindResult Blind(byte[] input, string mode = "oprf", byte[]? fixedBlind = null)
    {
        AssertBytes(input, "Blind(input)", MaxFramed);
        var r = fixedBlind == null ? RandomScalar() : DeserializeScalar(fixedBlind);
        var inputElement = HashToGroupPoint(input, mode);
        if (inputElement.IsIdentity) throw new InvalidOperationException("Blind: input maps to identity");
        return new BlindResult(SerializeScalar(r), inputElement.Mul(r).Encode());
    }

    /// <summary>BlindEvaluate: sk * blinded; for any mode other than "oprf" the evaluation carries a DLEQ proof (the reference takes the VOPRF path for every other mode string).</summary>
    public static EvaluateResult BlindEvaluate(byte[] secretKey, byte[] blindedElement, string mode = "oprf", byte[]? publicKey = null, byte[]? fixedProofRandomness = null)
    {
        var skS = DeserializeScalar(secretKey);
        var r = Deserialize(blindedElement);
        var evaluated = r.Mul(skS);
        if (mode == "oprf") return new EvaluateResult(evaluated.Encode());
        var pk = publicKey == null ? ScalarBaseMult(skS) : Deserialize(publicKey);
        var proof = GenerateProof(skS, RPoint.Base, pk, r, evaluated, "voprf", fixedProofRandomness);
        return new EvaluateResult(evaluated.Encode(), proof);
    }

    /// <summary>Finalize: unblind and hash. For "voprf" a proof, the server public key and the blinded element are required and the proof must verify.</summary>
    public static byte[] Finalize(byte[] input, byte[] blindScalar, byte[] evaluatedElement, string mode = "oprf", byte[]? proof = null, byte[]? publicKey = null, byte[]? blindedElement = null)
    {
        AssertBytes(input, "Finalize(input)", MaxFramed);
        var r = DeserializeScalar(blindScalar);
        var evaluated = Deserialize(evaluatedElement);
        if (mode == "voprf")
        {
            if (proof == null || publicKey == null || blindedElement == null) throw new ArgumentException("Finalize(voprf): proof, publicKey and blindedElement are required");
            var pk = Deserialize(publicKey);
            var blinded = Deserialize(blindedElement);
            if (!VerifyProof(RPoint.Base, pk, blinded, evaluated, proof, "voprf")) throw new CryptographicException("Finalize(voprf): DLEQ proof verification failed");
        }
        return FinalizeHash(input, evaluated.Mul(ScalarInvert(r)).Encode());
    }

    /// <summary>Evaluate(sk, input): the PRF output computed directly by the key holder.</summary>
    public static byte[] Evaluate(byte[] secretKey, byte[] input, string mode = "oprf")
    {
        AssertBytes(input, "Evaluate(input)", MaxFramed);
        var skS = DeserializeScalar(secretKey);
        var inputElement = HashToGroupPoint(input, mode);
        if (inputElement.IsIdentity) throw new InvalidOperationException("Evaluate: input maps to identity");
        return FinalizeHash(input, inputElement.Mul(skS).Encode());
    }

    // ---- POPRF ----
    static BigInteger PoprfInfoScalar(byte[] info)
    {
        AssertBytes(info, "info", MaxFramed);
        return HashToScalar(Pca.Cat(U8("Info"), I2osp(info.Length, 2), info), "poprf");
    }

    public static PoprfBlindResult BlindPoprf(byte[] input, byte[] info, byte[] publicKey, byte[]? fixedBlind = null)
    {
        AssertBytes(input, "Blind(input)", MaxFramed);
        var m = PoprfInfoScalar(info);
        var tweaked = ScalarBaseMult(m).Add(Deserialize(publicKey));
        if (tweaked.IsIdentity) throw new InvalidOperationException("Blind(poprf): tweaked key is identity");
        var b = Blind(input, "poprf", fixedBlind);
        return new PoprfBlindResult(b.Blind, b.BlindedElement, tweaked.Encode());
    }

    public static EvaluateResult BlindEvaluatePoprf(byte[] secretKey, byte[] blindedElement, byte[] info, byte[]? fixedProofRandomness = null)
    {
        var skS = DeserializeScalar(secretKey);
        var m = PoprfInfoScalar(info);
        var t = Mod(skS + m, Order);
        if (t.IsZero) throw new InvalidOperationException("BlindEvaluate(poprf): inverse of zero (bad info/key)");
        var blinded = Deserialize(blindedElement);
        var evaluated = blinded.Mul(ScalarInvert(t));
        var tweakedKey = ScalarBaseMult(t);
        var proof = GenerateProof(t, RPoint.Base, tweakedKey, evaluated, blinded, "poprf", fixedProofRandomness);
        return new EvaluateResult(evaluated.Encode(), proof);
    }

    public static byte[] FinalizePoprf(byte[] input, byte[] blindScalar, byte[] evaluatedElement, byte[] info, byte[]? proof, byte[]? blindedElement, byte[]? tweakedKey)
    {
        AssertBytes(input, "Finalize(input)", MaxFramed);
        AssertBytes(info, "info", MaxFramed);
        var r = DeserializeScalar(blindScalar);
        var evaluated = Deserialize(evaluatedElement);
        var blinded = Deserialize(blindedElement);
        var tweaked = Deserialize(tweakedKey);
        if (proof == null || !VerifyProof(RPoint.Base, tweaked, evaluated, blinded, proof, "poprf")) throw new CryptographicException("Finalize(poprf): DLEQ proof verification failed");
        return FinalizeHashPoprf(input, info, evaluated.Mul(ScalarInvert(r)).Encode());
    }

    public static byte[] EvaluatePoprf(byte[] secretKey, byte[] input, byte[] info)
    {
        AssertBytes(input, "Evaluate(input)", MaxFramed);
        var skS = DeserializeScalar(secretKey);
        var m = PoprfInfoScalar(info);
        var t = Mod(skS + m, Order);
        if (t.IsZero) throw new InvalidOperationException("Evaluate(poprf): inverse of zero (bad info/key)");
        var inputElement = HashToGroupPoint(input, "poprf");
        if (inputElement.IsIdentity) throw new InvalidOperationException("Evaluate(poprf): input maps to identity");
        return FinalizeHashPoprf(input, info, inputElement.Mul(ScalarInvert(t)).Encode());
    }

    public static string ToHex(byte[] bytes) => Convert.ToHexString(bytes).ToLowerInvariant();

    public static bool BytesEqual(byte[] a, byte[] b) => a.Length == b.Length && CryptographicOperations.FixedTimeEquals(a, b);
}

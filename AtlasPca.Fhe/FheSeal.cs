using System.Text.RegularExpressions;
using Microsoft.Research.SEAL;

namespace AtlasPca.Fhe;

/// <summary>The public gate policy: fixed-point weights, kappa-weighted weights and the budget bound, all at scale S (budget at S^2).</summary>
public sealed record FheRiskPolicy(long Scale, long Dim, long[] WeightsScaled, long[] KappaWeightsScaled, long BudgetScaled, double Kappa);

/// <summary>Full key material. The key holder keeps SecretKey; the evaluator only ever gets public key, relin keys and Galois keys.</summary>
public sealed record FheKeyset(string SecretKey, string PublicKey, string RelinKeys, string GaloisKeys);

/// <summary>The keys an evaluator is given (no secret key).</summary>
public sealed record FheEvalKeys(string PublicKey, string RelinKeys, string GaloisKeys);

/// <summary>The two encrypted gate outputs, each a base64 SEAL stream.</summary>
public sealed record EncryptedGate(string EncRiskRaw, string EncSlack);

/// <summary>The opened verdict: RScaled is r at scale S^2 clamped to [0,S^2]; Admit is slack &gt;= 0.</summary>
public sealed record Verdict(long RScaled, long Slack, bool Admit);

/// <summary>
/// Homomorphic evaluation of PCA's risk gate (BFV on Microsoft SEAL), the same circuit as the TypeScript reference: encrypted inputs times
/// public weights, summed across slots with Galois rotations, budget folded in with a plaintext negate and add. SEAL objects cross the API as
/// base64 of the SEAL native stream, byte-compatible with node-seal.
/// </summary>
public static class FheSeal
{
    public const int PolyModulusDegree = 8192;
    public const int PlainModulusBits = 30;
    public const long PlainModulus = 1_073_692_673;
    public const long SignedBound = PlainModulus / 2;
    public const int RiskDim = 6;
    const int MinNoiseBudgetBits = 16;
    static readonly Regex B64 = new("^[A-Za-z0-9+/]*={0,2}$", RegexOptions.Compiled);

    /// <summary>Reject anything that is not a well-formed SEAL stream envelope (magic, header size, compression mode, declared size == length) before SEAL parses it.</summary>
    public static byte[] AssertSealBlob(string blob, string what)
    {
        if (blob is null || blob.Length < 24 || blob.Length % 4 != 0 || !B64.IsMatch(blob))
            throw new ArgumentException($"{what}: not a serialized SEAL object (bad encoding)");
        var b = Convert.FromBase64String(blob);
        if (b.Length < 16 || b[0] != 0x5e || b[1] != 0xa1 || b[2] != 16 || b[5] > 2 || b[6] != 0 || b[7] != 0)
            throw new ArgumentException($"{what}: not a serialized SEAL object (bad header)");
        ulong size = BitConverter.ToUInt64(b, 8);
        if (!BitConverter.IsLittleEndian) size = System.Buffers.Binary.BinaryPrimitives.ReverseEndianness(size);
        if (size != (ulong)b.Length)
            throw new ArgumentException($"{what}: truncated or padded SEAL object (declared {size} bytes, got {b.Length})");
        return b;
    }

    /// <summary>The policy crosses a trust boundary: validate every coefficient exactly as the policy builder would have produced it.</summary>
    public static void RequirePolicy(FheRiskPolicy policy)
    {
        ArgumentNullException.ThrowIfNull(policy);
        if (policy.Scale <= 0) throw new ArgumentException("policy.Scale must be a positive integer");
        if (policy.WeightsScaled is null || policy.KappaWeightsScaled is null) throw new ArgumentException("policy weight vectors are required");
        foreach (var v in policy.WeightsScaled.Concat(policy.KappaWeightsScaled).Append(policy.BudgetScaled))
            if (v <= -SignedBound || v >= SignedBound) throw new ArgumentException("policy coefficients must be integers with |value| < SignedBound");
        if (policy.Dim != RiskDim) throw new ArgumentException($"policy.Dim must be {RiskDim}");
        if (policy.WeightsScaled.Length != RiskDim || policy.KappaWeightsScaled.Length != RiskDim)
            throw new ArgumentException($"policy weight vectors must have length {RiskDim}");
    }

    /// <summary>The deterministic BFV context (N=8192, BFVDefault 128-bit coefficient modulus, batching plain modulus) with its batch encoder.</summary>
    public sealed class Ctx : IDisposable
    {
        public SEALContext Context { get; }
        public BatchEncoder Encoder { get; }
        public int SlotCount { get; }
        Ctx(SEALContext c, BatchEncoder e) { Context = c; Encoder = e; SlotCount = (int)e.SlotCount; }

        public static Ctx Create()
        {
            using var parms = new EncryptionParameters(SchemeType.BFV);
            parms.PolyModulusDegree = PolyModulusDegree;
            parms.CoeffModulus = CoeffModulus.BFVDefault(PolyModulusDegree, SecLevelType.TC128);
            using var plain = PlainModulus_();
            parms.PlainModulus = plain;
            var live = plain.Value;
            var ctx = new SEALContext(parms, true, SecLevelType.TC128);
            if (!ctx.ParametersSet) { ctx.Dispose(); throw new InvalidOperationException("SEAL rejected the BFV parameters"); }
            if (live != (ulong)PlainModulus) { ctx.Dispose(); throw new InvalidOperationException($"plain modulus drift: live {live} != documented {PlainModulus}"); }
            return new Ctx(ctx, new BatchEncoder(ctx));
        }

        static Modulus PlainModulus_() => Microsoft.Research.SEAL.PlainModulus.Batching(PolyModulusDegree, PlainModulusBits);

        public void Dispose() { Encoder.Dispose(); Context.Dispose(); }
    }

    static string B64Of(Func<Stream, long> save) { using var ms = new MemoryStream(); save(ms); return Convert.ToBase64String(ms.ToArray()); }

    static T Load<T>(Ctx ctx, string blob, string what, T obj, Func<T, Stream, long> load)
    {
        var bytes = AssertSealBlob(blob, what);
        using var ms = new MemoryStream(bytes);
        load(obj, ms);
        return obj;
    }

    static Plaintext Encode(Ctx ctx, IReadOnlyList<long> values)
    {
        var slots = new long[ctx.SlotCount];
        for (int k = 0; k < values.Count; k++) slots[k] = values[k];
        var pt = new Plaintext();
        ctx.Encoder.Encode(slots, pt);
        return pt;
    }

    /// <summary>Generate the key material (secret key stays with the policy owner).</summary>
    public static FheKeyset Keygen()
    {
        using var ctx = Ctx.Create();
        using var gen = new KeyGenerator(ctx.Context);
        using var sk = gen.SecretKey;
        gen.CreatePublicKey(out PublicKey pk);
        gen.CreateRelinKeys(out RelinKeys rk);
        gen.CreateGaloisKeys(out GaloisKeys gk);
        using (pk) using (rk) using (gk)
            return new FheKeyset(B64Of(s => sk.Save(s)), B64Of(s => pk.Save(s)), B64Of(s => rk.Save(s)), B64Of(s => gk.Save(s)));
    }

    /// <summary>BFV-encrypt the quantized risk-input vector (length 6, each a non-negative integer below the signed bound) under the public key.</summary>
    public static string EncryptRiskInputs(string publicKey, IReadOnlyList<long> inputsScaled)
    {
        ArgumentNullException.ThrowIfNull(inputsScaled);
        if (inputsScaled.Count != RiskDim) throw new ArgumentException($"inputsScaled must have length {RiskDim}");
        foreach (var v in inputsScaled)
            if (v < 0 || v >= SignedBound) throw new ArgumentException("each scaled input must be a non-negative integer below the signed bound");
        using var ctx = Ctx.Create();
        using var pk = Load(ctx, publicKey, "publicKey", new PublicKey(), (o, s) => o.Load(ctx.Context, s));
        using var enc = new Encryptor(ctx.Context, pk);
        using var plain = Encode(ctx, inputsScaled);
        using var ct = new Ciphertext();
        enc.Encrypt(plain, ct);
        return B64Of(s => ct.Save(s));
    }

    /// <summary>
    /// Evaluate the gate blind: encRiskRaw = sum(x * w), encSlack = budget - sum(x * kappa*w), all on ciphertext. Never constructs a Decryptor.
    /// Same operation order as the reference: multiplyPlain, sumElements (rotateColumns+add, then rotateRows/rotateColumns/add for steps N/4..1),
    /// negate, addPlain.
    /// </summary>
    public static EncryptedGate EvalRiskGate(FheEvalKeys evalKeys, string encInputs, FheRiskPolicy policy)
    {
        RequirePolicy(policy);
        ArgumentNullException.ThrowIfNull(evalKeys);
        using var ctx = Ctx.Create();
        using var gk = Load(ctx, evalKeys.GaloisKeys, "galoisKeys", new GaloisKeys(), (o, s) => o.Load(ctx.Context, s));
        using var pk = Load(ctx, evalKeys.PublicKey, "publicKey", new PublicKey(), (o, s) => o.Load(ctx.Context, s));
        using var ev = new Evaluator(ctx.Context);
        using var enc = new Encryptor(ctx.Context, pk);
        using var x = Load(ctx, encInputs, "encInputs", new Ciphertext(), (o, s) => o.Load(ctx.Context, s));

        Ciphertext Sum(Ciphertext prod)
        {
            var temp = new Ciphertext(prod);
            using var dest = new Ciphertext();
            ev.RotateColumns(temp, gk, dest);
            ev.Add(temp, dest, temp);
            for (int steps = PolyModulusDegree / 4; steps >= 1; steps /= 2)
            {
                ev.RotateRows(temp, steps, gk, dest);
                ev.RotateColumns(dest, gk, dest);
                ev.Add(temp, dest, temp);
            }
            return temp;
        }

        // SEAL refuses multiplyPlain by an all-zero plaintext (transparent result); the dot product is then a fresh encryption of zero.
        Ciphertext Dot(long[] coeffs)
        {
            if (coeffs.All(c => c == 0))
            {
                using var z = Encode(ctx, Array.Empty<long>());
                var zero = new Ciphertext();
                enc.Encrypt(z, zero);
                return zero;
            }
            using var pt = Encode(ctx, coeffs);
            using var prod = new Ciphertext();
            ev.MultiplyPlain(x, pt, prod);
            return Sum(prod);
        }

        using var riskRaw = Dot(policy.WeightsScaled);
        using var kappaRisk = Dot(policy.KappaWeightsScaled);
        using var neg = new Ciphertext();
        ev.Negate(kappaRisk, neg);
        using var budget = Encode(ctx, new[] { policy.BudgetScaled });
        using var slack = new Ciphertext();
        ev.AddPlain(neg, budget, slack);
        return new EncryptedGate(B64Of(s => riskRaw.Save(s)), B64Of(s => slack.Save(s)));
    }

    /// <summary>The outcome of <see cref="EvalSignedRiskClaim"/>: the blind gate output and the digest of the signed claim, or the reason it was refused.</summary>
    public sealed record SignedEval(bool Ok, EncryptedGate? Gate, string? ClaimDigest, string? Reason);

    /// <summary>Evaluator: verify the signed claim, then run the gate. The ciphertext is not loaded into SEAL unless the signature, signer, context, binding, policy and nonce all
    /// check out. <see cref="EvalRiskGate"/> stays the low-level primitive; the PCA claim path has no unsigned entry.</summary>
    public static SignedEval EvalSignedRiskClaim(FheEvalKeys evalKeys, object? signed, FheParts.FheOrigin.ClaimExpectations exp)
    {
        var chk = FheParts.FheOrigin.VerifySignedRiskClaim(signed, exp);
        if (!chk.Ok) return new SignedEval(false, null, null, chk.Reason);
        try
        {
            var claim = chk.Claim!;
            var p = (Dictionary<string, object?>)claim["policy"]!;
            static long L(object? v) => (long)Js.JsJson.ToJsNumber(v);
            static long[] Ls(object? v) => ((List<object?>)v!).Select(L).ToArray();
            var policy = new FheRiskPolicy(L(p["scale"]), L(p["dim"]), Ls(p["weightsScaled"]), Ls(p["kappaWeightsScaled"]), L(p["budgetScaled"]), Js.JsJson.ToJsNumber(p["kappa"]));
            return new SignedEval(true, EvalRiskGate(evalKeys, (string)claim["encInputs"]!, policy), chk.Digest, null);
        }
        catch (Exception e) { return new SignedEval(false, null, null, "evaluation failed: " + e.Message); }
    }

    /// <summary>Decrypt the gate outputs with the secret key and read the verdict; fails closed when the noise budget is exhausted (wrong key, corrupt or foreign ciphertext).</summary>
    public static Verdict DecryptVerdict(string secretKey, string encRiskRaw, string encSlack, FheRiskPolicy policy)
    {
        RequirePolicy(policy);
        using var ctx = Ctx.Create();
        using var sk = Load(ctx, secretKey, "secretKey", new SecretKey(), (o, s) => o.Load(ctx.Context, s));
        using var dec = new Decryptor(ctx.Context, sk);
        using var ctR = Load(ctx, encRiskRaw, "encRiskRaw", new Ciphertext(), (o, s) => o.Load(ctx.Context, s));
        using var ctS = Load(ctx, encSlack, "encSlack", new Ciphertext(), (o, s) => o.Load(ctx.Context, s));
        if (dec.InvariantNoiseBudget(ctR) < MinNoiseBudgetBits || dec.InvariantNoiseBudget(ctS) < MinNoiseBudgetBits)
            throw new InvalidOperationException("DecryptVerdict: ciphertext has no noise budget left (wrong key, corrupted, or not produced by the gate)");
        long First(Ciphertext c)
        {
            using var pt = new Plaintext();
            dec.Decrypt(c, pt);
            var o = new List<long>();
            ctx.Encoder.Decode(pt, o);
            return o.Count > 0 ? o[0] : 0;
        }
        long raw = First(ctR), slack = First(ctS), cap = policy.Scale * policy.Scale;
        return new Verdict(raw < 0 ? 0 : raw > cap ? cap : raw, slack, slack >= 0);
    }

    /// <summary>Re-save a base64 SEAL ciphertext uncompressed, for byte comparison independent of the zstd build.</summary>
    public static byte[] CanonicalCipher(string blob)
    {
        using var ctx = Ctx.Create();
        using var ct = Load(ctx, blob, "ciphertext", new Ciphertext(), (o, s) => o.Load(ctx.Context, s));
        using var ms = new MemoryStream();
        ct.Save(ms, ComprModeType.None);
        return ms.ToArray();
    }
}

using System.Runtime.InteropServices;
using System.Text;

namespace AtlasPca.Zk;

/// <summary>libpcazk could not be loaded, or it reported a usage or internal error. Never mapped to "invalid proof": a missing or failing library fails loudly.</summary>
public sealed class ZkNativeException(string message, Exception? inner = null) : InvalidOperationException(message, inner);

/// <summary>Proving failed. <see cref="Code"/> is the library's code: -3 the witness does not satisfy the circuit (or the zkey is not one the prover reads),
/// -4 the witness program failed or the input does not fit the circuit, -5 the zkey is malformed or for another curve, -6 the input is not a JSON object.</summary>
public sealed class ZkProveException(int code, string message) : Exception(message)
{
    public int Code { get; } = code;
}

/// <summary>The pairing curve of a Groth16 key and proof.</summary>
public enum ZkCurve
{
    Bn254 = 0,
    Bls12381 = 1,
}

/// <summary>The verdict of <see cref="ZkNative.Verify(ZkCurve, byte[], byte[], byte[], bool)"/>. <see cref="Reason"/> is 0 for a valid proof, else why it was refused:
/// 1 bad_json, 2 bad_protocol, 3 bad_curve, 4 bad_encoding, 5 not_in_subgroup, 6 not_affine, 7 bad_shape, 8 signal_count, 9 ic_short, 10 pairing_failed.</summary>
public sealed record ZkVerdict(bool Valid, int Reason, string ReasonText);

/// <summary>
/// Groth16 over libpcazk (arkworks behind a small C library): verification and proving for snarkjs / circom artifacts on BN254 and BLS12-381.
/// Inputs are UTF-8 JSON in the snarkjs encoding (decimal-string field elements, G1 [x, y, "1"], G2 [[x0, x1], [y0, y1], ["1", "0"]]).
/// The library decides the pairing question only: the caller keeps its own checks of the envelope, the circuit and the public-signal pins in front.
/// <see cref="Register"/> makes it the engine of <see cref="ZkCompliance"/>, which runs those checks.
/// </summary>
public static unsafe class ZkNative
{
    internal const string Lib = "pcazk";
    const uint FlagSnarkjsCompat = 1;
    const int Valid = 1, Invalid = 0, ErrArg = -1, SeedBytes = 32;

    [DllImport(Lib)] static extern byte* pca_zk_version();
    [DllImport(Lib)] static extern byte* pca_zk_reason_text(int reason);
    [DllImport(Lib)]
    static extern int pca_zk_verify(int curve, uint flags, byte* vkey, nuint vkeyLen, byte* proof, nuint proofLen, byte* signals, nuint signalsLen, int* reason);
    [DllImport(Lib)]
    static extern int pca_zk_prove(int curve, byte* wasm, nuint wasmLen, byte* zkey, nuint zkeyLen, byte* input, nuint inputLen, byte* seed, nuint seedLen, byte** output, nuint* outputLen);
    [DllImport(Lib)] static extern void pca_zk_free(byte* ptr, nuint len);

    static ZkNativeException Missing(Exception e) =>
        new("libpcazk could not be loaded (set ATLAS_PCA_LIBPCAZK to the shared library): " + e.Message, e);

    static bool IsLoadFailure(Exception e) => e is DllNotFoundException or EntryPointNotFoundException or BadImageFormatException;

    static byte[] NonEmpty(byte[]? b, string name) =>
        b is { Length: > 0 } ? b : throw new ArgumentException(name + " must not be empty", name);

    /// <summary>The library version. Throws <see cref="ZkNativeException"/> when libpcazk does not load.</summary>
    public static string Version()
    {
        try { return Marshal.PtrToStringUTF8((nint)pca_zk_version()) ?? throw new ZkNativeException("libpcazk reports no version"); }
        catch (Exception e) when (IsLoadFailure(e)) { throw Missing(e); }
    }

    sealed class NativeEngine : IGroth16Engine
    {
        static ZkCurve Curve(string curve) => curve switch
        {
            ZkCompliance.CurveBn254 => ZkCurve.Bn254,
            ZkCompliance.CurveBls12381 => ZkCurve.Bls12381,
            _ => throw new ArgumentException("unknown curve " + curve, nameof(curve)),
        };

        public bool Verify(string curve, string vkeyJson, string publicSignalsJson, string proofJson, bool strict) =>
            ZkNative.Verify(Curve(curve), vkeyJson, proofJson, publicSignalsJson, strict).Valid;

        public string Prove(string curve, byte[] wasm, byte[] zkey, string inputJson) => ZkNative.Prove(Curve(curve), wasm, zkey, Encoding.UTF8.GetBytes(inputJson));
    }

    /// <summary>This library as a Groth16 engine: the default mode unless the caller asks for strict, a missing library an exception.</summary>
    public static IGroth16Engine Engine { get; } = new NativeEngine();

    /// <summary>Makes this library the Groth16 engine of <see cref="ZkCompliance"/> (its proof verification and provers), process-wide.</summary>
    public static void Register() => ZkCompliance.RegisterGroth16Engine(Engine);

    /// <summary>True when libpcazk loads.</summary>
    public static bool Available()
    {
        try { return Version().Length > 0; } catch (ZkNativeException) { return false; }
    }

    /// <summary>
    /// Verifies a snarkjs Groth16 proof: <paramref name="vkeyJson"/> is the verification key object, <paramref name="proofJson"/> the proof object and
    /// <paramref name="signalsJson"/> the array of public signals as decimal strings. By default it accepts what the reference verifier accepts (the key's
    /// protocol and nPublic and the proof's protocol / curve members are ignored, IC entries beyond signals + 1 are not read); <paramref name="strict"/> also
    /// requires those to agree. Field, group and subgroup checks are on in both modes. An invalid proof is a verdict; a library that is missing or
    /// reports an error throws <see cref="ZkNativeException"/>.
    /// </summary>
    public static ZkVerdict Verify(ZkCurve curve, byte[] vkeyJson, byte[] proofJson, byte[] signalsJson, bool strict = false)
    {
        NonEmpty(vkeyJson, nameof(vkeyJson));
        NonEmpty(proofJson, nameof(proofJson));
        NonEmpty(signalsJson, nameof(signalsJson));
        int rc, reason = 0;
        string text;
        try
        {
            fixed (byte* k = vkeyJson, p = proofJson, s = signalsJson)
                rc = pca_zk_verify((int)curve, strict ? 0 : FlagSnarkjsCompat, k, (nuint)vkeyJson.Length, p, (nuint)proofJson.Length, s, (nuint)signalsJson.Length, &reason);
            if (rc != Valid && rc != Invalid) throw new ZkNativeException($"libpcazk verify reported error {rc}");
            text = Marshal.PtrToStringUTF8((nint)pca_zk_reason_text(reason)) ?? "unknown";
        }
        catch (Exception e) when (IsLoadFailure(e)) { throw Missing(e); }
        // a verdict of valid with a refusal reason (or the reverse) is a library fault, never a pass
        if ((rc == Valid) != (reason == 0)) throw new ZkNativeException($"libpcazk verify returned {rc} with reason {reason}");
        return new ZkVerdict(rc == Valid, reason, text);
    }

    /// <summary><see cref="Verify(ZkCurve, byte[], byte[], byte[], bool)"/> over JSON text.</summary>
    public static ZkVerdict Verify(ZkCurve curve, string vkeyJson, string proofJson, string signalsJson, bool strict = false) =>
        Verify(curve, Encoding.UTF8.GetBytes(vkeyJson), Encoding.UTF8.GetBytes(proofJson), Encoding.UTF8.GetBytes(signalsJson), strict);

    /// <summary>
    /// Proves: runs the circom witness program <paramref name="wasm"/> over the input JSON object, reads the snarkjs <paramref name="zkey"/> (the whole file, in
    /// memory) and proves with Groth16. Returns the JSON text <c>{"proof": {...}, "publicSignals": [...]}</c>. <paramref name="seed"/> (exactly 32 bytes) makes the
    /// blinding deterministic and is for tests only; null uses operating-system randomness. Throws <see cref="ZkProveException"/> when proving fails.
    /// </summary>
    public static string Prove(ZkCurve curve, byte[] wasm, byte[] zkey, byte[] inputJson, byte[]? seed = null)
    {
        NonEmpty(wasm, nameof(wasm));
        NonEmpty(zkey, nameof(zkey));
        NonEmpty(inputJson, nameof(inputJson));
        if (seed != null && seed.Length != SeedBytes) throw new ArgumentException("the seed must be 32 bytes", nameof(seed));
        int rc;
        byte* output = null;
        nuint outputLen = 0;
        try
        {
            fixed (byte* w = wasm, z = zkey, i = inputJson, sd = seed)
                rc = pca_zk_prove((int)curve, w, (nuint)wasm.Length, z, (nuint)zkey.Length, i, (nuint)inputJson.Length, sd, (nuint)(seed?.Length ?? 0), &output, &outputLen);
        }
        catch (Exception e) when (IsLoadFailure(e)) { throw Missing(e); }
        string text;
        try { text = output == null ? "" : Encoding.UTF8.GetString(output, checked((int)outputLen)); }
        finally { if (output != null) pca_zk_free(output, outputLen); }
        if (rc == 0) return text;
        if (rc == ErrArg || rc == -2) throw new ZkNativeException($"libpcazk prove reported error {rc}" + (text.Length > 0 ? ": " + text : ""));
        throw new ZkProveException(rc, text.Length > 0 ? text : $"proving failed ({rc})");
    }
}

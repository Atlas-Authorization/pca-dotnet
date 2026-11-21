// Public names of the TypeScript core that this SDK carried only as private or inline helpers: the wire length limits, the PCActn
// version and lifetime limits, the provenance levels, the hash and base64url helpers of the hash module, PCActn decoding and the
// small DER / PEM helpers of the hardware attestation verifiers. Each is the same value or function as its reference namesake.
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using JD = System.Collections.Generic.Dictionary<string, object?>;

namespace AtlasPca;

public static partial class PcaConstants
{
    /// <summary>The longest verifier audience and the longest replay nonce a PCActn may carry (UTF-8 bytes).</summary>
    public const int MaxAudLen = 256, MaxNonceLen = 128;

    /// <summary>The PCActn wire version, its longest lifetime and the clock skew a verifier allows (milliseconds).</summary>
    public const int PcactnVersion = PcactnWireVersion;
    public const long PcactnMaxLifetimeMs = 3_600_000, PcactnMaxSkewMs = 60_000;

    /// <summary>The provenance levels of an argument, most trusted first.</summary>
    public static IReadOnlyList<string> ProvLevels { get; } = new[] { "trusted", "first_party", "tool", "web", "agent" };
}

public static partial class PcaHelpers
{
    /// <summary>UTF-8 bytes of a string.</summary>
    public static byte[] Utf8(string s) => Encoding.UTF8.GetBytes(s);

    /// <summary>SHA-256 / SHA-384 digests.</summary>
    public static byte[] Sha256(byte[] bytes) => SHA256.HashData(bytes);
    public static byte[] Sha384(byte[] bytes) => SHA384.HashData(bytes);

    /// <summary>Unpadded base64url decode that throws on anything the strict decoder refuses (the reference <c>unb64u</c>).</summary>
    public static byte[] Unb64u(string s) => Pca.B64uDecode(s) ?? throw new FormatException("unb64u: not canonical base64url");

    /// <summary>Public key to wire text and back (the reference <c>encodeKey</c> / <c>decodeKey</c>: base64url).</summary>
    public static string EncodeKey(byte[] key) => Pca.B64u(key);
    public static byte[] DecodeKey(string s) => Unb64u(s);

    /// <summary>A JSON object (not null, not an array, not a scalar).</summary>
    public static bool IsPlainObject(object? v) => v is JD;

    /// <summary>Decode a PCActn artifact: the size limit is checked FIRST, then a strict parse; the value must be an object.</summary>
    public static JD DecodePcactn(string s)
    {
        if (Pca.ArtifactTooLarge(s)) throw new ArgumentOutOfRangeException(nameof(s), Pca.ArtifactSizeReason);
        return Pca.ParseStrict(s) as JD ?? throw new ArgumentException("decodePCActn: not an object");
    }

    /// <summary>The epoch milliseconds of an ASN.1 UTCTime (tag 0x17) or GeneralizedTime (tag 0x18) text, NaN for anything malformed.</summary>
    public static double ParseDerTime(int tag, string text)
    {
        var r = AttestDer.ParseDerTime(tag, text);
        return r.Ok ? r.Ms : double.NaN;
    }

    /// <summary>The DER bytes of the first PEM certificate of a text; throws when there is none.</summary>
    public static byte[] PemToDer(string pem)
    {
        var m = Regex.Match(pem, "-----BEGIN CERTIFICATE-----([\\s\\S]*?)-----END CERTIFICATE-----");
        if (!m.Success || m.Groups[1].Length == 0) throw new ArgumentOutOfRangeException(nameof(pem), "pemToDer: no certificate found");
        return Convert.FromBase64String(Regex.Replace(m.Groups[1].Value, "\\s+", ""));
    }
    /// <summary>SHA-256 of bytes as unpadded base64url.</summary>
    public static string Sha256B64u(byte[] bytes) => Pca.B64u(SHA256.HashData(bytes));

    /// <summary>The public-key rule of the reference <c>rsaKeyOk</c>: an RSA key is accepted only with a 512 to 16384 bit modulus and an odd public exponent of 2 to 32 bits (anything else, or a key that cannot be exported, is refused).</summary>
    public static bool RsaKeyOk(RSA key)
    {
        try
        {
            var p = key.ExportParameters(false);
            return p.Modulus != null && p.Exponent != null && AttestCerts.RsaKeyOk(p.Modulus, p.Exponent);
        }
        catch (CryptographicException) { return false; }
    }

    /// <summary>Run <paramref name="fn"/> against a deadline: its boolean answer, or null (unknown) when it answers anything else, throws or does not finish in time.</summary>
    public static async Task<bool?> Settle(Func<Task<object?>> fn, int timeoutMs)
    {
        try
        {
            var work = Task.Run(fn);
            var done = await Task.WhenAny(work, Task.Delay(timeoutMs)).ConfigureAwait(false);
            if (done != work) return null;
            var r = await work.ConfigureAwait(false);
            return r is bool b ? (bool?)b : null;
        }
        catch (Exception) { return null; }
    }
}

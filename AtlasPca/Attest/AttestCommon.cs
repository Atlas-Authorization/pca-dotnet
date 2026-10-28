// Hardware attestation verifiers (AMD SEV-SNP, Intel TDX DCAP, Azure MAA, Google Confidential Space, NVIDIA GPU SPDM): shared
// types. The vendor verifiers answer exactly what the reference verifiers of @atlasauth/pca answer, reason text included, and
// fail closed on anything they cannot establish.
using JD = System.Collections.Generic.Dictionary<string, object?>;

namespace AtlasPca;

/// <summary>What a vendor quote's bound value must equal: the server-known holder key, grant, epoch and nonce. Epoch is a double
/// because the wire form carries a JSON number; only a non-negative safe integer is constructible into a binding.</summary>
public sealed record AttestationBinding(string HolderPub, string GrantRef, double Epoch, string Nonce);

/// <summary>A vendor verifier's answer (the reference <c>HardwareAttestationResult</c>).</summary>
public sealed record HardwareResult(bool Ok, bool Bound = false, string? Reason = null, JD? Measured = null, IReadOnlyDictionary<string, string>? HostAsserted = null)
{
    public static HardwareResult Fail(string reason) => new(false, false, reason);

    /// <summary>The language-neutral form (what the conformance vectors record in <c>expect</c>).</summary>
    public JD Wire()
    {
        if (!Ok) return new JD { ["ok"] = false, ["reason"] = Reason };
        var o = new JD { ["ok"] = true, ["bound"] = Bound };
        if (Measured != null) o["measured"] = Measured;
        if (HostAsserted != null) o["hostAsserted"] = HostAsserted.ToDictionary(kv => kv.Key, kv => (object?)kv.Value);
        return o;
    }
}

/// <summary>A vendor verifier under a fixed configuration (see <see cref="AttestationVerifiers.FromConfig"/>). Thread-safe, total.</summary>
public interface IVendorVerifier
{
    string Vendor { get; }
    /// <summary>Verify the vendor evidence (null: none supplied) against the expected binding at the clock <paramref name="nowMs"/>. Never throws.</summary>
    HardwareResult Verify(JD? evidence, AttestationBinding? expected, long nowMs);
}

/// <summary>Small helpers shared by the vendor verifiers (ports of the reference's utilities; the JavaScript quirks they emulate are named).</summary>
internal static class AttestUtil
{
    internal const string BindDomain = "atlas-pca/attest-bind/v1\0";

    internal static byte[] LengthPrefixed(string s)
    {
        var b = System.Text.Encoding.UTF8.GetBytes(s);
        var o = new byte[4 + b.Length];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(o, (uint)b.Length);
        b.CopyTo(o, 4);
        return o;
    }

    /// <summary>SHA-512( "atlas-pca/attest-bind/v1\0" || lp(holderPub) || lp(grantRef) || u64be(epoch) || lp(nonce) ).</summary>
    internal static byte[] BindingBytes(AttestationBinding e)
    {
        if (e.HolderPub.Length == 0) throw new AttestError("binding: holderPub required");
        if (e.GrantRef.Length == 0) throw new AttestError("binding: grantRef required");
        if (e.Nonce.Length == 0) throw new AttestError("binding: nonce required");
        if (double.IsNaN(e.Epoch) || e.Epoch != Math.Truncate(e.Epoch) || e.Epoch < 0 || e.Epoch > Pca.MaxSafeInt) throw new AttestError("binding: epoch must be a non-negative safe integer");
        var ep = new byte[8];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt64BigEndian(ep, (ulong)e.Epoch);
        var buf = Pca.Concat(System.Text.Encoding.UTF8.GetBytes(BindDomain), LengthPrefixed(e.HolderPub), LengthPrefixed(e.GrantRef), ep, LengthPrefixed(e.Nonce));
        return System.Security.Cryptography.SHA512.HashData(buf);
    }

    internal static JD NewMeasured(string runtimeMeasurement, string op) =>
        new() { ["model_id"] = "", ["weights_digest"] = "", ["weights_measured"] = false, ["runtime_measurement"] = runtimeMeasurement, ["operator"] = op };

    internal static string Hex(byte[] b) => Convert.ToHexString(b).ToLowerInvariant();
    internal static bool TimingSafeEq(byte[] a, byte[] b) => System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(a, b);

    internal static bool IsJsSpace(char r) => r is '\t' or '\n' or '\v' or '\f' or '\r' or ' ' or '\u00A0' or '\u1680' or '\u2028' or '\u2029' or '\u202F' or '\u205F' or '\u3000' or '\uFEFF' || (r >= '\u2000' && r <= '\u200A');
    internal static string JsTrim(string s)
    {
        int a = 0, b = s.Length;
        while (a < b && IsJsSpace(s[a])) a++;
        while (b > a && IsJsSpace(s[b - 1])) b--;
        return s[a..b];
    }

    /// <summary>Decodes like Buffer.from(s, "base64"): either alphabet, characters outside it are skipped, "=" ends the data.</summary>
    internal static byte[] NodeB64(string s)
    {
        var o = new List<byte>(s.Length * 3 / 4);
        uint acc = 0; int bits = 0;
        foreach (char ch in s)
        {
            int v;
            if (ch >= 'A' && ch <= 'Z') v = ch - 'A';
            else if (ch >= 'a' && ch <= 'z') v = ch - 'a' + 26;
            else if (ch >= '0' && ch <= '9') v = ch - '0' + 52;
            else if (ch == '+' || ch == '-') v = 62;
            else if (ch == '/' || ch == '_') v = 63;
            else if (ch == '=') break;
            else continue;
            acc = (acc << 6) | (uint)v;
            bits += 6;
            if (bits >= 8)
            {
                bits -= 8;
                o.Add((byte)(acc >> bits));
                acc &= (1u << bits) - 1;
            }
        }
        return o.ToArray();
    }

    internal static bool IsHexString(string s) => s.Length > 0 && s.Length % 2 == 0 && s.All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f' or >= 'A' and <= 'F');

    /// <summary>Decodes a byte-carrying claim: hex (optionally 0x-prefixed), else base64url / base64; null when empty.</summary>
    internal static byte[]? DecodeClaimBytes(string value)
    {
        var t = JsTrim(value);
        var hx = t.StartsWith("0x", StringComparison.Ordinal) || t.StartsWith("0X", StringComparison.Ordinal) ? t[2..] : t;
        if (IsHexString(hx)) return Convert.FromHexString(hx);
        var b = NodeB64(t);
        return b.Length > 0 ? b : null;
    }

    /// <summary>The reference <c>asNumber</c>: a finite JSON number.</summary>
    internal static double? AsFinite(object? v) => IntentJs.NumOf(v) is double d && double.IsFinite(d) ? d : null;

    internal static string JsNumString(double f) => JsCanon.NumberString(f);

    internal static List<string>? AsStrList(object? v) => v is List<object?> l && l.All(x => x is string) ? l.Cast<string>().ToList() : null;

    internal static List<string> LowerAll(IEnumerable<string> xs) => xs.Select(s => s.ToLowerInvariant()).ToList();

    internal static JD MergeOverrides(JD measured, JD ov)
    {
        var o = new JD(measured);
        foreach (var (k, v) in ov) o[k] = v;
        return o;
    }

    internal static byte[] Sha256(byte[] b) => System.Security.Cryptography.SHA256.HashData(b);
    internal static byte[] Sha384(byte[] b) => System.Security.Cryptography.SHA384.HashData(b);
    internal static byte[] Sha512(byte[] b) => System.Security.Cryptography.SHA512.HashData(b);

    static bool AllHex(string s) => s.All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f' or >= 'A' and <= 'F');

    /// <summary>Checks the Azure runtime-data binding: the hash relation and user-data equality. The failure reason, or null when the quote binds.</summary>
    internal static string? CheckAzureRuntimeDataBinding(byte[] reportData, byte[] runtimeData, AttestationBinding expected)
    {
        if (reportData.Length != 64) return "report_data is not 64 bytes";
        for (int i = 32; i < 64; i++) if (reportData[i] != 0) return "report_data[32:64] is not zero (not an Azure runtime-data hash)";
        if (!Sha256(runtimeData).AsSpan().SequenceEqual(reportData.AsSpan(0, 32))) return "sha256(runtime data) does not equal the quote report_data";
        object? parsed;
        try { parsed = Pca.ParseJson(System.Text.Encoding.UTF8.GetString(runtimeData)); }
        catch (Exception) { return "runtime data is not valid JSON"; }
        if (parsed is not JD obj) return "runtime data is not a JSON object";
        if (obj.GetValueOrDefault("user-data") is not string ud || ud.Length != 128 || !AllHex(ud)) return "runtime data carries no 64-byte hex user-data";
        byte[] want;
        try { want = BindingBytes(expected); }
        catch (AttestError e) { return "binding not constructible: " + e.Message; }
        return Convert.FromHexString(ud).AsSpan().SequenceEqual(want) ? null : "runtime user-data does not bind holder/grant/epoch/nonce (relayed or unbound quote)";
    }

    internal static string ErrMsg(Exception? e) => e?.Message ?? "invalid";
}

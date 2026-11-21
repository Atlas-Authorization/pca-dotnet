// Quantum entropy as an ADD to key generation, never a trust dependency (the reference entropy module): every seed is HKDF-SHA256(local CSPRNG || quantum), so a
// hostile or broken quantum source cannot lower the result below the local CSPRNG. Parts: an HTTP QRNG source over an injected transport (ANU-style JSON, hex or
// base64 bodies; https only; the key never in an error), the unavailable source, the SP 800-90B 4.4 continuous health tests, the combiner, SecureSeed and an
// Ed25519 key-pair helper. There is no HTTP client here: the caller supplies the transport.
using System.Security.Cryptography;
using System.Text;
using AtlasPca.InteropJs;
using AtlasPca.Jose;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca;

/// <summary>An entropy refusal with its code: <c>quantum_required</c>, <c>health_test_failed</c> or <c>insecure_transport</c>.</summary>
public sealed class EntropyError : Exception
{
    public string Code { get; }
    public EntropyError(string code, string message) : base(message) { Code = code; }
}

/// <summary>A quantum random number source. <see cref="Name"/> is a short log-safe identifier (never a secret); <see cref="FetchAsync"/> returns exactly
/// the requested number of bytes or fails.</summary>
public interface IQrngSource
{
    string Name { get; }
    Task<byte[]> FetchAsync(int numBytes);
}

/// <summary>A source that is never available: every fetch fails with <c>QRNG unavailable: reason</c>.</summary>
public sealed class NullQrngSource : IQrngSource
{
    readonly string _reason;
    public NullQrngSource(string reason = "no QRNG source configured") { _reason = reason; }
    public string Name => "null-qrng";
    public Task<byte[]> FetchAsync(int numBytes) => Task.FromException<byte[]>(new InvalidOperationException("QRNG unavailable: " + _reason));
}

/// <summary>One outgoing request of <see cref="HttpQrngSource"/>. <see cref="Redirect"/> is always <c>error</c>: the transport must not follow redirects.</summary>
public sealed record QrngRequest(string Url, IReadOnlyDictionary<string, string> Headers, string Redirect, int TimeoutMs);

/// <summary>The response subset the source reads. Only <see cref="Ok"/> decides success; <see cref="Json"/> returns the parsed body as a JSON tree (the
/// shape <c>Pca.ParseJson</c> gives) and <see cref="Text"/> the body text; either may fail.</summary>
public sealed class QrngResponse
{
    public bool Ok { get; init; }
    public int Status { get; init; }
    public Func<Task<object?>>? Json { get; init; }
    public Func<Task<string>>? Text { get; init; }
}

/// <summary>The injected transport: it sends the request and must stop when the token is cancelled (the source's timeout).</summary>
public delegate Task<QrngResponse> QrngTransport(QrngRequest request, CancellationToken cancel);

/// <summary>Configuration of <see cref="HttpQrngSource"/>; null members take the reference defaults.</summary>
public sealed class HttpQrngConfig
{
    /// <summary>Base endpoint URL (required). The requested length is added as a query parameter unless <see cref="BuildUrl"/> is set.</summary>
    public string? Url { get; set; }
    /// <summary>Optional API key, sent as a header; never logged or placed in an error message.</summary>
    public string? ApiKey { get; set; }
    /// <summary>Header name of the key (default <c>x-api-key</c>).</summary>
    public string? ApiKeyHeader { get; set; }
    /// <summary><c>anu-uint8</c> (default), <c>hex</c> or <c>base64</c>; any other name is read as base64.</summary>
    public string? Format { get; set; }
    /// <summary>Request timeout in ms (default 5000).</summary>
    public int? TimeoutMs { get; set; }
    /// <summary>Largest request in bytes (default 1024).</summary>
    public int? MaxBytes { get; set; }
    /// <summary>Query parameter carrying the length (default <c>length</c>).</summary>
    public string? LengthParam { get; set; }
    /// <summary>Extra query parameters, set in order after the length (one named as the length parameter overrides it).</summary>
    public IEnumerable<KeyValuePair<string, string>>? ExtraParams { get; set; }
    /// <summary>Builds the whole request URL from (base, numBytes); its result still goes through the https check.</summary>
    public Func<string, int, string>? BuildUrl { get; set; }
    /// <summary>Permit plain http only for the hosts localhost, 127.0.0.1 and [::1]. Default false: https only.</summary>
    public bool AllowInsecureLoopback { get; set; }
    /// <summary>The transport; a source with none refuses every fetch.</summary>
    public QrngTransport? Transport { get; set; }
}

/// <summary>An HTTP QRNG backend for a configurable REST endpoint, validated into exactly the requested number of bytes. Fail-closed: a non-success status, a
/// malformed body, a wrong-length payload, an out-of-range byte, a cleartext endpoint or a timeout all throw.</summary>
public sealed class HttpQrngSource : IQrngSource
{
    readonly HttpQrngConfig _c;
    readonly int _timeoutMs, _maxBytes;

    public string Name { get; }

    public HttpQrngSource(HttpQrngConfig config)
    {
        ArgumentNullException.ThrowIfNull(config);
        if (string.IsNullOrEmpty(config.Url)) throw new ArgumentException("HttpQrngSource: `url` must be a non-empty string");
        _maxBytes = config.MaxBytes ?? Entropy.DefaultMaxQrngBytes;
        if (_maxBytes <= 0) throw new ArgumentException("HttpQrngSource: `maxBytes` must be a positive integer");
        _timeoutMs = config.TimeoutMs ?? Entropy.DefaultTimeoutMs;
        if (_timeoutMs <= 0) throw new ArgumentException("HttpQrngSource: `timeoutMs` must be a positive integer");
        _c = config;
        Name = "http-qrng(" + (WhatwgUrl.TryParse(config.Url) is { Host.Length: > 0 } u ? u.Host : "unknown") + ")";
    }

    string RequestUrl(int numBytes)
    {
        if (_c.BuildUrl != null) return _c.BuildUrl(_c.Url!, numBytes);
        var parts = WhatwgUrl.TryParse(_c.Url!) ?? throw new InvalidUrlException();
        if (parts.Protocol is not ("https:" or "http:")) return _c.Url!; // refused by the transport check below
        var u = QrngUrl.Parse(_c.Url!);
        u.SetParam(_c.LengthParam ?? "length", numBytes.ToString(System.Globalization.CultureInfo.InvariantCulture));
        if (_c.ExtraParams != null) foreach (var e in _c.ExtraParams) u.SetParam(e.Key, e.Value);
        return u.Href();
    }

    static void AssertSecureTransport(string url, bool allowLoopback)
    {
        var u = WhatwgUrl.TryParse(url) ?? throw new EntropyError("insecure_transport", "QRNG: endpoint URL is not a valid URL");
        if (u.Protocol == "https:") return;
        var hostname = QrngUrl.Hostname(u.Host);
        bool loop = hostname is "localhost" or "127.0.0.1" or "[::1]";
        if (u.Protocol == "http:" && allowLoopback && loop) return;
        throw new EntropyError("insecure_transport", "QRNG: endpoint must be https (http only for loopback with allowInsecureLoopback)");
    }

    static string Describe(Exception e) => e is OperationCanceledException or TimeoutException ? "timeout" : e.Message;

    /// <summary>Removes the API key from a message if it appears there.</summary>
    static string Scrub(string msg, string? apiKey) => string.IsNullOrEmpty(apiKey) ? msg : msg.Replace(apiKey, "[redacted]", StringComparison.Ordinal);

    public async Task<byte[]> FetchAsync(int numBytes)
    {
        if (numBytes <= 0) throw new ArgumentException($"QRNG: numBytes must be a positive integer, got {numBytes}");
        if (numBytes > _maxBytes) throw new ArgumentOutOfRangeException(null, $"QRNG: requested {numBytes} bytes exceeds per-request cap {_maxBytes}");
        var transport = _c.Transport ?? throw new InvalidOperationException("QRNG: no fetch implementation available in this runtime");
        var url = RequestUrl(numBytes);
        // fail closed on transport: the key header and the entropy itself must not cross a cleartext link
        AssertSecureTransport(url, _c.AllowInsecureLoopback);
        var headers = new Dictionary<string, string> { ["accept"] = "application/json, text/plain" };
        if (!string.IsNullOrEmpty(_c.ApiKey)) headers[_c.ApiKeyHeader ?? "x-api-key"] = _c.ApiKey;
        QrngResponse res;
        using (var cts = new CancellationTokenSource(_timeoutMs))
        {
            try
            {
                res = await transport(new QrngRequest(url, headers, "error", _timeoutMs), cts.Token).WaitAsync(TimeSpan.FromMilliseconds(_timeoutMs)).ConfigureAwait(false)
                    ?? throw new InvalidOperationException("the transport returned no response");
            }
            catch (Exception e)
            {
                cts.Cancel();
                throw new InvalidOperationException($"QRNG: fetch failed ({Scrub(Describe(e), _c.ApiKey)})");
            }
        }
        if (!res.Ok) throw new InvalidOperationException($"QRNG: endpoint returned HTTP {res.Status}");
        byte[] bytes;
        var format = _c.Format ?? "anu-uint8";
        if (format == "anu-uint8") bytes = Entropy.ParseAnuUint8(await (res.Json ?? throw new InvalidOperationException("QRNG: the response has no JSON body"))().ConfigureAwait(false));
        else
        {
            var text = JsX.JsTrim(await (res.Text ?? throw new InvalidOperationException("QRNG: the response has no text body"))().ConfigureAwait(false));
            bytes = format == "hex" ? Entropy.ParseHex(text) : Entropy.ParseBase64(text);
        }
        if (bytes.Length != numBytes) throw new InvalidOperationException($"QRNG: expected {numBytes} bytes, response decoded to {bytes.Length}");
        return bytes;
    }
}

/// <summary>The request URL of the HTTP source: the scheme, host and path as the URL parser of this package normalises them, with the credentials, query and
/// fragment kept, and query parameters set the way <c>URLSearchParams.set</c> does (application/x-www-form-urlencoded). Credentials are percent-encoded with the
/// URL standard's userinfo set: the user name ends at the first colon, the credentials at the last at sign of the authority.</summary>
internal sealed class QrngUrl
{
    readonly string _protocol, _userinfo, _host, _pathname;
    readonly string? _fragment;
    readonly List<(string Name, string Value)> _params = new();

    QrngUrl(string protocol, string userinfo, string host, string pathname, string? fragment)
    {
        _protocol = protocol; _userinfo = userinfo; _host = host; _pathname = pathname; _fragment = fragment;
    }

    /// <summary>The host without its port (IPv6 keeps its brackets).</summary>
    internal static string Hostname(string host)
    {
        if (host.StartsWith('[')) { int e = host.IndexOf(']'); return e < 0 ? host : host[..(e + 1)]; }
        int c = host.IndexOf(':');
        return c < 0 ? host : host[..c];
    }

    static bool IsHex(char c) => c is >= '0' and <= '9' or >= 'a' and <= 'f' or >= 'A' and <= 'F';

    /// <summary>application/x-www-form-urlencoded decoding: + is a space, %XX a byte, the bytes UTF-8.</summary>
    static string FormDecode(string s)
    {
        var raw = Encoding.UTF8.GetBytes(s);
        var o = new List<byte>(raw.Length);
        for (int i = 0; i < raw.Length; i++)
        {
            if (raw[i] == '+') o.Add(0x20);
            else if (raw[i] == '%' && i + 2 < raw.Length && IsHex((char)raw[i + 1]) && IsHex((char)raw[i + 2]))
            {
                o.Add(Convert.ToByte(Encoding.ASCII.GetString(raw, i + 1, 2), 16));
                i += 2;
            }
            else o.Add(raw[i]);
        }
        return Encoding.UTF8.GetString(o.ToArray());
    }

    /// <summary>application/x-www-form-urlencoded encoding: letters, digits and <c>* - . _</c> stay, a space is +, every other UTF-8 byte is %XX.</summary>
    static string FormEncode(string s)
    {
        var sb = new StringBuilder();
        foreach (var b in Encoding.UTF8.GetBytes(s))
        {
            if (b is >= (byte)'a' and <= (byte)'z' or >= (byte)'A' and <= (byte)'Z' or >= (byte)'0' and <= (byte)'9' or (byte)'*' or (byte)'-' or (byte)'.' or (byte)'_') sb.Append((char)b);
            else if (b == 0x20) sb.Append('+');
            else sb.Append('%').Append(b.ToString("X2", System.Globalization.CultureInfo.InvariantCulture));
        }
        return sb.ToString();
    }

    /// <summary>Parses <paramref name="url"/>; throws <see cref="InvalidUrlException"/> when it does not parse or has no host.</summary>
    internal static QrngUrl Parse(string url)
    {
        var parts = WhatwgUrl.TryParse(url);
        if (parts == null || parts.Host.Length == 0) throw new InvalidUrlException();
        // the same trimming and tab / newline removal as the parser, so the pieces below are cut from the text it read
        int st = 0, en = url.Length;
        while (st < en && url[st] <= 0x20) st++;
        while (en > st && url[en - 1] <= 0x20) en--;
        var inp = url[st..en].Replace("\t", "").Replace("\n", "").Replace("\r", "");
        string? fragment = null;
        int hash = inp.IndexOf('#');
        if (hash >= 0) { fragment = inp[(hash + 1)..]; inp = inp[..hash]; }
        string? query = null;
        int q = inp.IndexOf('?');
        if (q >= 0) { query = inp[(q + 1)..]; inp = inp[..q]; }
        var rest = inp[(inp.IndexOf(':') + 1)..].TrimStart('/', '\\');
        int slash = rest.IndexOfAny(new[] { '/', '\\' });
        var authority = slash < 0 ? rest : rest[..slash];
        var userinfo = "";
        int at = authority.LastIndexOf('@');
        if (at >= 0)
        {
            var raw = authority[..at];
            int colon = raw.IndexOf(':');
            string user = UserinfoEncode(colon < 0 ? raw : raw[..colon]), pass = colon < 0 ? "" : UserinfoEncode(raw[(colon + 1)..]);
            if (user.Length + pass.Length > 0) userinfo = user + (pass.Length > 0 ? ":" + pass : "") + "@";
        }
        var u = new QrngUrl(parts.Protocol, userinfo, parts.Host, parts.Pathname, fragment);
        if (query != null)
            foreach (var piece in query.Split('&'))
            {
                if (piece.Length == 0) continue;
                int eq = piece.IndexOf('=');
                u._params.Add(eq < 0 ? (FormDecode(piece), "") : (FormDecode(piece[..eq]), FormDecode(piece[(eq + 1)..])));
            }
        return u;
    }

    /// <summary><c>URLSearchParams.set</c>: the first parameter of that name takes the value and the later ones are dropped; with none it is appended.</summary>
    internal void SetParam(string name, string value)
    {
        int first = _params.FindIndex(p => p.Name == name);
        if (first < 0) { _params.Add((name, value)); return; }
        _params[first] = (name, value);
        for (int i = _params.Count - 1; i > first; i--) if (_params[i].Name == name) _params.RemoveAt(i);
    }

    /// <summary>The URL standard's userinfo percent-encode set over UTF-8: C0 controls, space, everything above <c>~</c> and <c>" # &lt; &gt; ? ` { } / : ; = @ [ \ ] ^ |</c>.
    /// A percent sign is kept as written.</summary>
    static string UserinfoEncode(string s)
    {
        var sb = new StringBuilder();
        foreach (var b in Encoding.UTF8.GetBytes(s))
        {
            if (b <= 0x20 || b > 0x7e || "\"#<>?`{}/:;=@[\\]^|".IndexOf((char)b) >= 0) sb.Append('%').Append(b.ToString("X2", System.Globalization.CultureInfo.InvariantCulture));
            else sb.Append((char)b);
        }
        return sb.ToString();
    }

    static string FragmentEncode(string s)
    {
        var sb = new StringBuilder();
        foreach (var b in Encoding.UTF8.GetBytes(s))
        {
            if (b <= 0x20 || b > 0x7e || b is (byte)'"' or (byte)'<' or (byte)'>' or (byte)'`') sb.Append('%').Append(b.ToString("X2", System.Globalization.CultureInfo.InvariantCulture));
            else sb.Append((char)b);
        }
        return sb.ToString();
    }

    internal string Href()
    {
        var sb = new StringBuilder(_protocol).Append("//").Append(_userinfo).Append(_host).Append(_pathname);
        if (_params.Count > 0) sb.Append('?').Append(string.Join("&", _params.Select(p => FormEncode(p.Name) + "=" + FormEncode(p.Value))));
        if (_fragment != null) sb.Append('#').Append(FragmentEncode(_fragment));
        return sb.ToString();
    }
}

/// <summary>The verdict of <see cref="Entropy.HealthTestBytes"/>: Ok, or the test that failed (<c>repetition-count</c> or <c>adaptive-proportion</c>).</summary>
public sealed record HealthVerdict(bool Ok, string? Test = null);

/// <summary>Health-test parameters: <see cref="H"/> is the assessed min-entropy per 8-bit sample (default 8, valid 1..8), <see cref="Window"/> the adaptive
/// proportion window (default 512, an integer of at least 2; shrunk to the buffer when that is shorter).</summary>
public sealed record HealthTestOptions(double? H = null, double? Window = null);

/// <summary>What <see cref="Entropy.SecureSeedAsync"/> reads; null members take the reference defaults.</summary>
public sealed class SecureSeedOptions
{
    /// <summary>Seed length in bytes (default 32, 1..8160).</summary>
    public int? Length { get; set; }
    /// <summary>The QRNG source; null is CSPRNG only.</summary>
    public IQrngSource? Source { get; set; }
    /// <summary>Quantum bytes to request (default max(32, length)).</summary>
    public int? QuantumBytes { get; set; }
    /// <summary>Local CSPRNG bytes to draw (default max(32, length), at least 16).</summary>
    public int? LocalBytes { get; set; }
    /// <summary>Extra domain-separation context of the combiner.</summary>
    public string? Context { get; set; }
    /// <summary>Fail closed (an <see cref="EntropyError"/> <c>quantum_required</c>) when no healthy quantum bytes were obtained, instead of falling back.</summary>
    public bool RequireQuantum { get; set; }
    /// <summary>Health-test parameters for every quantum buffer (null: the defaults).</summary>
    public HealthTestOptions? HealthTest { get; set; }
    /// <summary>Turns the health tests off (tests only).</summary>
    public bool DisableHealthTest { get; set; }
    /// <summary>Called when the QRNG is skipped or fails; what it throws is swallowed.</summary>
    public Action<Exception>? OnQrngError { get; set; }
    /// <summary>The CSPRNG (for tests; default the platform one). It must return exactly n bytes.</summary>
    public Func<int, byte[]?>? RandomBytesImpl { get; set; }
}

/// <summary>The result of <see cref="Entropy.SecureSeedAsync"/>: the seed (always full length and at least CSPRNG strength), whether quantum bytes were mixed in,
/// how many, and the source name (null when there was no source).</summary>
public sealed record SecureSeedResult(byte[] Seed, bool UsedQuantum, int QuantumByteCount, string? Source);

/// <summary>An Ed25519 key pair made by <see cref="Entropy.GenerateKeyPairWithEntropyAsync"/>: the 32-byte seed (secret) and public key.</summary>
public sealed record EntropyKeyPair(byte[] SecretKey, byte[] PublicKey, bool UsedQuantum);

public static class Entropy
{
    public const int MaxHkdfOutput = 255 * 32;
    public const int MinLocalBytes = 16;
    public const int DefaultSeedBytes = 32;
    public const int DefaultMaxQrngBytes = 1024;
    public const int DefaultTimeoutMs = 5000;
    const string MixLabel = "atlas-pca/entropy/mix/v1";
    const string MixSalt = "atlas-pca/entropy/salt/v1";

    /// <summary>A source that is never available (see <see cref="NullQrngSource"/>).</summary>
    public static IQrngSource UnavailableSource(string reason = "no QRNG source configured") => new NullQrngSource(reason);

    // ---- response bodies ----

    /// <summary>The ANU JSON shape <c>{success?: true, data: [0..255, ...]}</c> as bytes. <paramref name="body"/> is a parsed JSON tree.</summary>
    public static byte[] ParseAnuUint8(object? body)
    {
        if (body is L) throw new InvalidOperationException("QRNG: response `data` is not an array");
        if (body is not D rec) throw new InvalidOperationException("QRNG: response body is not a JSON object");
        if (rec.TryGetValue("success", out var success) && success is not true) throw new InvalidOperationException("QRNG: response reports success=false");
        if (rec.GetValueOrDefault("data") is not L data) throw new InvalidOperationException("QRNG: response `data` is not an array");
        var o = new byte[data.Count];
        for (int i = 0; i < data.Count; i++)
        {
            if (data[i] is bool || IntentJs.NumOf(data[i]) is not double v || v != Math.Floor(v) || v < 0 || v > 255) throw new InvalidOperationException($"QRNG: response data[{i}] is not a 0..255 integer");
            o[i] = (byte)v;
        }
        return o;
    }

    static int HexVal(char c) => c is >= '0' and <= '9' ? c - '0' : c is >= 'a' and <= 'f' ? c - 'a' + 10 : c is >= 'A' and <= 'F' ? c - 'A' + 10 : -1;

    /// <summary>Hex text (either case, even length, nothing else) as bytes.</summary>
    public static byte[] ParseHex(string text)
    {
        ArgumentNullException.ThrowIfNull(text);
        if (text.Length % 2 != 0 || text.Any(c => HexVal(c) < 0)) throw new InvalidOperationException("QRNG: malformed hex payload");
        var o = new byte[text.Length / 2];
        for (int i = 0; i < o.Length; i++) o[i] = (byte)(HexVal(text[2 * i]) * 16 + HexVal(text[2 * i + 1]));
        return o;
    }

    static int B64Val(char c) => c is >= 'A' and <= 'Z' ? c - 'A' : c is >= 'a' and <= 'z' ? c - 'a' + 26 : c is >= '0' and <= '9' ? c - '0' + 52 : c == '+' ? 62 : c == '/' ? 63 : -1;

    /// <summary>Standard-alphabet base64 as the forgiving decoder reads it: up to two trailing <c>=</c> are accepted only when they make the length a multiple
    /// of four, missing padding is accepted, a length of 1 mod 4 is refused, and trailing bits that are not zero are dropped. The length is not checked here.</summary>
    public static byte[] ParseBase64(string text)
    {
        ArgumentNullException.ThrowIfNull(text);
        var bad = new InvalidOperationException("QRNG: malformed base64 payload");
        int body = text.Length;
        while (body > 0 && text.Length - body < 2 && text[body - 1] == '=') body--;
        for (int i = 0; i < text.Length; i++)
            if (i < body ? B64Val(text[i]) < 0 : text[i] != '=') throw bad; // the alphabet, then at most two '=' and nothing after them
        if (body != text.Length && text.Length % 4 != 0) throw bad; // padding that does not complete a group of four
        if (body % 4 == 1) throw bad;
        var o = new byte[body * 6 / 8];
        int acc = 0, bits = 0, at = 0;
        for (int i = 0; i < body; i++)
        {
            acc = (acc << 6) | B64Val(text[i]);
            bits += 6;
            if (bits >= 8) { bits -= 8; o[at++] = (byte)(acc >> bits); acc &= (1 << bits) - 1; }
        }
        return o;
    }

    // ---- SP 800-90B 4.4 continuous health tests ----

    /// <summary>The repetition count cutoff <c>1 + ceil(20 / h)</c>.</summary>
    public static double RepetitionCutoff(double h) => 1 + Math.Ceiling(20 / h);

    /// <summary>The adaptive proportion cutoff for min-entropy <paramref name="h"/> and window <paramref name="w"/>: one more than the smallest k whose binomial
    /// CDF (p = 2^-h) reaches 1 - 2^-20.</summary>
    public static double ProportionCutoff(double h, double w)
    {
        // the reference's own pow (see FdLibm): the platform's may differ in the last place, which can move a cutoff
        double p = FdLibm.Pow(2, -h);
        double target = 1 - FdLibm.Pow(2, -20);
        double pmf = FdLibm.Pow(1 - p, w);
        double cdf = pmf;
        double k = 0;
        while (cdf < target && k < w)
        {
            pmf *= ((w - k) / (k + 1)) * (p / (1 - p));
            k++;
            cdf += pmf;
        }
        return 1 + k;
    }

    /// <summary>Runs the repetition count test over the whole buffer, then the adaptive proportion test over each complete window. Fails CLOSED (as
    /// <c>repetition-count</c>) on an empty buffer and on parameters outside their range.</summary>
    public static HealthVerdict HealthTestBytes(byte[] bytes, HealthTestOptions? opts = null)
    {
        ArgumentNullException.ThrowIfNull(bytes);
        double h = opts?.H ?? 8, w0 = opts?.Window ?? 512;
        if (!(h >= 1 && h <= 8) || !double.IsFinite(w0) || w0 != Math.Floor(w0) || w0 < 2) return new HealthVerdict(false, "repetition-count");
        if (bytes.Length == 0) return new HealthVerdict(false, "repetition-count");
        double rc = RepetitionCutoff(h);
        int run = 1;
        for (int i = 1; i < bytes.Length; i++)
        {
            run = bytes[i] == bytes[i - 1] ? run + 1 : 1;
            if (run >= rc) return new HealthVerdict(false, "repetition-count");
        }
        int w = (int)Math.Min(w0, bytes.Length);
        double ac = ProportionCutoff(h, w);
        for (int start = 0; start + w <= bytes.Length; start += w)
        {
            int count = 0;
            for (int i = start; i < start + w; i++) if (bytes[i] == bytes[start]) count++;
            if (count >= ac) return new HealthVerdict(false, "adaptive-proportion");
        }
        return new HealthVerdict(true);
    }

    // ---- the combiner ----

    static void U32Be(byte[] o, int at, int v) { o[at] = (byte)(v >> 24); o[at + 1] = (byte)(v >> 16); o[at + 2] = (byte)(v >> 8); o[at + 3] = (byte)v; }

    /// <summary>HKDF-SHA256 over the length-framed pair (local, quantum): <paramref name="length"/> bytes (default the local length, 1..8160), with
    /// <paramref name="context"/> folded into the HKDF info. The local input must be at least 16 bytes; the quantum input may be empty.</summary>
    public static byte[] MixEntropy(byte[] local, byte[] quantum, int? length = null, string? context = null)
    {
        if (local == null) throw new ArgumentException("mixEntropy: `local` must be a Uint8Array");
        if (quantum == null) throw new ArgumentException("mixEntropy: `quantum` must be a Uint8Array");
        if (local.Length < MinLocalBytes) throw new ArgumentOutOfRangeException(null, $"mixEntropy: local CSPRNG must be >= {MinLocalBytes} bytes (fail-closed)");
        int n = length ?? local.Length;
        if (n <= 0 || n > MaxHkdfOutput) throw new ArgumentOutOfRangeException(null, $"mixEntropy: length must be an integer in 1..{MaxHkdfOutput}");
        var ikm = new byte[8 + local.Length + quantum.Length];
        U32Be(ikm, 0, local.Length);
        U32Be(ikm, 4, quantum.Length);
        local.CopyTo(ikm, 8);
        quantum.CopyTo(ikm, 8 + local.Length);
        var label = Encoding.UTF8.GetBytes(string.IsNullOrEmpty(context) ? MixLabel : MixLabel + "/" + context);
        var info = new byte[label.Length + 4];
        label.CopyTo(info, 0);
        U32Be(info, label.Length, n);
        var o = HKDF.DeriveKey(HashAlgorithmName.SHA256, ikm, n, Encoding.ASCII.GetBytes(MixSalt), info);
        CryptographicOperations.ZeroMemory(ikm);
        return o;
    }

    // ---- seeds ----

    /// <summary>A seed of local CSPRNG bytes mixed with best-effort, health-tested quantum bytes. A source that fails, answers with the wrong length or fails the
    /// health test is skipped (reported through <see cref="SecureSeedOptions.OnQrngError"/>) and the seed is CSPRNG only, unless
    /// <see cref="SecureSeedOptions.RequireQuantum"/> is set. A local CSPRNG that misbehaves always fails closed.</summary>
    public static async Task<SecureSeedResult> SecureSeedAsync(SecureSeedOptions? opts = null)
    {
        opts ??= new SecureSeedOptions();
        int length = opts.Length ?? DefaultSeedBytes;
        if (length <= 0 || length > MaxHkdfOutput) throw new ArgumentOutOfRangeException(null, $"secureSeed: length must be an integer in 1..{MaxHkdfOutput}");
        int localBytes = opts.LocalBytes ?? Math.Max(DefaultSeedBytes, length);
        if (localBytes < MinLocalBytes) throw new ArgumentOutOfRangeException(null, $"secureSeed: localBytes must be an integer >= {MinLocalBytes}");
        int quantumBytes = opts.QuantumBytes ?? Math.Max(DefaultSeedBytes, length);
        if (quantumBytes <= 0) throw new ArgumentOutOfRangeException(null, "secureSeed: quantumBytes must be a positive integer");
        var local = opts.RandomBytesImpl != null ? opts.RandomBytesImpl(localBytes) : RandomNumberGenerator.GetBytes(localBytes);
        // the local CSPRNG is the trust anchor: when it misbehaves this fails CLOSED
        if (local == null || local.Length != localBytes) throw new InvalidOperationException("secureSeed: local CSPRNG did not return the requested bytes (fail-closed)");
        var quantum = Array.Empty<byte>();
        bool usedQuantum = false;
        if (opts.Source is { } source)
        {
            try
            {
                var q = await source.FetchAsync(quantumBytes).ConfigureAwait(false);
                if (q == null || q.Length != quantumBytes) throw new InvalidOperationException($"QRNG: source returned {(q == null ? "non-bytes" : q.Length.ToString(System.Globalization.CultureInfo.InvariantCulture))}, expected {quantumBytes}");
                if (!opts.DisableHealthTest)
                {
                    var v = HealthTestBytes(q, opts.HealthTest);
                    if (!v.Ok) throw new EntropyError("health_test_failed", $"QRNG: {v.Test ?? "health"} test failed; source rejected");
                }
                quantum = q;
                usedQuantum = true;
            }
            catch (Exception e)
            {
                // fail safe: fall back to CSPRNG only; observability must never break key generation
                try { opts.OnQrngError?.Invoke(e); } catch (Exception) { }
            }
        }
        if (opts.RequireQuantum && !usedQuantum)
        {
            CryptographicOperations.ZeroMemory(local);
            throw new EntropyError("quantum_required", "secureSeed: quantum entropy is required but was not obtained (fail-closed)");
        }
        var seed = MixEntropy(local, quantum, length, opts.Context);
        CryptographicOperations.ZeroMemory(local);
        return new SecureSeedResult(seed, usedQuantum, usedQuantum ? quantum.Length : 0, opts.Source?.Name);
    }

    /// <summary>An Ed25519 key pair whose 32-byte seed comes from <see cref="SecureSeedAsync"/> (the options' length is ignored; the context defaults to
    /// <c>ed25519-key</c>, an empty one stays empty).</summary>
    public static async Task<EntropyKeyPair> GenerateKeyPairWithEntropyAsync(SecureSeedOptions? opts = null)
    {
        opts ??= new SecureSeedOptions();
        var r = await SecureSeedAsync(new SecureSeedOptions
        {
            Length = 32, Source = opts.Source, QuantumBytes = opts.QuantumBytes, LocalBytes = opts.LocalBytes, Context = opts.Context ?? "ed25519-key", RequireQuantum = opts.RequireQuantum,
            HealthTest = opts.HealthTest, DisableHealthTest = opts.DisableHealthTest, OnQrngError = opts.OnQrngError, RandomBytesImpl = opts.RandomBytesImpl,
        }).ConfigureAwait(false);
        using var key = EdKey.FromSeed(r.Seed);
        return new EntropyKeyPair(r.Seed, (byte[])key.Pub.Clone(), r.UsedQuantum);
    }
}

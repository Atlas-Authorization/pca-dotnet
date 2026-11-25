// A careful minimal reader of the WHATWG URL forms the PCA packages need: the scheme, the host (with a non-default port), and the
// pathname, as `new URL(x)` reports them. Used by dpop (htu normalisation), vc (the @authority component) and oidc (is this https).
//
// shortcut: a special-scheme host with a non-ASCII character is converted with the platform's IDNA mapping (the reference's own tables may
// differ on exotic labels; one the platform refuses is refused); credentials, query and fragment are read only far enough to drop them.
// Anything outside the forms below fails closed (returns null).
using System.Numerics;
using System.Text;

namespace AtlasPca.Jose;

/// <summary>The parts of a parsed URL: <see cref="Protocol"/> is <c>scheme:</c>, <see cref="Host"/> is <c>host[:port]</c> (default port dropped,
/// IPv6 in brackets), <see cref="Pathname"/> the normalised path.</summary>
public sealed record UrlParts(string Protocol, string Host, string Pathname);

/// <summary>The reference's <c>TypeError [ERR_INVALID_URL]: Invalid URL</c> (an <see cref="ArgumentException"/> carrying its <c>code</c>).</summary>
public sealed class InvalidUrlException : ArgumentException
{
    public string Code => "ERR_INVALID_URL";
    public InvalidUrlException() : base("Invalid URL") { }
}

public static class WhatwgUrl
{
    static readonly string[] Special = { "http", "https", "ws", "wss", "ftp" };
    const string HostForbidden = "\u0000\t\n\r #/:<>?@[\\]^|";

    static int DefaultPort(string scheme) => scheme switch { "http" or "ws" => 80, "https" or "wss" => 443, "ftp" => 21, _ => -1 };

    /// <summary>True when <paramref name="url"/> parses and its scheme is https (the reference's <c>new URL(u).protocol === 'https:'</c>).</summary>
    public static bool IsHttps(string url) => TryParse(url) is { Protocol: "https:" };

    /// <summary><c>protocol + "//" + host + pathname</c> as the reference's <c>normalizeHtu</c> builds it, or null when the URL does not parse.</summary>
    public static string? NormalizeHtu(string url) => TryParse(url) is { } u ? u.Protocol + "//" + u.Host + u.Pathname : null;

    /// <summary>The URL's parts as <c>new URL(url)</c> reports them; throws <see cref="InvalidUrlException"/> when it does not parse.</summary>
    public static UrlParts Require(string? url) => (url == null ? null : TryParse(url)) ?? throw new InvalidUrlException();

    /// <summary>The URL's parts, or null when it does not parse (or uses a form this reader refuses).</summary>
    public static UrlParts? TryParse(string url)
    {
        try { return Parse(url); }
        catch (FormatException) { return null; }
    }

    static FormatException Bad() => new("Invalid URL");

    static bool IsHex(char c) => c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F';

    static string PercentEncode(string s, bool pathSet)
    {
        var sb = new StringBuilder();
        foreach (var c in Encoding.UTF8.GetBytes(s))
        {
            bool enc = c < 0x20 || c > 0x7e;
            if (!enc && pathSet && " \"#<>?`{}".IndexOf((char)c) >= 0) enc = true;
            if (enc) sb.Append('%').Append(c.ToString("X2"));
            else sb.Append((char)c);
        }
        return sb.ToString();
    }

    static string PercentDecode(string s)
    {
        var inp = Encoding.UTF8.GetBytes(s);
        var o = new List<byte>();
        for (int i = 0; i < inp.Length; i++)
        {
            if (inp[i] == '%' && i + 2 < inp.Length && IsHex((char)inp[i + 1]) && IsHex((char)inp[i + 2]))
            {
                o.Add(Convert.ToByte(Encoding.ASCII.GetString(inp, i + 1, 2), 16));
                i += 2;
            }
            else o.Add(inp[i]);
        }
        return Encoding.UTF8.GetString(o.ToArray());
    }

    static BigInteger? Ipv4Number(string inp)
    {
        if (inp.Length == 0) return null;
        int radix = 10;
        var s = inp;
        if (s.Length >= 2 && (s.StartsWith("0x", StringComparison.Ordinal) || s.StartsWith("0X", StringComparison.Ordinal))) { s = s[2..]; radix = 16; }
        else if (s.Length >= 2 && s[0] == '0') { s = s[1..]; radix = 8; }
        if (s.Length == 0) return BigInteger.Zero;
        BigInteger v = BigInteger.Zero;
        foreach (var c in s)
        {
            int d = c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : c >= 'A' && c <= 'F' ? c - 'A' + 10 : 99;
            if (d >= radix) return null;
            v = v * radix + d;
        }
        return v;
    }

    static bool EndsInNumber(string host)
    {
        var parts = host.Split('.').ToList();
        if (parts[^1].Length == 0)
        {
            if (parts.Count == 1) return false;
            parts.RemoveAt(parts.Count - 1);
        }
        var last = parts[^1];
        if (last.Length > 0 && last.All(c => c >= '0' && c <= '9')) return true;
        return Ipv4Number(last) != null;
    }

    static string Ipv4Parse(string host)
    {
        var parts = host.Split('.').ToList();
        if (parts[^1].Length == 0 && parts.Count > 1) parts.RemoveAt(parts.Count - 1);
        if (parts.Count > 4) throw Bad();
        var nums = new List<BigInteger>();
        foreach (var p in parts) nums.Add(Ipv4Number(p) ?? throw Bad());
        for (int i = 0; i < nums.Count - 1; i++) if (nums[i] > 255) throw Bad();
        var lastN = nums[^1];
        if (lastN >= BigInteger.Pow(256, 5 - nums.Count)) throw Bad();
        var ip = lastN;
        for (int i = 0; i < nums.Count - 1; i++) ip += nums[i] * BigInteger.Pow(256, 3 - i);
        long v = (long)ip;
        return ((v >> 24) & 255) + "." + ((v >> 16) & 255) + "." + ((v >> 8) & 255) + "." + (v & 255);
    }

    static string Ipv6Parse(string inp)
    {
        var a = new int[8];
        int piece = 0, compress = -1, p = 0, n = inp.Length;
        if (n > p && inp[p] == ':')
        {
            if (n < 2 || inp[1] != ':') throw Bad();
            p += 2; piece++; compress = piece;
        }
        while (p < n)
        {
            if (piece == 8) throw Bad();
            if (inp[p] == ':')
            {
                if (compress != -1) throw Bad();
                p++; piece++; compress = piece;
                continue;
            }
            int value = 0, length = 0;
            while (length < 4 && p < n && IsHex(inp[p])) { value = value * 16 + Convert.ToInt32(inp[p].ToString(), 16); p++; length++; }
            if (p < n && inp[p] == '.')
            {
                if (length == 0) throw Bad();
                p -= length;
                if (piece > 6) throw Bad();
                int seen = 0;
                while (p < n)
                {
                    int v4 = -1;
                    if (seen > 0)
                    {
                        if (inp[p] == '.' && seen < 4) p++;
                        else throw Bad();
                    }
                    if (p >= n || inp[p] < '0' || inp[p] > '9') throw Bad();
                    while (p < n && inp[p] >= '0' && inp[p] <= '9')
                    {
                        int d = inp[p] - '0';
                        if (v4 == -1) v4 = d;
                        else if (v4 == 0) throw Bad();
                        else v4 = v4 * 10 + d;
                        if (v4 > 255) throw Bad();
                        p++;
                    }
                    a[piece] = a[piece] * 256 + v4;
                    seen++;
                    if (seen == 2 || seen == 4) piece++;
                }
                if (seen != 4) throw Bad();
                break;
            }
            else if (p < n && inp[p] == ':')
            {
                p++;
                if (p >= n) throw Bad();
            }
            else if (p < n) throw Bad();
            a[piece] = value;
            piece++;
        }
        if (compress != -1)
        {
            int swaps = piece - compress;
            piece = 7;
            while (piece != 0 && swaps > 0)
            {
                (a[compress + swaps - 1], a[piece]) = (a[piece], a[compress + swaps - 1]);
                piece--; swaps--;
            }
        }
        else if (piece != 8) throw Bad();
        int bestStart = -1, bestLen = 0;
        for (int i = 0; i < 8;)
        {
            if (a[i] != 0) { i++; continue; }
            int j = i;
            while (j < 8 && a[j] == 0) j++;
            if (j - i > bestLen) { bestLen = j - i; bestStart = i; }
            i = j;
        }
        if (bestLen < 2) bestStart = -1;
        var sb = new StringBuilder("[");
        bool ignore0 = false;
        for (int i = 0; i < 8; i++)
        {
            if (ignore0 && a[i] == 0) continue;
            ignore0 = false;
            if (bestStart == i) { sb.Append(i == 0 ? "::" : ":"); ignore0 = true; continue; }
            sb.Append(a[i].ToString("x"));
            if (i != 7) sb.Append(':');
        }
        return sb.Append(']').ToString();
    }

    static string ParseHost(string raw, bool special)
    {
        if (raw.StartsWith('['))
        {
            if (!raw.EndsWith(']')) throw Bad();
            return Ipv6Parse(raw[1..^1]);
        }
        if (!special)
        {
            foreach (var c in raw) if (HostForbidden.IndexOf(c) >= 0) throw Bad();
            return PercentEncode(raw, false);
        }
        var domain = PercentDecode(raw).ToLowerInvariant();
        if (domain.Any(c => c >= 0x80))
        {
            // UTS 46 on Ada (the parser Node uses), so the A-labels match the reference byte for byte; refused when libatlasada is absent unless the approximation is opted into (AdaIdna)
            foreach (var c in domain)
                if (c < 0x80 && (HostForbidden.IndexOf(c) >= 0 || c <= 0x1f || c == '%' || c == 0x7f)) throw Bad();
            domain = AtlasPca.Ciba.AdaIdna.HostToAscii(domain)?.ToLowerInvariant() ?? throw Bad();
        }
        if (domain.Length == 0) throw Bad();
        foreach (var c in domain)
            if (HostForbidden.IndexOf(c) >= 0 || c <= 0x1f || c == '%' || c == 0x7f) throw Bad();
        return EndsInNumber(domain) ? Ipv4Parse(domain) : domain;
    }

    static bool IsDot(string seg) { var l = seg.ToLowerInvariant(); return l == "." || l == "%2e"; }
    static bool IsDotDot(string seg) { var l = seg.ToLowerInvariant(); return l == ".." || l == ".%2e" || l == "%2e." || l == "%2e%2e"; }

    static int IndexOfAny(string s, string set) => s.IndexOfAny(set.ToCharArray());

    static string HostPort(string authority, string scheme, bool special)
    {
        var a = authority;
        int at = a.LastIndexOf('@');
        if (at >= 0)
        {
            a = a[(at + 1)..];
            if (a.Length == 0) throw Bad();
        }
        int colon = -1;
        bool bracket = false;
        for (int i = 0; i < a.Length; i++)
        {
            char c = a[i];
            if (c == '[') bracket = true;
            else if (c == ']') bracket = false;
            else if (c == ':' && !bracket) { colon = i; break; }
        }
        var hostRaw = colon < 0 ? a : a[..colon];
        string? portRaw = colon < 0 ? null : a[(colon + 1)..];
        var port = "";
        if (!string.IsNullOrEmpty(portRaw))
        {
            foreach (var c in portRaw) if (c < '0' || c > '9') throw Bad();
            var pv = BigInteger.Parse(portRaw, System.Globalization.CultureInfo.InvariantCulture);
            if (pv > 65535) throw Bad();
            if ((int)pv != DefaultPort(scheme)) port = ":" + pv;
        }
        if (hostRaw.Length == 0)
        {
            if (special) throw Bad();
            if (port.Length != 0 || portRaw != null) throw Bad();
            return "";
        }
        return ParseHost(hostRaw, special) + port;
    }

    static UrlParts Parse(string url)
    {
        int st = 0, en = url.Length;
        while (st < en && url[st] <= 0x20) st++;
        while (en > st && url[en - 1] <= 0x20) en--;
        var inp = url[st..en].Replace("\t", "").Replace("\n", "").Replace("\r", "");
        int ci = 0;
        if (inp.Length == 0 || !(inp[0] >= 'A' && inp[0] <= 'Z' || inp[0] >= 'a' && inp[0] <= 'z')) throw Bad();
        while (ci < inp.Length && (inp[ci] >= 'A' && inp[ci] <= 'Z' || inp[ci] >= 'a' && inp[ci] <= 'z' || inp[ci] >= '0' && inp[ci] <= '9' || inp[ci] is '+' or '-' or '.')) ci++;
        if (ci >= inp.Length || inp[ci] != ':') throw Bad();
        var scheme = inp[..ci].ToLowerInvariant();
        var rest = inp[(ci + 1)..];
        bool special = Special.Contains(scheme);
        string host = "", pathStr;
        int q = IndexOfAny(rest, "?#");
        var beforeQ = q < 0 ? rest : rest[..q];
        if (special)
        {
            int i = 0;
            while (i < beforeQ.Length && (beforeQ[i] == '/' || beforeQ[i] == '\\')) i++;
            var after = beforeQ[i..];
            int e = IndexOfAny(after, "/\\");
            var authority = e < 0 ? after : after[..e];
            pathStr = e < 0 ? "" : after[e..].Replace('\\', '/');
            host = HostPort(authority, scheme, true);
            if (host.Length == 0) throw Bad();
        }
        else if (beforeQ.StartsWith("//", StringComparison.Ordinal))
        {
            var after = beforeQ[2..];
            int e = after.IndexOf('/');
            var authority = e < 0 ? after : after[..e];
            pathStr = e < 0 ? "" : after[e..];
            host = HostPort(authority, scheme, false);
        }
        else if (beforeQ.StartsWith('/')) pathStr = beforeQ;
        else return new UrlParts(scheme + ":", "", PercentEncode(beforeQ, false)); // opaque path
        string pathname;
        if (special || pathStr.StartsWith('/'))
        {
            var body = pathStr.StartsWith('/') ? pathStr[1..] : pathStr;
            var path = new List<string>();
            var segs = body.Split('/');
            for (int i = 0; i < segs.Length; i++)
            {
                var seg = segs[i];
                bool last = i == segs.Length - 1;
                if (IsDotDot(seg))
                {
                    if (path.Count > 0) path.RemoveAt(path.Count - 1);
                    if (last) path.Add("");
                }
                else if (IsDot(seg)) { if (last) path.Add(""); }
                else path.Add(PercentEncode(seg, true));
            }
            pathname = path.Count == 0 ? "" : "/" + string.Join("/", path);
            if (special && pathname.Length == 0) pathname = "/";
        }
        else pathname = "";
        return new UrlParts(scheme + ":", host, pathname);
    }
}

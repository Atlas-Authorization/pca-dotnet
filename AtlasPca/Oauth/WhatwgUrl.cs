// The slice of the WHATWG URL parser the OAuth bridge needs: absolute http(s)/ftp/ws(s) URLs (scheme, origin, normalized pathname and
// search) and the success / failure of parsing any other scheme. Hosts follow the WHATWG host parser, IPv4 number forms (0x7f.1, 2130706433)
// included. Not implemented: the opaque-host rules of non-special schemes (they parse successfully and carry no host).
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Numerics;
using System.Text;

namespace AtlasPca.Oauth;

internal sealed class WhatwgUrl
{
    public string Scheme = "";
    public string Origin = "null";
    public string Pathname = "";
    public string Search = "";

    static readonly Dictionary<string, int?> Special = new() { ["http"] = 80, ["https"] = 443, ["ftp"] = 21, ["ws"] = 80, ["wss"] = 443, ["file"] = null };

    public static WhatwgUrl? TryParse(string input)
    {
        var s = input.Trim(Enumerable.Range(0, 0x21).Select(i => (char)i).ToArray());
        s = s.Replace("\t", "").Replace("\n", "").Replace("\r", "");
        if (s.Length == 0 || !char.IsAsciiLetter(s[0])) return null;
        int i = 1;
        while (i < s.Length && (char.IsAsciiLetterOrDigit(s[i]) || s[i] is '+' or '-' or '.')) i++;
        if (i >= s.Length || s[i] != ':') return null;
        var scheme = s[..i].ToLowerInvariant();
        var rest = s[(i + 1)..];
        var url = new WhatwgUrl { Scheme = scheme };
        if (!Special.TryGetValue(scheme, out var dflt) || scheme == "file") return url; // non-special / file: parses, no host handled
        var hash = rest.IndexOf('#');
        if (hash >= 0) rest = rest[..hash];
        int p = 0;
        while (p < rest.Length && rest[p] is '/' or '\\') p++;
        rest = rest[p..];
        int end = rest.IndexOfAny(new[] { '/', '\\', '?' });
        var authority = end < 0 ? rest : rest[..end];
        var tail = end < 0 ? "" : rest[end..];
        var at = authority.LastIndexOf('@');
        var hostport = at >= 0 ? authority[(at + 1)..] : authority;
        if (at >= 0 && hostport.Length == 0) return null;
        string hostText; string portText = "";
        if (hostport.StartsWith('['))
        {
            var close = hostport.IndexOf(']');
            if (close < 0) return null;
            hostText = hostport[..(close + 1)];
            var after = hostport[(close + 1)..];
            if (after.Length > 0) { if (after[0] != ':') return null; portText = after[1..]; }
        }
        else
        {
            var colon = hostport.IndexOf(':');
            hostText = colon < 0 ? hostport : hostport[..colon];
            portText = colon < 0 ? "" : hostport[(colon + 1)..];
        }
        int? port = null;
        if (portText.Length > 0)
        {
            if (!portText.All(char.IsAsciiDigit)) return null;
            var trimmed = portText.TrimStart('0');
            if (trimmed.Length > 5) return null;
            var pv = trimmed.Length == 0 ? 0 : int.Parse(trimmed, CultureInfo.InvariantCulture);
            if (pv > 65535) return null;
            port = pv == dflt ? null : pv;
        }
        var host = Host(hostText);
        if (host == null) return null;
        // path and query
        var q = tail.IndexOf('?');
        var path = q < 0 ? tail : tail[..q];
        var query = q < 0 ? null : tail[(q + 1)..];
        url.Origin = scheme + "://" + host + (port == null ? "" : ":" + port.Value.ToString(CultureInfo.InvariantCulture));
        url.Pathname = Path(path);
        url.Search = string.IsNullOrEmpty(query) ? "" : "?" + Enc(query, QuerySet);
        return url;
    }

    static string? Host(string h)
    {
        if (h.StartsWith('['))
        {
            var inner = h[1..^1];
            if (inner.Contains('%') || !IPAddress.TryParse(inner, out var ip) || ip.AddressFamily != AddressFamily.InterNetworkV6) return null;
            return "[" + ip.ToString().ToLowerInvariant() + "]";
        }
        string dec;
        try { dec = new UTF8Encoding(false, true).GetString(PercentDecode(h)); } catch (Exception) { return null; }
        if (dec.Length == 0) return null;
        if (dec.Any(c => !char.IsAscii(c)))
        {
            // UTS 46 on Ada (the parser Node uses); refused when libatlasada is absent unless the approximation is opted into (AdaIdna)
            foreach (var c in dec) if (char.IsAscii(c) && (c <= 0x20 || c == 0x7f || "#/:<>?@[\\]^|%".Contains(c))) return null;
            var ascii = AtlasPca.Ciba.AdaIdna.HostToAscii(dec);
            if (ascii == null) return null;
            dec = ascii;
        }
        dec = dec.ToLowerInvariant();
        foreach (var c in dec) if (c <= 0x20 || c == 0x7f || "#/:<>?@[\\]^|%".Contains(c)) return null;
        return EndsInNumber(dec) ? Ipv4Parse(dec) : dec;
    }

    // WHATWG URL "IPv4 number parser", "ends in a number checker" and "IPv4 parser".
    static BigInteger? Ipv4Number(string inp)
    {
        if (inp.Length == 0) return null;
        int radix = 10;
        var s = inp;
        if (s.Length >= 2 && (s.StartsWith("0x", StringComparison.Ordinal) || s.StartsWith("0X", StringComparison.Ordinal))) { s = s[2..]; radix = 16; }
        else if (s.Length >= 2 && s[0] == '0') { s = s[1..]; radix = 8; }
        if (s.Length == 0) return BigInteger.Zero;
        var v = BigInteger.Zero;
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
        if (last.Length > 0 && last.All(char.IsAsciiDigit)) return true;
        return Ipv4Number(last) != null;
    }

    static string? Ipv4Parse(string host)
    {
        var parts = host.Split('.').ToList();
        if (parts[^1].Length == 0 && parts.Count > 1) parts.RemoveAt(parts.Count - 1);
        if (parts.Count > 4) return null;
        var nums = new List<BigInteger>();
        foreach (var p in parts) { var n = Ipv4Number(p); if (n == null) return null; nums.Add(n.Value); }
        for (int i = 0; i < nums.Count - 1; i++) if (nums[i] > 255) return null;
        var lastN = nums[^1];
        if (lastN >= BigInteger.Pow(256, 5 - nums.Count)) return null;
        var ip = lastN;
        for (int i = 0; i < nums.Count - 1; i++) ip += nums[i] * BigInteger.Pow(256, 3 - i);
        long v = (long)ip;
        return ((v >> 24) & 255) + "." + ((v >> 16) & 255) + "." + ((v >> 8) & 255) + "." + (v & 255);
    }

    static byte[] PercentDecode(string s)
    {
        var o = new List<byte>();
        var b = Encoding.UTF8.GetBytes(s);
        for (int i = 0; i < b.Length; i++)
        {
            if (b[i] == '%' && i + 2 < b.Length && Uri.IsHexDigit((char)b[i + 1]) && Uri.IsHexDigit((char)b[i + 2]))
            {
                o.Add(Convert.ToByte(((char)b[i + 1]).ToString() + (char)b[i + 2], 16));
                i += 2;
            }
            else o.Add(b[i]);
        }
        return o.ToArray();
    }

    static bool QuerySet(int c) => c <= 0x20 || c == '"' || c == '#' || c == '<' || c == '>' || c == '\'' || c > 0x7e;
    static bool PathSet(int c) => c <= 0x20 || c is '"' or '#' or '<' or '>' or '?' or '`' or '{' or '}' || c > 0x7e;

    static string Enc(string s, Func<int, bool> set)
    {
        var sb = new StringBuilder();
        foreach (var r in s.EnumerateRunes())
        {
            if (r.Value < 0x80 && !set(r.Value)) { sb.Append((char)r.Value); continue; }
            foreach (var b in Encoding.UTF8.GetBytes(r.ToString())) sb.Append('%').Append(b.ToString("X2", CultureInfo.InvariantCulture));
        }
        return sb.ToString();
    }

    static string Path(string raw)
    {
        // the path starts at a '/' (or '\') or is empty; '\' is a separator
        var segs = raw.Replace('\\', '/').Split('/').ToList();
        if (raw.Length > 0) segs.RemoveAt(0); // the empty piece before the leading slash
        var outp = new List<string>();
        for (int k = 0; k < segs.Count; k++)
        {
            var seg = segs[k];
            var last = k == segs.Count - 1;
            var low = seg.ToLowerInvariant();
            if (low is ".." or ".%2e" or "%2e." or "%2e%2e") { if (outp.Count > 0) outp.RemoveAt(outp.Count - 1); if (last) outp.Add(""); }
            else if (low is "." or "%2e") { if (last) outp.Add(""); }
            else outp.Add(Enc(seg, PathSet));
        }
        return "/" + string.Join("/", outp);
    }
}

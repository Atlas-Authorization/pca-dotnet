// The part of the WHATWG URL parser the egress target check needs: scheme, credentials, host, port, path and query of an absolute URL.
// Hosts must be ASCII (a non-ASCII host is refused: fail closed). Returns null for a URL the parser rejects.
using System.Numerics;
using System.Text;

namespace AtlasPca.Sandbox;

internal sealed class EgressUrl
{
    public string Scheme = "";
    public bool Credentials;
    public bool Hash;
    public string Host = "";
    public int Port = -1;
    public string Path = "/";
    public string Query = "";

    static int DefaultPort(string scheme) => scheme switch { "http" or "ws" => 80, "https" or "wss" => 443, "ftp" => 21, _ => -1 };

    static bool IsAlpha(char c) => (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');

    public static EgressUrl? Parse(string input)
    {
        int b = 0, e = input.Length;
        while (b < e && input[b] <= 0x20) b++;
        while (e > b && input[e - 1] <= 0x20) e--;
        var sb = new StringBuilder();
        for (int i = b; i < e; i++)
        {
            char c = input[i];
            if (c != '\t' && c != '\n' && c != '\r') sb.Append(c);
        }
        var s = sb.ToString();
        int colon = -1;
        if (s.Length > 0 && IsAlpha(s[0]))
        {
            for (int i = 1; i < s.Length; i++)
            {
                char c = s[i];
                if (c == ':') { colon = i; break; }
                if (!(IsAlpha(c) || (c >= '0' && c <= '9') || c == '+' || c == '-' || c == '.')) return null;
            }
        }
        if (colon < 0) return null;
        var p = new EgressUrl { Scheme = s.Substring(0, colon).ToLowerInvariant() };
        var rest = s.Substring(colon + 1);
        bool special = DefaultPort(p.Scheme) >= 0 || p.Scheme == "file";
        if (!special)
        {
            int h = rest.IndexOf('#');
            p.Hash = h >= 0 && h + 1 < rest.Length;
            return p; // an opaque or hierarchical non-special URL: the caller refuses its scheme
        }
        if (p.Scheme == "file") return p;
        int k0 = 0;
        while (k0 < rest.Length && (rest[k0] == '/' || rest[k0] == '\\')) k0++;
        int end = k0;
        while (end < rest.Length && "/\\?#".IndexOf(rest[end]) < 0) end++;
        var authority = rest.Substring(k0, end - k0);
        var tail = rest.Substring(end);
        var hostport = authority;
        int at = authority.LastIndexOf('@');
        if (at >= 0)
        {
            var userinfo = authority.Substring(0, at);
            int c = userinfo.IndexOf(':');
            var user = c < 0 ? userinfo : userinfo.Substring(0, c);
            var pass = c < 0 ? "" : userinfo.Substring(c + 1);
            p.Credentials = user.Length > 0 || pass.Length > 0;
            hostport = authority.Substring(at + 1);
            if (hostport.Length == 0) return null;
        }
        string hostText;
        var portText = "";
        if (hostport.StartsWith('['))
        {
            int close = hostport.IndexOf(']');
            if (close < 0) return null;
            hostText = hostport.Substring(0, close + 1);
            var after = hostport.Substring(close + 1);
            if (after.Length > 0)
            {
                if (after[0] != ':') return null;
                portText = after.Substring(1);
            }
        }
        else
        {
            int c = hostport.IndexOf(':');
            hostText = c < 0 ? hostport : hostport.Substring(0, c);
            if (c >= 0) portText = hostport.Substring(c + 1);
        }
        if (hostText.Length == 0) return null;
        if (portText.Length > 0)
        {
            foreach (var ch in portText) if (ch < '0' || ch > '9') return null;
            var n = BigInteger.Parse(portText, System.Globalization.CultureInfo.InvariantCulture);
            if (n > 65535) return null;
            int v = (int)n;
            p.Port = v == DefaultPort(p.Scheme) ? -1 : v;
        }
        var host = hostText.StartsWith('[') ? Ipv6Host(hostText.Substring(1, hostText.Length - 2)) : DomainHost(hostText);
        if (host == null) return null;
        p.Host = host;

        int hashAt = tail.IndexOf('#');
        var beforeHash = hashAt < 0 ? tail : tail.Substring(0, hashAt);
        p.Hash = hashAt >= 0 && hashAt + 1 < tail.Length;
        int q = beforeHash.IndexOf('?');
        var pathPart = q < 0 ? beforeHash : beforeHash.Substring(0, q);
        p.Query = q < 0 ? "" : Encode(beforeHash.Substring(q + 1), true);
        p.Path = PathOf(pathPart);
        return p;
    }

    static string PathOf(string raw)
    {
        if (raw.Length == 0) return "/";
        var parts = raw.Replace('\\', '/').Substring(1).Split('/');
        var stack = new List<string>();
        for (int i = 0; i < parts.Length; i++)
        {
            var seg = parts[i];
            var l = seg.ToLowerInvariant();
            bool last = i == parts.Length - 1;
            if (l is ".." or ".%2e" or "%2e." or "%2e%2e")
            {
                if (stack.Count > 0) stack.RemoveAt(stack.Count - 1);
                if (last) stack.Add("");
            }
            else if (l is "." or "%2e")
            {
                if (last) stack.Add("");
            }
            else stack.Add(Encode(seg, false));
        }
        return "/" + string.Join("/", stack);
    }

    /// <summary>Percent-encode with the path (or special-query) encode set: C0 controls, space, ", #, &lt;, &gt;, DEL and non-ASCII (UTF-8); path adds ? ^ ` { }; query adds '.</summary>
    static string Encode(string s, bool query)
    {
        var o = new StringBuilder();
        foreach (var raw in Encoding.UTF8.GetBytes(s))
        {
            int c = raw;
            bool enc = c <= 0x20 || c >= 0x7f || c == '"' || c == '#' || c == '<' || c == '>'
                || (query ? c == '\'' : (c == '?' || c == '^' || c == '`' || c == '{' || c == '}'));
            if (enc) o.Append('%').Append("0123456789ABCDEF"[c >> 4]).Append("0123456789ABCDEF"[c & 15]);
            else o.Append((char)c);
        }
        return o.ToString();
    }

    static int Hex(int c)
    {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    }

    static string? DomainHost(string text)
    {
        var src = Encoding.UTF8.GetBytes(text);
        var d = new StringBuilder();
        for (int i = 0; i < src.Length; i++)
        {
            int c = src[i];
            if (c == '%' && i + 2 < src.Length && Hex(src[i + 1]) >= 0 && Hex(src[i + 2]) >= 0)
            {
                c = Hex(src[i + 1]) * 16 + Hex(src[i + 2]);
                i += 2;
            }
            if (c >= 0x80) return null; // non-ASCII host: not ported, refused
            d.Append((char)c);
        }
        var domain = d.ToString().ToLowerInvariant();
        if (domain.Length == 0) return null;
        foreach (var c in domain)
            if (c <= 0x1f || c == 0x7f || " #%/:<>?@[\\]^|".IndexOf(c) >= 0) return null;
        if (EndsInNumber(domain)) return Ipv4Host(domain);
        return domain;
    }

    static bool EndsInNumber(string domain)
    {
        var parts = domain.Split('.').ToList();
        if (parts[^1].Length == 0)
        {
            if (parts.Count == 1) return false;
            parts.RemoveAt(parts.Count - 1);
        }
        var last = parts[^1];
        if (last.Length > 0 && last.All(c => c >= '0' && c <= '9')) return true;
        if (last.Length >= 2 && last[0] == '0' && (last[1] == 'x' || last[1] == 'X'))
        {
            for (int i = 2; i < last.Length; i++) if (Hex(last[i]) < 0) return false;
            return true;
        }
        return false;
    }

    static BigInteger? Ipv4Number(string input)
    {
        if (input.Length == 0) return null;
        int radix = 10;
        var s = input;
        if (s.Length >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) { s = s.Substring(2); radix = 16; }
        else if (s.Length >= 2 && s[0] == '0') { s = s.Substring(1); radix = 8; }
        if (s.Length == 0) return BigInteger.Zero;
        BigInteger n = BigInteger.Zero;
        foreach (var ch in s)
        {
            int h = Hex(ch);
            if (h < 0 || h >= radix) return null;
            n = n * radix + h;
        }
        return n;
    }

    static string? Ipv4Host(string domain)
    {
        var parts = domain.Split('.').ToList();
        if (parts[^1].Length == 0 && parts.Count > 1) parts.RemoveAt(parts.Count - 1);
        if (parts.Count > 4) return null;
        var nums = new List<BigInteger>();
        foreach (var p in parts)
        {
            var n = Ipv4Number(p);
            if (n == null) return null;
            nums.Add(n.Value);
        }
        for (int i = 0; i < nums.Count - 1; i++) if (nums[i] > 255) return null;
        var last = nums[^1];
        if (last >= BigInteger.Pow(256, 5 - nums.Count)) return null;
        var ip = last;
        for (int i = 0; i < nums.Count - 1; i++) ip += nums[i] * BigInteger.Pow(256, 3 - i);
        long v = (long)ip;
        return ((v >> 24) & 255) + "." + ((v >> 16) & 255) + "." + ((v >> 8) & 255) + "." + (v & 255);
    }

    /// <summary>Parse the text between the brackets and serialize it in the compressed lowercase form; null when invalid.</summary>
    static string? Ipv6Host(string input)
    {
        var a = new int[8];
        int piece = 0, compress = -1, p = 0, n = input.Length;
        if (n > 0 && input[0] == ':')
        {
            if (n < 2 || input[1] != ':') return null;
            p += 2;
            piece++;
            compress = piece;
        }
        while (p < n)
        {
            if (piece == 8) return null;
            if (input[p] == ':')
            {
                if (compress != -1) return null;
                p++;
                piece++;
                compress = piece;
                continue;
            }
            int value = 0, length = 0;
            while (length < 4 && p < n && Hex(input[p]) >= 0)
            {
                value = value * 16 + Hex(input[p]);
                p++;
                length++;
            }
            if (p < n && input[p] == '.')
            {
                if (length == 0) return null;
                p -= length;
                if (piece > 6) return null;
                int seen = 0;
                while (p < n)
                {
                    int v4 = -1;
                    if (seen > 0)
                    {
                        if (input[p] == '.' && seen < 4) p++;
                        else return null;
                    }
                    if (p >= n || input[p] < '0' || input[p] > '9') return null;
                    while (p < n && input[p] >= '0' && input[p] <= '9')
                    {
                        int d = input[p] - '0';
                        if (v4 == -1) v4 = d;
                        else if (v4 == 0) return null;
                        else v4 = v4 * 10 + d;
                        if (v4 > 255) return null;
                        p++;
                    }
                    a[piece] = a[piece] * 0x100 + v4;
                    seen++;
                    if (seen == 2 || seen == 4) piece++;
                }
                if (seen != 4) return null;
                break;
            }
            else if (p < n && input[p] == ':')
            {
                p++;
                if (p >= n) return null;
            }
            else if (p < n) return null;
            a[piece] = value;
            piece++;
        }
        if (compress != -1)
        {
            int swaps = piece - compress;
            piece = 7;
            while (piece != 0 && swaps > 0)
            {
                int t = a[compress + swaps - 1];
                a[compress + swaps - 1] = a[piece];
                a[piece] = t;
                piece--;
                swaps--;
            }
        }
        else if (piece != 8) return null;
        int bestStart = -1, bestLen = 0;
        for (int i = 0; i < 8;)
        {
            if (a[i] != 0) { i++; continue; }
            int j = i;
            while (j < 8 && a[j] == 0) j++;
            if (j - i > bestLen) { bestStart = i; bestLen = j - i; }
            i = j;
        }
        if (bestLen < 2) bestStart = -1;
        var o = new StringBuilder();
        bool ignore0 = false;
        for (int i = 0; i < 8; i++)
        {
            if (ignore0 && a[i] == 0) continue;
            ignore0 = false;
            if (bestStart == i)
            {
                o.Append(i == 0 ? "::" : ":");
                ignore0 = true;
                continue;
            }
            o.Append(a[i].ToString("x"));
            if (i != 7) o.Append(':');
        }
        return o.ToString();
    }
}

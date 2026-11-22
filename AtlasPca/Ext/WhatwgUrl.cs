// The WHATWG URL Standard, as far as one question needs it: "is this a plain https URL?", i.e. does `new URL(s)` of the reference platform succeed with the scheme https and an empty username and an empty
// password. System.Uri answers differently on inputs the standard accepts or refuses (a scheme without slashes, a backslash, a percent-encoded host, numeric hosts, a bare "@" or ":@" credential section, tabs and
// newlines, empty labels), so this is the standard's own basic URL parser (scheme, special authority, credentials, host and port) with nothing after the authority able to fail: the path, query and fragment of a
// special URL never make parsing fail.
//
// Residual difference: the domain-to-ASCII step (UTS 46) maps non-ASCII labels with the platform's IDNA tables (System.Globalization.IdnMapping), whose Unicode version can differ from the reference platform's;
// ASCII labels are handled here without it.
using System.Globalization;
using System.Numerics;
using System.Text;

namespace AtlasPca;

internal static class WhatwgPlainUrl
{
    /// <summary>True iff the WHATWG URL parser accepts <paramref name="input"/> (no base URL) as an <c>https:</c> URL with an empty username and password.</summary>
    internal static bool IsPlainHttps(string input)
    {
        // strip leading and trailing C0 controls and spaces, then remove every tab and newline
        var s = input.Trim(Enumerable.Range(0, 0x21).Select(i => (char)i).ToArray());
        s = s.Replace("\t", "").Replace("\n", "").Replace("\r", "");
        if (s.Length == 0 || !IsAsciiAlpha(s[0])) return false;
        int i = 0;
        while (i < s.Length && (IsAsciiAlpha(s[i]) || (s[i] >= '0' && s[i] <= '9') || s[i] is '+' or '-' or '.')) i++;
        if (i >= s.Length || s[i] != ':' || !s[..i].Equals("https", StringComparison.OrdinalIgnoreCase)) return false;
        // special authority: any number of slashes or backslashes, then the authority up to the next / \ ? #
        var rest = s[(i + 1)..].TrimStart('/', '\\');
        var end = rest.IndexOfAny(new[] { '/', '\\', '?', '#' });
        var authority = end < 0 ? rest : rest[..end];
        // everything before the LAST @ is credentials, the username up to the first colon: only "" and ":" are both empty
        var at = authority.LastIndexOf('@');
        var hostPort = authority;
        if (at >= 0)
        {
            var userInfo = authority[..at];
            if (userInfo.Length != 0 && userInfo != ":") return false;
            hostPort = authority[(at + 1)..];
        }
        var inBrackets = false;
        var colon = -1;
        for (int k = 0; k < hostPort.Length && colon < 0; k++)
        {
            if (hostPort[k] == '[') inBrackets = true;
            else if (hostPort[k] == ']') inBrackets = false;
            else if (hostPort[k] == ':' && !inBrackets) colon = k;
        }
        var host = colon < 0 ? hostPort : hostPort[..colon];
        if (colon >= 0 && !PortOk(hostPort[(colon + 1)..])) return false;
        return HostOk(host);
    }

    static bool IsAsciiAlpha(char c) => (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');

    // a port is ASCII digits only (or empty), at most 65535
    static bool PortOk(string port)
    {
        if (!port.All(c => c >= '0' && c <= '9')) return false;
        var t = port.TrimStart('0');
        return t.Length == 0 || (t.Length <= 5 && int.Parse(t, CultureInfo.InvariantCulture) <= 65535);
    }

    static bool HostOk(string host)
    {
        if (host.Length == 0) return false;
        if (host[0] == '[') return host[^1] == ']' && host.Length >= 2 && Ipv6Ok(host[1..^1]);
        var ascii = DomainToAscii(PercentDecode(host));
        if (string.IsNullOrEmpty(ascii)) return false;
        foreach (var c in ascii)
            if (c <= 0x1F || c == 0x7F || c is ' ' or '#' or '%' or '/' or ':' or '<' or '>' or '?' or '@' or '[' or '\\' or ']' or '^' or '|') return false;
        return !EndsInNumber(ascii) || Ipv4Ok(ascii);
    }

    // percent-decode (bytes that are not valid UTF-8 become U+FFFD); a % not followed by two hex digits stays
    static string PercentDecode(string s)
    {
        var bytes = new List<byte>();
        var raw = Encoding.UTF8.GetBytes(s);
        for (int i = 0; i < raw.Length; i++)
        {
            if (raw[i] == '%' && i + 2 < raw.Length && Hex(raw[i + 1]) >= 0 && Hex(raw[i + 2]) >= 0) { bytes.Add((byte)(Hex(raw[i + 1]) * 16 + Hex(raw[i + 2]))); i += 2; }
            else bytes.Add(raw[i]);
        }
        return Encoding.UTF8.GetString(bytes.ToArray());
    }

    static int Hex(int c) => c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : c >= 'A' && c <= 'F' ? c - 'A' + 10 : -1;

    // UTS 46 as the URL standard uses it (no STD3 rules, no DNS length checks); the labels are processed one by one
    static string? DomainToAscii(string domain)
    {
        var d = domain.Replace('。', '.').Replace('．', '.').Replace('｡', '.');
        var idn = new IdnMapping { UseStd3AsciiRules = false, AllowUnassigned = false };
        var labels = d.Split('.');
        for (int i = 0; i < labels.Length; i++)
        {
            var l = labels[i];
            try
            {
                // an ASCII label is only lowercased (the reference platform does not decode an "xn--" label to check it); any other label is mapped to Punycode
                l = l.All(c => c < 0x80) ? l.ToLowerInvariant() : idn.GetAscii(l);
            }
            catch (ArgumentException) { return null; }
            labels[i] = l;
        }
        return string.Join(".", labels);
    }

    // the last label is a number (all digits, or an IPv4 number), so the host must be an IPv4 address
    static bool EndsInNumber(string domain)
    {
        var parts = domain.Split('.').ToList();
        if (parts[^1].Length == 0)
        {
            if (parts.Count == 1) return false;
            parts.RemoveAt(parts.Count - 1);
        }
        var last = parts[^1];
        return (last.Length > 0 && last.All(c => c >= '0' && c <= '9')) || Ipv4Number(last) != null;
    }

    // an IPv4 number: decimal, 0x hexadecimal or leading-0 octal; null when it is none of them (capped far above any valid value)
    static BigInteger? Ipv4Number(string input)
    {
        if (input.Length == 0) return null;
        var radix = 10;
        if (input.Length >= 2 && input[0] == '0' && (input[1] == 'x' || input[1] == 'X')) { input = input[2..]; radix = 16; }
        else if (input.Length >= 2 && input[0] == '0') { input = input[1..]; radix = 8; }
        if (input.Length == 0) return 0;
        BigInteger v = 0;
        foreach (var c in input)
        {
            var h = Hex(c);
            if (h < 0 || h >= radix) return null;
            v = v * radix + h;
        }
        return v;
    }

    static bool Ipv4Ok(string domain)
    {
        var parts = domain.Split('.').ToList();
        if (parts[^1].Length == 0 && parts.Count > 1) parts.RemoveAt(parts.Count - 1);
        if (parts.Count > 4) return false;
        var nums = new List<BigInteger>();
        foreach (var p in parts)
        {
            if (Ipv4Number(p) is not BigInteger n) return false;
            nums.Add(n);
        }
        for (int i = 0; i < nums.Count - 1; i++) if (nums[i] > 255) return false;
        return nums[^1] < BigInteger.Pow(256, 5 - nums.Count);
    }

    // the WHATWG IPv6 parser, for validity only
    static bool Ipv6Ok(string s)
    {
        int p = 0, pieceIndex = 0;
        int? compress = null;
        int? C() => p < s.Length ? s[p] : null;
        bool IsHex(int? c) => c != null && Hex(c.Value) >= 0;
        bool IsDigit(int? c) => c != null && c >= '0' && c <= '9';
        if (C() == ':')
        {
            if (p + 1 >= s.Length || s[p + 1] != ':') return false;
            p += 2;
            pieceIndex++;
            compress = pieceIndex;
        }
        while (C() != null)
        {
            if (pieceIndex == 8) return false;
            if (C() == ':')
            {
                if (compress != null) return false;
                p++;
                pieceIndex++;
                compress = pieceIndex;
                continue;
            }
            int length = 0;
            while (length < 4 && IsHex(C())) { p++; length++; }
            if (C() == '.')
            {
                if (length == 0) return false;
                p -= length;
                if (pieceIndex > 6) return false;
                int numbersSeen = 0;
                while (C() != null)
                {
                    int? piece = null;
                    if (numbersSeen > 0)
                    {
                        if (C() == '.' && numbersSeen < 4) p++;
                        else return false;
                    }
                    if (!IsDigit(C())) return false;
                    while (IsDigit(C()))
                    {
                        var n = C()!.Value - '0';
                        if (piece == null) piece = n;
                        else if (piece == 0) return false;
                        else piece = piece * 10 + n;
                        if (piece > 255) return false;
                        p++;
                    }
                    numbersSeen++;
                    if (numbersSeen == 2 || numbersSeen == 4) pieceIndex++;
                }
                if (numbersSeen != 4) return false;
                break;
            }
            else if (C() == ':')
            {
                p++;
                if (C() == null) return false;
            }
            else if (C() != null) return false;
            pieceIndex++;
        }
        return compress != null || pieceIndex == 8;
    }
}

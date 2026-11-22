// JavaScript string, URI and URL behaviours the vault reads (decodeURIComponent, URLSearchParams, new URL members, Node's lenient base64url).
using System.Text;
using AtlasPca.Js;
using AtlasPca.Jose;

namespace AtlasPca.Connect;

/// <summary>The members of <c>new URL(x)</c> the vault reads: <c>protocol</c>, <c>origin</c>, <c>pathname</c>, <c>search</c>.</summary>
internal sealed record UrlView(string Protocol, string Origin, string Pathname, string Search);

internal static class ConnectJs
{
    static FormatException Malformed() => new("URI malformed");

    static int Hex(char c) => c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : c >= 'A' && c <= 'F' ? c - 'A' + 10 : -1;

    static int Byte(string s, int i)
    {
        if (i + 2 >= s.Length || s[i] != '%') throw Malformed();
        int h = Hex(s[i + 1]), l = Hex(s[i + 2]);
        if (h < 0 || l < 0) throw Malformed();
        return h * 16 + l;
    }

    /// <summary>decodeURIComponent (ECMA-262 Decode): throws FormatException (the reference's URIError) on a malformed escape or invalid UTF-8.</summary>
    internal static string DecodeUriComponent(string s)
    {
        var sb = new StringBuilder();
        for (int k = 0; k < s.Length; k++)
        {
            char c = s[k];
            if (c != '%') { sb.Append(c); continue; }
            int start = k;
            if (k + 2 >= s.Length) throw Malformed();
            int b = Byte(s, k);
            k += 2;
            if (b < 0x80) { sb.Append((char)b); continue; }
            int n = (b & 0xE0) == 0xC0 ? 2 : (b & 0xF0) == 0xE0 ? 3 : (b & 0xF8) == 0xF0 ? 4 : 0;
            if (n == 0) throw Malformed();
            if (start + 3 * (n - 1) >= s.Length) throw Malformed();
            int cp = b & (0xFF >> (n + 1));
            for (int j = 1; j < n; j++)
            {
                k++;
                if (k + 2 >= s.Length || s[k] != '%') throw Malformed();
                int b2 = Byte(s, k);
                k += 2;
                if ((b2 & 0xC0) != 0x80) throw Malformed();
                cp = (cp << 6) | (b2 & 0x3F);
            }
            bool bad = cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF) || (n == 2 && cp < 0x80) || (n == 3 && cp < 0x800) || (n == 4 && cp < 0x10000);
            if (bad) throw Malformed();
            sb.Append(char.ConvertFromUtf32(cp));
        }
        return sb.ToString();
    }

    /// <summary>key=value pairs joined with '&amp;', each side through encodeURIComponent, in the given order (a lone surrogate throws FormatException).</summary>
    internal static string FormEncode(IEnumerable<KeyValuePair<string, string>> pairs)
    {
        var sb = new StringBuilder();
        foreach (var (k, v) in pairs)
        {
            if (sb.Length > 0) sb.Append('&');
            sb.Append(JsJson.EncodeUriComponent(k)).Append('=').Append(JsJson.EncodeUriComponent(v));
        }
        return sb.ToString();
    }

    /// <summary><c>s.split(/\s+/)</c> (JavaScript semantics: leading and trailing empty pieces are kept).</summary>
    internal static List<string> SplitRuns(string s)
    {
        var o = new List<string>();
        int start = 0, i = 0;
        while (i < s.Length)
        {
            if (JsJson.IsJsSpace(s[i]))
            {
                int j = i;
                while (j < s.Length && JsJson.IsJsSpace(s[j])) j++;
                o.Add(s[start..i]);
                start = j;
                i = j;
            }
            else i++;
        }
        o.Add(s[start..]);
        return o;
    }

    /// <summary>Replace every secret in <paramref name="text"/> (split/join semantics) so an error message can never carry one.</summary>
    internal static string Redact(string text, IEnumerable<string?> secrets)
    {
        var o = text;
        foreach (var s in secrets) if (!string.IsNullOrEmpty(s)) o = o.Replace(s, "[redacted]", StringComparison.Ordinal);
        return o;
    }

    // ---- URLSearchParams ----

    /// <summary>The application/x-www-form-urlencoded parser behind URLSearchParams: '+' is a space, an invalid percent escape stays literal, UTF-8 is decoded leniently.</summary>
    internal static List<string[]> FormParse(string s)
    {
        var o = new List<string[]>();
        if (s.Length == 0) return o;
        foreach (var part in s.Split('&'))
        {
            if (part.Length == 0) continue;
            int eq = part.IndexOf('=');
            string k = eq < 0 ? part : part[..eq], v = eq < 0 ? "" : part[(eq + 1)..];
            o.Add(new[] { PctLenient(k.Replace('+', ' ')), PctLenient(v.Replace('+', ' ')) });
        }
        return o;
    }

    /// <summary><c>new URLSearchParams(text)</c> input: one leading '?' is dropped.</summary>
    internal static List<string[]> FormParseText(string text) => FormParse(text.StartsWith('?') ? text[1..] : text);

    static string PctLenient(string s)
    {
        if (s.IndexOf('%') < 0) return s;
        var o = new List<byte>();
        var inp = Encoding.UTF8.GetBytes(s);
        for (int i = 0; i < inp.Length; i++)
        {
            if (inp[i] == '%' && i + 2 < inp.Length && Hex((char)inp[i + 1]) >= 0 && Hex((char)inp[i + 2]) >= 0)
            {
                o.Add((byte)(Hex((char)inp[i + 1]) * 16 + Hex((char)inp[i + 2])));
                i += 2;
            }
            else o.Add(inp[i]);
        }
        return Encoding.UTF8.GetString(o.ToArray());
    }

    // ---- new URL(x) ----

    static string Clean(string input)
    {
        int a = 0, b = input.Length;
        while (a < b && input[a] <= 0x20) a++;
        while (b > a && input[b - 1] <= 0x20) b--;
        var sb = new StringBuilder();
        for (int i = a; i < b; i++) if (input[i] != '\t' && input[i] != '\n' && input[i] != '\r') sb.Append(input[i]);
        return sb.ToString();
    }

    /// <summary>True when <c>new URL(input).hash</c> is not the empty string (a '#' followed by at least one character).</summary>
    internal static bool HasFragment(string input)
    {
        var s = Clean(input);
        int h = s.IndexOf('#');
        return h >= 0 && h + 1 < s.Length;
    }

    static bool Special(string s)
    {
        int c = s.IndexOf(':');
        return c >= 0 && s[..c].ToLowerInvariant() is "http" or "https" or "ftp" or "ws" or "wss";
    }

    /// <summary>True when the URL carries a non-empty username or password.</summary>
    internal static bool HasCredentials(string input)
    {
        var s = Clean(input);
        int c = s.IndexOf(':');
        if (c < 0) return false;
        var rest = s[(c + 1)..];
        bool sp = Special(s);
        int p = 0;
        if (sp) { while (p < rest.Length && (rest[p] == '/' || rest[p] == '\\')) p++; }
        else if (rest.StartsWith("//", StringComparison.Ordinal)) p = 2;
        else return false;
        int e = rest.Length;
        for (int k = p; k < rest.Length; k++)
        {
            char ch = rest[k];
            if (ch == '/' || ch == '?' || ch == '#' || (sp && ch == '\\')) { e = k; break; }
        }
        var authority = rest[p..e];
        int at = authority.LastIndexOf('@');
        if (at < 0) return false;
        var userinfo = authority[..at];
        return !(userinfo.Length == 0 || userinfo == ":");
    }

    static string EncodeQuery(string s)
    {
        var sb = new StringBuilder();
        foreach (var r in s.EnumerateRunes()) // a lone surrogate enumerates as U+FFFD, as the URL parser sees it
        {
            int cp = r.Value;
            bool enc = cp > 0x7e || cp <= 0x20 || cp == '"' || cp == '#' || cp == '<' || cp == '>' || cp == '\'';
            if (!enc) { sb.Append((char)cp); continue; }
            foreach (var b in Encoding.UTF8.GetBytes(r.ToString())) sb.Append('%').Append(b.ToString("X2", System.Globalization.CultureInfo.InvariantCulture));
        }
        return sb.ToString();
    }

    /// <summary>The URL's members, or null where <c>new URL()</c> throws (or the reader refuses the form: fail closed).
    /// shortcut: the host and path come from the shared WHATWG reader, only the query is read here; upgrade with that reader.</summary>
    internal static UrlView? ParseUrl(string input)
    {
        UrlParts? u;
        try { u = WhatwgUrl.TryParse(input); }
        catch (Exception) { return null; }
        if (u == null) return null;
        var s = Clean(input);
        int h = s.IndexOf('#');
        var t = h >= 0 ? s[..h] : s;
        int q = t.IndexOf('?');
        var query = q >= 0 ? t[(q + 1)..] : "";
        var search = query.Length == 0 ? "" : "?" + EncodeQuery(query);
        var origin = Special(s) ? u.Protocol + "//" + u.Host : "null";
        return new UrlView(u.Protocol, origin, u.Pathname, search);
    }

    // ---- Node's Buffer.from(s, 'base64url') ----

    /// <summary>Node's lenient base64url decoding: characters outside the alphabet are skipped, non-canonical trailing bits and a dangling single character are accepted.</summary>
    internal static byte[] LenientB64uDecode(string s)
    {
        var o = new List<byte>();
        int acc = 0, bits = 0;
        foreach (var c in s)
        {
            int v = c >= 'A' && c <= 'Z' ? c - 'A' : c >= 'a' && c <= 'z' ? c - 'a' + 26 : c >= '0' && c <= '9' ? c - '0' + 52 : c == '+' || c == '-' ? 62 : c == '/' || c == '_' ? 63 : -1;
            if (c == '=') break;
            if (v < 0) continue;
            acc = (acc << 6) | v;
            bits += 6;
            if (bits >= 8) { bits -= 8; o.Add((byte)((acc >> bits) & 0xFF)); acc &= (1 << bits) - 1; }
        }
        return o.ToArray();
    }
}

using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;
using AtlasPca.Js;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.PolicyBridgeKit;

/// <summary>JavaScript string semantics the policy translators depend on: the exact whitespace set of <c>\s</c> / <c>trim()</c>, ASCII word
/// boundaries, <c>slice</c>, <c>JSON.stringify</c> of strings, the top-level splitters and the key order of <c>Object.entries</c>. Regex fragments are
/// built so a .NET pattern matches what the JavaScript pattern matches.</summary>
internal static class PbJs
{
    /// <summary>The characters of JavaScript <c>\s</c> (WhiteSpace and LineTerminator), as the inside of a character class.</summary>
    public const string Ws = @"\t\n\v\f\r    - \u2028\u2029  　﻿";
    public const string S = "[" + Ws + "]";
    public const string NS = "[^" + Ws + "]";
    /// <summary>JavaScript <c>.</c> (no dotAll): everything but the four line terminators.</summary>
    public const string Dot = @"[^\n\r\u2028\u2029]";
    /// <summary>JavaScript <c>\b</c> next to a <c>\w</c> character (<c>\w</c> is ASCII only).</summary>
    public const string WbL = "(?<![A-Za-z0-9_])";
    public const string WbR = "(?![A-Za-z0-9_])";

    const RegexOptions Ro = RegexOptions.CultureInvariant;
    static readonly Regex WsRun = new(S + "+", Ro);

    /// <summary>A pattern that must match the whole input (Java <c>matches</c>).</summary>
    public static Regex Full(string p) => new(@"\A(?:" + p + @")\z", Ro);
    /// <summary>A pattern that must match at the start of the input (Java <c>lookingAt</c>).</summary>
    public static Regex Start(string p) => new(@"\G(?:" + p + ")", Ro);
    public static Regex Find(string p) => new(p, Ro);

    /// <summary>A case-insensitive spelling of an ASCII word (the non-Unicode JavaScript /i never maps a non-ASCII character onto an ASCII letter).</summary>
    public static string CI(string word) => string.Concat(word.Select(c => char.IsLetter(c) ? $"[{char.ToLowerInvariant(c)}{char.ToUpperInvariant(c)}]" : c.ToString()));

    public static string Trim(string s)
    {
        int a = 0, b = s.Length;
        while (a < b && JsJson.IsJsSpace(s[a])) a++;
        while (b > a && JsJson.IsJsSpace(s[b - 1])) b--;
        return s[a..b];
    }

    /// <summary>String.prototype.slice(from, to).</summary>
    public static string Slice(string s, int from, int to)
    {
        int n = s.Length;
        int a = from < 0 ? Math.Max(n + from, 0) : Math.Min(from, n);
        int b = to < 0 ? Math.Max(n + to, 0) : Math.Min(to, n);
        return a >= b ? "" : s[a..b];
    }

    public static string Slice(string s, int from) => Slice(s, from, s.Length);

    public static bool IsAsciiLetter(char c) => (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
    public static bool IsIdentStart(char c) => IsAsciiLetter(c) || c == '_';
    public static bool IsIdentPart(char c) => IsIdentStart(c) || (c >= '0' && c <= '9');
    public static bool IsDigit(char c) => c >= '0' && c <= '9';

    /// <summary>truncate: whitespace collapsed to one space, at most 80 UTF-16 units.</summary>
    public static string Truncate(string s)
    {
        var one = Trim(WsRun.Replace(s, " "));
        return one.Length > 80 ? Slice(one, 0, 77) + "..." : one;
    }

    /// <summary>JSON.stringify of a string (well-formed: a lone surrogate is escaped).</summary>
    public static string JsonStr(string s)
    {
        var sb = new StringBuilder();
        JsJson.Str(sb, s);
        return sb.ToString();
    }

    /// <summary>JSON.stringify of a verb: a string or a list of strings.</summary>
    public static string JsonVerb(object? verb) => verb is string s ? JsonStr(s) : "[" + string.Join(",", ((L)verb!).Select(o => JsonStr((string)o!))) + "]";

    /// <summary>A JavaScript number from its decimal text, as the JSON number the reference serializes.</summary>
    public static Num Number(string text)
    {
        var d = double.Parse(text, NumberStyles.Float, CultureInfo.InvariantCulture);
        return new Num(d == 0 ? "0" : JsJson.NumberToString(d));
    }

    public static Num N(long v) => new(v.ToString(CultureInfo.InvariantCulture));

    /// <summary>The own keys of an object in Object.entries order: array indices ascending, then insertion order.</summary>
    public static List<string> EntryKeys(D m) => IntentJs.JsKeys(m.Keys).ToList();

    /// <summary>Object.entries of an object or array value (an array's keys are its indices); null for anything else.</summary>
    public static List<KeyValuePair<string, object?>>? Entries(object? o)
    {
        if (o is D m) return EntryKeys(m).Select(k => new KeyValuePair<string, object?>(k, m[k])).ToList();
        if (o is L l) return l.Select((v, i) => new KeyValuePair<string, object?>(i.ToString(CultureInfo.InvariantCulture), v)).ToList();
        return null;
    }

    // ---- bracket and quote aware scanning (shared by the Cedar and Rego readers) ----

    /// <summary>Index of <paramref name="token"/> at bracket/quote depth 0, or -1.</summary>
    public static int IndexOfTopLevel(string text, string token)
    {
        int depth = 0;
        bool inStr = false;
        for (int i = 0; i < text.Length; i++)
        {
            char ch = text[i];
            if (inStr) { if (ch == '"') inStr = false; continue; }
            if (ch == '"') { inStr = true; continue; }
            if (ch == '(' || ch == '[' || ch == '{') depth++;
            else if (ch == ')' || ch == ']' || ch == '}') depth--;
            else if (depth == 0 && string.CompareOrdinal(text, i, token, 0, token.Length) == 0) return i;
        }
        return -1;
    }

    /// <summary>Split on a delimiter (one or two characters) at bracket/quote depth 0.</summary>
    public static List<string> SplitTopLevel(string text, string delim)
    {
        var outp = new List<string>();
        int depth = 0;
        bool inStr = false;
        int start = 0;
        for (int i = 0; i < text.Length; i++)
        {
            char ch = text[i];
            if (inStr) { if (ch == '"') inStr = false; continue; }
            if (ch == '"') { inStr = true; continue; }
            if (ch == '(' || ch == '[' || ch == '{') depth++;
            else if (ch == ')' || ch == ']' || ch == '}') depth--;
            if (depth == 0 && string.CompareOrdinal(text, i, delim, 0, delim.Length) == 0)
            {
                outp.Add(text[start..i]);
                i += delim.Length - 1;
                start = i + 1;
            }
        }
        outp.Add(text[Math.Min(start, text.Length)..]);
        return outp;
    }

    public static int MatchDelim(string text, int open, char o, char c)
    {
        int depth = 0;
        bool inStr = false;
        for (int i = open; i < text.Length; i++)
        {
            char ch = text[i];
            if (inStr) { if (ch == '"') inStr = false; continue; }
            if (ch == '"') inStr = true;
            else if (ch == o) depth++;
            else if (ch == c) { depth--; if (depth == 0) return i; }
        }
        return -1;
    }

    public static List<string> TrimmedNonEmpty(IEnumerable<string> parts) => parts.Select(Trim).Where(t => t.Length > 0).ToList();

    /// <summary>A growable JSON object in insertion order: <c>Obj("field", f, "op", o, ...)</c>.</summary>
    public static D Obj(params object?[] kv)
    {
        var m = new D();
        for (int i = 0; i < kv.Length; i += 2) m[(string)kv[i]!] = kv[i + 1];
        return m;
    }
}

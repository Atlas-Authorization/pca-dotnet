using System.Text;
using System.Text.RegularExpressions;
using AtlasPca.InteropJs;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.WebBotAuth;

/// <summary>A parse failure the reference raises as WebBotAuthParseError (its message is part of the verify reason).</summary>
public sealed class WebBotAuthParseError : Exception
{
    public WebBotAuthParseError(string message) : base(message) { }
}

/// <summary>JavaScript string / number / Buffer semantics the Web Bot Auth port needs.</summary>
internal static class WbaJs
{
    /// <summary>JavaScript's white space + line terminator set (<c>String.prototype.trim</c>).</summary>
    internal static bool IsWs(char c) =>
        c == ' ' || (c >= '\t' && c <= '\r') || c == ' ' || c == ' ' || (c >= ' ' && c <= ' ') || c == '\u2028' || c == '\u2029'
        || c == ' ' || c == ' ' || c == '　' || c == '﻿';

    internal static string Trim(string s)
    {
        int a = 0, b = s.Length;
        while (a < b && IsWs(s[a])) a++;
        while (b > a && IsWs(s[b - 1])) b--;
        return s[a..b];
    }

    /// <summary>The number value of a parsed JSON number (NaN when it is not one).</summary>
    internal static double Number(object? o) => IntentJs.NumOf(o) ?? double.NaN;

    internal static string Lower(string s) => s.ToLowerInvariant();

    internal static bool Def(object? m, string k) => m is D d && d.ContainsKey(k);

    internal static object? Get(object? m, string k) => m is D d ? d.GetValueOrDefault(k) : null;

    /// <summary><c>Buffer.from(s, "base64")</c>: standard and URL-safe alphabets, other characters skipped, decoding stops at the first "=", dangling bits dropped.</summary>
    internal static byte[] NodeBase64(string s)
    {
        var o = new List<byte>();
        int acc = 0, bits = 0;
        foreach (var c in s)
        {
            if (c == '=') break;
            int v = c >= 'A' && c <= 'Z' ? c - 'A' : c >= 'a' && c <= 'z' ? c - 'a' + 26 : c >= '0' && c <= '9' ? c - '0' + 52 : c == '+' || c == '-' ? 62 : c == '/' || c == '_' ? 63 : -1;
            if (v < 0) continue;
            acc = (acc << 6) | v;
            bits += 6;
            if (bits >= 8) { bits -= 8; o.Add((byte)((acc >> bits) & 0xff)); acc &= (1 << bits) - 1; }
        }
        return o.ToArray();
    }

    /// <summary>Standard base64 (padded).</summary>
    internal static string B64(byte[] b) => Convert.ToBase64String(b);

    internal static string NumStr(double d) => JsX.JsNumString(d);

    /// <summary><c>String(v)</c> of a parameter value (string, double or bool) or of undefined.</summary>
    internal static string Str(object? v) => v == null ? "undefined" : v is double d ? NumStr(d) : v is bool b ? (b ? "true" : "false") : v.ToString()!;

    /// <summary><c>String(v)</c> of any parsed JSON value.</summary>
    internal static string AnyStr(object? v) => JsX.Str(v);

    /// <summary>An RFC 8941 sf-string: quoted, with backslash and double quote escaped.</summary>
    internal static string SfString(string s) => "\"" + s.Replace("\\", "\\\\").Replace("\"", "\\\"") + "\"";

    /// <summary>A required member of an input bag as a string; anything else is a TypeError of the reference.</summary>
    internal static string RequireString(object? o, string what) => o as string ?? throw new InvalidOperationException($"TypeError: {what} must be a string");

    /// <summary>The members of a parsed JSON list, or none for any other value.</summary>
    internal static L ListOf(object? o) => o as L ?? new L();

    internal static Regex R(string pattern) => Rx.Get(pattern, RegexOptions.CultureInvariant);
}

/// <summary>A refusal the reference raises with a Node <c>code</c> (an <see cref="ArgumentException"/> carrying it).</summary>
public sealed class NodeCodedException(string code, string message) : ArgumentException(message)
{
    public string Code { get; } = code;
}

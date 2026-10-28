// The lenient canonical form of the reference (__canonicalizeLenientServerOnly): keys in UTF-8 order, JSON.stringify strings (a
// lone surrogate escaped as \uXXXX), Number::toString numbers (-0 as "0", non-finite refused), no depth limit.
using System.Globalization;
using System.Text;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca;

internal static class JsCanon
{
    /// <summary>The lenient canonical text, or null when a value is not canonicalizable (a non-finite number, an unsupported type).</summary>
    internal static string? Lenient(object? v)
    {
        var sb = new StringBuilder();
        return Ser(sb, v) ? sb.ToString() : null;
    }

    static bool Ser(StringBuilder sb, object? v)
    {
        switch (v)
        {
            case null: sb.Append("null"); return true;
            case bool b: sb.Append(b ? "true" : "false"); return true;
            case string s: Str(sb, s); return true;
            case D m:
                {
                    sb.Append('{');
                    var keys = IntentJs.SortedUtf8(m.Keys);
                    for (int i = 0; i < keys.Count; i++)
                    {
                        if (i > 0) sb.Append(',');
                        Str(sb, keys[i]); sb.Append(':');
                        if (!Ser(sb, m[keys[i]])) return false;
                    }
                    sb.Append('}');
                    return true;
                }
            case L l:
                sb.Append('[');
                for (int i = 0; i < l.Count; i++)
                {
                    if (i > 0) sb.Append(',');
                    if (!Ser(sb, l[i])) return false;
                }
                sb.Append(']');
                return true;
        }
        if (IntentJs.NumOf(v) is not double d || !double.IsFinite(d)) return false;
        sb.Append(NumberString(d));
        return true;
    }

    static void Str(StringBuilder sb, string s)
    {
        sb.Append('"');
        for (int i = 0; i < s.Length; i++)
        {
            char c = s[i];
            switch (c)
            {
                case '"': sb.Append("\\\""); break;
                case '\\': sb.Append("\\\\"); break;
                case '\b': sb.Append("\\b"); break;
                case '\f': sb.Append("\\f"); break;
                case '\n': sb.Append("\\n"); break;
                case '\r': sb.Append("\\r"); break;
                case '\t': sb.Append("\\t"); break;
                default:
                    if (c < 0x20) sb.Append("\\u").Append(((int)c).ToString("x4", CultureInfo.InvariantCulture));
                    else if (char.IsHighSurrogate(c) && i + 1 < s.Length && char.IsLowSurrogate(s[i + 1])) { sb.Append(c).Append(s[i + 1]); i++; }
                    else if (char.IsSurrogate(c)) sb.Append("\\u").Append(((int)c).ToString("x4", CultureInfo.InvariantCulture));
                    else sb.Append(c);
                    break;
            }
        }
        sb.Append('"');
    }

    /// <summary>ECMAScript Number::toString for a finite double (-0 prints "0").</summary>
    internal static string NumberString(double d)
    {
        if (d == 0) return "0";
        var neg = d < 0;
        var r = Math.Abs(d).ToString("R", CultureInfo.InvariantCulture); // shortest round-trip digits
        int e10 = 0;
        var ei = r.IndexOf('E');
        if (ei >= 0) { e10 = int.Parse(r[(ei + 1)..], NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture); r = r[..ei]; }
        var dot = r.IndexOf('.');
        var digits = dot < 0 ? r : r.Remove(dot, 1);
        int n = (dot < 0 ? r.Length : dot) + e10; // value = 0.DIGITS x 10^n
        int lead = 0;
        while (lead < digits.Length - 1 && digits[lead] == '0') lead++;
        digits = digits[lead..]; n -= lead;
        digits = digits.TrimEnd('0');
        if (digits.Length == 0) return "0";
        int k = digits.Length;
        string body;
        if (k <= n && n <= 21) body = digits + new string('0', n - k);
        else if (0 < n && n <= 21) body = digits[..n] + "." + digits[n..];
        else if (-6 < n && n <= 0) body = "0." + new string('0', -n) + digits;
        else
        {
            int ex = n - 1;
            var m = k == 1 ? digits : digits[..1] + "." + digits[1..];
            body = m + "e" + (ex < 0 ? "-" : "+") + Math.Abs(ex).ToString(CultureInfo.InvariantCulture);
        }
        return neg ? "-" + body : body;
    }
}

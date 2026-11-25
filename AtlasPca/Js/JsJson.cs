// JavaScript JSON.stringify / encodeURIComponent semantics over the house JSON tree (insertion-ordered objects).
using System.Globalization;
using System.Text;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Js;

public static class JsJson
{
    /// <summary>JSON.stringify of a tree: keys in insertion order, numbers as JavaScript prints them, no whitespace.</summary>
    public static string Stringify(object? v)
    {
        var sb = new StringBuilder();
        Ser(sb, v);
        return sb.ToString();
    }

    static void Ser(StringBuilder sb, object? v)
    {
        switch (v)
        {
            case null: sb.Append("null"); break;
            case bool b: sb.Append(b ? "true" : "false"); break;
            case string s: Str(sb, s); break;
            case Num n: sb.Append(double.TryParse(n.Raw, NumberStyles.Float, CultureInfo.InvariantCulture, out var nd) && double.IsFinite(nd) ? NumberToString(nd) : "null"); break;
            case int or long: sb.Append(Convert.ToString(v, CultureInfo.InvariantCulture)); break;
            case double dd: sb.Append(double.IsFinite(dd) ? NumberToString(dd) : "null"); break;
            case D m:
                sb.Append('{');
                var first = true;
                foreach (var k in IntentJs.JsKeys(m.Keys)) // Object.keys order: array-index keys ascending first
                {
                    if (!first) sb.Append(',');
                    first = false;
                    Str(sb, k); sb.Append(':'); Ser(sb, m[k]);
                }
                sb.Append('}');
                break;
            case IEnumerable<object?> l:
                sb.Append('[');
                var i = 0;
                foreach (var x in l) { if (i++ > 0) sb.Append(','); Ser(sb, x); }
                sb.Append(']');
                break;
            default: throw new InvalidOperationException("JsJson.Stringify: unsupported " + v.GetType());
        }
    }

    /// <summary>A JSON.stringify string literal (well-formed: a lone surrogate becomes \uXXXX).</summary>
    public static void Str(StringBuilder sb, string s)
    {
        sb.Append('"');
        for (int i = 0; i < s.Length; i++)
        {
            var c = s[i];
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

    /// <summary>JSON.stringify of one string.</summary>
    public static string Quote(string s)
    {
        var sb = new StringBuilder();
        Str(sb, s);
        return sb.ToString();
    }

    const string Unreserved = "-_.!~*'()";

    /// <summary>encodeURIComponent; throws on a lone surrogate (URIError in the reference).</summary>
    public static string EncodeUriComponent(string s)
    {
        var sb = new StringBuilder();
        for (int i = 0; i < s.Length; i++)
        {
            var c = s[i];
            if (c < 0x80 && (char.IsAsciiLetterOrDigit(c) || Unreserved.Contains(c))) { sb.Append(c); continue; }
            int len = 1;
            if (char.IsHighSurrogate(c) && i + 1 < s.Length && char.IsLowSurrogate(s[i + 1])) len = 2;
            else if (char.IsSurrogate(c)) throw new FormatException("URI malformed");
            foreach (var b in Encoding.UTF8.GetBytes(s.Substring(i, len))) sb.Append('%').Append(b.ToString("X2", CultureInfo.InvariantCulture));
            i += len - 1;
        }
        return sb.ToString();
    }

    /// <summary>Number::toString (ECMAScript): shortest round-trip digits, exponent form outside 1e-7 .. 1e21, -0 prints "0".</summary>
    public static string NumberToString(double d)
    {
        if (double.IsNaN(d)) return "NaN";
        if (double.IsInfinity(d)) return d > 0 ? "Infinity" : "-Infinity";
        if (d == 0) return "0";
        var neg = d < 0;
        var r = Math.Abs(d).ToString("E16", CultureInfo.InvariantCulture);
        // shortest round trip: try increasing precision
        string digits = ""; int exp10 = 0;
        for (int prec = 0; prec <= 16; prec++)
        {
            var t = Math.Abs(d).ToString("E" + prec, CultureInfo.InvariantCulture);
            if (double.Parse(t, CultureInfo.InvariantCulture) == Math.Abs(d) || prec == 16) { r = t; break; }
        }
        var ePos = r.IndexOf('E');
        var mant = r[..ePos].Replace(".", "");
        exp10 = int.Parse(r[(ePos + 1)..], CultureInfo.InvariantCulture);
        digits = mant.TrimEnd('0');
        if (digits.Length == 0) digits = "0";
        int k = digits.Length, n = exp10 + 1; // value = 0.digits x 10^n
        string body;
        if (k <= n && n <= 21) body = digits + new string('0', n - k);
        else if (0 < n && n <= 21) body = digits[..n] + "." + digits[n..];
        else if (-6 < n && n <= 0) body = "0." + new string('0', -n) + digits;
        else
        {
            var e = n - 1;
            var es = (e < 0 ? "-" : "+") + Math.Abs(e).ToString(CultureInfo.InvariantCulture);
            body = k == 1 ? digits + "e" + es : digits[0] + "." + digits[1..] + "e" + es;
        }
        return neg ? "-" + body : body;
    }

    /// <summary>The ECMAScript WhiteSpace and LineTerminator characters (what \s and String.prototype.trim use).</summary>
    public static bool IsJsSpace(char c) =>
        c is '\t' or '\n' or '\v' or '\f' or '\r' or ' ' or '\u00a0' or '\u1680' or '\u2028' or '\u2029' or '\u202f' or '\u205f' or '\u3000' or '\ufeff' || (c >= '\u2000' && c <= '\u200a');

    /// <summary>String(value) for a JSON tree value (undefined is the caller's business): arrays join with ",", objects are "[object Object]".</summary>
    public static string ToJsString(object? v) => v switch
    {
        null => "null",
        bool b => b ? "true" : "false",
        string s => s,
        Num n => double.TryParse(n.Raw, NumberStyles.Float, CultureInfo.InvariantCulture, out var d) ? NumberToString(d) : n.Raw,
        int or long => Convert.ToString(v, CultureInfo.InvariantCulture)!,
        double d => NumberToString(d),
        IEnumerable<object?> l => string.Join(",", l.Select(x => x == null ? "" : ToJsString(x))),
        _ => "[object Object]",
    };

    /// <summary>Number(value) for a JSON tree value.</summary>
    public static double ToJsNumber(object? v)
    {
        switch (v)
        {
            case null: return 0;
            case bool b: return b ? 1 : 0;
            case Num n: return double.TryParse(n.Raw, NumberStyles.Float, CultureInfo.InvariantCulture, out var d) ? d : double.NaN;
            case int or long: return Convert.ToDouble(v, CultureInfo.InvariantCulture);
            case double dd: return dd;
            case string s: return StringToNumber(s);
            case IEnumerable<object?> l: return StringToNumber(ToJsString(l));
            default: return double.NaN;
        }
    }

    static double StringToNumber(string s)
    {
        int a = 0, z = s.Length;
        while (a < z && IsJsSpace(s[a])) a++;
        while (z > a && IsJsSpace(s[z - 1])) z--;
        var t = s[a..z];
        if (t.Length == 0) return 0;
        if (t.Length > 2 && t[0] == '0' && t[1] is 'x' or 'X' or 'b' or 'B' or 'o' or 'O')
        {
            int radix = t[1] is 'x' or 'X' ? 16 : t[1] is 'b' or 'B' ? 2 : 8;
            System.Numerics.BigInteger acc = 0;
            for (int i = 2; i < t.Length; i++)
            {
                int dv = t[i] >= '0' && t[i] <= '9' ? t[i] - '0' : t[i] >= 'a' && t[i] <= 'f' ? t[i] - 'a' + 10 : t[i] >= 'A' && t[i] <= 'F' ? t[i] - 'A' + 10 : 99;
                if (dv >= radix) return double.NaN;
                acc = acc * radix + dv;
            }
            return (double)acc;
        }
        if (t is "Infinity" or "+Infinity") return double.PositiveInfinity;
        if (t == "-Infinity") return double.NegativeInfinity;
        if (!System.Text.RegularExpressions.Regex.IsMatch(t, @"\A[+-]?(?:[0-9]+\.?[0-9]*|\.[0-9]+)(?:[eE][+-]?[0-9]+)?\z", System.Text.RegularExpressions.RegexOptions.CultureInvariant)) return double.NaN;
        return double.Parse(t, NumberStyles.Float, CultureInfo.InvariantCulture);
    }
}

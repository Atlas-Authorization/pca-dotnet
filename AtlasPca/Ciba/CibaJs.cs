using System.Globalization;
using System.Numerics;
using System.Text;

namespace AtlasPca.Ciba;

/// <summary>Number and whitespace semantics of JavaScript the CIBA reference relies on (the rest of the JSON-value helpers are shared with the GNAP bridge).</summary>
static class CibaJs
{
    /// <summary>Number.isSafeInteger of a JSON value.</summary>
    internal static bool IsSafeInteger(object? o) =>
        AtlasPca.Gnap.GnapJs.NumOf(o) is double d && double.IsFinite(d) && d == Math.Round(d) && Math.Abs(d) <= 9007199254740991.0;

    /// <summary>String(n) of a number: the shortest round-trip digits laid out as ECMAScript does.</summary>
    internal static string JsNumber(double d)
    {
        if (double.IsNaN(d)) return "NaN";
        if (double.IsInfinity(d)) return d > 0 ? "Infinity" : "-Infinity";
        if (d == 0) return "0";
        bool neg = d < 0;
        var r = Math.Abs(d).ToString("R", CultureInfo.InvariantCulture); // shortest round-trip digits
        // split "d.dddE+xx" / "ddd.ddd" into digits and the decimal exponent n (value = 0.digits * 10^n)
        int exp = 0;
        var mant = r;
        int ei = r.IndexOfAny(new[] { 'E', 'e' });
        if (ei >= 0) { mant = r[..ei]; exp = int.Parse(r[(ei + 1)..], NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture); }
        int dot = mant.IndexOf('.');
        var digitsAll = mant.Replace(".", "");
        int intLen = dot >= 0 ? dot : mant.Length;
        int lead = 0;
        while (lead < digitsAll.Length - 1 && digitsAll[lead] == '0') lead++;
        var digits = digitsAll[lead..].TrimEnd('0');
        if (digits.Length == 0) digits = "0";
        int n = intLen - lead + exp;
        int k = digits.Length;
        var sb = new StringBuilder();
        if (neg) sb.Append('-');
        if (k <= n && n <= 21) { sb.Append(digits); sb.Append('0', n - k); }
        else if (0 < n && n <= 21) sb.Append(digits, 0, n).Append('.').Append(digits, n, k - n);
        else if (-6 < n && n <= 0) { sb.Append("0."); sb.Append('0', -n); sb.Append(digits); }
        else
        {
            int e = n - 1;
            sb.Append(digits[0]);
            if (k > 1) sb.Append('.').Append(digits, 1, k - 1);
            sb.Append('e').Append(e < 0 ? '-' : '+').Append(Math.Abs(e).ToString(CultureInfo.InvariantCulture));
        }
        return sb.ToString();
    }

    /// <summary>The JavaScript whitespace set (\s, also what trim removes).</summary>
    internal static bool IsWs(int c) =>
        (c >= 0x09 && c <= 0x0d) || c == 0x20 || c == 0xa0 || c == 0x1680 || (c >= 0x2000 && c <= 0x200a) || c == 0x2028 || c == 0x2029 || c == 0x202f || c == 0x205f || c == 0x3000 || c == 0xfeff;

    internal static string Trim(string s)
    {
        int a = 0, b = s.Length;
        while (a < b && IsWs(s[a])) a++;
        while (b > a && IsWs(s[b - 1])) b--;
        return s[a..b];
    }

    /// <summary>The code points of a string (a lone surrogate is its own code point).</summary>
    internal static List<int> CodePoints(string s)
    {
        var o = new List<int>(s.Length);
        for (int i = 0; i < s.Length; i++)
        {
            if (char.IsHighSurrogate(s[i]) && i + 1 < s.Length && char.IsLowSurrogate(s[i + 1])) { o.Add(char.ConvertToUtf32(s[i], s[i + 1])); i++; }
            else o.Add(s[i]);
        }
        return o;
    }

    internal static string FromCodePoint(int cp) => cp >= 0xd800 && cp <= 0xdfff ? ((char)cp).ToString() : char.ConvertFromUtf32(cp);

    /// <summary>A deep copy of a JSON tree (what structuredClone gives for JSON values).</summary>
    internal static object? DeepCopy(object? v) => v switch
    {
        Dictionary<string, object?> m => m.ToDictionary(e => e.Key, e => DeepCopy(e.Value)),
        List<object?> l => l.Select(DeepCopy).ToList(),
        _ => v,
    };
}

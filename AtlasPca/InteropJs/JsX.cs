using System.Globalization;
using System.Numerics;
using System.Text;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.InteropJs;

/// <summary>JavaScript value semantics over the parsed JSON tree (D, L, string, bool, Num, null), shared by the interop ports
/// (mcp, a2a, agentcard, webbotauth): truthiness, object spread, number-to-string, Number.isSafeInteger.</summary>
internal static class JsX
{
    internal const double MaxSafe = 9007199254740991.0;

    internal static bool Truthy(object? o) => o switch
    {
        null => false,
        _ when ReferenceEquals(o, Undef) => false,
        bool b => b,
        string s => s.Length > 0,
        Num n => IntentJs.NumOf(n) is double d && !(d == 0.0 || double.IsNaN(d)),
        _ => true,
    };

    /// <summary><c>{...x}</c>: a map copies, a list or string spreads its indices, any other value has no own members.</summary>
    internal static D Spread(object? x)
    {
        var o = new D();
        switch (x)
        {
            case D m: foreach (var (k, v) in m) o[k] = v; break;
            case L l: for (int i = 0; i < l.Count; i++) o[i.ToString(CultureInfo.InvariantCulture)] = l[i]; break;
            case string s: for (int i = 0; i < s.Length; i++) o[i.ToString(CultureInfo.InvariantCulture)] = s[i].ToString(); break;
        }
        return o;
    }

    /// <summary><c>Object.keys(o)</c> of a parsed value (JavaScript order: array-index keys ascending, then insertion order).</summary>
    internal static List<string> Keys(object? o)
    {
        var raw = new List<string>();
        switch (o)
        {
            case D m: raw.AddRange(m.Keys); break;
            case L l: for (int i = 0; i < l.Count; i++) raw.Add(i.ToString(CultureInfo.InvariantCulture)); break;
            case string s: for (int i = 0; i < s.Length; i++) raw.Add(i.ToString(CultureInfo.InvariantCulture)); break;
        }
        return IntentJs.JsKeys(raw).ToList();
    }

    /// <summary><c>o[k]</c> for a key of <see cref="Keys"/>.</summary>
    internal static object? ValueOf(object? o, string k) => o switch
    {
        D m => m.GetValueOrDefault(k),
        L l => l[int.Parse(k, CultureInfo.InvariantCulture)],
        string s => s[int.Parse(k, CultureInfo.InvariantCulture)].ToString(),
        _ => null,
    };

    /// <summary><c>Number.isSafeInteger</c> (accepts -0).</summary>
    internal static bool SafeInt(object? o) => IntentJs.IsSafeInteger(o);

    internal static double? NumOf(object? o) => IntentJs.NumOf(o);

    /// <summary>A binary64 value as the Num the reference's JSON would print (a non-finite value is null, as JSON.stringify prints it).</summary>
    internal static object? Number(double d) => double.IsFinite(d) ? new Num(JsNumString(d)) : null;

    /// <summary>Number.prototype.toString for a double.</summary>
    internal static string JsNumString(double d)
    {
        if (double.IsNaN(d)) return "NaN";
        if (d == 0) return "0";
        if (double.IsInfinity(d)) return d > 0 ? "Infinity" : "-Infinity";
        if (d < 0) return "-" + JsNumString(-d);
        var r = d.ToString("R", CultureInfo.InvariantCulture);
        int exp = 0;
        var ei = r.IndexOf('E');
        if (ei >= 0) { exp = int.Parse(r[(ei + 1)..], NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture); r = r[..ei]; }
        var dot = r.IndexOf('.');
        var digits = dot < 0 ? r : r.Remove(dot, 1);
        int n = (dot < 0 ? r.Length : dot) + exp;
        int lead = 0;
        while (lead < digits.Length - 1 && digits[lead] == '0') lead++;
        digits = digits[lead..]; n -= lead;
        digits = digits.TrimEnd('0');
        if (digits.Length == 0) return "0";
        int k = digits.Length;
        if (k <= n && n <= 21) return digits + new string('0', n - k);
        if (0 < n && n <= 21) return digits[..n] + "." + digits[n..];
        if (-6 < n && n <= 0) return "0." + new string('0', -n) + digits;
        int e = n - 1;
        var es = (e < 0 ? "-" : "+") + Math.Abs(e).ToString(CultureInfo.InvariantCulture);
        return k == 1 ? digits + "e" + es : digits[0] + "." + digits[1..] + "e" + es;
    }

    /// <summary><c>String(v)</c> for parsed JSON (an array joins its elements with commas, null and undefined elements empty).</summary>
    internal static string Str(object? v)
    {
        if (ReferenceEquals(v, Undef)) return "undefined";
        switch (v)
        {
            case null: return "null";
            case string s: return s;
            case bool b: return b ? "true" : "false";
            case L l:
                var sb = new StringBuilder();
                for (int i = 0; i < l.Count; i++) { if (i > 0) sb.Append(','); if (l[i] != null) sb.Append(Str(l[i])); }
                return sb.ToString();
            case D: return "[object Object]";
        }
        return IntentJs.NumOf(v) is double d ? JsNumString(d) : "[object Object]";
    }

    /// <summary>JavaScript <c>undefined</c> as opposed to JSON null (a member that is absent).</summary>
    internal static readonly object Undef = new();

    /// <summary><c>o[k]</c>: Undef when absent or when <paramref name="o"/> is not an object; a null or undefined o throws (TypeError).</summary>
    internal static object? At(object? o, string k)
    {
        if (o == null || ReferenceEquals(o, Undef)) throw TypeError($"cannot read properties of null (reading '{k}')");
        return o is D m ? (m.TryGetValue(k, out var v) ? v : Undef) : Undef;
    }

    /// <summary><c>o?.[k]</c>: Undef for null / non-objects / absent.</summary>
    internal static object? Opt(object? o, string k) => o == null || ReferenceEquals(o, Undef) ? Undef : At(o, k);

    /// <summary>Undef reads as JSON null.</summary>
    internal static object? JsonOf(object? v) => ReferenceEquals(v, Undef) ? null : v;

    /// <summary>JavaScript <c>a === b</c> for parsed JSON values; objects and arrays are never equal (distinct references).</summary>
    internal static bool StrictEq(object? a, object? b)
    {
        if (ReferenceEquals(a, Undef) || ReferenceEquals(b, Undef)) return ReferenceEquals(a, b);
        if (a == null || b == null) return a == null && b == null;
        if (a is string x && b is string y) return x == y;
        if (a is bool p && b is bool q) return p == q;
        return NumOf(a) is double d && NumOf(b) is double e && d == e;
    }

    /// <summary><c>String.prototype.trim</c> (ECMAScript white space and line terminators).</summary>
    internal static string JsTrim(string s)
    {
        int a = 0, b = s.Length;
        while (a < b && A2a.IsJsSpace(s[a])) a++;
        while (b > a && A2a.IsJsSpace(s[b - 1])) b--;
        return s[a..b];
    }

    /// <summary><c>new Date(ms).toISOString()</c>; throws (RangeError) for an invalid time value.</summary>
    internal static string ToIsoString(object? msO)
    {
        if (NumOf(msO) is not double d || double.IsNaN(d) || double.IsInfinity(d) || Math.Abs(d) > 8.64e15) throw new ArgumentException("Invalid time value");
        long ms = (long)Math.Truncate(d); // TimeClip truncates toward zero
        long days = ms >= 0 ? ms / 86_400_000 : -((-ms + 86_399_999) / 86_400_000);
        long rem = ms - days * 86_400_000;
        long z = days + 719_468;
        long era = (z >= 0 ? z : z - 146_096) / 146_097;
        long doe = z - era * 146_097;
        long yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
        long y = yoe + era * 400;
        long doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        long mp = (5 * doy + 2) / 153;
        long dd = doy - (153 * mp + 2) / 5 + 1;
        long mo = mp < 10 ? mp + 3 : mp - 9;
        if (mo <= 2) y++;
        var year = y >= 0 && y <= 9999 ? y.ToString("D4", CultureInfo.InvariantCulture) : (y < 0 ? "-" : "+") + Math.Abs(y).ToString("D6", CultureInfo.InvariantCulture);
        long hh = rem / 3_600_000, mi = rem / 60_000 % 60, ss = rem / 1000 % 60, mss = rem % 1000;
        return string.Create(CultureInfo.InvariantCulture, $"{year}-{mo:D2}-{dd:D2}T{hh:D2}:{mi:D2}:{ss:D2}.{mss:D3}Z");
    }

    /// <summary>A reference TypeError: the native refuses by throwing (the reference throws, with no code).</summary>
    internal static InvalidOperationException TypeError(string message) => new("TypeError: " + message);
}

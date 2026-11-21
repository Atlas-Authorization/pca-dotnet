using System.Globalization;
using System.Numerics;
using System.Text;
using System.Text.RegularExpressions;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.GoalPkg;

/// <summary>A value that is not exactly a Goal IR value, or a malformed compiler tape.</summary>
public sealed class IrError : Exception
{
    public IrError(string m) : base("pca-goal: " + m) { }
}

/// <summary>Java-shaped accessors over the goal modules' parsed-JSON values (a Goal is a dictionary of parsed JSON, like the
/// TypeScript objects): lowercase on purpose so the goal sources read like each other.</summary>
internal static class JX
{
    public static object? get(this D m, object? k) => k is string s && m.TryGetValue(s, out var v) ? v : null;
    public static V? get<V>(this Dictionary<string, V> m, object? k) => k is string s && m.TryGetValue(s, out var v) ? v : default;
    public static T? get<T>(this IList<T> l, int i) => l[i];
    public static object? put(this D m, string k, object? v) { var o = m.get(k); m[k] = v; return o; }
    public static void put<V>(this Dictionary<string, V> m, string k, V v) => m[k] = v;
    public static bool containsKey<V>(this IDictionary<string, V> m, object? k) => k is string s && m.ContainsKey(s);
    public static ICollection<string> keySet<V>(this IDictionary<string, V> m) => m.Keys;
    public static int size<T>(this ICollection<T> c) => c.Count;
    public static bool isEmpty<T>(this ICollection<T> c) => c.Count == 0;
    public static bool isEmpty(this string s) => s.Length == 0;
    public static void add<T>(this ICollection<T> c, T x) => c.Add(x);
    public static bool add<T>(this HashSet<T> c, T x) => c.Add(x);
    public static void addAll<T>(this List<T> c, IEnumerable<T> x) => c.AddRange(x);
    public static V computeIfAbsent<K, V>(this Dictionary<K, V> m, K k, Func<K, V> f) where K : notnull { if (!m.TryGetValue(k, out var v)) m[k] = v = f(k); return v; }
    public static void addAll<T>(this HashSet<T> s, IEnumerable<T> x) => s.UnionWith(x);
    public static bool contains(this IEnumerable<object?> c, object? x) { foreach (var e in c) if (Equals(e, x)) return true; return false; }
    public static bool contains(this List<string> c, object? x) => x is string s && c.Contains(s);
    public static int indexOf<T>(this IList<T> c, T x) => c.IndexOf(x);
    public static int indexOf(this string s, char c) => s.IndexOf(c);
    public static int indexOf(this string s, string c) => s.IndexOf(c, StringComparison.Ordinal);
    public static int lastIndexOf(this string s, char c) => s.LastIndexOf(c);
    public static string replace(this string s, string a, string b) => s.Replace(a, b, StringComparison.Ordinal);
    public static void remove<V>(this Dictionary<string, V> m, string k) => m.Remove(k);
    /// <summary>Stable sort (Java List.sort / Array.prototype.sort).</summary>
    public static void sort<T>(this List<T> l, Comparison<T> c)
    {
        var s = l.Select((x, i) => (x, i)).OrderBy(t => t, Comparer<(T x, int i)>.Create((a, b) => { var r = c(a.x, b.x); return r != 0 ? r : a.i.CompareTo(b.i); })).Select(t => t.x).ToList();
        l.Clear();
        l.AddRange(s);
    }
    public static bool startsWith(this string s, string p) => s.StartsWith(p, StringComparison.Ordinal);
    public static bool endsWith(this string s, string p) => s.EndsWith(p, StringComparison.Ordinal);
    public static int compareTo(this string a, string b) => string.CompareOrdinal(a, b);
    public static string substring(this string s, int a) => s.Substring(a);
    public static string substring(this string s, int a, int b) => s.Substring(a, b - a);
    public static bool equals(this string? a, object? b) => b is string s && a == s;
    public static bool equals(this object? a, object? b) => Equals(a, b);
    public static string toString(this object? o) => o?.ToString() ?? "null";
}

/// <summary>Small JSON-shaped value helpers shared by the goal modules.</summary>
internal static class G
{
    public const long MAX_SAFE = 9007199254740991L;

    public static D? m(object? o) => o as D;
    public static L? l(object? o) => o as L;

    public static D obj(object? o, string what) => o as D ?? throw new IrError(what + " expected an object");

    public static L arr(object? o, string what) => o as L ?? throw new IrError("array expected" + (what.Length == 0 ? "" : " (" + what + ")"));

    public static object? get(object? o, string k) => o is D d && d.TryGetValue(k, out var v) ? v : null;

    public static bool has(object? o, string k) => o is D d && d.ContainsKey(k);

    public static string str(object? o, string k) => get(o, k) as string ?? throw new IrError("string expected");

    /// <summary>The discriminant k of a value ("" when absent or not a string).</summary>
    public static string kind(object? o) => get(o, "k") as string ?? "";

    /// <summary>Safe-integer value of a JSON number (Num, long, int), or null. -0 and non-integers are null.</summary>
    public static long? safeInt(object? v)
    {
        if (v is long l) return Math.Abs(l) <= MAX_SAFE ? l : null;
        if (v is int i) return i;
        if (v is Num n) return SafeIntRaw(n.Raw);
        return null;
    }

    static long? SafeIntRaw(string raw)
    {
        var m = Regex.Match(raw, @"^(-?)([0-9]*)(?:\.([0-9]*))?(?:[eE]([+-]?[0-9]+))?$");
        if (!m.Success || (m.Groups[2].Length == 0 && m.Groups[3].Length == 0)) return null;
        var digits = (m.Groups[2].Value + m.Groups[3].Value).TrimStart('0');
        long scale = -m.Groups[3].Length;
        if (m.Groups[4].Success)
        {
            if (!long.TryParse(m.Groups[4].Value, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out var e) || Math.Abs(e) > 100000) return digits.Length == 0 && m.Groups[1].Length == 0 ? 0L : null;
            scale += e;
        }
        if (digits.Length == 0) return m.Groups[1].Length == 1 ? null : 0L; // -0 is refused
        BigInteger v = BigInteger.Parse(digits, CultureInfo.InvariantCulture);
        if (scale >= 0) { if (scale > 40) return null; v *= BigInteger.Pow(10, (int)scale); }
        else
        {
            if (-scale > digits.Length + 1) return null;
            var p = BigInteger.Pow(10, (int)-scale);
            if (!(v % p).IsZero) return null;
            v /= p;
        }
        if (v > MAX_SAFE) return null;
        return (long)(m.Groups[1].Length == 1 ? -v : v);
    }

    /// <summary>The number as a JavaScript double, or null when it is not a number.</summary>
    public static double? dbl(object? v)
    {
        if (v is Num n) return double.TryParse(n.Raw, NumberStyles.Float, CultureInfo.InvariantCulture, out var d) ? d : null;
        if (v is long l) return l;
        if (v is int i) return i;
        if (v is double dd) return dd;
        return null;
    }

    public static Num num(long v) => new(v.ToString(CultureInfo.InvariantCulture));

    public static D map(params object?[] kv)
    {
        var r = new D();
        for (int i = 0; i < kv.Length; i += 2) r[(string)kv[i]!] = kv[i + 1];
        return r;
    }

    public static L list(params object?[] xs) => new L(xs);

    /// <summary>JSON.stringify of a string.</summary>
    public static string q(string s)
    {
        var sb = new StringBuilder("\"");
        for (int i = 0; i < s.Length; i++)
        {
            char c = s[i];
            switch (c)
            {
                case '"': sb.Append("\\\""); break;
                case '\\': sb.Append("\\\\"); break;
                case '\b': sb.Append("\\b"); break;
                case '\t': sb.Append("\\t"); break;
                case '\n': sb.Append("\\n"); break;
                case '\f': sb.Append("\\f"); break;
                case '\r': sb.Append("\\r"); break;
                default:
                    if (c < 0x20) sb.Append("\\u").Append(((int)c).ToString("x4"));
                    else if (char.IsHighSurrogate(c) && i + 1 < s.Length && char.IsLowSurrogate(s[i + 1])) { sb.Append(c).Append(s[++i]); }
                    else if (char.IsSurrogate(c)) sb.Append("\\u").Append(((int)c).ToString("x4"));
                    else sb.Append(c);
                    break;
            }
        }
        return sb.Append('"').ToString();
    }

    /// <summary>JSON.stringify of any JSON-shaped value with insertion-order keys (an in-memory comparison key, not a signed form).</summary>
    public static string stringify(object? v) { var sb = new StringBuilder(); Stringify(sb, v, false); return sb.ToString(); }

    /// <summary>The sorted-key stable form (UTF-16 code-unit key order).</summary>
    public static string stable(object? v) { var sb = new StringBuilder(); Stringify(sb, v, true); return sb.ToString(); }

    static void Stringify(StringBuilder sb, object? v, bool sorted)
    {
        switch (v)
        {
            case null: sb.Append("null"); break;
            case string s: sb.Append(q(s)); break;
            case bool b: sb.Append(b ? "true" : "false"); break;
            case Num n: sb.Append(n.Raw); break;
            case long or int: sb.Append(Convert.ToString(v, CultureInfo.InvariantCulture)); break;
            case List<object?> l:
                sb.Append('[');
                for (int i = 0; i < l.Count; i++) { if (i > 0) sb.Append(','); Stringify(sb, l[i], sorted); }
                sb.Append(']');
                break;
            case D d:
                var ks = new List<string>(d.Keys);
                if (sorted) ks.Sort(string.CompareOrdinal);
                sb.Append('{');
                bool f = true;
                foreach (var k in ks) { if (!f) sb.Append(','); f = false; sb.Append(q(k)).Append(':'); Stringify(sb, d[k], sorted); }
                sb.Append('}');
                break;
            default: throw new ArgumentException("unsupported " + v.GetType().FullName);
        }
    }

    /// <summary>Java Math.round / JavaScript Math.round: floor(x + 0.5), ties toward +infinity.</summary>
    public static long jsRound(double x) => (long)Math.Floor(x + 0.5);

    /// <summary>A map key for an arbitrary JSON value (a string key never equals a number key).</summary>
    public static string key(object? o) => o is string s ? "s" + s : "j" + stringify(o);

    public static List<string> lst(params string[] xs) => new(xs);

    /// <summary>JavaScript String.prototype.trim (the ECMAScript WhiteSpace and LineTerminator set).</summary>
    public static string jsTrim(string s) => s.Trim(Actions.JsSpace);

    public static string itoa(int i) => i.ToString(CultureInfo.InvariantCulture);

    public static int cmp(string a, string b) => string.CompareOrdinal(a, b);

    public static L strs(object? o) { var r = new L(); if (o is L src) r.AddRange(src); return r; }

    /// <summary>JavaScript truthiness of a parsed JSON value.</summary>
    public static bool truthy(object? v)
    {
        if (v == null) return false;
        if (v is bool b) return b;
        if (v is string s) return s.Length != 0;
        var d = dbl(v);
        if (d != null) return d != 0.0 && !double.IsNaN(d.Value);
        return true;
    }

    /// <summary>JavaScript ToNumber of a parsed JSON value (null 0, "" 0, [] 0, [x] ToNumber(x), objects NaN).</summary>
    public static double toNum(object? v)
    {
        if (v == null) return 0;
        if (v is bool b) return b ? 1 : 0;
        var d = dbl(v);
        if (d != null) return d.Value;
        if (v is string s)
        {
            var t = s.Trim();
            if (t.Length == 0) return 0;
            if (!Regex.IsMatch(t, @"^[+-]?([0-9]+\.?[0-9]*|\.[0-9]+)([eE][+-]?[0-9]+)?$")) return double.NaN;
            return double.Parse(t, NumberStyles.Float, CultureInfo.InvariantCulture);
        }
        if (v is List<object?> l) return l.Count == 0 ? 0 : l.Count == 1 ? toNum(l[0]) : double.NaN;
        return double.NaN;
    }

    /// <summary>JavaScript String(v) of a parsed JSON value (template-literal interpolation).</summary>
    public static string jsStr(object? v)
    {
        switch (v)
        {
            case null: return "null";
            case string s: return s;
            case Num n: return n.Raw;
            case List<object?> l:
                {
                    var sb = new StringBuilder();
                    bool f = true;
                    foreach (var x in l) { if (!f) sb.Append(','); f = false; if (x != null) sb.Append(jsStr(x)); }
                    return sb.ToString();
                }
            case D: return "[object Object]";
            case bool b: return b ? "true" : "false";
            default: return Convert.ToString(v, CultureInfo.InvariantCulture) ?? "";
        }
    }

    /// <summary>JSON.stringify of a value used as a quoted label (strings quoted, everything else as its JSON text).</summary>
    public static string quote(object? v) => v is string s ? q(s) : stringify(v);

    public static double? strictNum(object? v) => v is Num or long or int or double ? dbl(v) : null;
}

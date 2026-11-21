using System.Globalization;
using AtlasPca.Js;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Explain;

/// <summary>The few JavaScript value semantics the explainer depends on, over the JSON tree: property reads that throw on null/undefined,
/// String(x), Number(x), the + / - / relational operators with their coercions, and truthiness. <see cref="Undef"/> is "undefined".</summary>
internal static class ExplainJs
{
    public static readonly object Undef = new();

    public static bool IsUndef(object? v) => ReferenceEquals(v, Undef);
    public static bool Nullish(object? v) => v == null || IsUndef(v);

    /// <summary>o.k: null / undefined throw (TypeError); a map yields its member or undefined; a list its index-named member; anything else undefined.</summary>
    public static object? G(object? o, string k)
    {
        if (Nullish(o)) throw new InvalidOperationException($"Cannot read properties of {(o == null ? "null" : "undefined")} (reading '{k}')");
        return Q(o, k);
    }

    /// <summary>o?.k</summary>
    public static object? Q(object? o, string k)
    {
        if (Nullish(o)) return Undef;
        if (o is D d) return d.TryGetValue(k, out var v) ? v : Undef;
        if (o is L l && int.TryParse(k, NumberStyles.None, CultureInfo.InvariantCulture, out var i) && i < l.Count && i.ToString(CultureInfo.InvariantCulture) == k) return l[i];
        if (o is string s && int.TryParse(k, NumberStyles.None, CultureInfo.InvariantCulture, out var j) && j < s.Length && j.ToString(CultureInfo.InvariantCulture) == k) return s[j].ToString();
        return Undef;
    }

    /// <summary>o[i] with optional chaining (nullish o yields undefined).</summary>
    public static object? Qi(object? o, int i) => Q(o, i.ToString(CultureInfo.InvariantCulture));

    /// <summary>Object.keys(o).</summary>
    public static List<string> Keys(object? o) => o switch
    {
        D d => IntentJs.JsKeys(d.Keys).ToList(),
        L l => Enumerable.Range(0, l.Count).Select(i => i.ToString(CultureInfo.InvariantCulture)).ToList(),
        string s => Enumerable.Range(0, s.Length).Select(i => i.ToString(CultureInfo.InvariantCulture)).ToList(),
        _ => new List<string>(),
    };

    public static bool IsObject(object? v) => v is D || v is L; // typeof v === 'object' && v !== null
    public static bool IsArray(object? v) => v is L;

    /// <summary>Property presence, as the <c>in</c> operator reports it for a map.</summary>
    public static bool In(object? o, string k) => o is D d && d.ContainsKey(k);

    public static bool Truthy(object? v) => v switch
    {
        null => false,
        bool b => b,
        string s => s.Length > 0,
        Num => JsJson.ToJsNumber(v) is var x && x != 0 && !double.IsNaN(x),
        _ => !IsUndef(v),
    };

    /// <summary>String(v).</summary>
    public static string S(object? v) => IsUndef(v) ? "undefined" : JsJson.ToJsString(v);

    /// <summary>JSON.stringify(v) as a template substitution: undefined stringifies to "undefined".</summary>
    public static string Json(object? v) => IsUndef(v) ? "undefined" : JsJson.Stringify(v);

    public static double ToN(object? v) => IsUndef(v) ? double.NaN : JsJson.ToJsNumber(v);

    public static bool IsNumber(object? v) => v is Num;

    public static string Str(double d) => JsJson.NumberToString(d);
    public static Num NumOf(double d) => new(JsJson.NumberToString(d));

    static object? Prim(object? v) => v is L || v is D ? S(v) : v;

    /// <summary>a + b</summary>
    public static object Add(object? a, object? b)
    {
        a = Prim(a); b = Prim(b);
        if (a is string || b is string) return S(a) + S(b);
        return ToN(a) + ToN(b);
    }

    public static double Sub(object? a, object? b) => ToN(a) - ToN(b);

    static int? Cmp(object? a, object? b)
    {
        a = Prim(a); b = Prim(b);
        if (a is string x && b is string y) return Math.Sign(string.CompareOrdinal(x, y));
        double p = ToN(a), q = ToN(b);
        if (double.IsNaN(p) || double.IsNaN(q)) return null;
        return p < q ? -1 : p > q ? 1 : 0;
    }

    public static bool Gt(object? a, object? b) => Cmp(a, b) is int c && c > 0;
    public static bool Lt(object? a, object? b) => Cmp(a, b) is int c && c < 0;
    public static bool Le(object? a, object? b) => Cmp(a, b) is int c && c <= 0;

    public static string JsTrim(string s)
    {
        int a = 0, z = s.Length;
        while (a < z && JsJson.IsJsSpace(s[a])) a++;
        while (z > a && JsJson.IsJsSpace(s[z - 1])) z--;
        return s[a..z];
    }

    /// <summary>for (x of v): a list, or a string by code point; anything else throws (TypeError: not iterable).</summary>
    public static IEnumerable<object?> Iter(object? v) => v switch
    {
        L l => l,
        string s => s.EnumerateRunes().Select(r => (object?)r.ToString()).ToList(),
        _ => throw new InvalidOperationException("value is not iterable"),
    };

    /// <summary>v.includes(needle): a string substring test, a list membership test; any other receiver has no such method (TypeError).</summary>
    public static bool Includes(object? v, string needle) => v switch
    {
        string s => s.Contains(needle, StringComparison.Ordinal),
        L l => l.Any(e => e is string t && t == needle),
        _ => throw new InvalidOperationException("includes is not a function"),
    };

    /// <summary>v.length: a list or string length; undefined otherwise (null / undefined throw).</summary>
    public static object? Len(object? v)
    {
        if (Nullish(v)) throw new InvalidOperationException("Cannot read properties of nullish (reading 'length')");
        return v switch { L l => new Num(l.Count.ToString(CultureInfo.InvariantCulture)), string s => new Num(s.Length.ToString(CultureInfo.InvariantCulture)), _ => Undef };
    }

    /// <summary>v.slice(n) for a list or a string; any other receiver has no slice (TypeError).</summary>
    public static object Slice(object? v, int n) => v switch
    {
        L l => l.Skip(n).ToList(),
        string s => n >= s.Length ? "" : s[n..],
        _ => throw new InvalidOperationException("slice is not a function"),
    };
}

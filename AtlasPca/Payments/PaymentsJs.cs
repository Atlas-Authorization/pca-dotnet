// JavaScript value semantics over the JSON tree, for the payments package: mandates, charges and settlements are untrusted objects whose
// members the reference reads with JavaScript coercion (Number(), String(), relational operators, object spread). Internal.
using System.Globalization;
using System.Numerics;
using JD = System.Collections.Generic.Dictionary<string, object?>;
using JL = System.Collections.Generic.List<object?>;

namespace AtlasPca.Payments;

internal static class Js
{
    /// <summary>The member of an object value, or null (undefined and null are not told apart; use <see cref="Has"/> where they differ).</summary>
    internal static object? Prop(object? o, string k) => o is JD d && d.TryGetValue(k, out var v) ? v : null;
    internal static bool Has(object? o, string k) => o is JD d && d.ContainsKey(k);

    /// <summary>Reading a member of null (or undefined) throws; a missing member is undefined (null here).</summary>
    internal static object? Read(object? o, string k, bool defined = true) => o == null ? throw new InvalidOperationException($"cannot read '{k}' of undefined") : Prop(o, k);

    /// <summary>The value, or a throw when it is null or undefined (the next member read of it would throw).</summary>
    internal static object NotNull(object? v) => v ?? throw new InvalidOperationException("cannot read a member of undefined");

    internal static bool IsObject(object? o) => o is JD || o is JL;
    internal static bool Truthy(object? x) => IntentRevocation.Truthy(x);

    /// <summary>String(x) / the template-literal text.</summary>
    internal static string Str(object? x, bool present = true) => IntentRevocation.JsText(x, present);

    internal static bool IsWs(char c) => c is '\t' or '\n' or '\v' or '\f' or '\r' or ' ' or ' ' or ' ' or (>= ' ' and <= ' ') or '\u2028' or '\u2029' or ' ' or ' ' or '　' or '﻿';

    internal static string Trim(string s)
    {
        int a = 0, b = s.Length;
        while (a < b && IsWs(s[a])) a++;
        while (b > a && IsWs(s[b - 1])) b--;
        return s[a..b];
    }

    internal static bool IsFiniteNum(object? x) => x is Num && IntentJs.IsFinite(x);

    internal static double D(object? x) => IntentJs.NumOf(x) ?? double.NaN;

    /// <summary>ToNumber of a JSON value (null is 0, true is 1, a string or array through its text, an object NaN).</summary>
    internal static double ToNumber(object? x) => x switch
    {
        null => 0,
        bool b => b ? 1 : 0,
        Num n => D(n),
        string s => StrToNumber(s),
        JL l => StrToNumber(Str(l)),
        _ => double.NaN,
    };

    internal static double StrToNumber(string raw)
    {
        var s = Trim(raw);
        if (s.Length == 0) return 0;
        if (s is "Infinity" or "+Infinity") return double.PositiveInfinity;
        if (s == "-Infinity") return double.NegativeInfinity;
        if (s.Length > 2 && s[0] == '0' && char.ToLowerInvariant(s[1]) is 'x' or 'o' or 'b')
        {
            int radix = char.ToLowerInvariant(s[1]) switch { 'x' => 16, 'o' => 8, _ => 2 };
            double v = 0;
            foreach (var ch in s[2..])
            {
                int dg = ch is >= '0' and <= '9' ? ch - '0' : ch is >= 'a' and <= 'f' ? ch - 'a' + 10 : ch is >= 'A' and <= 'F' ? ch - 'A' + 10 : 99;
                if (dg >= radix) return double.NaN;
                v = v * radix + dg;
            }
            return v;
        }
        if (s.Any(c => char.IsLetter(c) && c is not ('e' or 'E'))) return double.NaN;
        return double.TryParse(s, NumberStyles.Float, CultureInfo.InvariantCulture, out var d) ? d : double.NaN;
    }

    static object? Prim(object? x) => x switch { JL l => Str(l), JD => "[object Object]", _ => x };

    /// <summary><c>a &gt; b</c> with the abstract relational comparison (two strings compare by code units, otherwise numerically).</summary>
    internal static bool Gt(object? a, object? b)
    {
        var pa = Prim(a); var pb = Prim(b);
        if (pa is string sa && pb is string sb) return string.CompareOrdinal(sa, sb) > 0;
        double x = ToNumber(pa), y = ToNumber(pb);
        return x > y;
    }

    internal static bool Ge(object? a, object? b)
    {
        var pa = Prim(a); var pb = Prim(b);
        if (pa is string sa && pb is string sb) return string.CompareOrdinal(sa, sb) >= 0;
        double x = ToNumber(pa), y = ToNumber(pb);
        return x >= y;
    }

    /// <summary>A double as a JSON number (NaN and infinities have no JSON form: null).</summary>
    internal static object? Out(double d) => double.IsFinite(d) ? IntentJs.Normalize(d) : null;

    /// <summary>Math.round: half rounds up.</summary>
    internal static double Round(double x)
    {
        if (!double.IsFinite(x)) return x;
        var f = Math.Floor(x);
        return x - f >= 0.5 ? f + 1 : f;
    }

    /// <summary>Object spread of a value: an object's members, a string's or array's indexed members, nothing for any other value.</summary>
    internal static JD Spread(object? v)
    {
        var o = new JD();
        switch (v)
        {
            case JD d: foreach (var kv in d) o[kv.Key] = kv.Value; break;
            case string s: for (int i = 0; i < s.Length; i++) o[i.ToString(CultureInfo.InvariantCulture)] = s[i].ToString(); break;
            case JL l: for (int i = 0; i < l.Count; i++) o[i.ToString(CultureInfo.InvariantCulture)] = l[i]; break;
        }
        return o;
    }

    /// <summary>The elements of an array spread <c>[...x]</c>: an array, or the code points of a string; anything else is not iterable.</summary>
    internal static JL SpreadList(object? v)
    {
        switch (v)
        {
            case JL l: return new JL(l);
            case string s:
                {
                    var o = new JL();
                    for (int i = 0; i < s.Length; i++)
                    {
                        if (char.IsHighSurrogate(s[i]) && i + 1 < s.Length && char.IsLowSurrogate(s[i + 1])) { o.Add(s.Substring(i, 2)); i++; }
                        else o.Add(s[i].ToString());
                    }
                    return o;
                }
            default: throw new InvalidOperationException("not iterable");
        }
    }

    /// <summary>x.length: an array's or string's length; an object has none (undefined, null here); null and undefined throw.</summary>
    internal static double? Length(object? x, bool defined = true) => x switch
    {
        _ when !defined || x == null => throw new InvalidOperationException("cannot read 'length' of undefined"),
        JL l => l.Count,
        string s => s.Length,
        _ => null,
    };

    /// <summary>Array.prototype.sort() without a comparator over strings: UTF-16 code unit order.</summary>
    internal static List<string> SortStrings(IEnumerable<string> xs) { var l = xs.ToList(); l.Sort(StringComparer.Ordinal); return l; }

    internal static BigInteger BigOf(double d) => new(d);
}

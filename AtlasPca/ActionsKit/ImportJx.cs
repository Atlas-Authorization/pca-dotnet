// JSON-tree and JavaScript-semantics helpers of the importers (values are Dictionary / List / string / bool / Num / null).
using System.Text;
using AtlasPca.Js;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.ActionsKit;

internal static class ImportJx
{
    /// <summary>Marks an absent member (JavaScript undefined) where a present JSON null differs.</summary>
    internal static readonly object Undef = new();

    internal static object? Get(object? o, string k) => o is D d && d.TryGetValue(k, out var v) ? v : null;
    internal static object? GetU(object? o, string k) => o is D d && d.TryGetValue(k, out var v) ? v : Undef;
    internal static bool Has(object? o, string k) => o is D d && d.ContainsKey(k);
    internal static double? Dbl(object? o) => IntentJs.NumOf(o);
    internal static Num N(long v) => new(v.ToString(System.Globalization.CultureInfo.InvariantCulture));
    internal static Num NumOfDouble(double v) => new(JsJson.NumberToString(v));

    /// <summary>Number.isSafeInteger(v) (so -0 counts).</summary>
    internal static bool IsSafe(object? o) => Dbl(o) is double d && double.IsFinite(d) && d == Math.Round(d) && Math.Abs(d) <= 9007199254740991.0;
    /// <summary>Number.isSafeInteger(v) and not -0.</summary>
    internal static bool IsInt(object? o) => IsSafe(o) && !(Dbl(o) == 0.0 && double.IsNegative(Dbl(o)!.Value));

    internal static bool Truthy(object? v)
    {
        if (v == null || ReferenceEquals(v, Undef)) return false;
        if (v is bool b) return b;
        if (v is string s) return s.Length > 0;
        return Dbl(v) is double d ? !(d == 0.0 || double.IsNaN(d)) : true;
    }

    internal static string JsStr(object? v) => v == null ? "null" : JsJson.ToJsString(v);

    internal static bool JsSpace(char c) =>
        (c >= 9 && c <= 13) || c == 32 || c == 0xa0 || c == 0x1680 || (c >= 0x2000 && c <= 0x200a) || c == 0x2028 || c == 0x2029 || c == 0x202f || c == 0x205f || c == 0x3000 || c == 0xfeff;

    internal static string JsTrim(string s)
    {
        int a = 0, b = s.Length;
        while (a < b && JsSpace(s[a])) a++;
        while (b > a && JsSpace(s[b - 1])) b--;
        return s.Substring(a, b - a);
    }

    internal static byte[] Utf8(string s) => Encoding.UTF8.GetBytes(s); // a lone surrogate becomes U+FFFD, as TextEncoder writes it
    internal static int U8(string s) => Encoding.UTF8.GetByteCount(s);
    internal static string Sha256B64u(byte[] b) => Pca.B64u(Pca.Sha(b));

    internal static D Obj(params (string, object?)[] kv)
    {
        var m = new D();
        foreach (var (k, v) in kv) m[k] = v;
        return m;
    }

    internal static L List(params object?[] xs) => new(xs);

    static bool IsIndexKey(string k)
    {
        if (k.Length == 0 || k.Length > 10 || (k.Length > 1 && k[0] == '0')) return false;
        foreach (var ch in k) if (ch < '0' || ch > '9') return false;
        return long.Parse(k) < 4294967295L;
    }

    /// <summary>Object.keys order: integer-like keys ascending, then the rest in insertion order.</summary>
    internal static List<string> Keys(D m)
    {
        var idx = new List<string>(); var rest = new List<string>();
        foreach (var k in m.Keys) (IsIndexKey(k) ? idx : rest).Add(k);
        idx.Sort((x, y) => long.Parse(x).CompareTo(long.Parse(y)));
        idx.AddRange(rest);
        return idx;
    }

    internal static void PutAll(D dst, D src) { foreach (var kv in src) dst[kv.Key] = kv.Value; }

    /// <summary>{...src} into dst: an object copies its members, a string or array its indexed entries, anything else nothing.</summary>
    internal static void Spread(D dst, object? src)
    {
        if (src is D d) PutAll(dst, d);
        else if (src is string s) for (int i = 0; i < s.Length; i++) dst[i.ToString()] = s[i].ToString();
        else if (src is L l) for (int i = 0; i < l.Count; i++) dst[i.ToString()] = l[i];
    }

    /// <summary>[...x] of an array or a string (its code points); anything else throws as the engine does.</summary>
    internal static L SpreadList(object? x)
    {
        var o = new L();
        if (x is L l) o.AddRange(l);
        else if (x is string s)
        {
            for (int i = 0; i < s.Length;)
            {
                int n = char.IsHighSurrogate(s[i]) && i + 1 < s.Length && char.IsLowSurrogate(s[i + 1]) ? 2 : 1;
                o.Add(s.Substring(i, n));
                i += n;
            }
        }
        else throw new ArgumentException("not iterable");
        return o;
    }

    static int HexByte(string s, int i)
    {
        if (i + 2 >= s.Length) return -1;
        int H(char ch) => ch >= '0' && ch <= '9' ? ch - '0' : ch >= 'a' && ch <= 'f' ? ch - 'a' + 10 : ch >= 'A' && ch <= 'F' ? ch - 'A' + 10 : -1;
        int h = H(s[i + 1]), l = H(s[i + 2]);
        return h < 0 || l < 0 ? -1 : h * 16 + l;
    }

    /// <summary>decodeURIComponent; null when the engine would throw URIError.</summary>
    internal static string? DecodeUriComponent(string s)
    {
        var b = new StringBuilder();
        int n = s.Length;
        for (int i = 0; i < n; i++)
        {
            char c = s[i];
            if (c != '%') { b.Append(c); continue; }
            int b0 = HexByte(s, i);
            if (b0 < 0) return null;
            i += 2;
            if (b0 < 0x80) { b.Append((char)b0); continue; }
            int need, cp, min;
            if ((b0 & 0xE0) == 0xC0) { need = 1; cp = b0 & 0x1F; min = 0x80; }
            else if ((b0 & 0xF0) == 0xE0) { need = 2; cp = b0 & 0x0F; min = 0x800; }
            else if ((b0 & 0xF8) == 0xF0) { need = 3; cp = b0 & 0x07; min = 0x10000; }
            else return null;
            for (int k = 0; k < need; k++)
            {
                if (i + 1 >= n || s[i + 1] != '%') return null;
                int bx = HexByte(s, i + 1);
                if (bx < 0 || (bx & 0xC0) != 0x80) return null;
                cp = (cp << 6) | (bx & 0x3F);
                i += 3;
            }
            if (cp < min || cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF)) return null;
            b.Append(char.ConvertFromUtf32(cp));
        }
        return b.ToString();
    }

    /// <summary>Replace lone surrogates by U+FFFD (so BCL normalization and encoding never throw).</summary>
    internal static string NoLone(string s)
    {
        StringBuilder? b = null;
        for (int i = 0; i < s.Length; i++)
        {
            char c = s[i];
            bool bad = false;
            if (char.IsHighSurrogate(c)) { if (i + 1 < s.Length && char.IsLowSurrogate(s[i + 1])) { b?.Append(c).Append(s[i + 1]); i++; continue; } bad = true; }
            else if (char.IsLowSurrogate(c)) bad = true;
            if (bad) { b ??= new StringBuilder(s, 0, i, s.Length); b.Append('�'); } else b?.Append(c);
        }
        return b?.ToString() ?? s;
    }
}

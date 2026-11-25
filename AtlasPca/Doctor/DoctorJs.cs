// JavaScript value semantics the doctor's checks depend on (Number(), String(), Date.parse, toFixed, JSON.stringify(v, null, 2)) over parsed JSON values.
using System.Globalization;
using System.Numerics;
using System.Text;
using System.Text.RegularExpressions;
using AtlasPca.Js;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Doctor;

internal static class DoctorJs
{
    /// <summary>A member that is absent (JavaScript undefined); distinct from a JSON null.</summary>
    internal sealed class UndefinedValue { public override string ToString() => "undefined"; }
    internal static readonly object Undef = new UndefinedValue();

    internal static bool IsUndef(object? o) => ReferenceEquals(o, Undef);
    internal static bool Nullish(object? o) => o == null || IsUndef(o);

    /// <summary>o[k]: Undef for an absent member or a non-object.</summary>
    internal static object? G(object? o, string k) => o is D m ? (m.TryGetValue(k, out var v) ? v : Undef) : Undef;

    /// <summary>The ?? operator.</summary>
    internal static object? Or(object? v, object? dflt) => Nullish(v) ? dflt : v;

    internal static double? Num(object? v) => IsUndef(v) ? null : IntentJs.NumOf(v);

    internal static bool IsInteger(object? v) => Num(v) is double d && double.IsFinite(d) && d == Math.Round(d);

    internal static bool IsNegZero(object? v) => Num(v) is double d && IntentJs.IsNegZero(d);

    internal static bool Truthy(object? v)
    {
        if (v == null || IsUndef(v) || v is false) return false;
        if (v is string s) return s.Length > 0;
        return Num(v) is not double d || !(d == 0.0 || double.IsNaN(d));
    }

    // ---- strings and numbers ----

    internal static string Trim(string s)
    {
        int a = 0, b = s.Length;
        while (a < b && JsJson.IsJsSpace(s[a])) a++;
        while (b > a && JsJson.IsJsSpace(s[b - 1])) b--;
        return s.Substring(a, b - a);
    }

    static readonly Regex Dec = new(@"\A[+-]?([0-9]+\.?[0-9]*|\.[0-9]+)([eE][+-]?[0-9]+)?\z", RegexOptions.CultureInvariant);

    /// <summary>Number(string).</summary>
    internal static double ToNumber(string s)
    {
        var t = Trim(s);
        if (t.Length == 0) return 0;
        if (Regex.IsMatch(t, @"\A0[xX][0-9a-fA-F]+\z")) return (double)ParseRadix(t.Substring(2), 16);
        if (Regex.IsMatch(t, @"\A0[oO][0-7]+\z")) return (double)ParseRadix(t.Substring(2), 8);
        if (Regex.IsMatch(t, @"\A0[bB][01]+\z")) return (double)ParseRadix(t.Substring(2), 2);
        if (t is "Infinity" or "+Infinity") return double.PositiveInfinity;
        if (t == "-Infinity") return double.NegativeInfinity;
        if (Dec.IsMatch(t)) return double.Parse(t, NumberStyles.Float, CultureInfo.InvariantCulture);
        return double.NaN;
    }

    static BigInteger ParseRadix(string s, int radix)
    {
        BigInteger n = BigInteger.Zero;
        foreach (var c in s) n = n * radix + (c <= '9' ? c - '0' : (c | 0x20) - 'a' + 10);
        return n;
    }

    /// <summary>Number(v) for a JSON value (objects and arrays are not coerced: NaN).</summary>
    internal static double ToNumber(object? v)
    {
        var d = Num(v);
        if (d != null) return d.Value;
        if (v == null) return 0;
        if (v is bool b) return b ? 1 : 0;
        if (v is string s) return ToNumber(s);
        return double.NaN;
    }

    internal static string NumStr(double d) => JsJson.NumberToString(d);

    /// <summary>String(v) for a JSON value.</summary>
    internal static string Str(object? v)
    {
        if (v == null) return "null";
        if (IsUndef(v)) return "undefined";
        if (v is string s) return s;
        if (v is bool b) return b ? "true" : "false";
        var d = Num(v);
        if (d != null) return NumStr(d.Value);
        if (v is L l) return string.Join(",", l.Select(x => Nullish(x) ? "" : Str(x)));
        return "[object Object]";
    }

    /// <summary>x.toFixed(digits) for a finite double (exact binary value, halves round up in magnitude).</summary>
    internal static string ToFixed(double x, int digits)
    {
        if (double.IsNaN(x)) return "NaN";
        if (double.IsInfinity(x)) return NumStr(x);
        bool neg = x < 0;
        long bits = BitConverter.DoubleToInt64Bits(Math.Abs(x));
        int exp = (int)((bits >> 52) & 0x7ff);
        long frac = bits & 0xfffffffffffffL;
        BigInteger mant = exp == 0 ? frac : (frac | (1L << 52));
        int e = (exp == 0 ? 1 : exp) - 1075;
        BigInteger scaled = mant * BigInteger.Pow(10, digits);
        BigInteger q = e >= 0 ? scaled << e : (scaled + (BigInteger.One << (-e - 1))) >> -e;
        var s = q.ToString(CultureInfo.InvariantCulture);
        if (digits > 0)
        {
            if (s.Length <= digits) s = new string('0', digits - s.Length + 1) + s;
            s = s.Substring(0, s.Length - digits) + "." + s.Substring(s.Length - digits);
        }
        return (neg ? "-" : "") + s;
    }

    internal static string ToFixed1(double x) => ToFixed(x, 1);

    internal static string PadEnd(string s, int n) => s.Length >= n ? s : s + new string(' ', n - s.Length);

    // ---- Date.parse ----

    static readonly string[] Months = { "jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec" };
    const string Sp = @"[ \t\n\x0B\f\r]";
    static readonly Regex Rfc = new(@"\A(?:[A-Za-z]+,?" + Sp + @"+)?([0-9]{1,2})" + Sp + @"+([A-Za-z]{3})[A-Za-z]*" + Sp + @"+([0-9]{4})" + Sp + @"+([0-9]{1,2}):([0-9]{2})(?::([0-9]{2}))?" + Sp + @"*((?i:GMT|UTC|UT|Z)|[+-][0-9]{4})\z", RegexOptions.CultureInvariant);
    static readonly Regex Iso = new(@"\A([0-9]{4})-([0-9]{2})-([0-9]{2})(?:T([0-9]{2}):([0-9]{2})(?::([0-9]{2})(?:\.([0-9]{1,9}))?)?(Z|[+-][0-9]{2}:[0-9]{2}))?\z", RegexOptions.CultureInvariant);

    static long DaysFromCivil(long y, int m, int d)
    {
        y -= m <= 2 ? 1 : 0;
        long era = (y >= 0 ? y : y - 399) / 400;
        long yoe = y - era * 400;
        long doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
        long doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
        return era * 146097 + doe - 719468;
    }

    static int LengthOfMonth(int y, int m) => m == 2 ? (DateTime.IsLeapYear(Math.Max(1, y)) ? 29 : 28) : m is 4 or 6 or 9 or 11 ? 30 : 31;

    static double Epoch(int y, int mo, int d, int h, int mi, int s, long ms, int offsetMin)
    {
        long days = DaysFromCivil(y, mo, 1) + (d - 1L);
        return ((days * 24 + h) * 60 + mi) * 60_000.0 + s * 1000.0 + ms - offsetMin * 60_000.0;
    }

    static int I(string s) => int.Parse(s, CultureInfo.InvariantCulture);

    /// <summary>Date.parse: NaN when unparseable. Covers the HTTP date (RFC 1123 with a zone; a weekday word is ignored) and ISO 8601 with a zone or date only (UTC).
    /// shortcut: a date without a zone is local time in the reference engine (host-dependent) and is NaN here; other legacy spellings are NaN.</summary>
    internal static double ParseDate(string s)
    {
        var t = Trim(s);
        var m = Rfc.Match(t);
        if (m.Success)
        {
            int mo = -1;
            var mn = m.Groups[2].Value.ToLowerInvariant();
            for (int i = 0; i < 12; i++) if (Months[i] == mn) mo = i + 1;
            if (mo < 0) return double.NaN;
            int h = I(m.Groups[4].Value), mi = I(m.Groups[5].Value), sec = m.Groups[6].Success ? I(m.Groups[6].Value) : 0;
            if (h > 24 || mi > 59 || sec > 59 || (h == 24 && (mi != 0 || sec != 0))) return double.NaN;
            var z = m.Groups[7].Value.ToUpperInvariant();
            int off = Regex.IsMatch(z, @"\A[+-][0-9]{4}\z") ? (z[0] == '-' ? -1 : 1) * (I(z.Substring(1, 2)) * 60 + I(z.Substring(3, 2))) : 0;
            int day = I(m.Groups[1].Value);
            if (day < 1 || day > 31) return double.NaN;
            return Epoch(I(m.Groups[3].Value), mo, day, h, mi, sec, 0, off);
        }
        m = Iso.Match(t);
        if (m.Success)
        {
            int mo = I(m.Groups[2].Value), d = I(m.Groups[3].Value);
            if (mo < 1 || mo > 12 || d < 1 || d > LengthOfMonth(I(m.Groups[1].Value), mo)) return double.NaN;
            int h = m.Groups[4].Success ? I(m.Groups[4].Value) : 0, mi = m.Groups[5].Success ? I(m.Groups[5].Value) : 0, sec = m.Groups[6].Success ? I(m.Groups[6].Value) : 0;
            if (h > 24 || mi > 59 || sec > 59 || (h == 24 && (mi != 0 || sec != 0 || m.Groups[7].Success))) return double.NaN;
            long ms = m.Groups[7].Success ? long.Parse((m.Groups[7].Value + "00").Substring(0, 3), CultureInfo.InvariantCulture) : 0;
            var z = m.Groups[8].Success ? m.Groups[8].Value : null;
            int off = 0;
            if (z != null && z != "Z") off = (z[0] == '-' ? -1 : 1) * (I(z.Substring(1, 2)) * 60 + I(z.Substring(4, 2)));
            return Epoch(I(m.Groups[1].Value), mo, d, h, mi, sec, ms, off);
        }
        return double.NaN;
    }

    // ---- JSON.stringify(v, null, 2) ----

    internal static string Stringify(object? v)
    {
        var b = new StringBuilder();
        Write(b, v, "");
        return b.ToString();
    }

    static void Write(StringBuilder b, object? v, string ind)
    {
        if (v == null || IsUndef(v)) { b.Append("null"); return; }
        if (v is string s) { JsJson.Str(b, s); return; }
        if (v is bool bo) { b.Append(bo ? "true" : "false"); return; }
        var d = Num(v);
        if (d != null) { b.Append(double.IsNaN(d.Value) || double.IsInfinity(d.Value) ? "null" : NumStr(d.Value)); return; }
        var inner = ind + "  ";
        if (v is L l)
        {
            if (l.Count == 0) { b.Append("[]"); return; }
            b.Append("[\n");
            for (int i = 0; i < l.Count; i++)
            {
                b.Append(inner);
                Write(b, l[i], inner);
                b.Append(i + 1 < l.Count ? ",\n" : "\n");
            }
            b.Append(ind).Append(']');
            return;
        }
        var m = (D)v;
        var keys = IntentJs.JsKeys(m.Where(e => !IsUndef(e.Value)).Select(e => e.Key)).ToList();
        if (keys.Count == 0) { b.Append("{}"); return; }
        b.Append("{\n");
        for (int i = 0; i < keys.Count; i++)
        {
            b.Append(inner);
            JsJson.Str(b, keys[i]);
            b.Append(": ");
            Write(b, m[keys[i]], inner);
            b.Append(i + 1 < keys.Count ? ",\n" : "\n");
        }
        b.Append(ind).Append('}');
    }
}

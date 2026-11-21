using System.Globalization;
using AtlasPca.Analyzer;
using AtlasPca.InteropJs;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.PolicyCi;

/// <summary>JavaScript-flavoured helpers over parsed-JSON trees for the policy-safety gate. A member that is absent reads as null here
/// (use <see cref="Has"/> to tell it from an explicit null).</summary>
internal static class CiJs
{
    internal static object? G(object? o, string k) => o is D m && m.TryGetValue(k, out var v) ? v : null;
    internal static bool Has(object? o, string k) => o is D m && m.ContainsKey(k);
    /// <summary>typeof x === 'object' and not null: an object or an array.</summary>
    internal static bool IsObject(object? o) => o is D || o is L;
    internal static bool IsRecord(object? o) => o is D;
    /// <summary>typeof x === 'object' (null included).</summary>
    internal static bool TypeofObject(object? o) => o == null || o is D || o is L;
    internal static double? Fin(object? o) => Jx.Fin(o);
    internal static object N(long v) => new Num(v.ToString(CultureInfo.InvariantCulture));
    internal static object? NumD(double d) => Jx.N(d);
    internal static bool Truthy(object? v) => v != null && !Jx.IsUndef(v) && JsX.Truthy(v);
    internal static string Str(object? v) => JsX.Str(v);
    internal static string NumStr(double d) => JsX.JsNumString(d);

    /// <summary><c>x.toFixed(digits)</c> of a non-negative value (the exact binary value, a tie rounds up).</summary>
    internal static string ToFixed(double x, int digits) => x.ToString("F" + digits, System.Globalization.CultureInfo.InvariantCulture);
    internal static string Stringify(object? v) => AtlasPca.Js.JsJson.Stringify(v);

    internal static D Obj(params (string, object?)[] kv)
    {
        var d = new D();
        foreach (var (k, v) in kv) d[k] = v;
        return d;
    }

    internal static D Copy(D d) => Jx.Copy(d);

    /// <summary>Array.prototype.join(' ') over values: a null element joins as the empty string.</summary>
    internal static string JoinSpace(IEnumerable<object?> parts) => string.Join(' ', parts.Select(p => p == null ? "" : Str(p)));

    /// <summary>Throws the TypeError a JavaScript engine would raise (a rule that throws becomes an internal-error finding).</summary>
    internal static InvalidOperationException TypeErr(string m) => JsX.TypeError(m);
}

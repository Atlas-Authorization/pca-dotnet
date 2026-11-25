using System.Globalization;
using AtlasPca.InteropJs;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Analyzer;

/// <summary>JavaScript value semantics over the parsed JSON tree for the analyzer ports: <c>undefined</c> is <see cref="JsX.Undef"/>
/// (an absent member), JSON null is null.</summary>
internal static class Jx
{
    internal static readonly object Undef = JsX.Undef;
    internal static bool IsUndef(object? x) => ReferenceEquals(x, Undef);

    /// <summary><c>o[k]</c>: a null or undefined o throws (TypeError); an object yields its member or undefined; any other value has no members.</summary>
    internal static object? Prop(object? o, string k)
    {
        if (o == null || IsUndef(o)) throw JsX.TypeError($"cannot read properties of {(o == null ? "null" : "undefined")} (reading '{k}')");
        return o is D m ? (m.TryGetValue(k, out var v) ? v : Undef) : Undef;
    }

    /// <summary><c>o?.[k]</c>.</summary>
    internal static object? Opt(object? o, string k) => o == null || IsUndef(o) ? Undef : Prop(o, k);

    internal static string Typeof(object? x) => x switch
    {
        null => "object",
        string => "string",
        bool => "boolean",
        Num or int or long or double => "number",
        _ => IsUndef(x) ? "undefined" : "object",
    };

    internal static bool IsNum(object? x) => x is Num or int or long or double;
    internal static bool IsObjRec(object? x) => x is D;

    /// <summary>A finite number's value, else null (typeof v === 'number' &amp;&amp; Number.isFinite(v)).</summary>
    internal static double? Fin(object? x) => IsNum(x) && IntentJs.NumOf(x) is double d && double.IsFinite(d) ? d : null;

    internal static bool Truthy(object? o) => !IsUndef(o) && JsX.Truthy(o);

    /// <summary>A binary64 value as a tree number; a non-finite value as {"$num": "Infinity"} (the reference's JSON form).</summary>
    internal static object NumOut(double d) => double.IsFinite(d) ? new Num(JsX.JsNumString(d)) : new D { ["$num"] = JsX.JsNumString(d) };

    /// <summary>A finite binary64 value as a tree number (a non-finite one becomes null, like JSON).</summary>
    internal static object? N(double d) => JsX.Number(d);

    /// <summary>Sets <paramref name="k"/> unless the value is undefined (an undefined member does not exist in JSON).</summary>
    internal static void Set(D d, string k, object? v) { if (!IsUndef(v)) d[k] = v; }

    /// <summary><c>String(x)</c> / template interpolation of a number.</summary>
    internal static string NumStr(double d) => JsX.JsNumString(d);

    /// <summary>The number a JavaScript relational operator compares (ToNumber): undefined is NaN.</summary>
    internal static double ToNumber(object? x) => IsUndef(x) ? double.NaN : AtlasPca.Js.JsJson.ToJsNumber(x);

    internal static bool IsArr(object? x) => x is L;
    internal static D Copy(D d) { var o = new D(); foreach (var (k, v) in d) o[k] = v; return o; }

    /// <summary>Insertion-ordered string set.</summary>
    internal sealed class OSet
    {
        readonly List<string> _l = new(); readonly HashSet<string> _h = new(StringComparer.Ordinal);
        internal bool Add(string s) { if (!_h.Add(s)) return false; _l.Add(s); return true; }
        internal List<string> ToList() => new(_l);
        internal int Count => _l.Count;
    }

    /// <summary>Insertion-ordered map with JavaScript Map semantics: set on an existing key keeps its position, delete then set appends.</summary>
    internal sealed class OMap
    {
        internal readonly List<KeyValuePair<string, object?>> Items = new();
        internal int Find(string k) { for (int i = 0; i < Items.Count; i++) if (Items[i].Key == k) return i; return -1; }
        internal void Set(string k, object? v) { var i = Find(k); if (i >= 0) Items[i] = new(k, v); else Items.Add(new(k, v)); }
        internal void Delete(string k) { var i = Find(k); if (i >= 0) Items.RemoveAt(i); }
        internal OMap Clone() { var m = new OMap(); m.Items.AddRange(Items); return m; }
        internal D ToDict() { var d = new D(); foreach (var kv in Items) d[kv.Key] = kv.Value; return d; }
    }
}

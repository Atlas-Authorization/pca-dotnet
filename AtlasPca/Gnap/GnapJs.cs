using System.Globalization;
using System.Text;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Gnap;

/// <summary>Thrown by the issuance paths of the GNAP bridge on a malformed request (the verify paths fail closed instead).</summary>
public sealed class GnapException(string message) : Exception(message);

/// <summary>A refusal of the interaction layer; <see cref="Code"/> is the stable error code (invalid_interaction, unknown_interaction,
/// too_many_attempts, invalid_request, expired, wrong_state, unsupported_hash).</summary>
public sealed class InteractionException(string code, string message) : Exception(message)
{
    public string Code { get; } = code;
}

/// <summary>JavaScript value semantics the reference relies on (truthiness, member reads, String(), JSON.stringify) over the JSON tree.</summary>
static class GnapJs
{
    /// <summary>An argument or member that is absent (JavaScript undefined); a null is a JSON null.</summary>
    internal static readonly object Absent = new();

    internal static bool Truthy(object? v) => v switch
    {
        null => false,
        bool b => b,
        string s => s.Length != 0,
        Num n => NumOf(n) is double d && d != 0 && !double.IsNaN(d),
        _ => !ReferenceEquals(v, Absent),
    };

    internal static double? NumOf(object? o) => o switch
    {
        Num n => double.TryParse(n.Raw, NumberStyles.Float, CultureInfo.InvariantCulture, out var d) ? d : null,
        int i => i,
        long l => l,
        double d => d,
        _ => null,
    };

    /// <summary>o[k] for an object; every other value has no such member (null stands for undefined here).</summary>
    internal static object? Member(object? o, string k) => o is D d && d.TryGetValue(k, out var v) ? v : null;

    internal static bool Has(object? o, string k) => o is D d && d.ContainsKey(k);

    /// <summary>o[k], or <see cref="Absent"/> when the member is not there.</summary>
    internal static object? Get(object? o, string k) => o is D d && d.TryGetValue(k, out var v) ? v : Absent;

    internal static bool IsObject(object? o) => o is D || o is L;

    /// <summary>String(v) for the values a JSON document holds.</summary>
    internal static string Str(object? v) => ReferenceEquals(v, Absent) ? "undefined" : IntentRevocation.JsText(v, true);

    /// <summary>Strict equality of two JSON members (===): strings, booleans and numbers by value, null with null, objects never.</summary>
    internal static bool StrictEq(object? a, object? b)
    {
        if (a is string x && b is string y) return x == y;
        if (a == null && b == null) return true;
        if (a is bool p && b is bool q) return p == q;
        var dx = NumOf(a); var dy = NumOf(b);
        return dx != null && dy != null && dx.Value == dy.Value;
    }

    internal static byte[] Utf8(string s) => Encoding.UTF8.GetBytes(s); // a lone surrogate is written as U+FFFD, as TextEncoder does

    /// <summary>JSON.stringify of a JSON value: insertion order of members, numbers as printed, lone surrogates escaped.</summary>
    internal static string Stringify(object? v)
    {
        var sb = new StringBuilder();
        Write(sb, v);
        return sb.ToString();
    }

    static void Write(StringBuilder sb, object? v)
    {
        switch (v)
        {
            case null: sb.Append("null"); break;
            case bool b: sb.Append(b ? "true" : "false"); break;
            case Num n: sb.Append(n.Raw == "-0" ? "0" : n.Raw); break;
            case int or long: sb.Append(Convert.ToString(v, CultureInfo.InvariantCulture)); break;
            case double dv: sb.Append(double.IsFinite(dv) ? AtlasPca.Js.JsJson.NumberToString(dv) : "null"); break;
            case string s: Quote(sb, s); break;
            case L l:
                sb.Append('[');
                for (int i = 0; i < l.Count; i++) { if (i > 0) sb.Append(','); Write(sb, l[i]); }
                sb.Append(']');
                break;
            case D m:
                sb.Append('{');
                bool first = true;
                foreach (var e in m)
                {
                    if (!first) sb.Append(',');
                    first = false;
                    Quote(sb, e.Key);
                    sb.Append(':');
                    Write(sb, e.Value);
                }
                sb.Append('}');
                break;
            default: throw new ArgumentException("not a JSON value: " + v.GetType().Name);
        }
    }

    static void Quote(StringBuilder sb, string s)
    {
        sb.Append('"');
        for (int i = 0; i < s.Length; i++)
        {
            char c = s[i];
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
                    else if (char.IsHighSurrogate(c) && i + 1 < s.Length && char.IsLowSurrogate(s[i + 1])) { sb.Append(c).Append(s[++i]); }
                    else if (char.IsSurrogate(c)) sb.Append("\\u").Append(((int)c).ToString("x4", CultureInfo.InvariantCulture));
                    else sb.Append(c);
                    break;
            }
        }
        sb.Append('"');
    }
}

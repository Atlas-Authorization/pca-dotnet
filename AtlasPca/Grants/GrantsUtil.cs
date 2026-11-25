// Small shared helpers of the operational plane (JS-shaped predicates over the JSON tree). Internal to the assembly.
using System.Text;
using JD = System.Collections.Generic.Dictionary<string, object?>;
using JL = System.Collections.Generic.List<object?>;

namespace AtlasPca.Grants;

internal static class G
{
    /// <summary>A non-empty string of at most <paramref name="max"/> UTF-16 units.</summary>
    internal static bool Str(object? x, int max = 512) => x is string s && s.Length > 0 && s.Length <= max;

    /// <summary>A non-negative safe integer (the reference's isSafeInt).</summary>
    internal static bool Nat(object? x) => Pca.SafeNat(x, out _);

    internal static long L(object? x) { Pca.SafeNat(x, out var n); return n; }

    internal static Num N(long v) => IntentJs.OfLong(v);

    internal static object? Get(object? o, string k) => IntentJs.Get(o, k);

    /// <summary>A deep copy of a JSON tree (strings, bools and Num are immutable).</summary>
    internal static object? Clone(object? v) => v switch
    {
        JD d => d.ToDictionary(e => e.Key, e => Clone(e.Value)),
        JL l => l.Select(Clone).ToList(),
        _ => v,
    };

    internal static JD CloneD(JD d) => (JD)Clone(d)!;

    /// <summary>Copy of a record with the named keys removed.</summary>
    internal static JD Without(JD d, params string[] keys) => d.Where(kv => !keys.Contains(kv.Key)).ToDictionary(kv => kv.Key, kv => kv.Value);

    /// <summary>The listed keys that are present, in the listed order (the body a signature covers).</summary>
    internal static JD Pick(JD d, IEnumerable<string> keys)
    {
        var o = new JD();
        foreach (var k in keys) if (d.TryGetValue(k, out var v)) o[k] = v;
        return o;
    }

    /// <summary>JSON.stringify of a string (escapes quotes, backslash, control characters and lone surrogates).</summary>
    internal static string JsonStr(string s)
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
                case '\f': sb.Append("\\f"); break;
                case '\n': sb.Append("\\n"); break;
                case '\r': sb.Append("\\r"); break;
                case '\t': sb.Append("\\t"); break;
                default:
                    if (c < 0x20) sb.Append("\\u").Append(((int)c).ToString("x4"));
                    else if (char.IsHighSurrogate(c) && i + 1 < s.Length && char.IsLowSurrogate(s[i + 1])) { sb.Append(c).Append(s[i + 1]); i++; }
                    else if (char.IsSurrogate(c)) sb.Append("\\u").Append(((int)c).ToString("x4"));
                    else sb.Append(c);
                    break;
            }
        }
        return sb.Append('"').ToString();
    }
}

/// <summary>An error carrying the reference's machine-readable <c>code</c>.</summary>
public class CodedException : Exception
{
    public string Code { get; }
    public CodedException(string code, string message) : base(message) { Code = code; }
}

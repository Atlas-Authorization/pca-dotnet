using System.Text;
using AtlasPca.InteropJs;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.A2aPkg;

/// <summary>Two things A2A 1.0 section 8.4 needs from an Agent Card implementation: <see cref="JcsBytes"/> (RFC 8785 canonical JSON, the
/// bytes a card signature covers) and <see cref="ValidateAgentCard1"/> (the A2A 1.0 <c>AgentCard</c> message). Shared by the A2A and
/// agent-card packages. Values are parsed JSON (D, L, string, bool, Num, null).</summary>
public static class A2aCard
{
    const int MaxDepth = 64;

    /// <summary>RFC 8785 canonical UTF-8 bytes of a JSON value; ArgumentException for a value with no JSON form (non-finite number, lone
    /// surrogate, nesting over 64).</summary>
    public static byte[] JcsBytes(object? value) => Encoding.UTF8.GetBytes(Jcs(value, 1));

    static string Jcs(object? v, int depth)
    {
        switch (v)
        {
            case null: return "null";
            case bool b: return b ? "true" : "false";
            case string s: return Str(s, "jcs: lone surrogate in string");
            case Num: case int: case long: case double:
                {
                    var d = IntentJs.NumOf(v);
                    if (d is not double x || double.IsNaN(x) || double.IsInfinity(x)) throw new ArgumentException("jcs: non-finite number");
                    return JsX.JsNumString(x); // -0 prints 0, as RFC 8785 requires
                }
        }
        if (v is not D && v is not L) throw new ArgumentException("jcs: unsupported type");
        if (depth > MaxDepth) throw new ArgumentException("jcs: nesting too deep");
        var sb = new StringBuilder();
        if (v is L l)
        {
            sb.Append('[');
            for (int i = 0; i < l.Count; i++) { if (i > 0) sb.Append(','); sb.Append(Jcs(l[i], depth + 1)); }
            return sb.Append(']').ToString();
        }
        var m = (D)v;
        var keys = m.Keys.ToList();
        keys.Sort(string.CompareOrdinal); // UTF-16 code unit order, as the default JavaScript sort
        sb.Append('{');
        bool first = true;
        foreach (var k in keys)
        {
            if (!first) sb.Append(',');
            first = false;
            sb.Append(Str(k, "jcs: lone surrogate in key")).Append(':').Append(Jcs(m[k], depth + 1));
        }
        return sb.Append('}').ToString();
    }

    /// <summary><c>JSON.stringify</c> of a string (a lone surrogate is refused first).</summary>
    internal static string Str(string s, string loneMsg)
    {
        if (Pca.HasLoneSurrogate(s)) throw new ArgumentException(loneMsg);
        var sb = new StringBuilder("\"");
        foreach (var c in s)
        {
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
                    if (c < 0x20) sb.Append("\\u").Append(((int)c).ToString("x4")); else sb.Append(c);
                    break;
            }
        }
        return sb.Append('"').ToString();
    }

    static bool IsObj(object? v) => v is D;
    static bool IsStr(object? v) => v is string;
    static object? Get(object? o, string k) => ((D)o!).GetValueOrDefault(k);
    static bool Has(object? o, string k) => ((D)o!).ContainsKey(k);

    static void ReqStr(List<string> p, object? o, string k, string at)
    {
        if (!(Get(o, k) is string s) || s.Length == 0) p.Add($"{at}.{k}: required non-empty string");
    }

    static void OptStr(List<string> p, object? o, string k, string at)
    {
        if (Has(o, k) && !IsStr(Get(o, k))) p.Add($"{at}.{k}: must be a string");
    }

    static void OptBool(List<string> p, object? o, string k, string at)
    {
        if (Has(o, k) && Get(o, k) is not bool) p.Add($"{at}.{k}: must be a boolean");
    }

    static void StrArray(List<string> p, object? v, string at, bool nonEmpty)
    {
        if (!(v is L l && l.All(IsStr))) p.Add($"{at}: must be an array of strings");
        else if (nonEmpty && l.Count == 0) p.Add($"{at}: must not be empty");
    }

    static void ObjArray(List<string> p, object? o, string k, string at, bool required, bool nonEmpty, Action<object?, string> each)
    {
        if (!Has(o, k))
        {
            if (required) p.Add($"{at}.{k}: required array");
            return;
        }
        if (Get(o, k) is not L l) { p.Add($"{at}.{k}: must be an array"); return; }
        if (nonEmpty && l.Count == 0) p.Add($"{at}.{k}: must not be empty");
        for (int i = 0; i < l.Count; i++)
        {
            var ea = $"{at}.{k}[{i}]";
            if (IsObj(l[i])) each(l[i], ea); else p.Add($"{ea}: must be an object");
        }
    }

    /// <summary>Check an object against the A2A 1.0 <c>AgentCard</c> message. Returns the problems found, each with a JSON path (empty = valid).</summary>
    public static List<string> ValidateAgentCard1(object? card)
    {
        var p = new List<string>();
        if (!IsObj(card)) { p.Add("$: the agent card must be an object"); return p; }
        ReqStr(p, card, "name", "$");
        ReqStr(p, card, "description", "$");
        ReqStr(p, card, "version", "$");
        OptStr(p, card, "documentationUrl", "$");
        OptStr(p, card, "iconUrl", "$");
        ObjArray(p, card, "supportedInterfaces", "$", true, true, (e, at) =>
        {
            ReqStr(p, e, "url", at);
            ReqStr(p, e, "protocolBinding", at);
            ReqStr(p, e, "protocolVersion", at);
            OptStr(p, e, "tenant", at);
        });
        if (Has(card, "provider"))
        {
            var pr = Get(card, "provider");
            if (!IsObj(pr)) p.Add("$.provider: must be an object");
            else
            {
                ReqStr(p, pr, "url", "$.provider");
                ReqStr(p, pr, "organization", "$.provider");
            }
        }
        if (!IsObj(Get(card, "capabilities"))) p.Add("$.capabilities: required object");
        else
        {
            var c = Get(card, "capabilities");
            OptBool(p, c, "streaming", "$.capabilities");
            OptBool(p, c, "pushNotifications", "$.capabilities");
            OptBool(p, c, "extendedAgentCard", "$.capabilities");
            ObjArray(p, c, "extensions", "$.capabilities", false, false, (e, at) =>
            {
                OptStr(p, e, "uri", at);
                OptStr(p, e, "description", at);
                OptBool(p, e, "required", at);
                if (Has(e, "params") && !IsObj(Get(e, "params"))) p.Add($"{at}.params: must be an object");
            });
        }
        if (Has(card, "securitySchemes") && !IsObj(Get(card, "securitySchemes"))) p.Add("$.securitySchemes: must be an object");
        if (Has(card, "securityRequirements") && Get(card, "securityRequirements") is not L) p.Add("$.securityRequirements: must be an array");
        if (!Has(card, "defaultInputModes")) p.Add("$.defaultInputModes: required array of strings");
        else StrArray(p, Get(card, "defaultInputModes"), "$.defaultInputModes", true);
        if (!Has(card, "defaultOutputModes")) p.Add("$.defaultOutputModes: required array of strings");
        else StrArray(p, Get(card, "defaultOutputModes"), "$.defaultOutputModes", true);
        ObjArray(p, card, "skills", "$", true, false, (e, at) =>
        {
            ReqStr(p, e, "id", at);
            ReqStr(p, e, "name", at);
            ReqStr(p, e, "description", at);
            if (!Has(e, "tags")) p.Add($"{at}.tags: required array of strings");
            else StrArray(p, Get(e, "tags"), $"{at}.tags", false);
            foreach (var k in new[] { "examples", "inputModes", "outputModes" }) if (Has(e, k)) StrArray(p, Get(e, k), $"{at}.{k}", false);
            if (Has(e, "securityRequirements") && Get(e, "securityRequirements") is not L) p.Add($"{at}.securityRequirements: must be an array");
        });
        ObjArray(p, card, "signatures", "$", false, false, (e, at) =>
        {
            ReqStr(p, e, "protected", at);
            ReqStr(p, e, "signature", at);
            if (Has(e, "header") && !IsObj(Get(e, "header"))) p.Add($"{at}.header: must be an object");
        });
        return p;
    }
}

// Shared helpers of the action-kit ports: member access over the JSON tree, JavaScript text/number semantics, the vocabularies.
using AtlasPca.Js;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.ActionsKit;

internal static class Ak
{
    internal static object? G(object? o, string k) => o is D d && d.TryGetValue(k, out var v) ? v : null;
    internal static bool Has(object? o, string k) => o is D d && d.ContainsKey(k);
    internal static string? S(object? o, string k) => G(o, k) as string;
    internal static L Lst(object? o, string k) => G(o, k) as L ?? new L();
    internal static List<string> Strs(object? v) => v is L l ? l.OfType<string>().ToList() : new List<string>();
    internal static L ToL(IEnumerable<string> xs) => new(xs.Cast<object?>());
    internal static long I(object? v) => (long)IntentJs.NumOf(v)!.Value;
    internal static double Dbl(object? v) => IntentJs.NumOf(v)!.Value;
    internal static int Cmp(string a, string b) => string.CompareOrdinal(a, b);
    /// <summary>String(v) of a present JSON value.</summary>
    internal static string JsStr(object? v) => JsJson.ToJsString(v);
    internal static bool JsTruthy(object? v) => v switch { null => false, bool b => b, string s => s.Length > 0, _ => IntentJs.NumOf(v) is double d ? d != 0 : true };
    internal static bool IsReadOnly(IEnumerable<string> effects) { var l = effects.ToList(); return l.Count > 0 && l.All(e => e == "read"); }
    internal static object? Copy(object? v) => v switch { D d => d.ToDictionary(kv => kv.Key, kv => Copy(kv.Value)), L l => new L(l.Select(Copy)), _ => v };
    internal static List<string> SortUniq(IEnumerable<string> xs) { var l = xs.Distinct(StringComparer.Ordinal).ToList(); l.Sort(StringComparer.Ordinal); return l; }
    internal static int U8(string s) => System.Text.Encoding.UTF8.GetByteCount(s);
    internal static int U16(string s) => s.Length;

    internal static readonly string[] Effects = { "read", "create", "update", "delete", "send", "pay", "exec", "privilege", "export", "publish", "provision", "sign" };
    internal static readonly string[] ContextKeys = { "approval_ref", "dry_run_first", "fresh_revocation", "idempotency", "revocable", "sandbox_attested" };
    internal static readonly string[] ParamRuleIds = { "array_bounded", "export_bounded", "id_not_wildcard", "money_amount_bounded", "money_has_currency", "pay_has_idempotency", "recipient_param_declared", "secret_not_logged" };
    internal static int RevRank(string r) => r switch { "reversible" => 0, "rate_limited" => 1, "irreversible" => 2, _ => -1 };
    internal static int SensRank(string s) => s switch { "free" => 0, "material" => 1, "critical" => 2, _ => -1 };
}

internal static class AkSens
{
    /// <summary>max(declared sensitivity, role/tag floor) of a param.</summary>
    internal static string Effective(D p)
    {
        var a = Ak.S(p, "sensitivity") ?? "free";
        var b = Actions.SensitivityFloor(p);
        return Ak.SensRank(a) >= Ak.SensRank(b) ? a : b;
    }
    internal static int RoleFloorRank(object? role) => role is string r ? Ak.SensRank(Actions.SensitivityFloor(new D { ["role"] = r })) : 0;
}

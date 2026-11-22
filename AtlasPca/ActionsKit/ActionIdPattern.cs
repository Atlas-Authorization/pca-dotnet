// The restricted resource id grammar: matching and decidable containment.
using System.Text.RegularExpressions;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.ActionsKit;

public static class ActionIdPattern
{
    public const int MaxIdLen = 128;
    const string Digits = "0123456789", HexLc = "0123456789abcdef", Lower = "abcdefghijklmnopqrstuvwxyz", Upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    static string Chars(string c) => c switch
    {
        "digits" => Digits,
        "hex" => HexLc,
        "alnum" => Digits + Lower + Upper,
        "slug" => Digits + Lower + "-_",
        "uuid" => HexLc + "-",
        "any_safe" => Digits + Lower + Upper + "._-:/",
        _ => throw new ArgumentException("unknown id class " + c),
    };
    static Regex UuidRe => Rx.Get(@"\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\z", RegexOptions.CultureInvariant);

    public static bool InClass(string s, string c) { var set = Chars(c); return s.All(set.Contains); }

    /// <summary>Null if the pattern is well formed (the checks of the action definition validator).</summary>
    public static string? IdPatternError(object? p) => Actions.IdPatternError(p);

    /// <summary>Does <paramref name="id"/> (the id part of a resource, without the type) match the pattern? A non-string id never matches.</summary>
    public static bool IdMatches(object? p, object? id)
    {
        if (id is not string s) return false;
        if (p is string star && star == "*") return s.Length > 0 && s.Length <= MaxIdLen && InClass(s, "any_safe");
        var d = (D)p!;
        if (d.ContainsKey("exact")) return d["exact"] is string e && s == e;
        var prefix = (string)d["prefix"]!;
        if (!s.StartsWith(prefix, StringComparison.Ordinal)) return false;
        var rest = s[prefix.Length..];
        var len = (L)d["len"]!;
        if (rest.Length < Ak.I(len[0]) || rest.Length > Ak.I(len[1])) return false;
        var cls = (string)d["class"]!;
        return cls == "uuid" ? UuidRe.IsMatch(rest) : InClass(rest, cls);
    }

    static bool ClassSubset(string a, string b) { var sb = Chars(b); return Chars(a).All(sb.Contains); }

    /// <summary>Is every id matched by <paramref name="inner"/> also matched by <paramref name="outer"/>? Sound; an exact id never contains a pattern.</summary>
    public static bool IdPatternContains(object? outer, object? inner)
    {
        if (outer is string os && os == "*") return true;
        if (inner is string ins && ins == "*") return false;
        var o = (D)outer!; var i = (D)inner!;
        if (o.ContainsKey("exact")) return i.ContainsKey("exact") && IntentJs.JsonEquals(i["exact"], o["exact"]);
        if (i.ContainsKey("exact")) return IdMatches(o, i["exact"]);
        var ip = (string)i["prefix"]!; var op = (string)o["prefix"]!;
        if (!ip.StartsWith(op, StringComparison.Ordinal)) return false;
        var r = ip[op.Length..];
        var oc = (string)o["class"]!; var ic = (string)i["class"]!;
        if (!InClass(r, oc)) return false;
        if (oc == "uuid") return ic == "uuid" && r == "";
        if (!ClassSubset(ic, oc)) return false;
        var ol = (L)o["len"]!; var il = (L)i["len"]!;
        return r.Length + Ak.I(il[0]) >= Ak.I(ol[0]) && r.Length + Ak.I(il[1]) <= Ak.I(ol[1]);
    }
}

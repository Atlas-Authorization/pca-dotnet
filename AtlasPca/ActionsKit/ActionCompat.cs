// Migration shims between the old, disagreeing action vocabularies and the one ActionDef vocabulary. Every conversion is total and fails closed.
using System.Text.RegularExpressions;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.ActionsKit;

public static class ActionCompat
{
    const long PpmMax = 1_000_000;
    static readonly string[] BlastRadii = { "one", "bounded", "tenant", "global" };
    static long BlastPpm(string r) => r switch { "one" => 50_000, "bounded" => 300_000, "tenant" => 700_000, _ => 1_000_000 };

    /// <summary>Any old reversibility word to the canonical class; anything unknown is irreversible (fail closed).</summary>
    public static string NormalizeReversibility(object? x) => x is string s ? s switch
    {
        "reversible" or "read" => "reversible",
        "rate_limited" or "costly" => "rate_limited",
        _ => "irreversible",
    } : "irreversible";

    /// <summary>The operations-side word for the revocation staleness table (rate_limited becomes costly).</summary>
    public static string LegacyOperationsClass(string r) => r == "rate_limited" ? "costly" : r;

    public static string MaxRevOf(string a, string b) => Ak.RevRank(a) >= Ak.RevRank(b) ? a : b;

    /// <summary>The schema units entry of a def's unit; null for a money unit whose currency is a parameter reference.</summary>
    public static D? UnitTagOf(D u)
    {
        if (Ak.S(u, "kind") != "money") return new D { ["kind"] = u["kind"] };
        if (u.GetValueOrDefault("ccy") is not string ccy) return null;
        var o = new D { ["kind"] = "money", ["currency"] = ccy };
        if (u.ContainsKey("exp")) o["exponent"] = u["exp"];
        return o;
    }

    static double JsRound(double v) { var f = Math.Floor(v); return v - f >= 0.5 ? f + 1 : f; }

    static long PpmOf(object? x)
    {
        var d = IntentJs.NumOf(x);
        var v = d is double dd && double.IsFinite(dd) ? dd : 1;
        return (long)Math.Min(PpmMax, Math.Max(0, JsRound(v * 1_000_000)));
    }

    /// <summary>The smallest radius whose default covers the float, and the integer ppm.</summary>
    public static D BlastOfFloat(object? x)
    {
        var ppm = PpmOf(x);
        return new D { ["radius"] = BlastRadii.FirstOrDefault(r => BlastPpm(r) >= ppm) ?? "global", ["ppm"] = ppm };
    }

    /// <summary>A legacy float kept exactly: the largest radius whose default does not exceed it, the ppm override carrying the exact value.</summary>
    public static D BlastExactOfFloat(object? x)
    {
        var ppm = PpmOf(x);
        return new D { ["radius"] = ((IEnumerable<string>)BlastRadii).Reverse().FirstOrDefault(r => BlastPpm(r) <= ppm) ?? "one", ["ppm"] = ppm };
    }

    static Regex ReadRe => Rx.Get(@"\A(?:read|get|list|view|search|fetch|head)(?:_|\z)", RegexOptions.CultureInvariant);
    static Regex DeleteRe => Rx.Get(@"(?:\A|_)(?:delete|remove|destroy|drop|purge)(?:_|\z)", RegexOptions.CultureInvariant);
    static Regex SendRe => Rx.Get(@"(?:\A|_)(?:send|post|publish|notify|email|sms)(?:_|\z)", RegexOptions.CultureInvariant);

    /// <summary>Convert an old catalog entry: effects inferred conservatively from the action name (an unknown write is update, never read);
    /// an amountField becomes a bounded money.amount parameter; the result is authored. o: {ccy, exp, maxAmount}.</summary>
    public static D FromCatalogSpec(D s, D? o = null)
    {
        var hasAmount = s.ContainsKey("amountField");
        var action = (string)s["action"]!;
        var effects = new L();
        if (hasAmount) effects.Add("pay");
        if (ReadRe.IsMatch(action)) effects.Add("read");
        if (DeleteRe.IsMatch(action)) effects.Add("delete");
        if (SendRe.IsMatch(action)) effects.Add("send");
        if (effects.Count == 0) effects.Add("update");
        var ps = new D();
        if (hasAmount)
        {
            ps[(string)s["amountField"]!] = new D
            {
                ["type"] = "integer", ["role"] = "money.amount", ["min"] = 0L, ["max"] = Ak.G(o, "maxAmount") ?? 100_000_000_000L,
                ["unit"] = new D { ["kind"] = "money", ["ccy"] = Ak.G(o, "ccy") ?? "USD", ["exp"] = Ak.G(o, "exp") ?? 2L },
            };
            ps["idempotency_key"] = new D { ["type"] = "string", ["max_len"] = 128L };
        }
        var b = BlastOfFloat(s["blastRadius"]);
        var wildcard = !s.ContainsKey("resource") || (s["resource"] is string rs && rs == "*");
        var desc = (string)s["description"]!;
        var title = desc.Length > 120 ? desc[..117] + "..." : desc;
        var outp = new D
        {
            ["v"] = 1L, ["kind"] = "pca-action-def", ["verb"] = s["verb"], ["title"] = title, ["description"] = desc, ["effects"] = effects,
            ["resource"] = new D
            {
                ["type"] = s["connector"],
                ["id"] = wildcard ? "*" : new D { ["prefix"] = "", ["class"] = "any_safe", ["len"] = new L { 1L, 128L } },
                ["scope"] = wildcard ? "set" : "one",
            },
            ["params"] = ps, ["reversibility"] = NormalizeReversibility(s["reversibility"]), ["blast"] = new D { ["radius"] = b["radius"], ["ppm"] = b["ppm"] },
        };
        if (hasAmount) outp["idempotency"] = new D { ["mode"] = "key_param", ["param"] = "idempotency_key" };
        outp["review"] = new D { ["state"] = "authored" };
        return outp;
    }

    public static L FromCatalog(IEnumerable<D> specs, D? o = null) => new(specs.Select(s => (object?)FromCatalogSpec(s, o)));
}

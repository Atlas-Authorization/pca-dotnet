// A platform's own business rules for one action, compiled into tighten rules and count accumulators. Every compiled rule signals
// escalate or deny, never allow: a rule can only lower a decision. Anything the evaluator cannot decide fires the rule (fail closed).
// Time zones come from the host's IANA database (TimeZoneInfo); a zone it does not know is not a known zone.
using System.Globalization;
using System.Numerics;
using System.Text;
using System.Text.RegularExpressions;
using AtlasPca.InteropJs;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.ActionsKit;

/// <summary>The money parameters of an action: amount parameter, exponent (null when the unit omits it) and the currency literal or parameter name.</summary>
public sealed record MoneyInfo(string Amount, object? Exp, string? Literal, string? Param)
{
    public D ToJson()
    {
        var o = new D { ["amount"] = Amount };
        if (Exp != null) o["exp"] = Exp;
        o["ccy"] = Param != null ? new D { ["param"] = Param } : new D { ["literal"] = Literal };
        return o;
    }
}

public static partial class ActionBusinessRules
{
    static readonly string[] RuleDays = { "sun", "mon", "tue", "wed", "thu", "fri", "sat" };
    static long PeriodMs(string p) => p == "hour" ? 3_600_000 : 86_400_000;
    static bool IsPeriod(object? p) => p is "hour" or "day";
    public const int MaxRuleCurrencies = 32, MaxRuleList = 64, MaxRuleApprovers = 16, MaxRuleExamples = 32;
    static readonly string[] RuleKeys = { "amount", "approval", "scope", "rate", "hours", "recipients", "required", "examples" };
    public const string BusinessRulesDomain = "atlas-pca/action-business-rules/v1";
    public const string RulesReviewDomain = "atlas-pca/action-rules-review/v1";
    public const string DefaultExampleAt = "2026-01-07T15:00:00Z";
    const long MaxSafe = 9007199254740991;

    const RegexOptions Ro = RegexOptions.CultureInvariant;
    static Regex CcyRe => Rx.Get(@"\A[A-Z]{3}\z", Ro);
    static Regex NameRe => Rx.Get(@"\A[a-z][a-z0-9_]{0,63}\z", Ro);
    static Regex HhmmRe => Rx.Get(@"\A([01][0-9]|2[0-3]):([0-5][0-9])\z", Ro);
    static Regex DomainRe => Rx.Get(@"\A(?=.{1,253}\z)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+\z", Ro);
    static Regex AddressRe => Rx.Get(@"\A[a-z0-9._%+-]{1,64}@[a-z0-9.-]{1,253}\z", Ro);
    static Regex DecRe => Rx.Get(@"\A(0|[1-9][0-9]{0,14})(?:\.([0-9]{1,6}))?\z", Ro);
    static Regex AtRe => Rx.Get(@"\A[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\z", Ro);
    static Regex TzRe => Rx.Get(@"\A[A-Za-z0-9_+\-/]+\z", Ro);

    static bool IsObj(object? v) => v is D;
    static bool Isi(object? v) => IntentJs.IsSafeInteger(v);
    static bool NegZero(object? v) => IntentJs.NumOf(v) is double d && IntentJs.IsNegZero(d);
    static double Num(object? v) => IntentJs.NumOf(v)!.Value;
    static Exception Bad(string msg) => new ActionKitError("bad_rules", msg);
    static void Closed(D o, string[] allowed, string at) { foreach (var k in o.Keys) if (!allowed.Contains(k)) throw Bad($"{at}: unknown member '{k}'"); }
    static string Hash(object? v) => Pca.HashCanonical(v);

    /// <summary>The parameter a reference names ({param} or {role}), with its definition. Throws bad_rules for none or several.</summary>
    public static (string Name, D P) ResolveParamRef(D d, object? r, string at)
    {
        if (r is not D rd) throw Bad($"{at}: name a parameter ({{param}} or {{role}})");
        var hasP = rd.GetValueOrDefault("param") is string; var hasR = rd.GetValueOrDefault("role") is string;
        if (hasP == hasR) throw Bad($"{at}: give exactly one of param or role");
        var ps = (D)d["params"]!;
        if (hasP)
        {
            var pn = (string)rd["param"]!;
            if (!ps.TryGetValue(pn, out var p) || p == null) throw Bad($"{at}: '{d["verb"]}' has no parameter '{pn}'");
            return (pn, (D)p);
        }
        var role = (string)rd["role"]!;
        var hits = ps.Keys.Where(n => Ak.S(ps[n], "role") == role).OrderBy(x => x, StringComparer.Ordinal).ToList();
        if (hits.Count != 1) throw Bad($"{at}: '{d["verb"]}' has {(hits.Count == 0 ? "no" : "several")} parameter{(hits.Count == 0 ? "" : "s")} with role {role}");
        return (hits[0], (D)ps[hits[0]]!);
    }

    /// <summary>The money parameters of an action.</summary>
    public static MoneyInfo MoneyOf(D d)
    {
        var ps = (D)d["params"]!;
        var hits = ps.Keys.Where(n => Ak.S(ps[n], "role") == "money.amount").OrderBy(x => x, StringComparer.Ordinal).ToList();
        if (hits.Count != 1) throw Bad($"'{d["verb"]}' needs exactly one parameter with role money.amount for an amount or approval-above rule (has {hits.Count})");
        var name = hits[0];
        var p = (D)ps[name]!;
        if (Ak.S(p, "type") != "integer") throw Bad($"'{d["verb"]}': the money.amount parameter '{name}' must be an integer");
        if (Ak.G(p, "unit") is not D u || Ak.S(u, "kind") != "money") throw Bad($"'{d["verb"]}': the amount parameter '{name}' declares no money unit (its currency)");
        var exp = u.GetValueOrDefault("exp");
        if (u["ccy"] is string lit) return new MoneyInfo(name, exp, lit, null);
        var frm = (string)Ak.G(u["ccy"], "from")!;
        if (!ps.ContainsKey(frm)) throw Bad($"'{d["verb"]}': the currency parameter '{frm}' does not exist");
        return new MoneyInfo(name, exp, null, frm);
    }

    static long ExpOf(object? exp) => exp != null ? (long)Num(exp) : throw new InvalidOperationException("TypeError: the money unit has no exponent");

    /// <summary>Integer minor units of a money value under exponent <paramref name="exp"/>. Throws bad_rules for a non-integer or over-precise value.</summary>
    public static long MinorUnits(object? v, long exp, string at)
    {
        if (IntentJs.NumOf(v) is double dv)
        {
            if (!Isi(v) || dv < 0 || NegZero(v)) throw Bad($"{at}: an amount is a non-negative integer of minor units, or a decimal string");
            return (long)dv;
        }
        if (v is not string s) throw Bad($"{at}: an amount is a number of minor units or a decimal string");
        var m = DecRe.Match(s);
        if (!m.Success) throw Bad($"{at}: '{s}' is not a decimal amount");
        var frac = m.Groups[2].Success ? m.Groups[2].Value : "";
        if (frac.Length > exp) throw Bad($"{at}: '{s}' has more decimals than the currency's {exp}");
        var padded = frac.PadRight((int)exp, '0');
        var n = BigInteger.Parse(m.Groups[1].Value, CultureInfo.InvariantCulture) * BigInteger.Pow(10, (int)exp) + (padded.Length == 0 ? BigInteger.Zero : BigInteger.Parse(padded, CultureInfo.InvariantCulture));
        if (n > MaxSafe) throw Bad($"{at}: '{s}' is too large");
        return (long)n;
    }

    static int Mins(string hhmm) => int.Parse(hhmm[0..2], CultureInfo.InvariantCulture) * 60 + int.Parse(hhmm[3..5], CultureInfo.InvariantCulture);

    // IANA time zone data bundled with the library, so the answer is the same on every platform (the platform's own zone database differs, e.g. Lord Howe before 1981)
    static readonly Dictionary<string, NodaTime.DateTimeZone?> ZoneCache = new();
    static NodaTime.DateTimeZone? Zone(string tz)
    {
        lock (ZoneCache)
        {
            if (ZoneCache.TryGetValue(tz, out var c)) return c;
            var p = NodaTime.DateTimeZoneProviders.Tzdb;
            var z = p.GetZoneOrNull(tz);
            if (z == null && p.Ids.FirstOrDefault(x => string.Equals(x, tz, StringComparison.OrdinalIgnoreCase)) is { } id) z = p.GetZoneOrNull(id); // the reference matches the name without regard to case
            ZoneCache[tz] = z;
            return z;
        }
    }

    /// <summary>Is this a time zone the runtime knows (IANA name)?</summary>
    public static bool KnownTimeZone(object? tz)
    {
        if (tz is not string s || s.Length == 0 || s.Length > 64 || !TzRe.IsMatch(s)) return false;
        try { return Zone(s) != null; } catch (Exception) { return false; }
    }

    static long DaysFromCivil(long y, long m, long d)
    {
        if (m <= 2) y -= 1;
        var era = (y >= 0 ? y : y - 399) / 400;
        var yoe = y - era * 400;
        var doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
        var doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
        return era * 146097 + doe - 719468;
    }

    /// <summary>Date.parse of an RFC 3339 "...Z" second-precision time: day 1..31 rolls over the month, 24:00:00 is the next day; else null (NaN).</summary>
    public static long? ParseUtcMs(object? s)
    {
        if (s is not string t || !AtRe.IsMatch(t)) return null;
        long y = long.Parse(t[0..4], CultureInfo.InvariantCulture), mo = long.Parse(t[5..7], CultureInfo.InvariantCulture), d = long.Parse(t[8..10], CultureInfo.InvariantCulture),
            h = long.Parse(t[11..13], CultureInfo.InvariantCulture), mi = long.Parse(t[14..16], CultureInfo.InvariantCulture), se = long.Parse(t[17..19], CultureInfo.InvariantCulture);
        if (!(1 <= mo && mo <= 12 && 1 <= d && d <= 31 && mi <= 59 && se <= 59 && (h <= 23 || (h == 24 && mi == 0 && se == 0)))) return null;
        return (DaysFromCivil(y, mo, 1) + d - 1) * 86_400_000 + h * 3_600_000 + mi * 60_000 + se * 1000;
    }

    /// <summary>Null iff <paramref name="rules"/> is a well-formed rules block for <paramref name="d"/>; the reason otherwise.</summary>
    public static string? BusinessRulesError(D d, object? rules)
    {
        try { ValidateRules(d, rules); return null; }
        catch (Exception e) { return e.Message; }
    }

    static void CcyMap(D d, object? m, string at)
    {
        if (m is not D md || md.Count == 0 || md.Count > MaxRuleCurrencies) throw Bad($"{at}: a map of 1..{MaxRuleCurrencies} currencies to amounts");
        var money = MoneyOf(d);
        foreach (var (c, v) in md)
        {
            if (!CcyRe.IsMatch(c)) throw Bad($"{at}: '{c}' is not an ISO 4217 currency code");
            MinorUnits(v, ExpOf(money.Exp), $"{at}.{c}");
        }
    }

    static D RefOf(D s) { var o = new D(); foreach (var k in new[] { "param", "role" }) if (s.ContainsKey(k)) o[k] = s[k]; return o; }

    static bool SameValueZero(object? a, object? b) => JsX.StrictEq(a, b);

    static void ValidateRules(D d, object? ro)
    {
        if (ro is not D r) throw Bad("rules must be an object");
        Closed(r, RuleKeys, "rules");
        if (r.Keys.Count(k => k != "examples") == 0) throw Bad("rules: name at least one rule");
        if (r.ContainsKey("amount"))
        {
            if (r["amount"] is not D a) throw Bad("rules.amount must be {max: {CCY: amount}}");
            Closed(a, new[] { "max" }, "rules.amount");
            CcyMap(d, a.GetValueOrDefault("max"), "rules.amount.max");
        }
        if (r.ContainsKey("approval"))
        {
            if (r["approval"] is not D ap) throw Bad("rules.approval must be an object");
            Closed(ap, new[] { "above", "always", "approvers", "group" }, "rules.approval");
            if (ap.ContainsKey("always") && ap["always"] is not true) throw Bad("rules.approval.always is true or absent");
            if (!ap.ContainsKey("above") == !ap.ContainsKey("always")) throw Bad("rules.approval: give exactly one of above or always");
            if (ap.ContainsKey("above")) CcyMap(d, ap["above"], "rules.approval.above");
            if (ap.ContainsKey("approvers") && (!Isi(ap["approvers"]) || Num(ap["approvers"]) < 1 || Num(ap["approvers"]) > MaxRuleApprovers)) throw Bad($"rules.approval.approvers is 1..{MaxRuleApprovers}");
            if (ap.ContainsKey("group") && (ap["group"] is not string g || !NameRe.IsMatch(g))) throw Bad("rules.approval.group is a lowercase name");
        }
        if (r.ContainsKey("scope"))
        {
            if (r["scope"] is not L sc || sc.Count == 0 || sc.Count > MaxRuleList) throw Bad($"rules.scope is a list of 1..{MaxRuleList} bindings");
            for (int i = 0; i < sc.Count; i++)
            {
                if (sc[i] is not D s) throw Bad($"rules.scope[{i}] must be an object");
                Closed(s, new[] { "param", "role", "caller" }, $"rules.scope[{i}]");
                var p = ResolveParamRef(d, RefOf(s), $"rules.scope[{i}]").P;
                if (Ak.S(p, "type") is not ("string" or "integer")) throw Bad($"rules.scope[{i}]: the bound parameter must be a string or integer id");
                if (s.GetValueOrDefault("caller") is not string cl || !NameRe.IsMatch(cl)) throw Bad($"rules.scope[{i}].caller is a lowercase attribute name of the caller");
            }
        }
        if (r.ContainsKey("rate"))
        {
            if (r["rate"] is not L rt || rt.Count == 0 || rt.Count > 4) throw Bad("rules.rate is a list of 1..4 limits");
            for (int i = 0; i < rt.Count; i++)
            {
                if (rt[i] is not D x) throw Bad($"rules.rate[{i}] must be an object");
                Closed(x, new[] { "max", "per", "by" }, $"rules.rate[{i}]");
                var mx = x.GetValueOrDefault("max");
                if (!Isi(mx) || Num(mx) < 1 || Num(mx) > 1_000_000) throw Bad($"rules.rate[{i}].max is 1..1000000");
                if (!IsPeriod(x.GetValueOrDefault("per"))) throw Bad($"rules.rate[{i}].per is hour or day");
                if (x.ContainsKey("by") && x["by"] is not ("principal" or "org")) throw Bad($"rules.rate[{i}].by is principal or org");
            }
        }
        if (r.ContainsKey("hours"))
        {
            if (r["hours"] is not D h) throw Bad("rules.hours must be an object");
            Closed(h, new[] { "days", "from", "to", "tz", "outside" }, "rules.hours");
            var days = h.GetValueOrDefault("days");
            if (days is not L dl || dl.Count == 0 || !dl.All(x => x is string xs && RuleDays.Contains(xs)) || dl.Select(x => (string)x!).Distinct(StringComparer.Ordinal).Count() != dl.Count)
                throw Bad($"rules.hours.days is a list of distinct days ({string.Join(", ", RuleDays)})");
            if (h.GetValueOrDefault("from") is not string f || !HhmmRe.IsMatch(f) || h.GetValueOrDefault("to") is not string t || !HhmmRe.IsMatch(t)) throw Bad("rules.hours.from and .to are HH:MM (24 h)");
            if (h.GetValueOrDefault("tz") is not string tz || !KnownTimeZone(tz)) throw Bad($"rules.hours.tz '{(h.ContainsKey("tz") ? Ak.JsStr(h["tz"]) : "undefined")}' is not a known IANA time zone");
            if (h.ContainsKey("outside") && h["outside"] is not ("escalate" or "deny")) throw Bad("rules.hours.outside is escalate or deny");
        }
        if (r.ContainsKey("recipients"))
        {
            if (r["recipients"] is not D x) throw Bad("rules.recipients must be an object");
            Closed(x, new[] { "param", "role", "domains", "addresses" }, "rules.recipients");
            var (name, p) = ResolveParamRef(d, RefOf(x), "rules.recipients");
            var ptype = Ak.S(p, "type");
            if (ptype is "array" or "set")
            {
                if (Ak.G(p, "items") != null && Ak.S(p, "items") != "string") throw Bad($"rules.recipients: '{name}' must hold strings");
                var mi = Ak.G(p, "max_items");
                if (!Isi(mi) || NegZero(mi) || Num(mi) > MaxRuleList) throw Bad($"rules.recipients: the list parameter '{name}' needs max_items <= {MaxRuleList} so every entry can be checked");
            }
            else if (ptype != "string") throw Bad($"rules.recipients: '{name}' must be a string or a bounded list of strings");
            var hasDoms = x.ContainsKey("domains"); var hasAdds = x.ContainsKey("addresses");
            if (!hasDoms && !hasAdds) throw Bad("rules.recipients: give domains and/or addresses");
            if (hasDoms && (x["domains"] is not L doms || doms.Count == 0 || doms.Count > MaxRuleList || !doms.All(v => v is string vs && DomainRe.IsMatch(vs)))) throw Bad("rules.recipients.domains is a list of lowercase domain names");
            if (hasAdds && (x["addresses"] is not L adds || adds.Count == 0 || adds.Count > MaxRuleList || !adds.All(v => v is string vs && AddressRe.IsMatch(vs)))) throw Bad("rules.recipients.addresses is a list of lowercase email addresses");
        }
        if (r.ContainsKey("required"))
        {
            if (r["required"] is not L rq || rq.Count == 0 || rq.Count > MaxRuleList || HasDup(rq)) throw Bad("rules.required is a list of distinct parameter names");
            var ps = (D)d["params"]!;
            foreach (var n in rq) if (n is not string ns || !ps.ContainsKey(ns)) throw Bad($"rules.required: '{d["verb"]}' has no parameter '{Ak.JsStr(n)}'");
        }
        if (r.ContainsKey("examples"))
        {
            if (r["examples"] is not L ex || ex.Count > MaxRuleExamples) throw Bad($"rules.examples is a list of at most {MaxRuleExamples}");
            for (int i = 0; i < ex.Count; i++)
            {
                if (ex[i] is not D e) throw Bad($"rules.examples[{i}] must be an object");
                Closed(e, new[] { "params", "caller", "at", "recent", "expect" }, $"rules.examples[{i}]");
                if (!IsObj(e.GetValueOrDefault("params"))) throw Bad($"rules.examples[{i}].params must be an object");
                if (e.ContainsKey("caller") && !IsObj(e["caller"])) throw Bad($"rules.examples[{i}].caller must be an object");
                if (e.ContainsKey("at") && ParseUtcMs(e["at"]) == null) throw Bad($"rules.examples[{i}].at is an RFC 3339 UTC time (…Z)");
                if (e.ContainsKey("recent") && (e["recent"] is not D rc || !rc.Values.All(n => Isi(n) && Num(n) >= 0 && !NegZero(n)))) throw Bad($"rules.examples[{i}].recent maps rate indexes to counts");
                if (e.GetValueOrDefault("expect") is not ("allow" or "escalate" or "deny")) throw Bad($"rules.examples[{i}].expect is allow, escalate or deny");
            }
        }
    }

    static bool HasDup(L xs) { for (int i = 0; i < xs.Count; i++) for (int j = 0; j < i; j++) if (SameValueZero(xs[i], xs[j])) return true; return false; }

    // ---- compiled form
    /// <summary>Digest of a rules block (examples are tests, not rules).</summary>
    public static string BusinessRulesDigest(string verb, D rules)
    {
        var r = new D(); foreach (var (k, v) in rules) if (k != "examples") r[k] = v;
        return Hash(new D { ["d"] = BusinessRulesDomain, ["verb"] = verb, ["rules"] = r });
    }

    static string P(string n) => "action.params." + n;

    static D? CcyCond(MoneyInfo m, string c)
    {
        if (m.Param != null) return new D { ["field"] = P(m.Param), ["op"] = "eq", ["value"] = c };
        return m.Literal == c ? null : new D { ["field"] = "action.verb", ["op"] = "eq", ["value"] = "\u0000never" };
    }

    static D And(IEnumerable<D?> cs) { var xs = cs.Where(c => c != null).Select(c => c!).ToList(); return xs.Count == 1 ? xs[0] : new D { ["all_of"] = new L(xs) }; }
    static D Always(string verb) => new() { ["field"] = "action.verb", ["op"] = "eq", ["value"] = verb };

    static string RuleId(string s)
    {
        var t = Regex.Replace(s.ToLowerInvariant(), "[^a-z0-9_]", "_");
        return t.Length > 64 ? t[..64] : t;
    }

    /// <summary>12345 minor units of USD (exp 2) is "123.45 USD". Deterministic (no locale).</summary>
    public static string FormatMoney(long minor, string ccy, long exp)
    {
        var s = minor.ToString(CultureInfo.InvariantCulture).PadLeft((int)exp + 1, '0');
        return (exp > 0 ? s[..^(int)exp] + "." + s[^(int)exp..] : s) + " " + ccy;
    }

    static readonly Dictionary<string, string> DayNames = new() { ["sun"] = "Sun", ["mon"] = "Mon", ["tue"] = "Tue", ["wed"] = "Wed", ["thu"] = "Thu", ["fri"] = "Fri", ["sat"] = "Sat" };

    static string HoursText(D h)
    {
        var ds = Ak.Strs(h["days"]).OrderBy(x => Array.IndexOf(RuleDays, x)).ToList();
        var idx = ds.Select(x => Array.IndexOf(RuleDays, x)).ToList();
        var run = idx.Count > 2 && idx.Select((x, k) => k == 0 || x == idx[k - 1] + 1).All(b => b);
        var days = run ? $"{DayNames[ds[0]]}-{DayNames[ds[^1]]}" : string.Join(", ", ds.Select(x => DayNames[x]));
        return $"{days} {h["from"]}-{h["to"]} ({h["tz"]})";
    }

    static string RecipientsText(D x) => string.Join(" or ", Ak.Strs(Ak.G(x, "domains")).Select(dm => "addresses at " + dm).Concat(Ak.Strs(Ak.G(x, "addresses"))));

    static D RefFor(D s) => s.ContainsKey("param") ? new D { ["param"] = s["param"] } : new D { ["role"] = s["role"] };
    static bool Truthy(object? v) => JsTruthy(v);
    static bool JsTruthy(object? v) => JsX.Truthy(v);
    static bool UsesMoney(D r) => r.ContainsKey("amount") || (Ak.G(r, "approval") is D ap && ap.ContainsKey("above"));

    /// <summary>Compile a rules block for <paramref name="d"/> into tighten rules and accumulators. Throws bad_rules for a malformed block. Deterministic.</summary>
    public static D CompileBusinessRules(D d, object? rulesO)
    {
        ValidateRules(d, rulesO);
        var rules = (D)rulesO!;
        var t = new L(); var acc = new L();
        var verb = (string)d["verb"]!;
        var outp = new D { ["v"] = 1L, ["verb"] = verb, ["rules_digest"] = BusinessRulesDigest(verb, rules), ["def_digest"] = Actions.DefDigest(d), ["tighten"] = t, ["accumulators"] = acc };
        var money = UsesMoney(rules) ? MoneyOf(d) : null;
        D? Unlisted(List<string> listed)
        {
            if (money == null) return null;
            if (money.Param != null) return new D { ["not"] = new D { ["field"] = P(money.Param), ["op"] = "in", ["value"] = Ak.ToL(listed) } };
            return listed.Contains(money.Literal!) ? null : Always(verb);
        }
        if (rules.ContainsKey("amount"))
        {
            var mxm = (D)((D)rules["amount"]!)["max"]!;
            var listed = mxm.Keys.OrderBy(x => x, StringComparer.Ordinal).ToList();
            var exp = ExpOf(money!.Exp);
            foreach (var c in listed)
            {
                var mx = MinorUnits(mxm[c], exp, "rules.amount.max." + c);
                t.Add(new D
                {
                    ["id"] = RuleId("amount_max_" + c), ["when"] = And(new[] { CcyCond(money, c), new D { ["field"] = P(money.Amount), ["op"] = "gt", ["value"] = mx } }), ["signal"] = "deny",
                    ["reason"] = $"the amount is above the {FormatMoney(mx, c, exp)} ceiling",
                });
            }
            var u = Unlisted(listed);
            if (u != null) t.Add(new D { ["id"] = "amount_currency", ["when"] = u, ["signal"] = "deny", ["reason"] = $"only {string.Join(", ", listed)} amounts are allowed" });
        }
        if (rules.ContainsKey("approval"))
        {
            var ap = (D)rules["approval"]!;
            var ao = new D { ["approvers"] = Ak.G(ap, "approvers") ?? 1L };
            outp["approval"] = ao;
            if (ap.ContainsKey("group")) ao["group"] = ap["group"];
            if (Truthy(Ak.G(ap, "always")))
                t.Add(new D { ["id"] = "approval_always", ["when"] = Always(verb), ["signal"] = "escalate", ["reason"] = "this action always needs approval" });
            else
            {
                var above = (D)ap["above"]!;
                var listed = above.Keys.OrderBy(x => x, StringComparer.Ordinal).ToList();
                var exp = ExpOf(money!.Exp);
                foreach (var c in listed)
                {
                    var x = MinorUnits(above[c], exp, "rules.approval.above." + c);
                    t.Add(new D
                    {
                        ["id"] = RuleId("approval_above_" + c), ["when"] = And(new[] { CcyCond(money, c), new D { ["field"] = P(money.Amount), ["op"] = "gt", ["value"] = x } }), ["signal"] = "escalate",
                        ["reason"] = $"amounts above {FormatMoney(x, c, exp)} need approval",
                    });
                }
                var u = Unlisted(listed);
                if (u != null) t.Add(new D { ["id"] = "approval_currency", ["when"] = u, ["signal"] = "escalate", ["reason"] = $"amounts in a currency other than {string.Join(", ", listed)} need approval" });
            }
        }
        if (rules.ContainsKey("scope"))
        {
            var sc = (L)rules["scope"]!;
            for (int i = 0; i < sc.Count; i++)
            {
                var s = (D)sc[i]!;
                var name = ResolveParamRef(d, RefFor(s), $"rules.scope[{i}]").Name;
                var caller = (string)s["caller"]!;
                // not eq: an absent caller attribute or parameter is undecided, so the rule fires
                t.Add(new D
                {
                    ["id"] = $"scope_{i}", ["when"] = new D { ["not"] = new D { ["field"] = P(name), ["op"] = "eq", ["ref"] = "subject." + caller } }, ["signal"] = "deny",
                    ["reason"] = $"{name} must be the caller's own {caller}",
                });
            }
        }
        if (rules.ContainsKey("rate"))
        {
            var rt = (L)rules["rate"]!;
            for (int i = 0; i < rt.Count; i++)
            {
                var r = (D)rt[i]!;
                var rid = $"rate_{i}";
                var by = Ak.G(r, "by") is string bs && bs.Length > 0 ? bs : "principal";
                acc.Add(new D
                {
                    ["id"] = rid, ["agg"] = "count", ["sel"] = new D { ["verbs"] = new L { verb } }, ["win"] = new D { ["kind"] = "sliding", ["ms"] = PeriodMs((string)r["per"]!) }, ["key"] = null,
                    ["domain_max"] = r["max"], ["cap"] = r["max"], ["holder"] = new D { ["kind"] = "site_local" }, ["scope"] = by,
                });
                t.Add(new D { ["id"] = rid, ["when"] = new D { ["field"] = "env.acc." + rid, ["op"] = "gte", ["value"] = r["max"] }, ["signal"] = "deny", ["reason"] = $"at most {Ak.JsStr(r["max"])} per {r["per"]} per {by}" });
            }
        }
        if (rules.ContainsKey("hours"))
        {
            var h = (D)rules["hours"]!;
            int frm = Mins((string)h["from"]!), to = Mins((string)h["to"]!);
            var dows = Ak.Strs(h["days"]).Select(x => (long)Array.IndexOf(RuleDays, x)).OrderBy(x => x).ToList();
            D inTime, day;
            D Min(string op, long v) => new() { ["field"] = "env.clock.min", ["op"] = op, ["value"] = v };
            D Dow(IEnumerable<long> vs) => new() { ["field"] = "env.clock.dow", ["op"] = "in", ["value"] = new L(vs.Select(v => (object?)v)) };
            if (frm < to)
            {
                inTime = new D { ["all_of"] = new L { Min("gte", frm), Min("lt", to) } };
                day = Dow(dows);
            }
            else
            {
                // an overnight window (22:00-06:00): the day named is the day the window starts
                inTime = new D { ["any_of"] = new L { Min("gte", frm), Min("lt", to) } };
                day = new D
                {
                    ["any_of"] = new L
                    {
                        new D { ["all_of"] = new L { Dow(dows), Min("gte", frm) } },
                        new D { ["all_of"] = new L { Dow(dows.Select(x => (x + 1) % 7)), Min("lt", to) } },
                    },
                };
            }
            outp["clock_tz"] = h["tz"];
            t.Add(new D { ["id"] = "hours", ["when"] = new D { ["not"] = new D { ["all_of"] = new L { day, inTime } } }, ["signal"] = Truthy(Ak.G(h, "outside")) ? h["outside"] : "escalate", ["reason"] = "outside " + HoursText(h) });
        }
        if (rules.ContainsKey("recipients"))
        {
            var x = (D)rules["recipients"]!;
            var (name, p) = ResolveParamRef(d, RefFor(x), "rules.recipients");
            D OkAt(string path)
            {
                var alts = new L(Ak.Strs(Ak.G(x, "domains")).Select(dm => (object?)new D { ["field"] = path, ["op"] = "like", ["value"] = "*@" + Regex.Replace(dm, @"[\\*?]", m => "\\" + m.Value) }));
                if (Ak.G(x, "addresses") != null) alts.Add(new D { ["field"] = path, ["op"] = "in", ["value"] = Ak.ToL(Ak.Strs(x["addresses"]).OrderBy(a => a, StringComparer.Ordinal)) });
                return new D { ["any_of"] = alts };
            }
            D ok;
            if (Ak.S(p, "type") == "string") ok = OkAt(P(name));
            else
            {
                var n = (int)Num(p["max_items"]);
                var all = new L();
                for (int i = 0; i < n; i++) all.Add(new D { ["any_of"] = new L { new D { ["field"] = P($"{name}.{i}"), ["op"] = "exists", ["value"] = false }, OkAt(P($"{name}.{i}")) } });
                all.Add(new D { ["field"] = P($"{name}.{n}"), ["op"] = "exists", ["value"] = false });
                ok = new D { ["all_of"] = all };
            }
            t.Add(new D { ["id"] = "recipients", ["when"] = new D { ["not"] = ok }, ["signal"] = "deny", ["reason"] = $"{name} may only name {RecipientsText(x)}" });
        }
        if (rules.ContainsKey("required"))
        {
            var rq = (L)rules["required"]!;
            for (int i = 0; i < rq.Count; i++)
            {
                var n = (string)rq[i]!;
                var pr = (D)((D)d["params"]!)[n]!;
                D missing = Ak.S(pr, "type") == "string"
                    ? new D { ["any_of"] = new L { new D { ["field"] = P(n), ["op"] = "exists", ["value"] = false }, new D { ["field"] = P(n), ["op"] = "eq", ["value"] = "" } } }
                    : new D { ["field"] = P(n), ["op"] = "exists", ["value"] = false };
                t.Add(new D { ["id"] = $"required_{i}", ["when"] = missing, ["signal"] = "deny", ["reason"] = $"{n} is required" });
            }
        }
        foreach (D r in t)
            if (r.GetValueOrDefault("reason") is string rs && rs.Length > 256) r["reason"] = rs[..253] + "...";
        return outp;
    }

    // ---- evaluation
    public static int DecisionRank(string s) => s switch { "deny" => 0, "escalate" => 1, _ => 2 };

    /// <summary>Meet in the order deny &lt; escalate &lt; allow.</summary>
    public static string MeetDecision(string a, string b) => DecisionRank(a) <= DecisionRank(b) ? a : b;

    /// <summary>Day of week (0 = Sunday) and minute of day at <paramref name="now"/> (ms since the epoch) in <paramref name="tz"/>, or null when it cannot be computed.
    /// shortcut: instants outside the NodaTime range (years -9998..9999) give null, where the reference still answers; upgrade if rules ever need them.</summary>
    public static D? ClockAt(object? now, string tz)
    {
        try
        {
            if (IntentJs.NumOf(now) is not double n || !double.IsFinite(n)) return null;
            var z = Zone(tz);
            if (z == null) return null;
            var local = NodaTime.Instant.FromUnixTimeMilliseconds((long)Math.Truncate(n)).InZone(z).LocalDateTime;
            return new D { ["dow"] = IntentJs.OfLong((int)local.DayOfWeek % 7), ["min"] = IntentJs.OfLong(local.Hour * 60 + local.Minute) }; // ISO Monday 1 .. Sunday 7 to Sunday 0
        }
        catch (Exception) { return null; }
    }

    /// <summary>The predicate context the compiled rules are evaluated in: verifier-computed env members only.</summary>
    public static D RulesContext(D c, D i)
    {
        var env = new D();
        if (Ak.G(c, "clock_tz") is string tz)
        {
            var k = ClockAt(i.GetValueOrDefault("now"), tz);
            if (k != null) env["clock"] = k;
        }
        var acc = new D();
        var counts = Truthy(i.GetValueOrDefault("counts")) ? i["counts"] : new D();
        foreach (var a in (L)c["accumulators"]!)
        {
            var id = (string)Ak.G(a, "id")!;
            var n = counts is D cd ? cd.GetValueOrDefault(id) : throw new InvalidOperationException("counts is not an object");
            if (Isi(n) && Num(n) >= 0) acc[id] = n;
        }
        env["acc"] = acc;
        return new D
        {
            ["action"] = new D { ["verb"] = c["verb"], ["resource"] = i.GetValueOrDefault("resource") ?? "", ["params"] = i["params"] },
            ["subject"] = i.GetValueOrDefault("subject") ?? new D(), ["env"] = env,
        };
    }

    /// <summary>Evaluate compiled rules: allow unless a rule fires; a fired rule caps the decision at its signal. Never throws.</summary>
    public static D EvaluateBusinessRules(D c, D i)
    {
        try
        {
            var ctx = RulesContext(c, i);
            var decision = "allow";
            var reasons = new L(); var fired = new L();
            var approval = false;
            foreach (var ro in c.GetValueOrDefault("tighten") as L ?? throw new InvalidOperationException("c.tighten is not iterable"))
            {
                var r = (D)ro!;
                if (Predicates.EvaluateConditionTri(r["when"], ctx) == Predicates.Tri.False) continue;
                var signal = (string)r["signal"]!;
                decision = MeetDecision(decision, signal);
                var id = (string)r["id"]!;
                fired.Add(id);
                reasons.Add($"{id}: {(r.GetValueOrDefault("reason") != null ? Ak.JsStr(r["reason"]) : signal)}");
                if (signal == "escalate" && id.StartsWith("approval_", StringComparison.Ordinal)) approval = true;
            }
            var o = new D { ["decision"] = decision, ["reasons"] = reasons, ["fired"] = fired };
            if (approval && Truthy(Ak.G(c, "approval"))) o["approval"] = c["approval"];
            return o;
        }
        catch (Exception e)
        {
            return new D { ["decision"] = "deny", ["reasons"] = new L { $"rules: evaluation error (fail closed): {e.Message}" }, ["fired"] = new L() };
        }
    }

    /// <summary>The decision with rules applied to a base decision: the meet, so rules never raise it.</summary>
    public static string WithBusinessRules(string baseDecision, D v) => MeetDecision(baseDecision, (string)v["decision"]!);

    /// <summary>Run a rules block's examples.</summary>
    public static L RunRuleExamples(D d, object? rulesO)
    {
        var c = CompileBusinessRules(d, rulesO);
        var rules = (D)rulesO!;
        var outp = new L();
        var accs = (L)c["accumulators"]!;
        var exs = Ak.Lst(rules, "examples");
        for (int index = 0; index < exs.Count; index++)
        {
            var e = (D)exs[index]!;
            var counts = new D();
            var recent = Truthy(Ak.G(e, "recent")) ? (D)e["recent"]! : new D();
            for (int k = 0; k < accs.Count; k++) counts[(string)Ak.G(accs[k], "id")!] = recent.GetValueOrDefault(k.ToString(CultureInfo.InvariantCulture)) ?? (recent.ContainsKey(k.ToString(CultureInfo.InvariantCulture)) ? null : IntentJs.OfLong(0));
            var ms = ParseUtcMs(e.ContainsKey("at") ? e["at"] : DefaultExampleAt);
            var inp = new D { ["params"] = e["params"], ["now"] = ms == null ? null : IntentJs.OfLong(ms.Value), ["counts"] = counts };
            if (e.GetValueOrDefault("caller") != null) inp["subject"] = e["caller"];
            var v = EvaluateBusinessRules(c, inp);
            var reasons = Ak.Strs(v["reasons"]);
            outp.Add(new D
            {
                ["index"] = (long)index, ["expect"] = e["expect"], ["got"] = v["decision"], ["ok"] = (string)v["decision"]! == (string)e["expect"]!,
                ["why"] = reasons.Count > 0 ? string.Join("; ", reasons) : "no rule fired",
            });
        }
        return outp;
    }

    /// <summary>One plain sentence per rule, for the policy card and the dashboard. Throws bad_rules for a malformed block.</summary>
    public static L ExplainBusinessRules(D d, object? rulesO)
    {
        ValidateRules(d, rulesO);
        var rules = (D)rulesO!;
        var outp = new L();
        var m = UsesMoney(rules) ? MoneyOf(d) : null;
        string Lst(D mp) => string.Join(", ", mp.Keys.OrderBy(x => x, StringComparer.Ordinal).Select(c => FormatMoney(MinorUnits(mp[c], ExpOf(m!.Exp), c), c, ExpOf(m.Exp))));
        if (rules.ContainsKey("amount")) outp.Add($"Refuses amounts above {Lst((D)((D)rules["amount"]!)["max"]!)}; any other currency is refused.");
        if (rules.ContainsKey("approval"))
        {
            var ap = (D)rules["approval"]!;
            var nObj = Ak.G(ap, "approvers");
            var n = nObj != null ? Ak.JsStr(nObj) : "1";
            var who = $"{n} approver{(n == "1" ? "" : "s")}{(Truthy(Ak.G(ap, "group")) ? $" from the {ap["group"]} group" : "")}";
            outp.Add(Truthy(Ak.G(ap, "always")) ? $"Always needs approval by {who}." : $"Needs approval by {who} when the amount is above {Lst((D)ap["above"]!)} (or in another currency).");
        }
        foreach (var so in Ak.Lst(rules, "scope"))
        {
            var s = (D)so!;
            var name = ResolveParamRef(d, RefFor(s), "rules.scope").Name;
            outp.Add($"Only the caller's own records: {name} must be the caller's {s["caller"]}.");
        }
        foreach (var ro in Ak.Lst(rules, "rate"))
        {
            var r = (D)ro!;
            outp.Add($"At most {Ak.JsStr(r["max"])} per {r["per"]} per {(Ak.S(r, "by") == "org" ? "organisation" : "principal")}.");
        }
        if (rules.ContainsKey("hours"))
        {
            var h = (D)rules["hours"]!;
            outp.Add($"Only {HoursText(h)}; outside those hours it {(Ak.S(h, "outside") == "deny" ? "is refused" : "needs approval")}.");
        }
        if (rules.ContainsKey("recipients"))
        {
            var x = (D)rules["recipients"]!;
            var name = ResolveParamRef(d, RefFor(x), "rules.recipients").Name;
            outp.Add($"{name} may only name {RecipientsText(x)}.");
        }
        if (rules.ContainsKey("required")) outp.Add($"Requires {string.Join(", ", Ak.Strs(rules["required"]))}.");
        return outp;
    }

    // ---- lint (contradictions and dead rules)
    public static readonly (string Id, string Severity, string Title)[] BusinessRuleLints =
    {
        ("LR-001", "error", "a rules block is malformed or names a parameter the action does not have"),
        ("LR-002", "error", "a contradiction: under the rules the action can never be allowed"),
        ("LR-003", "warning", "a rule that can never fire or that another rule already covers"),
        ("LR-004", "error", "a rules example does not decide as it expects"),
    };

    /// <summary>Lint one action's rules.</summary>
    public static L LintBusinessRules(D d, object? rules)
    {
        D F(string rule, string severity, string message) => new() { ["rule"] = rule, ["severity"] = severity, ["verb"] = d["verb"], ["message"] = message };
        var e = BusinessRulesError(d, rules);
        if (!string.IsNullOrEmpty(e)) return new L { F("LR-001", "error", e) };
        var r = (D)rules!;
        var outp = new L();
        var m = UsesMoney(r) ? MoneyOf(d) : null;
        var dps = (D)d["params"]!;
        D? amt = m != null ? (D)dps[m.Amount]! : null;
        List<object?>? ccyValues = null;
        if (m != null) ccyValues = m.Param != null ? (Ak.G(dps[m.Param], "values") as L) : new L { m.Literal };
        string Cv() => string.Join(", ", ccyValues!.Select(Ak.JsStr));
        if (r.ContainsKey("amount") && m != null)
        {
            var mxm = (D)((D)r["amount"]!)["max"]!;
            var listed = mxm.Keys.ToList();
            if (ccyValues != null && !ccyValues.Any(c => c is string cs && listed.Contains(cs)))
                outp.Add(F("LR-002", "error", $"rules.amount: none of the action's currencies ({Cv()}) has a ceiling, so every call is refused"));
            var exp = ExpOf(m.Exp);
            foreach (var c in listed)
            {
                var mx = MinorUnits(mxm[c], exp, c);
                if (ccyValues != null && !ccyValues.Any(x => x is string xs && xs == c)) outp.Add(F("LR-003", "warning", $"rules.amount.max.{c}: the action never uses {c}"));
                if (amt != null && Ak.G(amt, "min") != null && mx < Num(amt["min"])) outp.Add(F("LR-002", "error", $"rules.amount.max.{c}: the ceiling {FormatMoney(mx, c, exp)} is below the parameter's minimum, so every {c} call is refused"));
                if (amt != null && Ak.G(amt, "max") != null && mx >= Num(amt["max"])) outp.Add(F("LR-003", "warning", $"rules.amount.max.{c}: the parameter's own maximum already bounds the amount below this ceiling"));
            }
        }
        if (Ak.G(r, "approval") is D apr && apr.ContainsKey("above") && m != null)
        {
            var above = (D)apr["above"]!;
            var exp = ExpOf(m.Exp);
            foreach (var c in above.Keys)
            {
                var x = MinorUnits(above[c], exp, c);
                object? ceil = r.ContainsKey("amount") ? ((D)((D)r["amount"]!)["max"]!).GetValueOrDefault(c) : null;
                if (ceil != null && x >= MinorUnits(ceil, exp, c)) outp.Add(F("LR-003", "warning", $"rules.approval.above.{c}: above the amount ceiling, so the approval can never be asked for"));
                if (r.ContainsKey("amount") && ceil == null) outp.Add(F("LR-003", "warning", $"rules.approval.above.{c}: {c} has no ceiling, so it is always refused before an approval"));
            }
        }
        if (r.ContainsKey("hours") && (string)((D)r["hours"]!)["from"]! == (string)((D)r["hours"]!)["to"]!)
        {
            var h = (D)r["hours"]!;
            outp.Add(F("LR-002", "error", $"rules.hours: the window {h["from"]}-{h["to"]} is empty, so the action is {(Ak.S(h, "outside") == "deny" ? "always refused" : "always escalated")}"));
        }
        if (r.ContainsKey("required"))
            foreach (var no in (L)r["required"]!)
            {
                var n = (string)no!;
                var pr = (D)dps[n]!;
                if (!(Ak.G(pr, "required") is false) && Ak.S(pr, "type") != "string") outp.Add(F("LR-003", "warning", $"rules.required: '{n}' is already required by the definition"));
            }
        if (r.ContainsKey("rate"))
        {
            var seen = new Dictionary<string, double>();
            foreach (var xo in (L)r["rate"]!)
            {
                var x = (D)xo!;
                var by = Truthy(Ak.G(x, "by")) ? (string)x["by"]! : "principal";
                var k = $"{x["per"]}|{by}";
                var xm = Num(x["max"]);
                if (seen.TryGetValue(k, out var sv)) outp.Add(F("LR-003", "warning", $"rules.rate: two limits per {x["per"]} per {by}; only the lower ({Ak.JsStr(IntentJs.OfLong((long)Math.Min(sv, xm)))}) matters"));
                seen[k] = Math.Min(seen.GetValueOrDefault(k, double.PositiveInfinity), xm);
            }
            if (seen.TryGetValue("hour|principal", out var hh) && seen.TryGetValue("day|principal", out var dd) && dd <= hh)
                outp.Add(F("LR-003", "warning", "rules.rate: the daily limit is not above the hourly one, so the hourly limit never fires"));
        }
        try
        {
            foreach (var xo in RunRuleExamples(d, r))
            {
                var x = (D)xo!;
                if (!(x["ok"] is true)) outp.Add(F("LR-004", "error", $"rules.examples[{x["index"]}]: expected {x["expect"]}, got {x["got"]} ({x["why"]})"));
            }
        }
        catch (Exception err) { outp.Add(F("LR-001", "error", err.Message)); }
        return outp;
    }
}

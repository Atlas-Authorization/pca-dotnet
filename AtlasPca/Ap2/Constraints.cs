// AP2 open-mandate constraint evaluation: payment constraints (range, payees, instruments, PISPs, reference, budget, recurrence, execution
// window) against a closed payment mandate, and checkout constraints (merchants, line items by maximum flow) against a UCP checkout.
using System.Text.RegularExpressions;
using AtlasPca.InteropJs;
using AtlasPca.Js;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Ap2;

public static partial class Ap2
{
    static bool Truthy(object? v) => !IsUndef(v) && JsX.Truthy(v);

    /// <summary>Same merchant: equal ids when both carry one, else equal name and website (both present).</summary>
    public static bool MerchantMatches(object? candidate, object? target)
    {
        if (Truthy(G(candidate, "id")) && Truthy(G(target, "id"))) return JsX.StrictEq(G(candidate, "id"), G(target, "id"));
        return Truthy(G(candidate, "name")) && Truthy(G(candidate, "website")) && JsX.StrictEq(G(candidate, "name"), G(target, "name")) && JsX.StrictEq(G(candidate, "website"), G(target, "website"));
    }

    static object? SortKeys(object? v)
    {
        if (v is L l) return l.Select(SortKeys).ToList();
        if (v is D d)
        {
            var o = new D();
            foreach (var k in d.Keys.OrderBy(k => k, StringComparer.Ordinal)) o[k] = SortKeys(d[k]);
            return o;
        }
        return v;
    }

    static bool SameJson(object? a, object? b)
    {
        if (IsUndef(a) || IsUndef(b)) return IsUndef(a) && IsUndef(b);
        return JsJson.Stringify(SortKeys(a)) == JsJson.Stringify(SortKeys(b));
    }

    static readonly Regex Rfc3339 = new(@"\A([0-9]{4})-([0-9]{2})-([0-9]{2})(?:T([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.([0-9]{1,9}))?(Z|([+-])([0-9]{2}):([0-9]{2})))?\z", RegexOptions.CultureInvariant);
    const long DayMs = 86_400_000;

    static bool IsLeap(long y) => y % 4 == 0 && (y % 100 != 0 || y % 400 == 0);
    static int DaysInMonth(long y, int m) => m switch { 2 => IsLeap(y) ? 29 : 28, 4 or 6 or 9 or 11 => 30, _ => 31 };

    /// <summary>Days since 1970-01-01 of a proleptic Gregorian date.</summary>
    static long DaysFromCivil(long y, int m, int d)
    {
        y -= m <= 2 ? 1 : 0;
        long era = (y >= 0 ? y : y - 399) / 400;
        long yoe = y - era * 400;
        long doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
        long doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
        return era * 146097 + doe - 719468;
    }

    static (long y, int m, int d) CivilFromDays(long z)
    {
        z += 719468;
        long era = (z >= 0 ? z : z - 146096) / 146097;
        long doe = z - era * 146097;
        long yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
        long y = yoe + era * 400;
        long doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        long mp = (5 * doy + 2) / 153;
        int d = (int)(doy - (153 * mp + 2) / 5 + 1);
        int m = (int)(mp < 10 ? mp + 3 : mp - 9);
        return (m <= 2 ? y + 1 : y, m, d);
    }

    static long FloorDiv(long a, long b) => a / b - (a % b != 0 && (a < 0) != (b < 0) ? 1 : 0);

    /// <summary>An RFC 3339 date or date-time as epoch milliseconds, or null when it is not a valid instant.</summary>
    static double? ParseInstant(object? s)
    {
        if (s is not string str) return null;
        var m = Rfc3339.Match(str);
        if (!m.Success) return null;
        long y = long.Parse(m.Groups[1].Value);
        int mo = int.Parse(m.Groups[2].Value), d = int.Parse(m.Groups[3].Value);
        if (mo < 1 || mo > 12 || d < 1 || d > DaysInMonth(y, mo)) return null;
        double day = DaysFromCivil(y, mo, d) * (double)DayMs;
        if (!m.Groups[4].Success) return day;
        int h = int.Parse(m.Groups[4].Value), mi = int.Parse(m.Groups[5].Value), se = int.Parse(m.Groups[6].Value);
        if (h > 23 || mi > 59 || se > 59) return null;
        int ms = m.Groups[7].Success ? int.Parse(m.Groups[7].Value[..Math.Min(3, m.Groups[7].Value.Length)].PadRight(3, '0')) : 0;
        double offset = 0;
        if (m.Groups[8].Value != "Z")
        {
            int oh = int.Parse(m.Groups[10].Value), om = int.Parse(m.Groups[11].Value);
            if (oh > 23 || om > 59) return null;
            offset = (m.Groups[9].Value == "+" ? 1 : -1) * (oh * 60 + om) * 60_000.0;
        }
        return day + ((h * 60 + mi) * 60 + se) * 1000.0 + ms - offset;
    }

    static double? PeriodStart(double msD, string frequency)
    {
        if (!double.IsFinite(msD) || Math.Abs(msD) > 8.64e15) return double.NaN; // an invalid Date: every comparison against it is false
        long ms = (long)msD;
        long days = FloorDiv(ms, DayMs);
        long dayStart = days * DayMs;
        var (y, mo, _) = CivilFromDays(days);
        long dow = ((days + 4) % 7 + 7) % 7; // getUTCDay: 1970-01-01 was a Thursday
        long weekStart = dayStart - ((dow + 6) % 7) * DayMs;
        switch (frequency)
        {
            case "ON_DEMAND": return 0;
            case "DAILY": return dayStart;
            case "WEEKLY": return weekStart;
            case "BIWEEKLY":
                {
                    long week = 7 * DayMs, epochMonday = -3 * DayMs;
                    return epochMonday + FloorDiv(weekStart - epochMonday, 2 * week) * 2 * week;
                }
            case "MONTHLY": return DaysFromCivil(y, mo, 1) * DayMs;
            case "QUARTERLY": return DaysFromCivil(y, (mo - 1) / 3 * 3 + 1, 1) * DayMs;
            case "ANNUALLY": return DaysFromCivil(y, 1, 1) * DayMs;
            default: return null; // no such frequency: the reference compares against undefined
        }
    }

    static string? ContextProblem(object? c)
    {
        bool Ok(object? n) => IntentJs.IsNonNeg(n);
        if (!Ok(G(c, "totalAmount")) || !Ok(G(c, "totalUses")) || (!IsUndef(G(c, "lastUsedDate")) && !Ok(G(c, "lastUsedDate"))))
            return "mandate context must carry non-negative integer totalAmount, totalUses and lastUsedDate";
        return null;
    }

    static double Num0(object? v) => JsJson.ToJsNumber(v);

    static List<string> EvaluatePayment(object? c, object? closed, object? o)
    {
        var amt = G(closed, "payment_amount");
        var v = new List<string>();
        var type = G(c, "type");
        switch (type as string)
        {
            case "payment.amount_range":
                if (!JsX.StrictEq(G(amt, "currency"), G(c, "currency"))) v.Add($"currency mismatch: expected {S(G(c, "currency"))}, got {S(G(amt, "currency"))}");
                if (!double.IsFinite(Num0(G(amt, "amount")))) v.Add($"amount {S(G(amt, "amount"))} is not finite");
                if (!IsUndef(G(c, "min")) && !(Num0(G(amt, "amount")) >= Num0(G(c, "min")))) v.Add($"amount {S(G(amt, "amount"))} below minimum {S(G(c, "min"))}");
                if (!(Num0(G(amt, "amount")) <= Num0(G(c, "max")))) v.Add($"amount {S(G(amt, "amount"))} exceeds maximum {S(G(c, "max"))}");
                return v;
            case "payment.allowed_payees":
                return ((L)G(c, "allowed")!).Any(m => MerchantMatches(m, G(closed, "payee"))) ? v : new() { $"payee {S(G(G(closed, "payee"), "name"))} is not in the allowed list" };
            case "payment.allowed_payment_instruments":
                return ((L)G(c, "allowed")!).Any(i => JsX.StrictEq(G(i, "id"), G(G(closed, "payment_instrument"), "id"))) ? v : new() { $"payment instrument {S(G(G(closed, "payment_instrument"), "id"))} is not in the allowed list" };
            case "payment.allowed_pisps":
                {
                    var p = G(closed, "pisp");
                    if (!Truthy(p)) return new() { "missing PISP in the closed mandate" };
                    return ((L)G(c, "allowed")!).Any(a => JsX.StrictEq(G(a, "legal_name"), G(p, "legal_name")) && JsX.StrictEq(G(a, "brand_name"), G(p, "brand_name")) && JsX.StrictEq(G(a, "domain_name"), G(p, "domain_name")))
                        ? v : new() { "PISP is not in the allowed list" };
                }
            case "payment.reference":
                {
                    var h = G(o, "openCheckoutHash");
                    if (!Truthy(h)) return new() { "openCheckoutHash is required to evaluate a payment.reference constraint" };
                    return JsX.StrictEq(h, G(c, "conditional_transaction_id")) ? v : new() { "payment.reference does not match the open checkout mandate hash" };
                }
            case "payment.budget":
                {
                    if (!JsX.StrictEq(G(amt, "currency"), G(c, "currency"))) return new() { $"budget currency mismatch: expected {S(G(c, "currency"))}, got {S(G(amt, "currency"))}" };
                    var ctx = G(o, "context");
                    if (!Truthy(ctx)) return new() { "mandate context is required to evaluate a budget" };
                    var bad = ContextProblem(ctx);
                    if (bad != null) return new() { bad };
                    double scaled = Num0(G(c, "max")) * 100;
                    double maxMinor = JsRound(scaled);
                    if (Math.Abs(scaled - maxMinor) > 1e-6) return new() { "budget.max is not a whole number of minor units" };
                    double spend = Num0(G(ctx, "totalAmount")) + Num0(G(amt, "amount"));
                    return !(double.IsFinite(spend) && spend <= maxMinor) ? new() { $"cumulative spend {JsX.JsNumString(spend)} exceeds budget {JsX.JsNumString(maxMinor)} (past spend {S(G(ctx, "totalAmount"))})" } : v;
                }
            case "payment.agent_recurrence":
                {
                    // strict: an unknown frequency is a violation whether or not a last-used date exists
                    if (G(c, "frequency") is not string freq || !Frequencies.Contains(freq)) return new() { "unknown recurrence frequency" };
                    var ctx = G(o, "context");
                    if (Truthy(ctx))
                    {
                        var bad = ContextProblem(ctx);
                        if (bad != null) return new() { bad };
                    }
                    var maxOcc = G(c, "max_occurrences");
                    if (!IsUndef(maxOcc))
                    {
                        if (!Truthy(ctx)) return new() { "mandate context is required to evaluate recurrence limits" };
                        if (!(Num0(G(ctx, "totalUses")) < Num0(maxOcc))) v.Add($"maximum occurrences exceeded: {S(G(ctx, "totalUses"))} >= {S(maxOcc)}");
                    }
                    if (!JsX.StrictEq(G(c, "frequency"), "ON_DEMAND"))
                    {
                        if (!Truthy(ctx)) return new() { "mandate context is required to evaluate recurrence frequency" };
                        var last = G(ctx, "lastUsedDate");
                        if (!IsUndef(last) && !(Num0(last) * 1000 < (G(c, "frequency") is string fr ? PeriodStart(Num0(G(o, "now")) * 1000, fr) ?? double.NaN : double.NaN)))
                            v.Add($"already used in the current {S(G(c, "frequency"))} period");
                    }
                    return v;
                }
            case "payment.execution_date":
                {
                    var ed = G(closed, "execution_date");
                    double? at = !IsUndef(ed) ? ParseInstant(ed) : Num0(G(o, "now")) * 1000;
                    if (at == null || !double.IsFinite(at.Value)) return new() { $"execution_date {S(ed)} is not a valid instant" };
                    foreach (var (key, bound, before) in new[] { ("not_before", G(c, "not_before"), true), ("not_after", G(c, "not_after"), false) })
                    {
                        if (IsUndef(bound)) continue;
                        var b = ParseInstant(bound);
                        if (b == null) v.Add($"{key} {S(bound)} is not a valid instant");
                        else if (before ? !(at >= b) : !(at <= b)) v.Add($"execution date is {(before ? "before" : "after")} the allowed window ({key} {S(bound)})");
                    }
                    return v;
                }
            default:
                return new() { $"unknown constraint type {S(type)}" };
        }
    }

    /// <summary>Violations of an open payment mandate's pre-set fields and constraints by a closed mandate. <paramref name="o"/>:
    /// <c>{openCheckoutHash?, context?, now}</c> where context is <c>{totalAmount, totalUses, lastUsedDate?}</c>. Empty = satisfied.</summary>
    public static List<string> CheckPaymentConstraints(object? open, object? closed, object? o)
    {
        var v = new List<string>();
        if (!IsUndef(G(open, "payee")) && !MerchantMatches(G(open, "payee"), G(closed, "payee")))
            v.Add($"pre-set payee mismatch: expected {S(G(G(open, "payee"), "name"))}, got {S(G(G(closed, "payee"), "name"))}");
        if (!IsUndef(G(open, "payment_amount")) && !SameJson(G(open, "payment_amount"), G(closed, "payment_amount"))) v.Add("pre-set payment_amount mismatch");
        if (!IsUndef(G(open, "payment_instrument")) && !SameJson(G(open, "payment_instrument"), G(closed, "payment_instrument"))) v.Add("pre-set payment_instrument mismatch");
        if (!IsUndef(G(open, "pisp")) && !SameJson(G(open, "pisp"), G(closed, "pisp"))) v.Add("pre-set pisp mismatch");
        if (!IsUndef(G(open, "execution_date")) && !JsX.StrictEq(G(open, "execution_date"), G(closed, "execution_date"))) v.Add("pre-set execution_date mismatch");
        var constraints = G(open, "constraints") as L ?? throw JsX.TypeError("open.constraints.map is not a function");
        var types = new HashSet<string?>(constraints.Select(c => G(c, "type") as string));
        if (types.Contains("payment.agent_recurrence"))
        {
            if (!types.Contains("payment.amount_range")) v.Add("payment.agent_recurrence requires a payment.amount_range constraint");
            if (!types.Contains("payment.budget")) v.Add("payment.agent_recurrence requires a payment.budget constraint");
        }
        foreach (var c in constraints) v.AddRange(EvaluatePayment(c, closed, o));
        return v;
    }

    // ===== checkout =====

    static Ap2Exception Bad(string m) => new($"checkout_jwt payload: {m}");

    /// <summary>The UCP checkout view of a checkout JWT payload: <c>{id, currency, line_items, totals, merchant?}</c>; throws on a malformed payload.</summary>
    public static D ProjectCheckout(D payload)
    {
        var id = G(payload, "id") as string;
        if (id is null || id.Length == 0) throw Bad("id is required");
        var currency = G(payload, "currency") as string;
        if (currency is null || !IsUpper3(currency)) throw Bad("currency must be ISO 4217");
        var lis = G(payload, "line_items") as L;
        if (lis is null || lis.Count == 0) throw Bad("line_items must be a non-empty array");
        var tots = G(payload, "totals") as L;
        if (tots is null) throw Bad("totals must be an array");
        var lineItems = new L();
        for (int i = 0; i < lis.Count; i++)
        {
            D? li = null, item = null;
            string? lid = null;
            if ((li = lis[i] as D) is null || (lid = G(li, "id") as string) is null || (item = G(li, "item") as D) is null) throw Bad($"line_items[{i}] is malformed");
            var price = G(item, "price");
            string? iid = null, title = null;
            if ((iid = G(item, "id") as string) is null || (title = G(item, "title") as string) is null || !IsInt(price) || Dbl(price) < 0) throw Bad($"line_items[{i}].item needs id, title and integer minor-unit price");
            var qty = G(li, "quantity");
            if (!JsX.SafeInt(qty) || Dbl(qty) < 1) throw Bad($"line_items[{i}].quantity must be a positive integer");
            lineItems.Add(new D { ["id"] = lid, ["item"] = new D { ["id"] = iid, ["title"] = title, ["price"] = price }, ["quantity"] = qty });
        }
        var totals = new L();
        for (int i = 0; i < tots.Count; i++)
        {
            D? t = null;
            string? tt = null;
            if ((t = tots[i] as D) is null || (tt = G(t, "type") as string) is null || !JsX.SafeInt(G(t, "amount")) || IntentJs.IsNegZero(Dbl(G(t, "amount")))) throw Bad($"totals[{i}] is malformed");
            totals.Add(new D { ["type"] = tt, ["amount"] = G(t, "amount") });
        }
        var r = new D { ["id"] = id, ["currency"] = currency, ["line_items"] = lineItems, ["totals"] = totals };
        if (!IsUndef(G(payload, "merchant")))
        {
            D? m = null;
            string? mid = null, mname = null;
            if ((m = G(payload, "merchant") as D) is null || (mid = G(m, "id") as string) is null || (mname = G(m, "name") as string) is null) throw Bad("merchant needs id and name");
            var mm = new D { ["id"] = mid, ["name"] = mname };
            if (G(m, "website") is string w) mm["website"] = w;
            r["merchant"] = mm;
        }
        return r;
    }

    /// <summary>The single <c>total</c> entry's amount, or null when there is not exactly one.</summary>
    public static object? CheckoutTotal(D checkout)
    {
        var t = ((L)G(checkout, "totals")!).Where(x => JsX.StrictEq(G(x, "type"), "total")).ToList();
        return t.Count == 1 ? G(t[0], "amount") : null;
    }

    static List<string> LineItemViolations(L cart, L reqs)
    {
        var qty = new Dictionary<string, double>(StringComparer.Ordinal);
        var skus = new List<string>();
        foreach (var li in cart)
        {
            var id = (string)G(G(li, "item"), "id")!;
            if (!qty.ContainsKey(id)) { skus.Add(id); qty[id] = 0; }
            qty[id] += Dbl(G(li, "quantity"));
        }
        const int S0 = 0;
        int T = 1 + skus.Count + reqs.Count;
        var cap = Enumerable.Range(0, T + 1).Select(_ => new Dictionary<int, double>()).ToArray();
        void Add(int u, int v, double c)
        {
            cap[u][v] = cap[u].GetValueOrDefault(v) + c;
            if (!cap[v].ContainsKey(u)) cap[v][u] = 0;
        }
        double INF = 9007199254740991.0;
        for (int i = 0; i < skus.Count; i++) Add(S0, 1 + i, qty[skus[i]]);
        for (int j = 0; j < reqs.Count; j++)
        {
            Add(1 + skus.Count + j, T, Dbl(G(reqs[j], "quantity")));
            var ok = ((L)G(reqs[j], "acceptable_items")!).Select(a => G(a, "id")).ToList();
            for (int i = 0; i < skus.Count; i++) if (ok.Any(x => JsX.StrictEq(x, skus[i]))) Add(1 + i, 1 + skus.Count + j, INF);
        }
        double flow = 0;
        for (; ; )
        {
            var parent = new Dictionary<int, int> { [S0] = S0 };
            var queue = new List<int> { S0 };
            for (int h = 0; h < queue.Count && !parent.ContainsKey(T); h++)
            {
                int u = queue[h];
                foreach (var (v, c) in cap[u]) if (c > 0 && !parent.ContainsKey(v)) { parent[v] = u; queue.Add(v); }
            }
            if (!parent.ContainsKey(T)) break;
            double push = INF;
            for (int v = T; v != S0; v = parent[v]) push = Math.Min(push, cap[parent[v]][v]);
            for (int v = T; v != S0; v = parent[v])
            {
                int u = parent[v];
                cap[u][v] -= push;
                cap[v][u] += push;
            }
            flow += push;
        }
        double required = reqs.Sum(r => Dbl(G(r, "quantity")));
        double carted = qty.Values.Sum();
        if (flow == required && flow == carted) return new();
        return new() { $"line items do not satisfy the constraint: assigned {JsX.JsNumString(flow)} of {JsX.JsNumString(required)} required and {JsX.JsNumString(carted)} carted units" };
    }

    static List<string> EvaluateCheckout(object? c, D checkout)
    {
        var type = G(c, "type");
        if (JsX.StrictEq(type, "checkout.allowed_merchants"))
        {
            var m = G(checkout, "merchant");
            if (!Truthy(m)) return new() { "missing merchant in the checkout" };
            return ((L)G(c, "allowed")!).Any(a => MerchantMatches(a, m)) ? new() : new() { $"merchant {S(G(m, "name"))} is not in the allowed list" };
        }
        if (!JsX.StrictEq(type, "checkout.line_items")) return new() { $"unknown constraint type {S(type)}" };
        var items = (L)G(checkout, "line_items")!;
        return items.Count == 0 ? new() { "empty cart does not satisfy a line_items constraint" } : LineItemViolations(items, (L)G(c, "items")!);
    }

    /// <summary>Violations of an open checkout mandate's constraints by a projected checkout. Empty = satisfied.</summary>
    public static List<string> CheckCheckoutConstraints(object? open, D checkout)
    {
        var cs = G(open, "constraints") as L ?? throw JsX.TypeError("open.constraints.flatMap is not a function");
        return cs.SelectMany(c => EvaluateCheckout(c, checkout)).ToList();
    }
}

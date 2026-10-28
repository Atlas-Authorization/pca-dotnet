// Session histories (Intent Layer v2 section 2.1; packages/pca/src/intent-history.ts): the host side of accumulators and monitors.
// The verifier receives the PRE-STATE of the action's group from its own store; these functions compute it from the session's
// event history (window, key, selection and counted statuses applied) and fold a monitor over it. They are pure: the store, its
// lock and the reservation are the host's. Numbers are read as JavaScript doubles, as the reference does.
using System.Globalization;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca;

public static class IntentHistory
{
    /// <summary>A reserved or committed event counts toward a cap (a reservation counts as soon as it is made).</summary>
    static bool IsCountedStatus(object? s) => s is "reserved" or "committed";

    static double F(object? o) => IntentJs.NumOf(o) ?? double.NaN;

    /// <summary>Does the counted event stamped <paramref name="ti"/> still count at <paramref name="t"/>? task: always; sliding(ms):
    /// (t-ms, t]; period(ms, t0): the period containing t; and every event stamped AFTER t (it has not left any window). A time that
    /// is not a safe integer is in no window (fail closed: the caller treats the store as corrupt).</summary>
    public static bool InWindow(D win, object? ti, object? t)
    {
        if (!IntentJs.IsInt(ti) || !IntentJs.IsInt(t)) return false;
        double fi = F(ti), ft = F(t);
        if (fi > ft) return true;
        switch (IntentJs.Get(win, "kind"))
        {
            case "task": return true;
            case "sliding": return fi > ft - F(IntentJs.Get(win, "ms"));
            case "period":
                double ms = F(IntentJs.Get(win, "ms")), t0 = F(IntentJs.Get(win, "t0"));
                return Math.Floor((fi - t0) / ms) == Math.Floor((ft - t0) / ms);
        }
        return false;
    }

    /// <summary>The canonical key of the grouping parameter, "•" when ungrouped, null when the parameter is missing or not a string /
    /// safe integer.</summary>
    public static string? AccKeyOf(D a, D? parameters)
    {
        if (IntentJs.Get(a, "key") is not string k) return "•";
        return parameters != null && parameters.TryGetValue(k.Substring("action.params.".Length), out var x) ? IntentAcc.DistinctKey(x) : null;
    }

    static D EmptyPre(string? agg) => agg switch
    {
        "sum" => new D { ["sum"] = 0L },
        "count" => new D { ["count"] = 0L },
        "max" => new D { ["max"] = 0L },
        _ => new D { ["values"] = new L() },
    };

    static bool SafeInt(double d) => double.IsFinite(d) && d == Math.Floor(d) && Math.Abs(d) <= IntentJs.MaxSafe;

    /// <summary>The pre-state of psi for a candidate action. Null is the reference's throw: a past event's value or time is unreadable
    /// (store corruption), the candidate's key is missing, or a sum leaves the safe-integer range.</summary>
    public static D? AccPreState(D a, L? history, D? candParams, object? candT, object? schema)
    {
        var key = AccKeyOf(a, candParams);
        if (key == null || !IntentJs.IsInt(candT)) return null;
        var win = IntentJs.Get(a, "win") as D ?? new D();
        double sum = 0, count = 0, mx = 0;
        var vals = new List<string>();
        foreach (var ev in history ?? new L())
        {
            var e = ev as D;
            bool counted = IsCountedStatus(IntentJs.Get(e, "status"));
            if (counted && !IntentJs.IsInt(IntentJs.Get(e, "t"))) return null;
            if (!counted || !InWindow(win, IntentJs.Get(e, "t"), candT)) continue;
            var verb = IntentJs.Get(e, "verb") as string ?? "";
            bool sel;
            try { sel = IntentAcc.AccSelects(a, verb, schema); } catch (Exception) { return null; }
            var parameters = IntentJs.Get(e, "params") as D;
            if (!sel) continue;
            if (AccKeyOf(a, parameters) != key) continue;
            IntentAcc.AccValue v;
            try { v = IntentAcc.AccValueOf(a, verb, parameters ?? new D(), schema); } catch (Exception) { return null; }
            if (v.Reason != null) return null;
            sum += v.Val; count++; mx = Math.Max(mx, v.Val);
            if (v.Key != null) vals.Add(v.Key);
        }
        switch (IntentJs.Get(a, "agg"))
        {
            case "sum": return SafeInt(sum) ? new D { ["sum"] = (long)sum } : null;
            case "count": return new D { ["count"] = (long)count };
            case "max": return new D { ["max"] = (long)mx };
        }
        return new D { ["values"] = new L(IntentJs.SortedUtf8(vals.Distinct(StringComparer.Ordinal)).Cast<object?>()) };
    }

    /// <summary>post_psi(xi, omega, t): the pre-state combined with omega when omega is selected, else the pre-state's value. Null: throws.</summary>
    public static long? AccPost(D a, L? history, string verb, D parameters, object? t, object? schema)
    {
        var agg = IntentJs.Get(a, "agg") as string;
        D? pre = null;
        if (IntentJs.Get(a, "key") is string && AccKeyOf(a, parameters) == null) pre = EmptyPre(agg);
        pre ??= AccPreState(a, history, parameters, t, schema);
        if (pre == null) return null;
        bool sel;
        try { sel = IntentAcc.AccSelects(a, verb, schema); } catch (Exception) { return null; }
        if (!sel) return IntentAcc.PreValue(agg, pre);
        IntentAcc.AccValue v;
        try { v = IntentAcc.AccValueOf(a, verb, parameters, schema); } catch (Exception) { return null; }
        return v.Reason != null ? null : IntentAcc.CombineAcc(agg, pre, v);
    }

    /// <summary>The start state of a monitor.</summary>
    public static string MonitorInitialState(D m) => IntentJs.Get(m, "kind") switch
    {
        "requires_prior" or "precedes" => "unmet",
        "never" => "clean",
        "always" => "ok",
        _ => "idle",
    };

    /// <summary>One monitor step on one event; statuses that do not count leave the state unchanged.</summary>
    public static string MonitorStep(D m, string q, D e)
    {
        bool counts = (IntentJs.Get(m, "status") is "committed") ? (IntentJs.Get(e, "status") is "committed") : IsCountedStatus(IntentJs.Get(e, "status"));
        if (!counts) return q;
        var ctx = new D { ["action"] = new D { ["verb"] = IntentJs.Get(e, "verb"), ["resource"] = IntentJs.Get(e, "resource"), ["params"] = IntentJs.Get(e, "params") } };
        bool Match(object? p) => Predicates.PredicateMatches(p, ctx);
        switch (IntentJs.Get(m, "kind"))
        {
            case "requires_prior":
            case "precedes":
                return q == "met" || Match(IntentJs.Get(m, "p")) ? "met" : "unmet";
            case "never":
                return q == "seen" || Match(IntentJs.Get(m, "p")) ? "seen" : "clean";
            case "always":
                return q == "broken" || !Match(IntentJs.Get(m, "p")) ? "broken" : "ok";
            case "responds_within":
                {
                    if (q == "missed") return "missed";
                    double w = F(IntentJs.Get(m, "within"));
                    double pending = 0; bool has = false;
                    if (q.StartsWith("pending:", StringComparison.Ordinal))
                    {
                        pending = double.TryParse(q.AsSpan("pending:".Length), NumberStyles.Float, CultureInfo.InvariantCulture, out var pv) ? pv : double.NaN;
                        has = true;
                    }
                    if (has)
                    {
                        if (Match(IntentJs.Get(m, "q"))) has = false;
                        else if (pending - 1 <= 0) return "missed";
                        else pending--;
                    }
                    if (Match(IntentJs.Get(m, "p")))
                    {
                        if (!has) { pending = w; has = true; }
                        else pending = Math.Min(pending, w);
                    }
                    return !has ? "idle" : "pending:" + IntentJs.Shortest(pending);
                }
        }
        return q;
    }

    /// <summary>q(xi): the fold of the monitor over the history (admission order, current statuses).</summary>
    public static string MonitorState(D m, L? history)
    {
        var q = MonitorInitialState(m);
        foreach (var ev in history ?? new L()) q = MonitorStep(m, q, ev as D ?? new D());
        return q;
    }
}

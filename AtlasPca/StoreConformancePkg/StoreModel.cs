// The sequential specification both store operations share, the verdict-preserving reductions of the checker, and the budgeted linearizability search.
//
// ONE MODEL FOR BOTH OPERATIONS. Each operation carries a threshold Lo and a write value W:
//  - consumeOnce(key, retainUntil, now): lo = now, w = retainUntil (the record is live while its horizon is >= now);
//  - advance(stream, counter):           lo = w = counter.
// The register s starts at -Infinity (no record / no counter). A TRUE answer is legal iff s < lo, and then s := max(s, w); a FALSE answer is legal iff
// s >= lo and leaves s unchanged. An UNKNOWN outcome (error, timeout, killed client) may or may not have taken effect: from s < lo it may leave s or move it
// to max(s, w). The register never decreases, which is what the reductions rely on.
using System.Globalization;
using System.Numerics;
using AtlasPca.InteropJs;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.StoreConformancePkg;

/// <summary>One recorded store operation. Instances are compared by reference (the checker's sound deletion removes one operation, not an equal one).</summary>
public sealed class HistoryOp
{
    /// <summary>The client (connection / process) that issued it. Informational.</summary>
    public string Client { get; set; } = "";
    /// <summary><c>consume</c> or <c>advance</c>.</summary>
    public string Kind { get; set; } = "consume";
    public string Key { get; set; } = "";
    /// <summary>consume: nowMs. advance: the counter.</summary>
    public double Lo { get; set; }
    /// <summary>consume: retainUntilMs. advance: the counter.</summary>
    public double W { get; set; }
    /// <summary>Invocation time (ms, any shared clock). Recorded BEFORE the request leaves the client.</summary>
    public double Call { get; set; }
    /// <summary>Response time; Infinity when the outcome is unknown (the operation may still take effect at any later time).</summary>
    public double Ret { get; set; } = double.PositiveInfinity;
    /// <summary><c>true</c>, <c>false</c> or <c>unknown</c>.</summary>
    public string Res { get; set; } = "unknown";

    /// <summary>A number as the oracle writes it: a non-finite one is <c>{"$num": "Infinity" | "-Infinity" | "NaN"}</c>.</summary>
    public static object? EncodeNumber(double d) =>
        double.IsFinite(d) ? d : new D { ["$num"] = double.IsNaN(d) ? "NaN" : d > 0 ? "Infinity" : "-Infinity" };

    /// <summary>The operation as a plain object. With <paramref name="nonFiniteAsNull"/> a non-finite number is null (JSON.stringify's spelling), else <c>{"$num"}</c>.</summary>
    public D ToJson(bool nonFiniteAsNull = false)
    {
        object? N(double d) => nonFiniteAsNull ? (double.IsFinite(d) ? (object?)d : null) : EncodeNumber(d);
        return new D { ["client"] = Client, ["kind"] = Kind, ["key"] = Key, ["lo"] = N(Lo), ["w"] = N(W), ["call"] = N(Call), ["ret"] = N(Ret), ["res"] = Res };
    }

    /// <summary>A number from a parsed value: a JSON number, or <c>{"$num": "Infinity" | "-Infinity" | "NaN"}</c>.</summary>
    public static double DecodeNumber(object? v) => v switch
    {
        D m when m.Count == 1 && m.TryGetValue("$num", out var s) && s is string t => t == "Infinity" ? double.PositiveInfinity : t == "-Infinity" ? double.NegativeInfinity : double.NaN,
        _ => JsX.NumOf(v) ?? double.NaN,
    };

    public static HistoryOp FromJson(object? o)
    {
        var m = (D)o!;
        return new HistoryOp
        {
            Client = (string)m["client"]!, Kind = (string)m["kind"]!, Key = (string)m["key"]!, Lo = DecodeNumber(m["lo"]), W = DecodeNumber(m["w"]),
            Call = DecodeNumber(m["call"]), Ret = DecodeNumber(m["ret"]), Res = (string)m["res"]!,
        };
    }
}

public static class RegisterModel
{
    /// <summary>The register's successor states after <paramref name="op"/> from <paramref name="s"/> (empty: the answer is impossible from <paramref name="s"/>).</summary>
    public static List<double> Step(double s, HistoryOp op)
    {
        bool fresh = s < op.Lo;
        if (op.Res == "true") return fresh ? new List<double> { Math.Max(s, op.W) } : new List<double>();
        if (op.Res == "false") return fresh ? new List<double>() : new List<double> { s };
        return fresh ? new List<double> { s, Math.Max(s, op.W) } : new List<double> { s };
    }

    static bool DefiniteTrue(HistoryOp o) => o.Res == "true";

    /// <summary>Two definite TRUE answers whose [lo, w] intervals overlap can never both linearize. Returns such a pair (the minimal counterexample), or null.</summary>
    public static (HistoryOp, HistoryOp)? OverlappingTrues(IEnumerable<HistoryOp> ops)
    {
        // sorted by lo (stable), the intervals are pairwise disjoint iff each starts after the previous one ends, so comparing neighbours finds an overlap if there is one
        var ts = ops.Where(DefiniteTrue).OrderBy(o => o.Lo).ToList();
        for (int i = 1; i < ts.Count; i++) if (ts[i - 1].W >= ts[i].Lo) return (ts[i - 1], ts[i]);
        return null;
    }

    /// <summary>Drop every definite FALSE that a definite TRUE explains: a TRUE with <c>w &gt;= lo</c> that RETURNED before the FALSE was invoked.</summary>
    public static List<HistoryOp> Prune(IReadOnlyList<HistoryOp> ops)
    {
        var ts = ops.Where(DefiniteTrue).OrderBy(o => o.Ret).ToList();
        var pm = new List<double>(); // prefix maximum of w over the TRUEs in return order
        foreach (var t in ts) pm.Add(Math.Max(t.W, pm.Count > 0 ? pm[^1] : double.NegativeInfinity));
        return ops.Where(o =>
        {
            if (o.Res != "false") return true;
            int n = 0; // number of TRUEs that returned strictly before o.Call
            while (n < ts.Count && ts[n].Ret < o.Call) n++;
            return !(n > 0 && pm[n - 1] >= o.Lo);
        }).ToList();
    }

    /// <summary>EXACT decision for a history with no unknown operation, in O(n log n) (null when one is unknown).</summary>
    public static bool? FastCheck(IReadOnlyList<HistoryOp> ops)
    {
        if (ops.Any(o => o.Res == "unknown")) return null;
        var ts = ops.Where(DefiniteTrue).OrderBy(o => o.Lo).ToList();
        var t = new List<double>();
        double prev = double.NegativeInfinity;
        for (int i = 0; i < ts.Count; i++)
        {
            var o = ts[i];
            if (i > 0 && ts[i - 1].W >= o.Lo) return false;
            double ti = Math.Max(o.Call, prev);
            if (ti > o.Ret) return false;
            t.Add(ti);
            prev = ti;
        }
        foreach (var f in ops)
        {
            if (f.Res != "false") continue;
            int j = ts.FindIndex(x => x.W >= f.Lo);
            if (j < 0 || t[j] > f.Ret) return false;
        }
        return true;
    }
}

/// <summary>Linearizability search (Wing-Gong / Lowe style) for ONE key's history against the register model. Depth-first over "which pending operation linearizes
/// next", memoized on (set of linearized operations, register value). BUDGETED: a key that exceeds the budget is UNRESOLVED, never a pass.</summary>
public static class LinearizabilitySearch
{
    /// <summary>Default number of distinct search states explored per key before giving up (UNRESOLVED).</summary>
    public const double DefaultBudget = 200_000;

    /// <summary><c>ok</c>, <c>violation</c> or <c>unresolved</c>.</summary>
    public static string Search(IReadOnlyList<HistoryOp> ops, double budget = DefaultBudget)
    {
        var order = ops.OrderBy(o => o.Call).ToList();
        int n = order.Count;
        var bits = Enumerable.Range(0, n).Select(i => BigInteger.One << i).ToArray();
        var all = (BigInteger.One << n) - 1;
        var seen = new HashSet<(BigInteger, double)>();
        var stack = new Stack<(BigInteger Done, double S)>();
        stack.Push((BigInteger.Zero, double.NegativeInfinity));
        while (stack.Count > 0)
        {
            var (done, s) = stack.Pop();
            if (done == all) return "ok";
            if (seen.Contains((done, s))) continue;
            if (seen.Count >= budget) return "unresolved";
            seen.Add((done, s));
            double minRet = double.PositiveInfinity;
            for (int i = 0; i < n; i++) if ((done & bits[i]).IsZero) minRet = Math.Min(minRet, order[i].Ret);
            // sorted by invocation: once one starts after the earliest pending return, all later ones do too
            for (int i = 0; i < n && order[i].Call <= minRet; i++)
            {
                if (!(done & bits[i]).IsZero) continue;
                foreach (var s2 in RegisterModel.Step(s, order[i])) stack.Push((done | bits[i], s2));
            }
        }
        return "violation";
    }
}

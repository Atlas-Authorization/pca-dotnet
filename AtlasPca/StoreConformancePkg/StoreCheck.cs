// Per-key linearizability check of a recorded history (P-compositionality: a history is linearizable iff every key's sub-history is, because keys are
// independent registers), with a minimal counterexample per violating key.
//
// Per key: (1) two overlapping definite TRUEs are an immediate violation (the pair is the counterexample); (2) explained FALSEs are pruned
// (verdict-preserving); (3) a key with no unknown outcome is decided exactly; (4) otherwise the budgeted search decides, and a key over budget is
// UNRESOLVED (never a pass).
using System.Globalization;
using AtlasPca.Js;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.StoreConformancePkg;

public sealed class CheckOptions
{
    /// <summary>Search states per key before the key is UNRESOLVED (default 200,000).</summary>
    public double? Budget { get; set; }
    /// <summary>Shrink each violating key's history to a 1-minimal counterexample (default true).</summary>
    public bool? Minimize { get; set; }
    /// <summary>Keys with more operations than this (after pruning) are reported without shrinking (default 200).</summary>
    public double? MinimizeLimit { get; set; }
}

public sealed class KeyResult
{
    public string Key { get; set; } = "";
    public string Kind { get; set; } = "";
    /// <summary>Operations recorded for the key.</summary>
    public int Ops { get; set; }
    /// <summary>How many remained after pruning.</summary>
    public int Searched { get; set; }
    /// <summary><c>ok</c>, <c>violation</c> or <c>unresolved</c>.</summary>
    public string Verdict { get; set; } = "";
    /// <summary><c>overlap</c>, <c>exact</c> or <c>search</c>.</summary>
    public string Method { get; set; } = "";
    /// <summary>For a violation: a history that is itself non-linearizable; 1-minimal unless <see cref="Minimized"/> is false.</summary>
    public List<HistoryOp>? Counterexample { get; set; }
    public bool? Minimized { get; set; }

    public D ToJson(bool nonFiniteAsNull = false)
    {
        var o = new D { ["key"] = Key, ["kind"] = Kind, ["ops"] = (long)Ops, ["searched"] = (long)Searched, ["verdict"] = Verdict, ["method"] = Method };
        if (Counterexample != null) o["counterexample"] = Counterexample.Select(x => (object?)x.ToJson(nonFiniteAsNull)).ToList();
        if (Minimized != null) o["minimized"] = Minimized.Value;
        return o;
    }

    public static KeyResult FromJson(object? v)
    {
        var m = (D)v!;
        return new KeyResult
        {
            Key = (string)m["key"]!, Kind = (string)m["kind"]!, Ops = (int)HistoryOp.DecodeNumber(m["ops"]), Searched = (int)HistoryOp.DecodeNumber(m["searched"]),
            Verdict = (string)m["verdict"]!, Method = (string)m["method"]!,
            Counterexample = m.GetValueOrDefault("counterexample") is L l ? l.Select(HistoryOp.FromJson).ToList() : null,
            Minimized = m.GetValueOrDefault("minimized") as bool?,
        };
    }
}

public sealed class HistoryCheck
{
    public int Ops { get; set; }
    public int Keys { get; set; }
    public bool Ok { get; set; }
    /// <summary>Counts by outcome over the whole history.</summary>
    public int OutcomesTrue { get; set; }
    public int OutcomesFalse { get; set; }
    public int OutcomesUnknown { get; set; }
    public List<KeyResult> Violations { get; set; } = new();
    public List<KeyResult> Unresolved { get; set; } = new();

    public D ToJson() => new()
    {
        ["ops"] = (long)Ops, ["keys"] = (long)Keys, ["ok"] = Ok,
        ["outcomes"] = new D { ["true"] = (long)OutcomesTrue, ["false"] = (long)OutcomesFalse, ["unknown"] = (long)OutcomesUnknown },
        ["violations"] = Violations.Select(v => (object?)v.ToJson()).ToList(),
        ["unresolved"] = Unresolved.Select(v => (object?)v.ToJson()).ToList(),
    };
}

public static class HistoryChecker
{
    /// <summary>Decide one key's history (all operations share kind and key).</summary>
    public static (string Verdict, string Method, List<HistoryOp> Kept) DecideKey(IReadOnlyList<HistoryOp> ops, double budget = LinearizabilitySearch.DefaultBudget)
    {
        if (RegisterModel.OverlappingTrues(ops) != null) return ("violation", "overlap", new List<HistoryOp>(ops));
        var kept = RegisterModel.Prune(ops);
        var exact = RegisterModel.FastCheck(kept);
        if (exact != null) return (exact.Value ? "ok" : "violation", "exact", kept);
        return (LinearizabilitySearch.Search(kept, budget), "search", kept);
    }

    /// <summary>The SOUND deletion step for <paramref name="op"/> (identified by reference): a deletion under which a linearizable history stays linearizable.
    /// Deleting a FALSE never helps it; deleting a writer (TRUE or unknown) lowers the register, which can only break the FALSEs it may have explained (<c>lo &lt;= w</c>), so those go with it.</summary>
    public static List<HistoryOp> Deletion(IReadOnlyList<HistoryOp> ops, HistoryOp op)
    {
        if (op.Res == "false") return ops.Where(o => !ReferenceEquals(o, op)).ToList();
        return ops.Where(o => !ReferenceEquals(o, op) && !(o.Res == "false" && o.Lo <= op.W)).ToList();
    }

    /// <summary>Greedy sound deletion to a 1-minimal violating history (no single deletion step keeps it violating).</summary>
    public static List<HistoryOp> Minimize(IReadOnlyList<HistoryOp> ops, double budget = LinearizabilitySearch.DefaultBudget)
    {
        var cur = new List<HistoryOp>(ops);
        for (bool changed = true; changed;)
        {
            changed = false;
            foreach (var op in cur)
            {
                var next = Deletion(cur, op);
                if (DecideKey(next, budget).Verdict == "violation")
                {
                    cur = next;
                    changed = true;
                    break;
                }
            }
        }
        return cur;
    }

    public static KeyResult CheckKey(IReadOnlyList<HistoryOp> ops, CheckOptions? opts = null)
    {
        opts ??= new CheckOptions();
        double budget = opts.Budget ?? LinearizabilitySearch.DefaultBudget;
        var first = ops[0];
        var (verdict, method, kept) = DecideKey(ops, budget);
        var r = new KeyResult { Key = first.Key, Kind = first.Kind, Ops = ops.Count, Searched = kept.Count, Verdict = verdict, Method = method };
        if (verdict != "violation") return r;
        var pair = RegisterModel.OverlappingTrues(ops);
        if (pair != null)
        {
            r.Counterexample = new[] { pair.Value.Item1, pair.Value.Item2 }.OrderBy(o => o.Call).ToList();
            r.Minimized = true;
        }
        else if (opts.Minimize != false && kept.Count <= (opts.MinimizeLimit ?? 200))
        {
            r.Counterexample = Minimize(kept, budget);
            r.Minimized = true;
        }
        else
        {
            r.Counterexample = kept;
            r.Minimized = false;
        }
        return r;
    }

    /// <summary>Split a history by (kind, key) and check every key.</summary>
    public static HistoryCheck CheckHistory(IReadOnlyList<HistoryOp> ops, CheckOptions? opts = null)
    {
        var byKey = new Dictionary<string, List<HistoryOp>>(StringComparer.Ordinal);
        var order = new List<List<HistoryOp>>();
        var h = new HistoryCheck { Ops = ops.Count };
        foreach (var o in ops)
        {
            if (o.Res == "true") h.OutcomesTrue++;
            else if (o.Res == "false") h.OutcomesFalse++;
            else h.OutcomesUnknown++;
            var id = o.Kind + "\0" + o.Key;
            if (!byKey.TryGetValue(id, out var list)) { byKey[id] = list = new List<HistoryOp>(); order.Add(list); }
            list.Add(o);
        }
        foreach (var list in order)
        {
            var r = CheckKey(list, opts);
            if (r.Verdict == "violation") h.Violations.Add(r);
            else if (r.Verdict == "unresolved") h.Unresolved.Add(r);
        }
        h.Keys = byKey.Count;
        h.Ok = h.Violations.Count == 0 && h.Unresolved.Count == 0;
        return h;
    }

    static string FmtT(double t, double bas)
    {
        if (double.IsPositiveInfinity(t)) return "open";
        var d = t - bas;
        if (d == 0) d = 0; // -0 prints as 0
        return "+" + d.ToString("F3", CultureInfo.InvariantCulture) + "ms";
    }

    /// <summary>One line per operation, times relative to the first invocation.</summary>
    public static List<string> FormatOps(IReadOnlyList<HistoryOp> ops)
    {
        double bas = ops.Count == 0 ? double.PositiveInfinity : ops.Min(o => o.Call);
        return ops.OrderBy(o => o.Call).Select(o =>
        {
            var what = o.Kind == "consume" ? $"consumeOnce(now={JsJson.NumberToString(o.Lo)}, retainUntil={JsJson.NumberToString(o.W)})" : $"advance({JsJson.NumberToString(o.Lo)})";
            return $"{o.Client}: {what} [{FmtT(o.Call, bas)} .. {FmtT(o.Ret, bas)}] -> {(o.Res == "true" ? "TRUE" : o.Res == "false" ? "false" : "unknown")}";
        }).ToList();
    }
}

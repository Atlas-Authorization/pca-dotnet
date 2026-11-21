// History recording: rebuild the operations from recorder lines, and the deterministic workload PRNG.
using AtlasPca.InteropJs;
using AtlasPca.Js;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.StoreConformancePkg;

public static class HistoryRecorder
{
    /// <summary>Wall-clock milliseconds since the epoch with sub-millisecond resolution; comparable across processes on one host.</summary>
    public static double Clock() => (DateTime.UtcNow.Ticks - DateTime.UnixEpoch.Ticks) / 10_000.0;

    static object? At(L l, int i) => i < l.Count ? l[i] : JsX.Undef;

    /// <summary>Rebuild the operations from recorder lines (any number of files concatenated). An invocation without a response is pending (unknown, open-ended); an
    /// <c>unknown</c> response stays open-ended too. Lines that do not parse are counted as torn.
    /// shortcut: an invocation whose kind is not a string keeps its text form (the reference keeps the raw value); upgrade if a recorder ever writes one.</summary>
    public static (List<HistoryOp> Ops, int Torn, int Pending) ParseHistory(string text)
    {
        var open = new Dictionary<string, HistoryOp>(StringComparer.Ordinal);
        var ops = new List<HistoryOp>();
        int torn = 0;
        foreach (var line in text.Split('\n'))
        {
            if (line.Length == 0) continue;
            object? parsed;
            try { parsed = Pca.ParseJson(line); }
            catch (Exception) { torn++; continue; }
            if (parsed is not L e) { torn++; continue; }
            var id = JsX.Str(At(e, 1)) + "/" + JsX.Str(At(e, 2));
            var tag = At(e, 0) as string;
            if (tag == "i" && e.Count == 9)
            {
                var op = new HistoryOp
                {
                    Client = JsX.Str(e[4]), Kind = JsX.Str(e[5]), Key = JsX.Str(e[6]), Lo = JsJson.ToJsNumber(e[7]), W = JsJson.ToJsNumber(e[8]), Call = JsJson.ToJsNumber(e[3]),
                    Ret = double.PositiveInfinity, Res = "unknown",
                };
                open[id] = op;
                ops.Add(op);
            }
            else if (tag == "r" && e.Count == 5 && open.TryGetValue(id, out var o))
            {
                open.Remove(id);
                if (!(e[4] is string u && u == "unknown"))
                {
                    o.Ret = JsJson.ToJsNumber(e[3]);
                    o.Res = e[4] is string t && t == "true" ? "true" : "false";
                }
            }
            else torn++;
        }
        return (ops, torn, open.Count);
    }
}

public static class WorkloadRandom
{
    static uint ToUint32(double x)
    {
        if (!double.IsFinite(x)) return 0;
        var m = Math.Truncate(x) % 4294967296.0;
        if (m < 0) m += 4294967296.0;
        return (uint)m;
    }

    /// <summary>Deterministic PRNG (mulberry32): the returned function maps n to an integer in [0, n).</summary>
    public static Func<double, double> Prng(double seed)
    {
        uint a = ToUint32(seed);
        return n =>
        {
            unchecked
            {
                a += 0x6d2b79f5u;
                uint t = a;
                t = (t ^ (t >> 15)) * (t | 1);
                t ^= t + (t ^ (t >> 7)) * (t | 61);
                return Math.Floor(((t ^ (t >> 14)) / 4294967296.0) * n);
            }
        };
    }
}

using AtlasPca.InteropJs;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Analyzer;

/// <summary>Static exposure of a workflow DAG: depth, width, path count, cost against budget, steps that can never run, and sinks fed by other steps.</summary>
public static class DagAnalysis
{
    const double PathCap = 1_000_000;

    static L Iter(object? x) => x as L ?? throw JsX.TypeError("value is not iterable");
    static string Id(object? s) => Jx.Prop(s, "id") is string i ? i : JsX.Str(Jx.Prop(s, "id"));
    static int LenOf(object? x) => x switch { L l => l.Count, string s => s.Length, _ => throw JsX.TypeError("length of a non-list") };

    /// <summary>dagExposure: throws on a duplicate step id, a cycle or an unknown step (the reference RangeError).</summary>
    public static D DagExposure(object? body)
    {
        var steps = Iter(Jx.Prop(body, "steps"));
        var byId = new Dictionary<string, object?>(StringComparer.Ordinal);
        foreach (var s in steps) byId[Id(s)] = s;
        if (byId.Count != steps.Count) throw new ArgumentException("dagExposure: duplicate step id");
        var level = new Dictionary<string, int>(StringComparer.Ordinal);
        var anc = new Dictionary<string, HashSet<string>>(StringComparer.Ordinal);
        var visiting = new HashSet<string>(StringComparer.Ordinal);
        void Visit(string id)
        {
            if (level.ContainsKey(id)) return;
            if (visiting.Contains(id)) throw new ArgumentException("dagExposure: cycle");
            visiting.Add(id);
            if (!byId.TryGetValue(id, out var s)) throw new ArgumentException($"dagExposure: unknown step {id}");
            var a = new HashSet<string>(StringComparer.Ordinal);
            var l = 0;
            foreach (var dO in Iter(Jx.Prop(s, "deps")))
            {
                var d = JsX.Str(dO);
                Visit(d);
                a.Add(d);
                foreach (var x in anc[d]) a.Add(x);
                l = Math.Max(l, level[d] + 1);
            }
            visiting.Remove(id);
            anc[id] = a; level[id] = l;
        }
        foreach (var s in steps) Visit(Id(s));
        var depth = (level.Count == 0 ? 0 : level.Values.Max()) + 1;
        var widths = new Dictionary<int, int>();
        foreach (var l in level.Values) widths[l] = widths.GetValueOrDefault(l) + 1;
        double levelWidth = widths.Count == 0 ? double.NegativeInfinity : widths.Values.Max();

        var children = new Dictionary<string, List<string>>(StringComparer.Ordinal);
        foreach (var s in steps) children[Id(s)] = new List<string>();
        foreach (var s in steps) foreach (var d in Iter(Jx.Prop(s, "deps"))) children[JsX.Str(d)].Add(Id(s));
        var memo = new Dictionary<string, double>(StringComparer.Ordinal);
        var capped = false;
        double ToLeaves(string id)
        {
            if (memo.TryGetValue(id, out var m)) return m;
            var kids = children[id];
            double n = kids.Count == 0 ? 1 : 0;
            foreach (var k in kids) n += ToLeaves(k);
            if (n > PathCap) { n = PathCap; capped = true; }
            memo[id] = n;
            return n;
        }
        double paths = 0;
        foreach (var s in steps) if (LenOf(Jx.Prop(s, "deps")) == 0) paths = Math.Min(PathCap, paths + ToLeaves(Id(s)));

        var budget = Jx.Prop(body, "budget");
        var caps = Jx.Prop(budget, "caps");
        if (caps == null || Jx.IsUndef(caps)) throw JsX.TypeError("Cannot convert undefined or null to object");
        var cost = new D();
        foreach (var name in JsX.Keys(caps))
        {
            var cap = Jx.ToNumber(JsX.ValueOf(caps, name));
            double total = 0;
            foreach (var s in steps) { var cv = Jx.Prop(Jx.Prop(s, "cost"), name); total += Jx.IsUndef(cv) || cv == null ? 0 : Jx.ToNumber(cv); }
            cost[name] = new D { ["cap"] = Jx.NumOut(cap), ["total"] = Jx.NumOut(total), ["maxSpend"] = Jx.NumOut(Math.Min(cap, total)) };
        }
        var maxSteps = Jx.ToNumber(Jx.Prop(budget, "max_steps"));
        var neverRunnable = new L();
        foreach (var s in steps)
        {
            var sc = Jx.Prop(s, "cost");
            var over = false;
            foreach (var n in JsX.Keys(sc))
            {
                var capv = Jx.Prop(caps, n);
                var capn = Jx.IsUndef(capv) || capv == null ? 0 : Jx.ToNumber(capv);
                if (Jx.ToNumber(JsX.ValueOf(sc, n)) > capn) { over = true; break; }
            }
            if (over) neverRunnable.Add(new D { ["step"] = Id(s), ["reason"] = "cost_over_cap" });
            else if (anc[Id(s)].Count + 1 > maxSteps) neverRunnable.Add(new D { ["step"] = Id(s), ["reason"] = "needs_more_steps_than_budget" });
        }

        var edges = Iter(Jx.Prop(body, "edges"));
        var feeds = new Dictionary<string, HashSet<string>>(StringComparer.Ordinal);
        foreach (var s in steps) feeds[Id(s)] = new HashSet<string>(StringComparer.Ordinal);
        foreach (var e in edges)
        {
            var to = JsX.Str(Jx.Prop(Jx.Prop(e, "to"), "step"));
            if (!feeds.TryGetValue(to, out var set)) throw JsX.TypeError("Cannot read properties of undefined (reading 'add')");
            set.Add(JsX.Str(Jx.Prop(Jx.Prop(e, "from"), "step")));
        }
        HashSet<string> LineageOf(string id, HashSet<string> seen)
        {
            if (!feeds.TryGetValue(id, out var fs)) throw JsX.TypeError("undefined is not iterable");
            foreach (var f in fs.ToList()) if (!seen.Contains(f)) { seen.Add(f); LineageOf(f, seen); }
            return seen;
        }
        var sinks = new List<(string Step, bool Protected, int Lineage)>(); var sinkJ = new L();
        foreach (var s in steps)
        {
            var sink = Jx.Prop(s, "sink");
            if (sink == null) continue;
            var sid = Id(s);
            var incoming = edges.Where(e => JsX.Str(Jx.Prop(Jx.Prop(e, "to"), "step")) == sid).ToList();
            var lineage = LineageOf(sid, new HashSet<string>(StringComparer.Ordinal)).ToList();
            lineage.Sort(StringComparer.Ordinal);
            var prot = LenOf(Jx.Prop(s, "deny_labels")) > 0 || LenOf(Jx.Prop(s, "escalate_labels")) > 0 || incoming.Any(e => LenOf(Jx.Prop(e, "deny_labels")) > 0);
            sinks.Add((sid, prot, lineage.Count));
            sinkJ.Add(new D { ["step"] = sid, ["sink"] = sink, ["lineage"] = lineage.Cast<object?>().ToList(), ["protected"] = prot });
        }
        var unprotected = new L(sinks.Where(k => !k.Protected && k.Lineage > 0).Select(k => (object?)k.Step));
        var orderingOnly = new L();
        foreach (var s in steps)
            if (LenOf(Jx.Prop(s, "deps")) > 0 && !edges.Any(e => JsX.Str(Jx.Prop(Jx.Prop(e, "to"), "step")) == Id(s))) orderingOnly.Add(Id(s));
        var pipelinable = new L();
        for (int i = 0; i < edges.Count; i++) if (Jx.Prop(edges[i], "promise") != null) pipelinable.Add(Jx.N(i));
        return new D
        {
            ["steps"] = Jx.N(steps.Count), ["maxSteps"] = Jx.NumOut(Math.Min(steps.Count, maxSteps)), ["depth"] = Jx.N(depth), ["levelWidth"] = Jx.NumOut(levelWidth),
            ["paths"] = Jx.NumOut(paths), ["pathsCapped"] = capped, ["cost"] = cost, ["neverRunnable"] = neverRunnable, ["sinks"] = sinkJ,
            ["unprotectedSinks"] = unprotected, ["orderingOnly"] = orderingOnly, ["pipelinable"] = pipelinable,
        };
    }
}

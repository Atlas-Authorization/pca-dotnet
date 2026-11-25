using System.Globalization;
using AtlasPca.InteropJs;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Analyzer;

/// <summary>Minimal-change counterfactual search on a deny or escalate: "what is the smallest thing the agent can change to be allowed?",
/// as a typed patch ordered by cost: wait, move a parameter to the nearest admissible value, pick another allowed value or resource,
/// obtain a named fact, split the action (opt-in), and only then ask a human. The search PROPOSES; the real decision VERIFIES: every
/// candidate is re-run through the evaluator and only one that reaches the wanted decision is returned. A counterfactual teaches the
/// holder about the policy, so it is shown only to the authenticated holder, is rate-limited by a probe budget, and redacts critical values.</summary>
public static class Flip
{
    static double Rank(object? d) => d is string s ? (s == "deny" ? 0 : s == "escalate" ? 1 : s == "allow" ? 2 : double.NaN) : double.NaN;

    sealed class Cand
    {
        public D Repair = new(); public double Cost; public string Decision = ""; public object? Action;
        public D ToJson() => new() { ["repair"] = Repair, ["cost"] = Jx.N(Cost), ["decision"] = Decision, ["action"] = Action };
    }

    static D WithParam(object? action, D prms, string name, object? v)
    {
        var p = Jx.Copy(prms); p[name] = v;
        var a = JsX.Spread(action); a["params"] = p;
        return a;
    }

    /// <summary>The camelCase caveat context as the evaluator's context.</summary>
    static D CaveatCtx(object? c, object? now, bool overrideNow)
    {
        var m = new D();
        if (overrideNow) m["now"] = now; else PutIf(m, "now", c, "now");
        PutIf(m, "blast_radius", c, "blastRadius");
        PutIf(m, "reversibility_class", c, "reversibilityClass");
        PutIf(m, "delegation_depth", c, "delegationDepth");
        PutIf(m, "recent_action_times", c, "recentActionTimes");
        return m;
    }

    static void PutIf(D to, string k, object? from, string fk) { var v = Jx.Opt(from, fk); if (!Jx.IsUndef(v)) to[k] = v; }

    static bool CaveatsOkAt(PolicyModel model, object? ctx, object? now, bool overrideNow) => Caveats.EvaluateCaveats(model.Caveats, CaveatCtx(ctx, now, overrideNow)).Ok;

    static bool Meters(PolicyModel m)
    {
        var cs = new L(m.Caveats);
        foreach (var x in m.Meets) cs.AddRange(x.Caveats);
        return cs.Any(c => Jx.Prop(c, "type") is string t && (t == "rate" || t == "budget_alloc" || t == "max_blast_radius"));
    }

    static double? WaitTime(L caveats, object? ctx)
    {
        double? at = null;
        var now = Jx.ToNumber(Jx.Prop(ctx, "now"));
        foreach (var c in caveats)
        {
            var type = Jx.Prop(c, "type") as string;
            if (type == "not_before" && Jx.IsNum(Jx.Prop(c, "at")) && IntentJs.NumOf(Jx.Prop(c, "at"))!.Value > now) at = Math.Max(at ?? 0, IntentJs.NumOf(Jx.Prop(c, "at"))!.Value);
            if (type == "rate" && Jx.IsNum(Jx.Prop(c, "max")) && Jx.IsNum(Jx.Prop(c, "per_secs")))
            {
                var span = IntentJs.NumOf(Jx.Prop(c, "per_secs"))!.Value * 1000;
                var rt = Jx.Opt(ctx, "recentActionTimes");
                var recent = new List<double>();
                if (rt is L rl) foreach (var t in rl) { var tv = Jx.ToNumber(t); if (tv > now - span) recent.Add(tv); }
                recent = recent.OrderBy(x => x).ToList();
                var max = IntentJs.NumOf(Jx.Prop(c, "max"))!.Value;
                if (recent.Count >= max)
                {
                    var idx = recent.Count - max;
                    var v = idx >= 0 && idx == Math.Floor(idx) && idx < recent.Count ? recent[(int)idx] + span : double.NaN;
                    at = Math.Max(at ?? 0, v);
                }
            }
        }
        return at;
    }

    static void SetPath(D o, List<string> path, int from, object? v)
    {
        if (from >= path.Count) return;
        var k = path[from];
        if (from == path.Count - 1) o[k] = v;
        else
        {
            var inner = JsX.Spread(o.GetValueOrDefault(k));
            SetPath(inner, path, from + 1, v);
            o[k] = inner;
        }
    }

    static List<object?> Distinct(IEnumerable<object?> xs)
    {
        var o = new List<object?>();
        foreach (var x in xs) if (!o.Any(y => JsX.StrictEq(x, y))) o.Add(x);
        return o;
    }

    /// <summary>Array.prototype.slice(0, n) for a JavaScript number n.</summary>
    static List<T> SliceTo<T>(List<T> xs, double n)
    {
        var cut = double.IsNaN(n) ? 0 : Math.Truncate(n);
        int take = cut < 0 ? (int)Math.Max(xs.Count + cut, 0) : (int)Math.Min(cut, xs.Count);
        return xs.Take(take).ToList();
    }

    /// <summary>Search for the smallest verified change that gets <paramref name="action"/> to the wanted decision. Options: desired
    /// ("allow" | "escalate"), schema (verb shapes), holderAuthenticated (required), probe {limit, windowSecs, history, now}, changeable,
    /// caveatContext, allowSplit, redact ("none" | "critical" | "all"), maxCandidates.</summary>
    public static D MinimalFlip(object? policy, object? action, object? o)
    {
        if (action == null || Jx.IsUndef(action)) throw JsX.TypeError("cannot read properties of null (reading 'reversibilityClass')");
        var model = Enumerate.ToModel(policy);
        var cctx = Jx.Opt(o, "caveatContext");
        var hasCtx = !Jx.IsUndef(cctx);
        var caveatsOk = !hasCtx || CaveatsOkAt(model, cctx, null, false);
        var current = caveatsOk ? Enumerate.DecideAction(model, action) : "deny";
        var wantO = Jx.Opt(o, "desired");
        object? want = wantO == null || Jx.IsUndef(wantO) ? "allow" : wantO;
        var res = new D { ["current"] = current, ["repairs"] = new L(), ["repairExists"] = false };
        if (!Jx.Truthy(Jx.Opt(o, "holderAuthenticated"))) { res["refused"] = "counterfactuals are shown only to the authenticated holder"; return res; }
        var probe = Jx.Opt(o, "probe");
        if (Jx.Truthy(probe))
        {
            var recent = new L();
            var now = Jx.ToNumber(Jx.Prop(probe, "now"));
            if (Jx.Prop(probe, "history") is not L hist) throw JsX.TypeError("history.filter is not a function");
            foreach (var t in hist) if (Jx.ToNumber(t) > now - Jx.ToNumber(Jx.Prop(probe, "windowSecs")) * 1000) recent.Add(t);
            if (recent.Count >= Jx.ToNumber(Jx.Prop(probe, "limit")))
            {
                res["refused"] = "probe budget exhausted";
                res["probe"] = new D { ["history"] = recent };
                return res;
            }
            var h = new L(recent) { Jx.Prop(probe, "now") };
            res["probe"] = new D { ["history"] = h };
        }
        var policyDigest = Residual.PolicyDigestOf(model);
        if (Rank(current) >= Rank(want)) return res;

        object? shape = null;
        var schema = Jx.Opt(o, "schema");
        if (Jx.Truthy(schema))
        {
            if (schema is not L sl) throw JsX.TypeError("schema.find is not a function");
            foreach (var s in sl) if (JsX.StrictEq(Jx.Prop(s, "verb"), Jx.Prop(action, "verb"))) { shape = s; break; }
        }
        var cands = new List<Cand>();
        string? Reaches(object? a)
        {
            var d = Enumerate.DecideAction(model, a);
            return Rank(d) >= Rank(want) ? d : null;
        }
        object? Decl(string name) => shape == null ? Jx.Undef : Jx.Opt(Jx.Opt(shape, "params"), name);

        var pr = Enumerate.CollectProbes(new ProbeInputs { PredicateSets = new List<L> { Enumerate.ProbeSet(model) }, VaryReversibility = model.RevCap != null });
        var po = Jx.Prop(action, "params");
        var prms = po is D pd ? pd : new D();
        List<string> names;
        var ch = Jx.Opt(o, "changeable");
        if (ch != null && !Jx.IsUndef(ch)) names = (ch as L ?? throw JsX.TypeError("changeable is not iterable")).Select(x => (string)x!).ToList();
        else if (shape != null) names = JsX.Keys(Jx.Prop(shape, "params"));
        else names = JsX.Keys(prms);
        var actionResource = Jx.Prop(action, "resource");

        // 1. wait: a time caveat that is not open yet, or a rate window that will reset
        if (!caveatsOk && Jx.Truthy(cctx))
        {
            var at = WaitTime(model.Caveats, cctx);
            var d = Enumerate.DecideAction(model, action);
            if (at != null && CaveatsOkAt(model, cctx, Jx.N(at.Value), true) && Rank(d) >= Rank(want))
                cands.Add(new Cand { Repair = new D { ["kind"] = "wait_until", ["at"] = Jx.N(at.Value), ["reason"] = "a time or rate caveat opens then" }, Cost = 1, Decision = d, Action = action });
        }
        var finish = !caveatsOk; // nothing else helps while a caveat is closed

        // 2. one parameter changed: the nearest verified value, per parameter
        foreach (var name in finish ? new List<string>() : names)
        {
            var path = "action.params." + name;
            var decl = Decl(name);
            var cur = prms.TryGetValue(name, out var cv) ? cv : Jx.Undef;
            var field = pr.Fields.FirstOrDefault(f => f.Path == path);
            var pool = new List<object?>();
            if (field != null) pool.AddRange(field.Values.Where(v => !ReferenceEquals(v, Enumerate.Absent)));
            if (Jx.Opt(decl, "values") is L dvals) pool.AddRange(dvals);
            var dmin = Jx.Opt(decl, "min"); var dmax = Jx.Opt(decl, "max");
            if (!Jx.IsUndef(dmin)) pool.Add(dmin);
            if (!Jx.IsUndef(dmax)) pool.Add(dmax);
            var nums = pool.Where(v => Jx.Fin(v) != null).Select(v => Jx.Fin(v)!.Value).ToList();
            var T = Exposure.ThresholdsOf(model, path);
            var curNum = Jx.Fin(cur);
            var integer = (Jx.Opt(decl, "type") is string ty && ty == "integer") || (curNum is double cd && cd == Math.Floor(cd));
            var all = new List<double>(nums);
            if (integer) foreach (var t in T) { all.Add(t - 1); all.Add(t + 1); }
            var numeric = new List<double>();
            foreach (var v in all.Select(x => x == 0 ? 0.0 : x).Distinct())
                if ((Jx.IsUndef(dmin) || v >= Jx.ToNumber(dmin)) && (Jx.IsUndef(dmax) || v <= Jx.ToNumber(dmax))) numeric.Add(v);
            var curN = Jx.IsNum(cur) ? IntentJs.NumOf(cur)!.Value : 0;
            numeric.Sort((a, b) =>
            {
                var dd = Math.Abs(a - curN) - Math.Abs(b - curN);
                if (dd != 0 && !double.IsNaN(dd)) return dd < 0 ? -1 : 1;
                var e = a - b;
                return e < 0 ? -1 : e > 0 ? 1 : 0;
            });
            var strs = pool.OfType<string>().Where(s => !s.StartsWith('\u0000')).Distinct().ToList();
            var order = new List<object?>();
            foreach (var v in numeric) order.Add(Jx.N(v));
            order.AddRange(strs);
            foreach (var v in order)
            {
                if (JsX.StrictEq(v, cur)) continue;
                var a = WithParam(action, prms, name, v);
                var d = Reaches(a);
                if (d == null) continue;
                var extra = Jx.IsNum(v) && Jx.IsNum(cur) ? Math.Min(1, Math.Abs(IntentJs.NumOf(v)!.Value - IntentJs.NumOf(cur)!.Value) / (Math.Abs(IntentJs.NumOf(cur)!.Value) + 1)) : 0.5;
                var repair = new D { ["kind"] = "set_param", ["param"] = name };
                if (!Jx.IsUndef(cur)) repair["from"] = cur;
                repair["to"] = v;
                cands.Add(new Cand { Repair = repair, Cost = 2 + extra, Decision = d, Action = a });
                break; // the pool is ordered nearest first
            }
        }

        // 2b. when no single edit works, the cheapest PAIR of edits (a parameter and the resource, or two parameters)
        if (!finish && cands.Count == 0)
        {
            var dimValues = new List<List<object?>>();
            var dimCost = new List<double>();
            var make = new List<Func<object?, object?, object?>>();
            var step = new List<Func<object?, D>>();
            foreach (var name in names)
            {
                var n2 = name;
                var path = "action.params." + n2;
                var decl = Decl(n2);
                var field = pr.Fields.FirstOrDefault(f => f.Path == path);
                var src = new List<object?>();
                if (field != null) src.AddRange(field.Values);
                if (Jx.Opt(decl, "values") is L dvals) src.AddRange(dvals);
                var cur0 = prms.TryGetValue(n2, out var cv0) ? cv0 : Jx.Undef;
                var vals = src.Where(v => !ReferenceEquals(v, Enumerate.Absent) && (v is string vs ? !vs.StartsWith('\u0000') : Jx.IsNum(v)) && !JsX.StrictEq(v, cur0)).ToList();
                dimValues.Add(SliceTo(Distinct(vals), 6));
                dimCost.Add(2);
                make.Add((a, v) => WithParam(a, Jx.Opt(a, "params") is D ap ? ap : new D(), n2, v));
                step.Add(v =>
                {
                    var s = new D { ["kind"] = "set_param", ["param"] = n2 };
                    if (prms.TryGetValue(n2, out var f0)) s["from"] = f0;
                    s["to"] = v;
                    return s;
                });
            }
            dimValues.Add(SliceTo(pr.Resources.Where(x => !x.StartsWith('\u0000') && !JsX.StrictEq(x, actionResource)).Cast<object?>().ToList(), 6));
            dimCost.Add(3);
            make.Add((a, v) => { var c = JsX.Spread(a); c["resource"] = v; return c; });
            step.Add(v => { var s = new D { ["kind"] = "set_resource" }; Jx.Set(s, "from", actionResource); s["to"] = v; return s; });
            for (int i = 0; i < dimValues.Count; i++)
                for (int j = i + 1; j < dimValues.Count; j++)
                    foreach (var x in dimValues[i])
                        foreach (var y in dimValues[j])
                        {
                            var a = make[j](make[i](action, x), y);
                            var d = Reaches(a);
                            if (d != null)
                                cands.Add(new Cand { Repair = new D { ["kind"] = "combine", ["steps"] = new L { step[i](x), step[j](y) } }, Cost = dimCost[i] + dimCost[j], Decision = d, Action = a });
                        }
        }

        // 3. another allowed resource
        if (!finish)
            foreach (var r in pr.Resources)
            {
                if (r.StartsWith('\u0000') || JsX.StrictEq(r, actionResource)) continue;
                var a = JsX.Spread(action); a["resource"] = r;
                var d = Reaches(a);
                if (d != null)
                {
                    var rp = new D { ["kind"] = "set_resource" };
                    Jx.Set(rp, "from", actionResource); rp["to"] = r;
                    cands.Add(new Cand { Repair = rp, Cost = 3, Decision = d, Action = a });
                }
            }

        // 4. a named fact that is missing: a subject or env field the policy reads
        if (!finish)
            foreach (var f in pr.Fields)
            {
                if (!f.Path.StartsWith("subject.", StringComparison.Ordinal) && !f.Path.StartsWith("env.", StringComparison.Ordinal)) continue;
                var segs = f.Path.Split('.').ToList();
                var root = segs[0];
                foreach (var v in f.Values)
                {
                    if (ReferenceEquals(v, Enumerate.Absent)) continue;
                    var sub = JsX.Spread(Jx.Opt(action, root));
                    SetPath(sub, segs, 1, v);
                    var a = JsX.Spread(action); a[root] = sub;
                    var before = Reaches(action);
                    var d = Reaches(a);
                    if (d != null && before == null)
                    {
                        cands.Add(new Cand { Repair = new D { ["kind"] = "obtain_fact", ["path"] = f.Path, ["value"] = v }, Cost = 4, Decision = d, Action = a });
                        break;
                    }
                }
            }

        // 5. split (opt-in, and only when nothing meters the total)
        if (Jx.Opt(o, "allowSplit") is true && !Meters(model))
            foreach (var name in names)
            {
                var cur = prms.TryGetValue(name, out var cv) ? cv : Jx.Undef;
                if (!Jx.IsNum(cur)) continue;
                var flipped = cands.FirstOrDefault(c => c.Repair["kind"] is string k && k == "set_param" && c.Repair["param"] is string pn && pn == name && c.Repair.TryGetValue("to", out var tv) && Jx.IsNum(tv));
                if (flipped == null) continue;
                var part = IntentJs.NumOf(flipped.Repair["to"])!.Value;
                var cn = IntentJs.NumOf(cur)!.Value;
                if (part <= 0 || part >= cn) continue;
                var n = Math.Ceiling(cn / part);
                if (n > 8) continue;
                var parts = new L();
                var allOk = true;
                for (int i = 0; i < n; i++)
                {
                    var pv = Jx.N(i < n - 1 ? part : cn - part * (n - 1));
                    parts.Add(new D { [name] = pv });
                    var merged = Jx.Copy(prms); merged[name] = pv;
                    var a = JsX.Spread(action); a["params"] = merged;
                    if (Reaches(a) == null) allOk = false;
                }
                if (allOk) cands.Add(new Cand { Repair = new D { ["kind"] = "split", ["param"] = name, ["parts"] = parts }, Cost = 3 + n, Decision = (string)want!, Action = action });
            }

        var sorted = cands.OrderBy(c => c.Cost).ToList();
        var maxO = Jx.Opt(o, "maxCandidates");
        var top = SliceTo(sorted, maxO == null || Jx.IsUndef(maxO) ? 8 : Jx.ToNumber(maxO));
        res["repairExists"] = top.Count > 0;
        var redO = Jx.Opt(o, "redact");
        var redact = redO == null || Jx.IsUndef(redO) ? "critical" : redO as string ?? "\u0000";
        D Hide(Cand c)
        {
            if (redact == "none" || !(c.Repair["kind"] is string rk && rk == "set_param")) return c.ToJson();
            var sens = shape == null ? Jx.Undef : Jx.Opt(Jx.Opt(Jx.Opt(shape, "params"), (string)c.Repair["param"]!), "sensitivity");
            if (redact == "critical" && !(sens is string ss && ss == "critical")) return c.ToJson();
            res["redacted"] = true;
            return new D
            {
                ["repair"] = new D { ["kind"] = "set_param", ["param"] = c.Repair["param"], ["redacted"] = true },
                ["cost"] = Jx.N(c.Cost), ["decision"] = c.Decision, ["action"] = JsX.Spread(action),
            };
        }
        if (redact == "all") res["redacted"] = true;
        else res["repairs"] = top.Select(c => (object?)Hide(c)).ToList();
        var free = top.FirstOrDefault(c => c.Decision == "allow" && !(c.Repair["kind"] is string fk && fk == "split"));
        if (free != null && current == "escalate") res["humanFree"] = Hide(free);
        if (current == "escalate" || top.Count == 0)
        {
            var ask = new D();
            Jx.Set(ask, "verb", Jx.Prop(action, "verb"));
            Jx.Set(ask, "resource", actionResource);
            ask["params"] = Jx.Copy(prms);
            ask["kind"] = current == "escalate" ? "approval" : "access-request";
            ask["policyDigest"] = policyDigest;
            res["humanAsk"] = ask;
        }
        return res;
    }
}

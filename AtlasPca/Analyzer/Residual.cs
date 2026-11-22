using AtlasPca.InteropJs;
using AtlasPca.Js;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Analyzer;

/// <summary>Partial evaluation: what remains of a policy once some facts of the action are known, and what an agent may do per verb.</summary>
public static class Residual
{
    static object? G(object? o, string k) => o is D d && d.TryGetValue(k, out var v) ? v : Jx.Undef;
    static bool IsGroup(D c) => c.ContainsKey("all_of") || c.ContainsKey("any_of") || c.ContainsKey("not");

    static bool IsUnknownPath(object? path, IReadOnlyList<string> unknown) =>
        path is string p && unknown.Any(u => p == u || p.StartsWith(u + ".", StringComparison.Ordinal) || u.StartsWith(p + ".", StringComparison.Ordinal));

    sealed record PE(bool Const, string V, object? Src, object? C);
    static PE Const(string v, object? src) => new(true, v, src, null);
    static PE Cond(object? c) => new(false, "", null, c);
    static string TriText(Predicates.Tri t) => t == Predicates.Tri.True ? "true" : t == Predicates.Tri.False ? "false" : "unknown";

    static PE Pe(object? c, D ctx, IReadOnlyList<string> unk)
    {
        if (c is not D d)
        {
            if (c is L) return Const(TriText(Predicates.EvaluateConditionTri(c, ctx)), c);
            return Const("unknown", c);
        }
        if (IsGroup(d))
        {
            if (d.ContainsKey("all_of") || d.ContainsKey("any_of"))
            {
                var isAll = d.ContainsKey("all_of");
                var key = isAll ? "all_of" : "any_of";
                if (d[key] is not L items || items.Count == 0) return Const("unknown", c);
                var rs = items.Select(x => Pe(x, ctx, unk)).ToList();
                var absorb = isAll ? "false" : "true"; var neutral = isAll ? "true" : "false";
                if (rs.Any(r => r.Const && r.V == absorb)) return Const(absorb, c);
                var kept = rs.Where(r => !(r.Const && r.V == neutral)).ToList();
                if (kept.Count == 0) return Const(neutral, c);
                if (kept.All(r => r.Const)) return Const("unknown", c);
                var cs = new L(kept.Select(r => r.Const ? r.Src : r.C));
                return Cond(cs.Count == 1 ? cs[0] : new D { [key] = cs });
            }
            var inner = Pe(d["not"], ctx, unk);
            if (!inner.Const) return Cond(new D { ["not"] = inner.C });
            return Const(inner.V == "true" ? "false" : inner.V == "false" ? "true" : "unknown", c);
        }
        if (Field.IsLeaf(d) && (IsUnknownPath(G(d, "field"), unk) || IsUnknownPath(G(d, "ref"), unk) || IsUnknownPath(G(d, "collection"), unk))) return Cond(c);
        return Const(TriText(Predicates.EvaluateConditionTri(c, ctx)), c);
    }

    /// <summary>peAll result: a constant truth (<c>V</c>) or the conditions that remain (<c>Cs</c>).</summary>
    sealed record AllResult(string? V, L? Cs);

    static AllResult PeAll(object? where, D ctx, IReadOnlyList<string> unk)
    {
        if (Jx.IsUndef(where)) return new AllResult("true", null);
        if (where is not L l) return new AllResult("unknown", null);
        var rs = l.Select(w => Pe(w, ctx, unk)).ToList();
        if (rs.Any(r => r.Const && r.V == "false")) return new AllResult("false", null);
        var kept = rs.Where(r => !(r.Const && r.V == "true")).ToList();
        if (kept.Count == 0) return new AllResult("true", null);
        if (kept.All(r => r.Const)) return new AllResult("unknown", null);
        return new AllResult(null, new L(kept.Select(r => r.Const ? r.Src : r.C)));
    }

    static D ContextOf(object? k)
    {
        var verb = G(k, "verb"); var resource = G(k, "resource");
        var action = new D
        {
            ["verb"] = verb == null || Jx.IsUndef(verb) ? "\u0000unknown-verb\u0000" : verb,
            ["resource"] = resource == null || Jx.IsUndef(resource) ? "\u0000unknown-resource\u0000" : resource,
            ["params"] = JsX.Spread(Nn(G(k, "params"))),
        };
        var rc = G(k, "reversibilityClass");
        if (!Jx.IsUndef(rc)) action["reversibility_class"] = rc;
        return new D { ["action"] = action, ["subject"] = JsX.Spread(Nn(G(k, "subject"))), ["env"] = JsX.Spread(Nn(G(k, "env"))) };
    }

    static object Nn(object? x) => x == null || Jx.IsUndef(x) ? new D() : x;

    /// <summary>policyDigestOf: the digest of a model (its four lists and the digests of its meet parents).</summary>
    public static string PolicyDigestOf(PolicyModel m) => Pca.HashCanonical(new D
    {
        ["predicates"] = m.Predicates, ["caveats"] = m.Caveats, ["vetoes"] = m.Vetoes, ["tighten"] = m.Tighten,
        ["meet"] = new L(m.Meets.Select(x => (object?)PolicyDigestOf(x))),
    });

    static IEnumerable<PolicyModel> Flatten(PolicyModel m)
    {
        yield return m;
        foreach (var x in m.Meets) foreach (var y in Flatten(x)) yield return y;
    }

    static bool Matches(object? verb, object? resource, D ctx)
    {
        var p = new D(); Jx.Set(p, "verb", verb); Jx.Set(p, "resource", resource);
        return Predicates.PredicateMatches(p, ctx);
    }

    static D ResidualPart(PolicyModel part, D ctx, IReadOnlyList<string> unk, bool verbKnown, bool resKnown)
    {
        var predicates = new L();
        foreach (var po in part.Predicates)
        {
            if (po is not D p) continue;
            if (verbKnown && !Matches(G(p, "verb"), "*", ctx)) continue;
            if (resKnown && !Matches("*", G(p, "resource"), ctx)) continue;
            var w = PeAll(G(p, "where"), ctx, unk);
            if (w.V != null && w.V != "true") continue; // false and unknown both fail closed for a permit
            var np = new D { ["verb"] = verbKnown ? "*" : G(p, "verb") };
            if (!resKnown && !Jx.IsUndef(G(p, "resource"))) np["resource"] = G(p, "resource");
            if (w.Cs != null) np["where"] = w.Cs;
            if (Jx.IsUndef(np["verb"])) np.Remove("verb");
            predicates.Add(np);
        }
        var vetoes = new L();
        foreach (var v in part.Vetoes) { var r = PeVeto(v, ctx, unk, verbKnown, resKnown); if (r != null) vetoes.Add(r); }
        var tighten = new L();
        foreach (var t in part.Tighten)
        {
            var when = Jx.Prop(t, "when");
            var r = Pe(when, ctx, unk);
            if (r.Const && r.V == "false") continue; // a veto-polarity rule that cleanly cannot hold
            var nt = JsX.Spread(t); nt["when"] = r.Const ? when : r.C;
            tighten.Add(nt);
        }
        return new D { ["predicates"] = predicates, ["caveats"] = part.Caveats, ["vetoes"] = vetoes, ["tighten"] = tighten };
    }

    static D? PeVeto(object? v, D ctx, IReadOnlyList<string> unk, bool verbKnown, bool resKnown)
    {
        var when = Jx.Prop(v, "when");
        var wverb = Jx.Prop(when, "verb"); var wres = Jx.Prop(when, "resource");
        if (verbKnown && !Matches(wverb, "*", ctx)) return null;
        if (resKnown && !Jx.IsUndef(wres) && !Matches("*", wres, ctx)) return null;
        var w = PeAll(Jx.Prop(when, "where"), ctx, unk);
        if (w.V == "false") return null;
        var nw = new D(); Jx.Set(nw, "verb", verbKnown ? "*" : wverb);
        if (!resKnown && !Jx.IsUndef(wres)) nw["resource"] = wres;
        if (w.Cs != null) nw["where"] = w.Cs;
        var o = new D(); Jx.Set(o, "id", Jx.Prop(v, "id")); Jx.Set(o, "kind", Jx.Prop(v, "kind")); o["when"] = nw;
        var over = Jx.Prop(v, "over");
        if (Jx.Truthy(over))
        {
            if (IsUnknownPath(Jx.Prop(over, "path"), unk)) o["over"] = over;
            else
            {
                var r = Predicates.ResolvePath(ctx, Jx.Prop(over, "path"));
                var isOver = !r.Found || Jx.Fin(r.Value) is not double rv || rv < 0 || rv > Jx.ToNumber(Jx.Prop(over, "threshold"));
                if (!isOver) return null;
            }
        }
        var unless = Jx.Prop(v, "unless");
        if (Jx.Truthy(unless) && (Jx.Prop(v, "kind") as string) == "approval") o["unless"] = unless; // the evidence of approval: carried, never used to drop the veto
        else if (Jx.Truthy(unless))
        {
            var u = PeAll(unless, ctx, unk);
            if (u.Cs != null) o["unless"] = u.Cs;
            else if (u.V == "true") return null; // the exception certainly holds: the veto never applies
        }
        return o;
    }

    static D Empty() => new() { ["predicates"] = new L(), ["caveats"] = new L(), ["vetoes"] = new L(), ["tighten"] = new L() };

    /// <summary>residual: the policy specialised to the known facts, with a decision of never, always or conditional.</summary>
    public static D Compute(object? policy, object? known, object? opts = null)
    {
        var model = Enumerate.ToModel(policy);
        var digest = PolicyDigestOf(model);
        var verbKnown = !Jx.IsUndef(Jx.Prop(known, "verb"));
        var resKnown = !Jx.IsUndef(Jx.Prop(known, "resource")) && !(Jx.Opt(opts, "resourceUnknown") is true);
        var unk = new List<string>();
        var uo = Jx.Opt(opts, "unknown");
        if (uo == null || Jx.IsUndef(uo)) unk.Add("action.params"); else foreach (var u in (L)uo) unk.Add(JsX.Str(u));
        if (!verbKnown) unk.Add("action.verb");
        if (!resKnown) unk.Add("action.resource");
        var ctx = ContextOf(known);
        D Never(string reason) => new() { ["decision"] = "never", ["reason"] = reason, ["policy"] = Empty(), ["policyDigest"] = digest };
        if (!model.CaveatSat) return Never("caveats unsatisfiable: " + (model.CaveatReason ?? "unknown"));
        var krc = Jx.Prop(known, "reversibilityClass");
        if (!Jx.IsUndef(krc) && model.RevCap != null)
        {
            var idx = krc is string s ? CaveatAnalysis.ReversibilityOrder.ToList().IndexOf(s) : -1;
            if (idx < 0 || idx > model.RevCap) return Never("reversibility class exceeds the caveat cap");
        }
        var parts = Flatten(model).Select(m => ResidualPart(m, ctx, unk, verbKnown, resKnown)).ToList();
        var policyOut = Jx.Copy(parts[0]);
        if (parts.Count > 1) policyOut["meet"] = new L(parts.Skip(1));
        var res = new D { ["decision"] = "conditional", ["policy"] = policyOut, ["policyDigest"] = digest };
        if (parts.Any(p => ((L)p["predicates"]!).Count == 0)) return Never("no permit survives the known facts");
        foreach (var p in parts)
        {
            foreach (var v in (L)p["vetoes"]!)
            {
                var vw = Jx.Prop(v, "when");
                var vr = Jx.Prop(vw, "resource"); var vwh = Jx.Prop(vw, "where");
                if ((Jx.Prop(v, "kind") as string) == "deny" && (Jx.IsUndef(vr) || (vr is string rs && rs == "*")) && (Jx.IsUndef(vwh) || (vwh is L wl && wl.Count == 0))
                    && Jx.IsUndef(Jx.Prop(v, "unless")) && Jx.IsUndef(Jx.Prop(v, "over")))
                    return Never($"veto {JsX.Str(Jx.Prop(v, "id"))} applies to every completion");
            }
        }
        if (parts.All(p => ((L)p["predicates"]!).Any(x => Jx.IsUndef(Jx.Prop(x, "where"))) && ((L)p["vetoes"]!).Count == 0 && ((L)p["tighten"]!).Count == 0)) res["decision"] = "always";
        return res;
    }

    /// <summary>residualPolicy: the residual as a policy input (own part plus meet parents).</summary>
    public static D PolicyOf(object? r)
    {
        var pol = (D)Jx.Prop(r, "policy")!;
        var o = new D();
        foreach (var (k, v) in pol) if (k != "meet") o[k] = v;
        if (Jx.Truthy(G(pol, "meet"))) o["meet"] = new L(((L)pol["meet"]!).Select(m => (object?)JsX.Spread(m)));
        return o;
    }

    /// <summary>evaluateResidual: the decision of a residual at a full context.</summary>
    public static string Evaluate(object? r, object? ctx)
    {
        if ((Jx.Prop(r, "decision") as string) == "never") return "deny";
        var a = Jx.Prop(ctx, "action");
        var action = new D(); Jx.Set(action, "verb", Jx.Prop(a, "verb")); Jx.Set(action, "resource", Jx.Prop(a, "resource"));
        if (Jx.Truthy(Jx.Prop(a, "params"))) action["params"] = a is D ad ? ad["params"] : null;
        if (Jx.Truthy(Jx.Prop(ctx, "subject"))) action["subject"] = ((D)ctx!)["subject"];
        if (Jx.Truthy(Jx.Prop(ctx, "env"))) action["env"] = ((D)ctx!)["env"];
        if (Jx.Truthy(Jx.Prop(a, "reversibility_class"))) action["reversibilityClass"] = ((D)a!)["reversibility_class"];
        return Enumerate.DecideAction(Enumerate.ToModel(PolicyOf(r)), action);
    }

    // ---- what may I do ----

    sealed class NumRange
    {
        public double? Lo, Hi; public bool? LoInc, HiInc;
        public NumRange Copy() => new() { Lo = Lo, Hi = Hi, LoInc = LoInc, HiInc = HiInc };
        public D ToJson()
        {
            var o = new D();
            if (Lo != null) o["lo"] = Jx.NumOut(Lo.Value);
            if (Hi != null) o["hi"] = Jx.NumOut(Hi.Value);
            if (LoInc != null) o["loInclusive"] = LoInc.Value;
            if (HiInc != null) o["hiInclusive"] = HiInc.Value;
            return o;
        }
    }

    static List<NumRange> MergeRanges(List<NumRange> rs)
    {
        int Cmp(NumRange a, NumRange b)
        {
            var diff = (a.Lo ?? double.NegativeInfinity) - (b.Lo ?? double.NegativeInfinity);
            if (!double.IsNaN(diff) && diff != 0) return diff < 0 ? -1 : 1;
            return (b.LoInc == true ? 1 : 0) - (a.LoInc == true ? 1 : 0);
        }
        var sorted = rs.OrderBy(x => x, Comparer<NumRange>.Create(Cmp)).ToList();
        var o = new List<NumRange>();
        foreach (var r in sorted)
        {
            var last = o.Count > 0 ? o[^1] : null;
            var lh = last?.Hi ?? double.PositiveInfinity; var rl = r.Lo ?? double.NegativeInfinity;
            if (last != null && lh >= rl && !(lh == rl && last.HiInc != true && r.LoInc != true))
            {
                var rh = r.Hi ?? double.PositiveInfinity;
                if (rh > lh || (rh == lh && r.HiInc == true))
                {
                    last.Hi = r.Hi;
                    if (r.HiInc == true) last.HiInc = true; else last.HiInc = null;
                }
            }
            else o.Add(r.Copy());
        }
        return o;
    }

    static NumRange CellRange(double value, List<double> T)
    {
        if (T.Contains(value)) return new NumRange { Lo = value, Hi = value, LoInc = true, HiInc = true };
        double? below = null, above = null;
        for (int i = T.Count - 1; i >= 0; i--) if (T[i] < value) { below = T[i]; break; }
        foreach (var t in T) if (t > value) { above = t; break; }
        return new NumRange { Lo = below, Hi = above };
    }

    sealed class Seen { public object? Value; public bool Allow, Escalate; }

    /// <summary>whatMayIDo: per verb, the autonomous and approval-gated domains of each declared parameter and resource, advisory only.</summary>
    public static L WhatMayIDo(object? policy, object? verbs, object? known, object? o)
    {
        var outl = new L();
        var mc = Jx.Opt(o, "maxCombinations");
        var max = Jx.IsNum(mc) ? IntentJs.NumOf(mc)!.Value : AnalyzerCore.DefaultMaxCombinations;
        foreach (var shape in (L)verbs!)
        {
            var verb = Jx.Prop(shape, "verb");
            var kn = JsX.Spread(known); kn["verb"] = verb;
            var res = Compute(policy, kn);
            var env = new D
            {
                ["verb"] = verb, ["status"] = "denied", ["params"] = new D(),
                ["resources"] = new D { ["autonomous"] = new L(), ["withApproval"] = new L(), ["other"] = false },
                ["policyDigest"] = res["policyDigest"], ["advisory"] = true,
            };
            var rem = Jx.Opt(o, "remaining");
            if (Jx.Truthy(rem)) env["remaining"] = JsX.Spread(rem);
            var md = Jx.Opt(o, "missingDischarges");
            if (Jx.Truthy(md)) env["missingDischarges"] = new L((L)md!);
            if ((res["decision"] as string) == "never") { Jx.Set(env, "reason", G(res, "reason")); outl.Add(env); continue; }
            var rp = Enumerate.ToModel(PolicyOf(res));
            var sp = Jx.Prop(shape, "params");
            var names = JsX.Keys(sp);
            var extra = new List<(string, D)>(); var extraNum = new List<(string, D)>();
            foreach (var name in names)
            {
                var d = JsX.ValueOf(sp, name); var path = "action.params." + name;
                if (!Jx.IsUndef(Jx.Prop(d, "values"))) extra.Add((path, new D { ["field"] = path, ["op"] = "in", ["value"] = Jx.Prop(d, "values") }));
            }
            foreach (var name in names)
            {
                var d = JsX.ValueOf(sp, name); var path = "action.params." + name;
                if (!Jx.IsUndef(Jx.Prop(d, "min"))) extraNum.Add((path, new D { ["field"] = path, ["op"] = "gte", ["value"] = Jx.Prop(d, "min") }));
                if (!Jx.IsUndef(Jx.Prop(d, "max"))) extraNum.Add((path, new D { ["field"] = path, ["op"] = "lte", ["value"] = Jx.Prop(d, "max") }));
            }
            var pr = Enumerate.CollectProbes(new ProbeInputs { PredicateSets = new List<L> { Enumerate.ProbeSet(rp) }, ExtraFieldConditions = extra.Concat(extraNum).ToList(), VaryReversibility = rp.RevCap != null });
            pr.Verbs = new List<string> { JsX.Str(verb) };
            if (Enumerate.ProductSize(pr) > max)
            {
                env["status"] = "needs-approval"; env["approximate"] = true; env["reason"] = "representative grid exceeded the bound; no domain is claimed";
                outl.Add(env); continue;
            }
            var kres = Jx.Prop(known, "resource");
            if (!Jx.IsUndef(kres)) pr.Resources = new List<string> { JsX.Str(kres) };
            var seen = new Dictionary<string, List<(string Key, Seen S)>>(StringComparer.Ordinal);
            var resSeen = new List<(string R, Seen S)>();
            bool anyAllow = false, anyEscalate = false, freshRes = false;
            foreach (var rep in Enumerate.Representatives(pr))
            {
                var dec = Enumerate.Decide(rp, rep);
                if (dec == "deny") continue;
                if (dec == "allow") anyAllow = true; else anyEscalate = true;
                var act = Enumerate.RepToAction(rep);
                var aprm = (D)act["params"]!;
                foreach (var name in names)
                {
                    var v = aprm.TryGetValue(name, out var pv) ? pv : Jx.Undef;
                    if (!seen.TryGetValue(name, out var m)) { m = new(); seen[name] = m; }
                    var k = Jx.IsUndef(v) ? "\u0000absent" : JsJson.Stringify(v);
                    var cur = m.FirstOrDefault(x => x.Key == k).S;
                    if (cur == null) { cur = new Seen { Value = v }; m.Add((k, cur)); }
                    if (dec == "allow") cur.Allow = true; else cur.Escalate = true;
                }
                var resource = (string)act["resource"]!;
                var rr = resSeen.FirstOrDefault(x => x.R == resource).S;
                if (rr == null) { rr = new Seen(); resSeen.Add((resource, rr)); }
                if (dec == "allow") rr.Allow = true; else rr.Escalate = true;
                if (resource.StartsWith('\u0000')) freshRes = true;
            }
            env["status"] = anyAllow ? "autonomous" : anyEscalate ? "needs-approval" : "denied";
            var paramsOut = (D)env["params"]!;
            foreach (var name in names)
            {
                var decl = JsX.ValueOf(sp, name);
                var path = "action.params." + name;
                var T = Exposure.ThresholdsOf(rp, path);
                var vals = seen.TryGetValue(name, out var mm) ? mm.Select(x => x.S).ToList() : new List<Seen>();
                var dmin = Jx.Prop(decl, "min"); var dmax = Jx.Prop(decl, "max"); var dvalues = Jx.Prop(decl, "values");
                var nums = vals.Where(x => Jx.IsNum(x.Value) && (Jx.IsUndef(dmin) || IntentJs.NumOf(x.Value)!.Value >= Jx.ToNumber(dmin)) && (Jx.IsUndef(dmax) || IntentJs.NumOf(x.Value)!.Value <= Jx.ToNumber(dmax))).ToList();
                var strs = vals.Where(x => x.Value is string).ToList();
                if ((Jx.Prop(decl, "type") as string) == "integer" || nums.Count > 0)
                {
                    double? lo = Jx.IsUndef(dmin) ? null : Jx.ToNumber(dmin); double? hi = Jx.IsUndef(dmax) ? null : Jx.ToNumber(dmax);
                    NumRange Clip(NumRange r)
                    {
                        var c = r.Copy();
                        if (lo != null && (r.Lo == null || r.Lo < lo)) { c.Lo = lo; c.LoInc = true; }
                        if (hi != null && (r.Hi == null || r.Hi > hi)) { c.Hi = hi; c.HiInc = true; }
                        return c;
                    }
                    L Ranges(Func<Seen, bool> pick) => new L(MergeRanges(nums.Where(pick).Select(x => Clip(CellRange(IntentJs.NumOf(x.Value)!.Value, T))).ToList()).Select(r => (object?)r.ToJson()));
                    paramsOut[name] = new D { ["kind"] = "numeric", ["autonomous"] = Ranges(x => x.Allow), ["withApproval"] = Ranges(x => x.Escalate && !x.Allow) };
                }
                else if (!Jx.IsUndef(dvalues) || strs.Count > 0)
                {
                    L PickList(Func<Seen, bool> f) { var l = strs.Where(x => f(x) && !((string)x.Value!).StartsWith('\u0000')).Select(x => (string)x.Value!).ToList(); l.Sort(StringComparer.Ordinal); return new L(l); }
                    var fresh = strs.FirstOrDefault(x => ((string)x.Value!).StartsWith('\u0000'));
                    paramsOut[name] = new D
                    {
                        ["kind"] = "enum", ["autonomous"] = PickList(x => x.Allow), ["withApproval"] = PickList(x => x.Escalate && !x.Allow),
                        ["otherAutonomous"] = Jx.IsUndef(dvalues) && fresh?.Allow == true,
                        ["otherWithApproval"] = Jx.IsUndef(dvalues) && fresh != null && fresh.Escalate && !fresh.Allow,
                    };
                }
                else paramsOut[name] = new D { ["kind"] = "unconstrained" };
            }
            var rnames = resSeen.Where(x => !x.R.StartsWith('\u0000')).ToList();
            List<string> Sorted(IEnumerable<string> xs) { var l = xs.ToList(); l.Sort(StringComparer.Ordinal); return l; }
            env["resources"] = new D
            {
                ["autonomous"] = new L(Sorted(rnames.Where(x => x.S.Allow).Select(x => x.R)).Cast<object?>()),
                ["withApproval"] = new L(Sorted(rnames.Where(x => x.S.Escalate && !x.S.Allow).Select(x => x.R)).Cast<object?>()),
                ["other"] = freshRes,
            };
            if (rp.Undecidable.Count > 0) { env["approximate"] = true; env["reason"] = $"over-approximated ({string.Join("; ", rp.Undecidable)})"; }
            outl.Add(env);
        }
        return outl;
    }
}

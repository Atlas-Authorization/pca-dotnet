using AtlasPca.InteropJs;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Analyzer;

/// <summary>The largest single action admitted: its amount ceiling, whether it is attained, and a witness.</summary>
public sealed class PeakResult
{
    public bool Admitted { get; init; }
    public double Max { get; init; }
    public bool Attained { get; init; }
    public D? Witness { get; init; }
    public D ToJson()
    {
        var o = new D { ["admitted"] = Admitted, ["max"] = Jx.NumOut(Max), ["attained"] = Attained };
        if (Witness != null) o["witness"] = Witness;
        return o;
    }
}

/// <summary>The bound on the total over a window.</summary>
public sealed class WindowBound
{
    public double? Secs { get; init; }
    public double MaxActions { get; init; }
    public double Bound { get; init; }
    public List<string> Basis { get; init; } = new();
    public List<string> NotApplied { get; init; } = new();
    public (D Action, double Repeat)? Sequence { get; init; }
    public D ToJson()
    {
        var o = new D();
        if (Secs != null) o["secs"] = Jx.NumOut(Secs.Value);
        o["maxActions"] = Jx.NumOut(MaxActions); o["bound"] = Jx.NumOut(Bound);
        o["basis"] = Basis.Cast<object?>().ToList(); o["notApplied"] = NotApplied.Cast<object?>().ToList();
        if (Sequence != null) o["sequence"] = new D { ["action"] = Sequence.Value.Action, ["repeat"] = Jx.NumOut(Sequence.Value.Repeat) };
        return o;
    }
}

public sealed class ExposureResult
{
    public string Verb { get; init; } = "";
    public string AmountField { get; init; } = "";
    public PeakResult PerAction { get; init; } = null!;
    public PeakResult AutonomousPerAction { get; init; } = null!;
    public WindowBound Window { get; init; } = null!;
    public WindowBound AutonomousWindow { get; init; } = null!;
    public List<string> Unmodeled { get; init; } = new();
    public bool Approximate { get; set; }
    public string? Reason { get; set; }
    public D ToJson()
    {
        var o = new D
        {
            ["verb"] = Verb, ["amountField"] = AmountField, ["perAction"] = PerAction.ToJson(), ["autonomousPerAction"] = AutonomousPerAction.ToJson(),
            ["window"] = Window.ToJson(), ["autonomousWindow"] = AutonomousWindow.ToJson(), ["unmodeled"] = Unmodeled.Cast<object?>().ToList(),
        };
        if (Approximate) o["approximate"] = true;
        if (Reason != null) o["reason"] = Reason;
        return o;
    }
}

/// <summary>Quantitative exposure, escalation surface, delegation envelope and policy diffs over the bounded decision engine.</summary>
public static class Exposure
{
    const double Huge = 9007199254740991.0;
    static readonly string[] Widen = { "deny->allow", "deny->escalate", "escalate->allow" };

    static L Iter(object? x) => x == null || Jx.IsUndef(x) ? new L() : x as L ?? throw JsX.TypeError("value is not iterable");
    static double? OptNum(object? o, string k) { var v = Jx.Opt(o, k); return v == null || Jx.IsUndef(v) ? null : Jx.ToNumber(v); }
    static string? OptStr(object? o, string k) { var v = Jx.Opt(o, k); return Jx.IsUndef(v) ? null : v as string; }

    static void CondThresholds(object? c, string path, List<double> into)
    {
        if (c is not D d) return;
        if (d.ContainsKey("all_of") || d.ContainsKey("any_of") || d.ContainsKey("not"))
        {
            if (d.ContainsKey("all_of") && d["all_of"] is L a) foreach (var x in a) CondThresholds(x, path, into);
            else if (d.ContainsKey("any_of") && d["any_of"] is L b) foreach (var x in b) CondThresholds(x, path, into);
            else if (d.ContainsKey("not")) CondThresholds(d["not"], path, into);
            return;
        }
        if (!Field.IsLeaf(d) || (string)d["field"]! != path) return;
        var v = d.TryGetValue("value", out var vv) ? vv : Jx.Undef;
        if (Jx.Fin(v) is double f) into.Add(f);
        else if (v is L l) foreach (var x in l) if (Jx.Fin(x) is double g) into.Add(g);
    }

    /// <summary>thresholdsOf: every numeric constant the policy compares <paramref name="path"/> against, ascending.</summary>
    public static List<double> ThresholdsOf(PolicyModel model, string path)
    {
        var o = new List<double>();
        foreach (var p in Enumerate.ProbeSet(model)) foreach (var c in Iter(Jx.Prop(p, "where"))) CondThresholds(c, path, o);
        foreach (var v in model.Vetoes)
        {
            var over = Jx.Opt(Jx.Prop(v, "over"), "path");
            if (over is string ps && ps == path) o.Add(Jx.ToNumber(Jx.Prop(Jx.Prop(v, "over"), "threshold")));
        }
        var u = new List<double>();
        foreach (var x in o) if (!u.Any(y => y == x || (double.IsNaN(x) && double.IsNaN(y)))) u.Add(x);
        u.Sort((a, b) => (a - b) is var r && !double.IsNaN(r) ? r.CompareTo(0.0) : 0);
        return u;
    }

    static Probes Pinned(Probes pr, string path, double value, string? resource)
    {
        var fields = pr.Fields.Where(f => f.Path != path).ToList();
        fields.Add(new ProbeField(path, new List<object?> { Jx.N(value) }));
        return new Probes { Verbs = pr.Verbs, Resources = resource != null ? new List<string> { resource } : pr.Resources, RevClasses = pr.RevClasses, Fields = fields };
    }

    sealed record Peak(PeakResult Result, bool Overflow);

    static Peak PeakAt(PolicyModel model, object? o, string level)
    {
        var amountField = OptStr(o, "amountField") ?? "amount";
        var path = "action.params." + amountField;
        var max = AnalyzerCore.BoundOf(o);
        var bs = Enumerate.CollectProbes(new ProbeInputs { PredicateSets = new List<L> { Enumerate.ProbeSet(model) }, VaryReversibility = model.RevCap != null });
        bs.Verbs = new List<string> { OptStr(o, "verb") ?? "" };
        var resource = OptStr(o, "resource");
        var T = ThresholdsOf(model, path);
        var lo = Math.Max(0, OptNum(o, "min") ?? 0);
        var hi = OptNum(o, "max") ?? double.PositiveInfinity;
        var raw = new List<double>();
        for (int i = 0; i < T.Count; i++)
        {
            var t = T[i];
            raw.Add(t - 1); raw.Add(t);
            if (i + 1 < T.Count) raw.Add((t + T[i + 1]) / 2);
        }
        raw.Add(T.Count > 0 ? T[^1] + 1 : 0); raw.Add(Huge); raw.Add(lo);
        if (double.IsFinite(hi)) raw.Add(hi);
        var uniq = new List<double>();
        foreach (var x in raw) if (!uniq.Contains(x)) uniq.Add(x);
        var cands = uniq.Where(c => c >= lo && c <= hi && double.IsFinite(c)).ToList();
        cands.Sort((a, b) => b.CompareTo(a));
        bool Ok(string d) => level == "allow" ? d == "allow" : d != "deny";
        var overflow = false;
        foreach (var c in cands)
        {
            var outc = Enumerate.Search(Pinned(bs, path, c, resource), rep => Ok(Enumerate.Decide(model, rep)), max);
            if (outc.Overflow) { overflow = true; break; }
            if (outc.Hit == null) continue;
            D Act(double v) { var a = Enumerate.RepToAction(outc.Hit); var p = Jx.Copy((D)a["params"]!); p[amountField] = Jx.N(v); a["params"] = p; return a; }
            bool Holds(D a) => Ok(Enumerate.DecideAction(model, a));
            var top = T.Count > 0 ? T[^1] : double.NegativeInfinity;
            if (c > top)
            {
                if (double.IsFinite(hi)) { var w = Act(hi); return new Peak(new PeakResult { Admitted = true, Max = hi, Attained = Holds(w), Witness = w }, false); }
                return new Peak(new PeakResult { Admitted = true, Max = double.PositiveInfinity, Attained = false, Witness = Act(Huge) }, false);
            }
            if (T.Contains(c)) return new Peak(new PeakResult { Admitted = true, Max = c, Attained = true, Witness = Act(c) }, false);
            var next = T.First(t => t > c);
            if (OptBool(o, "integer"))
            {
                var m = Math.Ceiling(next) - 1;
                if (m >= c) { var w = Act(m); if (Holds(w)) return new Peak(new PeakResult { Admitted = true, Max = m, Attained = true, Witness = w }, false); }
            }
            return new Peak(new PeakResult { Admitted = true, Max = next, Attained = false, Witness = Act(c) }, false);
        }
        return new Peak(new PeakResult { Admitted = false, Max = 0, Attained = false }, overflow);
    }

    static bool OptBool(object? o, string k) => Jx.Opt(o, k) is true;

    static bool Universal(object? p, string verb)
    {
        var pv = Jx.Prop(p, "verb");
        var verbOk = (pv is string s0 && (s0 == "*" || s0 == verb)) || (pv is L pl && pl.Any(x => x is string xs && (xs == "*" || xs == verb)));
        var res = Jx.Prop(p, "resource");
        var wh = Jx.Prop(p, "where");
        var whereEmpty = Jx.IsUndef(wh) || (wh is L wl ? wl.Count == 0 : wh is string ws ? ws.Length == 0 : throw JsX.TypeError("where.length"));
        return verbOk && (Jx.IsUndef(res) || (res is string rs && rs == "*")) && whereEmpty;
    }

    static WindowBound WindowOf(PolicyModel model, object? c, object? o, PeakResult peak)
    {
        var W = OptNum(o, "windowSecs");
        var amountField = OptStr(o, "amountField") ?? "amount";
        var path = "action.params." + amountField;
        var verb = OptStr(o, "verb") ?? "";
        var per = peak.Admitted ? peak.Max : 0;
        var basis = new List<string>(); var notApplied = new List<string>();
        double maxActions = double.PositiveInfinity;
        void LimitActions(double n, double perSecs, string why)
        {
            var k = W == null ? double.PositiveInfinity : n * Math.Ceiling(W.Value / perSecs);
            if (k < maxActions) { maxActions = k; basis.Add(why); }
        }
        var caveats = new List<object?>(model.Caveats);
        foreach (var m in model.Meets) caveats.AddRange(m.Caveats);
        foreach (var cv in caveats)
            if (Jx.Prop(cv, "type") as string == "rate" && Jx.Fin(Jx.Prop(cv, "max")) is double cm && Jx.IsNum(Jx.Prop(cv, "max")) && Jx.IsNum(Jx.Prop(cv, "per_secs")) && IntentJs.NumOf(Jx.Prop(cv, "per_secs")) is double ps && ps > 0)
                LimitActions(IntentJs.NumOf(Jx.Prop(cv, "max"))!.Value, ps, $"rate caveat {JsX.Str(Jx.Prop(cv, "max"))}/{JsX.Str(Jx.Prop(cv, "per_secs"))}s");
        var invs = Iter(Jx.Opt(c, "invariants"));
        foreach (var inv in invs)
        {
            if (Jx.Prop(inv, "kind") as string != "rate") continue;
            if (Universal(Jx.Prop(inv, "when"), verb)) LimitActions(Jx.ToNumber(Jx.Prop(inv, "max")), Jx.ToNumber(Jx.Prop(inv, "window_secs")), $"rate invariant {JsX.Str(Jx.Prop(inv, "id"))}");
            else notApplied.Add(JsX.Str(Jx.Prop(inv, "id")));
        }
        var bound = per == 0 ? 0 : double.IsPositiveInfinity(maxActions) ? double.PositiveInfinity : per * maxActions;
        if (double.IsFinite(per) && per > 0) basis.Insert(0, "per-action ceiling");
        var budgetModel = OptStr(o, "budgetModel");
        var kappaV = Jx.Opt(o, "kappa");
        foreach (var cv in caveats)
        {
            if (Jx.Prop(cv, "type") as string != "budget_alloc" || !Jx.IsNum(Jx.Prop(cv, "limit"))) continue;
            var limit = IntentJs.NumOf(Jx.Prop(cv, "limit"))!.Value;
            if (budgetModel == "dollars")
            {
                if (limit < bound) { bound = limit; basis.Add($"budget_alloc limit {Jx.NumStr(limit)}"); }
            }
            else if (budgetModel == "risk" && Jx.IsNum(kappaV) && IntentJs.NumOf(kappaV)!.Value > 0)
            {
                var kappa = IntentJs.NumOf(kappaV)!.Value;
                var br = OptNum(o, "blastRadius") ?? Blast(verb);
                var cost = kappa * Math.Min(1, Math.Max(0, br));
                var n = cost > 0 ? Math.Floor(limit / cost) : double.PositiveInfinity;
                if (n < maxActions)
                {
                    maxActions = n;
                    bound = n == 0 ? 0 : double.IsFinite(per) && per > 0 ? per * n : bound;
                    basis.Add($"budget_alloc {Jx.NumStr(limit)} / cost {Jx.NumStr(cost)} = {Jx.NumStr(n)} actions");
                }
            }
            else notApplied.Add($"budget_alloc {Jx.NumStr(limit)} (trust-budget units; pass budgetModel and kappa)");
        }
        foreach (var inv in invs)
        {
            if (Jx.Prop(inv, "kind") as string != "cap") continue;
            if (!Universal(Jx.Prop(inv, "when"), verb) || !(Jx.Prop(inv, "amount") is string am && am == path)) { notApplied.Add(JsX.Str(Jx.Prop(inv, "id"))); continue; }
            var ws = Jx.Prop(inv, "window_secs");
            if (!Jx.IsUndef(ws) && W == null) continue;
            var cap = Jx.IsUndef(ws) || W == null ? Jx.ToNumber(Jx.Prop(inv, "max")) : Jx.ToNumber(Jx.Prop(inv, "max")) * Math.Ceiling(W.Value / Jx.ToNumber(ws));
            if (cap < bound) { bound = cap; basis.Add($"cap invariant {JsX.Str(Jx.Prop(inv, "id"))}"); }
        }
        (D, double)? seq = null;
        if (peak.Admitted && peak.Witness != null && double.IsFinite(maxActions) && double.IsFinite(peak.Max) && peak.Max > 0) seq = (peak.Witness, maxActions);
        return new WindowBound { Secs = W, MaxActions = maxActions, Bound = bound, Basis = basis, NotApplied = notApplied, Sequence = seq };
    }

    static double Blast(string verb)
    {
        foreach (var a in Catalog.Builtin) if (a.Verb == verb) return a.BlastRadius;
        return 1; // an uncatalogued verb is treated as maximum blast radius
    }

    /// <summary>maxExposure: the largest single action and the largest total over a window the policy can admit.</summary>
    public static ExposureResult MaxExposure(object? policy, object? given)
    {
        var o = JsX.Spread(given);
        if (!o.ContainsKey("budgetModel") || o["budgetModel"] == null)
        {
            var bm = Jx.Prop(policy, "budgetModel");
            if (bm is string b && (b == "dollars" || b == "risk")) o["budgetModel"] = b;
        }
        if (!o.ContainsKey("kappa") || o["kappa"] == null)
        {
            var k = Jx.Opt(Jx.Prop(policy, "riskPolicy"), "kappa");
            if (Jx.IsNum(k)) o["kappa"] = k;
        }
        var hasCon = o.ContainsKey("constitution");
        D? cv = hasCon ? Constitution.VetoesFromConstitution(o["constitution"]) : null;
        var bmod = Enumerate.ToModel(policy);
        var model = cv != null ? bmod.WithVetoes(new L(bmod.Vetoes.Concat((L)cv["vetoes"]!))) : bmod;
        var field = OptStr(o, "amountField") ?? "amount";
        var admit = PeakAt(model, o, "admit");
        var auto = PeakAt(model, o, "allow");
        var approximate = admit.Overflow || auto.Overflow || model.Undecidable.Count > 0;
        PeakResult Unb() => new() { Admitted = true, Max = double.PositiveInfinity, Attained = false };
        var admitPeak = admit.Overflow ? Unb() : admit.Result; var autoPeak = auto.Overflow ? Unb() : auto.Result;
        var con = hasCon ? o["constitution"] : Jx.Undef;
        var e = new ExposureResult
        {
            Verb = OptStr(o, "verb") ?? "", AmountField = field, PerAction = admitPeak, AutonomousPerAction = autoPeak,
            Window = WindowOf(model, con, o, admitPeak), AutonomousWindow = WindowOf(model, con, o, autoPeak),
            Unmodeled = ((L?)cv?["unmodeled"] ?? new L()).Where(u => !(Jx.Prop(u, "kind") is string uk && (uk == "cap" || uk == "rate")))
                .Select(u => $"{JsX.Str(Jx.Prop(u, "id"))}: {JsX.Str(Jx.Prop(u, "reason"))}").ToList(),
        };
        if (approximate)
        {
            e.Approximate = true;
            e.Reason = admit.Overflow || auto.Overflow ? "representative grid exceeded the bound; exposure reported as unbounded" : $"over-approximated ({string.Join("; ", model.Undecidable)})";
        }
        return e;
    }

    /// <summary>escalationSurface: actions the policy admits only with a human or guardian co-sign.</summary>
    public static D EscalationSurface(object? policy, object? opts = null)
    {
        var model = Enumerate.ToModel(policy);
        var bs = Enumerate.CollectProbes(new ProbeInputs { PredicateSets = new List<L> { Enumerate.ProbeSet(model) }, VaryReversibility = model.RevCap != null });
        var verb = OptStr(opts, "verb");
        if (verb != null) bs.Verbs = new List<string> { verb };
        var limit = (int)Math.Min(int.MaxValue, OptNum(opts, "limit") ?? 8);
        var r = Enumerate.Collect(bs, rep => Enumerate.Decide(model, rep) == "escalate", AnalyzerCore.BoundOf(opts), limit);
        var witnesses = r.Hits.Select(Enumerate.RepToAction).Where(a => Enumerate.DecideAction(model, a) == "escalate").Cast<object?>().ToList();
        var o = new D { ["escalates"] = witnesses.Count > 0, ["witnesses"] = witnesses };
        if (r.Overflow || model.Undecidable.Count > 0)
        {
            o["approximate"] = true;
            o["reason"] = r.Overflow ? "representative grid exceeded the bound" : $"over-approximated ({string.Join("; ", model.Undecidable)})";
        }
        return o;
    }

    /// <summary>delegationEnvelope: what the leaf of a delegation chain can do once every ancestor bounds it, and which hops widen authority.</summary>
    public static D DelegationEnvelope(object? chainO, object? opts = null)
    {
        var chain = (L)chainO!;
        object? leaf = chain.Count > 0 ? chain[^1] : null;
        object policy;
        if (chain.Count > 0 && leaf is D ld)
        {
            var meet = new L(chain.Take(chain.Count - 1));
            if (ld.ContainsKey("meet") && Jx.Truthy(ld["meet"]))
            {
                var m = ld["meet"];
                if (m is L ml) meet.AddRange(ml); else if (m is string ms) foreach (var ch in ms) meet.Add(ch.ToString()); else throw JsX.TypeError("meet is not iterable");
            }
            var np = Jx.Copy(ld); np["meet"] = meet; policy = np;
        }
        else policy = new D { ["predicates"] = new L() };
        var model = Enumerate.ToModel(policy);
        var bs = Enumerate.CollectProbes(new ProbeInputs { PredicateSets = new List<L> { Enumerate.ProbeSet(model) }, VaryReversibility = model.RevCap != null });
        var verbs = new L(); var anyVerb = false; var overflow = false;
        var bound = AnalyzerCore.BoundOf(opts);
        foreach (var verb in bs.Verbs)
        {
            var pr = new Probes { Verbs = new List<string> { verb }, Resources = bs.Resources, RevClasses = bs.RevClasses, Fields = bs.Fields };
            var r = Enumerate.Collect(pr, rep => Enumerate.Decide(model, rep) != "deny", bound, 1);
            if (r.Overflow) { overflow = true; break; }
            if (r.Hits.Count == 0) continue;
            var hit = r.Hits[0];
            var w = Enumerate.RepToAction(hit);
            if (verb.StartsWith('\u0000')) anyVerb = true;
            else verbs.Add(new D { ["verb"] = verb, ["witness"] = w, ["autonomous"] = Enumerate.Decide(model, hit) == "allow" });
        }
        var violations = new L();
        for (int i = 0; i + 1 < chain.Count; i++)
        {
            var a = Enumerate.ToModel(chain[i]); var b = Enumerate.ToModel(chain[i + 1]);
            var pr = Enumerate.CollectProbes(new ProbeInputs { PredicateSets = new List<L> { Enumerate.ProbeSet(a), Enumerate.ProbeSet(b) }, VaryReversibility = a.RevCap != null || b.RevCap != null });
            var outc = Enumerate.Search(pr, rep => Enumerate.Decide(b, rep) != "deny" && Enumerate.Decide(a, rep) == "deny", bound);
            if (outc.Hit != null || outc.Overflow) violations.Add(Jx.N(i + 1));
        }
        var depths = new List<double>();
        foreach (var p in chain)
            if (p is D pd && pd.GetValueOrDefault("caveats") is L cl)
                foreach (var c in cl)
                    if (Jx.Prop(c, "type") as string == "delegation_depth" && Jx.IsNum(Jx.Prop(c, "max"))) depths.Add(IntentJs.NumOf(Jx.Prop(c, "max"))!.Value);
        var used = Math.Max(0, chain.Count - 1);
        var depth = new D { ["used"] = Jx.N(used) };
        if (depths.Count > 0)
        {
            var allowed = depths.Min();
            depth["allowed"] = Jx.NumOut(allowed); depth["remaining"] = Jx.NumOut(Math.Max(0, allowed - used));
        }
        var o = new D { ["violations"] = violations, ["verbs"] = verbs, ["anyVerb"] = anyVerb, ["depth"] = depth };
        if (overflow || model.Undecidable.Count > 0)
        {
            o["approximate"] = true;
            o["reason"] = overflow ? "representative grid exceeded the bound" : $"over-approximated ({string.Join("; ", model.Undecidable)})";
        }
        return o;
    }

    static double Sub(double x, double y) => x == y ? 0 : x - y; // Infinity - Infinity is no change

    /// <summary>diffPolicies: every decision shift between two policies over the joint grid (a sample per shift kind), widen/narrow flags and an optional exposure delta.</summary>
    public static D DiffPolicies(object? a, object? b, object? o = null)
    {
        var ma = Enumerate.ToModel(a); var mb = Enumerate.ToModel(b);
        var pr = Enumerate.CollectProbes(new ProbeInputs { PredicateSets = new List<L> { Enumerate.ProbeSet(ma), Enumerate.ProbeSet(mb) }, VaryReversibility = ma.RevCap != null || mb.RevCap != null });
        var limit = OptNum(o, "limit") ?? 4;
        var kinds = new List<string>(); var shifts = new Dictionary<string, L>(StringComparer.Ordinal); var counts = new Dictionary<string, int>(StringComparer.Ordinal);
        var walk = Enumerate.Collect(pr, rep =>
        {
            var x = Enumerate.Decide(ma, rep); var y = Enumerate.Decide(mb, rep);
            if (x == y) return false;
            var k = x + "->" + y;
            counts.TryGetValue(k, out var n); counts[k] = n + 1;
            if (n < limit)
            {
                if (!shifts.TryGetValue(k, out var l)) { l = new L(); shifts[k] = l; kinds.Add(k); }
                l.Add(Enumerate.RepToAction(rep));
            }
            return false;
        }, AnalyzerCore.BoundOf(o), 1);
        var overflow = walk.Overflow;
        var widens = kinds.Any(k => Widen.Contains(k)); var narrows = kinds.Any(k => !Widen.Contains(k));
        var summary = new L(kinds.Select(k =>
        {
            var w0 = (D)shifts[k][0]!;
            return (object?)$"{k}: {shifts[k].Count}+ action(s), e.g. {w0["verb"]} {w0["resource"]} {AtlasPca.Js.JsJson.Stringify(w0.GetValueOrDefault("params") ?? new D())}";
        }));
        var shiftsJ = new D(); foreach (var k in kinds) shiftsJ[k] = shifts[k];
        var d = new D
        {
            ["equivalent"] = kinds.Count == 0 && !overflow && ma.Undecidable.Count == 0 && mb.Undecidable.Count == 0,
            ["shifts"] = shiftsJ, ["widens"] = widens, ["narrows"] = narrows, ["summary"] = summary,
        };
        var exposure = Jx.Opt(o, "exposure");
        if (!Jx.IsUndef(exposure))
        {
            var before = MaxExposure(a, exposure); var after = MaxExposure(b, exposure);
            var pad = Sub(after.PerAction.Max, before.PerAction.Max); var ad = Sub(after.AutonomousWindow.Bound, before.AutonomousWindow.Bound); var dl = Sub(after.Window.Bound, before.Window.Bound);
            d["exposure"] = new D { ["before"] = before.ToJson(), ["after"] = after.ToJson(), ["perActionDelta"] = Jx.NumOut(pad), ["autonomousDelta"] = Jx.NumOut(ad), ["delta"] = Jx.NumOut(dl) };
            var worst = Math.Max(dl, Math.Max(pad, ad)); var best = Math.Min(dl, pad);
            var verb = JsX.Str(Jx.Prop(exposure, "verb"));
            if (worst > 0) summary.Add($"max exposure of {verb} rises by {Jx.NumStr(worst)}");
            else if (best < 0) summary.Add($"max exposure of {verb} falls by {Jx.NumStr(-best)}");
        }
        if (overflow || ma.Undecidable.Count > 0 || mb.Undecidable.Count > 0)
        {
            d["approximate"] = true;
            var u = new Jx.OSet(); foreach (var r in ma.Undecidable) u.Add(r); foreach (var r in mb.Undecidable) u.Add(r);
            d["reason"] = overflow ? "representative grid exceeded the bound" : $"over-approximated ({string.Join("; ", u.ToList())})";
        }
        return d;
    }

    /// <summary>diffGate: refuse a diff that widens authority, raises exposure beyond the allowance, or is inconclusive.</summary>
    public static D DiffGate(object? d, object? allow = null)
    {
        var reasons = new L();
        if (Jx.Truthy(Jx.Prop(d, "widens")) && !(Jx.Opt(allow, "widen") is true))
        {
            var sm = Iter(Jx.Prop(d, "summary")).Where(s => s is string ss && Widen.Any(k => ss.StartsWith(k, StringComparison.Ordinal)));
            reasons.Add("widens authority: " + string.Join("; ", sm.Select(s => (string)s!)));
        }
        double rise = 0;
        var ex = Jx.Prop(d, "exposure");
        if (Jx.Truthy(ex)) rise = Math.Max(Jx.ToNumber(Jx.Prop(ex, "delta")), Math.Max(Jx.ToNumber(Jx.Prop(ex, "perActionDelta")), Jx.ToNumber(Jx.Prop(ex, "autonomousDelta"))));
        var mi = Jx.Opt(allow, "maxExposureIncrease");
        if (rise > (mi == null || Jx.IsUndef(mi) ? 0 : Jx.ToNumber(mi))) reasons.Add($"max exposure rises by {Jx.NumStr(rise)}");
        if (Jx.Truthy(Jx.Prop(d, "approximate")))
        {
            var rs = Jx.Prop(d, "reason");
            reasons.Add("inconclusive: " + (rs == null || Jx.IsUndef(rs) ? "approximate" : JsX.Str(rs)));
        }
        return new D { ["ok"] = reasons.Count == 0, ["reasons"] = reasons };
    }

    /// <summary>findWithBackend: ask a solver backend for a witness and re-check it with the evaluator; a solver's unsat claim is never trusted as proof.</summary>
    public static D FindWithBackend(string backendName, Func<D, D> find, D q)
    {
        var r = find(q);
        if (r.TryGetValue("witness", out var wit) && wit != null)
        {
            var ma = Enumerate.ToModel(q["a"]);
            bool ok;
            if (q.GetValueOrDefault("kind") as string == "reachable")
                ok = Enumerate.DecideAction(ma, wit) != "deny" && (!q.TryGetValue("verb", out var qv) || qv == null || Jx.Prop(wit, "verb") is string wv && qv is string qs && wv == qs);
            else
                ok = q.TryGetValue("b", out var qb) && qb != null && (Enumerate.DecideAction(ma, wit) != "deny") != (Enumerate.DecideAction(Enumerate.ToModel(qb), wit) != "deny");
            return ok ? new D { ["witness"] = wit } : new D { ["rejected"] = true };
        }
        if (r.GetValueOrDefault("unsat") is true)
            return new D { ["claimedUnsat"] = new D { ["by"] = backendName, ["proof"] = "solver-claimed, not machine-checked" } };
        return new D();
    }
}

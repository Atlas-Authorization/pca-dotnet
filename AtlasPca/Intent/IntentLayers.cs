// The layered intent lattice (org ceiling, site policy, standing profile, task grant: deny anywhere wins, a ceiling is never a question), the quorum
// of principal-signed approvals that a shared layer needs to widen, the joint-grant rules of multi-principal intent (unanimity, quorum(k), weighted with
// a threshold, plus vetoers), the common refinement of several outcome spaces, and the measurement of a grant against an intent.
using AtlasPca.InteropJs;
using static AtlasPca.IntentPkg.IntentOmega;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.IntentPkg;

/// <summary>The joint-grant rules of multi-principal intent and the common refinement of several outcome spaces. A rule is a JSON tree {kind, vetoers?, k?, weights?, threshold?}.</summary>
public static class IntentMulti
{
    /// <summary>A rule in normal form: integer weights, an integer threshold, per-principal veto flags.</summary>
    public sealed record NormalRule(double[] Weights, double Threshold, bool[] Veto)
    {
        public D ToJson() => new()
        {
            ["weights"] = Weights.Select(x => N(x)).ToList(),
            ["threshold"] = N(Threshold),
            ["veto"] = Veto.Select(x => (object?)x).ToList(),
        };

        public static NormalRule FromJson(object? o)
        {
            var m = Obj(o);
            var w = Arr(m.GetValueOrDefault("weights"));
            var v = Arr(m.GetValueOrDefault("veto"));
            return new NormalRule(w.Select(Dbl).ToArray(), Dbl(m.GetValueOrDefault("threshold")), v.Select(x => (bool)x!).ToArray());
        }
    }

    static bool IsInteger(object? o)
    {
        if (o == null || !IsNum(o)) return false;
        double d = Dbl(o);
        return double.IsFinite(d) && d == Math.Round(d);
    }

    public static NormalRule NormalizeRule(D rule, List<string> refs)
    {
        var vetoers = new List<string>();
        if (rule.GetValueOrDefault("vetoers") is L vl) foreach (var v in vl) { var s = JsX.Str(v); if (!vetoers.Contains(s)) vetoers.Add(s); }
        foreach (var v in vetoers) if (!refs.Contains(v)) throw new ArgumentException("aggregateIntentMaps: vetoer " + v + " is not one of the maps");
        var veto = refs.Select(r => vetoers.Contains(r)).ToArray();
        var ones = Enumerable.Repeat(1.0, refs.Count).ToArray();
        var kind = rule.GetValueOrDefault("kind");
        if ((kind as string) == "unanimity") return new NormalRule(ones, refs.Count, veto);
        if ((kind as string) == "quorum")
        {
            var k = rule.GetValueOrDefault("k");
            if (!(IsInteger(k) && Dbl(k) >= 1 && Dbl(k) <= refs.Count)) throw new ArgumentException("aggregateIntentMaps: quorum k must be an integer in [1, " + refs.Count + "]");
            return new NormalRule(ones, Dbl(k), veto);
        }
        // rule.weights[ref] on an absent weights table: the engine names the first member it read (no member, no read)
        var wm = rule.GetValueOrDefault("weights") as D ?? (refs.Count == 0 ? new D() : throw new ArgumentException("Cannot read properties of undefined (reading '" + refs[0] + "')"));
        var weights = new double[refs.Count];
        for (int i = 0; i < weights.Length; i++)
        {
            var w = wm.GetValueOrDefault(refs[i]);
            if (!(IsInteger(w) && Dbl(w) >= 0)) throw new ArgumentException("aggregateIntentMaps: every principal needs a non-negative integer weight");
            weights[i] = Dbl(w);
        }
        double total = 0;
        foreach (var w in weights) total += w;
        var t = rule.GetValueOrDefault("threshold");
        if (!(IsInteger(t) && Dbl(t) >= 1 && Dbl(t) <= total)) throw new ArgumentException("aggregateIntentMaps: threshold must be an integer in [1, " + JsX.JsNumString(total) + "]");
        return new NormalRule(weights, Dbl(t), veto);
    }

    /// <summary>Principals that bound the joint grant: explicit vetoers plus implicit ones (threshold &gt; W - w_i).</summary>
    public static List<string> EffectiveVetoers(D rule, List<string> refs)
    {
        var n = NormalizeRule(rule, refs);
        double total = 0;
        foreach (var w in n.Weights) total += w;
        var o = new List<string>();
        for (int i = 0; i < refs.Count; i++) if (n.Veto[i] || n.Threshold > total - n.Weights[i]) o.Add(refs[i]);
        return o;
    }

    /// <summary>Does the rule admit, given which principals admit (vetoers must; the admitting weight must reach the threshold)?</summary>
    public static bool RuleAdmits(NormalRule n, bool[] ins)
    {
        double s = 0;
        for (int i = 0; i < ins.Length; i++)
        {
            if (n.Veto[i] && !ins[i]) return false;
            if (ins[i]) s += n.Weights[i];
        }
        return s >= n.Threshold;
    }

    /// <summary>P(rule admits) with independent Bernoulli(p_i) acceptances: DP over the capped admitting weight.</summary>
    public static double JointAcceptance(NormalRule n, double[] ps)
    {
        int cap = (int)n.Threshold;
        var dist = new double[cap + 1];
        dist[0] = 1;
        for (int i = 0; i < ps.Length; i++)
        {
            var next = new double[cap + 1];
            double w = n.Weights[i];
            double p = ps[i];
            for (int s = 0; s <= cap; s++)
            {
                double m = dist[s];
                if (m == 0) continue;
                int to = (int)Math.Min(cap, s + w);
                next[to] = next[to] + m * p;
                if (!n.Veto[i]) next[s] = next[s] + m * (1 - p);
            }
            dist = next;
        }
        return dist[cap];
    }

    // ---- common refinement ----

    static readonly string[] Sev = { "reversible", "rate_limited", "irreversible" };

    static Dim MergeDim(Dim a, Dim b)
    {
        if (a.Kind != b.Kind) throw new ArgumentException("commonRefinement: " + a.Path + " is numeric in one Omega and categorical in another");
        if (a is NumDim x && b is NumDim y)
        {
            if (x.Lo != y.Lo || x.Hi != y.Hi)
                throw new ArgumentException("commonRefinement: " + a.Path + " has different domains ([" + JsX.JsNumString(x.Lo) + ", " + JsX.JsNumString(x.Hi)
                    + "] vs [" + JsX.JsNumString(y.Lo) + ", " + JsX.JsNumString(y.Hi) + "])");
            var cuts = new SortedSet<double>();
            foreach (var c in x.Cuts) cuts.Add(c + 0.0);
            foreach (var c in y.Cuts) cuts.Add(c + 0.0);
            return new NumDim(a.Path, x.Lo, x.Hi, cuts.ToArray(), x.Dist);
        }
        var ex = new SortedSet<string>(StringComparer.Ordinal);
        var pre = new SortedSet<string>(StringComparer.Ordinal);
        foreach (var v in ((CatDim)a).Values.Concat(((CatDim)b).Values))
        {
            if (v.Kind == "exact") ex.Add(v.Value);
            else if (v.Kind == "prefix") pre.Add(v.Value);
        }
        var values = new List<CatValue>();
        foreach (var v in ex) values.Add(new CatValue("exact", v));
        foreach (var v in pre) values.Add(new CatValue("prefix", v));
        values.Add(new CatValue("other", Other));
        return new CatDim(a.Path, values);
    }

    /// <summary>The union of the spaces' verbs, dimensions, cuts and named values (every input cell is a union of result cells).</summary>
    public static Omega CommonRefinement(IEnumerable<Omega> omegas)
    {
        var revs = new Dictionary<string, string>();
        var dimsByVerb = new Dictionary<string, List<Dim>>();
        var approx = new SortedSet<string>(StringComparer.Ordinal);
        foreach (var o in omegas)
        {
            foreach (var a in o.Approximate) approx.Add(a);
            foreach (var vs in o.Verbs)
            {
                if (!dimsByVerb.TryGetValue(vs.Verb, out var cur))
                {
                    revs[vs.Verb] = vs.Reversibility;
                    dimsByVerb[vs.Verb] = vs.Dims.Select(d => DimFromJson(DimToJson(d))).ToList();
                    continue;
                }
                if (Array.IndexOf(Sev, vs.Reversibility) > Array.IndexOf(Sev, revs[vs.Verb])) revs[vs.Verb] = vs.Reversibility;
                foreach (var d in vs.Dims)
                {
                    int i = cur.FindIndex(x => x.Path == d.Path);
                    if (i < 0) cur.Add(DimFromJson(DimToJson(d)));
                    else cur[i] = MergeDim(cur[i], d);
                }
            }
        }
        var names = new SortedSet<string>(dimsByVerb.Keys, StringComparer.Ordinal).ToList();
        var verbs = new List<VerbSpace>();
        foreach (var v in names)
        {
            var dims = dimsByVerb[v].OrderBy(x => x.Path, StringComparer.Ordinal).ToList();
            verbs.Add(new VerbSpace(v, revs[v], 1.0 / names.Count, dims));
        }
        return new Omega(verbs, approx.ToList());
    }
}

/// <summary>Measuring a grant against an intent over the outcome space: risk R(G) = E[1_G (1 - a) h], burden B(G) = E[1_notG a], R_max = E[(1 - a) h],
/// fidelity F = 1 - R / R_max, by Monte Carlo with the real evaluator on both sides or exactly by summing over cells.</summary>
public static class IntentMetrics
{
    /// <summary>The acceptability of an outcome in [0, 1].</summary>
    public delegate double Acceptability(VerbSpace vs, Outcome o);

    public static Acceptability AcceptabilityOf(object? policy)
    {
        var a = IntentPolicyKit.MakeAdmitter(policy);
        return (vs, o) => a.Admits(vs, o) ? 1 : 0;
    }

    public sealed record GrantMetrics(double Risk, double Burden, double RiskMax, double Fidelity, double Samples, double RiskHalfWidth, double? MeanHarm)
    {
        public D ToJson()
        {
            var m = new D { ["risk"] = N(Risk), ["burden"] = N(Burden), ["riskMax"] = N(RiskMax), ["fidelity"] = N(Fidelity) };
            if (MeanHarm == null)
            {
                m["samples"] = N(Samples);
                m["riskHalfWidth"] = N(RiskHalfWidth);
            }
            else m["meanHarm"] = N(MeanHarm.Value);
            return m;
        }
    }

    /// <summary>Monte Carlo over the workload; hMax null = the largest harm drawn.</summary>
    public static GrantMetrics MeasureGrant(Omega omega, object? grant, Acceptability acceptability, double samples = 20000, double seed = 1, HarmModel? harm = null, double? hMax = null)
    {
        harm ??= DefaultHarmModel;
        double count = samples;
        var rand = Rng(seed);
        var g = IntentPolicyKit.MakeAdmitter(grant);
        double r = 0, b = 0, rm = 0, hm = 0;
        for (double i = 0; i < count; i++)
        {
            var s = SampleOutcome(omega, rand);
            double a = acceptability(s.Vs, s.O);
            double h = HarmOf(s.Vs, s.O, harm);
            hm = Math.Max(hm, h);
            if (g.Admits(s.Vs, s.O)) r += (1 - a) * h;
            else b += a;
            rm += (1 - a) * h;
        }
        r /= count;
        b /= count;
        rm /= count;
        return new GrantMetrics(r, b, rm, rm > 0 ? 1 - r / rm : 1, count, IntentStats.HoeffdingHalfWidth(hMax ?? hm, count), null);
    }

    /// <summary>Exact R, B, R_max, F by summing over the cells; valid when grant and acceptability are constant on each cell.</summary>
    public static GrantMetrics MeasureGrantExact(Omega omega, object? grant, Acceptability acceptability, HarmModel? harm = null)
    {
        harm ??= DefaultHarmModel;
        var g = IntentPolicyKit.MakeAdmitter(grant);
        double r = 0, b = 0, rm = 0, eh = 0;
        foreach (var vs in omega.Verbs)
        {
            double n = VerbCellCount(vs);
            for (double c = 0; c < n; c++)
            {
                var idx = DecodeCell(vs, c);
                var o = CellRep(vs, idx);
                var st = CellStats(vs, idx, harm);
                double a = acceptability(vs, o);
                eh += st.Mass * st.Harm;
                rm += st.Mass * (1 - a) * st.Harm;
                if (g.Admits(vs, o)) r += st.Mass * (1 - a) * st.Harm;
                else b += st.Mass * a;
            }
        }
        return new GrantMetrics(r, b, rm, rm > 0 ? 1 - r / rm : 1, 0, 0, eh);
    }
}

public static class IntentLayers
{
    /// <summary>The ceilings in evaluation order.</summary>
    public static readonly string[] LayerCeilings = { "org", "site", "std" };
    public const string LayerApprovalDomain = "atlas-pca/intent-layer-approval/v1\0";

    /// <summary>Compiled ceilings; an absent ceiling is null.</summary>
    public sealed record CeilingAdmitters(IntentPolicyKit.Admitter? Org, IntentPolicyKit.Admitter? Site, IntentPolicyKit.Admitter? Std)
    {
        internal IntentPolicyKit.Admitter? Of(string k) => k == "org" ? Org : k == "site" ? Site : Std;
    }

    /// <summary>Absent = no ceiling; a ceiling PRESENT with null (or not an object) is malformed: throws.</summary>
    public static CeilingAdmitters MakeCeilingAdmitters(D layers)
    {
        var o = new IntentPolicyKit.Admitter?[3];
        for (int i = 0; i < 3; i++)
        {
            var k = LayerCeilings[i];
            if (!layers.ContainsKey(k)) continue;
            if (layers[k] is not D) throw new ArgumentException("ceilingAdmitters: the " + k + " ceiling is malformed (null or not an object)");
            o[i] = IntentPolicyKit.MakeAdmitter(layers[k]);
        }
        return new CeilingAdmitters(o[0], o[1], o[2]);
    }

    /// <summary>The first ceiling that excludes the outcome, or null when every ceiling admits it.</summary>
    public static string? CeilingOf(CeilingAdmitters c, VerbSpace vs, Outcome o)
    {
        foreach (var k in LayerCeilings)
        {
            var a = c.Of(k);
            if (a != null && !a.Admits(vs, o)) return k;
        }
        return null;
    }

    /// <summary>The verifier side of the layers check: <see cref="Pass"/>, else the <see cref="Layer"/> (org, site or std) that refused and why.</summary>
    public sealed record LayerCeilingDecision(bool Pass, string? Layer = null, string? Reason = null);

    /// <summary>The full layer decision: <c>admit</c> (<see cref="By"/> 0 for the task grant, k for delta k), <c>ceiling</c> (<see cref="Layer"/>), <c>intent_denied</c> or <c>intent_required</c>.</summary>
    public sealed record LayerDecision(string Decision, long By = 0, string? Layer = null);

    /// <summary>A well-formed layer: an object whose only member is <c>predicates</c>, a list.</summary>
    public static bool IsLayerPolicy(object? l) => l is D d && d.Count == 1 && d.TryGetValue("predicates", out var p) && p is L;

    static bool LayerAdmits(object? layer, D ctx) => Predicates.EvaluatePredicates(((D)layer!)["predicates"], ctx);

    static LayerCeilingDecision CeilingsOf(object? layers, D ctx)
    {
        try
        {
            if (layers is not D ld) return new(false, "org", "layers: the layers member is malformed (not an object)");
            foreach (var k in LayerCeilings)
            {
                if (!ld.TryGetValue(k, out var layer)) continue;
                if (!IsLayerPolicy(layer)) return new(false, k, $"layers: the {k} ceiling is malformed (null or not {{predicates: [...]}})");
                if (!LayerAdmits(layer, ctx)) return new(false, k, $"layers: the action is outside the {k} ceiling (a ceiling is never a question)");
            }
            return new(true);
        }
        catch (Exception e) { return new(false, "org", "layers: evaluation error (fail closed): " + e.Message); }
    }

    /// <summary>The <c>layers</c> check of the v2 verification order: the action must be inside G^org, then G^site, then G^std (an absent ceiling is no constraint). The first
    /// ceiling that denies is named. An unknown member, a ceiling that is not exactly <c>{predicates: [...]}</c> (null included) and an empty predicate list all fail. Never throws.</summary>
    public static LayerCeilingDecision DecideLayerCeilings(object? layers, D ctx) =>
        layers is D ld && ld.Keys.Any(k => !LayerCeilings.Contains(k))
            ? new(false, "org", "layers: unknown member (the layers object is {org?, site?, std?})")
            : CeilingsOf(layers, ctx);

    /// <summary>The full layer decision for one action: outside a ceiling is <c>ceiling</c>; inside a denied region <c>intent_denied</c>; inside the task grant or a delta <c>admit</c>;
    /// otherwise <c>intent_required</c>. A malformed grant (an unknown member, a non-list <c>task</c> or <c>denied</c>, a malformed entry) is <c>intent_denied</c>. Never throws.</summary>
    public static LayerDecision DecideLayers(object? grant, D ctx)
    {
        try
        {
            if (grant is D gd && gd.Keys.Any(k => !LayerCeilings.Contains(k) && k is not ("task" or "denied"))) return new("intent_denied");
            var c = CeilingsOf(grant, ctx);
            if (!c.Pass) return new("ceiling", 0, c.Layer);
            var g = (D)grant!;
            var denied = g.TryGetValue("denied", out var dn) ? dn : new L();
            g.TryGetValue("task", out var task);
            if (denied is not L dl || !dl.All(IsLayerPolicy) || task is not L tl || !tl.All(IsLayerPolicy)) return new("intent_denied");
            if (dl.Any(d => LayerAdmits(d, ctx))) return new("intent_denied");
            for (var i = 0; i < tl.Count; i++) if (LayerAdmits(tl[i], ctx)) return new("admit", i);
            return new("intent_required");
        }
        catch (Exception) { return new("intent_denied"); }
    }

    static string Key(string verb, L cell) => verb + "|" + string.Join(",", cell.Select(x => JsX.JsNumString(Dbl(x))));

    /// <summary>A question may only be about a cell of the uncertain set (inside every ceiling). Throws otherwise.</summary>
    public static void AssertAskable(D view, D c)
    {
        var k = Key((string)c["verb"]!, Arr(c.GetValueOrDefault("cell")));
        foreach (var u in Arr(view.GetValueOrDefault("uncertain")))
        {
            var um = Obj(u);
            if (Key((string)um["verb"]!, Arr(um.GetValueOrDefault("cell"))) == k) return;
        }
        throw new ArgumentException("layers: cell " + k + " is not an uncertain cell inside every ceiling (never a question)");
    }

    /// <summary>Layer owner's own risk of a set of cells ({verb, cell}): sum of mass * (1 - a) * E[h | cell].</summary>
    public static double OwnerRisk(Omega omega, IEnumerable<D> cells, IntentMetrics.Acceptability acceptability, HarmModel? harm = null)
    {
        harm ??= DefaultHarmModel;
        double r = 0;
        foreach (var c in cells)
        {
            var vs = VerbSpaceOf(omega, (string)c["verb"]!);
            if (vs == null) continue;
            var idx = Arr(c.GetValueOrDefault("cell")).Select(x => (int)Dbl(x)).ToArray();
            var st = CellStats(vs, idx, harm);
            r += st.Mass * (1 - acceptability(vs, CellRep(vs, idx))) * st.Harm;
        }
        return r;
    }

    /// <summary>Every cell of the space an admitter admits (the layer as a cell set).</summary>
    public static List<D> LayerCells(Omega omega, IntentPolicyKit.Admitter a)
    {
        var o = new List<D>();
        foreach (var vs in omega.Verbs)
        {
            double n = VerbCellCount(vs);
            for (double f = 0; f < n; f++)
            {
                var cell = DecodeCell(vs, f);
                if (a.Admits(vs, CellRep(vs, cell))) o.Add(new D { ["verb"] = vs.Verb, ["cell"] = cell.Select(x => (object?)N(x)).ToList() });
            }
        }
        return o;
    }

    /// <summary>Flat key of a cell ({verb, cell}).</summary>
    public static string CellKeyOf(Omega omega, D c)
    {
        var verb = (string)c["verb"]!;
        var vs = VerbSpaceOf(omega, verb);
        var cl = Arr(c.GetValueOrDefault("cell"));
        if (vs == null) return Key(verb, cl);
        var idx = cl.Select(x => (int)Dbl(x)).ToArray();
        return verb + "|" + JsX.JsNumString(EncodeCell(vs, idx));
    }

    // ---- quorum-signed layer approvals ----

    static readonly string[] StatementKeys = { "v", "kind", "layer", "session", "seq", "map_digest", "prev" };

    static D StatementOf(D a)
    {
        var st = new D { ["v"] = new Num("1"), ["kind"] = "pca-intent-layer-approval" };
        foreach (var k in new[] { "layer", "session", "seq", "map_digest", "prev" }) if (a.ContainsKey(k)) st[k] = a[k];
        return st;
    }

    static byte[] ApprovalMessage(D st) => IntentJs.Message(LayerApprovalDomain, st);

    /// <summary>Sign an approval of a shared-layer widening ({layer, session, seq, map_digest, prev}).</summary>
    public static D SignLayerApproval(D s, byte[] secretSeed)
    {
        using var key = EdKey.FromSeed(secretSeed);
        var st = StatementOf(s);
        var o = new D(st) { ["signer"] = key.Id, ["sig"] = Pca.B64u(key.Sign(ApprovalMessage(st))) };
        return o;
    }

    static bool StrictEq(object? a, object? b)
    {
        if (a == null || b == null) return a == null && b == null;
        var x = IntentJs.NumOf(a);
        var y = IntentJs.NumOf(b);
        if (x != null || y != null) return x != null && y != null && x.Value == y.Value;
        if (a is string || a is bool) return a.Equals(b);
        return ReferenceEquals(a, b);
    }

    static D QuorumResult(bool ok, List<string> signers, List<D> ignored) => new()
    {
        ["ok"] = ok,
        ["signers"] = signers.Select(x => (object?)x).ToList(),
        ["ignored"] = ignored.Select(x => (object?)x).ToList(),
    };

    static D Ign(int index, string reason) => new() { ["index"] = N(index), ["reason"] = reason };

    /// <summary>Verify approvals against the layer's members and rule. An approval counts iff its signer is a member, it is the FIRST from that member, its statement
    /// equals expected field by field and its signature verifies; the rule is the multi-principal one over member keys. Returns {ok, signers, ignored[{index, reason}]}.</summary>
    public static D VerifyQuorumApprovals(object? approvals, object? members, D rule, object? expected)
    {
        var none = new List<D>();
        if (approvals is not L aps || members is not L ms || expected is not D)
        {
            none.Add(Ign(-1, "approvals and members must be arrays and expected an object"));
            return QuorumResult(false, new List<string>(), none);
        }
        bool bad = false;
        foreach (var m in ms) if (m is not string || !IntentJs.B32(m)) bad = true;
        if (!bad && new HashSet<string>(ms.Select(x => (string)x!), StringComparer.Ordinal).Count != ms.Count) bad = true;
        if (bad)
        {
            none.Add(Ign(-1, "members must be distinct 32-byte keys"));
            return QuorumResult(false, new List<string>(), none);
        }
        var mem = ms.Select(x => (string)x!).ToList();
        IntentMulti.NormalRule n;
        try
        {
            n = IntentMulti.NormalizeRule(rule, mem);
        }
        catch (Exception e)
        {
            none.Add(Ign(-1, e.Message));
            return QuorumResult(false, new List<string>(), none);
        }
        var want = StatementOf(Obj(expected));
        var counted = new HashSet<string>(StringComparer.Ordinal);
        var ignored = new List<D>();
        for (int i = 0; i < aps.Count; i++)
        {
            var ao = aps[i];
            if (ao is not D && ao is not L) { ignored.Add(Ign(i, "not an object")); continue; }
            if (ao is L) { ignored.Add(Ign(i, "signer is not a member")); continue; }
            var a = (D)ao;
            var signer = a.GetValueOrDefault("signer");
            if (!(signer is string sg && mem.Contains(sg))) { ignored.Add(Ign(i, "signer is not a member")); continue; }
            if (counted.Contains(sg)) { ignored.Add(Ign(i, "second approval from the same member")); continue; }
            var st = StatementOf(a);
            bool same = true;
            foreach (var k in StatementKeys)
            {
                var x = st.GetValueOrDefault(k);
                var y = want.GetValueOrDefault(k);
                bool xd = st.ContainsKey(k), yd = want.ContainsKey(k);
                if (xd != yd || (xd && !StrictEq(x, y))) same = false;
            }
            same = same && StrictEq(a.GetValueOrDefault("v"), new Num("1")) && (a.GetValueOrDefault("kind") as string) == "pca-intent-layer-approval";
            if (!same) { ignored.Add(Ign(i, "approval is for another (layer, session, seq, map_digest, prev)")); continue; }
            bool ok;
            try
            {
                ok = IntentJs.VerifyEd(sg, ApprovalMessage(st), a.GetValueOrDefault("sig"));
            }
            catch (Exception)
            {
                ok = false;
            }
            if (!ok) { ignored.Add(Ign(i, "bad signature")); continue; }
            counted.Add(sg);
        }
        var signers = new List<string>();
        var ins = new bool[mem.Count];
        for (int i = 0; i < mem.Count; i++)
        {
            ins[i] = counted.Contains(mem[i]);
            if (ins[i]) signers.Add(mem[i]);
        }
        return QuorumResult(IntentMulti.RuleAdmits(n, ins), signers, ignored);
    }
}

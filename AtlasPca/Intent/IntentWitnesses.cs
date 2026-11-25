// Specification by example for a fixed grant: boundary facets (admission changes when exactly one dimension moves to an adjacent
// cell), one verb witness per verb, and one unconstrained witness per dimension the grant ignores. The question count is linear in
// the number of facets, not in the size of the space.
using static AtlasPca.IntentPkg.IntentOmega;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.IntentPkg;

public static class IntentWitnesses
{
    /// <summary>One question: an action inside or outside the grant, isolating one literal.</summary>
    public sealed record Witness(string Kind, string Side, string Verb, int[] Cell, Outcome Outcome, bool GrantAllows, string Facet, string Question)
    {
        public D ToJson() => new()
        {
            ["kind"] = Kind,
            ["side"] = Side,
            ["verb"] = Verb,
            ["cell"] = Cell.Select(x => (object?)N(x)).ToList(),
            ["outcome"] = OutcomeToJson(Outcome),
            ["grantAllows"] = GrantAllows,
            ["facet"] = Facet,
            ["question"] = Question,
        };

        public static Witness FromJson(object? o)
        {
            var m = Obj(o);
            return new Witness(Str(m.GetValueOrDefault("kind")), Str(m.GetValueOrDefault("side")), Str(m.GetValueOrDefault("verb")),
                Arr(m.GetValueOrDefault("cell")).Select(x => (int)Dbl(x)).ToArray(), OutcomeFromJson(m.GetValueOrDefault("outcome")),
                m.GetValueOrDefault("grantAllows") is true, Str(m.GetValueOrDefault("facet")), Str(m.GetValueOrDefault("question")));
        }
    }

    sealed class Best
    {
        public int[] Ins = Array.Empty<int>();
        public int[] Outs = Array.Empty<int>();
        public double Score;
    }

    public static List<Witness> BoundaryWitnesses(object? grant, Omega omega, Catalog? catalog = null)
    {
        catalog ??= Catalog.Default;
        var g = IntentPolicyKit.MakeAdmitter(grant);
        var output = new List<Witness>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        void Push(VerbSpace vs, string kind, int[] idx, bool allows, string facet)
        {
            var key = vs.Verb + "|" + string.Join(",", idx);
            if (!seen.Add(key)) return;
            output.Add(new Witness(kind, allows ? "inside" : "outside", vs.Verb, (int[])idx.Clone(), CellRep(vs, idx), allows, facet, IntentRender.RenderQuestion(vs, idx, catalog)));
        }
        foreach (var vs in omega.Verbs)
        {
            int n = (int)VerbCellCount(vs);
            var acc = new bool[n];
            var mass = new double[n];
            int typical = -1, typicalOut = -1;
            for (int c = 0; c < n; c++)
            {
                var idx = DecodeCell(vs, c);
                acc[c] = g.Admits(vs, CellRep(vs, idx));
                mass[c] = CellStats(vs, idx).Mass;
                if (acc[c] && (typical < 0 || mass[c] > mass[typical])) typical = c;
                if (typicalOut < 0 || mass[c] > mass[typicalOut]) typicalOut = c;
            }
            if (typical < 0)
            {
                Push(vs, "verb", DecodeCell(vs, typicalOut), false, vs.Verb + "|verb");
                continue;
            }
            var bas = DecodeCell(vs, typical);
            Push(vs, "verb", bas, true, vs.Verb + "|verb");
            var best = new Dictionary<string, Best>(StringComparer.Ordinal);
            for (int c = 0; c < n; c++)
            {
                if (!acc[c]) continue;
                var idx = DecodeCell(vs, c);
                for (int k = 0; k < vs.Dims.Count; k++)
                {
                    var d = vs.Dims[k];
                    int nk = CellCount(d);
                    var neigh = new List<int>();
                    if (d is NumDim) { foreach (var x in new[] { idx[k] - 1, idx[k] + 1 }) if (x >= 0 && x < nk) neigh.Add(x); }
                    else for (int x = 0; x < nk; x++) if (x != idx[k]) neigh.Add(x);
                    foreach (var x in neigh)
                    {
                        var j = (int[])idx.Clone();
                        j[k] = x;
                        int cj = (int)EncodeCell(vs, j);
                        if (acc[cj]) continue;
                        var facet = d is NumDim ? vs.Verb + "|" + d.Path + "|" + Math.Min(x, idx[k]) + "~" + Math.Max(x, idx[k]) : vs.Verb + "|" + d.Path + "|" + x;
                        int shared = 0;
                        for (int t = 0; t < idx.Length; t++) if (t != k && idx[t] == bas[t]) shared++;
                        double score = shared * 10 + mass[c];
                        if (!best.TryGetValue(facet, out var prev) || score > prev.Score) best[facet] = new Best { Ins = idx, Outs = j, Score = score };
                    }
                }
            }
            foreach (var facet in best.Keys.OrderBy(f => f, StringComparer.Ordinal))
            {
                Push(vs, "boundary", best[facet].Ins, true, facet);
                Push(vs, "boundary", best[facet].Outs, false, facet);
            }
            for (int k = 0; k < vs.Dims.Count; k++)
            {
                var d = vs.Dims[k];
                int nk = CellCount(d);
                if (nk < 2) continue;
                bool depends = false;
                for (int c = 0; c < n && !depends; c++)
                {
                    var idx = DecodeCell(vs, c);
                    for (int x = 0; x < nk && !depends; x++)
                    {
                        var j = (int[])idx.Clone();
                        j[k] = x;
                        if (acc[(int)EncodeCell(vs, j)] != acc[c]) depends = true;
                    }
                }
                if (depends) continue;
                var jj = (int[])bas.Clone();
                jj[k] = d is NumDim ? nk - 1 : ((CatDim)d).Values.FindIndex(v => v.Kind == "other");
                Push(vs, "unconstrained", jj, true, vs.Verb + "|" + d.Path + "|unconstrained");
            }
        }
        return output;
    }

    /// <summary>The oracle's disagreements with the grant, with the number of questions asked.</summary>
    public sealed record WitnessCheck(int Questions, List<Witness> Mismatches);

    /// <summary>Ask an oracle (the principal) about each witness; a mismatch is a place where grant and intent disagree.</summary>
    public static WitnessCheck CheckWitnesses(IReadOnlyList<Witness> witnesses, Func<Witness, bool> oracle) =>
        new(witnesses.Count, witnesses.Where(w => oracle(w) != w.GrantAllows).ToList());
}

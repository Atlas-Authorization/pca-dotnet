// Dimensions beyond the action's own parameters: world state (an observed quantity such as slack against an optimum), argument
// provenance, and classifier labels. Each lives under its own path prefix; an outcome is lifted onto them from an environment of
// observed values.
using static AtlasPca.IntentPkg.IntentOmega;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.IntentPkg;

public static class IntentWorld
{
    public const string WorldPrefix = "env.world.";
    public const string ProvPrefix = "env.prov.";
    public const string ClassPrefix = "env.class.";

    /// <summary>A numeric world dimension; <paramref name="cuts"/> may be null, <paramref name="dist"/> null = uniform.</summary>
    public static NumDim WorldDim(string name, double lo, double hi, IEnumerable<double>? cuts = null, string? dist = null)
    {
        var uniq = new List<double>();
        foreach (var c in cuts ?? Array.Empty<double>()) { var v = c + 0.0; if (!uniq.Contains(v)) uniq.Add(v); }
        var kept = uniq.Where(c => c >= lo && c <= hi).OrderBy(c => c).ToArray();
        return new NumDim(WorldPrefix + name, lo, hi, kept, dist ?? "uniform");
    }

    /// <summary>Excess over an optimum: cut at 0 and at each slack, log-uniform.</summary>
    public static NumDim ExcessDim(string name, double hi, IEnumerable<double>? slacks = null) =>
        WorldDim(name, 0, hi, new[] { 0.0 }.Concat(slacks ?? Array.Empty<double>()), "loguniform");

    /// <summary>The condition "the observed quantity is at most the slack".</summary>
    public static D OptimalityCondition(string name, double slack = 0) => new() { ["field"] = WorldPrefix + name, ["op"] = "lte", ["value"] = N(slack) };

    public static CatDim ProvenanceDim(string paramPath) => new(ProvPrefix + paramPath, new List<CatValue>
    {
        new("exact", "first_party"), new("exact", "trusted"), new("other", Other),
    });

    public static CatDim ClassifierDim(string id, IEnumerable<string> labels)
    {
        var sorted = labels.Distinct(StringComparer.Ordinal).ToList();
        sorted.Sort(IntentJs.CompareUtf8);
        var values = sorted.Select(v => new CatValue("exact", v)).ToList();
        values.Add(new CatValue("other", Other));
        return new CatDim(ClassPrefix + id, values);
    }

    /// <summary>The space with <paramref name="dims"/> added to one verb (a duplicate path throws), dimensions re-sorted by path.</summary>
    public static Omega WithDims(Omega omega, string verb, IReadOnlyList<Dim> dims)
    {
        var verbs = new List<VerbSpace>();
        bool found = false;
        foreach (var vs in omega.Verbs)
        {
            if (vs.Verb != verb) { verbs.Add(new VerbSpace(vs.Verb, vs.Reversibility, vs.Weight, new List<Dim>(vs.Dims))); continue; }
            found = true;
            var have = new HashSet<string>(vs.Dims.Select(d => d.Path), StringComparer.Ordinal);
            foreach (var d in dims) if (have.Contains(d.Path)) throw new InvalidOperationException($"withDims: {verb} already has a dimension {d.Path}");
            var all = vs.Dims.Concat(dims).OrderBy(d => d.Path, StringComparer.Ordinal).ToList(); // stable, UTF-16 order
            verbs.Add(new VerbSpace(vs.Verb, vs.Reversibility, vs.Weight, all));
        }
        if (!found) throw new InvalidOperationException($"withDims: no verb {verb} in the space");
        return new Omega(verbs, omega.Approximate);
    }

    static object? Get(object? root, params string[] segs)
    {
        var cur = root;
        foreach (var s in segs)
        {
            if (cur is not D m || !m.TryGetValue(s, out var next)) return null;
            cur = next;
        }
        return cur;
    }

    /// <summary>Lift an outcome onto the world / provenance / classifier dimensions from the environment {world?, prov?, class?} (a JSON object).</summary>
    public static Outcome LiftOutcome(Outcome o, D env, IEnumerable<string> dimPaths)
    {
        var values = new Dictionary<string, object?>(o.Values);
        foreach (var p in dimPaths)
        {
            if (p.StartsWith(WorldPrefix, StringComparison.Ordinal))
            {
                var v = Get(env.GetValueOrDefault("world"), p[WorldPrefix.Length..]);
                if (IntentJs.NumOf(v) is double d) values[p] = d;
                else if (v is string) values[p] = v;
            }
            else if (p.StartsWith(ProvPrefix, StringComparison.Ordinal))
            {
                var v = Get(env.GetValueOrDefault("prov"), p[ProvPrefix.Length..].Split('.'));
                values[p] = v is string ? v : "agent";
            }
            else if (p.StartsWith(ClassPrefix, StringComparison.Ordinal))
            {
                var v = Get(env.GetValueOrDefault("class"), p[ClassPrefix.Length..]);
                if (v is string) values[p] = v;
            }
        }
        return new Outcome(o.Verb, values);
    }
}

// Deriving the outcome space from the vocabulary of the policies and the structured intent slots (every literal a policy or a slot
// mentions becomes a cut or a value, so each such policy is constant on a cell), and compiling slots into the policy they literally
// describe. Policies, slots and options are JSON trees (Dictionary / List / Num / string / bool / null).
using AtlasPca.InteropJs;
using static AtlasPca.IntentPkg.IntentOmega;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.IntentPkg;

public static class IntentDerive
{
    public sealed record Domain(double Lo, double Hi, string Dist);

    /// <summary>Built-in numeric domains for common fields.</summary>
    public static readonly Dictionary<string, Domain> DefaultDomains = new()
    {
        ["action.params.amount"] = new(0, 100_000, "loguniform"),
        ["env.hour"] = new(0, 23, "uniform"),
        ["action.params.count"] = new(0, 1_000, "loguniform"),
    };

    sealed class FieldLits
    {
        public readonly List<double> Nums = new();
        public readonly SortedSet<string> Exacts = new(StringComparer.Ordinal);
        public readonly SortedSet<string> Prefixes = new(StringComparer.Ordinal);
    }

    static FieldLits Lits(Dictionary<string, FieldLits> m, string path)
    {
        if (!m.TryGetValue(path, out var f)) m[path] = f = new FieldLits();
        return f;
    }

    static void AddNum(FieldLits f, double x)
    {
        if (!double.IsFinite(x)) return;
        foreach (var v in new[] { Math.Floor(x) + 0.0, Math.Ceiling(x) + 0.0 }) if (!f.Nums.Contains(v)) f.Nums.Add(v); // +0.0: a Set holds -0 as 0
    }

    static void CollectCond(object? c, Dictionary<string, FieldLits> m, SortedSet<string> approx)
    {
        if (c is not D cd) return;
        if (cd.ContainsKey("all_of") || cd.ContainsKey("any_of") || cd.ContainsKey("not"))
        {
            if (cd.ContainsKey("all_of") && cd["all_of"] is L all) foreach (var x in all) CollectCond(x, m, approx);
            else if (cd.ContainsKey("any_of") && cd["any_of"] is L any) foreach (var x in any) CollectCond(x, m, approx);
            else if (cd.ContainsKey("not")) CollectCond(cd["not"], m, approx);
            return;
        }
        if (cd.GetValueOrDefault("field") is not string field) return;
        var op = cd.GetValueOrDefault("op");
        if (cd.ContainsKey("ref")) approx.Add($"cross-field ref on {field}");
        if (op is "like" or "matches" or "is_a" or "member_of") approx.Add($"{(string)op} on {field}");
        if (op is "exists")
        {
            Lits(m, field);
            return;
        }
        var f = Lits(m, field);
        var value = cd.GetValueOrDefault("value");
        foreach (var v in value is L vl ? vl : new L { value })
        {
            if (IntentJs.NumOf(v) is double d) AddNum(f, d);
            else if (v is string s) (op is "prefix" ? f.Prefixes : f.Exacts).Add(s);
        }
    }

    static void AddResource(object? r, Dictionary<string, FieldLits> m, SortedSet<string> approx)
    {
        if (r is not string s || s == "*") return;
        if (s.StartsWith("re:", StringComparison.Ordinal))
        {
            approx.Add("re: resource matcher");
            return;
        }
        var f = Lits(m, "action.resource");
        if (s.EndsWith('*')) f.Prefixes.Add(s[..^1]);
        else f.Exacts.Add(s);
    }

    /// <summary>The verbs a predicate names, or null for the wildcard.</summary>
    static List<string>? VerbsOf(object? p)
    {
        if (p == null) throw new InvalidOperationException("Cannot read properties of null (reading 'verb')");
        var v = IntentJs.Get(p, "verb");
        if (v is string s) return s == "*" ? null : new List<string> { s };
        if (v is L l)
        {
            if (l.Any(x => x is "*")) return null;
            return l.OfType<string>().ToList();
        }
        return new List<string>();
    }

    /// <summary>Derive the space from the policies and slots in <paramref name="opts"/> ({policies, slots?, domains?, extraVerbs?}). Wildcard verbs
    /// expand to the verbs of every connector that appears anywhere (the whole catalog when none does).</summary>
    public static Omega DeriveOmega(D opts, Catalog? catalog = null, IEnumerable<CatalogAction>? all = null)
    {
        catalog ??= Catalog.Default;
        var catalogAll = all ?? Catalog.Builtin;
        var approx = new SortedSet<string>(StringComparer.Ordinal);
        var preds = new List<object?>();
        foreach (var p in Arr(opts.GetValueOrDefault("policies"))) preds.AddRange((L)IntentPolicyKit.NormalizePolicy(p)["predicates"]!);
        var explicitVerbs = new SortedSet<string>(StringComparer.Ordinal);
        if (opts.GetValueOrDefault("extraVerbs") is L extra) foreach (var x in extra) explicitVerbs.Add(Str(x));
        bool wildcard = false;
        foreach (var p in preds)
        {
            var vs = VerbsOf(p);
            if (vs == null) wildcard = true;
            else foreach (var v in vs) explicitVerbs.Add(v);
        }
        var slots = opts.GetValueOrDefault("slots");
        if (IntentJs.Get(slots, "verbs") is L sv) foreach (var x in sv) explicitVerbs.Add(Str(x));
        if (wildcard)
        {
            var connectors = new HashSet<string>(explicitVerbs.Select(v => v.Split('.')[0]), StringComparer.Ordinal);
            var pool = connectors.Count > 0 ? catalogAll.Where(s => connectors.Contains(s.Connector)).ToList() : catalogAll.ToList();
            foreach (var s in pool) explicitVerbs.Add(s.Verb);
        }
        var constraints = IntentJs.Get(slots, "constraints") as L ?? new L();
        var domains = opts.GetValueOrDefault("domains") as D;
        var output = new List<VerbSpace>();
        foreach (var verb in explicitVerbs)
        {
            var m = new Dictionary<string, FieldLits>();
            foreach (var p in preds)
            {
                var pv = VerbsOf(p);
                if (pv != null && !pv.Contains(verb)) continue;
                AddResource(IntentJs.Get(p, "resource"), m, approx);
                if (IntentJs.Get(p, "where") is L where) foreach (var c in where) CollectCond(c, m, approx);
            }
            foreach (var sc in constraints)
            {
                if (IntentJs.Own(sc, "verb") && !(IntentJs.Get(sc, "verb") is string sv2 && sv2 == verb)) continue;
                var f = Lits(m, Str(IntentJs.Get(sc, "path")));
                if (IntentJs.NumOf(IntentJs.Get(sc, "max")) is double mx) AddNum(f, mx);
                if (IntentJs.NumOf(IntentJs.Get(sc, "min")) is double mn) AddNum(f, mn);
                if (IntentJs.Get(sc, "oneOf") is L one) foreach (var x in one.OfType<string>()) f.Exacts.Add(x);
                if (IntentJs.Get(sc, "noneOf") is L none) foreach (var x in none.OfType<string>()) f.Exacts.Add(x);
                if (IntentJs.Get(sc, "prefixOneOf") is L pre) foreach (var x in pre.OfType<string>()) f.Prefixes.Add(x);
            }
            var dims = new List<Dim>();
            foreach (var path in m.Keys.OrderBy(k => k, StringComparer.Ordinal))
            {
                var f = m[path];
                if (f.Nums.Count > 0 || (f.Exacts.Count == 0 && f.Prefixes.Count == 0 && DefaultDomains.ContainsKey(path)))
                {
                    var cuts = f.Nums.OrderBy(x => x).ToList();
                    double? dlo = null, dhi = null; string? ddist = null;
                    if (domains != null && domains.GetValueOrDefault(path) is D dom)
                    {
                        dlo = IntentJs.NumOf(dom.GetValueOrDefault("lo"));
                        dhi = IntentJs.NumOf(dom.GetValueOrDefault("hi"));
                        ddist = dom.GetValueOrDefault("dist") as string;
                    }
                    else if (DefaultDomains.TryGetValue(path, out var dd)) { dlo = dd.Lo; dhi = dd.Hi; ddist = dd.Dist; }
                    double maxCut = cuts.Count > 0 ? cuts[^1] : 0, minCut = cuts.Count > 0 ? cuts[0] : 0;
                    double lo = dlo ?? Math.Min(0, minCut - 1);
                    double hi = dhi ?? Math.Max(Math.Max(10, 2 * maxCut), maxCut + 10);
                    string dist = ddist ?? (lo >= 0 ? "loguniform" : "uniform");
                    dims.Add(new NumDim(path, lo, hi, cuts.Where(c => c >= lo && c <= hi).ToArray(), dist));
                }
                else
                {
                    var values = f.Exacts.Select(v => new CatValue("exact", v)).Concat(f.Prefixes.Select(v => new CatValue("prefix", v))).ToList();
                    values.Add(new CatValue("other", Other));
                    dims.Add(new CatDim(path, values));
                }
            }
            var spec = catalog.Get(verb);
            output.Add(new VerbSpace(verb, spec?.Reversibility ?? "irreversible", 0, dims));
        }
        foreach (var v in output) v.Weight = 1.0 / output.Count;
        return new Omega(output, approx.ToList());
    }

    // ---- slots ----

    static D Leaf(string field, string op, object? value) => new() { ["field"] = field, ["op"] = op, ["value"] = value };

    static List<object?> SlotConds(object? sc)
    {
        var output = new List<object?>();
        var path = Str(IntentJs.Get(sc, "path"));
        if (IntentJs.Own(sc, "min")) output.Add(Leaf(path, "gte", IntentJs.Get(sc, "min")));
        if (IntentJs.Own(sc, "max")) output.Add(Leaf(path, "lte", IntentJs.Get(sc, "max")));
        var anyOf = new List<object?>();
        if (IntentJs.Get(sc, "oneOf") is L one && one.Count > 0) anyOf.Add(Leaf(path, "in", new L(one)));
        if (IntentJs.Get(sc, "prefixOneOf") is L pre) foreach (var p in pre) anyOf.Add(Leaf(path, "prefix", p));
        if (anyOf.Count == 1) output.Add(anyOf[0]);
        else if (anyOf.Count > 1) output.Add(new D { ["any_of"] = anyOf });
        if (IntentJs.Get(sc, "noneOf") is L none && none.Count > 0) output.Add(Leaf(path, "nin", new L(none)));
        return output;
    }

    /// <summary>Compile slots into the policy they literally describe (one predicate per slot verb).</summary>
    public static D SlotsToPolicy(object? slots)
    {
        var predicates = new L();
        foreach (var verb in Arr(IntentJs.Get(slots, "verbs")))
        {
            var constraints = Arr(IntentJs.Get(slots, "constraints"));
            var where = new L();
            foreach (var c in constraints)
                if (!IntentJs.Own(c, "verb") || IntentJs.Get(c, "verb") is string cv && verb is string vs && cv == vs) where.AddRange(SlotConds(c));
            var p = new D { ["verb"] = verb, ["resource"] = "*" };
            if (where.Count > 0) p["where"] = where;
            predicates.Add(p);
        }
        return new D { ["predicates"] = predicates, ["caveats"] = new L() };
    }
}

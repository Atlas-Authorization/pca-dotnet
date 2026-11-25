// The outcome space from the site's signed action schema: one dimension per parameter whose effective sensitivity (after the wallet
// floor) is material or critical, boolean / set / array parameters on their canonical projection path, closed-world default sets for
// silent parameters. The schema, the slots, the policies and the confirmed values are JSON trees.
using AtlasPca.InteropJs;
using static AtlasPca.IntentPkg.IntentOmega;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.IntentPkg;

public static class IntentSchema
{
    public static readonly IReadOnlyList<string> WalletFloorPrefixes = new[] { "money.", "party.", "contact.", "person.", "credential." };
    public static readonly IReadOnlyList<string> WalletFloorExact = new[] { "text.message" };
    static readonly string[] Rev = { "reversible", "rate_limited", "irreversible" };

    /// <summary>The derived space with the wallet-floor overrides, the default-pinning slot constraints and the canonical-projection map.</summary>
    public sealed class SchemaOmega
    {
        public Omega Omega { get; }
        public List<D> Overrides { get; }
        public List<D> Defaults { get; }
        public Dictionary<string, string> CanonOf { get; }
        internal SchemaOmega(Omega omega, List<D> overrides, List<D> defaults, Dictionary<string, string> canonOf) { Omega = omega; Overrides = overrides; Defaults = defaults; CanonOf = canonOf; }

        public D ToJson() => new()
        {
            ["omega"] = OmegaToJson(Omega),
            ["overrides"] = Overrides.Select(x => (object?)x).ToList(),
            ["defaults"] = Defaults.Select(x => (object?)x).ToList(),
            ["canonOf"] = CanonOf.ToDictionary(e => e.Key, e => (object?)e.Value),
        };
    }

    static List<string>? Strs(object? o, List<string>? dflt)
    {
        if (o == null) return dflt;
        return Arr(o).Select(Str).ToList();
    }

    static bool FloorApplies(string semantic, D? floor)
    {
        var pre = Strs(floor?.GetValueOrDefault("prefixes"), WalletFloorPrefixes.ToList())!;
        var ex = Strs(floor?.GetValueOrDefault("exact"), WalletFloorExact.ToList())!;
        return ex.Contains(semantic) || pre.Any(p => semantic.StartsWith(p, StringComparison.Ordinal));
    }

    /// <summary>The wallet's effective sensitivity: a site <c>free</c> on a floored semantic type becomes <c>material</c>.</summary>
    public static string? EffectiveSensitivity(D d, D? floor) =>
        d.GetValueOrDefault("sensitivity") is "free" && FloorApplies(Str(d.GetValueOrDefault("semantic")), floor) ? "material" : d.GetValueOrDefault("sensitivity") as string;

    static string MaxRev(IEnumerable<object?> xs)
    {
        var a = "reversible";
        foreach (var b in xs)
            if (Array.IndexOf(Rev, b as string) > Array.IndexOf(Rev, a)) a = (string)b!;
        return a;
    }

    /// <summary>The value-independent reversibility class of a verb declaration (the worst a value can map to).</summary>
    public static string VerbReversibility(D v)
    {
        var by = v.GetValueOrDefault("reversibility_by");
        if (by == null) return v.GetValueOrDefault("reversibility") is string r ? r : v.GetValueOrDefault("kind") is "read" ? "reversible" : "irreversible";
        var b = Obj(by);
        var d = Obj(v.GetValueOrDefault("params")).GetValueOrDefault(Str(b.GetValueOrDefault("param")));
        var map = Obj(b.GetValueOrDefault("map"));
        var mapped = map.Values.ToList();
        List<string>? domain = null;
        if (d != null)
        {
            var dm = Obj(d);
            if (dm.GetValueOrDefault("type") is "boolean") domain = new List<string> { "true", "false" };
            else if (dm.GetValueOrDefault("type") is "string" && dm.GetValueOrDefault("values") != null) domain = Strs(dm["values"], null);
        }
        bool covered = domain != null && domain.All(map.ContainsKey);
        var all = new List<object?>(mapped);
        if (!covered) all.Add(b.GetValueOrDefault("default") ?? "irreversible");
        return MaxRev(covered ? mapped : all);
    }

    /// <summary>Every override the wallet floor makes on the schema's verbs: [{verb, path, semantic, declared, effective}].</summary>
    public static List<D> WalletFloorOverrides(IEnumerable<object?> verbs, D? floor)
    {
        var output = new List<D>();
        foreach (var vo in verbs)
        {
            var v = Obj(vo);
            var prms = Obj(v.GetValueOrDefault("params"));
            foreach (var path in prms.Keys.OrderBy(k => k, Comparer<string>.Create(IntentJs.CompareUtf8)))
            {
                var d = Obj(prms[path]);
                var eff = EffectiveSensitivity(d, floor);
                if (eff != d.GetValueOrDefault("sensitivity") as string)
                    output.Add(new D { ["verb"] = v.GetValueOrDefault("verb"), ["path"] = path, ["semantic"] = d.GetValueOrDefault("semantic"), ["declared"] = d.GetValueOrDefault("sensitivity"), ["effective"] = eff });
            }
        }
        return output;
    }

    static string CanonPath(string paramPath) => "env.canon." + paramPath["action.params.".Length..];

    static bool UsesCanon(D d) => d.GetValueOrDefault("type") is "boolean" or "set" or "array";

    /// <summary>The canonical text a value of a canon-projected parameter has.</summary>
    public static string CanonValue(D d, object? x)
    {
        if (d.GetValueOrDefault("type") is "boolean") return x is true ? "true" : "false";
        var norm = IntentJs.Normalize(x);
        if (d.GetValueOrDefault("type") is "set")
        {
            var l = Arr(norm).Select(Str).ToList();
            l.Sort(IntentJs.CompareUtf8);
            return IntentJs.Canon(l.Select(s => (object?)s).ToList());
        }
        return IntentJs.Canon(norm);
    }

    static List<string> SortedUtf8(IEnumerable<string> s)
    {
        var l = s.Distinct(StringComparer.Ordinal).ToList();
        l.Sort(IntentJs.CompareUtf8);
        return l;
    }

    /// <summary>Derive the space. <paramref name="o"/> members: schema {verbs}, verbs?, slots?, policies?, confirmed?, floor?, domains?. Throws on a malformed schema.</summary>
    public static SchemaOmega DeriveOmegaFromSchema(D o)
    {
        var schemaVerbs = Arr(Obj(o.GetValueOrDefault("schema")).GetValueOrDefault("verbs"));
        List<string> verbNames;
        if (o.GetValueOrDefault("verbs") != null) verbNames = Strs(o["verbs"], null)!;
        else
        {
            var set = new List<string>();
            foreach (var v in schemaVerbs) if (Obj(v).GetValueOrDefault("kind") is "write") { var n = Str(Obj(v).GetValueOrDefault("verb")); if (!set.Contains(n)) set.Add(n); }
            if (o.GetValueOrDefault("slots") != null && Obj(o["slots"]).GetValueOrDefault("verbs") != null)
                foreach (var n in Strs(Obj(o["slots"])["verbs"], null)!) if (!set.Contains(n)) set.Add(n);
            verbNames = set;
        }
        var baseOpts = new D { ["policies"] = o.GetValueOrDefault("policies") ?? new L() };
        if (o.GetValueOrDefault("slots") != null) baseOpts["slots"] = o["slots"];
        baseOpts["extraVerbs"] = verbNames.Select(x => (object?)x).ToList();
        var baseOmega = IntentDerive.DeriveOmega(baseOpts);
        var floor = o.GetValueOrDefault("floor") == null ? null : Obj(o["floor"]);
        var defaults = new List<D>();
        var canonOf = new Dictionary<string, string>();
        var verbs = new List<VerbSpace>();
        var sortedNames = new List<string>(verbNames);
        sortedNames.Sort(IntentJs.CompareUtf8);
        var confirmed = o.GetValueOrDefault("confirmed") == null ? new D() : Obj(o["confirmed"]);
        var domains = o.GetValueOrDefault("domains") == null ? new D() : Obj(o["domains"]);
        foreach (var verb in sortedNames)
        {
            var decl = schemaVerbs.Select(Obj).FirstOrDefault(v => v.GetValueOrDefault("verb") is string s && s == verb);
            if (decl == null) continue;
            var lits = baseOmega.Verbs.Find(v => v.Verb == verb);
            var dims = new List<Dim>();
            if (lits != null) dims.AddRange(lits.Dims.Where(d => !d.Path.StartsWith("action.params.", StringComparison.Ordinal)));
            var prms = Obj(decl.GetValueOrDefault("params"));
            foreach (var path in prms.Keys.OrderBy(k => k, Comparer<string>.Create(IntentJs.CompareUtf8)))
            {
                var pd = Obj(prms[path]);
                if (EffectiveSensitivity(pd, floor) == "free") continue;
                var lit = lits?.Dims.Find(d => d.Path == path);
                bool silent = lit == null;
                var defaultSet = new List<object?>();
                if (confirmed.GetValueOrDefault(path) != null) defaultSet.AddRange(Arr(confirmed[path]));
                if (pd.GetValueOrDefault("principal_neutral_default") is true && pd.ContainsKey("default")) defaultSet.Add(pd["default"]);
                if (pd.GetValueOrDefault("type") is "integer")
                {
                    var cuts = new List<double>();
                    if (lit is NumDim nd) foreach (var c in nd.Cuts) { var cc = c + 0.0; if (!cuts.Contains(cc)) cuts.Add(cc); }
                    foreach (var x in defaultSet)
                        if (IntentJs.NumOf(x) is double xd && Math.Abs(xd) <= 9007199254740991.0 && xd == Math.Floor(xd)) { var cc = xd + 0.0; if (!cuts.Contains(cc)) cuts.Add(cc); }
                    var sorted = cuts.OrderBy(c => c).ToList();
                    double maxCut = sorted.Count == 0 ? 0 : sorted[^1];
                    var dom = domains.GetValueOrDefault(path) == null ? null : Obj(domains[path]);
                    double lo = IntentJs.NumOf(dom?.GetValueOrDefault("lo")) ?? IntentJs.NumOf(pd.GetValueOrDefault("min")) ?? Math.Min(0, sorted.Count == 0 ? 0 : sorted[0] - 1);
                    double hi = IntentJs.NumOf(dom?.GetValueOrDefault("hi")) ?? IntentJs.NumOf(pd.GetValueOrDefault("max")) ?? Math.Max(10, Math.Max(2 * maxCut, maxCut + 10));
                    dims.Add(new NumDim(path, lo, hi, sorted.Where(c => c >= lo && c <= hi).ToArray(), lo >= 0 ? "loguniform" : "uniform"));
                    var nums = defaultSet.Select(IntentJs.NumOf).Where(n => n != null).Select(n => n!.Value).ToList();
                    if (silent && nums.Count == 1) defaults.Add(new D { ["verb"] = verb, ["path"] = path, ["min"] = N(nums[0]), ["max"] = N(nums[0]) });
                    continue;
                }
                bool canon = UsesCanon(pd);
                var dimPath = canon ? CanonPath(path) : path;
                if (canon) canonOf[dimPath] = path;
                var exacts = new List<string>();
                var prefixes = new List<string>();
                if (lit is CatDim cd)
                    foreach (var v in cd.Values) { if (v.Kind == "exact") exacts.Add(v.Value); else if (v.Kind == "prefix") prefixes.Add(v.Value); }
                if (pd.GetValueOrDefault("type") is "string" && pd.GetValueOrDefault("values") != null) exacts.AddRange(Strs(pd["values"], null)!);
                if (pd.GetValueOrDefault("type") is "boolean") { exacts.Add("false"); exacts.Add("true"); }
                var defTexts = defaultSet.Select(x => canon ? CanonValue(pd, x) : JsX.Str(x)).ToList();
                exacts.AddRange(defTexts);
                var values = SortedUtf8(exacts).Select(s => new CatValue("exact", s)).Concat(SortedUtf8(prefixes).Select(s => new CatValue("prefix", s))).ToList();
                values.Add(new CatValue("other", Other));
                dims.Add(new CatDim(dimPath, values));
                if (silent && defTexts.Count > 0)
                    defaults.Add(new D { ["verb"] = verb, ["path"] = dimPath, ["oneOf"] = SortedUtf8(defTexts).Select(s => (object?)s).ToList() });
            }
            var ordered = dims.OrderBy(d => d.Path, Comparer<string>.Create(IntentJs.CompareUtf8)).ToList();
            verbs.Add(new VerbSpace(verb, VerbReversibility(decl), 0, ordered));
        }
        foreach (var v in verbs) v.Weight = 1.0 / (verbs.Count == 0 ? 1 : verbs.Count);
        var included = schemaVerbs.Where(v => verbNames.Contains(Str(Obj(v).GetValueOrDefault("verb")))).ToList();
        return new SchemaOmega(new Omega(verbs, new List<string>(baseOmega.Approximate)), WalletFloorOverrides(included, floor), defaults, canonOf);
    }
}

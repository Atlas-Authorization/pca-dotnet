using AtlasPca.InteropJs;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Analyzer;

/// <summary>Validating a policy against the action schema / ActionDefs: a lint that compares the two descriptions of the same actions
/// before the policy is signed (an undeclared parameter, a number compared with a string, an enum value that does not exist, a bound the
/// schema makes impossible or redundant, a predicate that can never match, a money verb with no ceiling, a unit-bearing parameter read
/// without the matching unit tag). Verb shapes are {verb, params: {name: {type?, values?, min?, max?, unit?, semantic?, sensitivity?, required?}}}.</summary>
public static class Validate
{
    static readonly string[] DefTypes = { "string", "integer", "boolean", "date", "set", "array" };
    static readonly string[] NumericOps = { "lt", "lte", "gt", "gte" };
    static readonly string[] EqOps = { "eq", "ne", "in", "nin", "lt", "lte", "gt", "gte" };

    static bool IsGroup(D c) => c.ContainsKey("all_of") || c.ContainsKey("any_of") || c.ContainsKey("not");

    /// <summary>Object.entries(x ?? {}) keys.</summary>
    static List<string> KeysOrEmpty(object? x) => x == null || Jx.IsUndef(x) ? new List<string>() : JsX.Keys(x);

    static D ShapeOfDef(object? p)
    {
        var m = new D();
        var t = Jx.Prop(p, "type");
        if (t is string ts && DefTypes.Contains(ts)) m["type"] = ts;
        if (Jx.Truthy(Jx.Prop(p, "role"))) m["semantic"] = Jx.Prop(p, "role");
        if (Jx.Truthy(Jx.Prop(p, "values"))) m["values"] = Jx.Prop(p, "values");
        if (!Jx.IsUndef(Jx.Prop(p, "min"))) m["min"] = Jx.Prop(p, "min");
        if (!Jx.IsUndef(Jx.Prop(p, "max"))) m["max"] = Jx.Prop(p, "max");
        if (Jx.Truthy(Jx.Prop(p, "sensitivity"))) m["sensitivity"] = Jx.Prop(p, "sensitivity");
        if (!Jx.IsUndef(Jx.Prop(p, "required"))) m["required"] = Jx.Prop(p, "required");
        return m;
    }

    /// <summary>Verb shapes from real ActionDefs ({verb, params: {name: {type, role?, required?, values?, min?, max?, sensitivity?}}}). Types the
    /// policy language cannot compare directly (datetime, duration, object_ref) are left untyped; a money role keeps its semantic so the
    /// unbounded-money lint applies.</summary>
    public static L VerbShapesFromActionDefs(object? defs)
    {
        var dl = defs as L ?? throw JsX.TypeError("defs.map is not a function");
        var @out = new L();
        foreach (var d in dl)
        {
            var dp = Jx.Prop(d, "params");
            var prms = new D();
            foreach (var k in KeysOrEmpty(dp)) prms[k] = ShapeOfDef(JsX.ValueOf(dp, k));
            var s = new D();
            Jx.Set(s, "verb", Jx.Prop(d, "verb"));
            s["params"] = prms;
            @out.Add(s);
        }
        return @out;
    }

    /// <summary>The verbs and parameters of a signed action schema ({verbs: [...]}), a list of shapes, or a list of ActionDefs.</summary>
    public static L VerbShapes(object? src)
    {
        var @out = new L();
        if (src is not L)
        {
            if (src is not D sd) throw JsX.TypeError("cannot use 'in' operator on a non-object");
            if (sd.ContainsKey("verbs"))
            {
                var verbs = sd["verbs"] as L ?? throw JsX.TypeError("verbs.map is not a function");
                foreach (var v in verbs)
                {
                    var vp = Jx.Prop(v, "params");
                    var prms = new D();
                    foreach (var k in KeysOrEmpty(vp))
                    {
                        var d = JsX.ValueOf(vp, k);
                        var m = new D();
                        Jx.Set(m, "type", Jx.Prop(d, "type"));
                        if (Jx.Truthy(Jx.Prop(d, "values"))) m["values"] = Jx.Prop(d, "values");
                        if (!Jx.IsUndef(Jx.Prop(d, "min"))) m["min"] = Jx.Prop(d, "min");
                        if (!Jx.IsUndef(Jx.Prop(d, "max"))) m["max"] = Jx.Prop(d, "max");
                        if (Jx.Truthy(Jx.Prop(d, "unit"))) m["unit"] = Jx.Prop(d, "unit");
                        Jx.Set(m, "semantic", Jx.Prop(d, "semantic"));
                        Jx.Set(m, "sensitivity", Jx.Prop(d, "sensitivity"));
                        if (!Jx.IsUndef(Jx.Prop(d, "required"))) m["required"] = Jx.Prop(d, "required");
                        prms[k] = m;
                    }
                    var s = new D();
                    Jx.Set(s, "verb", Jx.Prop(v, "verb"));
                    s["params"] = prms;
                    @out.Add(s);
                }
                return @out;
            }
            throw JsX.TypeError("list.map is not a function");
        }
        foreach (var d in (L)src)
        {
            if (d is not D dd) throw JsX.TypeError("cannot use 'in' operator on a non-object");
            object? verb = Jx.Truthy(dd.GetValueOrDefault("verb")) ? dd["verb"] : Jx.Truthy(dd.GetValueOrDefault("id")) ? dd["id"] : "";
            var orig = dd.GetValueOrDefault("params");
            var prms = new D();
            foreach (var k in KeysOrEmpty(orig))
            {
                var o = JsX.ValueOf(orig, k);
                var m = ShapeOfDef(o);
                // shape-style params carry `semantic` and `unit` directly; keep them
                var sem = Jx.Opt(o, "semantic"); var unit = Jx.Opt(o, "unit");
                if (!Jx.IsUndef(sem)) m["semantic"] = sem;
                if (!Jx.IsUndef(unit)) m["unit"] = unit;
                prms[k] = m;
            }
            @out.Add(new D { ["verb"] = verb, ["params"] = prms });
        }
        return @out;
    }

    static void Leaves(object? c, List<object?> into)
    {
        if (c is not D d)
        {
            if (c is L) into.Add(c);
            return;
        }
        if (IsGroup(d))
        {
            if (d.ContainsKey("all_of") && d["all_of"] is L a) foreach (var x in a) Leaves(x, into);
            else if (d.ContainsKey("any_of") && d["any_of"] is L b) foreach (var x in b) Leaves(x, into);
            else if (d.ContainsKey("not")) Leaves(d["not"], into);
        }
        else into.Add(c);
    }

    static bool TypeOk(object? t, object? v)
    {
        if (Jx.IsUndef(t)) return true;
        if (t is string s)
        {
            if (s == "integer") return Jx.Fin(v) != null;
            if (s == "boolean") return v is bool;
            if (s == "string" || s == "date") return v is string;
        }
        return true;
    }

    static string StrOf(object? x) => JsX.Str(x);

    static bool VerbMatches(object? pv, object? verb) =>
        (pv is string ps && ps == "*") || JsX.StrictEq(pv, verb) || (pv is L l && (l.Any(e => e is string es && es == "*") || l.Any(e => JsX.StrictEq(e, verb))));

    static bool IsMoney(object? d)
    {
        var sem = Jx.Prop(d, "semantic");
        if (sem == null || Jx.IsUndef(sem)) return false;
        return sem is string s ? s.StartsWith("money.", StringComparison.Ordinal) : throw JsX.TypeError("startsWith is not a function");
    }

    static bool Bounded(object? p, string path)
    {
        if (Jx.Prop(p, "where") is not L w) return false;
        foreach (var c in w)
        {
            object? target = c is D cd && IsGroup(cd) ? new D { ["all_of"] = cd.ContainsKey("all_of") ? cd["all_of"] : new L() } : c;
            var ls = new List<object?>();
            Leaves(target, ls);
            foreach (var l in ls)
                if (Field.IsLeaf(l) && ((D)l!)["field"] is string f && f == path && ((D)l).GetValueOrDefault("op") is string op && (op == "lt" || op == "lte" || op == "eq" || op == "in")) return true;
        }
        return false;
    }

    static void Add(L findings, string code, string severity, object? where, string message)
    {
        var f = new D { ["code"] = code, ["severity"] = severity };
        Jx.Set(f, "where", where);
        f["message"] = message;
        findings.Add(f);
    }

    sealed class Ctx
    {
        public L Shapes = new();
        public Dictionary<string, D> ByVerb = new(StringComparer.Ordinal);
        public object? Opts;
        public object? SchemaUnits = Jx.Undef;
        public L Findings = new();
    }

    static string Range(object? d)
    {
        string B(object? x, string dflt) => x == null || Jx.IsUndef(x) ? dflt : StrOf(x);
        return $"[{B(Jx.Prop(d, "min"), "-inf")}, {B(Jx.Prop(d, "max"), "inf")}]";
    }

    static void Check(Ctx cx, object? p, string where, bool isVeto)
    {
        var pv = Jx.Prop(p, "verb");
        List<object?> verbs;
        if ((pv is string s0 && s0 == "*") || (pv is L l0 && l0.Any(e => e is string es && es == "*"))) verbs = cx.Shapes.Select(s => Jx.Prop(s, "verb")).ToList();
        else if (pv is L l1) verbs = new List<object?>(l1);
        else verbs = new List<object?> { pv };
        foreach (var v in verbs)
            if (!(v is string vs && cx.ByVerb.ContainsKey(vs))) Add(cx.Findings, "undeclared-verb", isVeto ? "warn" : "error", where, $"verb '{StrOf(v)}' is not declared by the schema");
        var declared = verbs.Where(v => v is string vs && cx.ByVerb.ContainsKey(vs)).Select(v => cx.ByVerb[(string)v!]).ToList();
        if (declared.Count == 0) return;
        var pw = Jx.Prop(p, "where");
        if (pw == null || Jx.IsUndef(pw)) return;
        var wl = pw as L ?? throw JsX.TypeError("(p.where ?? []).forEach is not a function");
        string JoinVerbs(IEnumerable<D> shapes) => string.Join(", ", shapes.Select(sh => { var v = Jx.Prop(sh, "verb"); return v == null || Jx.IsUndef(v) ? "" : StrOf(v); }));
        for (int wi = 0; wi < wl.Count; wi++)
        {
            var cs = new List<object?>();
            Leaves(wl[wi], cs);
            foreach (var c in cs)
            {
                if (!Field.IsLeaf(c) || !((string)((D)c!)["field"]!).StartsWith("action.params.", StringComparison.Ordinal)) continue;
                var cd = (D)c!;
                var field = (string)cd["field"]!;
                var name = field["action.params.".Length..].Split('.')[0];
                var at = $"{where}.where[{wi}]";
                var having = declared.Where(sh => Jx.Prop(sh, "params") is D pm && pm.ContainsKey(name)).ToList();
                if (having.Count == 0)
                {
                    Add(cx.Findings, "undeclared-param", "error", at, $"parameter '{name}' is declared by none of {JoinVerbs(declared)}");
                    continue;
                }
                if (having.Count < declared.Count)
                    Add(cx.Findings, "undeclared-param", "warn", at, $"parameter '{name}' is not declared by {JoinVerbs(declared.Where(sh => !having.Contains(sh)))}");
                var d = ((D)Jx.Prop(having[0], "params")!)[name];
                var op = cd.GetValueOrDefault("op");
                var value = cd.TryGetValue("value", out var vv) ? vv : Jx.Undef;
                var vals = value is L vl && op is string o1 && (o1 == "in" || o1 == "nin") ? vl : new L { value };
                var dtype = Jx.Prop(d, "type");
                var noRef = Jx.IsUndef(cd.TryGetValue("ref", out var rv) ? rv : Jx.Undef);
                var ops = op as string;
                if (noRef && ops != null && EqOps.Contains(ops))
                    foreach (var x in vals) if (!TypeOk(dtype, x)) Add(cx.Findings, "type-mismatch", "error", at, $"'{name}' is {StrOf(dtype)} but is compared ({ops}) with {Jx.Typeof(x)}");
                if (ops != null && NumericOps.Contains(ops) && !Jx.IsUndef(dtype) && !(dtype is string dts0 && dts0 == "integer"))
                {
                    if (dtype is string dts && (dts == "string" || dts == "date")) Add(cx.Findings, "ordering-on-string", "warn", at, $"'{name}' is {dts}: ordering follows UTF-8 byte order");
                    else Add(cx.Findings, "type-mismatch", "error", at, $"ordering operator {ops} on {StrOf(dtype)} parameter '{name}'");
                }
                var dvals = Jx.Prop(d, "values");
                if (Jx.Truthy(dvals) && (ops == "eq" || ops == "in") && vals.Count > 0 && vals[0] is string)
                {
                    bool Has(object? x) => dvals is L dl ? dl.Any(e => JsX.StrictEq(e, x)) : dvals is string dstr && x is string xs && dstr.Contains(xs, StringComparison.Ordinal);
                    var missing = vals.Where(x => x is string && !Has(x)).ToList();
                    if (missing.Count == vals.Count) Add(cx.Findings, "value-not-in-enum", "error", at, $"no value of {ops} {AtlasPca.Js.JsJson.Stringify(vals)} is in the schema's set for '{name}'");
                    else if (missing.Count > 0) Add(cx.Findings, "value-not-in-enum", "warn", at, $"{AtlasPca.Js.JsJson.Stringify(missing)} are not in the schema's set for '{name}'");
                }
                if (dtype is string dt2 && dt2 == "integer" && Jx.IsNum(value) && noRef)
                {
                    var v = IntentJs.NumOf(value)!.Value;
                    var dmaxO = Jx.Prop(d, "max"); var dminO = Jx.Prop(d, "min");
                    var hasMax = !Jx.IsUndef(dmaxO); var hasMin = !Jx.IsUndef(dminO);
                    var dmax = hasMax ? Jx.ToNumber(dmaxO) : double.NaN; var dmin = hasMin ? Jx.ToNumber(dminO) : double.NaN;
                    var o2 = ops ?? "";
                    var dead = (o2 == "eq" && ((hasMax && v > dmax) || (hasMin && v < dmin)))
                        || (o2 == "gt" && hasMax && v >= dmax)
                        || (o2 == "gte" && hasMax && v > dmax)
                        || (o2 == "lt" && hasMin && v <= dmin)
                        || (o2 == "lte" && hasMin && v < dmin);
                    if (dead) Add(cx.Findings, "out-of-range", "error", at, $"'{name}' {o2} {Jx.NumStr(v)} can never hold: the schema bounds it to {Range(d)}");
                    else if ((o2 == "lte" && hasMax && v >= dmax) || (o2 == "gte" && hasMin && v <= dmin))
                        Add(cx.Findings, "redundant-bound", "info", at, $"'{name}' {o2} {Jx.NumStr(v)} never binds: the schema already bounds it to {Range(d)}");
                }
                var unit = Jx.Prop(d, "unit");
                var units = Jx.Opt(cx.Opts, "units");
                if (Jx.Truthy(unit) && !Jx.IsUndef(units) && ops != null && (NumericOps.Contains(ops) || ops == "eq") && !isVeto)
                {
                    var tag = Jx.Prop(units, field);
                    if (tag == null || Jx.IsUndef(tag)) tag = Jx.Prop(units, "action.params." + name);
                    var sch = cx.SchemaUnits == null || Jx.IsUndef(cx.SchemaUnits) ? Jx.Undef : Jx.Prop(cx.SchemaUnits, StrOf(unit));
                    if (Jx.IsUndef(tag)) Add(cx.Findings, "unit-missing", "error", at, $"'{name}' carries unit '{StrOf(unit)}' but the policy has no unit tag for it (rule 20)");
                    else if (Jx.Truthy(sch) && (!JsX.StrictEq(Jx.Prop(tag, "kind"), Jx.Prop(sch, "kind")) || !JsX.StrictEq(Jx.Prop(tag, "currency"), Jx.Prop(sch, "currency")) || !JsX.StrictEq(Jx.Prop(tag, "exponent"), Jx.Prop(sch, "exponent"))))
                        Add(cx.Findings, "unit-mismatch", "error", at, $"'{name}': policy unit {AtlasPca.Js.JsJson.Stringify(tag)} differs from the schema's {AtlasPca.Js.JsJson.Stringify(sch)} (rule 20)");
                }
            }
        }
    }

    /// <summary>Lint a policy against the schema it is written for: {ok (false when any finding is an error), findings: [{code, severity, message, where}]}.
    /// Options: units (the grant's unit map), schemaUnits, listUngranted.</summary>
    public static D ValidatePolicyAgainstSchema(object? policy, object? src, object? o = null)
    {
        var cx = new Ctx { Opts = o };
        cx.Shapes = VerbShapes(src);
        foreach (var sh in cx.Shapes) if (Jx.Prop(sh, "verb") is string v) cx.ByVerb[v] = (D)sh!;
        var su = Jx.Opt(o, "schemaUnits");
        if ((su == null || Jx.IsUndef(su)) && src is not L && src is D sd && sd.ContainsKey("units")) su = sd["units"];
        cx.SchemaUnits = su == null ? Jx.Undef : su;
        var model = Enumerate.ToModel(policy);
        var listUngranted = Jx.Truthy(Jx.Opt(o, "listUngranted"));

        for (int i = 0; i < model.Predicates.Count; i++)
        {
            var p = model.Predicates[i];
            if (!(p is D || p is L)) continue;
            Check(cx, p, $"predicates[{i}]", false);
            var r = AnalyzerCore.AlwaysDenies(new D { ["predicates"] = new L { p } });
            if (r.GetValueOrDefault("alwaysDenies") is true && !Jx.Truthy(r.GetValueOrDefault("approximate"))) Add(cx.Findings, "unreachable-predicate", "warn", $"predicates[{i}]", "no action can ever match this predicate");
        }
        for (int i = 0; i < model.Vetoes.Count; i++) Check(cx, Jx.Prop(model.Vetoes[i], "when"), $"vetoes[{i}]", true);

        // a money verb with no ceiling in any predicate that grants it
        foreach (var sh in cx.Shapes)
        {
            var verb = Jx.Prop(sh, "verb");
            var sp = Jx.Prop(sh, "params");
            var money = KeysOrEmpty(sp).Where(k => IsMoney(JsX.ValueOf(sp, k))).ToList();
            if (money.Count == 0) continue;
            var granting = model.Predicates.Where(p => VerbMatches(Jx.Prop(p, "verb"), verb)).ToList();
            if (granting.Count == 0)
            {
                if (listUngranted) Add(cx.Findings, "verb-not-granted", "info", verb, $"the schema declares '{StrOf(verb)}' but no predicate grants it");
                continue;
            }
            foreach (var name in money)
            {
                var path = "action.params." + name;
                if (!granting.All(p => Bounded(p, path)))
                    Add(cx.Findings, "unbounded-money", "warn", verb, $"'{StrOf(verb)}' can move '{name}' with no per-action ceiling in at least one granting predicate");
            }
        }
        if (listUngranted)
            foreach (var sh in cx.Shapes)
            {
                var sp = Jx.Prop(sh, "params");
                if (Jx.Truthy(sp) && KeysOrEmpty(sp).Any(k => IsMoney(JsX.ValueOf(sp, k)))) continue;
                var verb = Jx.Prop(sh, "verb");
                if (!model.Predicates.Any(p => VerbMatches(Jx.Prop(p, "verb"), verb)))
                    Add(cx.Findings, "verb-not-granted", "info", verb, $"the schema declares '{StrOf(verb)}' but no predicate grants it");
            }
        return new D { ["ok"] = cx.Findings.All(f => !(Jx.Prop(f, "severity") is string sv && sv == "error")), ["findings"] = cx.Findings };
    }
}

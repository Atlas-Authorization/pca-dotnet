using System.Text;
using System.Text.RegularExpressions;
using AtlasPca.InteropJs;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Analyzer;

/// <summary>Compiles a residual policy to a row filter: a three-valued expression tree, parameterised SQL (postgres, sqlite, mysql) and a
/// UCAST condition tree, with evaluators for the first and the last. Anything without an exact SQL form is refused, never approximated.</summary>
public static class Filter
{
    sealed class Unsupported(string message) : Exception(message);

    static readonly Regex ColRe = new(@"^[A-Za-z_][A-Za-z0-9_]{0,62}(\.[A-Za-z_][A-Za-z0-9_]{0,62})?\z", RegexOptions.CultureInvariant);
    static object? G(object? o, string k) => o is D d && d.TryGetValue(k, out var v) ? v : Jx.Undef;
    static bool Scalar(object? v) => v is bool || v is string || Jx.Fin(v) != null;

    static string ColOf(object? path, object? cols)
    {
        if (cols == null || Jx.IsUndef(cols)) throw new InvalidOperationException("Cannot convert undefined or null to object");
        var c = path is string p && cols is D cd && cd.TryGetValue(p, out var cv) ? cv : Jx.Undef;
        if (Jx.IsUndef(c) || !(c is string cs && ColRe.IsMatch(cs))) throw new Unsupported($"field '{JsX.Str(path)}' has no usable column");
        return (string)c!;
    }

    static D Mk(string t) => new() { ["t"] = t };
    static D And(List<D> xs) => xs.Count == 0 ? Mk("true") : xs.Count == 1 ? xs[0] : new D { ["t"] = "and", ["xs"] = new L(xs) };
    static D Or(List<D> xs) => xs.Count == 0 ? Mk("false") : xs.Count == 1 ? xs[0] : new D { ["t"] = "or", ["xs"] = new L(xs) };
    static D Cmp(string col, string op, object? v) => new() { ["t"] = "cmp", ["col"] = col, ["op"] = op, ["v"] = v };
    static D Coalesce(D x, bool def) => new() { ["t"] = "coalesce", ["x"] = x, ["def"] = def };
    static D Not(D x) => new() { ["t"] = "not", ["x"] = x };
    static D NullTest(string col, bool isNull) => new() { ["t"] = "null", ["col"] = col, ["isNull"] = isNull };

    static D Cond(object? c, object? cols)
    {
        if (c is not D d) throw new Unsupported("malformed condition");
        if (d.ContainsKey("all_of") || d.ContainsKey("any_of") || d.ContainsKey("not"))
        {
            if (d.ContainsKey("all_of") && d["all_of"] is L a && a.Count > 0) return And(a.Select(x => Cond(x, cols)).ToList());
            if (d.ContainsKey("any_of") && d["any_of"] is L b && b.Count > 0) return Or(b.Select(x => Cond(x, cols)).ToList());
            if (d.ContainsKey("not")) return Not(Cond(d["not"], cols));
            throw new Unsupported("empty condition group");
        }
        if (!Field.IsLeaf(d)) throw new Unsupported("malformed condition");
        if (d.ContainsKey("ref")) throw new Unsupported("cross-field ref");
        var col = ColOf(d["field"], cols);
        var v = G(d, "value");
        var op = G(d, "op") as string;
        switch (op)
        {
            case "eq": case "ne":
                if (!Scalar(v)) throw new Unsupported($"{op} against a non-scalar");
                return Cmp(col, op, v);
            case "lt": case "lte": case "gt": case "gte":
                if (Jx.Fin(v) == null) throw new Unsupported("string ordering follows UTF-8 byte order, which SQL collations do not guarantee");
                return Cmp(col, op, v);
            case "in": case "nin":
                if (v is not L vl || vl.Count == 0 || !vl.All(Scalar)) throw new Unsupported($"{op} needs a non-empty list of scalars");
                return new D { ["t"] = "in", ["col"] = col, ["vs"] = vl, ["neg"] = op == "nin" };
            case "prefix":
                if (v is not string ps) throw new Unsupported("prefix needs a string");
                return new D { ["t"] = "prefix", ["col"] = col, ["prefix"] = ps };
            case "exists":
                return NullTest(col, v is false);
            default:
                throw new Unsupported($"operator '{JsX.Str(G(d, "op"))}' has no exact SQL form");
        }
    }

    static D ResourceExpr(object? p, object? cols)
    {
        var r = G(p, "resource");
        if (Jx.IsUndef(r) || (r is string rs0 && rs0 == "*")) return Mk("true");
        var col = ColOf("action.resource", cols);
        if (r is not string rs) throw new InvalidOperationException("r.startsWith is not a function");
        if (rs.StartsWith("re:", StringComparison.Ordinal)) throw new Unsupported("regex resource matcher");
        if (rs.EndsWith('*')) return new D { ["t"] = "prefix", ["col"] = col, ["prefix"] = rs[..^1] };
        return Cmp(col, "eq", rs);
    }

    static L ArrOrEmpty(object? x) => Jx.IsUndef(x) || x == null ? new L() : x as L ?? throw new InvalidOperationException("map is not a function");

    static D VetoExpr(object? v, object? cols)
    {
        var when = Jx.Prop(v, "when");
        var parts0 = new List<D>();
        if (!Jx.IsUndef(Jx.Prop(when, "resource"))) parts0.Add(Coalesce(ResourceExpr(when, cols), true));
        foreach (var c in ArrOrEmpty(Jx.Prop(when, "where"))) parts0.Add(Coalesce(Cond(c, cols), true));
        var parts = new List<D> { And(parts0) };
        var over = Jx.Prop(v, "over");
        if (Jx.Truthy(over))
        {
            var col = ColOf(Jx.Prop(over, "path"), cols);
            parts.Add(Or(new List<D> { NullTest(col, true), Cmp(col, "lt", Jx.N(0)), Cmp(col, "gt", Jx.Prop(over, "threshold")) }));
        }
        var unless = Jx.Prop(v, "unless");
        if ((Jx.Prop(v, "kind") as string) != "approval" && Jx.Truthy(unless) && (unless is L ul ? ul.Count > 0 : unless is string us ? us.Length > 0 : false))
            parts.Add(Not(And(((L)unless!).Select(c => Coalesce(Cond(c, cols), false)).ToList())));
        return And(parts);
    }

    static D PartExpr(D p, object? cols, string include)
    {
        var perm = new List<D>();
        foreach (var x in (L)p["predicates"]!)
        {
            var terms = new List<D> { ResourceExpr(x, cols) };
            foreach (var c in ArrOrEmpty(Jx.Prop(x, "where"))) terms.Add(Cond(c, cols));
            perm.Add(And(terms));
        }
        var gates = new List<D> { Or(perm) };
        foreach (var v in (L)p["vetoes"]!)
        {
            var e = VetoExpr(v, cols);
            if ((Jx.Prop(v, "kind") as string) == "deny" || include == "autonomous") gates.Add(Not(e));
        }
        if (include == "autonomous") foreach (var t in (L)p["tighten"]!) gates.Add(Not(Coalesce(Cond(Jx.Prop(t, "when"), cols), true)));
        else foreach (var t in (L)p["tighten"]!) if ((Jx.Prop(t, "signal") as string) == "deny") gates.Add(Not(Coalesce(Cond(Jx.Prop(t, "when"), cols), true)));
        return And(gates);
    }

    static string Render(D e, string dialect, L ps)
    {
        string Ph(object? v) { ps.Add(v); return dialect == "postgres" ? "$" + ps.Count : "?"; }
        string R(D x)
        {
            switch ((string)x["t"]!)
            {
                case "true": return "TRUE";
                case "false": return "FALSE";
                case "cmp":
                {
                    var sym = (string)x["op"]! switch { "eq" => "=", "ne" => "<>", "lt" => "<", "lte" => "<=", "gt" => ">", _ => ">=" };
                    return $"{x["col"]} {sym} {Ph(x["v"])}";
                }
                case "in": return $"{x["col"]} {((bool)x["neg"]! ? "NOT IN" : "IN")} ({string.Join(", ", ((L)x["vs"]!).Select(Ph))})";
                case "prefix": return $"{x["col"]} LIKE {Ph(Regex.Replace((string)x["prefix"]!, "[!%_]", m => "!" + m.Value) + "%")} ESCAPE '!'";
                case "null": return $"{x["col"]} IS {((bool)x["isNull"]! ? "" : "NOT ")}NULL";
                case "and": return "(" + string.Join(" AND ", ((L)x["xs"]!).Select(y => R((D)y!))) + ")";
                case "or": return "(" + string.Join(" OR ", ((L)x["xs"]!).Select(y => R((D)y!))) + ")";
                case "not": return "NOT (" + R((D)x["x"]!) + ")";
                default: return $"COALESCE({R((D)x["x"]!)}, {((bool)x["def"]! ? "TRUE" : "FALSE")})";
            }
        }
        return R(e);
    }

    /// <summary>toFilter: {ok, expr, sql, params, ucast} or {ok: false, reason} (never throws).</summary>
    public static D ToFilter(object? resObj, object? o)
    {
        try
        {
            var res = (D)resObj!;
            if ((res["decision"] as string) == "never")
                return new D { ["ok"] = true, ["expr"] = Mk("false"), ["sql"] = "FALSE", ["params"] = new L(), ["ucast"] = ToUcast(Mk("false")) };
            var inc = Jx.Opt(o, "include");
            var include = inc == null || Jx.IsUndef(inc) ? "autonomous" : JsX.Str(inc);
            var pol = (D)res["policy"]!;
            var cols = Jx.Prop(o, "columns");
            var parts = new List<D>();
            var own = new D(); foreach (var (k, v) in pol) if (k != "meet") own[k] = v;
            parts.Add(PartExpr(own, cols, include));
            if (G(pol, "meet") is L meet) foreach (var m in meet) parts.Add(PartExpr((D)m!, cols, include));
            var expr = And(parts);
            var dl = Jx.Opt(o, "dialect");
            var ps = new L();
            var sql = Render(expr, dl == null || Jx.IsUndef(dl) ? "postgres" : JsX.Str(dl), ps);
            return new D { ["ok"] = true, ["expr"] = expr, ["sql"] = sql, ["params"] = ps, ["ucast"] = ToUcast(expr) };
        }
        catch (Unsupported e) { return new D { ["ok"] = false, ["reason"] = e.Message }; }
        catch (Exception) { return new D { ["ok"] = false, ["reason"] = "filter compilation error" }; }
    }

    // ---- evaluation (three-valued) ----

    static object? Row(object? row, string c) => row is D d && d.TryGetValue(c, out var v) ? v : null;

    /// <summary>JavaScript relational comparison of two values of the same typeof (strings by UTF-16 code units, numbers, booleans).</summary>
    static int? Order(object? a, object? b)
    {
        if (a is string x && b is string y) return Math.Sign(string.CompareOrdinal(x, y));
        if (a is bool p && b is bool q) return (p ? 1 : 0).CompareTo(q ? 1 : 0);
        if (Jx.IsNum(a) && Jx.IsNum(b)) { var u = IntentJs.NumOf(a)!.Value; var w = IntentJs.NumOf(b)!.Value; return double.IsNaN(u) || double.IsNaN(w) ? null : u.CompareTo(w); }
        return null;
    }

    static bool Rel(string op, object? a, object? b)
    {
        var c = Order(a, b);
        if (c == null) return false;
        return op switch { "lt" => c < 0, "lte" => c <= 0, "gt" => c > 0, _ => c >= 0 };
    }

    /// <summary>evalFilter: true, false, or null (unknown) of an expression over a row.</summary>
    public static bool? EvalFilter(object? e, object? row)
    {
        bool? K(object? xo)
        {
            var x = (D)xo!;
            switch ((string)x["t"]!)
            {
                case "true": return true;
                case "false": return false;
                case "cmp":
                {
                    var a = Row(row, (string)x["col"]!); var b = x["v"];
                    if (a == null || Jx.Typeof(a) != Jx.Typeof(b)) return null;
                    return (string)x["op"]! switch { "eq" => JsX.StrictEq(a, b), "ne" => !JsX.StrictEq(a, b), var o => Rel(o, a, b) };
                }
                case "in":
                {
                    var a = Row(row, (string)x["col"]!);
                    if (a == null) return null;
                    var hit = ((L)x["vs"]!).Any(v => JsX.StrictEq(v, a));
                    return (bool)x["neg"]! ? !hit : hit;
                }
                case "prefix":
                {
                    var a = Row(row, (string)x["col"]!);
                    return a is string s ? s.StartsWith((string)x["prefix"]!, StringComparison.Ordinal) : null;
                }
                case "null": return (Row(row, (string)x["col"]!) == null) == (bool)x["isNull"]!;
                case "and":
                {
                    var unk = false;
                    foreach (var y in (L)x["xs"]!) { var v = K(y); if (v == false) return false; if (v == null) unk = true; }
                    return unk ? null : true;
                }
                case "or":
                {
                    var unk = false;
                    foreach (var y in (L)x["xs"]!) { var v = K(y); if (v == true) return true; if (v == null) unk = true; }
                    return unk ? null : false;
                }
                case "not": { var v = K(x["x"]); return v == null ? null : !v; }
                default: { var v = K(x["x"]); return v ?? (bool)x["def"]!; }
            }
        }
        return K(e);
    }

    // ---- UCAST ----

    static bool IsEmpty(D u, string op) => (u["type"] as string) == "compound" && (u["operator"] as string) == op && ((L)u["value"]!).Count == 0;

    static D Join(string op, List<D> xs)
    {
        var other = op == "and" ? "or" : "and";
        var flat = new List<D>();
        foreach (var x in xs) { if ((x["type"] as string) == "compound" && (x["operator"] as string) == op) foreach (var y in (L)x["value"]!) flat.Add((D)y!); else flat.Add(x); }
        if (flat.Any(x => IsEmpty(x, other))) return new D { ["type"] = "compound", ["operator"] = other, ["value"] = new L() };
        var kept = flat.Where(x => !IsEmpty(x, op)).ToList();
        if (kept.Count == 1) return kept[0];
        return new D { ["type"] = "compound", ["operator"] = op, ["value"] = new L(kept) };
    }

    static D And2(List<D> xs) => Join("and", xs);
    static D Or2(List<D> xs) => Join("or", xs);
    static D Not2(D x) => new() { ["type"] = "compound", ["operator"] = "not", ["value"] = new L { x } };
    static D F(string field, string op, object? value) => new() { ["type"] = "field", ["field"] = field, ["operator"] = op, ["value"] = value };
    static D NotNull(string c) => F(c, "ne", null);

    static D T(D x)
    {
        var col = x.GetValueOrDefault("col") as string ?? "";
        switch ((string)x["t"]!)
        {
            case "true": return And2(new List<D>());
            case "false": return Or2(new List<D>());
            case "cmp": return (string)x["op"]! == "ne" ? And2(new List<D> { NotNull(col), F(col, "ne", x["v"]) }) : F(col, (string)x["op"]!, x["v"]);
            case "in": return (bool)x["neg"]! ? And2(new List<D> { NotNull(col), F(col, "nin", x["vs"]) }) : F(col, "in", x["vs"]);
            case "prefix": return F(col, "startswith", x["prefix"]);
            case "null": return (bool)x["isNull"]! ? F(col, "eq", null) : NotNull(col);
            case "and": return And2(((L)x["xs"]!).Select(y => T((D)y!)).ToList());
            case "or": return Or2(((L)x["xs"]!).Select(y => T((D)y!)).ToList());
            case "not": return Fn((D)x["x"]!);
            default: return (bool)x["def"]! ? Not2(Fn((D)x["x"]!)) : T((D)x["x"]!);
        }
    }

    static D Fn(D x)
    {
        var col = x.GetValueOrDefault("col") as string ?? "";
        switch ((string)x["t"]!)
        {
            case "true": return Or2(new List<D>());
            case "false": return And2(new List<D>());
            case "cmp":
            {
                var inv = (string)x["op"]! switch { "eq" => "ne", "ne" => "eq", "lt" => "gte", "lte" => "gt", "gt" => "lte", _ => "lt" };
                return And2(new List<D> { NotNull(col), F(col, inv, x["v"]) });
            }
            case "in": return (bool)x["neg"]! ? F(col, "in", x["vs"]) : And2(new List<D> { NotNull(col), F(col, "nin", x["vs"]) });
            case "prefix": return And2(new List<D> { NotNull(col), Not2(F(col, "startswith", x["prefix"])) });
            case "null": return (bool)x["isNull"]! ? NotNull(col) : F(col, "eq", null);
            case "and": return Or2(((L)x["xs"]!).Select(y => Fn((D)y!)).ToList());
            case "or": return And2(((L)x["xs"]!).Select(y => Fn((D)y!)).ToList());
            case "not": return T((D)x["x"]!);
            default: return (bool)x["def"]! ? Fn((D)x["x"]!) : Not2(T((D)x["x"]!)); // coalesce(x, FALSE) is false exactly when x is not definitely true
        }
    }

    /// <summary>toUcast: the UCAST condition tree of an expression (three-valued logic made explicit with not-null guards).</summary>
    public static D ToUcast(D e) => T(e);

    /// <summary>evalUcast: a UCAST tree over a row (a missing column is null).</summary>
    public static bool EvalUcast(object? uo, object? row)
    {
        var u = (D)uo!;
        if ((u["type"] as string) == "compound")
        {
            var vs = (L)u["value"]!;
            return (string)u["operator"]! switch { "and" => vs.All(c => EvalUcast(c, row)), "or" => vs.Any(c => EvalUcast(c, row)), _ => !EvalUcast(vs[0], row) };
        }
        var a = Row(row, (string)u["field"]!);
        var v = u["value"]; var op = (string)u["operator"]!;
        if (op == "eq" && v == null) return a == null;
        if (op == "ne" && v == null) return a != null;
        if (a == null) return false;
        var same = Jx.Typeof(a) == Jx.Typeof(v);
        return op switch
        {
            "eq" => JsX.StrictEq(a, v),
            "ne" => same && !JsX.StrictEq(a, v),
            "lt" or "lte" or "gt" or "gte" => same && Rel(op, a, v),
            "in" => ((L)v!).Any(x => JsX.StrictEq(x, a)),
            "nin" => !((L)v!).Any(x => JsX.StrictEq(x, a)),
            _ => a is string s && v is string p && s.StartsWith(p, StringComparison.Ordinal),
        };
    }
}

using System.Numerics;
using System.Text;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.GoalPkg;


/** The human-readable PolicyCard text: a fixed phrase table over the IR, every clause with its exact numbers. */
public static class GoalCard {

    public static string Q(object? x) { return G.quote(x); }

    private static string s(object? o) { return G.jsStr(o); }

    private static D mm(object? o) { return G.obj(o, "value"); }

    public static string Unit(D u) { return G.kind(u).equals("money") ? s(u.get("ccy")) + " minor units" : G.kind(u); }

    public static string Quantity(D x) { return s(x.get("n")) + " " + Unit(mm(x.get("u"))); }

    public static string Value(D v) {
        string k = G.kind(v);
        if (k.equals("q")) return Quantity(mm(v.get("q")));
        if (k.equals("s")) return Q(v.get("s"));
        return "{" + join(G.arr(v.get("items"), "items"), i => Value(mm(i)), ", ") + "}";
    }

    private static string join(L xs, Func<object?, string> f, string sep) {
        List<string> outp = new();
        foreach (object? x in xs) outp.add(f(x));
        return string.Join(sep, outp);
    }

    public static string Term(D t) {
        string k = G.kind(t);
        if (k.equals("param")) {
            D ty = mm(t.get("ty"));
            return "param " + Q(t.get("path")) + " (" + (G.kind(ty).equals("q") ? Unit(mm(ty.get("u"))) : "text") + ")";
        }
        if (k.equals("lit")) return Value(mm(t.get("v")));
        return "running total of bound " + Q(t.get("bid")) + " (" + Unit(mm(t.get("u"))) + ")";
    }

    private static readonly Dictionary<string, string> OPW = new()
    {
        ["eq"] = "=", ["ne"] = "!=", ["lt"] = "<", ["lte"] = "<=", ["gt"] = ">", ["gte"] = ">=", ["in"] = "is one of", ["nin"] = "is none of",
    };

    public static string Cond(D c) {
        switch (G.kind(c)) {
            case "true": return "always";
            case "cmp": return Term(mm(c.get("l"))) + " " + (OPW.TryGetValue(s(c.get("op")) ?? "", out var opw) ? opw : "undefined") + " " + Term(mm(c.get("r")));
            case "and": return "(" + Cond(mm(c.get("a"))) + ") AND (" + Cond(mm(c.get("b"))) + ")";
            case "or": return "(" + Cond(mm(c.get("a"))) + ") OR (" + Cond(mm(c.get("b"))) + ")";
            case "not": return "NOT (" + Cond(mm(c.get("c"))) + ")";
            default: throw new IrError("unknown condition");
        }
    }

    public static string Res(D r) {
        switch (G.kind(r)) {
            case "exact": return "exactly " + Q(r.get("id"));
            case "oneof": return "one of [" + join(G.arr(r.get("ids"), "ids"), Q, ", ") + "]";
            case "related": return s(r.get("rel")) + " of " + Q(r.get("anchor"));
            case "all_of": return "ALL OF (" + join(G.arr(r.get("parts"), "parts"), p => Res(mm(p)), " AND ") + ")";
            default: return "ANY RESOURCE (reason: " + Q(r.get("reason")) + ")";
        }
    }

    public static string Win(D w) {
        switch (G.kind(w)) {
            case "task": return "per task";
            case "lifetime": return "over the lifetime";
            case "sliding": return "in any " + s(w.get("ms")) + " ms window";
            default: return "per " + s(w.get("ms")) + " ms period starting at " + s(w.get("t0"));
        }
    }

    public static string Scope(D sc) {
        return G.kind(sc).equals("fleet") ? "fleet [" + join(G.arr(sc.get("agents"), "agents"), Q, ", ") + "]" : G.kind(sc);
    }

    public static string GrantLine(D x) {
        return "ALLOW " + Q(x.get("gid")) + ": verb " + Q(x.get("verb")) + " on " + Res(mm(x.get("res"))) + " when " + Cond(mm(x.get("cond")));
    }

    public static string ProhibitLine(D x) {
        D t = mm(x.get("target"));
        string tgt = G.kind(t).equals("verb") ? "verb " + Q(t.get("verb")) : "every verb of effect class " + Q(t.get("cls"));
        return "NEVER " + Q(x.get("pid")) + ": " + tgt + " on " + Res(mm(x.get("res"))) + " when " + Cond(mm(x.get("cond")));
    }

    public static string BoundLine(D b) {
        D sel = mm(b.get("sel"));
        string over = G.kind(sel).equals("gids") ? "grants [" + join(G.arr(sel.get("gids"), "gids"), Q, ", ") + "]" : "effect class " + Q(sel.get("cls"));
        string agg = s(b.get("agg"));
        string of = agg.equals("count") ? "" : agg.equals("distinct") ? " of " + Q(b.get("key")) : " of " + Term(mm(b.get("value")));
        return "LIMIT " + Q(b.get("bid")) + ": " + agg + of + " over " + over + ", " + Win(mm(b.get("window"))) + ", scope " + Scope(mm(b.get("scope")))
            + ", at most " + Quantity(mm(b.get("cap"))) + "; beyond that: " + ("deny".equals(b.get("onExceed")) ? "deny" : "ask the principal");
    }

    public static string ValidityLine(D v) {
        return "VALID from " + s(v.get("notBefore")) + " to " + s(v.get("notAfter")) + "; idle limit " + (G.toNum(v.get("maxIdle")) > 0 ? s(v.get("maxIdle")) + " ms" : "none");
    }

    public static string DelegationLine(D d) {
        return "DELEGATION depth at most " + s(d.get("maxDepth")) + ", narrow only " + s(d.get("narrowOnly")) + ", delegates may use grants ["
            + join(G.arr(d.get("mayTouch"), "mayTouch"), Q, ", ") + "]";
    }

    public static string EscalateLine(D c) { return "ASK THE PRINCIPAL when " + Cond(c); }

    public static string HoleLine(D h) {
        return "UNRESOLVED " + Q(h.get("hid")) + ": " + Q(h.get("q")) + " options [" + join(G.arr(h.get("domain"), "domain"), Q, ", ") + "] affects "
            + (G.truthy(h.get("global")) ? "everything" : "[" + join(G.arr(h.get("affects"), "affects"), Q, ", ") + "]");
    }

    /** One line per clause in canonical order, plus the warnings the principal must look at twice: {lines, warnings}. */
    public static D RenderCard(D g) {
        L lines = new();
        L warnings = new();
        lines.add("Goal v" + s(g.get("v")) + " for principal " + Q(g.get("principal")) + "; ontology " + Q(g.get("ontDigest")) + "; request text digest " + Q(g.get("nlDigest")));
        foreach (object? x in G.arr(g.get("sources"), "sources")) lines.add("Source " + Q(x));
        L ack = G.arr(g.get("wildcardAck"), "wildcardAck");
        foreach (object? x in G.arr(g.get("grants"), "grants")) {
            D gr = mm(x);
            lines.add(GrantLine(gr));
            if (G.kind(gr.get("res")).equals("any")) warnings.add("grant " + Q(gr.get("gid")) + " applies to every resource" + (ack.contains(gr.get("gid")) ? " (acknowledged)" : " (NOT acknowledged)"));
        }
        foreach (object? x in G.arr(g.get("prohibits"), "prohibits")) lines.add(ProhibitLine(mm(x)));
        foreach (object? b in G.arr(g.get("bounds"), "bounds")) lines.add(BoundLine(mm(b)));
        lines.add(ValidityLine(mm(g.get("validity"))));
        lines.add(DelegationLine(mm(g.get("deleg"))));
        foreach (object? c in G.arr(g.get("escalateOn"), "escalateOn")) lines.add(EscalateLine(mm(c)));
        foreach (object? a in ack) lines.add("Wildcard acknowledged for " + Q(a));
        L holes = G.arr(g.get("holes"), "holes");
        foreach (object? h in holes) lines.add(HoleLine(mm(h)));
        if (!holes.isEmpty()) warnings.add("this goal has unresolved questions and cannot be signed");
        return G.map("lines", lines, "warnings", warnings);
    }
}

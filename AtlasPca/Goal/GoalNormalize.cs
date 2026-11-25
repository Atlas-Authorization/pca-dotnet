using System.Numerics;
using System.Text;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.GoalPkg;


/** Canonical form of a Goal: id-sorted clauses (code-unit order); duplicated ids are kept (the typechecker refuses them). */
public static class GoalNormalize {

    /** Stable JSON (sorted keys): an in-memory key for maps and sets, not a signed encoding. */
    public static string Stable(object? v) { return G.stable(v); }

    private static L byId(object? xs, string field) {
        L outp = new(G.arr(xs, field));
        // stable sort, like Array.prototype.sort
        outp.sort((x, y) => string.CompareOrdinal((string)G.get(x, field)!, (string)G.get(y, field)!));
        return outp;
    }

    private static L sortedSet(object? xs) {
        var s = new List<string>();
        foreach (object? o in G.arr(xs, "")) s.Add((string)o!);
        s = new List<string>(new HashSet<string>(s));
        s.Sort(string.CompareOrdinal);
        return new L(s);
    }

    public static D CanonicalizeGoal(D g) {
        D outp = new(g);
        outp.put("grants", byId(g.get("grants"), "gid"));
        outp.put("prohibits", byId(g.get("prohibits"), "pid"));
        outp.put("bounds", byId(g.get("bounds"), "bid"));
        outp.put("holes", byId(g.get("holes"), "hid"));
        outp.put("wildcardAck", sortedSet(g.get("wildcardAck")));
        D d = new(G.m(g.get("deleg")));
        d.put("mayTouch", sortedSet(d.get("mayTouch")));
        outp.put("deleg", d);
        return outp;
    }
}

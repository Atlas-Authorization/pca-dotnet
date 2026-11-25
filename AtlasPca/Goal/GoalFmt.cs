using System.Numerics;
using System.Text;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.GoalPkg;


/** Plain-text rendering of quantities, values and acts. An unknown currency is shown in raw minor units, never guessed. */
public static class GoalFmt {

    public static readonly Dictionary<string, int> CCY_EXPONENT = new() { ["USD"] = 2, ["EUR"] = 2, ["GBP"] = 2, ["CAD"] = 2, ["AUD"] = 2, ["CHF"] = 2, ["JPY"] = 0, ["KRW"] = 0 };

    private static string pad(string s, int n) {
        System.Text.StringBuilder b = new System.Text.StringBuilder();
        for (int i = s.Length; i < n; i++) b.Append('0');
        return b.Append(s).ToString();
    }

    /** {@code minor} is rendered as written (a JSON number lexeme or integer). */
    public static string FmtMoney(string ccy, object? minor) {
        int? e = CCY_EXPONENT.TryGetValue(ccy, out var ev) ? ev : null;
        string m = G.jsStr(minor);
        if (e == null) return ccy + " " + m + " (minor units)";
        if (e == 0) return ccy + " " + m;
        string s = pad(m, e.Value + 1);
        return ccy + " " + s.substring(0, s.Length - e.Value) + "." + s.substring(s.Length - e.Value);
    }

    public static string FmtQuantity(D q) {
        D u = G.obj(q.get("u"), "unit");
        object? n = q.get("n");
        switch (G.kind(u)) {
            case "money": return FmtMoney((string) u.get("ccy"), n);
            case "count": return G.jsStr(n);
            case "duration": return G.jsStr(n) + "ms";
            case "instant": return "@" + G.jsStr(n);
            case "bytes": return G.jsStr(n) + "B";
            case "ratio": return G.jsStr(n) + "ppm";
            default: throw new IrError("unknown unit");
        }
    }

    public static string FmtValue(D v) {
        string k = G.kind(v);
        if (k.equals("q")) return FmtQuantity(G.m(v.get("q")));
        if (k.equals("s")) return G.q((string) v.get("s"));
        List<string> xs = new();
        foreach (object? i in G.arr(v.get("items"), "items")) xs.add(FmtValue(G.m(i)));
        return "{" + string.Join(", ", xs) + "}";
    }

    public static string FmtAct(D a) {
        D prm = G.m(a.get("params"));
        List<string> ks = new(prm.Keys);
        ks.Sort(string.CompareOrdinal);
        List<string> ps = new();
        foreach (string k in ks) ps.add(k + "=" + FmtValue(G.m(prm.get(k))));
        return G.jsStr(a.get("verb")) + " on " + G.jsStr(a.get("res")) + (ps.isEmpty() ? "" : " (" + string.Join(", ", ps) + ")");
    }
}

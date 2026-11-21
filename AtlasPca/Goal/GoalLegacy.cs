using System.Numerics;
using System.Text;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.GoalPkg;


/**
 * liftLegacy: the total, conservative lift of the facade's {@code {permissions, limits}} input to a Goal plus IR ontology. The corrected
 * semantics of the facade's old limit bugs live here: {@code $200/day} is a SLIDING 86 400 000 ms sum bound (not a per-call ceiling plus a
 * one-day lifetime); a {@code $} limit on a verb with no amount field is an error; every limit is its own bound, so adding a limit only
 * narrows. Money parameters are integers in MINOR units of USD (cents).
 */
public static class GoalLegacy {

    private static readonly System.Text.RegularExpressions.Regex PATTERN_RESOURCE = new System.Text.RegularExpressions.Regex("[*?]|^re:");

    private static D usd() { return G.map("k", "money", "ccy", "USD"); }

    private static D cmp(string op, D l, D r) { return G.map("k", "cmp", "op", op, "l", l, "r", r); }

    private static D usdLit(long n) { return G.map("k", "lit", "v", G.map("k", "q", "q", G.map("u", usd(), "n", G.num(n)))); }

    /** JavaScript Math.Round: nearest integer, ties toward +infinity. */
    private static double jsRound(double v) {
        double f = Math.Floor(v);
        return v - f >= 0.5 ? f + 1 : f;
    }

    /**
     * Lift a legacy permission map ({@code {connector: [action, ...]}}) and limits ({@code {verb or action: "$500/day"}}) to
     * {goal, ontology}. {@code limits}, {@code catalog}, {@code notAfter}, {@code notBefore} and {@code nlDigest} may be null.
     */
    public static D LiftLegacy(D permissions, D? limits, Catalog? catalog, string principal, long? notAfter, long? notBefore, string nlDigest) {
        D raw = limits != null ? limits : new D();
        // the facade resolves every granted verb (uncatalogued verbs become irreversible); it also validates the permission map shape
        var specs = Facade.CompilePolicy(new PolicyOptions { Permissions = permissions, Catalog = catalog, Now = 0L }).Actions;
        L grants = new();
        L bounds = new();
        L verbs = new();
        foreach (CatalogAction s in specs) {
            string gid = "g:" + s.Verb;
            string? amountPath = s.AmountField != null && s.AmountField.Length > 0 ? s.AmountField : null;
            L prm = new();
            if (amountPath != null) prm.add(G.map("path", amountPath, "ty", G.map("k", "q", "u", usd())));
            verbs.add(G.map("verb", s.Verb, "cls", s.Reversibility, "params", prm));
            string resource = s.Resource != null ? s.Resource : "*";
            if (PATTERN_RESOURCE.IsMatch(resource) && !resource.equals("*")) throw new ArgumentException("liftLegacy: resource pattern '" + resource + "' of " + s.Verb + " is not expressible; name exact resources or acknowledge a wildcard");
            // own(verb) ?? own(action): a null verb limit falls through to the action; a present null action limit is malformed (parseLimit refuses it)
            object? rawLimit = raw.get(s.Verb);
            bool has = rawLimit != null;
            if (!has) { has = raw.containsKey(s.Action); rawLimit = raw.get(s.Action); }
            D cond = G.map("k", "true");
            if (has) {
                ParsedLimit lim = Facade.ParseLimit(rawLimit as string ?? throw new ArgumentException("parseLimit: empty limit"));
                if (lim.Unit == "usd") {
                    if (amountPath == null) throw new ArgumentException("liftLegacy: '$' limit on '" + s.Verb + "' but the catalog gives that verb no amount field, so the limit could not be enforced");
                    double mm = jsRound(lim.Amount * 100);
                    if (double.IsNaN(mm) || double.IsInfinity(mm) || Math.Abs(mm) > G.MAX_SAFE) throw new ArgumentException("liftLegacy: limit for " + s.Verb + " is out of range");
                    long minor = (long) mm;
                    D amt = G.map("k", "param", "path", amountPath, "ty", G.map("k", "q", "u", usd()));
                    cond = G.map("k", "and", "a", cmp("gte", amt, usdLit(0)), "b", cmp("lte", amt, usdLit(minor)));
                    if (lim.PeriodMs != null) {
                        bounds.add(G.map("bid", "b:" + s.Verb, "sel", G.map("k", "gids", "gids", G.list(gid)), "agg", "sum", "value", amt, "key", "",
                            "window", G.map("k", "sliding", "ms", G.num(lim.PeriodMs.Value)), "scope", G.map("k", "session"), "cap", G.map("u", usd(), "n", G.num(minor)), "onExceed", "deny"));
                    }
                } else {
                    if (lim.Amount != Math.Round(lim.Amount) || Math.Abs(lim.Amount) > G.MAX_SAFE) throw new ArgumentException("liftLegacy: count limit for " + s.Verb + " must be a whole number");
                    D count = G.map("k", "count");
                    bounds.add(G.map("bid", "b:" + s.Verb, "sel", G.map("k", "gids", "gids", G.list(gid)), "agg", "count",
                        "value", G.map("k", "lit", "v", G.map("k", "q", "q", G.map("u", count, "n", G.num(1)))), "key", "",
                        "window", lim.PeriodMs != null ? G.map("k", "sliding", "ms", G.num(lim.PeriodMs.Value)) : G.map("k", "lifetime"), "scope", G.map("k", "session"),
                        "cap", G.map("u", count, "n", G.num((long) lim.Amount)), "onExceed", "deny"));
                }
            }
            grants.add(G.map("gid", gid, "verb", s.Verb, "res", resource.equals("*") ? G.map("k", "any", "reason", "legacy default: no resource scope given") : G.map("k", "exact", "id", resource), "cond", cond));
        }
        grants.sort((a, b) => G.cmp((string) G.get(a, "gid"), (string) G.get(b, "gid")));
        bounds.sort((a, b) => G.cmp((string) G.get(a, "bid"), (string) G.get(b, "bid")));
        for (int i = 1; i < grants.size(); i++) if (object.Equals(G.get(grants.get(i), "gid"), G.get(grants.get(i - 1), "gid"))) throw new ArgumentException("liftLegacy: duplicate grant " + G.get(grants.get(i), "gid"));
        L mayTouch = new(), wildcardAck = new();
        foreach (object? g in grants) { mayTouch.add(G.get(g, "gid")); if ("any".equals(G.kind(G.get(g, "res")))) wildcardAck.add(G.get(g, "gid")); }
        D goal = G.map("v", G.num(1), "principal", principal, "ontDigest", "legacy-catalog", "nlDigest", nlDigest != null ? nlDigest : "", "sources", new L(),
            "grants", grants, "prohibits", new L(), "bounds", bounds,
            "validity", G.map("notBefore", G.num(notBefore ?? 0), "notAfter", G.num(notAfter ?? G.MAX_SAFE), "maxIdle", G.num(0)),
            "deleg", G.map("maxDepth", G.num(16), "narrowOnly", true, "mayTouch", mayTouch),
            "escalateOn", new L(), "wildcardAck", wildcardAck, "holes", new L());
        verbs.sort((a, b) => G.cmp((string) G.get(a, "verb"), (string) G.get(b, "verb")));
        L uniq = new();
        for (int i = 0; i < verbs.size(); i++) if (i == 0 || !object.Equals(G.get(verbs.get(i - 1), "verb"), G.get(verbs.get(i), "verb"))) uniq.add(verbs.get(i));
        return G.map("goal", goal, "ontology", G.map("verbs", uniq, "rels", new L()));
    }
}

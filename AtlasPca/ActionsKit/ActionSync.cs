// Keep a platform's action definitions in step with the sources they were imported from. Pure: the caller fetches the source and stores the lock.
// A def the lock does not attribute to this source is never touched; a changed operation is never carried over as confirmed.
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.ActionsKit;

public static class ActionSync
{
    static D AsImported(D d) => Ak.S(((D)d["review"]!), "state") == "confirmed" ? new D(d) { ["review"] = new D { ["state"] = "unreviewed" } } : d;

    /// <summary>Merge a fresh import of one source into the current defs: {defs, entries, deprecated, lock, needsReview}.</summary>
    public static D SyncSource(IEnumerable<D> current, IEnumerable<D> imported, string specDigest, object? now, D? lockDoc = null,
        Dictionary<string, D>? registry = null, Func<D, bool>? attestationVerified = null)
    {
        var reg = registry ?? Actions.CoreRegistry;
        var cur = new Dictionary<string, D>();
        foreach (var d in current) cur[(string)d["verb"]!] = d;
        var imp = new Dictionary<string, D>();
        foreach (var d in imported) imp[(string)d["verb"]!] = AsImported(d);
        var lockedOps = Ak.G(lockDoc, "ops") as D ?? new D();
        var ops = new D();
        var entries = new L();
        var defs = new L();
        var verbs = imp.Keys.ToList();
        verbs.Sort(StringComparer.Ordinal);
        foreach (var verb in verbs)
        {
            var d = imp[verb];
            var dg = Actions.DefDigest(d);
            ops[verb] = dg;
            cur.TryGetValue(verb, out var old);
            object? locked = lockDoc != null ? Ak.G(lockedOps, verb) : null;
            if (old == null)
            {
                entries.Add(new D { ["verb"] = verb, ["change"] = "added" });
                defs.Add(d);
            }
            else if ((locked is string ls && ls == dg) || (locked == null && Actions.DefDigest(old) == dg))
            {
                entries.Add(new D { ["verb"] = verb, ["change"] = "unchanged" });
                defs.Add(old);
            }
            else
            {
                D diff;
                try { diff = ActionDiff.DiffDefs(old, d, reg, attestationVerified); }
                catch (Exception e) { diff = new D { ["class"] = "incomparable", ["reasons"] = new L { e.Message } }; }
                entries.Add(new D { ["verb"] = verb, ["change"] = "changed", ["diff"] = diff });
                defs.Add(d);
            }
        }
        var deprecated = lockedOps.Keys.Where(v => !imp.ContainsKey(v)).ToList();
        deprecated.Sort(StringComparer.Ordinal);
        foreach (var v in deprecated) entries.Add(new D { ["verb"] = v, ["change"] = "removed" });
        return new D
        {
            ["defs"] = defs,
            ["entries"] = entries,
            ["deprecated"] = Ak.ToL(deprecated),
            ["lock"] = new D { ["spec_digest"] = specDigest, ["ops"] = ops, ["synced_at"] = now },
            ["needsReview"] = entries.Any(e => Ak.S(e, "change") is "added" or "changed"),
        };
    }

    /// <summary>One line per changed entry, then a summary.</summary>
    public static string SyncText(D r)
    {
        var es = Ak.Lst(r, "entries");
        var lines = new List<string>();
        foreach (var e in es)
        {
            var change = Ak.S(e, "change")!;
            if (change == "unchanged") continue;
            var extra = "";
            if (Ak.G(e, "diff") is D diff && diff.Count > 0)
            {
                var rs = Ak.Strs(diff["reasons"]);
                extra = "  (" + Ak.S(diff, "class") + (rs.Count > 0 ? ": " + string.Join(", ", rs) : "") + ")";
            }
            lines.Add(change.PadRight(9) + " " + Ak.S(e, "verb") + extra);
        }
        int N(string c) => es.Count(e => Ak.S(e, "change") == c);
        lines.Add($"{N("added")} added, {N("changed")} changed, {N("removed")} removed (deprecated), {N("unchanged")} unchanged"
            + (Ak.G(r, "needsReview") is true ? "; added and changed actions are unreviewed (strict) until a reviewer confirms them" : ""));
        return string.Join("\n", lines);
    }
}

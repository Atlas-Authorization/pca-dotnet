// Signed per-definition changes between two versions of a pack: the unsigned records, Ed25519 registry signing and the whole-change consistency check.
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.ActionsKit;

public static class ActionEvolve
{
    static Dictionary<string, D> ByVerb(IEnumerable<D> defs)
    {
        var m = new Dictionary<string, D>();
        foreach (var d in defs)
        {
            var v = (string)d["verb"]!;
            if (m.ContainsKey(v)) throw new ActionKitError("duplicate_def", $"verb '{v}' appears twice");
            m[v] = d;
        }
        return m;
    }

    /// <summary>The unsigned records that take <paramref name="prev"/> to <paramref name="nxt"/> (sorted by verb). A verb rename is removed + added.</summary>
    public static L EvolutionRecords(string ns, IEnumerable<D> prev, IEnumerable<D> nxt, Dictionary<string, D>? reg = null, Func<D, bool>? attestationVerified = null)
    {
        reg ??= Actions.CoreRegistry;
        var a = ByVerb(prev); var b = ByVerb(nxt);
        var outp = new L();
        foreach (var verb in a.Keys.Union(b.Keys).OrderBy(x => x, StringComparer.Ordinal))
        {
            a.TryGetValue(verb, out var o); b.TryGetValue(verb, out var n);
            D Rec(object? frm, object? to, string cls, object? reasons) => new()
            {
                ["v"] = 1L, ["kind"] = Actions.EvolutionRecordKind, ["ns"] = ns, ["verb"] = verb, ["from"] = frm, ["to"] = to, ["class"] = cls, ["reasons"] = reasons,
            };
            if (o == null) outp.Add(Rec(null, Actions.DefDigest(n!), "added", new L()));
            else if (n == null) outp.Add(Rec(Actions.DefDigest(o), null, "removed", new L()));
            else
            {
                var f = Actions.DefDigest(o); var t = Actions.DefDigest(n);
                if (f == t) continue;
                var d = ActionDiff.DiffDefs(o, n, reg, attestationVerified);
                outp.Add(Rec(f, t, (string)d["class"]!, d["reasons"]));
            }
        }
        return outp;
    }

    /// <summary>Sign the records as the registry (Ed25519 over the evolution domain and the strict canonical record).</summary>
    public static L SignEvolution(IEnumerable<D> records, string kid, byte[] secret)
    {
        var kp = EdKey.FromSeed(secret);
        var outp = new L();
        foreach (var r in records)
        {
            var bad = Actions.EvolutionRecordError(r, false);
            if (bad != null) throw new ArgumentException("signEvolutionRecord: " + bad);
            var sig = kp.Sign(IntentJs.Message(Actions.EvolutionDomain, r));
            var o = new D(r) { ["sig"] = new D { ["alg"] = "ed25519", ["kid"] = kid, ["value"] = Pca.B64u(sig) } };
            outp.Add(o);
        }
        return outp;
    }

    static string Key(D r) =>
        $"{Ak.JsStr(r["verb"])}|{Ak.JsStr(r["from"])}|{Ak.JsStr(r["to"])}|{Ak.JsStr(r["class"])}|{Actions.EvolutionDiffDigest(r)}";

    /// <summary>Does <paramref name="records"/> EXACTLY describe the change from prev to nxt? Null = consistent, else the reason.</summary>
    public static string? EvolutionError(string ns, IEnumerable<D> prev, IEnumerable<D> nxt, L records, object? keys, Dictionary<string, D>? reg = null, Func<D, bool>? attestationVerified = null)
    {
        try
        {
            foreach (var ro in records)
            {
                var v = Actions.VerifyEvolutionRecord(ro, keys);
                if (v != null) return "evolution record: " + v;
                var r = (D)ro!;
                if (!(r["ns"] is string rns && rns == ns)) return $"evolution record names namespace '{Ak.JsStr(r["ns"])}', not '{ns}'";
            }
            var want = EvolutionRecords(ns, prev, nxt, reg, attestationVerified).Select(r => Key((D)r!)).OrderBy(x => x, StringComparer.Ordinal).ToList();
            var have = records.Select(r => { var c = new D((D)r!); c.Remove("sig"); return Key(c); }).OrderBy(x => x, StringComparer.Ordinal).ToList();
            if (want.Count != have.Count) return $"evolution has {have.Count} records, the change needs {want.Count}";
            for (int i = 0; i < want.Count; i++)
                if (want[i] != have[i]) return "evolution records do not match the computed change (a missing, extra or mis-classified record)";
            return null;
        }
        catch (Exception e) { return "evolution error: " + e.Message; }
    }
}

// The information-flow taint lattice over JSON trees: the reference's own surface, where a label is any parsed value (an unknown or missing kind is the worst rank, never an
// error) and a registry hands back the label object it was given. The typed form of the same computation is Taint / TaintLabel; this one answers for every input the reference
// answers for.
//
// A level is one of trusted < first_party < tool < web < agent (least trusted last). A label is {kind, id?}; joining two labels keeps the higher rank as it is, and at equal rank keeps
// the id only when both agree. An empty lineage joins to agent (no verifiable trusted input is not "trusted"). Agent-declared provenance is untrusted: every declared ref is
// re-classified from the registry or the committed resource graph, an unverifiable one is agent, and nothing an agent claims about a ref is read.
using AtlasPca.Analyzer;
using AtlasPca.InteropJs;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca;

/// <summary>The inputs the server vouches for, by content digest: the label object it registered, or null.</summary>
public interface ITaintTreeRegistry
{
    object? Lookup(string digest);
}

/// <summary>The in-process registry over label trees (server-only: nothing an agent sends reaches it).</summary>
public sealed class TaintTreeRegistry : ITaintTreeRegistry
{
    readonly Dictionary<string, D> _m = new(StringComparer.Ordinal);
    readonly object _lock = new();

    /// <summary>Records <paramref name="label"/> (a copy of every member it has) for <paramref name="digest"/>; an empty or non-string digest, or a label whose kind is not a level, is ignored.</summary>
    public TaintTreeRegistry Record(object? digest, object? label)
    {
        if (digest is string { Length: > 0 } d && label is D m && TaintTree.IsTaintLevel(m.GetValueOrDefault("kind"))) lock (_lock) _m[d] = new D(m);
        return this;
    }

    public TaintTreeRegistry RecordTrusted(object? digest) => Record(digest, new D { ["kind"] = "trusted" });
    public TaintTreeRegistry RecordFirstParty(object? digest) => Record(digest, new D { ["kind"] = "first_party" });
    public TaintTreeRegistry RecordTool(object? digest, object? id) => Record(digest, new D { ["kind"] = "tool", ["id"] = id });
    public TaintTreeRegistry RecordWeb(object? digest) => Record(digest, new D { ["kind"] = "web" });

    public object? Lookup(string digest) { lock (_lock) return _m.TryGetValue(digest, out var l) ? new D(l) : null; }
    public int Size { get { lock (_lock) return _m.Count; } }
}

/// <summary>What the computation reads: the registry and (optionally) the committed, operator-controlled resource graph (<see cref="Node"/> says whether it names an id; it may throw, which
/// counts as no node).</summary>
public sealed record TaintTreeContext(ITaintTreeRegistry? Registry, Func<string, bool>? Node = null);

public static class TaintTree
{
    static readonly string[] LevelNames = { "trusted", "first_party", "tool", "web", "agent" };

    /// <summary>The five level names, least trusted last.</summary>
    public static IReadOnlyList<string> Levels => LevelNames;

    /// <summary>The most trusted label (the identity of the join).</summary>
    public static D Bottom => new() { ["kind"] = "trusted" };

    /// <summary>The least trusted label (the worst case).</summary>
    public static D Top => new() { ["kind"] = "agent" };

    /// <summary>True only for the five level names ('constructor', '__proto__', 'toString' are not levels).</summary>
    public static bool IsTaintLevel(object? kind) => kind is string s && Array.IndexOf(LevelNames, s) >= 0;

    static object? KindOf(object? l) => l is D m && m.TryGetValue("kind", out var k) ? k : Jx.Undef;

    /// <summary>The rank of a label (0 trusted ... 4 agent). An unknown, missing, inherited or non-string kind, and a value that is not a label at all, is the WORST rank 4.</summary>
    public static int LabelRank(object? l) => KindOf(l) is string s && Array.IndexOf(LevelNames, s) is var i && i >= 0 ? i : 4;

    /// <summary>The label's taint in [0, 1]: the rank over 4.</summary>
    public static double TaintValue(object? l) => LabelRank(l) / 4.0;

    // an own `id` member (undefined when there is none); a null or undefined label has no members to read
    static object? IdOf(object? l)
    {
        if (l == null || Jx.IsUndef(l)) throw JsX.TypeError("Cannot convert undefined or null to object");
        return l is D m && m.TryGetValue("id", out var v) ? v : Jx.Undef;
    }

    /// <summary>The least upper bound: the higher-ranked label as it is; at equal rank the first label when the ids agree, else <c>{kind}</c> alone. Commutative, associative and idempotent
    /// on levels. Throws on a null label that reaches the id comparison.</summary>
    public static object? JoinLabel(object? a, object? b)
    {
        int ra = LabelRank(a), rb = LabelRank(b);
        if (ra > rb) return a;
        if (rb > ra) return b;
        if (JsX.StrictEq(IdOf(a), IdOf(b))) return a;
        var o = new D();
        Jx.Set(o, "kind", KindOf(a));
        return o;
    }

    /// <summary>The join of a list of labels; the EMPTY lineage is the worst case. A single label is returned as it is.</summary>
    public static object? JoinLabels(object? labels)
    {
        if (labels is not L l) throw JsX.TypeError("labels.reduce is not a function");
        if (l.Count == 0) return Top;
        var acc = l[0];
        for (int i = 1; i < l.Count; i++) acc = JoinLabel(acc, l[i]);
        return acc;
    }

    static ITaintTreeRegistry RegistryOf(TaintTreeContext? ctx) => ctx?.Registry ?? throw JsX.TypeError("Cannot read properties of undefined (reading 'lookup')");

    static bool GraphHit(TaintTreeContext ctx, string r)
    {
        try { return ctx.Node != null && ctx.Node(r); }
        catch (Exception) { return false; } // the worst case
    }

    /// <summary>Independently classify ONE declared ref; the agent's own label is never read: a ref the registry vouches for is its registered label, one naming a resource-graph node is
    /// <c>first_party</c>, anything else is <c>agent</c> (carrying the ref as its id when it is at most 128 UTF-16 units). A non-string or empty ref is <c>agent</c>. A registry whose lookup
    /// throws makes this throw.</summary>
    public static D ClassifyRef(object? reference, TaintTreeContext? ctx)
    {
        if (reference is not string { Length: > 0 } r) return Top;
        var vouched = RegistryOf(ctx).Lookup(r);
        if (vouched is D v && IsTaintLevel(KindOf(v))) return v;
        if (GraphHit(ctx!, r)) return new D { ["kind"] = "first_party" };
        var o = new D { ["kind"] = "agent" };
        if (r.Length <= 128) o["id"] = r;
        return o;
    }

    static D Invalid(string reason) => new() { ["taint"] = IntentJs.OfLong(1), ["label"] = Top, ["refs"] = new L(), ["valid"] = false, ["reason"] = reason };

    // the label of a vouched ref as the computation reports it: its kind and its own id only
    static D Trim(D v)
    {
        var o = new D { ["kind"] = v["kind"] };
        if (v.TryGetValue("id", out var id)) o["id"] = id;
        return o;
    }

    /// <summary>The information-flow taint of <paramref name="provenance"/> (a PCActn's <c>provenance</c> object): <c>{taint, label, refs: [{ref, label}], valid, reason?}</c> where <c>taint</c> is
    /// the rank of the join over the independently classified <c>trusted_refs</c> over 4 (exactly 1 when fail-closed). Absent <c>trusted_refs</c> is no refs (taint 1). An invalid result
    /// (no registry, provenance that is not an object, <c>trusted_refs</c> not a list or with an element that is not a non-empty string, a registry that throws) is always
    /// <c>{taint: 1, label: agent, refs: [], valid: false, reason}</c>. Never throws.</summary>
    public static D ComputeTaint(object? provenance, TaintTreeContext? ctx)
    {
        try
        {
            if (ctx?.Registry == null) return Invalid("taint: no trusted-input registry");
            if (provenance is not D prov) return Invalid("taint: provenance is absent or malformed");
            var list = new L();
            if (prov.TryGetValue("trusted_refs", out var raw))
            {
                if (raw is not L l) return Invalid("taint: trusted_refs must be an array");
                if (l.Any(x => x is not string { Length: > 0 })) return Invalid("taint: trusted_refs must be non-empty strings");
                list = l;
            }
            var refs = new L();
            var labels = new L();
            foreach (string r in list)
            {
                var vouched = ctx.Registry.Lookup(r);
                D label;
                if (vouched is D v && IsTaintLevel(KindOf(v))) label = Trim(v);
                else if (GraphHit(ctx, r)) label = new D { ["kind"] = "first_party" };
                else
                {
                    label = new D { ["kind"] = "agent" };
                    if (r.Length <= 128) label["id"] = r;
                }
                refs.Add(new D { ["ref"] = r, ["label"] = label });
                labels.Add(label);
            }
            var join = (D)JoinLabels(labels)!;
            return new D { ["taint"] = Jx.N(LabelRank(join) / 4.0), ["label"] = join, ["refs"] = refs, ["valid"] = true };
        }
        catch (Exception e) { return Invalid("taint: evaluation error (fail closed): " + e.Message); }
    }
}

namespace AtlasPca;

/// <summary>A label of the information-flow taint lattice: <c>trusted</c> &lt; <c>first_party</c> &lt; <c>tool</c> &lt; <c>web</c> &lt; <c>agent</c> (least trusted last).
/// The <c>tool</c> / <c>agent</c> ids are explanatory metadata.</summary>
public sealed record TaintLabel(string Kind, string? Id = null)
{
    public static TaintLabel Top => new("agent");
    public static TaintLabel Bottom => new("trusted");
}

/// <summary>The inputs the SERVER vouches for, by content digest. An input counts as trusted only because the server recorded it, never because the agent said so.</summary>
public interface ITrustedInputRegistry
{
    /// <summary>The label the server independently vouches for this digest, or null.</summary>
    TaintLabel? Lookup(string digest);
}

/// <summary>The in-process registry (server-only: nothing an agent sends reaches it).</summary>
public sealed class InMemoryTrustedInputRegistry : ITrustedInputRegistry
{
    readonly Dictionary<string, TaintLabel> _m = new(StringComparer.Ordinal);
    readonly object _lock = new();

    /// <summary>Records that <paramref name="digest"/> is an input the server verified at <paramref name="label"/> (an empty digest or an unknown kind is ignored).</summary>
    public InMemoryTrustedInputRegistry Record(string digest, TaintLabel label)
    {
        if (!string.IsNullOrEmpty(digest) && Taint.IsLevel(label?.Kind)) lock (_lock) _m[digest] = label! with { };
        return this;
    }
    public InMemoryTrustedInputRegistry RecordTrusted(string digest) => Record(digest, new TaintLabel("trusted"));
    public InMemoryTrustedInputRegistry RecordFirstParty(string digest) => Record(digest, new TaintLabel("first_party"));
    public InMemoryTrustedInputRegistry RecordTool(string digest, string id) => Record(digest, new TaintLabel("tool", id));
    public InMemoryTrustedInputRegistry RecordWeb(string digest) => Record(digest, new TaintLabel("web"));
    public TaintLabel? Lookup(string digest) { lock (_lock) return _m.TryGetValue(digest, out var l) ? l with { } : null; }
    public int Size { get { lock (_lock) return _m.Count; } }
}

/// <summary>What the taint computation reads: the registry and (optionally) the committed, operator-controlled resource graph (<see cref="Node"/> says whether it names an id).</summary>
public sealed record TaintContext(ITrustedInputRegistry Registry, Func<string, bool>? Node = null);

/// <summary>One declared ref and the label the server independently gave it.</summary>
public sealed record TaintRef(string Ref, TaintLabel Label);

/// <summary>The information-flow taint of a PCActn's provenance: <c>Taint</c> in [0,1] (exactly 1 when fail-closed), the join <c>Label</c>, the per-ref classification and
/// <c>Valid</c> (false iff the provenance was absent, malformed or unverifiable).</summary>
public sealed record TaintResult(double Taint, TaintLabel Label, IReadOnlyList<TaintRef> Refs, bool Valid, string? Reason = null);

/// <summary>The L4 information-flow taint (spec section 6): agent-declared provenance is UNTRUSTED. Taint is lowered below the worst case only for inputs the server can
/// independently verify as trusted: the agent chooses WHICH refs to declare, never their label. Every ref is re-classified from the registry or the resource graph, an
/// unverifiable one is <c>agent</c> (worst), and an empty lineage joins to <c>agent</c>. Pure and total: every fault is the worst case.</summary>
public static class Taint
{
    static string[] Levels => new[] { "trusted", "first_party", "tool", "web", "agent" };

    public static bool IsLevel(string? kind) => kind != null && Array.IndexOf(Levels, kind) >= 0;

    /// <summary>The rank of a label; an unknown kind is the WORST rank (4), never an unordered value.</summary>
    public static int Rank(TaintLabel? l) => l != null && Array.IndexOf(Levels, l.Kind) is var i && i >= 0 ? i : 4;

    /// <summary>The normalised taint value of a label: trusted 0, first_party 0.25, tool 0.5, web 0.75, agent 1.</summary>
    public static double Value(TaintLabel? l) => Rank(l) / 4.0;

    /// <summary>The least upper bound: the higher-ranked label; at equal rank the id is kept only when both agree.</summary>
    public static TaintLabel Join(TaintLabel a, TaintLabel b)
    {
        int ra = Rank(a), rb = Rank(b);
        if (ra > rb) return a;
        if (rb > ra) return b;
        return a.Id == b.Id ? a : new TaintLabel(a.Kind);
    }

    /// <summary>The join of a list; the EMPTY lineage is the worst case (no verifiable trusted input is not "trusted").</summary>
    public static TaintLabel JoinAll(IReadOnlyList<TaintLabel> labels) => labels.Count == 0 ? TaintLabel.Top : labels.Aggregate(Join);

    static TaintLabel Classify(string r, TaintContext ctx)
    {
        var vouched = ctx.Registry.Lookup(r);
        if (vouched != null && IsLevel(vouched.Kind)) return vouched;
        try { if (ctx.Node != null && ctx.Node(r)) return new TaintLabel("first_party"); }
        catch (Exception) { /* the worst case */ }
        return new TaintLabel("agent", r.Length <= 128 ? r : null);
    }

    static TaintResult Invalid(string why) => new(1, TaintLabel.Top, Array.Empty<TaintRef>(), false, why);

    /// <summary>The taint of <paramref name="provenance"/> (the PCActn's <c>provenance</c> object as parsed JSON). Never throws.</summary>
    public static TaintResult Compute(object? provenance, TaintContext? ctx)
    {
        try
        {
            if (ctx?.Registry == null) return Invalid("taint: no trusted-input registry");
            if (provenance is not Dictionary<string, object?> prov) return Invalid("taint: provenance is absent or malformed");
            var list = new List<object?>();
            if (prov.TryGetValue("trusted_refs", out var raw) && raw != null)
            {
                if (raw is not List<object?> l) return Invalid("taint: trusted_refs must be an array");
                if (l.Any(x => x is not string { Length: > 0 })) return Invalid("taint: trusted_refs must be non-empty strings");
                list = l;
            }
            else if (prov.ContainsKey("trusted_refs") && raw == null) return Invalid("taint: trusted_refs must be an array");
            var refs = new List<TaintRef>();
            foreach (var x in list) { var r = (string)x!; refs.Add(new TaintRef(r, Classify(r, ctx))); }
            var label = JoinAll(refs.Select(t => t.Label).ToList());
            return new TaintResult(Rank(label) / 4.0, label, refs, true);
        }
        catch (Exception ex) { return Invalid("taint: evaluation error (fail closed): " + ex.Message); }
    }

    /// <summary>The <c>enforce.taint</c> gate: invalid lineage, a misconfigured bound (negative or NaN) and a taint above <paramref name="maxTaint"/> never pass.</summary>
    public static (bool Ok, string? Reason) Gate(object? provenance, TaintContext? ctx, double maxTaint)
    {
        try
        {
            var t = Compute(provenance, ctx);
            if (!t.Valid) return (false, t.Reason ?? "provenance lineage is not server-verifiable (fail closed)");
            if (!(maxTaint >= 0)) return (false, "taint gate misconfigured: maxTaint must be a non-negative number (fail closed)");
            int allowed = -1;
            for (int r = 0; r <= 4; r++) if (r / 4.0 <= maxTaint) allowed = r;
            if (Rank(t.Label) > allowed) return (false, $"information-flow taint {JsCanon.NumberString(t.Taint)} exceeds policy max {JsCanon.NumberString(maxTaint)}");
            return (true, null);
        }
        catch (Exception ex) { return (false, "taint gate error (fail closed): " + ex.Message); }
    }

    /// <summary>max(computed, claim) over the rank scale: the agent's own claim can only RAISE the taint, never lower it.</summary>
    public static int CombineRank(int computedRank, int claimRank) => Math.Max(computedRank, claimRank);
}

using AtlasPca.Js;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Dataflow;

/// <summary>The capability a value carries: its provenance sources (insertion-ordered set), whether every source is trusted, and an
/// optional allow-list of sink ids it may reach (<c>null</c> = unrestricted by the value).</summary>
public sealed class Capability
{
    public IReadOnlyList<string> Sources { get; }
    public bool IsTrusted { get; }
    public IReadOnlyList<string>? Readers { get; }

    public Capability(IEnumerable<string> sources, bool isTrusted, IEnumerable<string>? readers = null)
    {
        Sources = Dedupe(sources ?? throw new ArgumentException("a capability needs a set of sources"));
        IsTrusted = isTrusted;
        Readers = readers == null ? null : Dedupe(readers);
    }

    static IReadOnlyList<string> Dedupe(IEnumerable<string> xs)
    {
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var l = new List<string>();
        foreach (var x in xs) if (x != null && seen.Add(x)) l.Add(x);
        return l;
    }

    /// <summary>Build from the JSON shape <c>{sources:[..], isTrusted, readers?:[..]}</c>; any other shape throws (fail closed).</summary>
    public static Capability FromTree(object? t)
    {
        if (t is not D m) throw new ArgumentException("a capability needs a set of sources and a boolean isTrusted");
        if (!m.TryGetValue("sources", out var s) || s is not L sl || sl.Any(x => x is not string)) throw new ArgumentException("a capability needs a set of sources and a boolean isTrusted");
        if (!m.TryGetValue("isTrusted", out var tr) || tr is not bool b) throw new ArgumentException("a capability needs a set of sources and a boolean isTrusted");
        IEnumerable<string>? readers = null;
        if (m.TryGetValue("readers", out var r))
        {
            if (r is not L rl || rl.Any(x => x is not string)) throw new ArgumentException("readers must be a Set when given");
            readers = rl.Cast<string>();
        }
        return new Capability(sl.Cast<string>(), b, readers);
    }

    public D ToTree()
    {
        var d = new D { ["sources"] = Sources.Cast<object?>().ToList(), ["isTrusted"] = IsTrusted };
        if (Readers != null) d["readers"] = Readers.Cast<object?>().ToList();
        return d;
    }
}

/// <summary>A value carrying its capability. Only <see cref="DataFlow"/> mints one, so a look-alike map or list is never a tagged value.</summary>
public sealed class Tagged
{
    public object? Value { get; }
    public Capability Cap { get; }
    internal Tagged(object? value, Capability cap) { Value = value; Cap = cap; }
    public D ToTree() => new() { ["value"] = Value, ["cap"] = Cap.ToTree() };
}

/// <summary>What a sink accepts (provenance policy). A <c>null</c> flag is unset; only an explicit <c>true</c> acts.</summary>
public sealed class FlowPolicy
{
    public bool? External { get; init; }
    public bool? RequireTrusted { get; init; }
    public IReadOnlyCollection<string>? AllowedSources { get; init; }
    public IReadOnlyCollection<string>? DeniedSources { get; init; }

    public D ToTree()
    {
        var d = new D();
        if (External != null) d["external"] = External;
        if (RequireTrusted != null) d["requireTrusted"] = RequireTrusted;
        if (AllowedSources != null) d["allowedSources"] = AllowedSources.Cast<object?>().ToList();
        if (DeniedSources != null) d["deniedSources"] = DeniedSources.Cast<object?>().ToList();
        return d;
    }
}

/// <summary>A sink: where a value leaves the trusted interior. <c>Accepts == null</c> is a malformed sink (every flow to it is denied).</summary>
public sealed record Sink(string Id, FlowPolicy? Accepts)
{
    public D ToTree() => new() { ["id"] = Id, ["accepts"] = Accepts?.ToTree() };
}

public sealed record FlowDecision(string Outcome, string? Reason = null, IReadOnlyList<string>? Path = null)
{
    public D ToTree()
    {
        var d = new D { ["outcome"] = Outcome };
        if (Reason != null) d["reason"] = Reason;
        if (Path != null) d["path"] = Path.Cast<object?>().ToList();
        return d;
    }
}

/// <summary>The verb and resource of the action a gate reads.</summary>
public sealed record ActionRef(string Verb, string Resource);

public sealed record ActionDecision(string Outcome, string Sink, string? Reason = null, int? Arg = null, IReadOnlyList<string>? Path = null)
{
    public D ToTree()
    {
        var d = new D { ["outcome"] = Outcome, ["sink"] = Sink };
        if (Arg != null) d["arg"] = new Num(Arg.Value.ToString(System.Globalization.CultureInfo.InvariantCulture));
        if (Reason != null) d["reason"] = Reason;
        if (Path != null) d["path"] = Path.Cast<object?>().ToList();
        return d;
    }
}

/// <summary>The CaMeL-style capability-tagged data-flow model: values carry provenance and readers, combinators only lose trust, and
/// every flow to a sink is classified from the tags alone. Pure and deterministic. The guarantee is conditional on correct tagging at
/// the trust boundary (fromTrustedQuery / fromToolOutput / fromSource).</summary>
public static class DataFlow
{
    public const string TrustedQuery = "trusted-query";
    public static string ToolProvenance(string name) => "tool:" + name;

    /// <summary>Stand-in for an absent (JavaScript <c>undefined</c>) element of a tagged-argument list: the gate skips it.</summary>
    public static readonly object Undefined = new();
    /// <summary>Stand-in for a hole (an index never assigned) in a tagged-argument list: an argument nobody tagged, so the gate denies.</summary>
    public static readonly object Hole = new();

    public static bool IsTagged(object? x) => x is Tagged;

    static string[] SortedSources(Capability c) => Sorted(c.Sources);
    static string[] Sorted(IEnumerable<string> xs) { var a = xs.ToArray(); Array.Sort(a, StringComparer.Ordinal); return a; }

    /// <summary>Tag a raw value with an explicit capability (escape hatch; prefer the boundary constructors). A trusted capability needs a
    /// source and no tool source.</summary>
    public static Tagged Tag(object? value, Capability cap)
    {
        if (cap == null) throw new ArgumentException("tag: a capability needs a set of sources and a boolean isTrusted");
        if (cap.IsTrusted)
        {
            if (cap.Sources.Count == 0) throw new ArgumentException("tag: a trusted capability needs at least one source");
            foreach (var s in cap.Sources) if (s.StartsWith("tool:", StringComparison.Ordinal)) throw new ArgumentException("tag: tool output can never be trusted");
        }
        return new Tagged(value, new Capability(cap.Sources, cap.IsTrusted, cap.Readers));
    }

    public static Tagged FromTrustedQuery(object? value, IEnumerable<string>? readers = null) => Tag(value, new Capability(new[] { TrustedQuery }, true, readers));

    public static Tagged FromToolOutput(string name, object? value, IEnumerable<string>? readers = null) => Tag(value, new Capability(new[] { ToolProvenance(name) }, false, readers));

    /// <summary>Tag from an arbitrary named source; untrusted unless <paramref name="isTrusted"/> is true (fail closed).</summary>
    public static Tagged FromSource(string source, object? value, bool isTrusted = false, IEnumerable<string>? readers = null) => Tag(value, new Capability(new[] { source }, isTrusted, readers));

    public static IReadOnlyList<string> UnionSources(IEnumerable<Capability> caps)
    {
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var l = new List<string>();
        foreach (var c in caps) foreach (var s in c.Sources) if (seen.Add(s)) l.Add(s);
        return l;
    }

    /// <summary>sources = union, isTrusted = every input trusted (empty = untrusted), readers = intersection of the inputs that restrict them.</summary>
    public static Capability CombineCaps(IReadOnlyList<Capability> caps)
    {
        var sources = UnionSources(caps);
        var trusted = caps.Count > 0 && caps.All(c => c.IsTrusted);
        List<string>? readers = null;
        foreach (var c in caps)
        {
            if (c.Readers == null) continue;
            if (readers == null) readers = new List<string>(c.Readers);
            else readers = readers.Where(id => c.Readers.Contains(id)).ToList();
        }
        return new Capability(sources, trusted, readers);
    }

    /// <summary>Derive a value from tagged inputs; the capability is <see cref="CombineCaps"/> so trust can only be lost.</summary>
    public static Tagged Derive(IReadOnlyList<object?> inputs, Func<IReadOnlyList<object?>, object?> combine)
    {
        if (inputs == null || inputs.Any(i => i is not Tagged)) throw new ArgumentException("derive: every input must be a tagged value made by this module");
        var tagged = inputs.Cast<Tagged>().ToList();
        var value = combine(tagged.Select(t => t.Value).ToList());
        return new Tagged(value, CombineCaps(tagged.Select(t => t.Cap).ToList()));
    }

    /// <summary>Classify one value-to-sink flow: reader allow-list, denied sources, allow-list, external sink, trust requirement (in that order).</summary>
    public static FlowDecision ClassifyFlow(object? value, Sink? sink)
    {
        if (value is not Tagged v) return new FlowDecision("deny", "value carries no provenance tag made by this module (fail closed)", Array.Empty<string>());
        if (sink == null || sink.Id == null || sink.Id.Length == 0 || sink.Accepts == null)
            return new FlowDecision("deny", "the sink is not a valid sink (fail closed)", SortedSources(v.Cap));
        var cap = v.Cap;
        var p = sink.Accepts;

        if (cap.Readers != null && !cap.Readers.Contains(sink.Id))
        {
            var rs = string.Join(", ", Sorted(cap.Readers));
            return new FlowDecision("deny", $"value's readers capability [{(rs.Length == 0 ? "∅" : rs)}] does not include sink '{sink.Id}'", SortedSources(cap));
        }
        if (p.DeniedSources != null)
        {
            var bad = SortedSources(cap).Where(s => p.DeniedSources.Contains(s)).ToArray();
            if (bad.Length > 0) return new FlowDecision("deny", $"provenance [{string.Join(", ", bad)}] is forbidden at sink '{sink.Id}'", bad);
        }
        if (p.AllowedSources != null)
        {
            var bad = SortedSources(cap).Where(s => !p.AllowedSources.Contains(s)).ToArray();
            if (bad.Length > 0) return new FlowDecision("deny", $"provenance [{string.Join(", ", bad)}] is not in the allow-list of sink '{sink.Id}'", bad);
        }
        if (p.External == true && !cap.IsTrusted)
            return new FlowDecision("deny", $"untrusted value (provenance [{string.Join(", ", SortedSources(cap))}]) may not flow to external-send sink '{sink.Id}' — exfiltration / prompt-injection path", SortedSources(cap));
        if (p.RequireTrusted == true && !cap.IsTrusted)
            return new FlowDecision("step_up", $"sink '{sink.Id}' requires trusted provenance; value provenance [{string.Join(", ", SortedSources(cap))}] is untrusted — needs human review", SortedSources(cap));
        return new FlowDecision("allow");
    }

    /// <summary>True only for a clean allow (a step_up is not ok without a human).</summary>
    public static (bool Ok, string? Reason) CanFlow(object? value, Sink? sink)
    {
        var d = ClassifyFlow(value, sink);
        return (d.Outcome == "allow", d.Reason);
    }

    static int Severity(string o) => o switch { "allow" => 0, "step_up" => 1, _ => 2 };

    /// <summary>Gate an action by data flow: every argument is classified against the action's sink; the worst outcome wins. An argument that
    /// is <see cref="Undefined"/> is skipped, one that is <see cref="Hole"/> is an untagged argument (deny). When <paramref name="expectedArgs"/>
    /// is given a different argument count is a refusal.</summary>
    public static ActionDecision CheckAction(ActionRef action, IReadOnlyList<object?>? taggedArgs, Func<ActionRef, Sink?> sinkFor, double? expectedArgs = null)
    {
        Sink? sink;
        try { sink = sinkFor(action); }
        catch (Exception) { return new ActionDecision("deny", "(unresolved)", "the sink for this action could not be resolved (fail closed)"); }
        if (sink == null || sink.Id == null || sink.Id.Length == 0)
            return new ActionDecision("deny", "(unresolved)", "the sink for this action is not a valid sink (fail closed)");
        if (taggedArgs == null) return new ActionDecision("deny", sink.Id, "the tagged arguments are not a list (fail closed)");
        if (expectedArgs != null && taggedArgs.Count != expectedArgs.Value)
            return new ActionDecision("deny", sink.Id, $"expected {JsJson.NumberToString(expectedArgs.Value)} tagged argument(s), got {taggedArgs.Count} (fail closed)");
        var worst = new ActionDecision("allow", sink.Id);
        for (int i = 0; i < taggedArgs.Count; i++)
        {
            var arg = taggedArgs[i];
            if (ReferenceEquals(arg, Undefined)) continue;
            if (ReferenceEquals(arg, Hole)) { worst = new ActionDecision("deny", sink.Id, "an argument was not tagged (fail closed)", i); break; }
            var d = ClassifyFlow(arg, sink);
            if (Severity(d.Outcome) > Severity(worst.Outcome)) worst = new ActionDecision(d.Outcome, sink.Id, d.Reason, i, d.Path);
        }
        return worst;
    }

    /// <summary>Dual-context separation: the planner sees only the trusted query value; the quarantined handler returns a tagged result.</summary>
    public static (object? Plan, Tagged Result) DualContext(object? query, Func<object?, object?> plan, Func<object?, object?> quarantine)
    {
        if (query is not Tagged q) throw new ArgumentException("dualContext: the query must be a tagged value made by this module");
        if (!q.Cap.IsTrusted)
            throw new InvalidOperationException("dualContext: the privileged planner may only run on a TRUSTED query; got provenance [" + string.Join(", ", SortedSources(q.Cap)) + "]");
        var p = plan(q.Value);
        var r = quarantine(p);
        if (r is not Tagged rt) throw new ArgumentException("dualContext: the quarantined handler must return a tagged value made by this module");
        return (p, rt);
    }

    public static Sink ExternalSendSink(string id) => new(id, new FlowPolicy { External = true });
    public static Sink SensitiveSink(string id) => new(id, new FlowPolicy { RequireTrusted = true });

    /// <summary>A tagged value's label in the verifier's lattice: trusted only when trusted, tool when every source is a tool output, else agent.</summary>
    public static string LevelOf(object? value)
    {
        if (value is not Tagged t) return "agent";
        if (t.Cap.IsTrusted) return "trusted";
        return t.Cap.Sources.Count > 0 && t.Cap.Sources.All(s => s.StartsWith("tool:", StringComparison.Ordinal)) ? "tool" : "agent";
    }
}

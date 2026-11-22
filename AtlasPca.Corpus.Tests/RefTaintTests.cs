using AtlasPca;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Replay of the information-flow taint module over test-data/ref-taint.json.gz through the reference's own (untyped) surface: the lattice over labels of any shape, the
/// registry, the classification of one ref and the taint of a provenance. A registry spec is {records: [[digest, label]...]} (junk records included), {mode: "throws"} (lookup always
/// throws), {mode: "fixed", fixed: label|null} (lookup returns it for every digest) or null (the context has no registry); a graph spec is {nodes: [id...], throws?}.</summary>
public class RefTaintTests
{
    const string M = "ref-taint";

    sealed class FixedRegistry : ITaintTreeRegistry
    {
        readonly object? _label;
        public FixedRegistry(object? label) { _label = label; }
        public object? Lookup(string digest) => _label;
    }

    sealed class ThrowingRegistry : ITaintTreeRegistry
    {
        public object? Lookup(string digest) => throw new InvalidOperationException("registry boom");
    }

    static ITaintTreeRegistry? Registry(object? spec)
    {
        if (spec is not D m) return null;
        switch (m.GetValueOrDefault("mode") as string)
        {
            case "fixed": return new FixedRegistry(m.GetValueOrDefault("fixed"));
            case "throws": return new ThrowingRegistry();
        }
        var r = new TaintTreeRegistry();
        foreach (var rec in (L?)m.GetValueOrDefault("records") ?? new L()) r.Record(((L)rec!)[0], ((L)rec!)[1]);
        return r;
    }

    static TaintTreeContext Context(object? c)
    {
        var m = (D)c!;
        Func<string, bool>? node = null;
        if (m.GetValueOrDefault("graph") is D g)
            node = id =>
            {
                if (g.GetValueOrDefault("throws") is true) throw new InvalidOperationException("graph boom");
                return ((L)g["nodes"]!).Any(n => n is string s && s == id);
            };
        return new TaintTreeContext(Registry(m.GetValueOrDefault("registry")), node);
    }

    [Fact]
    public void Constants() => Base.Check(M, "constants", _ => new D { ["TAINT_LEVELS"] = TaintTree.Levels.Select(x => (object?)x).ToList(), ["BOTTOM"] = TaintTree.Bottom, ["TOP"] = TaintTree.Top });

    [Fact] public void IsTaintLevel() => Base.Check(M, "isTaintLevel", a => TaintTree.IsTaintLevel(a[0]), min: 24);
    [Fact] public void LabelRank() => Base.Check(M, "labelRank", a => TaintTree.LabelRank(a[0]), min: 27);
    [Fact] public void TaintValue() => Base.Check(M, "taintValue", a => TaintTree.TaintValue(a[0]), min: 27);
    [Fact] public void JoinLabel() => Base.Check(M, "joinLabel", a => TaintTree.JoinLabel(a[0], a[1]), min: 400);
    [Fact] public void JoinLabels() => Base.Check(M, "joinLabels", a => TaintTree.JoinLabels(a[0]), min: 25);

    [Fact]
    public void RegistryOps() => Base.Check(M, "registry", a =>
    {
        var r = new TaintTreeRegistry();
        var res = new L();
        foreach (var oo in (L)a[0]!)
        {
            var op = (L)oo!;
            switch ((string)op[0]!)
            {
                case "lookup": res.Add(r.Lookup((string)op[1]!)); break;
                case "size": res.Add((long)r.Size); break;
                case "emptyLookup": res.Add(null); break; // the empty registry vouches for nothing
                case "record": r.Record(op[1], op[2]); res.Add(null); break;
                case "recordTrusted": r.RecordTrusted(op[1]); res.Add(null); break;
                case "recordFirstParty": r.RecordFirstParty(op[1]); res.Add(null); break;
                case "recordTool": r.RecordTool(op[1], op[2]); res.Add(null); break;
                case "recordWeb": r.RecordWeb(op[1]); res.Add(null); break;
                default: throw new InvalidOperationException("bad op");
            }
        }
        return res;
    }, min: 9);

    [Fact] public void ClassifyRef() => Base.Check(M, "classifyRef", a => TaintTree.ClassifyRef(a[0], Context(a[1])), min: 841);
    [Fact] public void ComputeTaint() => Base.Check(M, "computeTaint", a => TaintTree.ComputeTaint(a[0], Context(a[1])), min: 990);

    [Fact]
    public void Covers()
    {
        Base.Covers(M, new[] { "constants", "isTaintLevel", "labelRank", "taintValue", "joinLabel", "joinLabels", "registry", "classifyRef", "computeTaint" });
        Assert.Equal(2344, Base.Total(M));
    }
}

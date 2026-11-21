using AtlasPca.ActionsKit;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>The YAML an action import writes, byte for byte against the reference's writer.</summary>
public class RefCoreYamlTests
{
    [Fact]
    public void DefsToYaml() => Base.Check("ref-core-yaml-java", "defsToYaml", a => YamlEmit.DefsToYaml((string)a[0]!, ((L)a[1]!).Select(d => (D)d!), (D)a[2]!));

    // one container per shared id, then every {"$ref": id} node replaced with THAT instance (cycles included)
    sealed class Shared
    {
        readonly D _box = new();

        public Shared(D spec)
        {
            foreach (var (k, v) in spec) _box[k] = v is L ? new L() : new D();
            foreach (var (k, v) in spec)
            {
                var filled = Sub(v);
                if (filled is L fl) ((L)_box[k]!).AddRange(fl);
                else foreach (var (fk, fv) in (D)filled!) ((D)_box[k]!)[fk] = fv;
            }
        }

        public object? Sub(object? x)
        {
            if (x is L l) return l.Select(Sub).ToList();
            if (x is D m)
            {
                if (m.Count == 1 && m.TryGetValue("$ref", out var r)) return _box[(string)r!];
                var o = new D();
                foreach (var (k, v) in m) o[k] = Sub(v);
                return o;
            }
            return x;
        }
    }

    [Fact]
    public void DefsToYamlSharedObjects() => Base.Check("ref-core-yaml-anchors-java", "defsToYaml", a =>
    {
        var sh = new Shared((D)a[3]!);
        return YamlEmit.DefsToYaml((string)a[0]!, ((L)sh.Sub(a[1])!).Select(d => (D)d!), (D)sh.Sub(a[2])!);
    });

    [Fact]
    public void EmptyAndScalarBasics()
    {
        Assert.Equal("ns: acme\nactions: []\n", YamlEmit.DefsToYaml("acme", new List<D>()));
        Assert.Equal("ns: \"true\"\nactions: []\n", YamlEmit.DefsToYaml("true", new List<D>()));
    }

    [Fact]
    public void Covers()
    {
        Base.Covers("ref-core-yaml-java", new[] { "defsToYaml" }); Assert.Equal(823, Base.Total("ref-core-yaml-java"));
        Base.Covers("ref-core-yaml-anchors-java", new[] { "defsToYaml" }); Assert.Equal(32, Base.Total("ref-core-yaml-anchors-java"));
    }
}

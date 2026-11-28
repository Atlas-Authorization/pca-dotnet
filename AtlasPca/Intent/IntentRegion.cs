// Regions: the part of the outcome space a cell question was about, written in value terms rather than cell indices, so an
// observation keeps its meaning when the space is refined or lifted onto another organisation's space. Mapping onto a finer
// space is exact; onto a non-refining one a "yes" claims only the cells wholly inside (inner) and a "no" widens to every cell
// that meets the region (outer).
using static AtlasPca.IntentPkg.IntentOmega;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.IntentPkg;

public static class IntentRegion
{
    /// <summary>One restricted dimension: numeric <c>Lo..Hi</c>, or categorical (the reference value list and the listed cell indices).</summary>
    public sealed class RegionDim
    {
        public string Kind { get; }
        public double Lo { get; }
        public double Hi { get; }
        public List<CatValue> Values { get; }
        public List<int> Cells { get; }
        RegionDim(string kind, double lo, double hi, List<CatValue> values, List<int> cells) { Kind = kind; Lo = lo; Hi = hi; Values = values; Cells = cells; }
        public static RegionDim Num(double lo, double hi) => new("num", lo, hi, new List<CatValue>(), new List<int>());
        public static RegionDim Cat(List<CatValue> values, List<int> cells) => new("cat", 0, 0, values, cells);

        public D ToJson()
        {
            if (Kind == "num") return new D { ["kind"] = "num", ["lo"] = N(Lo), ["hi"] = N(Hi) };
            return new D
            {
                ["kind"] = "cat",
                ["values"] = Values.Select(v => (object?)CatValueToJson(v)).ToList(),
                ["cells"] = Cells.Select(c => (object?)N(c)).ToList(),
            };
        }

        public static RegionDim FromJson(object? o)
        {
            var m = Obj(o);
            if (m.GetValueOrDefault("kind") is "num") return Num(Dbl(m.GetValueOrDefault("lo")), Dbl(m.GetValueOrDefault("hi")));
            return Cat(Arr(m.GetValueOrDefault("values")).Select(CatValueFromJson).ToList(), Arr(m.GetValueOrDefault("cells")).Select(x => (int)Dbl(x)).ToList());
        }
    }

    public sealed class Region
    {
        public string Verb { get; }
        public Dictionary<string, RegionDim> Dims { get; }
        public Region(string verb, Dictionary<string, RegionDim> dims) { Verb = verb; Dims = dims; }

        public D ToJson()
        {
            var ds = new D();
            foreach (var (k, v) in Dims) ds[k] = v.ToJson();
            return new D { ["verb"] = Verb, ["dims"] = ds };
        }

        public static Region FromJson(object? o)
        {
            var m = Obj(o);
            var ds = new Dictionary<string, RegionDim>();
            foreach (var (k, v) in Obj(m.GetValueOrDefault("dims"))) ds[k] = RegionDim.FromJson(v);
            return new Region(Str(m.GetValueOrDefault("verb")), ds);
        }
    }

    /// <summary>The value-space region of one cell.</summary>
    public static Region RegionOfCell(VerbSpace vs, IReadOnlyList<int> idx)
    {
        var dims = new Dictionary<string, RegionDim>();
        for (int k = 0; k < vs.Dims.Count; k++)
        {
            var d = vs.Dims[k];
            if (d is NumDim n)
            {
                var c = NumCells(n)[idx[k]];
                dims[d.Path] = RegionDim.Num(c.Lo, c.Hi);
            }
            else dims[d.Path] = RegionDim.Cat(new List<CatValue>(((CatDim)d).Values), new List<int> { idx[k] });
        }
        return new Region(vs.Verb, dims);
    }

    /// <summary>Restrict one dimension: <paramref name="part"/> is {lo, hi} for a numeric dimension, {cells} for a categorical one.</summary>
    public static Region RestrictRegion(Region r, Dim d, D part)
    {
        var dims = new Dictionary<string, RegionDim>(r.Dims);
        if (d is NumDim && part.ContainsKey("lo")) dims[d.Path] = RegionDim.Num(Dbl(part["lo"]), Dbl(part.GetValueOrDefault("hi")));
        else if (d is CatDim c && part.ContainsKey("cells")) dims[d.Path] = RegionDim.Cat(new List<CatValue>(c.Values), Arr(part["cells"]).Select(x => (int)Dbl(x)).ToList());
        else throw new InvalidOperationException($"restrictRegion: part does not match the kind of {d.Path}");
        return new Region(r.Verb, dims);
    }

    /// <summary>The cells of <paramref name="d"/> covered by <paramref name="rd"/>; <paramref name="inner"/> = wholly inside, else meeting it.</summary>
    public static List<int> DimCellsIn(Dim d, RegionDim? rd, bool inner)
    {
        int n = CellCount(d);
        var all = Enumerable.Range(0, n).ToList();
        if (rd == null) return all;
        if (d is NumDim nd)
        {
            if (rd.Kind != "num") throw new InvalidOperationException($"region: {d.Path} is numeric in Ω but categorical in the region");
            return all.Where(i =>
            {
                var c = NumCells(nd)[i];
                return inner ? c.Lo >= rd.Lo && c.Hi <= rd.Hi : c.Hi >= rd.Lo && c.Lo <= rd.Hi;
            }).ToList();
        }
        if (rd.Kind != "cat") throw new InvalidOperationException($"region: {d.Path} is categorical in Ω but numeric in the region");
        var cd = (CatDim)d;
        var reference = new CatDim(d.Path, rd.Values);
        var inSet = new HashSet<int>(rd.Cells);
        return all.Where(i => inSet.Contains(CatCellOf(reference, CatRep(cd, i)))).ToList();
    }

    /// <summary>Flat cell indices of the verb space covered by the region (row-major, last dimension fastest). A restricted dimension the space
    /// lacks throws: dropping that restriction would turn a narrow "yes" into a broad one.</summary>
    public static List<long> RegionCells(VerbSpace vs, Region r, bool inner)
    {
        if (r.Verb != vs.Verb) throw new InvalidOperationException($"region: verb {r.Verb} does not match {vs.Verb}");
        foreach (var p in r.Dims.Keys)
            if (!vs.Dims.Any(d => d.Path == p)) throw new InvalidOperationException($"region: restricts {p}, which Ω has no dimension for");
        var per = vs.Dims.Select(d => DimCellsIn(d, r.Dims.GetValueOrDefault(d.Path), inner)).ToList();
        if (per.Any(x => x.Count == 0)) return new List<long>();
        var acc = new List<long> { 0 };
        for (int k = 0; k < per.Count; k++)
        {
            long size = CellCount(vs.Dims[k]);
            var next = new List<long>();
            foreach (var f in acc) foreach (var c in per[k]) next.Add(f * size + c);
            acc = next;
        }
        return acc;
    }

    /// <summary>Is a concrete value (a double or a string) inside a region dimension?</summary>
    public static bool ValueInRegionDim(string path, RegionDim rd, object? x)
    {
        if (rd.Kind == "num") return x is double v && v >= rd.Lo && v <= rd.Hi;
        return x is string s && rd.Cells.Contains(CatCellOf(new CatDim(path, rd.Values), s));
    }
}

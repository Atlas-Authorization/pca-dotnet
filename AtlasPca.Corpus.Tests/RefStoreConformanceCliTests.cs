using AtlasPca;
using AtlasPca.StoreConformancePkg;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>The store conformance command line (test-data/ref-store-conformance-java.json.gz: its constants, argument parsing, and the entry point's usage
/// and error exits) and the pca-state profile over the reference adapters (test-data/ref-store-conformance-pca-state-py.json.gz: the verdict and the
/// admitted counts of the four deterministic checks).</summary>
public class RefStoreConformanceCliTests
{
    const string Cli = "ref-store-conformance-java";
    const string State = "ref-store-conformance-pca-state-py";

    static List<string> Strs(object? o) => ((L)o!).Select(x => (string)x!).ToList();

    [Fact]
    public void Consts() => Base.Check(Cli, "consts", _ => new D
    {
        ["DEFAULT_SEARCH_BUDGET"] = StoreConformanceCli.DefaultSearchBudget,
        ["ALL_TESTS"] = StoreConformanceCli.AllTests.Cast<object?>().ToList(),
        ["USAGE"] = StoreConformanceCli.Usage,
    }, min: 1);

    [Fact] public void ParseCli() => Base.Check(Cli, "parseCli", a => StoreConformanceCli.ParseCli(Strs(a[0])), min: 43);

    [Fact]
    public void Main() => Base.Check(Cli, "main", a =>
    {
        var outp = new L();
        var err = new L();
        int code = StoreConformanceCli.Main(Strs(a[0]), outp.Add, err.Add);
        return new D { ["code"] = code, ["out"] = outp, ["err"] = err };
    }, min: 5);

    [Fact]
    public void PcaStateRun() => Base.Check(State, "pcaStateRun", a =>
    {
        var c = StoreConformance.PcaStateReferenceAdapters[(string)((D)a[0]!)["adapter"]!](new Dictionary<string, string>());
        c.Rounds = 3;
        c.Copies = 8;
        c.Instances = 3;
        var r = StoreConformance.RunPcaState(c);
        var o = new D();
        foreach (var t in new[] { "one-instance", "instances", "crash-after-claim", "retry-after-timeout" })
            o[t] = new L { r.StatusOf(t), r.Admitted.TryGetValue(t, out var n) ? n.Select(x => (object?)IntentJs.OfLong(x)).ToList() : null };
        return o;
    }, min: 4);

    [Fact]
    public void TheCommandLineRunsTheProfileAndReportsABadStore()
    {
        var outp = new List<string>();
        Assert.Equal(1, StoreConformanceCli.Main(new[] { "--profile", "pca-state", "--adapter", "builtin:bad-unshared", "--tests", "instances", "--rounds", "2" }, outp.Add, outp.Add));
        Assert.Contains("FAIL", outp[0]);
        Assert.Equal(0, StoreConformanceCli.Main(new[] { "--profile", "pca-state", "--adapter", "builtin:in-memory", "--tests", "one-instance,retry-after-timeout", "--rounds", "2", "--json" }, outp.Add, outp.Add));
        Assert.Equal(2, StoreConformanceCli.Main(new[] { "--profile", "pca-state", "--adapter", "builtin:nope" }, outp.Add, outp.Add));
    }

    [Fact]
    public void TheGetPutAndLocalLockControlsAreCaught()
    {
        Assert.Equal(new[] { "in-memory", "durable-file", "bad-get-put", "bad-read-then-write-claim", "bad-local-lock", "bad-volatile", "bad-unshared" },
            StoreConformance.PcaStateReferenceAdapters.Keys.ToArray());
        PcaStateConformance Make(string name)
        {
            var c = StoreConformance.PcaStateReferenceAdapters[name](new Dictionary<string, string>());
            c.Rounds = 3;
            c.Copies = 8;
            c.Instances = 3;
            return c;
        }
        // read then write with no lock of its own: sound in one process, refused as soon as the guard is built for several instances
        var r = StoreConformance.RunPcaState(Make("bad-get-put"));
        Assert.Equal("pass", r.StatusOf("one-instance"));
        Assert.Equal(new[] { 1, 1, 1 }, r.Admitted["one-instance"]);
        Assert.Equal("fail", r.StatusOf("instances"));
        Assert.Contains("refused in multi-instance mode", r.Checks.First(t => t.Name == "instances").Note);
        Assert.False(r.Admitted.ContainsKey("instances"));
        Assert.False(r.Ok);
        // a lock that covers one handle: one instance is serialised, several instances admit the same proof more than once
        r = StoreConformance.RunPcaState(Make("bad-local-lock"));
        Assert.Equal("pass", r.StatusOf("one-instance"));
        Assert.Equal("fail", r.StatusOf("instances"));
        Assert.Contains(r.Admitted["instances"], n => n > 1);
        Assert.False(r.Ok);
    }

    [Fact]
    public void Covers()
    {
        Base.Covers(Cli, new[] { "consts", "parseCli", "main" });
        Assert.Equal(49, Base.Cases(Cli).Count);
        Base.Covers(State, new[] { "pcaStateRun" });
        Assert.Equal(4, Base.Cases(State).Count);
    }
}

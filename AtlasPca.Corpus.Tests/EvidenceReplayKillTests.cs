using System.IO.Compression;
using System.Text;
using AtlasPca.Evidence;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>The dispute evidence replay (<see cref="EvidenceReplay.Verify"/>) with the verifier ports and trust inputs the reference corpora leave out
/// (RefEvidenceBundleTests replays the corpora themselves, whole reports compared).</summary>
public partial class EvidenceReplayKillTests
{
    // ---- corpus access (own loader: one small file per module, no shared cache) ----

    static string Find(string file)
    {
        var d = AppContext.BaseDirectory;
        for (int i = 0; i < 12 && d != null; i++, d = Path.GetDirectoryName(d))
        {
            var f = Path.Combine(d, "test-data", file);
            if (File.Exists(f)) return f;
            f = Path.Combine(d, "AtlasPca.Corpus.Tests", "test-data", file);
            if (File.Exists(f)) return f;
        }
        throw new FileNotFoundException("test-data/" + file);
    }

    internal static (List<D> Cases, long Clock) Load(string module)
    {
        using var r = new StreamReader(new GZipStream(File.OpenRead(Find(module + ".json.gz")), CompressionMode.Decompress), new UTF8Encoding(false));
        var head = r.ReadLine() ?? throw new InvalidDataException("empty oracle");
        var clock = (long)Base.ClockOfHeader(head);
        var cases = new List<D>();
        for (string? line; (line = r.ReadLine()) != "]}";)
        {
            if (line == null) throw new InvalidDataException("truncated oracle");
            cases.Add((D)FixtureJson.Parse(line.EndsWith(',') ? line[..^1] : line)!);
        }
        return (cases, clock);
    }

    static EvidencePort Port(object? spec) => (_, _) => spec switch
    {
        string kind when kind == "throws" => throw new InvalidOperationException("boom"),
        string kind => kind == "ok" ? new D { ["ok"] = true } : new D { ["ok"] = false, ["reason"] = "port refused" },
        D v => v,
        _ => throw new InvalidOperationException("bad port spec"),
    };

    static D Run(L a, long clock)
    {
        D? trust = a.Count > 1 ? a[1] as D : null;
        var ports = new Dictionary<string, EvidencePort>();
        if (trust != null && trust.GetValueOrDefault("verifiers") is D vs)
        {
            foreach (var kv in vs) ports[kv.Key] = Port(kv.Value);
            trust = trust.Where(kv => kv.Key != "verifiers").ToDictionary(kv => kv.Key, kv => kv.Value);
        }
        var previous = AtlasPca.ReplayClock.Ms;
        AtlasPca.ReplayClock.Ms = () => clock;
        try { return EvidenceReplay.Verify(a[0], trust, ports); }
        finally { AtlasPca.ReplayClock.Ms = previous; }
    }

    static string Show(object? v) => Base.Show(Base.Json(v));

    /// <summary>The report as flat lines: header flags + digests, one line per finding, the summary members (proven / not_proven one line per item).</summary>
    static List<string> Render(D o)
    {
        var l = new List<string>
        {
            "H|ok=" + Show(o["ok"]) + "|consistent=" + Show(o["consistent"]) + "|attributed=" + Show(o["attributed"]) + "|complete=" + Show(o["complete"])
                + "|digest=" + Show(o["digest"]) + "|report_digest=" + Show(o["report_digest"]),
        };
        foreach (var fo in (L)o["findings"]!)
        {
            var f = (D)fo!;
            l.Add("F|" + f["code"] + "|" + f["status"] + "|" + string.Join(",", ((L)f["refs"]!).Select(x => (string)x!)) + "|" + f["text"]);
        }
        var s = (D)o["summary"]!;
        foreach (var k in s.Keys.OrderBy(k => k, StringComparer.Ordinal))
        {
            if (k is "proven" or "not_proven")
            {
                var items = (L)s[k]!;
                foreach (var t in items) l.Add("S|" + k + "|" + t);
                l.Add("S|" + k + "#|" + items.Count);
            }
            else l.Add("S|" + k + "|" + Show(s[k]));
        }
        return l;
    }

    // ---- ports that decline (return no verdict): the artifact stays unverified and says which verifier was missing ----

    static D WalkthroughNullPorts(params string[] names)
    {
        var (cases, clock) = Load("ref-evidence-bundle-py");
        var a = (L)Base.Deep(Base.Args(cases[0]))!;
        var trust = (D)a[1]!;
        trust.Remove("verifiers");
        var ports = new Dictionary<string, EvidencePort>();
        foreach (var n in names) ports[n] = (_, _) => null!;
        var previous = AtlasPca.ReplayClock.Ms;
        AtlasPca.ReplayClock.Ms = () => clock;
        try { return EvidenceReplay.Verify(a[0], trust, ports); }
        finally { AtlasPca.ReplayClock.Ms = previous; }
    }

    [Fact]
    public void DecliningPortsLeaveTheArtifactUnverifiedAndNameTheMissingVerifier()
    {
        var o = WalkthroughNullPorts("sessionRoot", "schema", "receipt", "effect");
        var lines = Render(o);
        Assert.Contains("F|session_root.signature|unverified|session_root|The session root is signed by one of its principal keys: not verified here (no verifier for the session root).", lines);
        Assert.Contains("F|schema.signature|unverified|schema|The action schema is signed by a site key: not verified here (no verifier for the action schema (no site keys supplied)).", lines);
        Assert.Contains("F|accumulator.receipts|unverified|receipt:trip_budget#1|The sequencer reservation receipt verifies and is consistent: not verified here (no verifier for the reserved contribution (the effect params were withheld)).", lines);
        Assert.Contains(lines, x => x.StartsWith("F|effect.signature|unverified|effect:", StringComparison.Ordinal) && x.EndsWith("|The effect record is signed by the site: not verified here (no verifier for effect records (no core format yet)).", StringComparison.Ordinal));
        Assert.False((bool)o["complete"]!);
        Assert.True((bool)o["consistent"]!);
        Assert.Contains("S|not_proven|Checked only through a supplied verifier, or not at all: accumulator.receipts, effect.signature, schema.signature, session_root.signature.", lines);
    }
}

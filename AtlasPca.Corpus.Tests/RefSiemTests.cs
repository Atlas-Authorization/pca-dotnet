using System.Globalization;
using AtlasPca.Siem;
using Xunit;
using S = AtlasPca.Siem.SiemExport;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Differential replay of the SIEM oracle (test-data/ref-siem.json.gz, TS reference @atlasauth/pca-siem): the OCSF / CEF / ECS event mapping,
/// formatDecision, the credential scrubber and the HTTP / console sinks and batch export.</summary>
public class RefSiemTests
{
    const string M = "ref-siem";

    static object? Opts(L a) => a.Count > 1 ? a[1] : null;
    static D Spec(L a) => (D)a[0]!;
    static Num N(long v) => new(v.ToString(CultureInfo.InvariantCulture));

    [Fact] public void ToOcsfEvent() => Base.Check(M, "toOcsfEvent", a => S.ToOcsfEvent(a[0], Opts(a)));
    [Fact] public void ToCef() => Base.Check(M, "toCef", a => S.ToCef(a[0], Opts(a)));
    [Fact] public void ToEcs() => Base.Check(M, "toEcs", a => S.ToEcs(a[0], Opts(a)));
    [Fact] public void FormatDecision() => Base.Check(M, "formatDecision", a => S.FormatDecision(a[0], (string?)a[1], a[2]).ToJson());
    [Fact] public void ScrubError() => Base.Check(M, "scrubError", a => S.ScrubError((string)a[0]!));

    [Fact]
    public void HttpSinkScenario() => Base.Check(M, "httpSinkScenario", a =>
    {
        var s = Spec(a);
        var mode = (string)s["mode"]!;
        var format = s["format"] as string;
        var calls = new List<D>();
        var o = new HttpSinkOptions { Format = format, ContentType = s.GetValueOrDefault("contentType") as string, Name = s.GetValueOrDefault("name") as string };
        if (s.GetValueOrDefault("headers") is D hd) o.Headers = hd.ToDictionary(e => e.Key, e => (string)e.Value!);
        if (s.GetValueOrDefault("timeoutMs") is Num tm) o.TimeoutMs = double.Parse(tm.Raw, CultureInfo.InvariantCulture);
        o.Fetch = async (url, init) =>
        {
            lock (calls) calls.Add(new D { ["url"] = url, ["method"] = init.Method, ["headers"] = init.Headers.ToDictionary(e => e.Key, e => (object?)e.Value), ["body"] = init.Body });
            if (mode == "ok") return new FetchLikeResponse(true, 200);
            if (mode.StartsWith("st:", StringComparison.Ordinal))
            {
                var p = mode.Split(':', 3);
                return new FetchLikeResponse(false, int.Parse(p[1], CultureInfo.InvariantCulture), p.Length > 2 ? p[2] : null);
            }
            if (mode.StartsWith("throws:", StringComparison.Ordinal)) throw new InvalidOperationException(mode[7..]);
            await new TaskCompletionSource<FetchLikeResponse>().Task; // hang: never settles
            return new FetchLikeResponse(true, 200);
        };
        var sink = S.HttpSinkOf((string)s["url"]!, o);
        var events = ((L)s["events"]!).Select(r => S.FormatDecision(r, format)).ToList();
        var res = sink.DeliverAsync(events).GetAwaiter().GetResult();
        var outp = new D { ["name"] = sink.Name, ["format"] = sink.Format, ["result"] = res.ToJson() };
        if (calls.Count > 0) outp["request"] = calls[0];
        return outp;
    });

    [Fact]
    public void ConsoleSinkScenario() => Base.Check(M, "consoleSinkScenario", a =>
    {
        var s = Spec(a);
        var lines = new L();
        var throwsMsg = s.GetValueOrDefault("throws") as string;
        var o = new ConsoleSinkOptions { Format = s.GetValueOrDefault("format") as string, Name = s.GetValueOrDefault("name") as string };
        o.Logger = l => { if (throwsMsg != null) throw new InvalidOperationException(throwsMsg); lines.Add(l); };
        var sink = S.ConsoleSinkOf(o);
        var events = ((L)s["records"]!).Select(r => S.FormatDecision(r, sink.Format)).ToList();
        var res = sink.DeliverAsync(events).GetAwaiter().GetResult();
        return new D { ["name"] = sink.Name, ["format"] = sink.Format, ["result"] = res.ToJson(), ["lines"] = lines };
    });

    sealed class ScriptedSink(string format, string mode, L delivered) : ISiemSink
    {
        public string Name => "s1";
        public string? Format => format;
        public Task<AtlasPca.Siem.SinkResult> DeliverAsync(IReadOnlyList<SiemEvent> events)
        {
            foreach (var e in events) delivered.Add(e.Line);
            if (mode == "ok") return Task.FromResult(new AtlasPca.Siem.SinkResult(true));
            if (mode == "fail") return Task.FromResult(new AtlasPca.Siem.SinkResult(false, "collector said no token=abcdef123"));
            if (mode == "failNoError") return Task.FromResult(new AtlasPca.Siem.SinkResult(false));
            throw new InvalidOperationException("deliver exploded Bearer abcdefghij");
        }
    }

    [Fact]
    public void ExportScenario() => Base.Check(M, "exportScenario", a =>
    {
        var s = Spec(a);
        var mode = (string)s["sinkMode"]!;
        var errors = new L();
        var delivered = new L();
        var sink = new ScriptedSink((string)s["format"]!, mode, delivered);
        bool cbThrows = mode == "throwsOnError" || s.GetValueOrDefault("onErrorThrows") is true;
        var o = new ExportOptions
        {
            Serialize = s.GetValueOrDefault("serialize"),
            OnError = (err, name, count) =>
            {
                errors.Add(new D { ["message"] = err.Message, ["sink"] = name, ["count"] = N(count) });
                if (cbThrows) throw new InvalidOperationException("cb");
            },
        };
        var result = S.ExportBatchAsync(((L)s["records"]!), sink, o).GetAwaiter().GetResult();
        return new D { ["result"] = result.ToJson(), ["errors"] = errors, ["delivered"] = delivered };
    });

    [Fact]
    public void AllFnsCovered() { Base.Covers(M, new[] { "toOcsfEvent", "toCef", "toEcs", "formatDecision", "scrubError", "httpSinkScenario", "consoleSinkScenario", "exportScenario" }); Assert.Equal(1290, Base.Total(M)); }
}

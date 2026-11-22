using AtlasPca.InteropJs;
using AtlasPca.Otel;
using Xunit;
using O = AtlasPca.Otel.OtelGuard;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Differential replay of the OpenTelemetry oracle (test-data/ref-otel.json.gz, TS reference @atlasauth/pca-otel): the secret redactor, the span attribute
/// mapping and the guard wrapper over scripted tracers and meters. The error name of a recorded exception is not compared.</summary>
public class RefOtelTests
{
    const string M = "ref-otel";

    static Func<string, string>? Mode(object? m) => (string?)m switch
    {
        null => null,
        "identity" => s => s,
        "upper" => s => s.ToUpperInvariant(),
        "brackets" => s => "<" + s + ">",
        var x => throw new ArgumentException("mode " + x),
    };

    static D Ev(string ev) => new() { ["ev"] = ev };

    [Fact] public void RedactSecrets() => Base.Check(M, "redactSecrets", a => O.RedactSecrets((string)a[0]!));
    [Fact] public void PcaSpanAttributes() => Base.Check(M, "pcaSpanAttributes", a => O.PcaSpanAttributes(a[0], Mode(a[1])));

    sealed class Span(L events, string tm) : ISpanLike
    {
        void Boom(string mode) { if (tm == mode) throw new InvalidOperationException("exporter boom"); }
        public void SetAttribute(string k, object? v) { var e = Ev("setAttribute"); e["k"] = k; e["v"] = v; events.Add(e); Boom("attrThrows"); }
        public void SetStatus(int code, string? message)
        {
            var e = Ev("setStatus"); e["code"] = JsX.Number(code); if (message != null) e["message"] = message; events.Add(e);
            Boom("statusThrows");
        }
        public void RecordException(Exception t) { var e = Ev("recordException"); e["message"] = t.Message; e["noStack"] = t.StackTrace == null; events.Add(e); Boom("recordThrows"); }
        public void End() { events.Add(Ev("end")); Boom("endThrows"); }
    }

    sealed class Tracer(L events, string tm, Span span) : ITracerLike
    {
        public ISpanLike StartSpan(string name)
        {
            var e = Ev("startSpan"); e["name"] = name; events.Add(e);
            if (tm == "startThrows") throw new InvalidOperationException("exporter boom");
            return span;
        }
    }

    sealed class Counter(L events, string mm) : ICounterLike
    {
        public void Add(double n, D? attrs)
        {
            var x = Ev("add"); x["v"] = JsX.Number(n); x["a"] = attrs; events.Add(x);
            if (mm == "addThrows") throw new InvalidOperationException("exporter boom");
        }
    }

    sealed class Histogram(L events, string mm) : IHistogramLike
    {
        public void Record(double n, D? attrs)
        {
            var x = Ev("record"); x["v"] = JsX.Number(n); x["a"] = attrs; events.Add(x);
            if (mm == "recordThrows") throw new InvalidOperationException("exporter boom");
        }
    }

    sealed class Meter(L events, string mm) : IMeterLike
    {
        public ICounterLike CreateCounter(string name)
        {
            var e = Ev("createCounter"); e["name"] = name; events.Add(e);
            if (mm == "createThrows") throw new InvalidOperationException("exporter boom");
            return new Counter(events, mm);
        }

        public IHistogramLike CreateHistogram(string name)
        {
            var e = Ev("createHistogram"); e["name"] = name; events.Add(e);
            return new Histogram(events, mm);
        }
    }

    [Fact]
    public void InstrumentScenario() => Base.Check(M, "instrumentScenario", a =>
    {
        var spec = (D)a[0]!;
        var events = new L();
        var tm = spec.GetValueOrDefault("tracerMode") as string ?? "ok";
        var mm = spec.GetValueOrDefault("meterMode") as string ?? "ok";
        var g = (D)spec["guard"]!;
        Func<string, Task<object?>> guard = async _ =>
        {
            await Task.Yield();
            if (g.GetValueOrDefault("throws") is string msg) throw new InvalidOperationException(msg);
            return g.GetValueOrDefault("result");
        };
        var o = new InstrumentGuardOptions { SpanName = spec.GetValueOrDefault("spanName") as string, Redact = Mode(spec.GetValueOrDefault("redact")) };
        if (spec.GetValueOrDefault("tracer") is true) o.Tracer = new Tracer(events, tm, new Span(events, tm));
        if (spec.GetValueOrDefault("meter") is true) o.Meter = new Meter(events, mm);
        var outp = new D();
        Func<string, Task<object?>> wrapped;
        try { wrapped = O.InstrumentGuard(guard, o); }
        catch (Exception e)
        {
            outp["wrap"] = e.Message;
            outp["events"] = events;
            return outp;
        }
        D outcome;
        try { outcome = new D { ["result"] = wrapped("req").GetAwaiter().GetResult() }; }
        catch (Exception e) { outcome = new D { ["threw"] = e.Message }; }
        outp["outcome"] = outcome;
        outp["events"] = events;
        return outp;
    });

    [Fact] public void AllFnsCovered() { Base.Covers(M, new[] { "redactSecrets", "pcaSpanAttributes", "instrumentScenario" }); Assert.Equal(1075, Base.Total(M)); }
}

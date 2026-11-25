using System.Diagnostics;
using System.Diagnostics.Metrics;
using System.Text.RegularExpressions;
using AtlasPca.InteropJs;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Otel;

/// <summary>Minimal structural shape of an OpenTelemetry <c>Span</c>: only the methods this package touches. <c>v</c> is a string, a number or a bool.</summary>
public interface ISpanLike
{
    void SetAttribute(string k, object? v);
    /// <summary><paramref name="message"/> is null when the status carries none.</summary>
    void SetStatus(int code, string? message);
    void RecordException(Exception e);
    void End();
}

public interface ITracerLike { ISpanLike StartSpan(string name); }
public interface ICounterLike { void Add(double n, D? attrs); }
public interface IHistogramLike { void Record(double n, D? attrs); }

public interface IMeterLike
{
    ICounterLike CreateCounter(string name);
    IHistogramLike CreateHistogram(string name);
}

/// <summary>Options of <see cref="OtelGuard.InstrumentGuard{TReq}"/>; leave tracer and meter null for a pure pass-through.</summary>
public sealed class InstrumentGuardOptions
{
    public ITracerLike? Tracer;
    public IMeterLike? Meter;
    public string? SpanName;
    /// <summary>Applied to every string that leaves in a span attribute, a status message or a recorded exception (default <see cref="OtelGuard.RedactSecrets"/>).</summary>
    public Func<string, string>? Redact;
}

/// <summary>A fresh error handed to <c>RecordException</c>: the original may carry credentials in its message, cause or stack. It is never thrown, so it has no stack trace.</summary>
public sealed class CleanError : Exception
{
    /// <summary>The original exception's type name when it is a plain word of at most 64 characters, else "Error".</summary>
    public string ErrorName { get; }
    internal CleanError(string name, string message) : base(message) { ErrorName = name; }
}

/// <summary>
/// OpenTelemetry instrumentation for Proof-Carrying Authority: wrap a verification guard so every decision emits a span (decision / tier / risk / verb /
/// resource) and two metrics. The telemetry types are tiny structural interfaces; <see cref="ActivityTracer"/> and <see cref="MetricsMeter"/> adapt
/// <c>System.Diagnostics.ActivitySource</c> and <c>System.Diagnostics.Metrics.Meter</c> (both in the base class library) to them. It observes and never decides:
/// with no tracer and no meter the wrapper returns the guard's result unchanged. Guard results and verdicts are JSON trees.
/// </summary>
public static class OtelGuard
{
    /// <summary>OpenTelemetry <c>SpanStatusCode</c>: UNSET = 0, OK = 1, ERROR = 2.</summary>
    public const int StatusOk = 1, StatusError = 2;

    const int MaxText = 256;

    // JavaScript whitespace (what \s matches), spelled out because the .NET \s differs.
    const string Ws = @" \t\n\u000B\f\r   - \u2028\u2029  　﻿";
    // \b before a word character, spelled out because the .NET \b is Unicode-aware.
    const string Wb = "(?<![A-Za-z0-9_])";

    /// <summary>A literal word matched case-insensitively over ASCII letters only (the JavaScript i flag without u does not fold the Kelvin sign into k).</summary>
    static string Ci(string word) => string.Concat(word.Select(c => char.IsAsciiLetter(c) ? $"[{char.ToLowerInvariant(c)}{char.ToUpperInvariant(c)}]" : Regex.Escape(c.ToString())));

    const string WordDash = @"A-Za-z0-9_\-";
    static readonly Regex Jwt = new(Wb + "eyJ[" + WordDash + "]{5,}\\.[" + WordDash + "]{5,}\\.[" + WordDash + "]*", RegexOptions.CultureInvariant);
    static readonly Regex AuthHeader = new(Wb + "(" + Ci("authorization") + "[\"']?[" + Ws + "]*[:=][" + Ws + "]*)[^\\n\"']*", RegexOptions.CultureInvariant);
    static readonly Regex Scheme = new(Wb + "(" + Ci("Bearer") + "|" + Ci("Basic") + "|" + Ci("Token") + ")[" + Ws + @"]+[A-Za-z0-9_.~+/=\-]{6,}", RegexOptions.CultureInvariant);
    static readonly Regex UrlUserinfo = new(@"([A-Za-z][A-Za-z0-9+.\-]*://)[^" + Ws + @"/@]*:[^" + Ws + @"/@]*@", RegexOptions.CultureInvariant);
    static readonly Regex Keyed = new(Wb + "((?:" + string.Join("|", new[] { Ci("token"), Ci("secret"), Ci("password"), Ci("passwd"), Ci("pwd"), Ci("api") + "[_-]?" + Ci("key"), Ci("key"), Ci("signature"), Ci("sig"), Ci("credential"), Ci("auth") })
        + ")[\"']?[" + Ws + "]*[:=][" + Ws + "]*)(\"[^\"]*\"|'[^']*'|[^" + Ws + "\"'&,;]+)", RegexOptions.CultureInvariant);
    static readonly Regex LongRun = new("[A-Za-z0-9_-]{32,}", RegexOptions.CultureInvariant);

    /// <summary>Remove what looks like a credential from text bound for telemetry: JWTs, Bearer and Basic credentials, URL userinfo, name=value pairs whose name
    /// is token, secret, password, key, signature, credential or authorization, and long unbroken base64url or hex runs (32+ characters). The result is cut to
    /// 256 characters. A pattern list is a net, not a proof: keep secrets out of resources and reasons in the first place.</summary>
    public static string RedactSecrets(string? text)
    {
        var t = text ?? "null";
        t = Jwt.Replace(t, "[redacted]");
        t = AuthHeader.Replace(t, m => m.Groups[1].Value + "[redacted]");
        t = Scheme.Replace(t, m => m.Groups[1].Value + " [redacted]");
        t = UrlUserinfo.Replace(t, m => m.Groups[1].Value + "[redacted]@");
        t = Keyed.Replace(t, m =>
        {
            var val = m.Groups[2].Value;
            var q = val[0] is '"' or '\'' ? val[..1] : "";
            return m.Groups[1].Value + q + "[redacted]" + q;
        });
        t = LongRun.Replace(t, "[redacted]");
        return t.Length > MaxText ? t[..MaxText] + "..." : t;
    }

    static object? G(object? o, string k) => o is D m ? m.GetValueOrDefault(k) : null;

    /// <summary><c>o?.[0]</c> over a JSON value: the first element of an array, the first character of a string, member "0" of an object.</summary>
    static object? First(object? o) => o switch
    {
        L l => l.Count == 0 ? null : l[0],
        string s => s.Length == 0 ? null : s[..1],
        D m => m.GetValueOrDefault("0"),
        _ => null,
    };

    /// <summary>The first deny reason, if any (a string), used for the span's error message and the <c>pca.reason</c> attribute.</summary>
    static string? FirstReason(object? result) => First(G(G(result, "verdict"), "reasons")) as string;

    static double? Finite(object? v) => IntentJs.NumOf(v) is double d && double.IsFinite(d) ? d : null;

    /// <summary>Map a guard result to OpenTelemetry span attributes. Fields the verdict lacks are omitted; <c>pca.reason</c> is added on deny only; anything but an
    /// explicit <c>ok: true</c> is reported as a deny.</summary>
    public static D PcaSpanAttributes(object? result, Func<string, string>? redact = null)
    {
        var rd = redact ?? RedactSecrets;
        var ok = G(result, "ok") is true;
        var attrs = new D { ["pca.decision"] = ok ? "allow" : "deny" };
        var status = G(result, "status");
        if (Finite(status) != null) attrs["pca.status"] = status;
        var verdict = G(result, "verdict");
        var tier = G(G(verdict, "requiredThreshold"), "t");
        if (Finite(tier) != null) attrs["pca.tier"] = tier;
        var risk = G(verdict, "r");
        if (Finite(risk) != null) attrs["pca.risk"] = risk;
        var action = G(G(result, "pcactn"), "action");
        if (G(action, "verb") is string verb) attrs["pca.verb"] = rd(verb);
        if (G(action, "resource") is string resource) attrs["pca.resource"] = rd(resource);
        if (!ok && FirstReason(result) is { } reason) attrs["pca.reason"] = rd(reason);
        return attrs;
    }

    static void Safe(Action f)
    {
        try { f(); }
        catch (Exception) { /* the decision is the guard's, not the exporter's */ }
    }

    static bool PlainWord(string s) => s.Length is >= 1 and <= 64 && s.All(c => c is >= 'A' and <= 'Z' or >= 'a' and <= 'z' or >= '0' and <= '9' or '_');

    /// <summary>Wrap a verification guard so each decision emits a span and metrics; the result is returned unchanged. A span named <c>SpanName</c> (default
    /// "pca.verify") is annotated with <see cref="PcaSpanAttributes"/>, given OK status on allow and ERROR status plus the first reason on deny, and always ended.
    /// When the guard throws, a redacted copy of the exception is recorded and the original is re-thrown. A <c>pca.verifications</c> counter and a
    /// <c>pca.verify.risk</c> histogram are created once and fed per decision. A tracer or meter that throws never changes what the guard decided.</summary>
    public static Func<TReq, Task<object?>> InstrumentGuard<TReq>(Func<TReq, Task<object?>> guard, InstrumentGuardOptions? opts = null)
    {
        var tracer = opts?.Tracer;
        var meter = opts?.Meter;
        var spanName = opts?.SpanName ?? "pca.verify";
        // metrics instruments are created once, up front, not per call
        var counter = meter?.CreateCounter("pca.verifications");
        var histogram = meter?.CreateHistogram("pca.verify.risk");
        var redact = opts?.Redact ?? RedactSecrets;

        return async req =>
        {
            ISpanLike? span = null;
            Safe(() => { span = tracer?.StartSpan(spanName); });
            try
            {
                var result = await guard(req).ConfigureAwait(false);
                if (span != null)
                {
                    var sp = span;
                    Safe(() =>
                    {
                        foreach (var (k, v) in PcaSpanAttributes(result, redact)) sp.SetAttribute(k, v);
                        var ok = G(result, "ok") is true;
                        var reason = ok ? null : FirstReason(result);
                        if (ok) sp.SetStatus(StatusOk, null);
                        else sp.SetStatus(StatusError, reason != null ? redact(reason) : null);
                    });
                }
                var decision = G(result, "ok") is true ? "allow" : "deny";
                Safe(() => counter?.Add(1, new D { ["decision"] = decision }));
                var risk = Finite(G(G(result, "verdict"), "r"));
                if (histogram != null && risk is double rv) Safe(() => histogram.Record(rv, new D { ["decision"] = decision }));
                return result;
            }
            catch (Exception e)
            {
                if (span != null)
                {
                    var sp = span;
                    Safe(() =>
                    {
                        // a fresh error: the original may carry credentials in its message, its cause or its stack
                        var simple = e.GetType().Name;
                        var clean = new CleanError(PlainWord(simple) ? simple : "Error", redact(e.Message));
                        sp.RecordException(clean);
                        sp.SetStatus(StatusError, clean.Message);
                    });
                }
                throw;
            }
            finally
            {
                var sp = span;
                if (sp != null) Safe(() => sp.End());
            }
        };
    }

    static object? Tag(object? v) => v is Num n ? IntentJs.NumOf(n) : v;

    /// <summary>Adapts a <see cref="System.Diagnostics.ActivitySource"/> to <see cref="ITracerLike"/>: each span is an <see cref="Activity"/> (none when nothing listens).</summary>
    public sealed class ActivityTracer(ActivitySource source) : ITracerLike
    {
        sealed class ActivitySpan(Activity? activity) : ISpanLike
        {
            public void SetAttribute(string k, object? v) => activity?.SetTag(k, Tag(v));
            public void SetStatus(int code, string? message) =>
                activity?.SetStatus(code == StatusOk ? ActivityStatusCode.Ok : code == StatusError ? ActivityStatusCode.Error : ActivityStatusCode.Unset, message);
            public void RecordException(Exception e) =>
                activity?.AddEvent(new ActivityEvent("exception", tags: new ActivityTagsCollection { ["exception.type"] = (e as CleanError)?.ErrorName ?? e.GetType().Name, ["exception.message"] = e.Message }));
            public void End() => activity?.Stop();
        }

        public ISpanLike StartSpan(string name) => new ActivitySpan(source.StartActivity(name));
    }

    /// <summary>Adapts a <see cref="System.Diagnostics.Metrics.Meter"/> to <see cref="IMeterLike"/>: a long counter and a double histogram.</summary>
    public sealed class MetricsMeter(Meter meter) : IMeterLike
    {
        static TagList Tags(D? attrs)
        {
            var t = new TagList();
            if (attrs != null) foreach (var (k, v) in attrs) t.Add(k, Tag(v));
            return t;
        }

        sealed class CounterAdapter(Counter<long> c) : ICounterLike { public void Add(double n, D? attrs) => c.Add((long)n, Tags(attrs)); }
        sealed class HistogramAdapter(Histogram<double> h) : IHistogramLike { public void Record(double n, D? attrs) => h.Record(n, Tags(attrs)); }

        public ICounterLike CreateCounter(string name) => new CounterAdapter(meter.CreateCounter<long>(name));
        public IHistogramLike CreateHistogram(string name) => new HistogramAdapter(meter.CreateHistogram<double>(name));
    }
}

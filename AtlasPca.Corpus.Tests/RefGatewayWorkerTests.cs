using AtlasPca;
using AtlasPca.Gateway;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>The runtime-free Worker adapter replayed against the reference with a structural request (method, url, headers) and injected next / respond.</summary>
public class RefGatewayWorkerTests
{
    const string M = "ref-gateway-worker";

    // header names lower-cased and iterated sorted, as a fetch Headers does
    sealed class Req : IWorkerRequest<Req>
    {
        public string Method { get; }
        public string Url { get; }
        public SortedDictionary<string, string> Headers { get; } = new(StringComparer.Ordinal);
        /// <summary>A fetch Headers that can look a name up but not enumerate (no forEach).</summary>
        public bool GetOnly { get; init; }
        public Req(string method, string url, IEnumerable<KeyValuePair<string, string>> h)
        {
            Method = method; Url = url;
            foreach (var (k, v) in h) Headers[k.ToLowerInvariant()] = v;
        }
        public string? Header(string name) => Headers.GetValueOrDefault(name.ToLowerInvariant());
        public IEnumerable<string> HeaderNames => GetOnly ? Array.Empty<string>() : Headers.Keys;
        public string? ReadBody() => null;
        public Req? WithoutHeaders(IReadOnlyList<string> drop) => new(Method, Url, Headers.Where(e => !drop.Contains(e.Key)));
    }

    /// <summary>The scenario of the second corpus: {spec, req: {method, url, headers}, mode: plain | getonly | norewrite} to
    /// ["next", method, url, sorted header names] | ["respond", body, status, headers] | {create}.</summary>
    static object? ModeScenario(D a)
    {
        var spec = (D)a["spec"]!; var rq = (D)a["req"]!; var mode = (string)a["mode"]!;
        var orig = ((D)rq["headers"]!).Select(e => KeyValuePair.Create(e.Key, (string)e.Value!)).ToList();
        Func<Req, IReadOnlyList<string>, Req?>? rewrite = mode == "norewrite" ? null
            : (r, drop) => new Req(r.Method, r.Url, orig.Where(e => !drop.Contains(e.Key.ToLowerInvariant())));
        Func<Req, object?> w;
        try
        {
            w = PcaGateway.CloudflareWorker<Req, object?>(RefGatewayTests.Build(spec),
                r => new L { "next", r.Method, r.Url, r.HeaderNames.Cast<object?>().ToList() },
                (body, status, h) => new L { "respond", RefGatewayTests.Mask(body), (long)status, h.ToDictionary(e => e.Key, e => (object?)e.Value) },
                rewrite, defaultRewrite: mode != "norewrite");
        }
        catch (ArgumentException e) { return new D { ["create"] = e.Message }; }
        var req = new Req((string)rq["method"]!, (string)rq["url"]!, orig) { GetOnly = mode == "getonly" };
        return w(req);
    }

    static object? Scenario(D spec)
    {
        if (spec.ContainsKey("mode")) return ModeScenario(spec);
        var ev = (D)((L)spec["events"]!)[0]!;
        var headers = ((D)ev["headers"]!).Select(e => KeyValuePair.Create(e.Key, (string)e.Value!)).ToList();
        var mode = ev.GetValueOrDefault("rewrite") as string;
        Func<Req, IReadOnlyList<string>, Req?>? rewrite = null;
        if (mode == "custom")
            rewrite = (r, drop) =>
            {
                var h = r.Headers.Where(e => !drop.Contains(e.Key)).ToList();
                h.Add(KeyValuePair.Create("x-rewritten", string.Join(",", drop)));
                return new Req(r.Method, r.Url, h);
            };
        Func<Req, object?> w;
        try
        {
            w = PcaGateway.CloudflareWorker<Req, object?>(RefGatewayTests.Build(spec),
                r => new D { ["forwarded"] = new D { ["method"] = r.Method, ["url"] = r.Url, ["headers"] = r.Headers.ToDictionary(e => e.Key, e => (object?)e.Value) } },
                (body, status, h) => new D { ["status"] = status, ["headers"] = h.ToDictionary(e => e.Key, e => (object?)e.Value), ["body"] = Pca.ParseJson(body) },
                rewrite, defaultRewrite: mode != "null");
        }
        catch (ArgumentException e) { return new D { ["create"] = e.Message }; }
        return RefGatewayTests.Mask(w(new Req((string)ev["method"]!, (string)ev["url"]!, headers)));
    }

    [Fact] public void WorkerScenario() => Base.Check(M, "workerScenario", a => Scenario((D)a[0]!));

    [Fact] public void Covers() { Base.Covers(M, new[] { "workerScenario" }); Assert.Equal(110, Base.Total(M)); }
}

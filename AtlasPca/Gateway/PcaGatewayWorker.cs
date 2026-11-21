using AtlasPca.Js;
using D = System.Collections.Generic.Dictionary<string, object?>;

namespace AtlasPca.Gateway;

/// <summary>The structural subset of a fetch-style request the Worker adapter reads: no runtime types, so any host that can say method, URL and headers fits.</summary>
public interface IWorkerRequest<TSelf> where TSelf : IWorkerRequest<TSelf>
{
    string Method { get; }
    string Url { get; }
    /// <summary>The first value of a header (case-insensitive), or null.</summary>
    string? Header(string name);
    /// <summary>Every header name the request carries (any case).</summary>
    IEnumerable<string> HeaderNames { get; }
    /// <summary>Full-policy mode with the body as the params reads the body here (the request still goes upstream intact); null when the request cannot be read.</summary>
    string? ReadBody();
    /// <summary>A copy without the named (lower-case) headers, or null when this request cannot be rewritten (the adapter then answers 400).</summary>
    TSelf? WithoutHeaders(IReadOnlyList<string> drop);
}

public static partial class PcaGateway
{
    /// <summary>
    /// The fetch-style (Cloudflare Worker) middleware, free of any runtime: verify the inbound PCActn, then on allow call <paramref name="next"/> with every
    /// inbound <c>x-pca-*</c> header removed (a client cannot forge the headers the gateway owns); on deny <paramref name="respond"/> builds the answer
    /// (the guard's status, its WWW-Authenticate challenge, a JSON <c>{error, reason}</c> body). The upstream is never reached on a deny.
    /// <paramref name="rewrite"/> overrides how the forged headers are removed; with <paramref name="rewrite"/> null and <paramref name="defaultRewrite"/> false the
    /// rewrite is opted out and a request carrying an <c>x-pca-*</c> header is answered 400 instead of forwarded.
    /// </summary>
    public static Func<TReq, TRes> CloudflareWorker<TReq, TRes>(GatewayOptions opts, Func<TReq, TRes> next,
        Func<string, int, IReadOnlyDictionary<string, string>, TRes> respond,
        Func<TReq, IReadOnlyList<string>, TReq?>? rewrite = null, bool defaultRewrite = true) where TReq : class, IWorkerRequest<TReq>
    {
        var gateway = CreateGateway(opts);
        return request =>
        {
            var (path, authority, query) = WorkerPathFromUrl(request.Url);
            var headers = new D();
            if (request.Header(PcaHeader) is { } ph) headers[PcaHeader.ToLowerInvariant()] = ph;
            foreach (var h in new[] { "pca-discharges", "pca-narrow" }) if (request.Header(h) is { } v) headers[h] = v;
            var req = new D { ["method"] = request.Method, ["path"] = path, ["query"] = query, ["authority"] = authority, ["headers"] = headers };
            if (opts.PolicyMode == "full" && opts.Full is { ParamsFn: null, ParamsFromBody: true } && request.ReadBody() is { } body) req["body"] = body;
            var d = gateway(req);
            if (d.Allow)
            {
                var forged = new SortedSet<string>(StringComparer.Ordinal);
                foreach (var k in request.HeaderNames) { var l = k.ToLowerInvariant(); if (l.StartsWith("x-pca-", StringComparison.Ordinal)) forged.Add(l); }
                foreach (var n in PcaInjectedHeaders) if (request.Header(n) != null) forged.Add(n);
                if (forged.Count == 0) return next(request);
                var drop = forged.ToList();
                var clean = rewrite != null ? rewrite(request, drop) : defaultRewrite ? request.WithoutHeaders(drop) : null;
                if (clean != null) return next(clean);
                return respond(JsJson.Stringify(new D { ["error"] = "forged-pca-header", ["reason"] = "inbound x-pca-* header cannot be removed" }), 400,
                    new Dictionary<string, string> { ["content-type"] = "application/json" });
            }
            var h2 = new Dictionary<string, string> { ["content-type"] = "application/json" };
            foreach (var (k, v) in d.Headers) h2[k] = v;
            return respond(JsJson.Stringify(new D { ["error"] = d.Code, ["reason"] = d.Reason }), d.Status, h2);
        };
    }

    // the path, authority and query of a request URL without a URL parser (a fragment ends the path)
    static (string Path, string Authority, string Query) WorkerPathFromUrl(string url)
    {
        var rest = url;
        var authority = "";
        var scheme = rest.IndexOf("://", StringComparison.Ordinal);
        if (scheme >= 0)
        {
            rest = rest[(scheme + 3)..];
            var slash = rest.IndexOf('/');
            if (slash >= 0) { authority = rest[..slash]; rest = rest[slash..]; } else { authority = rest; rest = "/"; }
        }
        var mark = rest.IndexOfAny(new[] { '?', '#' });
        var path = mark >= 0 ? rest[..mark] : rest;
        return (path.Length == 0 ? "/" : path, authority, QueryOfTarget(rest));
    }
}

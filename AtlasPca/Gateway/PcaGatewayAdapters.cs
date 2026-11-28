using System.Globalization;
using AtlasPca.Js;
using static AtlasPca.InteropJs.JsX;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Gateway;

/// <summary>The Envoy ext_authz (HTTP and gRPC) shapes, the AWS Lambda authorizers and the proxy join, as plain functions over event objects. The
/// Cloudflare Worker adapter runs JavaScript and has no port.</summary>
public static partial class PcaGateway
{
    public const int GrpcOk = 0;
    public const int GrpcUnauthenticated = 16;
    public const int GrpcPermissionDenied = 7;
    public const int GrpcUnavailable = 14;
    public const int OverwriteIfExistsOrAdd = 2;

    static D DenyResponse(GatewayDecision d)
    {
        var h = new D { ["content-type"] = "application/json" };
        foreach (var (k, v) in d.Headers) h[k] = v;
        return new D { ["status"] = d.Status, ["headers"] = h, ["body"] = JsJson.Stringify(new D { ["error"] = d.Code, ["reason"] = d.Reason }) };
    }

    /// <summary>Join a gateway to an injected upstream: on allow, <paramref name="upstream"/> is called with every client-supplied x-pca-* header
    /// removed and the decision's headers set; on deny the 401 / 403 response is returned and the upstream is never called.</summary>
    public static Func<D, object?> GatewayProxy(GatewayOptions opts, Func<D, GatewayDecision, object?> upstream)
    {
        var gateway = CreateGateway(opts);
        return req =>
        {
            var d = gateway(req);
            if (!d.Allow) return DenyResponse(d);
            var hdrs = new D();
            if (G(req, "headers") is D rh)
                foreach (var (k, v) in rh)
                    if (!PcaInjectedHeaders.Contains(k.ToLowerInvariant())) hdrs[k] = v;
            foreach (var (k, v) in d.Headers) hdrs[k] = v;
            var o = new D(req) { ["headers"] = hdrs };
            return upstream(o, d);
        };
    }

    // ---- Envoy HTTP ext_authz ----
    static string QueryOfTarget(string target)
    {
        var q = target.IndexOf('?');
        if (q < 0) return "";
        var rest = target[(q + 1)..];
        var h = rest.IndexOf('#');
        return h >= 0 ? rest[..h] : rest;
    }

    static D EnvoyRequest(D check)
    {
        var headers = First(G(check, "headers"), new D());
        var method = First(G(check, "method"), G(headers, ":method"), "*");
        var target = (string)First(G(check, "path"), G(headers, ":path"), "/")!;
        var m = target.IndexOfAny(new[] { '?', '#' });
        var rawPath = m >= 0 ? target[..m] : target;
        var req = new D { ["method"] = method, ["path"] = rawPath.Length == 0 ? "/" : rawPath, ["query"] = QueryOfTarget(target), ["headers"] = headers };
        var authority = First(G(check, "authority"), G(headers, ":authority"));
        if (authority != null) req["authority"] = authority;
        if (G(check, "body") != null) req["body"] = check["body"];
        return req;
    }

    /// <summary>Envoy HTTP ext_authz handler: 200 plus the verified verdict headers on allow (every injected header is overwritten, the unset ones
    /// blank), the guard's 401 / 403 with a WWW-Authenticate challenge and a JSON body on deny.</summary>
    public static Func<D, D> EnvoyExtAuthz(GatewayOptions opts)
    {
        var gateway = CreateGateway(opts);
        return c =>
        {
            var d = gateway(EnvoyRequest(c));
            if (!d.Allow)
                return DenyResponse(d);
            var h = new D();
            foreach (var k in PcaInjectedHeaders) h[k] = "";
            foreach (var (k, v) in d.Headers) h[k] = v;
            return new D { ["status"] = 200, ["headers"] = h, ["body"] = "" };
        };
    }

    // ---- Envoy gRPC ext_authz ----
    static L HeaderOptions(IEnumerable<KeyValuePair<string, string>> h) =>
        h.Select(kv => (object?)new D { ["header"] = new D { ["key"] = kv.Key, ["value"] = kv.Value }, ["appendAction"] = OverwriteIfExistsOrAdd }).ToList();

    /// <summary>Envoy gRPC ext_authz <c>Check</c> handler over a decoded CheckRequest (camelCase). On allow it also lists every x-pca-* header it did not
    /// set in <c>headersToRemove</c>, so a client cannot smuggle a forged verdict through an unmapped-route allow.</summary>
    public static Func<D, D> EnvoyGrpcExtAuthz(GatewayOptions opts)
    {
        var gateway = CreateGateway(opts);
        return c =>
        {
            var http = G(G(G(c, "attributes"), "request"), "http");
            if (!Jt(http))
                return new D
                {
                    ["status"] = new D { ["code"] = GrpcPermissionDenied, ["message"] = "no http request attributes" },
                    ["deniedResponse"] = new D
                    {
                        ["status"] = new D { ["code"] = 403 }, ["headers"] = new L(),
                        ["body"] = JsJson.Stringify(new D { ["error"] = "invalid-request", ["reason"] = "CheckRequest carried no HTTP attributes" }),
                    },
                };
            var headers = First(G(http, "headers"), new D());
            var req = new D { ["headers"] = headers };
            var method = First(G(http, "method"), G(headers, ":method"));
            if (method != null) req["method"] = method;
            var path = First(G(http, "path"), G(headers, ":path"));
            if (path != null) req["path"] = path;
            var authority = First(G(http, "host"), G(headers, ":authority"));
            if (authority != null) req["authority"] = authority;
            if (G(http, "body") != null) req["body"] = ((D)http!)["body"];
            var d = gateway(EnvoyRequest(req));
            if (d.Allow)
                return new D
                {
                    ["status"] = new D { ["code"] = GrpcOk, ["message"] = "" },
                    ["okResponse"] = new D
                    {
                        ["headers"] = HeaderOptions(d.Headers),
                        ["headersToRemove"] = PcaInjectedHeaders.Where(h => !d.Headers.ContainsKey(h)).Cast<object?>().ToList(),
                    },
                };
            var code = d.Status == 401 ? GrpcUnauthenticated : d.Status == 503 ? GrpcUnavailable : GrpcPermissionDenied;
            var hs = new Dictionary<string, string> { ["content-type"] = "application/json" };
            foreach (var (k, v) in d.Headers) hs[k] = v;
            return new D
            {
                ["status"] = new D { ["code"] = code, ["message"] = d.Reason },
                ["deniedResponse"] = new D
                {
                    ["status"] = new D { ["code"] = d.Status }, ["headers"] = HeaderOptions(hs),
                    ["body"] = JsJson.Stringify(new D { ["error"] = d.Code, ["reason"] = d.Reason }),
                },
            };
        };
    }

    // ---- AWS Lambda authorizers ----
    static string EncodeUriComponentOf(object? s) => JsJson.EncodeUriComponent(Str(s));

    static string LambdaResource(D ev) => (string)First(G(ev, "methodArn"), G(ev, "routeArn"), "*")!;

    static (object? Method, object? Path) LambdaMethodPath(D ev)
    {
        var http = G(G(ev, "requestContext"), "http");
        var method = First(G(http, "method"), G(ev, "httpMethod"));
        var path = First(G(ev, "rawPath"), G(ev, "path"), G(http, "path"));
        if (method != null && path != null) return (method, path);
        var arn = (string?)First(G(ev, "methodArn"), G(ev, "routeArn"));
        if (arn != null)
        {
            var parts = string.Join(":", arn.Split(':').Skip(5)).Split('/');
            var arnMethod = parts.Length > 2 ? parts[2].Split(' ')[0] : null;
            return (First(method, arnMethod, "*"), First(path, "/" + string.Join("/", parts.Skip(3))));
        }
        return (First(method, "*"), First(path, "/"));
    }

    /// <summary>The elements of a <c>for (const x of v)</c>: a list's items, a string's code points; anything else is not iterable.</summary>
    static IEnumerable<object?> Iterate(object? v)
    {
        if (v is L l) return l;
        if (v is string s)
        {
            var o = new List<object?>();
            for (int i = 0; i < s.Length; i++)
            {
                if (char.IsHighSurrogate(s[i]) && i + 1 < s.Length && char.IsLowSurrogate(s[i + 1])) { o.Add(s.Substring(i, 2)); i++; }
                else o.Add(s[i].ToString());
            }
            return o;
        }
        throw TypeError("not iterable");
    }

    static string LambdaQuery(D ev)
    {
        if (G(ev, "rawQueryString") is string raw) return raw;
        var multi = G(ev, "multiValueQueryStringParameters"); var single = G(ev, "queryStringParameters");
        var pairs = new List<string>();
        if (Jt(multi) && multi is D mm)
        {
            foreach (var (k, vs) in mm)
                foreach (var v in vs != null ? Iterate(vs) : Array.Empty<object?>())
                    pairs.Add(EncodeUriComponentOf(k) + "=" + EncodeUriComponentOf(v));
        }
        else if (Jt(single) && single is D sm)
        {
            foreach (var (k, v) in sm) pairs.Add(EncodeUriComponentOf(k) + "=" + EncodeUriComponentOf(v));
        }
        return string.Join("&", pairs);
    }

    static D LambdaRequest(D ev)
    {
        var (method, path) = LambdaMethodPath(ev);
        return new D { ["method"] = method, ["path"] = path, ["query"] = LambdaQuery(ev), ["headers"] = First(G(ev, "headers"), new D()) };
    }

    static D LambdaContext(GatewayDecision d)
    {
        if (d.Allow) return d.Verdict != null ? new D { ["pcaVerdict"] = JsJson.Stringify(d.Verdict) } : new D();
        return new D { ["pcaDenied"] = "true", ["pcaCode"] = d.Code, ["pcaReason"] = d.Reason, ["pcaStatus"] = d.Status.ToString(CultureInfo.InvariantCulture) };
    }

    /// <summary>AWS API Gateway REQUEST authorizer: an Allow IAM policy (verdict on <c>context.pcaVerdict</c>) on a valid proof, else a Deny policy. REST
    /// (<c>methodArn</c>) and HTTP-API (<c>routeArn</c>) payloads.</summary>
    public static Func<D, D> LambdaAuthorizer(GatewayOptions opts)
    {
        var gateway = CreateGateway(opts);
        return ev =>
        {
            var d = gateway(LambdaRequest(ev));
            return new D
            {
                ["principalId"] = First(G(d.Pcactn, "grant_ref"), "anonymous"),
                ["policyDocument"] = new D
                {
                    ["Version"] = "2012-10-17",
                    ["Statement"] = new L { new D { ["Action"] = "execute-api:Invoke", ["Effect"] = d.Allow ? "Allow" : "Deny", ["Resource"] = LambdaResource(ev) } },
                },
                ["context"] = LambdaContext(d),
            };
        };
    }

    /// <summary>HTTP-API simple-response variant: <c>{isAuthorized, context}</c> instead of an IAM policy.</summary>
    public static Func<D, D> LambdaSimpleAuthorizer(GatewayOptions opts)
    {
        var gateway = CreateGateway(opts);
        return ev =>
        {
            var d = gateway(LambdaRequest(ev));
            return new D { ["isAuthorized"] = d.Allow, ["context"] = LambdaContext(d) };
        };
    }
}

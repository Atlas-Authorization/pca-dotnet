// Vault proxy mode: re-derive the params digest of the OUTBOUND request, and the signed release receipt. The agent never holds the credential: it
// hands the vault the request it wants made; the vault maps that request back to the action's parameters with a pinned extractor and only then
// attaches the token. Anything the request carries that the extractor does not map is a mismatch.
using System.Text.RegularExpressions;
using AtlasPca.Jose;
using AtlasPca.InteropJs;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Connect;

/// <summary>An outbound request as the agent hands it to the vault.</summary>
public sealed class ProxyRequest
{
    public string Method { get; set; } = "";
    /// <summary>Absolute https URL.</summary>
    public string Url { get; set; } = "";
    public Dictionary<string, string>? Headers { get; set; }
    /// <summary>The body as text; null when none.</summary>
    public string? Body { get; set; }

    public ProxyRequest() { }
    public ProxyRequest(string method, string url, Dictionary<string, string>? headers, string? body) { Method = method; Url = url; Headers = headers; Body = body; }

    /// <summary>The request as the reference's plain object (members absent when unset).</summary>
    public D ToJson()
    {
        var o = new D { ["method"] = Method, ["url"] = Url };
        if (Headers != null) o["headers"] = Headers.ToDictionary(e => e.Key, e => (object?)e.Value);
        if (Body != null) o["body"] = Body;
        return o;
    }
}

public sealed class ProxyResponse
{
    public int Status { get; set; }
    public Dictionary<string, string>? Headers { get; set; } = new();
    /// <summary>Null when the transport returned no text body (refused as oversize).</summary>
    public string? Body { get; set; }

    public ProxyResponse() { }
    public ProxyResponse(int status, Dictionary<string, string>? headers, string? body) { Status = status; Headers = headers; Body = body; }
}

/// <summary>The injected outbound transport. It MUST NOT follow redirects (a redirect would send the credential to a host the extractor never saw).</summary>
public delegate ProxyResponse ProxyFetch(string method, string url, Dictionary<string, string> headers, string? body);

/// <summary>One operation's request shape.</summary>
public sealed class HttpRequestSpec
{
    /// <summary>Exact method, upper case.</summary>
    public string Method { get; set; } = "";
    /// <summary><c>https://host/path/{param}/more</c>: literal text matches exactly; each <c>{name}</c> is one path segment. No query, no fragment.</summary>
    public string Url { get; set; } = "";
    /// <summary>Query keys that may appear (null = none).</summary>
    public List<string>? Query { get; set; }
    /// <summary>"json", "form", or null for no body.</summary>
    public string? Body { get; set; }
    /// <summary>Body members the request always carries with exactly these values (null = none).</summary>
    public D? Fixed { get; set; }
}

public static class ConnectProxy
{
    static RequestMismatchError Mismatch(string m) => new("outbound request refused: " + m);

    static readonly Regex Placeholder = new(@"\{([A-Za-z0-9_]+)\}", RegexOptions.CultureInvariant);

    /// <summary>Build the extractor for one operation. Throws on a malformed spec (at configuration time, not at call time). The extractor takes the request as
    /// the reference's plain object (so hostile shapes are refused as the reference refuses them) and returns the action parameters.</summary>
    public static Func<object?, D> HttpExtractor(HttpRequestSpec spec)
    {
        var probe = Placeholder.Replace(spec.Url, "x");
        var u = ConnectJs.ParseUrl(probe) ?? throw new InvalidUrlException();
        if (u.Protocol != "https:" || u.Search.Length != 0 || ConnectJs.HasFragment(probe) || ConnectJs.HasCredentials(probe))
            throw new ArgumentException("httpExtractor: url must be https without query, fragment or userinfo");
        // shortcut: JavaScript's full Unicode upper-casing (ß -> SS) is not mirrored; a method with such a letter is accepted here, upgrade if that matters
        if (spec.Method != spec.Method.ToUpperInvariant()) throw new ArgumentException("httpExtractor: method must be upper case");
        var names = new List<string>();
        var origin = u.Origin;
        var pathTemplate = spec.Url[Math.Min(origin.Length, spec.Url.Length)..];
        var re = new System.Text.StringBuilder(@"\A");
        int last = 0;
        foreach (Match pm in Placeholder.Matches(pathTemplate))
        {
            if (pm.Index > last) re.Append(Regex.Escape(pathTemplate[last..pm.Index]));
            names.Add(pm.Groups[1].Value);
            re.Append("([A-Za-z0-9._~%-]+)");
            last = pm.Index + pm.Length;
        }
        if (last < pathTemplate.Length) re.Append(Regex.Escape(pathTemplate[last..]));
        re.Append(@"\z");
        var pathRe = new Regex(re.ToString(), RegexOptions.CultureInvariant);
        var allowedQuery = new HashSet<string>(spec.Query ?? new List<string>(), StringComparer.Ordinal);
        var ctype = spec.Body == "json" ? "application/json" : spec.Body == "form" ? "application/x-www-form-urlencoded" : null;
        var specMethod = spec.Method;
        var specBody = spec.Body;
        var specFixed = spec.Fixed;

        return req =>
        {
            var methodV = JsX.At(req, "method");
            if (!(methodV is string ms && ms == specMethod)) throw Mismatch($"method {JsX.Str(methodV)} is not {specMethod}");
            var urlText = JsX.Str(JsX.At(req, "url")); // new URL(x) takes String(x)
            var r = ConnectJs.ParseUrl(urlText) ?? throw Mismatch("the url does not parse");
            if (r.Origin != origin || ConnectJs.HasCredentials(urlText) || ConnectJs.HasFragment(urlText)) throw Mismatch("the url is not on the pinned origin");
            var m = pathRe.Match(r.Pathname);
            if (!m.Success) throw Mismatch("the path does not match the pinned template");
            var ps = new D();
            void Put(string k, object? v)
            {
                if (ps.ContainsKey(k)) throw Mismatch($"parameter '{k}' is carried twice");
                ps[k] = v;
            }
            for (int i = 0; i < names.Count; i++)
            {
                string dec;
                try { dec = ConnectJs.DecodeUriComponent(m.Groups[i + 1].Value); }
                catch (FormatException) { throw Mismatch("a path segment is not valid percent-encoding"); }
                Put(names[i], dec);
            }
            var seen = new HashSet<string>(StringComparer.Ordinal);
            foreach (var kv in ConnectJs.FormParse(r.Search.Length == 0 ? "" : r.Search[1..]))
            {
                if (!allowedQuery.Contains(kv[0])) throw Mismatch($"query key '{kv[0]}' is not allowed");
                if (!seen.Add(kv[0])) throw Mismatch($"query key '{kv[0]}' is repeated");
                Put(kv[0], kv[1]);
            }
            object? ct = JsX.Undef;
            var headersV = JsX.At(req, "headers");
            if (headersV is D hd) foreach (var h in hd) if (h.Key.ToLowerInvariant() == "content-type") { ct = h.Value; break; }
            var bodyV = JsX.At(req, "body");
            if (specBody == null)
            {
                if (!ReferenceEquals(bodyV, JsX.Undef) && !(bodyV is string b0 && b0.Length == 0)) throw Mismatch("this operation carries no body");
            }
            else
            {
                if (bodyV is not string body || body.Length == 0) throw Mismatch("the body is missing");
                if (ReferenceEquals(ct, JsX.Undef)) throw Mismatch($"content-type must be {ctype}");
                if (ct is not string cts) throw JsX.TypeError("Cannot read properties of non-string content-type (reading 'split')");
                if (JsX.JsTrim(cts.Split(';')[0]).ToLowerInvariant() != ctype) throw Mismatch($"content-type must be {ctype}");
                var fixedM = specFixed == null ? new D() : new D(specFixed);
                if (specBody == "json")
                {
                    object? b;
                    try { b = Pca.ParseStrict(body); }
                    catch (Exception) { throw Mismatch("the body is not strict JSON"); }
                    if (b is not D bd) throw Mismatch("the body must be a JSON object");
                    foreach (var k in JsX.Keys(bd))
                    {
                        if (fixedM.TryGetValue(k, out var fv))
                        {
                            if (Pca.HashCanonical(bd[k]) != Pca.HashCanonical(fv)) throw Mismatch($"fixed member '{k}' has another value");
                            fixedM.Remove(k);
                        }
                        else Put(k, bd[k]);
                    }
                }
                else
                {
                    var keys = new HashSet<string>(StringComparer.Ordinal);
                    foreach (var kv in ConnectJs.FormParseText(body))
                    {
                        if (!keys.Add(kv[0])) throw Mismatch($"form key '{kv[0]}' is repeated");
                        if (fixedM.TryGetValue(kv[0], out var fv))
                        {
                            if (!(fv is string fs && fs == kv[1])) throw Mismatch($"fixed member '{kv[0]}' has another value");
                            fixedM.Remove(kv[0]);
                        }
                        else Put(kv[0], kv[1]);
                    }
                }
                if (fixedM.Count > 0) throw Mismatch($"fixed member(s) {string.Join(", ", JsX.Keys(fixedM))} missing");
            }
            return ps;
        };
    }

    /// <summary>Request headers the agent may set; the vault sets Authorization itself. Anything else is refused (Host, Cookie, X-HTTP-Method-Override, ...).</summary>
    public static readonly IReadOnlyList<string> DefaultProxyHeaders = new[] { "content-type", "accept", "idempotency-key" };

    /// <summary>The headers the vault may forward, lower-cased; refuses a header outside <paramref name="allow"/>, a repeated one (by lower-cased name) and a value that is not a string without CR, LF or NUL.</summary>
    public static Dictionary<string, string> CheckProxyHeaders(object? headers, IReadOnlyList<string> allow)
    {
        var o = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var k in JsX.Keys(headers))
        {
            var v = JsX.ValueOf(headers, k);
            var n = k.ToLowerInvariant();
            if (!allow.Contains(n)) throw Mismatch($"header '{k}' is not allowed");
            if (o.ContainsKey(n)) throw Mismatch($"header '{k}' is repeated");
            if (v is not string sv || sv.IndexOfAny(new[] { '\r', '\n', '\0' }) >= 0) throw Mismatch($"header '{k}' has an invalid value");
            o[n] = sv;
        }
        return o;
    }

    // ---- release receipt ----

    public const string ReleaseReceiptDomain = "atlas-pca/connect-release-receipt/v1\0";

    /// <summary>Digest of the outbound request as made (method, url, headers sent, body).</summary>
    public static string OutboundRequestDigest(string method, string url, IReadOnlyDictionary<string, string> headers, string? body) =>
        Pca.HashCanonical(new D
        {
            ["d"] = "atlas-pca/connect-request/v1",
            ["method"] = method,
            ["url"] = url,
            ["headers"] = headers.ToDictionary(e => e.Key, e => (object?)e.Value),
            ["body"] = body,
        });

    /// <summary>Sign a receipt body (v, kind, action_digest, provider, connection_id, mode, scopes_released, request_digest, http_status, outcome, ts) under the vault key.</summary>
    public static D SignReleaseReceipt(D body, EdKey vaultKey) => Issue.SignArtifact(ReleaseReceiptDomain, body, SuiteKey.Ed25519(vaultKey));

    /// <summary>True iff the receipt is signed by the pinned vault key (an Ed25519 key; a PQ suite is not pinned here, so it fails).</summary>
    public static bool VerifyReleaseReceipt(D receipt, object? vaultPk) => IntentArtifacts.VerifyArtifactSig(ReleaseReceiptDomain, receipt, vaultPk, null);

    /// <summary>Digest of the exact PCActn that authorized a release.</summary>
    public static string ReceiptActionDigest(D pcActn) => Escalation.ActionDigest(pcActn);
}

using System.Globalization;
using System.Text;
using AtlasPca.InteropJs;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.WebBotAuth;

/// <summary>The part of an HTTP response the directory fetch reads.</summary>
public sealed record FetchResponse(int Status, Func<string, string?> Header, Func<string> Text);

/// <summary>Fetch and strictly parse a Web Bot Auth key directory. FAIL-CLOSED: throws on a non-https URL, a redirect, a non-200 status, a wrong content type, an
/// oversize body, invalid JSON, or any key that is not a well-formed Ed25519 OKP JWK with a string <c>kid</c> and 32-byte <c>x</c>. Never returns a partial directory.
/// shortcut: a directory URL that carries credentials is refused (the reference would pass them on) and a fragment is dropped, as fetch does; only http(s) URLs are
/// accepted. Upgrade if a credentialed directory URL is ever needed.</summary>
public static class DirectoryFetch
{
    /// <summary>The HTTP client: inject your own for SSRF-safe egress. It must NOT follow redirects (a redirect is a failure).</summary>
    public delegate FetchResponse Fetcher(string url, IReadOnlyDictionary<string, string> headers, long timeoutMs);

    /// <summary>The default <see cref="Fetcher"/>: <see cref="HttpClient"/> with redirects disabled.</summary>
    public static FetchResponse HttpFetch(string url, IReadOnlyDictionary<string, string> headers, long timeoutMs)
    {
        using var client = new HttpClient(new HttpClientHandler { AllowAutoRedirect = false }) { Timeout = TimeSpan.FromMilliseconds(timeoutMs) };
        using var request = new HttpRequestMessage(HttpMethod.Get, url);
        foreach (var (k, v) in headers) request.Headers.TryAddWithoutValidation(k, v);
        using var res = client.Send(request);
        var body = res.Content.ReadAsByteArrayAsync().GetAwaiter().GetResult();
        var seen = new Dictionary<string, string>();
        foreach (var h in res.Headers.Concat(res.Content.Headers)) seen.TryAdd(h.Key.ToLowerInvariant(), h.Value.FirstOrDefault() ?? "");
        return new FetchResponse((int)res.StatusCode, name => seen.GetValueOrDefault(name.ToLowerInvariant()), () => Encoding.UTF8.GetString(body));
    }

    /// <summary><paramref name="options"/>: <c>fetch</c> (<see cref="Fetcher"/>, default <see cref="HttpFetch"/>), <c>maxBytes</c> (characters, default 65536), <c>timeoutMs</c>
    /// (default 5000), <c>allowInsecureHttp</c> (tests only), <c>requireSignature</c> (require the signed directory response and return only the keys with a valid signature; throws
    /// when none does), <c>now</c> (epoch seconds for the signature check).</summary>
    public static D FetchKeyDirectory(string url, D? options = null)
    {
        options ??= new D();
        var u = AtlasPca.Jose.WhatwgUrl.TryParse(url) ?? throw new AtlasPca.Jose.InvalidUrlException();
        if (!(u.Protocol is "http:" or "https:" or "ws:" or "wss:" or "ftp:")) throw new ArgumentException("directory URL must be an http(s) URL");
        if (u.Protocol != "https:" && !(options.GetValueOrDefault("allowInsecureHttp") is true && u.Protocol == "http:")) throw new ArgumentException("directory URL must be https");
        var hostport = u.Host;
        int hash = url.IndexOf('#');
        var noFrag = hash >= 0 ? url[..hash] : url;
        int slashes = noFrag.IndexOf("//", StringComparison.Ordinal);
        int authEnd = noFrag.Length;
        for (int k = slashes + 2; k < noFrag.Length; k++) { var c = noFrag[k]; if (c == '/' || c == '\\' || c == '?') { authEnd = k; break; } }
        if (slashes >= 0 && noFrag[(slashes + 2)..authEnd].Contains('@')) throw new ArgumentException("directory URL must not carry credentials");
        var search = WebBotAuth.SearchOfUrl(url);
        var href = u.Protocol + "//" + hostport + u.Pathname + search + (search.Length == 0 && noFrag.Contains('?') ? "?" : "");
        var fetcher = options.GetValueOrDefault("fetch") as Fetcher ?? HttpFetch;
        long timeout = options.GetValueOrDefault("timeoutMs") != null ? (long)WbaJs.Number(options["timeoutMs"]) : 5000L;
        var headers = new Dictionary<string, string> { ["accept"] = "application/http-message-signatures-directory+json" };
        var res = fetcher(href, headers, timeout);
        if (res.Status != 200) throw new InvalidOperationException("directory fetch returned status " + res.Status.ToString(CultureInfo.InvariantCulture));
        var ct = WbaJs.Lower(WbaJs.Trim((res.Header("content-type") ?? "").Split(';')[0]));
        if (ct != "application/http-message-signatures-directory+json") throw new InvalidOperationException("directory has the wrong content type");
        var text = res.Text();
        double max = options.GetValueOrDefault("maxBytes") != null ? WbaJs.Number(options["maxBytes"]) : 65536;
        if (text.Length > max) throw new InvalidOperationException("directory response is too large");
        var directory = SignedDirectory.ParseKeyDirectory(text);
        if (options.GetValueOrDefault("requireSignature") is true)
        {
            var input = new D
            {
                ["authority"] = WbaJs.Lower(hostport),
                ["headers"] = new D { ["signature-input"] = res.Header("signature-input") ?? "", ["signature"] = res.Header("signature") ?? "" },
                ["body"] = text,
            };
            if (options.GetValueOrDefault("now") != null) input["now"] = options["now"];
            var v = SignedDirectory.VerifyDirectoryResponse(input);
            if (v["valid"] is not true) throw new InvalidOperationException("directory signature: " + v["reason"]);
            return new D { ["keys"] = v["keys"] };
        }
        return directory;
    }
}

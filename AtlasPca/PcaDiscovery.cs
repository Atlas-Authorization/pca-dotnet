// Resource-server discovery (the reference discovery.ts, <c>/.well-known/pca-configuration</c>): validate an untrusted discovery document, fetch one
// over an injectable transport, and ask whether the server accepts a suite. The document is PUBLIC configuration; nothing secret belongs in it.
using System.Globalization;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca;

public static partial class PcaDiscovery
{
    public const string WellKnownPcaPath = "/.well-known/pca-configuration";

    static bool IsInt(object? o, double lo, double hi) =>
        o is Num n && double.TryParse(n.Raw, NumberStyles.Float, CultureInfo.InvariantCulture, out var d) && d == Math.Floor(d) && d >= lo && d <= hi && !(d == 0 && n.Raw.StartsWith('-'));

    static ArgumentException Bad(string m) => new("parseDiscoveryDocument: " + m);

    /// <summary>Validate an <c>intent</c> discovery block (throws <see cref="ArgumentException"/> on anything malformed: fail closed).</summary>
    public static D ParseDiscoveryIntent(object? v)
    {
        if (v is not D o) throw Bad("intent must be an object");
        string[] known = { "versions", "actions_uri", "schema_keys", "question_relay", "tiers", "evidence_uri" };
        foreach (var k in o.Keys) if (!known.Contains(k)) throw Bad($"intent has unknown member '{k}'");
        if (o.GetValueOrDefault("versions") is not L vs || vs.Count == 0 || !vs.All(n => IsInt(n, 1, 2))) throw Bad("intent.versions must list 1 and/or 2");
        var outp = new D { ["versions"] = new L(vs) };
        foreach (var k in new[] { "actions_uri", "evidence_uri" })
            if (o.ContainsKey(k))
            {
                if (o[k] is not string s || s.Length == 0) throw Bad($"intent.{k} must be a non-empty string");
                outp[k] = s;
            }
        if (o.ContainsKey("schema_keys"))
        {
            if (o["schema_keys"] is not L sk) throw Bad("intent.schema_keys must be an array");
            outp["schema_keys"] = new L(sk.Select(x =>
            {
                if (x is not D e || e.GetValueOrDefault("kid") is not string kid || e.GetValueOrDefault("alg") is not string alg || e.GetValueOrDefault("pk") is not string pk
                    || (e.ContainsKey("pq_pk") && e["pq_pk"] is not string))
                    throw Bad("intent.schema_keys entries are {kid, alg, pk, pq_pk?}");
                var r = new D { ["kid"] = kid, ["alg"] = alg, ["pk"] = pk };
                if (e.ContainsKey("pq_pk")) r["pq_pk"] = e["pq_pk"];
                return (object?)r;
            }));
        }
        if (o.ContainsKey("question_relay"))
        {
            if (o["question_relay"] is not bool b) throw Bad("intent.question_relay must be a boolean");
            outp["question_relay"] = b;
        }
        if (o.ContainsKey("tiers"))
        {
            if (o["tiers"] is not D t) throw Bad("intent.tiers must be an object");
            if (!t.Values.All(n => IsInt(n, 0, 4))) throw Bad("intent.tiers values must be integers 0..4");
            outp["tiers"] = new D(t);
        }
        return outp;
    }

    /// <summary>Validate and narrow an untrusted value into a discovery document. Throws <see cref="ArgumentException"/> on anything malformed.</summary>
    public static D ParseDiscoveryDocument(object? value)
    {
        if (value is L) throw Bad("missing audience"); // an array is an object without members
        if (value is not D v) throw Bad("not an object");
        if (v.GetValueOrDefault("audience") is not string audience || audience.Length == 0) throw Bad("missing audience");
        if (v.GetValueOrDefault("pca_versions") is not L versions || !versions.All(n => n is Num)) throw Bad("pca_versions must be a number[]");
        if (v.GetValueOrDefault("signature_suites") is not L suites || !suites.All(s => s is string)) throw Bad("signature_suites must be a string[]");
        if (v.GetValueOrDefault("action_header") is not string header || header.Length == 0) throw Bad("missing action_header");
        var doc = new D { ["audience"] = audience, ["pca_versions"] = versions, ["signature_suites"] = suites, ["action_header"] = header };
        if (v.GetValueOrDefault("required_checks") is L rc && rc.All(s => s is string)) doc["required_checks"] = rc;
        if (v.GetValueOrDefault("endpoints") is D or L) doc["endpoints"] = v["endpoints"]; // typeof object: an array counts
        if (v.GetValueOrDefault("trusted_roots") is L tr && tr.All(s => s is string)) doc["trusted_roots"] = tr;
        if (v.GetValueOrDefault("metadata") is D or L) doc["metadata"] = v["metadata"];
        if (v.ContainsKey("intent")) doc["intent"] = ParseDiscoveryIntent(v["intent"]);
        if (v.ContainsKey("obligations_supported"))
        {
            if (v["obligations_supported"] is not L os || !os.All(s => s is string)) throw Bad("obligations_supported must be a string[]");
            doc["obligations_supported"] = new L(os);
        }
        return doc;
    }

    /// <summary>True iff the server (per its discovery document) accepts <paramref name="suite"/>.</summary>
    public static bool AcceptsSuite(D doc, string suite) => doc.GetValueOrDefault("signature_suites") is L l && l.Contains(suite);

    static readonly HttpClient Http = new();

    /// <summary>Fetch and parse a resource server's discovery document: <paramref name="baseUrl"/> is the server origin, the well-known path is appended.
    /// <paramref name="fetch"/> maps a URL to <c>(ok, status, json text)</c> (default: an HttpClient GET). Throws on a non-2xx answer or a malformed document.</summary>
    public static async Task<D> FetchDiscovery(string baseUrl, Func<string, Task<(bool Ok, int Status, string Body)>>? fetch = null)
    {
        var url = baseUrl.TrimEnd('/') + WellKnownPcaPath;
        var (ok, status, body) = await (fetch ?? DefaultFetch)(url).ConfigureAwait(false);
        if (!ok) throw new InvalidOperationException($"fetchDiscovery: {url} returned {status}");
        return ParseDiscoveryDocument(Pca.ParseJson(body));
    }

    static async Task<(bool, int, string)> DefaultFetch(string url)
    {
        using var req = new HttpRequestMessage(HttpMethod.Get, url);
        req.Headers.TryAddWithoutValidation("accept", "application/json");
        using var res = await Http.SendAsync(req).ConfigureAwait(false);
        return (res.IsSuccessStatusCode, (int)res.StatusCode, await res.Content.ReadAsStringAsync().ConfigureAwait(false));
    }
}

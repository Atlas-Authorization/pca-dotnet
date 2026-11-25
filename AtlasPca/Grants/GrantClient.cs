// Thin HttpClient client for the grant management resource (packages/pca-grants client.ts). It also carries the newest pca-fresh-at token
// it has seen: a token that does not verify under FreshSigner (when set) is ignored, and a token never replaces a fresher one.
using System.Net.Http.Headers;
using System.Text;
using AtlasPca.Js;
using JD = System.Collections.Generic.Dictionary<string, object?>;
using JL = System.Collections.Generic.List<object?>;

namespace AtlasPca.Grants;

public sealed class GrantApiException(int status, string code, string message) : Exception(message)
{
    public int Status { get; } = status;
    public string Code { get; } = code;
}

public sealed class GrantClient
{
    static readonly string[] Counters = ["revocation_epoch", "policy_revision", "ledger_tree_size", "budget_version"];
    readonly string _baseUrl;
    readonly HttpClient _http;
    readonly string? _freshSigner;
    readonly Func<IReadOnlyDictionary<string, string>>? _headers;
    readonly object _gate = new();
    JD? _latest;

    /// <param name="http">Inject a client (with a test handler) or leave null.</param>
    /// <param name="freshSigner">The AS's pinned token signer; when set, a fresh-at header that does not verify is ignored.</param>
    public GrantClient(string baseUrl, HttpClient? http = null, string? freshSigner = null, Func<IReadOnlyDictionary<string, string>>? headers = null)
    {
        _baseUrl = baseUrl.EndsWith('/') ? baseUrl[..^1] : baseUrl;
        _http = http ?? new HttpClient();
        _freshSigner = freshSigner;
        _headers = headers;
    }

    /// <summary>The newest consistency token seen on any response (attach it to later requests for read-your-writes), or null.</summary>
    public JD? FreshAt { get { lock (_gate) return _latest; } }

    /// <summary>Fold the newest token into a local state; null when none was seen.</summary>
    public JD? FoldFreshAt(JD state) { lock (_gate) return _latest == null ? null : FreshAtOps.MergeFreshAt(_latest, state); }

    async Task<JD> Call(HttpMethod method, string path, object? body = null, CancellationToken ct = default)
    {
        using var req = new HttpRequestMessage(method, _baseUrl + path);
        JD? latest; lock (_gate) latest = _latest;
        if (latest != null) req.Headers.TryAddWithoutValidation("pca-fresh-at", JsJson.Stringify(latest));
        if (_headers != null) foreach (var (k, v) in _headers()) req.Headers.TryAddWithoutValidation(k, v);
        if (body != null) req.Content = new StringContent(JsJson.Stringify(body), Encoding.UTF8, new MediaTypeHeaderValue("application/json"));
        using var res = await _http.SendAsync(req, ct).ConfigureAwait(false);
        if (res.Headers.TryGetValues("pca-fresh-at", out var toks)) Fold(toks.FirstOrDefault());
        JD json;
        try { json = Pca.ParseJson(await res.Content.ReadAsStringAsync(ct).ConfigureAwait(false)) as JD ?? new JD(); } catch (Exception) { json = new JD(); }
        if (!res.IsSuccessStatusCode)
            throw new GrantApiException((int)res.StatusCode, json.GetValueOrDefault("error") as string ?? "error", json.GetValueOrDefault("message") as string ?? res.ReasonPhrase ?? "");
        return json;
    }

    void Fold(string? tok)
    {
        if (string.IsNullOrEmpty(tok)) return;
        try // a malformed header is ignored: freshness is only ever tightened by a valid token
        {
            if (Pca.ParseJson(tok) is not JD t) return;
            if (_freshSigner != null && !AtlasPca.FreshAt.Verify(t, _freshSigner)) return;
            foreach (var k in Counters) if (!Pca.SafeNat(t.GetValueOrDefault(k), out _)) return;
            lock (_gate)
            {
                var newer = _latest == null || Counters.All(k => { Pca.SafeNat(t[k], out var a); Pca.SafeNat(_latest[k], out var b); return a >= b; });
                if (newer) _latest = t; // monotone fold: never replace a fresher token with an older one
            }
        }
        catch (Exception) { /* ignored */ }
    }

    static string Enc(string s) => JsJson.EncodeUriComponent(s);

    public Task<JD> List(IReadOnlyDictionary<string, string?>? q = null, CancellationToken ct = default)
    {
        var sb = new StringBuilder();
        if (q != null) foreach (var (k, v) in q) { if (v == null) continue; sb.Append(sb.Length == 0 ? '?' : '&').Append(Enc(k)).Append('=').Append(Enc(v)); }
        return Call(HttpMethod.Get, GrantHttp.GrantsPath + sb, null, ct);
    }

    public Task<JD> Inspect(string id, CancellationToken ct = default) => Call(HttpMethod.Get, GrantHttp.GrantsPath + "/" + Enc(id), null, ct);

    public Task<JD> Amend(string id, JD req, CancellationToken ct = default) => Call(HttpMethod.Post, GrantHttp.GrantsPath + "/" + Enc(id) + "/amend", req, ct);

    /// <summary><paramref name="scope"/> null means grant; <paramref name="sig"/> null sends no body (an admin revoke).</summary>
    public Task<JD> Revoke(string id, string? scope = null, string? sig = null, CancellationToken ct = default) =>
        Call(HttpMethod.Delete, GrantHttp.GrantsPath + "/" + Enc(id) + "?scope=" + (scope ?? "grant"), string.IsNullOrEmpty(sig) ? null : new JD { ["sig"] = sig }, ct);

    public Task<JD> RequestNeeds(string id, JL needs, CancellationToken ct = default) => Call(HttpMethod.Post, GrantHttp.GrantsPath + "/" + Enc(id) + "/needs", new JD { ["needs"] = needs }, ct);

    public Task<JD> ApproveNeeds(string needId, JL approved, string sig, string? stepUpRef = null, CancellationToken ct = default)
    {
        var body = new JD { ["approved"] = approved, ["sig"] = sig };
        if (!string.IsNullOrEmpty(stepUpRef)) body["step_up_ref"] = stepUpRef;
        return Call(HttpMethod.Post, GrantHttp.NeedsPath + "/" + Enc(needId) + "/approve", body, ct);
    }

    public Task<JD> DenyNeeds(string needId, CancellationToken ct = default) => Call(HttpMethod.Post, GrantHttp.NeedsPath + "/" + Enc(needId) + "/deny", null, ct);
}

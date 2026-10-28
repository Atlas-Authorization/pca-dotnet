// Step-up client for the principal's device: list the pending step-ups of an instance, approve one with the principal's Ed25519
// device key, or deny it. The device signature over the step-up's threshold message is the credential of the cosign call, so no
// session is needed to approve; listing and denying go through the dashboard API with a bearer token.
//
//   - DashboardUrl + a dashboard bearer token (a service key or console session token) serve the list and deny calls (deny needs an
//     owner or admin role).
//   - InstanceUrl (the host the agent talks to) serves the public, self-authenticating cosign call.
using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Org.BouncyCastle.Math.EC.Rfc8032;

namespace AtlasPca;

/// <summary>Where the 32-byte Ed25519 seed is persisted. <see cref="Load"/> returns null when nothing is stored.</summary>
public interface ISecretStore
{
    byte[]? Load();
    void Save(byte[] secret);
    void Delete();
}

/// <summary>Keeps the seed in memory, for tests and previews only.</summary>
public sealed class MemorySecretStore : ISecretStore
{
    byte[]? _value;
    readonly object _lock = new();

    public byte[]? Load() { lock (_lock) return _value == null ? null : (byte[])_value.Clone(); }
    public void Save(byte[] secret) { lock (_lock) _value = (byte[])secret.Clone(); }
    public void Delete() { lock (_lock) _value = null; }
}

/// <summary>Classifies a <see cref="StepUpException"/>.</summary>
public enum StepUpKind
{
    /// <summary>No principal key is stored yet; call Generate or ImportSecret.</summary>
    NoDeviceKey,
    /// <summary>The principal secret is not a base64url 32-byte Ed25519 seed.</summary>
    InvalidSecret,
    /// <summary>The server's threshold message is not valid base64url.</summary>
    InvalidThresholdMessage,
    /// <summary>The step-up id is not a plain URL segment.</summary>
    InvalidStepUp,
    /// <summary>HTTP 403: this device key is not the grant's principal key; the message is the server's guidance.</summary>
    PrincipalMismatch,
    /// <summary>Any other non-2xx answer (409 already approved, denied or expired, 401, 404, 422, ...).</summary>
    Api,
    /// <summary>A network failure or an unreadable body.</summary>
    Transport,
}

/// <summary>Everything the step-up client throws.</summary>
public sealed class StepUpException : Exception
{
    public StepUpKind Kind { get; }
    /// <summary>The HTTP status, for <see cref="StepUpKind.PrincipalMismatch"/> and <see cref="StepUpKind.Api"/>.</summary>
    public int Status { get; }

    public StepUpException(StepUpKind kind, string message, int status = 0, Exception? inner = null)
        : base(kind == StepUpKind.Api ? $"HTTP {status}: {message}" : message, inner)
    {
        Kind = kind;
        Status = status;
    }
}

/// <summary>
/// The principal's Ed25519 device key. Honest caveat: the PCA principal key MUST be Ed25519, and hardware key stores rarely offer a
/// portable Ed25519 key, so this is a software key: the 32-byte seed lives in the <see cref="ISecretStore"/> you provide (put it in
/// your platform's secure store). Once loaded it is in process memory. Gate approvals behind a user-presence check in your application.
/// </summary>
public sealed class PrincipalDeviceKey
{
    const string BadSecret = "The principal secret must be a base64url-encoded 32-byte Ed25519 seed.";
    readonly ISecretStore _store;

    public PrincipalDeviceKey(ISecretStore store) => _store = store ?? throw new ArgumentNullException(nameof(store));

    /// <summary>Whether a key is stored.</summary>
    public bool Exists()
    {
        try { return _store.Load() is { Length: > 0 }; }
        catch (Exception) { return false; }
    }

    static string PublicOf(byte[] seed)
    {
        var pk = new byte[32];
        Ed25519.GeneratePublicKey(seed, 0, pk, 0);
        return Pca.B64u(pk);
    }

    string Save(byte[] seed)
    {
        try { _store.Save(seed); }
        catch (Exception e) { throw new StepUpException(StepUpKind.Transport, "Could not persist the principal key.", 0, e); }
        return PublicOf(seed);
    }

    /// <summary>Creates a fresh key (replacing any existing one) and returns its public key (base64url) to register as the grant's principal.</summary>
    public string Generate() => Save(RandomNumberGenerator.GetBytes(32));

    /// <summary>Imports an existing principal secret (a base64url 32-byte seed). The key MUST match the grant's principal. Returns the public key.</summary>
    public string ImportSecret(string secretB64u)
    {
        var raw = Pca.B64uDecode(secretB64u, 32) ?? throw new StepUpException(StepUpKind.InvalidSecret, BadSecret);
        return Save(raw);
    }

    byte[] LoadSeed()
    {
        byte[]? seed;
        try { seed = _store.Load(); }
        catch (Exception e) { throw new StepUpException(StepUpKind.Transport, "Could not read the principal key.", 0, e); }
        if (seed is not { Length: > 0 }) throw new StepUpException(StepUpKind.NoDeviceKey, "No principal device key is stored on this device.");
        if (seed.Length != 32) throw new StepUpException(StepUpKind.InvalidSecret, BadSecret);
        return seed;
    }

    /// <summary>The secret (base64url seed) for backup or migration. Treat it like a password.</summary>
    public string ExportSecret() => Pca.B64u(LoadSeed());

    /// <summary>The public key (base64url), as registered on the grant.</summary>
    public string PublicKey() => PublicOf(LoadSeed());

    /// <summary>Ed25519-signs <paramref name="message"/> and returns the signature as base64url.</summary>
    public string Sign(byte[] message)
    {
        var seed = LoadSeed();
        var sig = new byte[64];
        Ed25519.Sign(seed, 0, message, 0, message.Length, sig, 0);
        return Pca.B64u(sig);
    }

    /// <summary>Removes the key from the store.</summary>
    public void Delete() => _store.Delete();
}

/// <summary>An action waiting for the principal's device signature. <see cref="ThresholdMessageB64u"/> is the base64url of the exact bytes the principal key must sign; <see cref="ExpiresAt"/> is epoch milliseconds.</summary>
public sealed record PendingStepUp(string Id, string GrantRef, string ActionVerb, string ActionResource, int RequiredT, string ThresholdMessageB64u, long ExpiresAt)
{
    /// <summary>A human summary for a confirmation sheet, for example <c>payments.refund on order/1234</c>.</summary>
    public string Summary => ActionVerb + " on " + ActionResource;
}

/// <summary>The result of an approval. <see cref="Anchored"/> is true once enough roles signed and the action was released.</summary>
public sealed record StepUpApproval(string? Status, bool Anchored, int HttpStatus);

/// <summary>Options of <see cref="StepUpClient"/>.</summary>
public sealed class StepUpClientOptions
{
    public string DashboardUrl { get; set; } = "";
    public string InstanceUrl { get; set; } = "";
    public string AccountId { get; set; } = "";
    public string InstanceId { get; set; } = "";
    public PrincipalDeviceKey? Key { get; set; }
    /// <summary>Returns the dashboard bearer token.</summary>
    public Func<CancellationToken, Task<string>>? Token { get; set; }
    /// <summary>The client to use (null: a client with a 30 second timeout).</summary>
    public HttpClient? Http { get; set; }
    /// <summary>The clock in epoch ms (null: the wall clock); expired step-ups are dropped from <see cref="StepUpClient.PendingAsync"/>.</summary>
    public Func<long>? Now { get; set; }
}

/// <summary>Lists, approves and denies PCA step-ups from the principal's device.</summary>
public sealed class StepUpClient
{
    const int MaxBody = 1 << 20;
    readonly StepUpClientOptions _o;
    readonly string _dashboard;
    readonly string _instance;
    readonly HttpClient _http;
    readonly Func<long> _now;

    public StepUpClient(StepUpClientOptions options)
    {
        _o = options ?? throw new ArgumentNullException(nameof(options));
        _dashboard = Base(options.DashboardUrl, "DashboardUrl");
        _instance = Base(options.InstanceUrl, "InstanceUrl");
        if (options.Key is null || options.Token is null || !ValidId(options.AccountId) || !ValidId(options.InstanceId))
            throw new ArgumentException("StepUpClient needs Key, Token and a valid AccountId and InstanceId.");
        _http = options.Http ?? new HttpClient { Timeout = TimeSpan.FromSeconds(30) };
        _now = options.Now ?? (() => DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());
    }

    static string Base(string raw, string what)
    {
        if (!Uri.TryCreate(raw, UriKind.Absolute, out var u) || (u.Scheme != Uri.UriSchemeHttp && u.Scheme != Uri.UriSchemeHttps) || string.IsNullOrEmpty(u.Host))
            throw new ArgumentException($"{what} must be an http(s) URL.");
        return raw.TrimEnd('/');
    }

    /// <summary>A path segment the client may put in a URL: letters, digits, '_', '-' and '.', not "." or "..".</summary>
    static bool ValidId(string? id) =>
        !string.IsNullOrEmpty(id) && id != "." && id != ".." && id.Length <= 200 && id.All(c => char.IsAsciiLetterOrDigit(c) || c is '_' or '-' or '.');

    string StepUpsUrl(params string[] parts) =>
        $"{_dashboard}/v1/dashboard/accounts/{_o.AccountId}/instances/{_o.InstanceId}/pca/stepups" + string.Concat(parts.Select(p => "/" + p));

    async Task<(int Status, byte[] Body)> CallAsync(HttpMethod method, string url, string? bearer, string? json, CancellationToken ct)
    {
        try
        {
            using var req = new HttpRequestMessage(method, url);
            if (!string.IsNullOrEmpty(bearer)) req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearer);
            if (json != null) req.Content = new StringContent(json, new UTF8Encoding(false), "application/json");
            using var resp = await _http.SendAsync(req, ct).ConfigureAwait(false);
            var data = await resp.Content.ReadAsByteArrayAsync(ct).ConfigureAwait(false);
            if (data.Length > MaxBody) throw new StepUpException(StepUpKind.Transport, "The response is too large.");
            int status = (int)resp.StatusCode;
            if (status < 200 || status > 299) throw HttpError(status, data);
            return (status, data);
        }
        catch (StepUpException) { throw; }
        catch (Exception e) { throw new StepUpException(StepUpKind.Transport, e.Message, 0, e); }
    }

    /// <summary>Reads the <c>{ errors: [{ code, message }] }</c> envelope.</summary>
    static StepUpException HttpError(int status, byte[] body)
    {
        var msg = "The request failed.";
        try
        {
            using var doc = JsonDocument.Parse(body);
            if (doc.RootElement.ValueKind == JsonValueKind.Object && doc.RootElement.TryGetProperty("errors", out var errs) && errs.ValueKind == JsonValueKind.Array
                && errs.GetArrayLength() > 0 && errs[0].ValueKind == JsonValueKind.Object && errs[0].TryGetProperty("message", out var m) && m.ValueKind == JsonValueKind.String
                && !string.IsNullOrEmpty(m.GetString()))
                msg = m.GetString()!;
        }
        catch (JsonException) { /* the default message */ }
        return status == (int)HttpStatusCode.Forbidden ? new StepUpException(StepUpKind.PrincipalMismatch, msg, status) : new StepUpException(StepUpKind.Api, msg, status);
    }

    async Task<string> BearerAsync(CancellationToken ct)
    {
        try { return await _o.Token!(ct).ConfigureAwait(false); }
        catch (Exception e) { throw new StepUpException(StepUpKind.Transport, "Could not get the dashboard token.", 0, e); }
    }

    static StepUpException Unreadable(string what) => new(StepUpKind.Transport, what);

    /// <summary>Lists the pending, not-yet-expired step-ups.</summary>
    public async Task<IReadOnlyList<PendingStepUp>> PendingAsync(CancellationToken ct = default)
    {
        var token = await BearerAsync(ct).ConfigureAwait(false);
        var (_, body) = await CallAsync(HttpMethod.Get, StepUpsUrl() + "?status=pending", token, null, ct).ConfigureAwait(false);
        var now = _now();
        var result = new List<PendingStepUp>();
        try
        {
            using var doc = JsonDocument.Parse(body);
            if (doc.RootElement.ValueKind != JsonValueKind.Object || !doc.RootElement.TryGetProperty("stepups", out var list) || list.ValueKind != JsonValueKind.Array)
                throw Unreadable("Unreadable step-up list.");
            foreach (var s in list.EnumerateArray())
            {
                string? Str(JsonElement e, string k) => e.ValueKind == JsonValueKind.Object && e.TryGetProperty(k, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;
                var id = Str(s, "id"); var grant = Str(s, "grant_ref"); var message = Str(s, "threshold_message");
                if (string.IsNullOrEmpty(id) || string.IsNullOrEmpty(grant) || string.IsNullOrEmpty(message)
                    || !DateTimeOffset.TryParse(Str(s, "expires_at"), CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var exp))
                    throw Unreadable("Unreadable step-up entry.");
                if (exp.ToUnixTimeMilliseconds() <= now) continue;
                string verb = "", resource = "";
                if (s.TryGetProperty("action", out var action)) { verb = Str(action, "verb") ?? ""; resource = Str(action, "resource") ?? ""; }
                int t = s.TryGetProperty("required_t", out var rt) && rt.ValueKind == JsonValueKind.Number && rt.TryGetInt32(out var n) ? n : 0;
                result.Add(new PendingStepUp(id, grant, verb, resource, t, message, exp.ToUnixTimeMilliseconds()));
            }
        }
        catch (JsonException) { throw Unreadable("Unreadable step-up list."); }
        return result;
    }

    /// <summary>Signs the step-up's threshold message with the device key and submits it. Throws a <see cref="StepUpException"/> of kind
    /// <see cref="StepUpKind.PrincipalMismatch"/> (server 403) when this key is not the grant's principal.</summary>
    public async Task<StepUpApproval> ApproveAsync(PendingStepUp stepUp, CancellationToken ct = default)
    {
        var message = Pca.B64uDecode(stepUp.ThresholdMessageB64u);
        if (message is not { Length: > 0 }) throw new StepUpException(StepUpKind.InvalidThresholdMessage, "The step-up's threshold message is not valid base64url.");
        if (!ValidId(stepUp.Id)) throw new StepUpException(StepUpKind.InvalidStepUp, "The step-up id is not valid.");
        var pub = _o.Key!.PublicKey();
        var sig = _o.Key.Sign(message);
        var payload = JsonSerializer.Serialize(new Dictionary<string, string> { ["role"] = "principal", ["publicKey"] = pub, ["sig"] = sig });
        var (status, body) = await CallAsync(HttpMethod.Post, $"{_instance}/v1/pca/stepups/{stepUp.Id}/cosign", null, payload, ct).ConfigureAwait(false);
        // 200 + allow:true = anchored; 202 = more roles still required.
        string? st = null; bool allow = false;
        try
        {
            using var doc = JsonDocument.Parse(body);
            if (doc.RootElement.ValueKind == JsonValueKind.Object)
            {
                if (doc.RootElement.TryGetProperty("status", out var s) && s.ValueKind == JsonValueKind.String) st = s.GetString();
                if (doc.RootElement.TryGetProperty("allow", out var a) && a.ValueKind == JsonValueKind.True) allow = true;
            }
        }
        catch (JsonException) { /* an unreadable answer is not an anchoring */ }
        return new StepUpApproval(st, allow, status);
    }

    /// <summary>Denies a pending step-up (dashboard endpoint; audited; owner or admin). <paramref name="reason"/> may be null.</summary>
    public async Task DenyAsync(PendingStepUp stepUp, string? reason = null, CancellationToken ct = default)
    {
        if (!ValidId(stepUp.Id)) throw new StepUpException(StepUpKind.InvalidStepUp, "The step-up id is not valid.");
        var token = await BearerAsync(ct).ConfigureAwait(false);
        var payload = string.IsNullOrEmpty(reason) ? "{}" : JsonSerializer.Serialize(new Dictionary<string, string> { ["reason"] = reason });
        await CallAsync(HttpMethod.Post, StepUpsUrl(stepUp.Id, "deny"), token, payload, ct).ConfigureAwait(false);
    }
}

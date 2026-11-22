using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using AtlasPca.Gnap;
using D = System.Collections.Generic.Dictionary<string, object?>;

namespace AtlasPca.Ciba;

/// <summary>An error response from the OP (RFC 6749 5.2 / CIBA Core 13), or a malformed reply.</summary>
public sealed class CibaProviderException : Exception
{
    public string Error { get; }
    public string? ErrorDescription { get; }
    public int Status { get; }
    /// <summary>True for failures worth retrying (network error, timeout, 5xx, non-JSON reply); not for a definitive OP answer.</summary>
    public bool Retryable { get; }

    public CibaProviderException(int status, string error, string? errorDescription, bool retryable)
        : base("ciba: provider returned " + status.ToString(CultureInfo.InvariantCulture) + " " + error + (errorDescription != null ? " (" + errorDescription + ")" : ""))
    {
        Status = status;
        Error = error;
        ErrorDescription = errorDescription;
        Retryable = retryable;
    }
}

/// <summary>One HTTP answer: the status code and the body text.</summary>
public sealed record CibaResponse(int Status, string Text)
{
    public bool Ok => Status >= 200 && Status < 300;
}

/// <summary>Client configuration. <see cref="Transport"/>, <see cref="Sleep"/> and <see cref="Now"/> default to <c>HttpClient</c>, <c>Thread.Sleep</c> and the system clock.</summary>
public sealed class CibaClientConfig
{
    public string? BackchannelAuthenticationEndpoint;
    public string? TokenEndpoint;
    public string? ClientId;
    public string? ClientSecret;
    /// <summary>POST <c>body</c> (form-encoded) to <c>url</c> with <c>headers</c>; throws on a network failure or a timeout.</summary>
    public Func<string, IReadOnlyDictionary<string, string>, string, long, CibaResponse>? Transport;
    /// <summary>Sleeps this many milliseconds (injectable for tests).</summary>
    public Action<long>? Sleep;
    public Func<long> Now = () => AtlasPca.ReplayClock.NowMs();
    public double TimeoutMs = 30_000;
    /// <summary>Permit <c>http://</c> endpoints (local test providers only).</summary>
    public bool AllowInsecureHttp;
}

/// <summary>
/// A network client for a real OpenID Provider's CIBA endpoints (OpenID CIBA Core 1.0): start a backchannel authentication request and wait for the human's
/// decision by POLL or PING. It is the relying-party side that the in-memory broker models. Poll discipline follows CIBA Core 7.3 / 11: the client never polls
/// faster than the <c>interval</c> the OP returned, adds at least 5 seconds to it on every <c>slow_down</c>, and stops at <c>expires_in</c>. A terminal answer
/// (approved / denied / expired) is cached, so a settled flow is never re-sent to the token endpoint. The client authenticates with <c>client_secret_basic</c>.
/// The returned tokens are the OP's response, not verified here. The transport is injectable; calls block.
/// </summary>
public static class CibaClient
{
    const string CibaGrant = "urn:openid:params:grant-type:ciba";
    const int SlowDownStepSec = 5;
    const int MinNotificationTokenChars = 22;
    const int MaxNotificationTokenChars = 1024;
    const long MaxBackoffMs = 60_000;
    const int MaxConsecutiveTransient = 5;

    // ---- helpers ----

    /// <summary>encodeURIComponent.</summary>
    internal static string EncodeUriComponent(string s)
    {
        var sb = new StringBuilder();
        foreach (var cp in CibaJs.CodePoints(s))
        {
            if (cp >= 0xd800 && cp <= 0xdfff) throw new ArgumentException("URI malformed");
            if ((cp >= 'a' && cp <= 'z') || (cp >= 'A' && cp <= 'Z') || (cp >= '0' && cp <= '9') || "-_.!~*'()".IndexOf((char)cp) >= 0 && cp < 128) sb.Append((char)cp);
            else foreach (var b in Encoding.UTF8.GetBytes(CibaJs.FromCodePoint(cp))) sb.Append('%').Append(b.ToString("X2", CultureInfo.InvariantCulture));
        }
        return sb.ToString();
    }

    /// <summary>application/x-www-form-urlencoded serialization of one parameter name or value.</summary>
    internal static string FormEncode(string s)
    {
        var sb = new StringBuilder();
        foreach (var b in Encoding.UTF8.GetBytes(s))
        {
            if ((b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') || b == '*' || b == '-' || b == '.' || b == '_') sb.Append((char)b);
            else if (b == ' ') sb.Append('+');
            else sb.Append('%').Append(b.ToString("X2", CultureInfo.InvariantCulture));
        }
        return sb.ToString();
    }

    static string FormBody(List<string[]> ps)
    {
        var sb = new StringBuilder();
        foreach (var kv in ps) { if (sb.Length > 0) sb.Append('&'); sb.Append(FormEncode(kv[0])).Append('=').Append(FormEncode(kv[1])); }
        return sb.ToString();
    }

    /// <summary>URLSearchParams.set: replace the first parameter of that name and drop the others, else append.</summary>
    static void SetParam(List<string[]> ps, string k, string v)
    {
        bool set = false;
        for (int i = 0; i < ps.Count; i++)
        {
            if (ps[i][0] != k) continue;
            if (!set) { ps[i][1] = v; set = true; } else ps.RemoveAt(i--);
        }
        if (!set) ps.Add(new[] { k, v });
    }

    static readonly Regex SchemeRe = new(@"\A\s*([A-Za-z][A-Za-z0-9+.\-]*):", RegexOptions.CultureInvariant);

    static void CheckEndpoint(string name, string? value, bool allowInsecure)
    {
        string? scheme = null;
        if (value != null)
        {
            var m = SchemeRe.Match(value);
            if (m.Success) scheme = m.Groups[1].Value.ToLowerInvariant();
        }
        bool parses = false;
        if (scheme != null && Uri.TryCreate(value!.Trim(), UriKind.Absolute, out var u)) parses = !string.IsNullOrEmpty(u.Host) || (scheme != "https" && scheme != "http");
        if (!parses) throw new ArgumentException("ciba: " + name + " is not a valid URL");
        if (scheme == "https") return;
        if (scheme == "http" && allowInsecure) return;
        throw new ArgumentException("ciba: " + name + " must be an https:// URL (set allowInsecureHttp only for a local test provider)");
    }

    /// <summary>A fresh <c>client_notification_token</c> (CIBA Core 7.1: at least 128 bits of entropy, at most 1024 chars): 256 random bits, base64url.</summary>
    public static string NewClientNotificationToken() => Pca.B64u(RandomNumberGenerator.GetBytes(32));

    static D ReadJson(CibaResponse res)
    {
        object? parsed;
        try { parsed = Pca.ParseJson(res.Text); }
        catch (Exception) { throw new CibaProviderException(res.Status, "invalid_response", "the provider reply was not JSON", true); }
        return parsed as D ?? throw new CibaProviderException(res.Status, "invalid_response", "the provider reply was not a JSON object", false);
    }

    static CibaProviderException ProviderError(int status, D body) =>
        new(status, body.GetValueOrDefault("error") as string ?? "invalid_response", body.GetValueOrDefault("error_description") as string, false);

    static long PositiveInt(object? value, string name, int status)
    {
        if (!CibaJs.IsSafeInteger(value) || value is bool || GnapJs.NumOf(value)! <= 0) throw new CibaProviderException(status, "invalid_response", name + " must be a positive integer", false);
        return (long)GnapJs.NumOf(value)!.Value;
    }

    static readonly HttpClient Http = new(new SocketsHttpHandler { AllowAutoRedirect = false });

    static CibaResponse DefaultTransport(string url, IReadOnlyDictionary<string, string> headers, string body, long timeoutMs)
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(timeoutMs));
        using var req = new HttpRequestMessage(HttpMethod.Post, url) { Content = new StringContent(body, Encoding.UTF8) };
        foreach (var h in headers)
        {
            if (h.Key.Equals("content-type", StringComparison.OrdinalIgnoreCase)) req.Content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/x-www-form-urlencoded");
            else req.Headers.TryAddWithoutValidation(h.Key, h.Value);
        }
        using var res = Http.Send(req, cts.Token);
        using var r = new StreamReader(res.Content.ReadAsStream(cts.Token), Encoding.UTF8);
        return new CibaResponse((int)res.StatusCode, r.ReadToEnd());
    }

    // ---- the client ----

    /// <summary>The CIBA client over one OP: <see cref="Initiate"/> starts a flow and <see cref="GetPoller"/> follows it.</summary>
    public sealed class Client
    {
        internal readonly CibaClientConfig Cfg;
        readonly Func<string, IReadOnlyDictionary<string, string>, string, long, CibaResponse> transport;
        readonly string basic;

        internal Client(CibaClientConfig cfg)
        {
            Cfg = cfg;
            transport = cfg.Transport ?? DefaultTransport;
            basic = "Basic " + Convert.ToBase64String(Encoding.UTF8.GetBytes(EncodeUriComponent(cfg.ClientId!) + ":" + EncodeUriComponent(cfg.ClientSecret!)));
        }

        internal CibaResponse Post(string url, List<string[]> form, CancellationToken signal)
        {
            if (signal.IsCancellationRequested) throw new InvalidOperationException("ciba: wait aborted");
            var headers = new Dictionary<string, string> { ["authorization"] = basic, ["content-type"] = "application/x-www-form-urlencoded", ["accept"] = "application/json" };
            try { return transport(url, headers, FormBody(form), (long)Math.Ceiling(Cfg.TimeoutMs)); }
            catch (Exception e)
            {
                if (signal.IsCancellationRequested) throw new InvalidOperationException("ciba: wait aborted");
                throw new CibaProviderException(0, "network_error", string.IsNullOrEmpty(e.Message) ? "request failed" : e.Message, true);
            }
        }

        /// <summary>Start a backchannel flow for a step-up. <paramref name="opts"/>: the request options of <see cref="Ciba.ToCibaAuthRequest"/> plus
        /// <c>loginHintToken</c>, <c>idTokenHint</c>, <c>delivery</c> (<c>poll</c> default or <c>ping</c>), <c>clientNotificationToken</c>, <c>acrValues</c>,
        /// <c>userCode</c>. Exactly one identifying hint is required (CIBA Core 7.1). Returns the flow
        /// <c>{authReqId, expiresInSec, intervalSec, startedAt, delivery, [clientNotificationToken,] request}</c>.</summary>
        public D Initiate(D stepUp, D? opts = null)
        {
            var o = opts ?? new D();
            int hints = new[] { "loginHint", "loginHintToken", "idTokenHint" }.Count(o.ContainsKey);
            if (hints != 1) throw new ArgumentException("ciba: exactly one of loginHint, loginHintToken, idTokenHint is required (CIBA Core 7.1)");
            var delivery = o.GetValueOrDefault("delivery") is { } dv ? (string)dv : "poll";
            var cnt = o.GetValueOrDefault("clientNotificationToken");
            string? notificationToken = delivery == "ping" ? (cnt != null ? (string)cnt : NewClientNotificationToken()) : null;
            if (o.ContainsKey("clientNotificationToken"))
            {
                var t = (string)o["clientNotificationToken"]!;
                bool printable = t.Length > 0 && t.All(c => c >= 0x21 && c <= 0x7e);
                if (t.Length < MinNotificationTokenChars || t.Length > MaxNotificationTokenChars || !printable)
                    throw new ArgumentException("ciba: clientNotificationToken must be " + MinNotificationTokenChars + ".." + MaxNotificationTokenChars + " printable characters (>= 128 bits, CIBA Core 7.1)");
            }
            var request = Ciba.ToCibaAuthRequest(stepUp, o);
            var form = new List<string[]>
            {
                new[] { "scope", (string)request["scope"]! },
                new[] { "binding_message", (string)request["binding_message"]! },
                new[] { "requested_expiry", GnapJs.Str(request["requested_expiry"]) },
            };
            if (o.ContainsKey("loginHint")) SetParam(form, "login_hint", GnapJs.Str(o["loginHint"]));
            if (o.ContainsKey("loginHintToken")) SetParam(form, "login_hint_token", GnapJs.Str(o["loginHintToken"]));
            if (o.ContainsKey("idTokenHint")) SetParam(form, "id_token_hint", GnapJs.Str(o["idTokenHint"]));
            if (o.ContainsKey("acrValues")) SetParam(form, "acr_values", GnapJs.Str(o["acrValues"]));
            if (o.ContainsKey("userCode")) SetParam(form, "user_code", GnapJs.Str(o["userCode"]));
            if (notificationToken != null) SetParam(form, "client_notification_token", notificationToken);
            var res = Post(Cfg.BackchannelAuthenticationEndpoint!, form, CancellationToken.None);
            var body = ReadJson(res);
            if (!res.Ok) throw ProviderError(res.Status, body);
            if (body.GetValueOrDefault("auth_req_id") is not string { Length: > 0 } authReqId) throw new CibaProviderException(res.Status, "invalid_response", "auth_req_id missing", false);
            long expiresInSec = PositiveInt(body.GetValueOrDefault("expires_in"), "expires_in", res.Status);
            // CIBA Core 7.3: `interval` is optional and defaults to 5 seconds.
            long intervalSec = body.ContainsKey("interval") ? PositiveInt(body["interval"], "interval", res.Status) : 5;
            var flow = new D { ["authReqId"] = authReqId, ["expiresInSec"] = expiresInSec, ["intervalSec"] = intervalSec, ["startedAt"] = Cfg.Now(), ["delivery"] = delivery };
            if (notificationToken != null) flow["clientNotificationToken"] = notificationToken;
            flow["request"] = request;
            return flow;
        }

        /// <summary>The poller for a flow returned by <see cref="Initiate"/>.</summary>
        public Poller GetPoller(D flow) => new(this, flow);
    }

    /// <summary>Follows one flow: sleeps until the interval allows it, asks the token endpoint once per <see cref="Poll"/>, and caches a settled answer.</summary>
    public sealed class Poller
    {
        readonly Client c;
        readonly CibaClientConfig cfg;
        readonly D flow;
        double intervalMs;
        double nextAt;
        readonly double deadline;
        D? settled;
        int failures;
        readonly object wake = new();
        bool woken;

        internal Poller(Client c, D flow)
        {
            this.c = c;
            cfg = c.Cfg;
            this.flow = flow;
            intervalMs = GnapJs.NumOf(flow["intervalSec"])!.Value * 1000;
            nextAt = GnapJs.NumOf(flow["startedAt"])!.Value + intervalMs;
            deadline = GnapJs.NumOf(flow["startedAt"])!.Value + GnapJs.NumOf(flow["expiresInSec"])!.Value * 1000;
        }

        /// <summary>Current poll interval in seconds (grows on <c>slow_down</c>).</summary>
        public double IntervalSec { get { lock (this) return intervalMs / 1000; } }

        /// <summary>A PING arrived: the next <see cref="Poll"/> may go out immediately, and a poll that is sleeping on its own timer wakes now.</summary>
        public void NotifyPing()
        {
            lock (wake)
            {
                nextAt = cfg.Now();
                woken = true;
                Monitor.PulseAll(wake);
            }
        }

        void Pause(double ms, CancellationToken signal)
        {
            if (cfg.Sleep != null) cfg.Sleep((long)Math.Ceiling(ms));
            else
            {
                long end = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() + (long)Math.Ceiling(ms);
                lock (wake)
                {
                    woken = false;
                    while (!woken && !signal.IsCancellationRequested)
                    {
                        long left = end - DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
                        if (left <= 0) break;
                        Monitor.Wait(wake, (int)Math.Min(left, 50));
                    }
                }
            }
            if (signal.IsCancellationRequested) throw new InvalidOperationException("ciba: wait aborted");
        }

        void Backoff()
        {
            failures += 1;
            double delay = Math.Min(MaxBackoffMs, intervalMs * Math.Pow(2, Math.Min(failures, 6)));
            nextAt = cfg.Now() + delay;
        }

        D DoPoll(CancellationToken signal)
        {
            if (settled != null) return settled;
            double wait = nextAt - cfg.Now();
            if (wait > 0) Pause(wait, signal);
            if (settled != null) return settled;
            if (cfg.Now() >= deadline)
            {
                settled = new D { ["status"] = "expired" };
                return settled;
            }
            CibaResponse res;
            D body;
            try
            {
                var form = new List<string[]> { new[] { "grant_type", CibaGrant }, new[] { "auth_req_id", (string)flow["authReqId"]! } };
                res = c.Post(cfg.TokenEndpoint!, form, signal);
                if (res.Status >= 500) throw new CibaProviderException(res.Status, "server_error", "the provider answered with a server error", true);
                body = ReadJson(res);
            }
            catch (CibaProviderException e)
            {
                if (e.Retryable) Backoff();
                throw;
            }
            failures = 0;
            nextAt = cfg.Now() + intervalMs;
            if (res.Ok)
            {
                if (body.GetValueOrDefault("access_token") is not string || body.GetValueOrDefault("token_type") is not string)
                    throw new CibaProviderException(res.Status, "invalid_response", "token response lacks access_token / token_type", false);
                settled = new D { ["status"] = "approved", ["tokens"] = body };
                return settled;
            }
            var err = ProviderError(res.Status, body);
            switch (err.Error)
            {
                case "authorization_pending":
                    return new D { ["status"] = "pending", ["intervalSec"] = intervalMs / 1000 };
                case "slow_down":
                    intervalMs += SlowDownStepSec * 1000;
                    nextAt = cfg.Now() + intervalMs;
                    return new D { ["status"] = "pending", ["intervalSec"] = intervalMs / 1000 };
                case "access_denied":
                    settled = new D { ["status"] = "denied", ["error"] = err.Error };
                    return settled;
                case "expired_token":
                    settled = new D { ["status"] = "expired" };
                    return settled;
                default:
                    throw err;
            }
        }

        /// <summary>Sleep until the interval allows it, then ask the token endpoint once: <c>{status: pending, intervalSec}</c>, <c>{approved, tokens}</c>,
        /// <c>{denied, error}</c> or <c>{expired}</c>. Concurrent callers are serialized.</summary>
        public D Poll(CancellationToken signal = default) { lock (this) return DoPoll(signal); }

        /// <summary>Poll until the flow settles; honours <paramref name="signal"/>. Transient failures are retried (up to 5 in a row); a definitive OP error throws.</summary>
        public D Await(CancellationToken signal = default)
        {
            int transientFailures = 0;
            for (; ; )
            {
                if (signal.IsCancellationRequested) throw new InvalidOperationException("ciba: wait aborted");
                try
                {
                    var r = Poll(signal);
                    transientFailures = 0;
                    if (r.GetValueOrDefault("status") is not "pending") return r;
                }
                catch (CibaProviderException e)
                {
                    if (!e.Retryable || ++transientFailures >= MaxConsecutiveTransient) throw;
                }
            }
        }
    }

    /// <summary>The CIBA client for <paramref name="cfg"/>; endpoints must be https:// unless <c>AllowInsecureHttp</c>.</summary>
    public static Client CreateCibaClient(CibaClientConfig cfg)
    {
        if (double.IsNaN(cfg.TimeoutMs) || double.IsInfinity(cfg.TimeoutMs) || cfg.TimeoutMs <= 0) throw new ArgumentException("ciba: timeoutMs must be a positive number");
        CheckEndpoint("backchannelAuthenticationEndpoint", cfg.BackchannelAuthenticationEndpoint, cfg.AllowInsecureHttp);
        CheckEndpoint("tokenEndpoint", cfg.TokenEndpoint, cfg.AllowInsecureHttp);
        return new Client(cfg);
    }

    // ---- PING callback ----

    static readonly Regex Bearer = new(@"\Abearer +(\S+)\z", RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);

    /// <summary>Validate a PING callback (CIBA Core 10.2): <c>Authorization: Bearer &lt;client_notification_token&gt;</c> and a JSON body <c>{"auth_req_id": ...}</c>. Returns
    /// the <c>auth_req_id</c> only when the bearer matches the token sent for that flow (constant-time comparison); throws otherwise. The callback carries no decision:
    /// call <c>NotifyPing()</c> on the poller and then <c>Poll()</c>.</summary>
    public static string VerifyPingCallback(string? authorization, object? body, D flow)
    {
        if (!flow.ContainsKey("clientNotificationToken")) throw new InvalidOperationException("ciba: flow was not started in ping mode");
        var m = Bearer.Match(authorization ?? "");
        if (!m.Success) throw new InvalidOperationException("ciba: ping callback lacks a bearer token");
        var a = SHA256.HashData(Encoding.UTF8.GetBytes(m.Groups[1].Value));
        if (flow["clientNotificationToken"] is not string notificationToken)
            throw new AtlasPca.Grants.CodedException("ERR_INVALID_ARG_TYPE", "The \"data\" argument must be of type string or an instance of Buffer, TypedArray, or DataView.");
        var b = SHA256.HashData(Encoding.UTF8.GetBytes(notificationToken));
        if (!CryptographicOperations.FixedTimeEquals(a, b)) throw new InvalidOperationException("ciba: ping callback bearer does not match the client_notification_token");
        var id = body is D bd ? bd.GetValueOrDefault("auth_req_id") : null;
        if (id is not string ids || id as string != flow.GetValueOrDefault("authReqId") as string) throw new InvalidOperationException("ciba: ping callback auth_req_id does not match this flow");
        return ids;
    }
}

// Question delivery of the wallet over the existing approval-channel transports (a webhook, and the email / SMS / push text-sender port).
// A delivery only tells the principal's device that a question is waiting and hands it the SIGNED question. It never carries a rendered
// card, agent text, the map, or p: a site question carries the site-signed intent_required body exactly as received (the device
// re-verifies it and renders the card itself from fixed templates); a wallet-originated question (an agent clarification) carries only its
// session and question id; canaries get no delivery of their own. Text surfaces use one fixed template with the wallet's verified display
// name of the site. Slack is deliberately not offered: a shared workspace would expose the principal's pending decisions.
using System.Text;
using AtlasPca.IntentPkg;
using AtlasPca.InteropJs;
using AtlasPca.Js;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Wallet;

/// <summary>What a webhook transport answers: the response status and whether it was a success (2xx).</summary>
public sealed record TransportResult(bool Ok, int Status);

/// <summary>An injectable fetch: (url, method, headers, body) to the response.</summary>
public delegate Task<TransportResult> WebhookFetch(string url, string method, D headers, string body);

/// <summary>An injectable text sender: the fixed {subject, text} body.</summary>
public delegate Task TextSender(D body);

public interface IQuestionChannel
{
    /// <summary>"webhook" | "email" | "sms" | "push".</summary>
    string Kind { get; }
    bool Enabled { get; }
    /// <summary>{kind, questionId, payload, delivered, status?, reason?}.</summary>
    Task<D> NotifyAsync(D notice);
}

public static class WalletDelivery
{
    /// <summary>The site-signature, shape and expiry check of an intent_required (null when valid, else the reason); the clock must be a safe integer.</summary>
    internal static string? VerifyIntentRequired(object? body, object? keys, object? now)
    {
        if (!IntentJs.IsSafeInteger(now)) return "the verifier clock is not a safe integer (fail closed)";
        return IntentJit.VerifyIntentRequired(body, keys, IntentJs.Lng(now));
    }

    /// <summary>A notice for a site-signed question. Throws when the signature or expiry does not verify (nothing unsigned leaves).
    /// <paramref name="keys"/> are the site's discovery keys; <paramref name="site"/> the origin as verified from discovery.</summary>
    public static D SiteQuestionNotice(D ir, object? keys, object? site, object? now, object? inboxUrl = null)
    {
        var bad = VerifyIntentRequired(ir, keys, now);
        if (bad != null) throw new WalletException("siteQuestionNotice: " + bad);
        var o = new D { ["type"] = "pca.intent.question" };
        foreach (var (k, v) in new (string, object?)[] { ("session", WalletCore.G(ir, "session")), ("question_id", WalletCore.G(ir, "question_id")), ("site", site), ("friction", WalletCore.G(ir, "friction")), ("expires_at", WalletCore.G(ir, "expires_at")) })
            if (!ReferenceEquals(v, JsX.Undef)) o[k] = v;
        o["intent_required"] = ir;
        if (JsX.Truthy(inboxUrl)) o["inbox_url"] = inboxUrl;
        return o;
    }

    /// <summary>A notice for a wallet-originated question (clarification): ids only.</summary>
    public static D ClarificationNotice(object? session, object? questionId, object? inboxUrl = null)
    {
        var o = new D { ["type"] = "pca.intent.clarification", ["session"] = session, ["question_id"] = questionId };
        if (JsX.Truthy(inboxUrl)) o["inbox_url"] = inboxUrl;
        return o;
    }

    /// <summary>The fixed text of a text-surface notice: {subject, text}.</summary>
    public static D QuestionText(D notice, string siteName)
    {
        bool isSite = WalletCore.G(notice, "type") is string t && t == "pca.intent.question";
        var name = isSite ? WalletCard.CleanText(siteName, 64) : "";
        var who = isSite ? (name.Length > 0 ? name : "A site") : "Your agent";
        var subject = isSite ? $"{who} has a question about your request" : $"{who} needs a decision about your request";
        string? link = null;
        if (JsX.Truthy(WalletCore.Nul(WalletCore.G(notice, "inbox_url"))))
        {
            var inbox = JsX.Str(WalletCore.G(notice, "inbox_url"));
            link = inbox + (inbox.Contains('?') ? "&" : "?") + "question=" + JsJson.EncodeUriComponent(JsX.Str(WalletCore.G(notice, "question_id")));
        }
        return new D { ["subject"] = subject, ["text"] = string.Join("\n", new[] { subject, "", link != null ? "Open your wallet to answer: " + link : "Open your wallet to answer." }) };
    }

    static D Base(string kind, object? questionId, object? payload) => new() { ["kind"] = kind, ["questionId"] = questionId, ["payload"] = payload };
    static D With(D b, bool delivered, int? status = null, string? reason = null)
    {
        var o = new D(b) { ["delivered"] = delivered };
        if (status != null) o["status"] = WalletCore.N(status.Value);
        if (reason != null) o["reason"] = reason;
        return o;
    }

    static readonly HttpClient Http = new();

    /// <summary>The default transport: an HTTP POST through a shared <see cref="HttpClient"/>.</summary>
    static async Task<TransportResult> DefaultFetch(string url, string method, D headers, string body)
    {
        using var req = new HttpRequestMessage(new HttpMethod(method), url) { Content = new StringContent(body, Encoding.UTF8) };
        req.Content.Headers.ContentType = null;
        foreach (var (k, v) in headers)
        {
            var val = JsX.Str(v);
            if (!req.Headers.TryAddWithoutValidation(k, val)) req.Content.Headers.TryAddWithoutValidation(k, val);
        }
        using var res = await Http.SendAsync(req).ConfigureAwait(false);
        return new TransportResult(res.IsSuccessStatusCode, (int)res.StatusCode);
    }

    sealed class WebhookChannel(string? url, D headers, WebhookFetch transport) : IQuestionChannel
    {
        public string Kind => "webhook";
        public bool Enabled { get; } = !string.IsNullOrEmpty(url);

        public async Task<D> NotifyAsync(D notice)
        {
            var b = Base("webhook", WalletCore.G(notice, "question_id"), notice);
            if (!Enabled || url == null) return With(b, false, reason: "webhook channel not configured");
            try
            {
                var res = await transport(url, "POST", headers, JsJson.Stringify(notice)).ConfigureAwait(false);
                return res.Ok ? With(b, true, res.Status) : With(b, false, res.Status, $"webhook returned {res.Status}");
            }
            catch (Exception err) { return With(b, false, reason: err.Message); }
        }
    }

    /// <summary>Webhook delivery (the principal's own wallet push endpoint): the JSON notice, signed question included. A configured header
    /// replaces the default content-type.</summary>
    public static IQuestionChannel QuestionWebhookChannel(string? url, IReadOnlyDictionary<string, string>? headers = null, WebhookFetch? fetch = null)
    {
        var h = new D { ["content-type"] = "application/json" };
        if (headers != null) foreach (var (k, v) in headers) h[k] = v;
        return new WebhookChannel(url, h, fetch ?? new WebhookFetch(DefaultFetch));
    }

    sealed class TextChannel(string kind, TextSender? send, string siteName) : IQuestionChannel
    {
        public string Kind => kind;
        public bool Enabled { get; } = send != null;

        public async Task<D> NotifyAsync(D notice)
        {
            var body = QuestionText(notice, siteName);
            var b = Base(kind, WalletCore.G(notice, "question_id"), body);
            if (!Enabled || send == null) return With(b, false, reason: $"{kind} channel not configured");
            try
            {
                await send(body).ConfigureAwait(false);
                return With(b, true);
            }
            catch (Exception err) { return With(b, false, reason: err.Message); }
        }
    }

    /// <summary>Email / SMS / push delivery through the per-instance sender port (fixed text only).</summary>
    public static IQuestionChannel QuestionTextChannel(string kind, TextSender? send, string siteName)
    {
        if (kind is not ("email" or "sms" or "push")) throw new WalletException("questionTextChannel: kind must be email, sms or push");
        return new TextChannel(kind, send, siteName);
    }

    /// <summary>Fan a notice out to every enabled channel in order (disabled channels are skipped).</summary>
    public static async Task<List<D>> NotifyAllAsync(IEnumerable<IQuestionChannel> channels, D notice)
    {
        var o = new List<D>();
        foreach (var c in channels) if (c.Enabled) o.Add(await c.NotifyAsync(notice).ConfigureAwait(false));
        return o;
    }
}

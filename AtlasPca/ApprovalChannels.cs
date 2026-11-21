// Approval-notification channels for PCA step-ups (the reference approval-channels.ts): each channel FORMATS a human-readable notification of a
// pending step-up request (a parsed JSON tree, see Approvals.Review) and DISPATCHES it over an injected transport. Channels are gated by config (an
// unconfigured one reports Enabled false and never dispatches), offline-testable (the HTTP transport is injected) and secret-free in their output.
// A channel only REPORTS a step-up the verifier already produced; it authorizes nothing.
using System.Globalization;
using System.Text;
using AtlasPca.Js;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca;

/// <summary>The minimal HTTP surface a channel needs: <c>(url, method, headers, body) -&gt; (ok, status)</c>.</summary>
public delegate Task<(bool Ok, int Status)> ApprovalFetch(string url, string method, IReadOnlyDictionary<string, string> headers, string body);

/// <summary>Where the human approves (absolute inbox URL) and the clock.</summary>
public sealed record ApprovalNotifyContext(string? InboxUrl = null, long? Now = null);

/// <summary>The outcome of one delivery attempt. <c>Payload</c> is the formatted, secret-free message.</summary>
public sealed record ApprovalDelivery(string Kind, string RequestId, bool Delivered, object? Payload, int? Status = null, string? Reason = null);

/// <summary>The common channel contract. <see cref="NotifyAsync"/> resolves (never throws) with the outcome.</summary>
public interface IApprovalChannel
{
    string Kind { get; }
    bool Enabled { get; }
    Task<ApprovalDelivery> NotifyAsync(D request, ApprovalNotifyContext? ctx = null);
}

public static class ApprovalChannels
{
    static string Str(D request, string key) => JsJson.ToJsString(request.GetValueOrDefault(key));

    /// <summary>One-line action summary: <c>verb on resource (tier N, risk R)</c>.</summary>
    public static string ActionSummary(D request) =>
        $"{Str(request, "verb")} on {Str(request, "resource")} (tier {Str(request, "tier")}, risk {Research.Immune.ToFixed(JsJson.ToJsNumber(request.GetValueOrDefault("r")), 2)})";

    /// <summary>The goal-lineage lines a human reads to understand WHY: the "because you asked to ..." sentence, the goal-authority-action chain, then the canonical render.</summary>
    public static List<string> LineageLines(D request)
    {
        var lineage = request.GetValueOrDefault("lineage") as D ?? throw new ArgumentException("lineageLines: lineage required");
        var lines = new List<string> { JsJson.ToJsString(lineage.GetValueOrDefault("because")) };
        lines.AddRange(Approvals.DescribeGoalLineage(lineage).Select(x => JsJson.ToJsString(x)));
        lines.AddRange(RenderLines(request));
        return lines;
    }

    static string EscapeControl(string json)
    {
        var sb = new StringBuilder();
        foreach (var r in json.EnumerateRunes())
        {
            var cat = Rune.GetUnicodeCategory(r);
            if (cat is UnicodeCategory.Control or UnicodeCategory.Format || r.Value is 0x2028 or 0x2029) sb.Append("\\u{").Append(r.Value.ToString("x", CultureInfo.InvariantCulture)).Append('}');
            else sb.Append(r.ToString());
        }
        return sb.ToString();
    }

    /// <summary>The canonical render, one line per field (nothing omitted), the banner for an unreviewed action and the speakable binding words of H(R).
    /// Empty when the request carries no render. Every channel shows the same lines.</summary>
    public static List<string> RenderLines(D request)
    {
        var o = new List<string>();
        if (request.GetValueOrDefault("render") is not D r || request.GetValueOrDefault("renderDigest") is not string digest) return o;
        if (r.GetValueOrDefault("unreviewed") is true) o.Add("UNREVIEWED ACTION: its definition has not been confirmed, so every value is shown raw and one-tap approval is disabled.");
        foreach (var fo in (r.GetValueOrDefault("fields") as L) ?? new L())
        {
            var f = (D)fo!;
            var u = f.GetValueOrDefault("unit") as D;
            var unit = u != null && u.GetValueOrDefault("kind") as string == "money"
                ? $" {JsJson.ToJsString(u.GetValueOrDefault("ccy"))} (minor units, exponent {JsJson.ToJsString(u.GetValueOrDefault("exp"))})" : "";
            o.Add($"{JsJson.ToJsString(f.GetValueOrDefault("id"))} [{JsJson.ToJsString(f.GetValueOrDefault("class"))}]: {EscapeControl(JsJson.Stringify(f.GetValueOrDefault("value")))}{unit}");
        }
        o.Add("Match code: " + Approval.BindingWords(digest));
        return o;
    }

    /// <summary>Add query parameters before any <c>#fragment</c> (an approval link may carry its token in the fragment, which must stay last).</summary>
    static string AppendQuery(string url, params (string K, string V)[] prms)
    {
        var query = string.Join("&", prms.Select(p => JsJson.EncodeUriComponent(p.K) + "=" + JsJson.EncodeUriComponent(p.V)));
        var hash = url.IndexOf('#');
        var bas = hash == -1 ? url : url[..hash];
        var fragment = hash == -1 ? "" : url[hash..];
        return bas + (bas.Contains('?') ? "&" : "?") + query + fragment;
    }

    static D Block(string type, params (string K, object? V)[] kv) { var d = new D { ["type"] = type }; foreach (var (k, v) in kv) d[k] = v; return d; }
    static D Text(string type, string text, bool? emoji = null) { var d = new D { ["type"] = type, ["text"] = text }; if (emoji != null) d["emoji"] = emoji; return d; }

    /// <summary>The Block Kit message of a step-up: action summary, goal lineage, approve / deny affordance.</summary>
    public static D BuildSlackMessage(D request, ApprovalNotifyContext? ctx = null)
    {
        var id = Str(request, "id");
        var blocks = new L
        {
            Block("header", ("text", Text("plain_text", $"Approval needed · tier {Str(request, "tier")}", true))),
            Block("section", ("text", Text("mrkdwn", $"*{Str(request, "verb")}* on `{Str(request, "resource")}`\n_{Str(request, "reason")}_"))),
            Block("section", ("text", Text("mrkdwn", "*Why this is requested*\n" + string.Join("\n", LineageLines(request).Select(l => "• " + l))))),
        };
        if (!string.IsNullOrEmpty(ctx?.InboxUrl))
        {
            var approve = AppendQuery(ctx!.InboxUrl!, ("stepup", id), ("decision", "approve"));
            var deny = AppendQuery(ctx.InboxUrl!, ("stepup", id), ("decision", "deny"));
            blocks.Add(Block("actions", ("elements", new L
            {
                new D { ["type"] = "button", ["text"] = Text("plain_text", "Approve", true), ["url"] = approve, ["style"] = "primary", ["action_id"] = "pca_approve" },
                new D { ["type"] = "button", ["text"] = Text("plain_text", "Deny", true), ["url"] = deny, ["style"] = "danger", ["action_id"] = "pca_deny" },
            })));
        }
        else blocks.Add(Block("context", ("elements", new L { Text("mrkdwn", $"Approve or deny step-up `{id}` in your Atlas inbox.") })));
        return new D { ["text"] = "Approval needed: " + ActionSummary(request), ["blocks"] = blocks };
    }

    /// <summary>The webhook JSON body: the step-up plus its pre-formatted summary and lineage.</summary>
    public static D BuildWebhookBody(D request, ApprovalNotifyContext? ctx = null)
    {
        var b = new D
        {
            ["type"] = "pca.step_up.created", ["stepup"] = request, ["summary"] = ActionSummary(request),
            ["lineage"] = new L(LineageLines(request).Cast<object?>()),
        };
        if (!string.IsNullOrEmpty(ctx?.InboxUrl)) b["inbox_url"] = ctx!.InboxUrl;
        return b;
    }

    /// <summary>The plain-text body (subject + text) shared by the email / sms / push surfaces.</summary>
    public static (string Subject, string Text) BuildTextBody(D request, ApprovalNotifyContext? ctx = null)
    {
        var lines = new List<string> { ActionSummary(request), "" };
        lines.AddRange(LineageLines(request));
        if (!string.IsNullOrEmpty(ctx?.InboxUrl)) { lines.Add(""); lines.Add("Approve or deny: " + AppendQuery(ctx!.InboxUrl!, ("stepup", Str(request, "id")))); }
        return ($"Approval needed: {Str(request, "verb")} on {Str(request, "resource")}", string.Join("\n", lines));
    }

    /// <summary>The default HTTP transport over <see cref="HttpClient"/>.</summary>
    public static ApprovalFetch DefaultFetch { get; } = async (url, method, headers, body) =>
    {
        using var req = new HttpRequestMessage(new HttpMethod(method), url) { Content = new StringContent(body, Encoding.UTF8, "application/json") };
        foreach (var (k, v) in headers) if (!k.Equals("content-type", StringComparison.OrdinalIgnoreCase)) req.Headers.TryAddWithoutValidation(k, v);
        using var res = await Http.SendAsync(req).ConfigureAwait(false);
        return (res.IsSuccessStatusCode, (int)res.StatusCode);
    };

    static readonly HttpClient Http = new();

    sealed class HttpChannel(string kind, string? url, ApprovalFetch? fetch, Func<D, ApprovalNotifyContext?, object> format, IReadOnlyDictionary<string, string> headers, string label) : IApprovalChannel
    {
        public string Kind => kind;
        public bool Enabled { get; } = !string.IsNullOrEmpty(url);
        public async Task<ApprovalDelivery> NotifyAsync(D request, ApprovalNotifyContext? ctx = null)
        {
            var id = Str(request, "id");
            var payload = format(request, ctx);
            if (!Enabled) return new(kind, id, false, payload, null, $"{label} channel not configured");
            try
            {
                var (ok, status) = await (fetch ?? DefaultFetch)(url!, "POST", headers, JsJson.Stringify(payload)).ConfigureAwait(false);
                return ok ? new(kind, id, true, payload, status)
                    : new(kind, id, false, payload, status, kind == "slack" ? $"slack webhook returned {status}" : $"webhook returned {status}");
            }
            catch (Exception e) { return new(kind, id, false, payload, null, e.Message); }
        }
    }

    static readonly IReadOnlyDictionary<string, string> Json = new Dictionary<string, string> { ["content-type"] = "application/json" };

    /// <summary>Slack approval channel (Block Kit over an incoming webhook). Disabled, and a no-op, unless a webhook URL is configured.</summary>
    public static IApprovalChannel SlackApprovalChannel(string? webhookUrl = null, ApprovalFetch? fetch = null) =>
        new HttpChannel("slack", webhookUrl, fetch, (r, c) => BuildSlackMessage(r, c), Json, "slack");

    /// <summary>Generic webhook approval channel: a JSON POST of <see cref="BuildWebhookBody"/>. <paramref name="headers"/> are extra headers (never logged).</summary>
    public static IApprovalChannel WebhookApprovalChannel(string? url = null, ApprovalFetch? fetch = null, IReadOnlyDictionary<string, string>? headers = null)
    {
        var h = new Dictionary<string, string> { ["content-type"] = "application/json" };
        if (headers != null) foreach (var (k, v) in headers) h[k] = v;
        return new HttpChannel("webhook", url, fetch, (r, c) => BuildWebhookBody(r, c), h, "webhook");
    }

    sealed class TextChannel(string kind, Func<string, string, Task>? send) : IApprovalChannel
    {
        public string Kind => kind;
        public bool Enabled => send != null;
        public async Task<ApprovalDelivery> NotifyAsync(D request, ApprovalNotifyContext? ctx = null)
        {
            var id = Str(request, "id");
            var (subject, text) = BuildTextBody(request, ctx);
            var payload = new D { ["subject"] = subject, ["text"] = text };
            if (send == null) return new(kind, id, false, payload, null, $"{kind} channel not configured");
            try { await send(subject, text).ConfigureAwait(false); return new(kind, id, true, payload); }
            catch (Exception e) { return new(kind, id, false, payload, null, e.Message); }
        }
    }

    /// <summary>A text-formatter channel (<c>email</c>, <c>sms</c> or <c>push</c>) over an injected sender <c>(subject, text) -&gt; task</c>; absent sender = disabled.</summary>
    public static IApprovalChannel TextApprovalChannel(string kind, Func<string, string, Task>? send = null) =>
        kind is "email" or "sms" or "push" ? new TextChannel(kind, send) : throw new ArgumentException("textApprovalChannel: kind must be email, sms or push");

    /// <summary>Register a set of channels behind one dispatcher; disabled channels are skipped at <see cref="ApprovalDispatcher.NotifyAllAsync"/>.</summary>
    public static ApprovalDispatcher CreateApprovalDispatcher(IEnumerable<IApprovalChannel> channels) => new(channels.ToList());
}

/// <summary>Fans a step-up out to every ENABLED channel and collects one <see cref="ApprovalDelivery"/> per channel.</summary>
public sealed class ApprovalDispatcher
{
    public IReadOnlyList<IApprovalChannel> Channels { get; }
    internal ApprovalDispatcher(IReadOnlyList<IApprovalChannel> channels) { Channels = channels; }

    public async Task<List<ApprovalDelivery>> NotifyAllAsync(D request, ApprovalNotifyContext? ctx = null)
    {
        var o = new List<ApprovalDelivery>();
        foreach (var c in Channels) if (c.Enabled) o.Add(await c.NotifyAsync(request, ctx).ConfigureAwait(false));
        return o;
    }
}

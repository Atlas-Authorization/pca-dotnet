using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Differential replay of the approval-channel layer against the TypeScript reference (test-data/ref-core-approval-channels.json.gz): the payload builders, every channel
/// kind over a scripted transport, and the dispatcher.</summary>
public class RefCoreApprovalChannelsTests
{
    const string M = "ref-core-approval-channels";

    static ApprovalNotifyContext Ctx(object? c) => new(c is D d && d.GetValueOrDefault("inboxUrl") is string u ? u : null);

    static ApprovalFetch Transport(string mode) => (url, method, headers, body) => mode switch
    {
        "ok" => Task.FromResult((true, 200)),
        "http500" => Task.FromResult((false, 500)),
        "throw" => throw new InvalidOperationException("boom"),
        _ => throw new InvalidOperationException(""),
    };

    static IApprovalChannel Channel(string kind, D cfg)
    {
        var configured = cfg.GetValueOrDefault("configured") is true;
        var t = (string)cfg["transport"]!;
        var f = Transport(t);
        if (kind == "slack") return ApprovalChannels.SlackApprovalChannel(configured ? "https://hooks.example/secret" : null, f);
        if (kind == "webhook")
        {
            var h = cfg.GetValueOrDefault("headers") is D hd ? hd.ToDictionary(kv => kv.Key, kv => (string)kv.Value!) : new Dictionary<string, string>();
            return ApprovalChannels.WebhookApprovalChannel(configured ? "https://hooks.example/secret" : null, f, h);
        }
        Func<string, string, Task>? sender = (subject, text) => t == "ok" ? Task.CompletedTask : throw new InvalidOperationException(t == "throw-empty" ? "" : "boom");
        return ApprovalChannels.TextApprovalChannel(kind, configured ? sender : null);
    }

    static D Out(ApprovalDelivery d)
    {
        var o = new D { ["kind"] = d.Kind, ["requestId"] = d.RequestId, ["delivered"] = d.Delivered, ["payload"] = d.Payload };
        if (d.Status != null) o["status"] = d.Status;
        if (d.Reason != null) o["reason"] = d.Reason;
        return o;
    }

    [Fact] public void ActionSummary() => Base.Check(M, "actionSummary", a => ApprovalChannels.ActionSummary((D)a[0]!));
    [Fact] public void LineageLines() => Base.Check(M, "lineageLines", a => ApprovalChannels.LineageLines((D)a[0]!));
    [Fact] public void RenderLines() => Base.Check(M, "renderLines", a => ApprovalChannels.RenderLines((D)a[0]!));
    [Fact] public void BuildSlackMessage() => Base.Check(M, "buildSlackMessage", a => ApprovalChannels.BuildSlackMessage((D)a[0]!, Ctx(a.Count > 1 ? a[1] : null)));
    [Fact] public void BuildWebhookBody() => Base.Check(M, "buildWebhookBody", a => ApprovalChannels.BuildWebhookBody((D)a[0]!, Ctx(a.Count > 1 ? a[1] : null)));

    [Fact]
    public void BuildTextBody() => Base.Check(M, "buildTextBody", a =>
    {
        var (subject, text) = ApprovalChannels.BuildTextBody((D)a[0]!, Ctx(a.Count > 1 ? a[1] : null));
        return new D { ["subject"] = subject, ["text"] = text };
    });

    [Fact]
    public void Notify() => Base.Check(M, "notify", a => Out(Channel((string)a[0]!, (D)a[3]!).NotifyAsync((D)a[1]!, Ctx(a[2])).GetAwaiter().GetResult()));

    [Fact]
    public void NotifyAll() => Base.Check(M, "notifyAll", a =>
    {
        var channels = ((L)a[2]!).Cast<D>().Select(c => Channel((string)c["kind"]!, c)).ToList();
        var res = ApprovalChannels.CreateApprovalDispatcher(channels).NotifyAllAsync((D)a[0]!, Ctx(a[1])).GetAwaiter().GetResult();
        return res.Select(r => (object?)Out(r)).ToList();
    });

    [Fact] public void EveryFnIsHandled() { Base.Covers(M, new[] { "actionSummary", "lineageLines", "renderLines", "buildSlackMessage", "buildWebhookBody", "buildTextBody", "notify", "notifyAll" }); Assert.Equal(411, Base.Total(M)); }
}

using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

public class ApprovalChannelsTests
{
    static D Request() => new()
    {
        ["id"] = "su_1", ["verb"] = "stripe.refund", ["resource"] = "charge:ch_1", ["tier"] = new Num("2"), ["reason"] = "over the limit", ["r"] = new Num("0.456"),
        ["lineage"] = new D
        {
            ["because"] = "you asked to refund order 1",
            ["chain"] = new L { new D { ["label"] = "Goal", ["detail"] = "refund order 1" }, new D { ["label"] = "Authority" } },
        },
    };

    [Fact]
    public void SummaryLineageAndBodies()
    {
        var r = Request();
        Assert.Equal("stripe.refund on charge:ch_1 (tier 2, risk 0.46)", ApprovalChannels.ActionSummary(r));
        Assert.Equal(new[] { "you asked to refund order 1", "Goal — refund order 1", "Authority" }, ApprovalChannels.LineageLines(r));
        var t = ApprovalChannels.BuildTextBody(r, new ApprovalNotifyContext("https://app.example/inbox#tok"));
        Assert.Equal("Approval needed: stripe.refund on charge:ch_1", t.Subject);
        Assert.EndsWith("Approve or deny: https://app.example/inbox?stepup=su_1#tok", t.Text); // the fragment stays last
        var w = ApprovalChannels.BuildWebhookBody(r);
        Assert.Equal("pca.step_up.created", w["type"]);
        Assert.False(w.ContainsKey("inbox_url"));
        var s = ApprovalChannels.BuildSlackMessage(r, new ApprovalNotifyContext("https://app.example/inbox"));
        var blocks = (L)s["blocks"]!;
        Assert.Equal(4, blocks.Count);
        Assert.Equal("actions", ((D)blocks[3]!)["type"]);
        Assert.Equal(4, ((L)ApprovalChannels.BuildSlackMessage(r)["blocks"]!).Count); // context block instead of the buttons
    }

    [Fact]
    public async Task ChannelsGateOnConfigAndNeverThrow()
    {
        var r = Request();
        var off = ApprovalChannels.SlackApprovalChannel();
        Assert.False(off.Enabled);
        Assert.Equal("slack channel not configured", (await off.NotifyAsync(r)).Reason);
        var calls = new List<string>();
        ApprovalFetch ok = (url, method, headers, body) => { calls.Add(method + " " + url + " " + headers["content-type"]); return Task.FromResult((true, 200)); };
        ApprovalFetch bad = (url, method, headers, body) => Task.FromResult((false, 500));
        ApprovalFetch boom = (url, method, headers, body) => throw new InvalidOperationException("down");
        var slack = ApprovalChannels.SlackApprovalChannel("https://hooks.example/x", ok);
        var d = await slack.NotifyAsync(r);
        Assert.True(d.Delivered); Assert.Equal(200, d.Status);
        Assert.Equal("POST https://hooks.example/x application/json", calls.Single());
        Assert.Equal("webhook returned 500", (await ApprovalChannels.WebhookApprovalChannel("https://h.example", bad).NotifyAsync(r)).Reason);
        Assert.Equal("down", (await ApprovalChannels.WebhookApprovalChannel("https://h.example", boom).NotifyAsync(r)).Reason);
        var sent = new List<string>();
        var email = ApprovalChannels.TextApprovalChannel("email", (subject, text) => { sent.Add(subject); return Task.CompletedTask; });
        var disp = ApprovalChannels.CreateApprovalDispatcher(new[] { off, slack, email, ApprovalChannels.TextApprovalChannel("sms") });
        var all = await disp.NotifyAllAsync(r);
        Assert.Equal(new[] { "slack", "email" }, all.Select(x => x.Kind));
        Assert.Single(sent);
        Assert.Throws<ArgumentException>(() => ApprovalChannels.TextApprovalChannel("fax"));
    }
}

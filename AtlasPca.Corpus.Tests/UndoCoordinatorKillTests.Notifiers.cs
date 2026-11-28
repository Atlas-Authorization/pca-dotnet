using System.Net;
using System.Net.Sockets;
using System.Text;
using AtlasPca;
using Xunit;
using JD = System.Collections.Generic.Dictionary<string, object?>;
using JL = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

// The principal notifier over the approval channels and the hosted veto relay, with the exact request, wording and parsing.
public partial class UndoCoordinatorKillTests
{
    const string Until = "2027-01-15T08:01:00.000Z"; // T0 + 60 000 ms

    sealed class Chan(string kind, bool enabled, Func<JD, ApprovalNotifyContext?, ApprovalDelivery>? answer = null) : IApprovalChannel
    {
        public readonly List<(JD Req, ApprovalNotifyContext? Ctx)> Seen = new();
        public string Kind => kind;
        public bool Enabled => enabled;
        public Task<ApprovalDelivery> NotifyAsync(JD request, ApprovalNotifyContext? ctx = null)
        {
            Seen.Add((request, ctx));
            return Task.FromResult(answer != null ? answer(request, ctx) : new ApprovalDelivery(kind, "x", true, null));
        }
    }

    static JD NoteRecord(JD? outcome = null, string? renderDigest = null)
    {
        var r = new JD
        {
            ["id"] = "rec1", ["action"] = new JD { ["verb"] = "pay", ["resource"] = "invoice:1" }, ["window_end"] = IntentJs.OfLong(T0 + 60_000),
            ["compensation"] = new JD { ["verb"] = "pay.refund" }, ["opened_at"] = IntentJs.OfLong(T0),
        };
        if (outcome != null) r["outcome"] = outcome;
        if (renderDigest != null) r["render_digest"] = renderDigest;
        return r;
    }

    static IUndoNotifier NotifierOver(Chan[] chans, string? inbox = "https://inbox.example") =>
        UndoNotifiers.FromDispatcher(ApprovalChannels.CreateApprovalDispatcher(chans), (token, id) => "https://u.example/undo/" + token + "/" + id, inbox);

    [Fact]
    public async Task EveryNoticeKindHasItsExactWordingAndRequest()
    {
        var cases = new (string Kind, string Reason)[]
        {
            ("opened", "Already done: pay on invoice:1. You can undo it until " + Until + "."),
            ("vetoed", "Undo started for pay on invoice:1."),
            ("compensated", "Undone: pay on invoice:1."),
            ("compensation_failed", "UNDO FAILED for pay on invoice:1: unknown. An operator has been alerted."),
            ("revoked", "The agent's grant was revoked. pay on invoice:1 can still be undone until " + Until + "."),
            ("finalized", "Final: pay on invoice:1 can no longer be undone."),
        };
        foreach (var (kind, reason) in cases)
        {
            var chan = new Chan("c", true);
            var rec = NoteRecord();
            var res = await NotifierOver(new[] { chan }).NotifyAsync(new UndoNotice(kind, rec));
            Assert.Equal(new UndoNotifyResult(true), res);
            var (req, _) = Assert.Single(chan.Seen);
            Assert.Equal("undo:rec1:" + kind, req["id"]);
            Assert.Equal("pay", req["verb"]);
            Assert.Equal("invoice:1", req["resource"]);
            Assert.Equal(3L, Lg(req["tier"]));
            Assert.Equal(reason, req["reason"]);
            Assert.Equal("", req["goalCommit"]);
            Assert.Equal(0L, Lg(req["r"]));
            Assert.Same(rec["opened_at"], req["requestedAt"]);
            var lineage = Sub(req, "lineage");
            Assert.Equal("", lineage["goalCommit"]);
            Assert.Equal(false, lineage["goalVerified"]);
            Assert.Equal(reason, lineage["because"]);
            var step = Assert.IsType<JD>(Assert.Single((JL)lineage["chain"]!));
            Assert.Equal("action", step["kind"]);
            Assert.Equal("pay invoice:1", step["label"]);
            Assert.Equal("undo: pay.refund", step["detail"]);
            Assert.False(req.ContainsKey("render"));
            Assert.False(req.ContainsKey("renderDigest"));
        }
    }

    [Fact]
    public async Task AFailedUndoNamesTheOutcomeReasonWhenThereIsOne()
    {
        async Task<string> Reason(JD rec)
        {
            var chan = new Chan("c", true);
            await NotifierOver(new[] { chan }).NotifyAsync(new UndoNotice("compensation_failed", rec));
            return (string)chan.Seen[0].Req["reason"]!;
        }
        Assert.Equal("UNDO FAILED for pay on invoice:1: boom. An operator has been alerted.", await Reason(NoteRecord(new JD { ["reason"] = "boom" })));
        Assert.Equal("UNDO FAILED for pay on invoice:1: unknown. An operator has been alerted.", await Reason(NoteRecord(new JD { ["reason"] = 5L })));
        Assert.Equal("UNDO FAILED for pay on invoice:1: unknown. An operator has been alerted.", await Reason(NoteRecord(new JD())));
    }

    [Fact]
    public async Task TheRenderTravelsOnlyWhenBothTheNoticeAndTheRecordCarryIt()
    {
        var render = new JD { ["lines"] = "x" };
        var both = new Chan("c", true);
        await NotifierOver(new[] { both }).NotifyAsync(new UndoNotice("opened", NoteRecord(renderDigest: "RD"), "TK", render));
        var req = both.Seen[0].Req;
        Assert.Same(render, req["render"]);
        Assert.Equal("RD", req["renderDigest"]);
        var noRender = new Chan("c", true);
        await NotifierOver(new[] { noRender }).NotifyAsync(new UndoNotice("opened", NoteRecord(renderDigest: "RD"), "TK", null));
        Assert.False(noRender.Seen[0].Req.ContainsKey("render"));
        Assert.False(noRender.Seen[0].Req.ContainsKey("renderDigest"));
        var noDigest = new Chan("c", true);
        await NotifierOver(new[] { noDigest }).NotifyAsync(new UndoNotice("opened", NoteRecord(), "TK", render));
        Assert.False(noDigest.Seen[0].Req.ContainsKey("render"));
        Assert.False(noDigest.Seen[0].Req.ContainsKey("renderDigest"));
    }

    [Fact]
    public async Task TheLinkIsTheUndoUrlOnlyForAnOpenedNoticeWithAToken()
    {
        async Task<string?> Link(string kind, string? token, string? inbox)
        {
            var chan = new Chan("c", true);
            await NotifierOver(new[] { chan }, inbox).NotifyAsync(new UndoNotice(kind, NoteRecord(), token));
            return chan.Seen[0].Ctx?.InboxUrl;
        }
        Assert.Equal("https://u.example/undo/TK/rec1", await Link("opened", "TK", "https://inbox"));
        Assert.Equal("https://inbox", await Link("opened", null, "https://inbox"));
        Assert.Equal("https://inbox", await Link("vetoed", "TK", "https://inbox"));
        Assert.Null(await Link("vetoed", "TK", null));
        Assert.Null(await Link("opened", null, null));
        var none = new Chan("c", true);
        await NotifierOver(new[] { none }, null).NotifyAsync(new UndoNotice("finalized", NoteRecord()));
        Assert.Null(none.Seen[0].Ctx);
    }

    [Fact]
    public async Task TheDeliveryVerdictNamesEveryFailedChannel()
    {
        var off = new Chan("sms", false);
        var ok = new Chan("email", true);
        Assert.Equal(new UndoNotifyResult(true), await NotifierOver(new[] { off, ok }).NotifyAsync(new UndoNotice("vetoed", NoteRecord())));
        Assert.Empty(off.Seen);
        Assert.Single(ok.Seen);

        Assert.Equal(new UndoNotifyResult(false, "no enabled channel"), await NotifierOver(new[] { new Chan("sms", false) }).NotifyAsync(new UndoNotice("vetoed", NoteRecord())));
        Assert.Equal(new UndoNotifyResult(false, "no enabled channel"), await NotifierOver(Array.Empty<Chan>()).NotifyAsync(new UndoNotice("vetoed", NoteRecord())));

        var slack = new Chan("slack", true, (_, _) => new ApprovalDelivery("slack", "x", false, null, 500, "http 500"));
        var mail = new Chan("email", true, (_, _) => new ApprovalDelivery("email", "x", false, null));
        Assert.Equal(new UndoNotifyResult(false, "slack: http 500; email: not delivered"), await NotifierOver(new[] { slack, mail }).NotifyAsync(new UndoNotice("vetoed", NoteRecord())));

        var mixed = await NotifierOver(new[] { slack, ok }).NotifyAsync(new UndoNotice("vetoed", NoteRecord()));
        Assert.Equal(new UndoNotifyResult(true), mixed);
    }

    // ---------------------------------------------------------------------------------------------------------------- the hosted relay

    static UndoNotifiers.UndoRelayFetch Body(string json, bool ok = true, int status = 200, List<(string Url, IReadOnlyDictionary<string, string> Headers)>? seen = null) => (url, headers) =>
    {
        seen?.Add((url, headers));
        return Task.FromResult(new UndoNotifiers.UndoRelayResponse(ok, status, () => Task.FromResult<object?>(Pca.ParseJson(json))));
    };

    [Fact]
    public async Task TheHostedRelaySendsTheRightRequest()
    {
        var seen = new List<(string Url, IReadOnlyDictionary<string, string> Headers)>();
        var relay = UndoNotifiers.HostedVetoRelay("https://u.example///", "sk_x", Body("{\"data\":[]}", seen: seen));
        Assert.Empty(await relay.PendingAsync());
        var (url, headers) = Assert.Single(seen);
        Assert.Equal("https://u.example/v1/pca/undo/vetoes?limit=200", url);
        Assert.Equal(2, headers.Count);
        Assert.Equal("Bearer sk_x", headers["authorization"]);
        Assert.Equal("application/json", headers["accept"]);
        foreach (var (limit, expected) in new[] { (0, 1), (-5, 1), (1, 1), (50, 50), (200, 200), (201, 200), (500, 200) })
        {
            var s = new List<(string Url, IReadOnlyDictionary<string, string> Headers)>();
            await UndoNotifiers.HostedVetoRelay("https://u.example", "k", Body("{\"data\":[]}", seen: s), limit).PendingAsync();
            Assert.Equal("https://u.example/v1/pca/undo/vetoes?limit=" + expected, s[0].Url);
        }
    }

    [Fact]
    public async Task TheHostedRelayRefusesWhatItCannotParse()
    {
        async Task<string> Fails(string json, bool ok = true, int status = 200)
        {
            var e = await Assert.ThrowsAsync<UndoError>(() => UndoNotifiers.HostedVetoRelay("https://u", "k", Body(json, ok, status)).PendingAsync());
            Assert.Equal("invalid", e.Code);
            return e.Message;
        }
        Assert.Equal("invalid: the veto relay answered 503", await Fails("{}", false, 503));
        Assert.Equal("invalid: the veto relay answered without a data list", await Fails("[]"));
        Assert.Equal("invalid: the veto relay answered without a data list", await Fails("{}"));
        Assert.Equal("invalid: the veto relay answered without a data list", await Fails("{\"data\":5}"));
        const string malformed = "invalid: the veto relay answered a malformed entry";
        Assert.Equal(malformed, await Fails("{\"data\":[{\"veto\":{\"token\":\"t\",\"at\":1}}]}"));
        Assert.Equal(malformed, await Fails("{\"data\":[{\"record_id\":5,\"veto\":{\"token\":\"t\",\"at\":1}}]}"));
        Assert.Equal(malformed, await Fails("{\"data\":[{\"record_id\":\"r\"}]}"));
        Assert.Equal(malformed, await Fails("{\"data\":[{\"record_id\":\"r\",\"veto\":{\"at\":1}}]}"));
        Assert.Equal(malformed, await Fails("{\"data\":[{\"record_id\":\"r\",\"veto\":{\"token\":5,\"at\":1}}]}"));
        Assert.Equal(malformed, await Fails("{\"data\":[{\"record_id\":\"r\",\"veto\":{\"token\":\"t\"}}]}"));
        Assert.Equal(malformed, await Fails("{\"data\":[{\"record_id\":\"r\",\"veto\":{\"token\":\"t\",\"at\":\"1\"}}]}"));
        var ok = await UndoNotifiers.HostedVetoRelay("https://u", "k", Body("{\"data\":[{\"record_id\":\"a\",\"veto\":{\"token\":\"t1\",\"at\":1}},{\"record_id\":\"b\",\"veto\":{\"token\":\"t2\",\"at\":2.5}}]}")).PendingAsync();
        Assert.Equal(new[] { new UndoRelayedVeto("a", "t1", 1), new UndoRelayedVeto("b", "t2", 2.5) }, ok.ToArray());
    }

    [Fact]
    public async Task TheDefaultHostedRelayTransportReadsOverHttp()
    {
        async Task<(string Url, Task<string> Request)> Serve(string status, string body)
        {
            var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            var port = ((IPEndPoint)listener.LocalEndpoint).Port;
            var request = Task.Run(async () =>
            {
                try
                {
                    using var client = await listener.AcceptTcpClientAsync();
                    using var stream = client.GetStream();
                    var text = new StringBuilder();
                    var buf = new byte[1024];
                    while (!text.ToString().Contains("\r\n\r\n"))
                    {
                        var n = await stream.ReadAsync(buf);
                        if (n == 0) break;
                        text.Append(Encoding.ASCII.GetString(buf, 0, n));
                    }
                    var bytes = Encoding.UTF8.GetBytes(body);
                    var head = "HTTP/1.1 " + status + "\r\nContent-Type: application/json\r\nContent-Length: " + bytes.Length + "\r\nConnection: close\r\n\r\n";
                    await stream.WriteAsync(Encoding.ASCII.GetBytes(head));
                    await stream.WriteAsync(bytes);
                    await stream.FlushAsync();
                    return text.ToString();
                }
                finally { listener.Stop(); }
            });
            return ("http://127.0.0.1:" + port, request);
        }

        var (url, request) = await Serve("200 OK", "{\"data\":[{\"record_id\":\"r1\",\"veto\":{\"token\":\"tok\",\"at\":7}}]}");
        var list = await UndoNotifiers.HostedVetoRelay(url, "sk_http").PendingAsync();
        Assert.Equal(new UndoRelayedVeto("r1", "tok", 7), Assert.Single(list));
        var sent = (await request).ToLowerInvariant();
        Assert.StartsWith("get /v1/pca/undo/vetoes?limit=200 http/1.1", sent);
        Assert.Contains("authorization: bearer sk_http", sent);
        Assert.Contains("accept: application/json", sent);

        var (url2, _) = await Serve("503 Service Unavailable", "{}");
        var e = await Assert.ThrowsAsync<UndoError>(() => UndoNotifiers.HostedVetoRelay(url2, "k").PendingAsync());
        Assert.Equal("invalid: the veto relay answered 503", e.Message);
    }
}

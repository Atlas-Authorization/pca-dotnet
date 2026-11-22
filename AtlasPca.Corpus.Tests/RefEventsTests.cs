using AtlasPca.Events;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Differential oracle of step-up events, HMAC-signed webhooks and delivery verification (test-data/ref-events.json.gz, TypeScript reference pca-events).
/// A secret is a JSON string, or {"$bytes": b64url} for a byte secret; any other JSON value is passed as is (and refused as a secret).</summary>
public class RefEventsTests
{
    const string M = "ref-events";
    const string Secret = "whsec_0123456789abcdef0123456789";

    static object? Sec(object? s) => Base.IsBytes(s) ? Base.Bytes(s) : s;

    [Fact] public void BuildStepUpEvent() => Base.Check(M, "buildStepUpEvent", a => StepUpEvents.BuildStepUpEvent(a[0], a[1]));
    [Fact] public void SerializeEvent() => Base.Check(M, "serializeEvent", a => StepUpEvents.SerializeEvent(a[0]));
    [Fact] public void ParseEvent() => Base.Check(M, "parseEvent", a => StepUpEvents.ParseEvent(a[0]));
    [Fact] public void SignWebhook() => Base.Check(M, "signWebhook", a => StepUpEvents.SignWebhook(Sec(a[0]), (string)a[1]!, a[2] as D));
    [Fact] public void WebhookHeaders() => Base.Check(M, "webhookHeaders", a => StepUpEvents.WebhookHeaders(Sec(a[0]), (string)a[1]!, a[2] as D));
    [Fact] public void VerifyWebhook() => Base.Check(M, "verifyWebhook", a => StepUpEvents.VerifyWebhook(Sec(a[0]), (string)a[1]!, a[2], a.Count > 3 ? a[3] as D : null));
    [Fact] public void MinSecretBytes() => Base.Check(M, "minSecretBytes", _ => StepUpEvents.MinSecretBytes);

    sealed class Throws : IReplayStore { public Task<bool> ConsumeOnce(string key, double r, double n) => throw new InvalidOperationException("down"); }
    sealed class Refuses : IReplayStore { public Task<bool> ConsumeOnce(string key, double r, double n) => Task.FromResult(false); }

    static string? Normalize(string? reason)
    {
        if (reason == null) return null;
        if (reason.StartsWith("canonicalize:", StringComparison.Ordinal)) return "<canonicalize>";
        string[] known = { "a replay store", "bad signature", "replayed", "replay store", "parseEvent: " };
        return known.Any(k => reason.StartsWith(k, StringComparison.Ordinal)) ? reason : "<json>";
    }

    static async Task<L> Deliveries(D spec)
    {
        IReplayStore store = (spec.GetValueOrDefault("store") as string) switch { "throws" => new Throws(), "refuses" => new Refuses(), _ => new MemoryReplayStore() };
        var outp = new L();
        foreach (var raw in (L)spec["deliveries"]!)
        {
            var d = (D)raw!;
            var dopts = d.GetValueOrDefault("opts") as D;
            D? opts = null;
            IReplayStore? replay = null;
            if (spec.GetValueOrDefault("noOpts") is not true)
            {
                opts = dopts == null ? new D() : new D(dopts);
                replay = spec.GetValueOrDefault("noReplay") is true || (dopts != null && dopts.ContainsKey("replay")) ? null : store;
            }
            var secret = Sec(d.TryGetValue("secret", out var sv) && sv != null ? sv : Secret);
            D v;
            try { v = await StepUpEvents.VerifyDelivery(secret, (string)d["payload"]!, d.GetValueOrDefault("header"), opts, replay); }
            catch (Exception) { v = new D { ["$err"] = true }; }
            if (v.GetValueOrDefault("ok") is false && v["reason"] is string r) v["reason"] = Normalize(r);
            outp.Add(v);
        }
        return outp;
    }

    [Fact] public void DeliveryScenario() => Base.Check(M, "deliveryScenario", a => Deliveries((D)a[0]!).GetAwaiter().GetResult());

    [Fact]
    public void EveryFn() { Base.Covers(M, new[] { "buildStepUpEvent", "serializeEvent", "parseEvent", "signWebhook", "verifyWebhook", "webhookHeaders", "deliveryScenario", "minSecretBytes" }); Assert.Equal(1071, Base.Total(M)); }
}

using System.Globalization;
using System.Net;
using System.Reflection;
using System.Text;
using System.Text.Json;
using AtlasPca;
using Xunit;
using JD = System.Collections.Generic.Dictionary<string, object?>;
using JL = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

// Mutation kills for StepUp, CaveatLang, Operations, RevocationFreshness, ReadVault and ArgProvenance: exact messages, boundaries, the
// fail-closed catches (a comparer that throws, a list that throws), the sampler's step bounds, and that no await captures the caller's
// SynchronizationContext. Limits are the TypeScript reference's (read-vault.ts, revocation.ts, arg-provenance.ts); the step-up client
// has no TypeScript counterpart, its limits are the same in the Go SDK (stepup.go).
public class GroupAKillTests
{
    const long Now = 1_800_000_000_000L;

    // ---- shared seams ------------------------------------------------------------------------------------------------------

    sealed class HostileComparer : IEqualityComparer<string>
    {
        public bool Armed;
        public bool Equals(string? a, string? b) => Armed ? throw new InvalidOperationException("hostile") : a == b;
        public int GetHashCode(string s) => Armed ? throw new InvalidOperationException("hostile") : 0;
    }

    // an empty dictionary answers a lookup without asking its comparer, and a key the closed-member check does not know is refused
    // before any lookup: so it holds a member the check allows
    static JD Hostile(string key)
    {
        var h = new HostileComparer();
        var d = new JD(h) { [key] = null };
        h.Armed = true;
        return d;
    }

    sealed class Bomb<T> : IReadOnlyList<T>
    {
        public int Count => throw new InvalidOperationException("boom");
        public T this[int index] => throw new InvalidOperationException("boom");
        public IEnumerator<T> GetEnumerator() => throw new InvalidOperationException("boom");
        System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator() => throw new InvalidOperationException("boom");
    }

    static object? Priv(Type t, string name, params object?[] args) =>
        t.GetMethod(name, BindingFlags.NonPublic | BindingFlags.Static)!.Invoke(null, args);

    static EdKey Ed(byte b) => EdKey.FromSeed(Enumerable.Repeat(b, 32).ToArray());

    sealed class CountingContext : SynchronizationContext
    {
        public int Posts;
        public override void Post(SendOrPostCallback d, object? state)
        {
            Interlocked.Increment(ref Posts);
            ThreadPool.QueueUserWorkItem(_ => d(state));
        }
    }

    // run's synchronous part sees the context; only an await that captured it posts back
    static async Task<int> PostsDuring(Func<Task> run)
    {
        var ctx = new CountingContext();
        var saved = SynchronizationContext.Current;
        Task t;
        SynchronizationContext.SetSynchronizationContext(ctx);
        try { t = run(); }
        finally { SynchronizationContext.SetSynchronizationContext(saved); }
        await t;
        return ctx.Posts;
    }

    // ---- StepUp: keys ------------------------------------------------------------------------------------------------------

    sealed class FakeStore : ISecretStore
    {
        public Func<byte[]?> OnLoad = () => null;
        public Action<byte[]> OnSave = _ => { };
        public byte[]? Load() => OnLoad();
        public void Save(byte[] secret) => OnSave(secret);
        public void Delete() { }
    }

    const string BadSecret = "The principal secret must be a base64url-encoded 32-byte Ed25519 seed.";

    [Fact]
    public void StepUpExceptionMessagePrefixOnlyForApi()
    {
        Assert.Equal("m", new StepUpException(StepUpKind.Transport, "m", 5).Message);
        Assert.Equal("m", new StepUpException(StepUpKind.PrincipalMismatch, "m", 403).Message);
        Assert.Equal("HTTP 5: m", new StepUpException(StepUpKind.Api, "m", 5).Message);
    }

    [Fact]
    public void DeviceKeyStoreFailuresAndBadSeeds()
    {
        Assert.Equal("store", Assert.Throws<ArgumentNullException>(() => new PrincipalDeviceKey(null!)).ParamName);
        Assert.False(new PrincipalDeviceKey(new FakeStore { OnLoad = () => Array.Empty<byte>() }).Exists());
        Assert.False(new PrincipalDeviceKey(new FakeStore { OnLoad = () => throw new IOException("x") }).Exists());
        Assert.True(new PrincipalDeviceKey(new FakeStore { OnLoad = () => new byte[1] }).Exists());

        var boom = new IOException("x");
        var save = Assert.Throws<StepUpException>(() => new PrincipalDeviceKey(new FakeStore { OnSave = _ => throw boom }).Generate());
        Assert.Equal((StepUpKind.Transport, "Could not persist the principal key.", 0), (save.Kind, save.Message, save.Status));
        Assert.Same(boom, save.InnerException);

        var read = Assert.Throws<StepUpException>(() => new PrincipalDeviceKey(new FakeStore { OnLoad = () => throw boom }).ExportSecret());
        Assert.Equal((StepUpKind.Transport, "Could not read the principal key."), (read.Kind, read.Message));

        foreach (var none in new[] { null, Array.Empty<byte>() })
        {
            var e = Assert.Throws<StepUpException>(() => new PrincipalDeviceKey(new FakeStore { OnLoad = () => none }).ExportSecret());
            Assert.Equal((StepUpKind.NoDeviceKey, "No principal device key is stored on this device."), (e.Kind, e.Message));
        }

        foreach (var len in new[] { 31, 33 })
        {
            var e = Assert.Throws<StepUpException>(() => new PrincipalDeviceKey(new FakeStore { OnLoad = () => new byte[len] }).ExportSecret());
            Assert.Equal((StepUpKind.InvalidSecret, BadSecret), (e.Kind, e.Message));
        }
    }

    // ---- StepUp: client ----------------------------------------------------------------------------------------------------

    sealed class FakeHttp : HttpClient
    {
        readonly Func<HttpRequestMessage, Task<HttpResponseMessage>> _f;
        public readonly List<string> Urls = new();
        public readonly List<byte[]> Bodies = new();
        public readonly List<string?> ContentTypes = new();
        public FakeHttp(Func<HttpRequestMessage, Task<HttpResponseMessage>> f) => _f = f;

        public override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Urls.Add(request.RequestUri!.AbsoluteUri);
            Bodies.Add(request.Content == null ? Array.Empty<byte>() : request.Content.ReadAsByteArrayAsync(cancellationToken).GetAwaiter().GetResult());
            ContentTypes.Add(request.Content?.Headers.ContentType?.ToString());
            return _f(request);
        }
    }

    sealed class SlowContent : HttpContent
    {
        readonly byte[] _b;
        public SlowContent(string text) => _b = Encoding.UTF8.GetBytes(text);
        protected override async Task SerializeToStreamAsync(Stream stream, TransportContext? context)
        {
            await Task.Delay(5).ConfigureAwait(false);
            await stream.WriteAsync(_b).ConfigureAwait(false);
        }
        protected override bool TryComputeLength(out long length) { length = 0; return false; }
    }

    static HttpResponseMessage Resp(int status, byte[] body) => new((HttpStatusCode)status) { Content = new ByteArrayContent(body) };
    static Task<HttpResponseMessage> Text(int status, string body) => Task.FromResult(Resp(status, Encoding.UTF8.GetBytes(body)));
    static FakeHttp Answer(int status, string body) => new(_ => Text(status, body));

    static async Task<HttpResponseMessage> Slow(int status, string body)
    {
        await Task.Delay(5).ConfigureAwait(false);
        return Resp(status, Encoding.UTF8.GetBytes(body));
    }

    static async Task<string> SlowToken(CancellationToken _)
    {
        await Task.Delay(5).ConfigureAwait(false);
        return "t";
    }

    static PrincipalDeviceKey NewKey()
    {
        var k = new PrincipalDeviceKey(new MemorySecretStore());
        k.Generate();
        return k;
    }

    static StepUpClientOptions Opts(HttpClient? http = null, Func<CancellationToken, Task<string>>? token = null, Func<long>? now = null) => new()
    {
        DashboardUrl = "https://d.example", InstanceUrl = "https://i.example", AccountId = "acc", InstanceId = "ins", Key = NewKey(),
        Token = token ?? (_ => Task.FromResult("t")), Http = http, Now = now ?? (() => Now),
    };

    static StepUpClient Client(HttpClient http, Func<CancellationToken, Task<string>>? token = null, Func<long>? now = null) => new(Opts(http, token, now));

    static readonly PendingStepUp Su = new("s", "g", "v", "r", 1, "AAEC", Now);

    static string Iso(long ms) => DateTimeOffset.FromUnixTimeMilliseconds(ms).UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", CultureInfo.InvariantCulture);

    static Dictionary<string, object?> Entry(long expires) => new()
    {
        ["id"] = "su", ["grant_ref"] = "g", ["threshold_message"] = "AA", ["expires_at"] = Iso(expires),
    };

    static string ListBody(params Dictionary<string, object?>[] entries) => JsonSerializer.Serialize(new Dictionary<string, object?> { ["stepups"] = entries });

    [Fact]
    public void StepUpOptionDefaultsAreEmpty()
    {
        var o = new StepUpClientOptions();
        Assert.Equal(("", "", "", ""), (o.DashboardUrl, o.InstanceUrl, o.AccountId, o.InstanceId));
    }

    [Fact]
    public void StepUpClientConstructorRefusals()
    {
        Assert.Equal("options", Assert.Throws<ArgumentNullException>(() => new StepUpClient(null!)).ParamName);

        var d = Opts(); d.DashboardUrl = "ftp://x";
        Assert.Equal("DashboardUrl must be an http(s) URL.", Assert.Throws<ArgumentException>(() => new StepUpClient(d)).Message);
        var i = Opts(); i.InstanceUrl = "nope";
        Assert.Equal("InstanceUrl must be an http(s) URL.", Assert.Throws<ArgumentException>(() => new StepUpClient(i)).Message);
        var k = Opts(); k.Key = null;
        Assert.Equal("StepUpClient needs Key, Token and a valid AccountId and InstanceId.", Assert.Throws<ArgumentException>(() => new StepUpClient(k)).Message);
    }

    [Fact]
    public void StepUpClientHttpDefaultAndOverride()
    {
        var field = typeof(StepUpClient).GetField("_http", BindingFlags.NonPublic | BindingFlags.Instance)!;
        var dflt = (HttpClient?)field.GetValue(new StepUpClient(Opts()));
        Assert.NotNull(dflt);
        Assert.Equal(TimeSpan.FromSeconds(30), dflt!.Timeout);
        var mine = new HttpClient();
        Assert.Same(mine, field.GetValue(new StepUpClient(Opts(mine))));
    }

    [Fact]
    public async Task StepUpClockOptionIsUsedAndDefaultsToTheWallClock()
    {
        var past = ListBody(Entry(978_307_200_000)); // 2001
        Assert.Single(await Client(Answer(200, past), now: () => 1000).PendingAsync());
        var o = Opts(Answer(200, past)); o.Now = null;
        Assert.Empty(await new StepUpClient(o).PendingAsync());
    }

    [Fact]
    public async Task StepUpBaseUrlTrailingSlashesAreTrimmed()
    {
        var http = Answer(200, "{\"stepups\":[]}");
        var o = Opts(http); o.DashboardUrl = "https://d.example//"; o.InstanceUrl = "https://i.example/";
        var c = new StepUpClient(o);
        await c.PendingAsync();
        await c.ApproveAsync(Su);
        Assert.Equal("https://d.example/v1/dashboard/accounts/acc/instances/ins/pca/stepups?status=pending", http.Urls[0]);
        Assert.Equal("https://i.example/v1/pca/stepups/s/cosign", http.Urls[1]);
    }

    [Theory]
    [InlineData("a-b", true)]
    [InlineData("a.b", true)]
    [InlineData("a_b", true)]
    [InlineData("A9", true)]
    [InlineData("...", true)]
    [InlineData("a b", false)]
    [InlineData("a/b", false)]
    [InlineData(".", false)]
    [InlineData("..", false)]
    [InlineData("", false)]
    public void StepUpIdCharacters(string id, bool ok)
    {
        var o = Opts(); o.AccountId = id;
        if (ok) _ = new StepUpClient(o);
        else Assert.Throws<ArgumentException>(() => new StepUpClient(o));
    }

    [Fact]
    public void StepUpIdLengthBoundary()
    {
        var o = Opts(); o.InstanceId = new string('a', 200);
        _ = new StepUpClient(o);
        o.InstanceId = new string('a', 201);
        Assert.Throws<ArgumentException>(() => new StepUpClient(o));
    }

    [Fact]
    public async Task StepUpRequestBodyHasNoBom()
    {
        var http = Answer(200, "{}");
        await Client(http).ApproveAsync(Su);
        Assert.Equal((byte)'{', http.Bodies[0][0]);
        Assert.Equal("application/json; charset=utf-8", http.ContentTypes[0]);
    }

    [Fact]
    public async Task StepUpResponseSizeBoundary()
    {
        const int Max = 1 << 20;
        var empty = "{\"stepups\":[]}";
        var exact = Encoding.UTF8.GetBytes(empty + new string(' ', Max - empty.Length));
        Assert.Empty(await Client(new FakeHttp(_ => Task.FromResult(Resp(200, exact)))).PendingAsync());
        var over = Encoding.UTF8.GetBytes(empty + new string(' ', Max - empty.Length + 1));
        var e = await Assert.ThrowsAsync<StepUpException>(() => Client(new FakeHttp(_ => Task.FromResult(Resp(200, over)))).PendingAsync());
        Assert.Equal((StepUpKind.Transport, "The response is too large."), (e.Kind, e.Message));
    }

    [Theory]
    [InlineData(200, true)]
    [InlineData(201, true)]
    [InlineData(299, true)]
    [InlineData(199, false)]
    [InlineData(300, false)]
    public async Task StepUpStatusBoundaries(int status, bool ok)
    {
        var c = Client(Answer(status, "{}"));
        if (ok) { await c.DenyAsync(Su); return; }
        var e = await Assert.ThrowsAsync<StepUpException>(() => c.DenyAsync(Su));
        Assert.Equal((StepUpKind.Api, status, $"HTTP {status}: The request failed."), (e.Kind, e.Status, e.Message));
    }

    [Fact]
    public async Task StepUpAnEmptyErrorListIsTheDefaultMessage()
    {
        var e = await Assert.ThrowsAsync<StepUpException>(() => Client(Answer(500, "{\"errors\":[]}")).DenyAsync(Su));
        Assert.Equal((StepUpKind.Api, "HTTP 500: The request failed."), (e.Kind, e.Message));
    }

    [Fact]
    public async Task StepUpTokenFailure()
    {
        Func<CancellationToken, Task<string>> bad = _ => throw new IOException("x");
        var e = await Assert.ThrowsAsync<StepUpException>(() => Client(Answer(200, "{}"), bad).PendingAsync());
        Assert.Equal((StepUpKind.Transport, "Could not get the dashboard token."), (e.Kind, e.Message));
    }

    [Theory]
    [InlineData("{\"stepups\":3}")]
    [InlineData("{\"nope\":[]}")]
    [InlineData("[]")]
    [InlineData("not json")]
    public async Task StepUpUnreadableList(string body)
    {
        var e = await Assert.ThrowsAsync<StepUpException>(() => Client(Answer(200, body)).PendingAsync());
        Assert.Equal((StepUpKind.Transport, "Unreadable step-up list."), (e.Kind, e.Message));
    }

    [Theory]
    [InlineData("id")]
    [InlineData("grant_ref")]
    [InlineData("threshold_message")]
    [InlineData("expires_at")]
    public async Task StepUpEntryMissingAnyMemberIsUnreadable(string member)
    {
        var entry = Entry(Now + 1000);
        entry.Remove(member);
        var e = await Assert.ThrowsAsync<StepUpException>(() => Client(Answer(200, ListBody(entry))).PendingAsync());
        Assert.Equal((StepUpKind.Transport, "Unreadable step-up entry."), (e.Kind, e.Message));
    }

    [Fact]
    public async Task StepUpExpiryBoundaryAndActionDefaults()
    {
        Assert.Empty(await Client(Answer(200, ListBody(Entry(Now)))).PendingAsync());
        var kept = Assert.Single(await Client(Answer(200, ListBody(Entry(Now + 1)))).PendingAsync());
        Assert.Equal(Now + 1, kept.ExpiresAt);
        Assert.Equal(("", ""), (kept.ActionVerb, kept.ActionResource));

        var partial = Entry(Now + 1);
        partial["action"] = new Dictionary<string, object?> { ["other"] = 1 };
        var p = Assert.Single(await Client(Answer(200, ListBody(partial))).PendingAsync());
        Assert.Equal(("", ""), (p.ActionVerb, p.ActionResource));
    }

    [Fact]
    public async Task StepUpApproveRefusalsAndAnswerShapes()
    {
        var empty = await Assert.ThrowsAsync<StepUpException>(() => Client(Answer(200, "{}")).ApproveAsync(Su with { ThresholdMessageB64u = "" }));
        Assert.Equal((StepUpKind.InvalidThresholdMessage, "The step-up's threshold message is not valid base64url."), (empty.Kind, empty.Message));
        var badId = await Assert.ThrowsAsync<StepUpException>(() => Client(Answer(200, "{}")).ApproveAsync(Su with { Id = "a/b" }));
        Assert.Equal((StepUpKind.InvalidStepUp, "The step-up id is not valid."), (badId.Kind, badId.Message));
        var denyBad = await Assert.ThrowsAsync<StepUpException>(() => Client(Answer(200, "{}")).DenyAsync(Su with { Id = "a/b" }));
        Assert.Equal((StepUpKind.InvalidStepUp, "The step-up id is not valid."), (denyBad.Kind, denyBad.Message));

        Assert.Equal(new StepUpApproval(null, false, 202), await Client(Answer(202, "{}")).ApproveAsync(Su));
        Assert.Equal(new StepUpApproval(null, false, 200), await Client(Answer(200, "{\"status\":3,\"allow\":false}")).ApproveAsync(Su));
        Assert.Equal(new StepUpApproval("x", false, 200), await Client(Answer(200, "{\"status\":\"x\",\"allow\":\"true\"}")).ApproveAsync(Su));
        Assert.Equal(new StepUpApproval("x", true, 200), await Client(Answer(200, "{\"status\":\"x\",\"allow\":true}")).ApproveAsync(Su));
    }

    [Fact]
    public async Task StepUpNoAwaitCapturesTheCallersContext()
    {
        var list = "{\"stepups\":[]}";
        // the token is pending: BearerAsync and PendingAsync suspend on it
        Assert.Equal(0, await PostsDuring(() => Client(Answer(200, list), SlowToken).PendingAsync()));
        // the transport is pending: CallAsync and PendingAsync suspend on it
        Assert.Equal(0, await PostsDuring(() => Client(new FakeHttp(_ => Slow(200, list))).PendingAsync()));
        // only reading the body is pending
        var lazy = new FakeHttp(_ => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new SlowContent(list) }));
        Assert.Equal(0, await PostsDuring(() => Client(lazy).PendingAsync()));
        // approve and deny
        Assert.Equal(0, await PostsDuring(() => Client(new FakeHttp(_ => Slow(200, "{}"))).ApproveAsync(Su)));
        Assert.Equal(0, await PostsDuring(() => Client(Answer(200, "{}"), SlowToken).DenyAsync(Su)));
        Assert.Equal(0, await PostsDuring(() => Client(new FakeHttp(_ => Slow(200, "{}"))).DenyAsync(Su)));
    }

    // ---- CaveatLang ------------------------------------------------------------------------------------------------------

    static readonly SuiteKey Holder = SuiteKey.Ed25519(Ed(0x21));
    static readonly SuiteKey Oracle = SuiteKey.Ed25519(Ed(0x22));

    static JD NeedsDischarge(string id = "kyc") => new()
    {
        ["type"] = "needs_discharge", ["id"] = id, ["issuer"] = "svc", ["issuer_class"] = "workload", ["bind"] = "chain_hop", ["ttl_ms"] = 3_600_000L, ["require"] = new JL(),
    };

    static JD Hop(params object?[] caveats) => Issue.NormJ(new JD { ["holder"] = Holder.Id, ["caveats"] = caveats.ToList() });

    static IEnumerable<KeyValuePair<string, string>> Header(string name, string value) => new[] { KeyValuePair.Create(name, value) };
    static string B64Text(string text) => Pca.B64u(Encoding.UTF8.GetBytes(text));

    [Fact]
    public void WithActionDigestKeepsEveryMember()
    {
        var pins = new[] { new DischargePin("a", "org", "k") };
        var discharges = new JL { "d" };
        var revoked = new[] { "r" };
        var history = new JL { "h" };
        var narrow = new K1Input { Pins = pins, Discharges = discharges, RevokedDischarges = revoked, SpiffeId = "s", History = history, ActionDigest = "old", Narrow = "n" }.WithActionDigest("new");
        Assert.True(narrow.HasNarrow);
        Assert.Equal("n", narrow.Narrow);
        Assert.Same(pins, narrow.Pins);
        Assert.Same(discharges, narrow.Discharges);
        Assert.Same(revoked, narrow.RevokedDischarges);
        Assert.Equal("s", narrow.SpiffeId);
        Assert.Same(history, narrow.History);
        Assert.Equal("new", narrow.ActionDigest);

        var plain = new K1Input { Pins = pins, Discharges = discharges, RevokedDischarges = revoked, SpiffeId = "s", History = history, ActionDigest = "old" }.WithActionDigest("new");
        Assert.False(plain.HasNarrow);
        Assert.Same(pins, plain.Pins);
        Assert.Same(discharges, plain.Discharges);
        Assert.Same(revoked, plain.RevokedDischarges);
        Assert.Equal("s", plain.SpiffeId);
        Assert.Same(history, plain.History);
        Assert.Equal("new", plain.ActionDigest);
    }

    [Fact]
    public void PresentedHeaders()
    {
        Assert.True(CaveatLang.PresentedK1Of(null).Ok);

        var bad = CaveatLang.PresentedK1Of(Header("PCA-Discharges", "a"));
        Assert.Equal((false, "not canonical base64url"), (bad.Ok, bad.Reason));
        var notArray = CaveatLang.PresentedK1Of(Header("PCA-Discharges", B64Text("{}")));
        Assert.Equal((false, "PCA-Discharges must be a JSON array"), (notArray.Ok, notArray.Reason));
    }

    // stricter than presentedK1 in the reference (server/require-pca.ts:513 has no artifact cap of its own): the cap stays
    [Fact]
    public void PresentedHeaderSizeBoundary()
    {
        static string Doc(int bytes) => B64Text("[\"" + new string('a', bytes - 4) + "\"]");
        var exact = CaveatLang.PresentedK1Of(Header("PCA-Discharges", Doc(Pca.MaxArtifactBytes)));
        Assert.True(exact.Ok, exact.Reason);
        Assert.Single(exact.Discharges!);
        var over = CaveatLang.PresentedK1Of(Header("PCA-Discharges", Doc(Pca.MaxArtifactBytes + 1)));
        Assert.Equal((false, Pca.ArtifactSizeReason), (over.Ok, over.Reason));
    }

    [Fact]
    public void MergePresentedMemberByMember()
    {
        var presented = new JL { "p" };
        var own = new JL { "o" };

        // an unreadable presentation presents nothing, whatever it carries
        var unread = CaveatLang.MergePresented(new PresentedK1(false, presented, true, "n", "why"), null);
        Assert.Null(unread.Discharges);
        Assert.False(unread.HasNarrow);
        Assert.Null(unread.Narrow);

        // the request's discharges and narrow block when the verifier supplies none
        var fromRequest = CaveatLang.MergePresented(new PresentedK1(true, presented, true, "n"), new K1Input());
        Assert.Same(presented, fromRequest.Discharges);
        Assert.Equal((true, (object?)"n"), (fromRequest.HasNarrow, fromRequest.Narrow));

        // the verifier's own narrow block wins, a present null included
        Assert.Equal("o", CaveatLang.MergePresented(new PresentedK1(true, null, true, "n"), new K1Input { Narrow = "o" }).Narrow);
        var ownNull = CaveatLang.MergePresented(new PresentedK1(true, null, true, "n"), new K1Input { Narrow = null });
        Assert.True(ownNull.HasNarrow);
        Assert.Null(ownNull.Narrow);

        // without a narrow block every other member of own still survives
        var pins = new[] { new DischargePin("a", "org", "k") };
        var revoked = new[] { "r" };
        var history = new JL { "h" };
        var plain = CaveatLang.MergePresented(new PresentedK1(true, presented), new K1Input { Pins = pins, Discharges = own, RevokedDischarges = revoked, SpiffeId = "s", History = history, ActionDigest = "a" });
        Assert.False(plain.HasNarrow);
        Assert.Same(pins, plain.Pins);
        Assert.Same(own, plain.Discharges);
        Assert.Same(revoked, plain.RevokedDischarges);
        Assert.Equal("s", plain.SpiffeId);
        Assert.Same(history, plain.History);
        Assert.Equal("a", plain.ActionDigest);
    }

    [Fact]
    public void ClockBoundaryIsTheSafeInteger()
    {
        const string Clock = "the verifier clock is not a safe integer (fail closed)";
        var bind = new DischargeBinding("x", null, Pca.MaxSafeInt);
        Assert.Equal("malformed needs_discharge caveat: caveat must be an object", CaveatLang.VerifyDischarge(null, null, bind).Reason);
        Assert.Equal("malformed needs_discharge caveat: caveat must be an object", CaveatLang.VerifyDischarge(null, null, bind with { Now = -Pca.MaxSafeInt }).Reason);
        Assert.Equal(Clock, CaveatLang.VerifyDischarge(null, null, bind with { Now = Pca.MaxSafeInt + 1 }).Reason);
        Assert.Equal(Clock, CaveatLang.VerifyDischarge(null, null, bind with { Now = -Pca.MaxSafeInt - 1 }).Reason);
    }

    [Fact]
    public void FailClosedCatchesNameTheirCause()
    {
        Assert.Equal("caveat error: hostile", CaveatLang.NeedsDischargeError(Hostile("type")));
        Assert.Equal("discharge error: hostile", CaveatLang.DischargeShapeError(Hostile("v")));
        Assert.Equal("narrow error: hostile", CaveatLang.NarrowShapeError(Hostile("v")));
        Assert.Equal("caveat error: hostile", CaveatLang.MaxUsesError(Hostile("type")));
        Assert.Equal("caveat error: hostile", CaveatLang.DeriveError(Hostile("type")));
        Assert.Equal("caveat error: hostile", CaveatLang.SpiffeBoundError(Hostile("type")));
    }

    [Fact]
    public void DischargeActionDigestHashesBothMembers()
    {
        var p = new JD { ["sig"] = "s" };
        // caveat-lang.ts:262 hashCanonical({ d: DISCHARGE_ACTION_DOMAIN, pcactn })
        Assert.Equal(Pca.HashCanonical(new JD { ["d"] = "atlas-pca/discharge-action/v1", ["pcactn"] = p }), CaveatLang.DischargeActionDigest(p));
    }

    [Fact]
    public void AClaimUnknownOpNeverHolds()
    {
        var claims = new JD { ["a"] = "x" };
        Assert.False((bool)Priv(typeof(CaveatLang), "ClaimHolds", new JD { ["claim"] = "a", ["op"] = "bogus", ["value"] = "x" }, claims)!);
        Assert.True((bool)Priv(typeof(CaveatLang), "ClaimHolds", new JD { ["claim"] = "a", ["op"] = "eq", ["value"] = "x" }, claims)!);
    }

    [Fact]
    public void VerifyDischargeThrowingPinsFailClosed()
    {
        var caveat = Issue.NormJ(NeedsDischarge());
        var hop = Hop(caveat);
        var d = Issue.Discharge(Oracle, "kyc", "svc", hop, "chain_hop", null, null, Now, Now + 60_000);
        var v = CaveatLang.VerifyDischarge(d, caveat, new DischargeBinding(Pca.CapHash(hop), new Bomb<DischargePin>(), Now + 1));
        Assert.Equal((false, "discharge error (fail closed): boom"), (v.Ok, v.Reason));
    }

    [Fact]
    public void VerifyNarrowHostileLeafFailsClosed()
    {
        var hop = Hop();
        var n = Issue.Narrow(Holder, hop, new JL { new JD { ["type"] = "note" } }, null, Now, Now + 60_000);
        Assert.True(CaveatLang.VerifyNarrow(n, hop, null, new NarrowBinding(Now + 1)).Ok);
        Assert.Equal("narrow error (fail closed): hostile", CaveatLang.VerifyNarrow(n, Hostile("holder"), null, new NarrowBinding(Now + 1)).Reason);
    }

    [Fact]
    public void AHybridNarrowNeedsTheCommittedPqKey()
    {
        var hybrid = SuiteKey.Create("hybrid-ed25519-ml-dsa-65", Ed(0x23), PqKey.Generate(Pq.Prim.MlDsa65));
        var committed = Issue.NormJ(new JD { ["holder"] = hybrid.Id, ["holder_pq"] = Pca.HolderPqCommitment(hybrid.PqPk!), ["caveats"] = new JL() });
        var ok = Issue.Narrow(hybrid, committed, new JL { new JD { ["type"] = "note" } }, null, Now, Now + 60_000);
        var good = CaveatLang.VerifyNarrow(ok, committed, null, new NarrowBinding(Now + 1));
        Assert.True(good.Ok, good.Reason);

        var other = Issue.NormJ(new JD { ["holder"] = hybrid.Id, ["holder_pq"] = Pca.HolderPqCommitment("another key"), ["caveats"] = new JL() });
        var bad = Issue.Narrow(hybrid, other, new JL { new JD { ["type"] = "note" } }, null, Now, Now + 60_000);
        Assert.Equal("narrow signature invalid", CaveatLang.VerifyNarrow(bad, other, null, new NarrowBinding(Now + 1)).Reason);
    }

    [Fact]
    public void MaxUsesSameIdUnderAnotherHopIsNotADuplicate()
    {
        static JD Uses(string id) => new() { ["type"] = "max_uses", ["id"] = id, ["n"] = new Num("1"), ["until"] = new Num("100") };
        // the two pairs concatenate to the same text without the separator
        var split = new[] { new BoundCaveat(Uses("bc"), 0, "a"), new BoundCaveat(Uses("c"), 0, "ab") };
        Assert.Equal(new UsesVerdict(true, 2), CaveatLang.ReserveMaxUses(new MemoryStateStore(), split, 1));
        var dup = new[] { new BoundCaveat(Uses("c"), 0, "a"), new BoundCaveat(Uses("c"), 1, "a") };
        Assert.Equal(new UsesVerdict(false, 0, "duplicate max_uses id 'c'"), CaveatLang.ReserveMaxUses(new MemoryStateStore(), dup, 1));
    }

    [Fact]
    public void K1MissingPinsMeansNotPinned()
    {
        var caveat = NeedsDischarge();
        var hop = Hop(caveat);
        var d = Issue.Discharge(Oracle, "kyc", "svc", hop, "chain_hop", null, null, Now, Now + 60_000);
        var r = CaveatLang.EvaluateK1(hop, null, new K1Input { Discharges = new JL { d } }, new K1Context(Now + 1));
        Assert.Equal(new[] { "the issuer is not pinned by this verifier" }, r.Reasons);
    }

    [Fact]
    public void K1TheFirstValidDischargeWins()
    {
        var derive = new JD
        {
            ["type"] = "derive", ["id"] = "d1",
            ["defs"] = new JL { new JD { ["name"] = "lvl", ["kind"] = "claim", ["caveat_id"] = "kyc", ["claim"] = "level" } },
            ["check"] = new JD { ["op"] = "eq", ["a"] = new JD { ["ref"] = "lvl" }, ["b"] = new JD { ["const"] = "one" } },
        };
        var hop = Hop(NeedsDischarge(), derive);
        var first = Issue.Discharge(Oracle, "kyc", "svc", hop, "chain_hop", null, new JD { ["level"] = "one" }, Now, Now + 60_000);
        var second = Issue.Discharge(Oracle, "kyc", "svc", hop, "chain_hop", null, new JD { ["level"] = "two" }, Now, Now + 60_000);
        var k1 = new K1Input { Pins = new[] { new DischargePin("svc", "workload", Oracle.Id!) }, Discharges = new JL { first, second } };
        var r = CaveatLang.EvaluateK1(hop, null, k1, new K1Context(Now + 1));
        Assert.True(r.Ok, string.Join("; ", r.Reasons));
    }

    [Fact]
    public void K1ThrowingDischargesFailClosed()
    {
        var r = CaveatLang.EvaluateK1(Hop(NeedsDischarge()), null, new K1Input { Discharges = new Bomb<object?>() }, new K1Context(Now));
        Assert.False(r.Ok);
        Assert.Equal(new[] { "<malformed>" }, r.Failed);
        Assert.Equal(new[] { "caveat language error (fail closed): boom" }, r.Reasons);
    }

    [Fact]
    public void EvaluateCaveatsK1NonIntegerClockStillRunsTheStockCaveats()
    {
        var grant = Issue.NormJ(new JD { ["caveats"] = new JL { new JD { ["type"] = "expires", ["at"] = 5L } } });
        var r = CaveatLang.EvaluateCaveatsK1(grant, null, new K1Input(), new JD { ["now"] = "x" });
        Assert.False(r.Allow);
        Assert.Equal(new[] { "<malformed>", "expires" }, r.Failed);
    }

    [Fact]
    public void EvaluateCaveatsK1PassesTheActionToPredicates()
    {
        var grant = Issue.NormJ(new JD { ["caveats"] = new JL { new JD { ["type"] = "predicates", ["allow"] = new JL { new JD { ["verb"] = "pay", ["resource"] = "*" } } } } });
        var action = new JD { ["verb"] = "pay", ["resource"] = "r" };
        var ok = CaveatLang.EvaluateCaveatsK1(grant, null, new K1Input(), new JD { ["now"] = new Num("1000"), ["action"] = action });
        Assert.True(ok.Allow, string.Join("; ", ok.Failed));
        Assert.Empty(ok.Failed);
        var none = CaveatLang.EvaluateCaveatsK1(grant, null, new K1Input(), new JD { ["now"] = new Num("1000") });
        Assert.False(none.Allow);
        Assert.Equal(new[] { "predicates" }, none.Failed);
    }

    [Fact]
    public void EvaluateCaveatsK1HostileContextFailsClosed()
    {
        var r = CaveatLang.EvaluateCaveatsK1(Hop(), null, new K1Input(), Hostile("now"));
        Assert.False(r.Allow);
        Assert.Equal(new[] { "<malformed>" }, r.Failed);
    }

    // ---- Operations ------------------------------------------------------------------------------------------------------

    sealed class ScriptStore : IOperationStore
    {
        public Func<OperationRecord, (bool, OperationRecord?)> OnCreate = _ => (true, (OperationRecord?)null);
        public Func<string, OperationRecord?> OnGet = _ => null;
        public Func<string, string, OperationRecord, bool> OnTransition = (_, _, _) => false;
        public (bool Created, OperationRecord? Existing) Create(OperationRecord record) => OnCreate(record);
        public OperationRecord? Get(string id) => OnGet(id);
        public bool Transition(string id, string from, OperationRecord next) => OnTransition(id, from, next);
    }

    sealed class NoopKv : IAtomicKv
    {
        public string? Get(string key) => null;
        public void Update(string key, Func<string?, string?> fn) { }
    }

    static OperationRecord Rec(string id, string state, long startedAt = 0) => new(id, state, "v", "r", "p", "reversible", startedAt);

    static AuthorizeResult Az(string id = "op1") => new()
    {
        Allow = true, Status = 200, Pcactn = new JD { ["action"] = new JD { ["reversibility_class"] = "reversible" } },
        Operation = new AuthorizedOperation("v", "r", "p", id),
    };

    static async Task<object?> SlowFn(ExecutionHandle _)
    {
        await Task.Delay(5).ConfigureAwait(false);
        return 1;
    }

    static async Task<RecheckResult> SlowRecheck(ExecutionHandle _)
    {
        await Task.Delay(5).ConfigureAwait(false);
        return RecheckResult.Pass;
    }

    [Fact]
    public void RecordResultMemberRules()
    {
        Assert.Equal("x", (Rec("i", OperationStates.Failed) with { Result = "x" }).ToJson()["result"]);
        var committed = Rec("i", OperationStates.Committed).ToJson();
        Assert.True(committed.ContainsKey("result"));
        Assert.Null(committed["result"]);
        Assert.False(Rec("i", OperationStates.Pending).ToJson().ContainsKey("result"));
    }

    [Fact]
    public void RecordFromJsonReadsEveryMemberAndDefaults()
    {
        var full = OperationRecord.FromJson(new JD
        {
            ["id"] = "i", ["state"] = "failed", ["verb"] = "ve", ["resource"] = "re", ["params_digest"] = "pd", ["reversibility"] = "reversible", ["startedAt"] = new Num("1"),
            ["executingAt"] = new Num("2"), ["finishedAt"] = new Num("3"), ["result"] = "res", ["error"] = "err",
        })!;
        Assert.Equal(("i", "failed", "ve", "re", "pd", "reversible", 1L), (full.Id, full.State, full.Verb, full.Resource, full.ParamsDigest, full.Reversibility, full.StartedAt));
        Assert.Equal(2L, full.ExecutingAt);
        Assert.Equal(3L, full.FinishedAt);
        Assert.Equal("res", full.Result);
        Assert.Equal("err", full.Error);

        var bare = OperationRecord.FromJson(new JD { ["id"] = "i", ["state"] = "failed" })!;
        Assert.Equal(("", "", "", "irreversible", 0L), (bare.Verb, bare.Resource, bare.ParamsDigest, bare.Reversibility, bare.StartedAt));
        Assert.Null(bare.Result);
        Assert.Null(bare.Error);
    }

    [Fact]
    public void ListOpenIsOrderedById()
    {
        var s = new MemoryOperationStore();
        s.Create(Rec("b", OperationStates.Pending));
        s.Create(Rec("a", OperationStates.Executing));
        s.Create(Rec("c", OperationStates.Committed));
        Assert.Equal(new[] { "a", "b" }, s.ListOpen().Select(r => r.Id));
    }

    [Fact]
    public void KvOperationStorePrefix()
    {
        Assert.Equal("kv", Assert.Throws<ArgumentNullException>(() => new KvOperationStore(null!)).ParamName);
        foreach (var (prefix, key) in new[] { ((string?)null, "pca-op:x"), ("", "pca-op:x"), ("p:", "p:x") })
        {
            var kv = new MemoryAtomicKv();
            Assert.True(new KvOperationStore(kv, prefix).Create(Rec("x", OperationStates.Pending)).Created);
            Assert.NotNull(kv.Get(key));
        }
    }

    [Fact]
    public void KvTransitionIsFalseWhenTheCallbackNeverRan()
    {
        Assert.False(new KvOperationStore(new NoopKv()).Transition("x", OperationStates.Pending, Rec("x", OperationStates.Executing)));
    }

    [Fact]
    public void ExecuteOutcomeDefaultStatusIsRefused()
    {
        Assert.Equal("refused", new ExecuteOutcome().Status);
    }

    [Fact]
    public void APendingRecordAgesFromItsStartNotItsExecutingMark()
    {
        var s = new MemoryOperationStore();
        s.Create(Rec("x", OperationStates.Pending) with { ExecutingAt = 1000 });
        Assert.Equal(OperationStates.Aborted, Pca.RecoverOperation(s, "x", 500, () => 1100)!.State);
    }

    [Fact]
    public void SettleAnswersFromTheStoreThenFromItsOwnTransition()
    {
        int gets = 0;
        var raced = new ScriptStore { OnGet = id => ++gets == 1 ? Rec(id, OperationStates.Pending) : Rec(id, OperationStates.Committed) };
        Assert.Equal(OperationStates.Committed, Pca.RecoverOperation(raced, "x", 500, () => 1000)!.State);

        int gets2 = 0;
        var gone = new ScriptStore { OnGet = id => ++gets2 == 1 ? Rec(id, OperationStates.Pending) : null };
        Assert.Equal(OperationStates.Aborted, Pca.RecoverOperation(gone, "x", 500, () => 1000)!.State);
    }

    [Fact]
    public void AnswerFromRecordDefaultsAndReplayed()
    {
        var s = new MemoryOperationStore();
        ExecuteOutcome A(string state) => Pca.AnswerFromRecord(s, Rec("x", state), 0, 1000);

        var failed = A(OperationStates.Failed);
        Assert.Equal(("failed", "x", "failed", true), (failed.Status, failed.OperationId, failed.Error, failed.Replayed));
        var aborted = A(OperationStates.Aborted);
        Assert.Equal(("aborted", "x", "aborted", true), (aborted.Status, aborted.OperationId, aborted.Reason, aborted.Replayed));
        var uncertain = A(OperationStates.Uncertain);
        Assert.Equal(("uncertain", "x", "outcome unknown", true), (uncertain.Status, uncertain.OperationId, uncertain.Reason, uncertain.Replayed));
        foreach (var open in new[] { OperationStates.Pending, OperationStates.Executing })
        {
            var p = A(open);
            Assert.Equal(("pending", "x", true), (p.Status, p.OperationId, p.Replayed));
        }
        var unknown = A("weird");
        Assert.Equal(("uncertain", "x", "unknown record state 'weird'", true), (unknown.Status, unknown.OperationId, unknown.Reason, unknown.Replayed));
    }

    [Fact]
    public void CommitAfterARecoverySettledTheRunLeavesUncertainForCommitted()
    {
        var s = new MemoryOperationStore();
        var o = Pca.ExecuteAuthorized(Az("u"), h =>
        {
            Assert.Equal(OperationStates.Uncertain, Pca.RecoverOperation(s, h.IdempotencyKey, 0, () => 10_000)!.State);
            return "done";
        }, new ExecuteOptions { Store = s, Now = () => 1 });
        Assert.Equal(("committed", true, (object?)"done"), (o.Status, o.Recorded, o.Result));
        Assert.Equal(OperationStates.Committed, s.Get("u")!.State);
    }

    [Fact]
    public void AnAbortedClaimNeverLeavesUncertain()
    {
        // the abort finds the record settled as uncertain by a recovery: it does not overwrite it
        var moved = new List<string>();
        var s = new ScriptStore
        {
            OnTransition = (_, from, _) => { moved.Add(from); return false; },
            OnGet = id => Rec(id, OperationStates.Uncertain),
        };
        var o = Pca.ExecuteAuthorized(Az("u"), _ => throw new InvalidOperationException("must not run"),
            new ExecuteOptions { Store = s, Now = () => 1, RecheckFor = "always", Recheck = _ => new RecheckResult(false, "no") });
        Assert.Equal(new[] { OperationStates.Pending }, moved);
        Assert.Equal(("uncertain", true), (o.Status, o.Replayed));
    }

    [Fact]
    public void AnswerCurrentRecordGoneOrPresent()
    {
        Func<ExecutionHandle, object?> never = _ => throw new InvalidOperationException("must not run");
        var gone = Pca.ExecuteAuthorized(Az("x"), never, new ExecuteOptions { Store = new ScriptStore(), Now = () => 1 });
        Assert.Equal(("uncertain", "x", "the operation record disappeared", true), (gone.Status, gone.OperationId, gone.Reason, gone.Replayed));

        var present = Pca.ExecuteAuthorized(Az("x"), never, new ExecuteOptions { Store = new ScriptStore { OnGet = id => Rec(id, OperationStates.Committed) with { Result = "r" } }, Now = () => 1 });
        Assert.Equal(("committed", "x", (object?)"r", true), (present.Status, present.OperationId, present.Result, present.Replayed));
    }

    [Fact]
    public void ExecuteErrorsAndRefusals()
    {
        Func<ExecutionHandle, object?> never = _ => throw new InvalidOperationException("must not run");
        var thrown = Pca.ExecuteAuthorized(Az(), never, new ExecuteOptions { Store = new MemoryOperationStore(), Now = () => throw new InvalidOperationException("boom") });
        Assert.Equal(("refused", "executeAuthorized: error (fail closed): boom"), (thrown.Status, thrown.Reason));

        var az = new AuthorizeResult { Allow = true, Status = 200, Pcactn = new JD(), Operation = new AuthorizedOperation("v", "r", "p", "") };
        var noId = Pca.ExecuteAuthorized(az, never, new ExecuteOptions { Store = new MemoryOperationStore(), Now = () => 1 });
        Assert.Equal(("refused", "executeAuthorized: the authorization did not allow an operation"), (noId.Status, noId.Reason));

        var msg = Assert.Throws<InvalidOperationException>(() => Pca.RecoverOperations(new ScriptStore())).Message;
        Assert.Equal("RecoverOperations: the store has no ListOpen (recover by id with RecoverOperation)", msg);
    }

    [Fact]
    public void RecheckReasonFallback()
    {
        ExecuteOutcome Run(string id, Func<ExecutionHandle, RecheckResult> rc) =>
            Pca.ExecuteAuthorized(Az(id), _ => throw new InvalidOperationException("must not run"), new ExecuteOptions { Store = new MemoryOperationStore(), Now = () => 1, RecheckFor = "always", Recheck = rc });
        Assert.Equal(("aborted", "recheck: refused"), (Run("a", _ => new RecheckResult(false)).Status, Run("a", _ => new RecheckResult(false)).Reason));
        Assert.Equal("recheck: refused", Run("b", _ => new RecheckResult(false, "")).Reason);
        Assert.Equal("recheck: refused", Run("c", _ => null!).Reason);
        Assert.Equal("recheck: no", Run("d", _ => new RecheckResult(false, "no")).Reason);
    }

    [Fact]
    public void ACommitTheStoreCannotRecordIsNotRecorded()
    {
        var s = new ScriptStore
        {
            OnTransition = (_, from, _) => from == OperationStates.Pending ? true : throw new IOException("down"),
        };
        var o = Pca.ExecuteAuthorized(Az(), _ => "r", new ExecuteOptions { Store = s, Now = () => 1 });
        Assert.Equal(("committed", false, (object?)"r"), (o.Status, o.Recorded, o.Result));
    }

    [Fact]
    public async Task ExecuteNoAwaitCapturesTheCallersContext()
    {
        var fnPending = new ExecuteOptions { Store = new MemoryOperationStore(), Now = () => 1 };
        Assert.Equal(0, await PostsDuring(() => Pca.ExecuteAuthorizedAsync(Az("f"), SlowFn, fnPending)));
        Assert.Equal(OperationStates.Committed, fnPending.Store!.Get("f")!.State);

        var recheckPending = new ExecuteOptions { Store = new MemoryOperationStore(), Now = () => 1, RecheckFor = "always", RecheckAsync = SlowRecheck };
        Assert.Equal(0, await PostsDuring(() => Pca.ExecuteAuthorizedAsync(Az("r"), _ => Task.FromResult<object?>(1), recheckPending)));
        Assert.Equal(OperationStates.Committed, recheckPending.Store!.Get("r")!.State);
    }

    // ---- RevocationFreshness ---------------------------------------------------------------------------------------------

    const string Positive = " must be a positive number of milliseconds";
    static readonly byte[] GuardianSeed = Enumerable.Repeat((byte)0x31, 32).ToArray();
    static readonly string Guardian = EdKey.FromSeed(GuardianSeed).Id;

    [Fact]
    public void PolicyErrorOrderAndNames()
    {
        Assert.Equal("maxRevocationAgeMs" + Positive, new RevocationStalenessPolicy(-1, new StalenessWindows(-1, -1, -1)).Error());
        Assert.Equal("staleness.irreversible" + Positive, new RevocationStalenessPolicy(Staleness: new StalenessWindows(-1, -1, -1)).Error());
        Assert.Equal("staleness.rate_limited" + Positive, new RevocationStalenessPolicy(Staleness: new StalenessWindows(Costly: -1, RateLimited: -1)).Error());
        Assert.Equal("staleness.costly" + Positive, new RevocationStalenessPolicy(Staleness: new StalenessWindows(Costly: -1)).Error());
        Assert.Null(new RevocationStalenessPolicy(1, new StalenessWindows(1, 1, 1)).Error());
    }

    // revocation.ts:279-280 validates both names: a bad old name next to a good new one is still a bad policy
    [Fact]
    public void PolicyFromJsonKeepsBothWindowNames()
    {
        var both = RevocationStalenessPolicy.FromJson(new JD
        {
            ["maxRevocationAgeMs"] = new Num("40"), ["allowUnsignedRootForIrreversible"] = true,
            ["staleness"] = new JD { ["irreversible"] = new Num("30"), ["costly"] = new Num("20"), ["rate_limited"] = new Num("10") },
        });
        Assert.Equal(40, both.MaxRevocationAgeMs);
        Assert.Equal(new StalenessWindows(30, 20, 10), both.Staleness);
        Assert.True(both.AllowUnsignedRootForIrreversible);

        Assert.False(RevocationStalenessPolicy.FromJson(new JD()).AllowUnsignedRootForIrreversible);
        Assert.False(RevocationStalenessPolicy.FromJson(new JD { ["allowUnsignedRootForIrreversible"] = "true" }).AllowUnsignedRootForIrreversible);

        Assert.Equal("staleness.costly" + Positive, RevocationStalenessPolicy.FromJson(new JD { ["staleness"] = new JD { ["rate_limited"] = new Num("10"), ["costly"] = "x" } }).Error());
        Assert.Equal("staleness.rate_limited" + Positive, RevocationStalenessPolicy.FromJson(new JD { ["staleness"] = new JD { ["rate_limited"] = new Num("-1"), ["costly"] = new Num("10") } }).Error());
    }

    // revocation.ts:296: rate_limited ?? costly ?? max, capped by max
    [Fact]
    public void MaxAgeRateLimitedWinsOverCostly()
    {
        RevocationStalenessPolicy P(double? costly, double? rate) => new(1000, new StalenessWindows(Costly: costly, RateLimited: rate));
        foreach (var cls in new[] { "rate_limited", "costly" })
        {
            Assert.Equal(70, RevocationFreshness.MaxAgeMs(P(90, 70), cls));
            Assert.Equal(90, RevocationFreshness.MaxAgeMs(P(90, null), cls));
            Assert.Equal(1000, RevocationFreshness.MaxAgeMs(P(null, null), cls));
            Assert.Equal(1000, RevocationFreshness.MaxAgeMs(P(null, 2000), cls));
        }
    }

    [Fact]
    public void OptionDefaultsAreEmpty()
    {
        Assert.Equal("", new EpochCheckOptions().GuardianPublic);
        Assert.Equal("", new RevocationGateInput().GrantRef);
    }

    [Fact]
    public void CheckAgeMessages()
    {
        Assert.Equal("revocation state age is unknown (unverifiable revocation state)", RevocationFreshness.CheckAge(null, 0, 1, null!).Reason);
        Assert.Equal("revocation state is 1000 ms old, over the verifier's maximum of NaN ms (stale revocation state)", RevocationFreshness.CheckAge(1000, 2000, double.NaN).Reason);
        Assert.Equal("revocation state is 1000 ms old, over the verifier's maximum of -Infinity ms (stale revocation state)", RevocationFreshness.CheckAge(1000, 2000, double.NegativeInfinity).Reason);
        Assert.Equal("revocation state is Infinity ms old, over the verifier's maximum of 1 ms (stale revocation state)", RevocationFreshness.CheckAge(-double.MaxValue, double.MaxValue, 1).Reason);
    }

    [Fact]
    public void CheckEpochErrors()
    {
        var ep = RevocationFreshness.SignEpoch(GuardianSeed, new RevocationEpochBody("ins", "g", 5, 0, "root", 1000, 2000));
        var o = new EpochCheckOptions { GuardianPublic = Guardian, Now = 1500 };
        Assert.True(RevocationFreshness.CheckEpoch(ep, o).Ok);
        ep.Remove("root");
        Assert.Equal("revocation epoch check error", RevocationFreshness.CheckEpoch(ep, o).Reason);
        Assert.Equal("revocation epoch check error", RevocationFreshness.CheckEpoch(Hostile("guardian"), o).Reason);
        Assert.Equal("SignEpoch: the guardian seed must be 32 bytes", Assert.Throws<ArgumentException>(() => RevocationFreshness.SignEpoch(new byte[31], new RevocationEpochBody("i", "g", 0, 0, "r", 0, 1))).Message);
    }

    [Fact]
    public void GateMessages()
    {
        Assert.Equal("revocation staleness policy invalid: maxRevocationAgeMs" + Positive, RevocationFreshness.Gate(new RevocationGateInput { Policy = new RevocationStalenessPolicy(0) }).Reason);
        Assert.Equal("no revocation root", RevocationFreshness.Gate(new RevocationGateInput()).Reason);
        var thrown = RevocationFreshness.Gate(new RevocationGateInput { Root = "r", Ids = new[] { "a" }, ProofFor = _ => throw new InvalidOperationException("x") });
        Assert.Equal("revocation state check error (fail closed)", thrown.Reason);
    }

    static readonly RevocationStalenessPolicy Fresh = new(300_000);

    static JD PcaOf(string cls) => new() { ["action"] = new JD { ["reversibility_class"] = cls } };

    static string? Gate(JD ctx, JD p, RevocationState? state, bool allowUnsigned = false) =>
        RevocationFreshness.ForAuthorize(new AuthorizeInput { RevocationStaleness = Fresh with { AllowUnsignedRootForIrreversible = allowUnsigned }, GuardianPublic = Guardian }, ctx, p, state, 1500);

    [Fact]
    public void ForAuthorizeWithoutState()
    {
        const string NoEpoch = "no signed revocation epoch";
        const string NoVerifiable = "no verifiable (guardian-signed) revocation state for an irreversible action";
        // the signed class decides (no cap_chain in this PCActn: no ids)
        Assert.Equal(NoEpoch, Gate(new JD(), PcaOf("reversible"), null));
        Assert.Equal(NoVerifiable, Gate(new JD(), PcaOf("irreversible"), null));
        Assert.Equal(NoVerifiable, Gate(new JD(), new JD(), null));
        // the server's class raises it
        Assert.Equal(NoVerifiable, Gate(new JD { ["reversibility_class"] = "irreversible" }, PcaOf("reversible"), null));
        // the opt-out
        Assert.Equal(NoEpoch, Gate(new JD(), PcaOf("irreversible"), null, allowUnsigned: true));
        // an empty state is no state
        Assert.Equal(NoEpoch, Gate(new JD(), PcaOf("reversible"), new RevocationState()));
    }

    [Fact]
    public void ForAuthorizeWithAnEpoch()
    {
        // a PCActn without grant_ref is bound to the empty grant reference
        var ep = RevocationFreshness.SignEpoch(GuardianSeed, new RevocationEpochBody("ins", "", 5, 0, "root", 1000, 400_000));
        Assert.Null(Gate(new JD(), PcaOf("reversible"), new RevocationState(ep)));
        var stale = PcaOf("reversible");
        stale["freshness"] = new JD { ["epoch"] = new Num("4") };
        Assert.Equal("PCActn freshness.epoch 4 predates the revocation epoch 5", Gate(new JD(), stale, new RevocationState(ep)));
    }

    // ---- ReadVault -------------------------------------------------------------------------------------------------------

    static readonly EdKey Rp = Ed(0x41);

    static JD ReadGrant() => Issue.SignReadGrant(Rp, new JD
    {
        ["v"] = 1L, ["id"] = "rg", ["principal"] = Rp.Id, ["issued_at"] = 1000L, ["expires_at"] = 2000L, ["caps"] = new JD(),
        ["reads"] = new JL
        {
            new JD
            {
                ["verb"] = "c.get", ["resource_prefix"] = "c/", ["purposes"] = new JL { "s" }, ["modes"] = new JD { ["ref"] = "token", ["h"] = "hash" }, ["default_mode"] = "drop",
            },
        },
        ["sinks"] = new JD { ["pay"] = new JD { ["allow"] = new JL { "ref" }, ["escalate"] = new JL() } },
    });

    static ReadInput Read(JD grant) => new(grant, Rp.Id, new Num("1500"), "c.get", "c/1", "s",
        new JD { ["fields"] = new JD { ["a"] = "ref", ["b"] = "h" }, ["required"] = new JL() }, new JD { ["a"] = "c_77", ["b"] = "secret" }, new JD(), "a-per-read-secret-salt", new JD());

    sealed class Recording : IVaultStore
    {
        public readonly List<(string Token, VaultEntry Entry)> Puts = new();
        public void Put(string token, VaultEntry entry) => Puts.Add((token, entry));
        public VaultEntry? Get(string token) => null;
    }

    sealed class BrokenVault : IVaultStore
    {
        public void Put(string token, VaultEntry entry) => throw new IOException("down");
        public VaultEntry? Get(string token) => throw new IOException("down");
    }

    [Fact]
    public void OnlyTokensReachTheVault()
    {
        var g = ReadGrant();
        var store = new Recording();
        var r = ReadVault.RedactReadWithVault(Read(g), store);
        Assert.Equal("allow", r.Decision);
        var (token, e) = Assert.Single(store.Puts);
        Assert.Equal(r.View["a"], token);
        Assert.Equal(("ref", (object?)"c_77", ReadSide.ReadGrantDigest((JD)g["body"]!), 2000L), (e.Cls, e.Value, e.Grant, e.Exp));
    }

    [Fact]
    public void ABrokenVaultFailsClosed()
    {
        var g = ReadGrant();
        var red = ReadVault.RedactReadWithVault(Read(g), new BrokenVault());
        Assert.Equal(("deny", "bad_request"), (red.Decision, red.Code));
        var det = ReadVault.Detokenize(new DetokenizeInput(g, Rp.Id, new Num("1500"), "pay", "t", new BrokenVault()));
        Assert.Equal(("deny", "bad_request"), (det.Decision, det.Code));
    }

    [Theory]
    [InlineData(999, 3000, "deny", "not_yet")]
    [InlineData(1000, 3000, "allow", null)]     // issued_at is inclusive
    [InlineData(1999, 3000, "allow", null)]
    [InlineData(2000, 3000, "deny", "expired")] // expires_at is exclusive, whatever the entry says
    [InlineData(1500, 1500, "deny", "expired")] // so is the entry's own horizon
    [InlineData(1500, 1501, "allow", null)]
    public void DetokenizeTimeBoundaries(long now, long entryExp, string decision, string? code)
    {
        var g = ReadGrant();
        var store = new MemoryVault();
        store.Put("t", new VaultEntry("ref", "v", ReadSide.ReadGrantDigest((JD)g["body"]!), entryExp));
        var r = ReadVault.Detokenize(new DetokenizeInput(g, Rp.Id, new Num(now.ToString(CultureInfo.InvariantCulture)), "pay", "t", store));
        Assert.Equal((decision, code), (r.Decision, r.Code));
    }

    static JD AggregateGrant(long eps, bool dp) => Issue.SignAggregateGrant(Rp, new JD
    {
        ["v"] = 1L, ["id"] = "ag", ["principal"] = Rp.Id, ["issued_at"] = 1000L, ["expires_at"] = 2000L, ["epsilon_budget_micro"] = 1_000_000L, ["max_queries"] = 10L,
        ["rules"] = new JL
        {
            new JD
            {
                ["verb"] = "o.s", ["resource_prefix"] = "o/", ["purposes"] = new JL { "a" }, ["fns"] = new JL { "count", "sum" }, ["min_group"] = 1L, ["clamp"] = 100L, ["epsilon_micro"] = eps, ["dp"] = dp,
            },
        },
    });

    static AggregateResult Aggregate(JD grant, JL values, string noise) =>
        ReadVault.AggregateRead(new AggregateInput(grant, Rp.Id, new Num("1500"), "o.s", "o/1", "a", "count", values, "a-per-read-secret-salt", noise, ReadVault.EmptyAggregateState()));

    // read-vault.ts:126 values.length > 1_000_000
    [Fact]
    public void AggregateRowCountBoundary()
    {
        var g = AggregateGrant(0, false);
        var one = new Num("1");
        var exact = Aggregate(g, Enumerable.Repeat<object?>(one, 1_000_000).ToList(), "seeded");
        Assert.Equal(("allow", (long?)1_000_000), (exact.Decision, exact.Value));
        var over = Aggregate(g, Enumerable.Repeat<object?>(one, 1_000_001).ToList(), "seeded");
        Assert.Equal(("deny", "bad_request"), (over.Decision, over.Code));
    }

    [Fact]
    public void SecureNoiseIsNotTheSeededStream()
    {
        var g = AggregateGrant(1000, true);
        var values = new JL { new Num("1"), new Num("2"), new Num("3") };
        var seeded = Enumerable.Range(0, 2).Select(_ => Aggregate(g, values, "seeded").Value).Distinct().ToList();
        Assert.Single(seeded);
        var secure = Enumerable.Range(0, 12).Select(_ => Aggregate(g, values, "secure").Value).Distinct().ToList();
        Assert.True(secure.Count > 1, "12 secure draws of scale 1000 were all equal");
    }

    const long Two48 = 1L << 48;

    // the raw stream, recomputed from its definition (read-vault.ts: block i = SHA-256 of canonical {d, seed, i}; five 48-bit values each)
    static IEnumerable<long> Raw(string seed)
    {
        for (long block = 0; ; block++)
        {
            var bytes = Pca.B64uDecode(Pca.HashCanonical(new JD { ["d"] = "atlas-pca/dp-stream/v1", ["seed"] = seed, ["i"] = block }), 32)!;
            for (var k = 0; k < 5; k++)
            {
                long v = 0;
                for (var j = 0; j < 6; j++) v = v * 256 + bytes[k * 6 + j];
                yield return v;
            }
        }
    }

    [Fact]
    public void UniformBounds()
    {
        var d = ReadVault.SeededDraws("x");
        Assert.StartsWith("uniform: bad bound", Assert.Throws<ArgumentOutOfRangeException>(() => d.Uniform(0)).Message);
        Assert.StartsWith("uniform: bad bound", Assert.Throws<ArgumentOutOfRangeException>(() => d.Uniform((1L << 47) + 1)).Message);
        Assert.InRange(d.Uniform(1L << 47), 0, (1L << 47) - 1);
    }

    [Fact]
    public void UniformRejectsTheModuloTail()
    {
        // just above 2^48 / 3: limit = 2n, so a third of the raw draws is rejected
        const long N = 93_824_992_236_886;
        long limit = Two48 - Two48 % N;
        var d = ReadVault.SeededDraws("rejection");
        using var raw = Raw("rejection").GetEnumerator();
        int rejected = 0;
        for (var i = 0; i < 100; i++)
        {
            long r;
            while (true)
            {
                raw.MoveNext();
                r = raw.Current;
                if (r < limit) break;
                rejected++;
            }
            Assert.Equal(r % N, d.Uniform(N));
        }
        Assert.True(rejected > 0);
    }

    [Fact]
    public void UniformRejectsADrawEqualToTheLimit()
    {
        // a seed whose first draw r0 is even and above 2/3 of 2^48: for n = r0 / 2 the limit is exactly r0
        for (var i = 0; ; i++)
        {
            var seed = "limit-" + i.ToString(CultureInfo.InvariantCulture);
            var firsts = Raw(seed).Take(2).ToArray();
            long r0 = firsts[0], r1 = firsts[1];
            if (r0 % 2 != 0 || r0 <= Two48 / 3 * 2 + 2) continue;
            long n = r0 / 2;
            if (Two48 - Two48 % n != r0 || r1 >= r0 || r1 % n == 0) continue;
            Assert.Equal(r1 % n, ReadVault.SeededDraws(seed).Uniform(n));
            return;
        }
    }

    [Fact]
    public void UniformGivesUpAfterExactlyMaxSteps()
    {
        // a stream of nothing but rejected draws: position 6 is past the block refill at 5, so no refill happens
        const int Steps = 100_000;
        var d = ReadVault.SeededDraws("x");
        var t = d.GetType();
        var buf = new long[Steps + 16];
        Array.Fill(buf, long.MaxValue);
        t.GetField("_buf", BindingFlags.NonPublic | BindingFlags.Instance)!.SetValue(d, buf);
        var pos = t.GetField("_pos", BindingFlags.NonPublic | BindingFlags.Instance)!;
        pos.SetValue(d, 6);
        Assert.Equal("uniform: no draw", Assert.Throws<InvalidOperationException>(() => d.Uniform(1L << 47)).Message);
        Assert.Equal(6 + Steps, (int)pos.GetValue(d)!);
    }

    sealed class FakeDraws : IDraws
    {
        readonly Func<long, long, long> _f;
        readonly long _runaway;
        public long Calls;
        public FakeDraws(Func<long, long, long> f, long runaway) { _f = f; _runaway = runaway; }
        public long Uniform(long n)
        {
            if (Calls >= _runaway) throw new InvalidOperationException("runaway");
            return _f(Calls++, n);
        }
    }

    [Fact]
    public void BernoulliGivesUpAfterExactlyMaxSteps()
    {
        // u = 1, then every Bernoulli(1 / (t k)) succeeds
        var d = new FakeDraws((i, _) => i == 0 ? 1 : 0, 200_000);
        Assert.Equal("bernoulli: no termination", Assert.Throws<InvalidOperationException>(() => ReadVault.DiscreteLaplace(d, 1, 1000)).Message);
        Assert.Equal(1 + 100_000, d.Calls);
    }

    [Fact]
    public void LaplaceGivesUpOnVAfterExactlyMaxSteps()
    {
        // u = 0 is accepted; every Bernoulli(exp(-1)) step answers true on its first draw (Uniform(1) = 1 is not below 1)
        var d = new FakeDraws((_, n) => n == 1 ? 1 : 0, 200_000);
        Assert.Equal("laplace: no termination", Assert.Throws<InvalidOperationException>(() => ReadVault.DiscreteLaplace(d, 1, 2)).Message);
        Assert.Equal(1 + 1 + 100_001, d.Calls);
    }

    [Fact]
    public void LaplaceGivesUpOnSamplesAfterExactlyMaxSteps()
    {
        // each round: u = 1; the first Bernoulli succeeds, the second fails, so exp(-u/t) answers false and the round restarts
        var d = new FakeDraws((i, _) => i % 3 == 1 ? 0 : 1, 400_000);
        Assert.Equal("laplace: no sample", Assert.Throws<InvalidOperationException>(() => ReadVault.DiscreteLaplace(d, 1, 1000)).Message);
        Assert.Equal(3 * 100_000, d.Calls);
    }

    // ---- ArgProvenance ---------------------------------------------------------------------------------------------------

    static readonly SuiteKey Mediator = SuiteKey.Ed25519(Ed(0x51));
    static readonly string Session = Pca.B64u(new byte[32]);

    static ProvenanceRecorder Recorder() => new("m", "k1", Mediator, Session, () => 1000);

    sealed class Opaque
    {
        readonly string? _text;
        public Opaque(string? text) => _text = text;
        public override string? ToString() => _text;
    }

    [Fact]
    public void OriginLevelsAndJoin()
    {
        string Level(string o) => (string)Priv(typeof(ArgProvenance), "OriginLevel", o)!;
        Assert.Equal(("trusted", "tool", "tool", "web", "agent"), (Level("principal"), Level("tool"), Level("retrieval"), Level("web"), Level("action")));
        string Join(string a, string b) => (string)Priv(typeof(ArgProvenance), "Join", a, b)!;
        Assert.Equal("web", Join("web", "tool"));
        Assert.Equal("web", Join("tool", "web"));
        Assert.Equal("x", Join("x", "y")); // arg-provenance.ts:68: on a tie the first wins
    }

    [Fact]
    public void BadChainIsUnverifiedAtTheTop()
    {
        var bad = Priv(typeof(ArgProvenance), "Bad", "c", "r")!;
        var t = bad.GetType();
        Assert.False((bool)t.GetProperty("Verified")!.GetValue(bad)!);
        Assert.Equal("agent", t.GetProperty("Context")!.GetValue(bad));
    }

    [Fact]
    public void WordBoundaryCharacters()
    {
        foreach (var c in new[] { 'A', 'Z', 'a', 'z', '0', '9', '_', '\u0080' })
            Assert.False(ArgProvenance.OccursAsToken(c + "12", "12"), c.ToString());
        foreach (var c in new[] { '@', '[', '`', '{', '/', ':', '\u007f' })
            Assert.True(ArgProvenance.OccursAsToken(c + "12", "12"), c.ToString());
    }

    // arg-provenance.ts:263: the entry check is `> max`, so an empty container after exactly max leaves is still inside
    [Fact]
    public void LeavesEntryBoundary()
    {
        var full = Enumerable.Repeat<object?>("a", ArgProvenance.MaxLeaves).ToList();
        full.Add(new JL());
        Assert.Equal(ArgProvenance.MaxLeaves, ArgProvenance.Leaves(full)!.Count);
        var over = Enumerable.Repeat<object?>("a", ArgProvenance.MaxLeaves + 1).ToList();
        Assert.Null(ArgProvenance.Leaves(over));
    }

    [Fact]
    public void AVerifiedChainWithOnlyTheActionIsAgentControlled()
    {
        var r = Recorder();
        var b = r.ForAction("v", "res", new JD());
        var op = new JD { ["verb"] = "v", ["resource"] = "res", ["params"] = new JD() };
        var d = ArgProvenance.Decide(new ArgProvenanceInput { Bundle = b, Operation = op, Mediators = new JL { r.Pin.ToJson() } });
        Assert.Equal(("escalate", "untrusted_control", true, "agent"), (d.Outcome, d.Code, d.Verified, d.Control));
        Assert.Equal(new[] { "unlabelled" }, d.Path);
        Assert.Equal("the choice of v derives from untrusted content [unlabelled]: the principal must confirm (prompt-injection path)", d.Reason);
    }

    [Fact]
    public void BundleSessionOfAnEmptyListIsNull()
    {
        Assert.Null(ArgProvenance.BundleSession(new JD { ["receipts"] = new JL() }));
        Assert.Equal("s", ArgProvenance.BundleSession(new JD { ["receipts"] = new JL { new JD { ["session"] = "s" } } }));
    }

    [Fact]
    public void RecorderRefusals()
    {
        Assert.Equal("PrincipalDirect: params must be a JSON object", Assert.Throws<ArgumentException>(() => ArgProvenance.PrincipalDirect(Recorder(), "v", "r", "text")).Message);
        Assert.Equal("ForAction: params must be a JSON object", Assert.Throws<ArgumentException>(() => Recorder().ForAction("v", "r", 5L)).Message);
        Assert.Equal("ProvenanceRecorder: mediator (<= 256 bytes) and kid (<= 64 bytes) are required", Assert.Throws<ArgumentException>(() => new ProvenanceRecorder("", "k")).Message);
        Assert.Equal("ProvenanceRecorder: session must be canonical base64url of 32 bytes", Assert.Throws<ArgumentException>(() => new ProvenanceRecorder("m", "k", Mediator, "bad")).Message);
        var pureMlDsa = SuiteKey.Create("ml-dsa-65", null, PqKey.Generate(Pq.Prim.MlDsa65));
        Assert.Equal("ProvenanceRecorder: the mediator key needs an Ed25519 identity", Assert.Throws<ArgumentException>(() => new ProvenanceRecorder("m", "k", pureMlDsa)).Message);
    }

    [Fact]
    public void ForActionRefusesAFullSession()
    {
        var r = Recorder();
        for (var i = 0; i < ArgProvenance.MaxReceipts; i++) r.Principal("x");
        Assert.Equal("provenance: the session holds 256 receipts; start a new session with the principal's message", Assert.Throws<InvalidOperationException>(() => r.ForAction("v", "r", new JD())).Message);
    }

    // arg-provenance.ts:507 String(c): a value with no JSON form is recorded as its text
    [Fact]
    public void AValueWithNoJsonFormIsItsText()
    {
        Assert.Equal(Pca.HashCanonical("hello"), Recorder().Tool("t", new Opaque("hello"))["content_digest"]);
        Assert.Equal(Pca.HashCanonical("null"), Recorder().Tool("t", new Opaque(null))["content_digest"]);
    }
}

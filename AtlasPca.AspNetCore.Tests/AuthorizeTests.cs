using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using AtlasPca;
using AtlasPca.AspNetCore;
using Microsoft.AspNetCore.Http;
using Microsoft.Data.Sqlite;
using Xunit;

namespace AtlasPca.AspNetCore.Tests;

// Pca.Authorize against the signed shared fixtures (test-data/authorize-fixtures.json, `pca-authorize-fixtures/1`), which also
// record the TypeScript authorize() outcome of every step (`ts`): one fresh store per case, memory and SQLite.
public class AuthorizeTests
{
    static readonly Dictionary<string, object?> Fix = (Dictionary<string, object?>)Pca.ParseJson(File.ReadAllText(Path.Combine(
        AppContext.BaseDirectory, "test-data", "authorize-fixtures.json")))!;
    static readonly List<Dictionary<string, object?>> Cases = ((List<object?>)Fix["cases"]!).Cast<Dictionary<string, object?>>().ToList();
    static readonly string Aud = (string)Fix["audience"]!;
    static readonly long Now = long.Parse(((Num)Fix["now"]!).Raw, CultureInfo.InvariantCulture);

    static Dictionary<string, object?> Kase(string name) => Cases.First(c => (string)c["name"]! == name);
    static List<Dictionary<string, object?>> Steps(Dictionary<string, object?> c) => ((List<object?>)c["steps"]!).Cast<Dictionary<string, object?>>().ToList();
    static Dictionary<string, object?> Grant(Dictionary<string, object?> c) => (Dictionary<string, object?>)c["grant"]!;
    static Dictionary<string, object?> Pcactn(Dictionary<string, object?> s) => (Dictionary<string, object?>)s["pcactn"]!;
    static Operation Op(Dictionary<string, object?> s)
    {
        var o = (Dictionary<string, object?>)s["operation"]!;
        return new Operation((string)o["verb"]!, (string)o["resource"]!, o["params"]);
    }
    static int Int(object? n) => int.Parse(((Num)n!).Raw, CultureInfo.InvariantCulture);

    static AuthorizeInput Input(Dictionary<string, object?> c, Dictionary<string, object?> s, IStateStore? store = null, bool revoked = false) => new()
    {
        Operation = Op(s), Audience = Aud, ResolveGrant = r => r == (string)Grant(c)["id"]! ? Grant(c) : null,
        StateStore = store ?? new MemoryStateStore(), IsRevoked = (_, _) => revoked, Now = Now, Plan = "single-step",
    };

    static AuthorizeResult Az(Dictionary<string, object?> c, int step = 0, Action<AuthorizeInput>? tweak = null)
    {
        var s = Steps(c)[step];
        var i = Input(c, s);
        tweak?.Invoke(i);
        return Pca.Authorize(Pcactn(s), i);
    }

    static (bool, int, string) Settle(AuthorizeResult r) =>
        (r.Allow, r.Status, string.Join(",", r.Checks.Where(kv => kv.Value == "fail").Select(kv => kv.Key).OrderBy(k => k, StringComparer.Ordinal)));

    static void RunCase(Dictionary<string, object?> c, IStateStore store)
    {
        foreach (var s in Steps(c))
        {
            var r = Pca.Authorize(Pcactn(s), Input(c, s, store, (bool)s["revoked"]!));
            var e = (Dictionary<string, object?>)s["expect"]!;
            var failed = ((List<object?>)e["failed"]!).Cast<string>().ToArray();
            var (a, st, f) = Settle(r);
            Assert.True((bool)e["allow"]! == a && Int(e["status"]) == st && string.Join(",", failed) == f, $"{c["name"]}: got {a} {st} {f}");
            if (e.TryGetValue("reason", out var want)) Assert.Contains((string)want!, r.Reason ?? "");
            var ts = (Dictionary<string, object?>)s["ts"]!;
            Assert.True((bool)ts["allow"]! == a && Int(ts["status"]) == st, $"{c["name"]} differs from the TypeScript decision");
        }
    }

    [Fact] public void FixtureShape()
    {
        Assert.Equal("pca-authorize-fixtures/1", Fix["format"]);
        Assert.Equal(31, Cases.Count);
        Assert.Equal(35, Cases.Sum(c => Steps(c).Count));
    }

    [Fact] public void FixturesMemoryStore() { foreach (var c in Cases) RunCase(c, new MemoryStateStore()); }

    [Fact] public void FixturesSqlStore()
    {
        foreach (var c in Cases)
        {
            var keep = new SqliteConnection("Data Source=file:" + Guid.NewGuid().ToString("N") + "?mode=memory&cache=shared");
            keep.Open();
            var store = new SqlStateStore(() => new SqliteConnection(keep.ConnectionString));
            store.EnsureSchema();
            RunCase(c, store);
            keep.Dispose();
        }
    }

    [Fact] public void AcceptanceReasons()
    {
        var r = Az(Kase("envelope-max-spend-400-refused"));
        Assert.Equal((false, 403, "policy"), Settle(r));
        Assert.Equal("policy: caveat(s) not satisfied: max_spend", r.Reason);
        Assert.Equal("policy: root caveat(s) not satisfied: max_spend", Az(Kase("root-max-spend-400-refused")).Reason);
        Assert.Equal("delegated_caveats: delegation caveat(s) not satisfied: max_spend", Az(Kase("delegated-max-spend-400-refused")).Reason);
        Assert.Equal("operation: the proof's params_digest does not match the params of this payments.send operation",
            Az(Kase("envelope-max-spend-signed-50-executes-400")).Reason);
        Assert.Equal("operation: the proof is for payments.send on payments/acme, but this operation is payments.refund on payments/acme",
            Az(Kase("operation-other-verb")).Reason);
        Assert.StartsWith("policy: root caveat(s) not satisfied: ", Az(Kase("root-unknown-caveat")).Reason);
        Assert.StartsWith("delegated_caveats: delegation caveat(s) not satisfied: ", Az(Kase("delegated-unknown-caveat")).Reason);
    }

    [Fact] public void AllowBindsTheOperationAndReplayIsRefused()
    {
        var c = Kase("envelope-max-spend-within");
        var s = Steps(c)[0];
        var store = new MemoryStateStore();
        var r = Pca.Authorize(Pcactn(s), Input(c, s, store));
        Assert.True(r.Allow);
        Assert.Equal(200, r.Status);
        Assert.Equal(Pca.HashCanonical(Pcactn(s)), r.Operation!.Id);
        Assert.Equal(((Dictionary<string, object?>)Pcactn(s)["action"]!)["params_digest"], r.Operation.ParamsDigest);
        Assert.True(Pca.IsAuthorizedFor(r, Op(s)));
        var other = new Dictionary<string, object?> { ["amount"] = 400, ["currency"] = "usd" };
        Assert.False(Pca.IsAuthorizedFor(r, new Operation("payments.send", "payments/acme", other)));
        Assert.False(Pca.IsAuthorizedFor(r, Op(s) with { Verb = "payments.refund" }));
        Assert.False(Pca.IsAuthorizedFor(r, null));
        var again = Pca.Authorize(Pcactn(s), Input(c, s, store));
        Assert.Equal((false, 403, "replay"), Settle(again));
        Assert.Equal("replay: 1 is not greater than last seen 1 (replay)", again.Reason);
        Assert.False(Pca.IsAuthorizedFor(again, Op(s)));
    }

    [Fact] public void MissingComponentsRefusedBeforeVerification()
    {
        var c = Kase("envelope-max-spend-within");
        var tweaks = new (string, Action<AuthorizeInput>)[]
        {
            ("Audience", i => i.Audience = ""), ("Audience", i => i.Audience = null), ("ResolveGrant", i => i.ResolveGrant = null),
            ("StateStore", i => i.StateStore = null), ("IsRevoked", i => i.IsRevoked = null),
        };
        foreach (var (name, t) in tweaks)
        {
            int seen = 0;
            var r = Az(c, 0, i => { i.ResolveGrant = ref_ => { seen++; return Grant(c); }; t(i); });
            Assert.Equal((false, 403, "authorize_config"), Settle(r));
            Assert.Equal(new[] { name }, r.Missing);
            Assert.Equal(0, seen);
        }
    }

    [Fact] public void OperationRequiredAndNoPlanSource()
    {
        var c = Kase("envelope-max-spend-within");
        int seen = 0;
        foreach (var op in new Operation?[] { null, new("", "x", new Dictionary<string, object?>()), new("v", "", new Dictionary<string, object?>()), new("v", "r", null), new("v", "r", 5) })
        {
            var r = Az(c, 0, i => { i.Operation = op; i.ResolveGrant = _ => { seen++; return Grant(c); }; });
            Assert.Equal((false, 403, "operation"), Settle(r));
        }
        Assert.Equal(0, seen);
        Assert.Equal((false, 403, "plan_root_authorized"), Settle(Az(c, 0, i => i.Plan = null)));
        // K5: default-deny with the exact reason (no opt-out exists on the pipeline); a configured single-step plan still passes.
        Assert.Contains("plan_root_authorized: default-deny: no authorized plan is configured for this verifier (supply the plan and its authorization, or set InsecureSkipPlanRootCheck)", Az(c, 0, i => i.Plan = null).Reasons);
        Assert.Equal("pass", Az(c, 0).Checks["plan_root_authorized"]);
    }

    [Fact] public void RevocationMustBeExactlyFalse()
    {
        var c = Kase("envelope-max-spend-within");
        foreach (var chk in new Func<Dictionary<string, object?>, Dictionary<string, object?>, bool?>[]
                 { (_, _) => null, (_, _) => throw new InvalidOperationException("down") })
        {
            var r = Az(c, 0, i => i.IsRevoked = chk);
            Assert.Equal((false, 403, "revocation"), Settle(r));
            Assert.Equal("revocation: the revocation check failed (fail closed)", r.Reason);
        }
        Assert.Equal("revocation: the grant is revoked", Az(c, 0, i => i.IsRevoked = (_, _) => true).Reason);
    }

    sealed class Broken : IStateStore { public ClaimResult? Claim(string key, long counter) => throw new IOException("locked"); }
    sealed class Null : IStateStore { public ClaimResult? Claim(string key, long counter) => null; }
    sealed class Recorder : IStateStore { public int Calls; public ClaimResult? Claim(string key, long counter) { Calls++; return new ClaimResult(true); } }

    [Fact] public void StoreFailureDeniesAndDeniedNeverClaims()
    {
        var c = Kase("envelope-max-spend-within");
        foreach (IStateStore st in new IStateStore[] { new Broken(), new Null() })
        {
            var r = Az(c, 0, i => i.StateStore = st);
            Assert.Equal((false, 403, "replay"), Settle(r));
            Assert.Equal("replay: the replay store failed (fail closed)", r.Reason);
        }
        var rec = new Recorder();
        foreach (var k in Cases)
        {
            var s = Steps(k)[0];
            if ((bool)((Dictionary<string, object?>)s["expect"]!)["allow"]!) continue;
            Assert.False(Pca.Authorize(Pcactn(s), Input(k, s, rec, (bool)s["revoked"]!)).Allow);
        }
        Assert.Equal(0, rec.Calls);
    }

    [Fact] public void ClaimTable()
    {
        var keep = new SqliteConnection("Data Source=file:" + Guid.NewGuid().ToString("N") + "?mode=memory&cache=shared");
        keep.Open();
        var sql = new SqlStateStore(() => new SqliteConnection(keep.ConnectionString));
        sql.EnsureSchema();
        foreach (IStateStore st in new IStateStore[] { new MemoryStateStore(), sql })
        {
            var got = new[] { ("a", 5L), ("a", 5), ("a", 4), ("a", 6), ("b", 0), ("b", 0) }.Select(t => st.Claim(t.Item1, t.Item2)!).Select(r => (r.Ok, r.LastCounter)).ToArray();
            Assert.Equal(new (bool, long?)[] { (true, null), (false, 5), (false, 5), (true, null), (true, null), (false, 0) }, got);
        }
        keep.Dispose();
    }

    [Fact] public async Task ConcurrentClaimsOneWins()
    {
        var keep = new SqliteConnection("Data Source=file:" + Guid.NewGuid().ToString("N") + "?mode=memory&cache=shared");
        keep.Open();
        var sql = new SqlStateStore(() => new SqliteConnection(keep.ConnectionString + ";Default Timeout=30"));
        sql.EnsureSchema();
        foreach (IStateStore st in new IStateStore[] { new MemoryStateStore(), sql })
        {
            var wins = (await Task.WhenAll(Enumerable.Range(0, 16).Select(_ => Task.Run(() => st.Claim("k", 1)!.Ok)))).Count(x => x);
            Assert.Equal(1, wins);
        }
        keep.Dispose();
    }

    // ---- middleware ----
    static async Task<(int, string, bool, HttpContext)> Post(string kase, string body, string verb = "payments.send", bool revoked = false, IStateStore? store = null, bool mapping = true)
    {
        var c = Kase(kase);
        var s = Steps(c)[0];
        var grants = new[] { Grant(c) }.ToDictionary(g => (string)g["id"]!);
        var opt = new PcaOptions
        {
            Audience = Aud, Clock = () => Now,
            GrantResolver = r => Task.FromResult(grants.TryGetValue(r, out var g) ? g : null),
            Authorize = new PcaAuthorizeOptions
            {
                StateStore = store ?? new MemoryStateStore(), IsRevoked = (_, _) => revoked,
                Operation = mapping ? ctx => Task.FromResult<Operation?>(new Operation(verb, "payments/acme", Pca.ParseJson(body))) : null,
            },
        };
        bool ran = false;
        var mw = new PcaMiddleware(_ => { ran = true; return Task.CompletedTask; }, opt);
        var http = new DefaultHttpContext();
        http.Response.Body = new MemoryStream();
        http.Request.Headers[opt.HeaderName] = Pca.B64u(Encoding.UTF8.GetBytes(Pca.Canonicalize(Pcactn(s))));
        await mw.InvokeAsync(http);
        http.Response.Body.Position = 0;
        return (http.Response.StatusCode, new StreamReader(http.Response.Body).ReadToEnd(), ran, http);
    }

    [Fact] public async Task MiddlewareAcceptance()
    {
        var (st, body, ran, _) = await Post("envelope-max-spend-400-refused", "{\"amount\":400,\"currency\":\"usd\"}");
        Assert.Equal(403, st); Assert.False(ran);
        Assert.Contains("policy: caveat(s) not satisfied: max_spend", body);
        (st, body, ran, _) = await Post("envelope-max-spend-within", "{\"amount\":400,\"currency\":\"usd\"}");
        Assert.Equal(403, st); Assert.False(ran);
        Assert.Contains("params_digest does not match", body);
        (st, body, ran, _) = await Post("envelope-max-spend-within", "{\"amount\":50,\"currency\":\"usd\"}", verb: "payments.refund");
        Assert.Equal(403, st); Assert.False(ran);
        Assert.Contains("the proof is for payments.send", body);
        (st, _, ran, _) = await Post("envelope-max-spend-within", "{\"amount\":50,\"currency\":\"usd\"}", revoked: true);
        Assert.Equal(403, st); Assert.False(ran);
        (st, _, ran, _) = await Post("envelope-max-spend-within", "{\"amount\":50,\"currency\":\"usd\"}", mapping: false);
        Assert.Equal(403, st); Assert.False(ran);

        var store = new MemoryStateStore();
        (st, _, ran, var http) = await Post("envelope-max-spend-within", "{\"amount\":50,\"currency\":\"usd\"}", store: store);
        Assert.Equal(200, st); Assert.True(ran);
        var res = (PcaAuthResult)http.Items["pca"]!;
        Assert.Equal("payments.send", res.Operation!.Verb);
        (st, body, ran, _) = await Post("envelope-max-spend-within", "{\"amount\":50,\"currency\":\"usd\"}", store: store);
        Assert.Equal(403, st); Assert.False(ran);
        Assert.Contains("replay: 1 is not greater than last seen 1 (replay)", body);
    }

    // ---- 0.5 defaults (B3) and check names (B6) ----
    static async Task<(int, string, bool, HttpContext)> Run(string kase, Action<PcaOptions> tweak, string body = "{\"amount\":50,\"currency\":\"usd\"}")
    {
        var c = Kase(kase);
        var grants = new[] { Grant(c) }.ToDictionary(g => (string)g["id"]!);
        var opt = new PcaOptions { Audience = Aud, Clock = () => Now, GrantResolver = r => Task.FromResult(grants.TryGetValue(r, out var g) ? g : null) };
        tweak(opt);
        bool ran = false;
        var mw = new PcaMiddleware(_ => { ran = true; return Task.CompletedTask; }, opt);
        var http = new DefaultHttpContext();
        http.Response.Body = new MemoryStream();
        http.Request.Headers[opt.HeaderName] = Pca.B64u(Encoding.UTF8.GetBytes(Pca.Canonicalize(Pcactn(Steps(c)[0]))));
        await mw.InvokeAsync(http);
        http.Response.Body.Position = 0;
        return (http.Response.StatusCode, new StreamReader(http.Response.Body).ReadToEnd(), ran, http);
    }

    [Fact] public async Task DefaultWithoutComponentsIsRefusedNamingWhatIsMissing()
    {
        var (st, body, ran, _) = await Run("envelope-max-spend-within", _ => { });
        Assert.Equal(403, st); Assert.False(ran);
        Assert.Contains("\"error\":\"access_denied\"", body);
        Assert.Contains("authorize_config: missing required component(s): StateStore, IsRevoked (fail closed)", body);
        (st, body, ran, _) = await Run("envelope-max-spend-within", o => o.Authorize = new PcaAuthorizeOptions { StateStore = new MemoryStateStore() });
        Assert.Equal(403, st); Assert.False(ran);
        Assert.Contains("authorize_config: missing required component(s): IsRevoked (fail closed)", body);
    }

    [Fact] public async Task SignatureOnlyVerifiesTheSignatureAndRunsTheHandler()
    {
        // the $400 proof is signed over a $400 action under a $100 cap: the default refuses it, signature-only lets it through
        var (st, body, ran, http) = await Run("envelope-max-spend-400-refused", o => o.SignatureOnly = true);
        Assert.Equal(200, st); Assert.True(ran);
        var res = (PcaAuthResult)http.Items["pca"]!;
        Assert.True(res.Verdict.Allow);
        Assert.Null(res.Authorization);
        Assert.Contains("counter_format", res.Verdict.Checks.Keys);
        Assert.DoesNotContain("counter", res.Verdict.Checks.Keys);
        (st, body, ran, _) = await Post("envelope-max-spend-400-refused", "{\"amount\":400,\"currency\":\"usd\"}");
        Assert.Equal(403, st); Assert.False(ran);
    }

    [Fact] public void SignatureOnlyWithAuthorizeIsAConfigurationError()
    {
        var both = new PcaOptions
        {
            Audience = Aud, SignatureOnly = true, Authorize = new PcaAuthorizeOptions(),
            GrantResolver = _ => Task.FromResult<Dictionary<string, object?>?>(null),
        };
        var ex = Assert.Throws<InvalidOperationException>(() => new PcaMiddleware(_ => Task.CompletedTask, both));
        Assert.Contains("mutually exclusive", ex.Message);
        Assert.Throws<InvalidOperationException>(() => both.Validate());
    }

    [Fact] public void CheckNamesAreCounterFormatAndReplay()
    {
        var c = Kase("envelope-max-spend-within");
        var r = Az(c);
        Assert.True(r.Allow);
        Assert.Equal("pass", r.Checks["counter_format"]);
        Assert.Equal("pass", r.Checks["replay"]);
        Assert.DoesNotContain("counter", r.Checks.Keys);
        Assert.Equal(new[] { "counter_format", "replay", "revocation", "plan_root_authorized", "audience", "validity", "grant_ref_bound", "operation", "params_digest", "policy" },
            Pca.DefaultRequiredChecks);
    }

    [Fact] public void RequireCounterIsAnAliasOfReplay()
    {
        var c = Kase("envelope-max-spend-within");
        Assert.True(Az(c, 0, i => i.Require = new[] { "counter" }).Allow);
        Assert.False(Az(c, 0, i => i.Require = new[] { "no_such_check" }).Allow);
    }
}

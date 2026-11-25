using System.Globalization;
using AtlasPca;
using AtlasPca.Connect;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Differential replay of the outbound connection/token vault against the TypeScript reference (test-data/ref-connect.json.gz).</summary>
public class RefConnectTests
{
    const string M = "ref-connect";

    // the hostile-variant scenarios store the scenario object itself as `args`; every other case stores the positional list
    static void Prep()
    {
        foreach (var c in Base.Cases(M))
            if (c["args"] is D scenario) c["args"] = new L { scenario };
    }

    static double Dbl(object? o) => o is Num n ? double.Parse(n.Raw, CultureInfo.InvariantCulture) : Convert.ToDouble(o, CultureInfo.InvariantCulture);
    static List<string>? Strs(object? o) => o is L l ? l.Select(x => (string)x!).ToList() : null;
    static Dictionary<string, string>? StrMap(object? o) => o is D d ? d.ToDictionary(e => e.Key, e => (string)e.Value!) : null;
    static EdKey Key(object? seedB64) => EdKey.FromSeed(Pca.B64uDecode(seedB64) ?? throw new InvalidDataException("seed"));

    // ---- small functions ----

    [Fact] public void OauthScopeCaveat() { Prep(); Base.Check(M, "oauthScopeCaveat", a => ConnectAuthority.OauthScopeCaveat((string)a[0]!, Strs(a[1])!)); }

    [Fact] public void IsOAuthScopeCaveat() { Prep(); Base.Check(M, "isOAuthScopeCaveat", a => ConnectAuthority.IsOAuthScopeCaveat(a[0])); }

    [Fact]
    public void GrantedOAuthScopes()
    {
        Prep();
        Base.Check(M, "grantedOAuthScopes", a =>
        {
            var s = ConnectAuthority.GrantedOAuthScopes(a[0], (string)a[1]!);
            if (s == null) return null;
            var l = s.ToList();
            l.Sort(StringComparer.Ordinal);
            return l;
        });
    }

    static HttpRequestSpec Spec(object? o)
    {
        var s = (D)o!;
        return new HttpRequestSpec { Method = (string)s["method"]!, Url = (string)s["url"]!, Query = Strs(s.GetValueOrDefault("query")), Body = s.GetValueOrDefault("body") as string, Fixed = s.GetValueOrDefault("fixed") as D };
    }

    [Fact] public void HttpExtractor() { Prep(); Base.Check(M, "httpExtractor", a => ConnectProxy.HttpExtractor(Spec(a[0]))(a[1])); }

    [Fact] public void CheckProxyHeaders() { Prep(); Base.Check(M, "checkProxyHeaders", a => ConnectProxy.CheckProxyHeaders(a[0], Strs(a[1])!)); }

    [Fact] public void DefaultProxyHeaders() { Prep(); Base.Check(M, "DEFAULT_PROXY_HEADERS", _ => ConnectProxy.DefaultProxyHeaders.ToList()); }

    [Fact] public void OutboundRequestDigest() { Prep(); Base.Check(M, "outboundRequestDigest", a => ConnectProxy.OutboundRequestDigest((string)a[0]!, (string)a[1]!, StrMap(a[2])!, a[3] as string)); }

    [Fact] public void SignReleaseReceipt() { Prep(); Base.Check(M, "signReleaseReceipt", a => ConnectProxy.SignReleaseReceipt((D)a[0]!, Key(a[1]))); }

    [Fact] public void VerifyReleaseReceipt() { Prep(); Base.Check(M, "verifyReleaseReceipt", a => ConnectProxy.VerifyReleaseReceipt((D)a[0]!, a[1])); }

    [Fact] public void ReceiptActionDigest() { Prep(); Base.Check(M, "receiptActionDigest", a => ConnectProxy.ReceiptActionDigest((D)a[0]!)); }

    // ---- scripted transport ----

    /// <summary>One scripted token-endpoint response ({ok, status, json?, jsonThrows?, text?, textThrows?}).</summary>
    sealed class ScriptedResponse(D r) : IVaultHttpResponse
    {
        public bool Ok => r.GetValueOrDefault("ok") is true;
        public int Status => (int)Dbl(r["status"]);
        public object? Json() => r.GetValueOrDefault("jsonThrows") is true ? throw new InvalidDataException("bad json") : r.GetValueOrDefault("json");
        public string Text() => r.GetValueOrDefault("textThrows") is true ? throw new InvalidDataException("bad text") : r.GetValueOrDefault("text") as string ?? "";
    }

    /// <summary>Replays the case's responses in order (the last one repeats) and logs every request.</summary>
    static VaultFetch? Transport(object? script, L log)
    {
        if (script is not L s) return null;
        int i = 0;
        return (url, init) =>
        {
            log.Add(new D { ["url"] = url, ["method"] = init.Method, ["headers"] = init.Headers.ToDictionary(e => e.Key, e => (object?)e.Value), ["body"] = init.Body });
            var r = (D)s[Math.Min(i++, s.Count - 1)]!;
            if (r.GetValueOrDefault("throws") is string t) throw new InvalidOperationException(t);
            return new ScriptedResponse(r);
        };
    }

    static D ErrOut(Exception e)
    {
        var o = new D { ["ok"] = false };
        if (e is VaultError v)
        {
            o["name"] = v.ErrorName;
            o["code"] = v.Code;
            if (v.Code != "not_authorized") o["message"] = v.Message;
            if (e is RefreshFailedError rf && rf.Status != null) o["status"] = (long)rf.Status.Value;
            if (e is ScopeExceededError se) o["missing"] = se.Missing.Cast<object?>().ToList();
        }
        else o["name"] = "Error";
        return o;
    }

    static StoredConnection Conn(object? o)
    {
        var c = (D)o!;
        var au = (D)c["authority"]!;
        return new StoredConnection
        {
            AgentId = (string)c["agentId"]!, Provider = (string)c["provider"]!, ConnectionId = (string)c["connectionId"]!, AccessToken = (string)c["accessToken"]!,
            RefreshToken = c.GetValueOrDefault("refreshToken") as string, ExpiresAt = Dbl(c["expiresAt"]), Scopes = Strs(c["scopes"])!,
            Authority = new ConnectionAuthority { Provider = (string)au["provider"]!, Principal = (string)au["principal"]!, Scopes = Strs(au["scopes"])!, Audience = au.GetValueOrDefault("audience") as string },
            CreatedAt = Dbl(c["createdAt"]), LastUsedAt = c.GetValueOrDefault("lastUsedAt") is { } lu ? Dbl(lu) : null, UseCount = (long)Dbl(c["useCount"]),
        };
    }

    static ProviderConfig? Config(object? o)
    {
        if (o is not D c) return null;
        return new ProviderConfig
        {
            TokenEndpoint = (string)c["tokenEndpoint"]!, ClientId = (string)c["clientId"]!, ClientSecret = c.GetValueOrDefault("clientSecret") as string,
            SupportsScopeNarrowing = c.GetValueOrDefault("supportsScopeNarrowing") as bool?, ExtraParams = StrMap(c.GetValueOrDefault("extraParams")),
        };
    }

    [Fact]
    public void RefreshConnection()
    {
        Prep();
        Base.Check(M, "refreshConnection", a =>
        {
            var c = (D)a[0]!;
            var log = new L();
            var o = new D();
            try
            {
                var r = ConnectRefresh.RefreshConnection(new RefreshArgs
                {
                    Connection = Conn(c["connection"]), Config = Config(c.GetValueOrDefault("config")), RefreshToken = (string)c["refreshToken"]!, Requested = Strs(c["requested"])!,
                    Fetch = Transport(c.GetValueOrDefault("script"), log), Now = Dbl(c["now"]), DefaultTokenLifetimeMs = Dbl(c["defaultTokenLifetimeMs"]),
                });
                o["ok"] = true;
                o["value"] = new D { ["accessToken"] = r.AccessToken, ["expiresAt"] = r.ExpiresAt, ["scopes"] = r.Scopes.Cast<object?>().ToList(), ["refreshToken"] = r.RefreshToken };
            }
            catch (Exception e) { foreach (var kv in ErrOut(e)) o[kv.Key] = kv.Value; }
            o["calls"] = log;
            return o;
        });
    }

    [Fact]
    public void DecryptRecord()
    {
        Prep();
        Base.Check(M, "decryptRecord", a =>
        {
            var c = (D)a[0]!;
            var inner = new InMemoryConnectionStore();
            inner.Set(Conn(c["record"]));
            var ring = ((D)c["ring"]!).ToDictionary(e => e.Key, e => Pca.B64uDecode(e.Value)!);
            var store = new EncryptedConnectionStore(inner, new LocalKeyWrapper(ring, (string)c["active"]!));
            var k = (D)c["key"]!;
            try
            {
                var r = store.Get(new ConnectionKey((string)k["agentId"]!, (string)k["provider"]!, (string)k["connectionId"]!));
                return new D { ["ok"] = true, ["value"] = r?.ToJson() };
            }
            catch (Exception e) { return ErrOut(e); }
        });
    }

    // ---- TokenVault scenarios ----

    static VaultAction MkAction(D t) => new()
    {
        Verb = t.GetValueOrDefault("verb") as string, DefDigest = t.GetValueOrDefault("def_digest") as string, Confirmed = t.GetValueOrDefault("confirmed") is true,
        Provider = (string)((D)t["upstream"]!)["provider"]!, ScopesMin = Strs(((D)t["upstream"]!)["scopes_min"])!,
        Extract = t.GetValueOrDefault("extract") is D ex ? ConnectProxy.HttpExtractor(Spec(ex)) : null,
    };

    static ProxyRequest Request(object? o)
    {
        var s = (D)o!;
        return new ProxyRequest((string)s["method"]!, (string)s["url"]!, StrMap(s.GetValueOrDefault("headers")), s.GetValueOrDefault("body") as string);
    }

    static D Vault(D s)
    {
        long now = (long)Dbl(s["nowMs"]);
        var store = new InMemoryConnectionStore();
        var fetchLog = new L();
        var proxyLog = new L();
        var receipts = new L();
        var op = s.GetValueOrDefault("opts") as D ?? new D();
        var table = s.GetValueOrDefault("actionsTable") as D;

        var o = new TokenVaultOptions
        {
            Strict = false, Store = store, Now = () => now, Fetch = Transport(s.GetValueOrDefault("fetchScript"), fetchLog),
            InsecureBearerRelease = op.GetValueOrDefault("insecureBearerRelease") is true, InsecureSkipPlanRootCheck = op.GetValueOrDefault("insecureSkipPlanRootCheck") is true,
        };
        if (op.GetValueOrDefault("authorizedPlanRoots") != null) o.AuthorizedPlanRoots = Strs(op["authorizedPlanRoots"]);
        if (op.GetValueOrDefault("audience") != null) o.Audience = (string)op["audience"]!;
        if (op.GetValueOrDefault("expiryLeewayMs") != null) o.ExpiryLeewayMs = Dbl(op["expiryLeewayMs"]);
        if (op.GetValueOrDefault("defaultTokenLifetimeMs") != null) o.DefaultTokenLifetimeMs = Dbl(op["defaultTokenLifetimeMs"]);
        if (op.GetValueOrDefault("requireActionBinding") != null) o.RequireActionBinding = (bool)op["requireActionBinding"]!;
        if (op.ContainsKey("useVerb")) o.UseVerb = op["useVerb"] as string;
        if (op.GetValueOrDefault("defaultConnectionId") != null) o.DefaultConnectionId = (string)op["defaultConnectionId"]!;
        if (op.GetValueOrDefault("providers") is D provs) foreach (var e in provs) o.Providers[e.Key] = Config(e.Value)!;
        if (op.GetValueOrDefault("pqPins") != null) o.PqPins = StrMap(op["pqPins"]);
        if (op.GetValueOrDefault("maxProxyResponseBytes") != null) o.MaxProxyResponseBytes = (long)Dbl(op["maxProxyResponseBytes"]);
        if (op.GetValueOrDefault("replay") is true) o.Replay = new MemoryStateStore();
        var revoked = op.GetValueOrDefault("revoked");
        if (revoked != null)
            o.IsRevoked = _ => revoked is "throws" ? throw new InvalidOperationException("src down") : revoked is "yes";
        if (table != null) o.Actions = verb => table.GetValueOrDefault(verb) is D t ? MkAction(t) : null;
        if (op.GetValueOrDefault("proxy") is true)
        {
            var script = (L)s["proxyScript"]!;
            int pi = 0;
            o.ProxyFetch = (method, url, headers, body) =>
            {
                proxyLog.Add(new D { ["method"] = method, ["url"] = url, ["headers"] = headers.ToDictionary(e => e.Key, e => (object?)e.Value), ["body"] = body, ["redirect"] = "manual" });
                var r = (D)script[Math.Min(pi++, script.Count - 1)]!;
                if (r.GetValueOrDefault("throws") != null) throw new InvalidOperationException("net");
                return new ProxyResponse((int)Dbl(r["status"]), StrMap(r["headers"]), (string)r["body"]!);
            };
        }
        if (op.GetValueOrDefault("receiptSeed") != null)
        {
            bool failing = op.GetValueOrDefault("failingSink") is true;
            o.Receipts = new VaultReceipts
            {
                SecretKey = Key(op["receiptSeed"]),
                Sink = r =>
                {
                    receipts.Add(r);
                    if (failing) throw new InvalidOperationException("sink");
                },
            };
        }
        var vault = new TokenVault(o);

        var results = new L();
        foreach (var co in (L)s["calls"]!)
        {
            var c = (D)co!;
            var kind = (string)c["op"]!;
            if (kind == "now") { now = (long)Dbl(c["now"]); continue; }
            D res;
            try
            {
                object? value;
                if (kind == "put")
                {
                    var g = (D)c["args"]!;
                    var au = (D)g["authority"]!;
                    value = vault.PutConnection(new PutConnectionArgs
                    {
                        AgentId = g.GetValueOrDefault("agentId") as string, Provider = g.GetValueOrDefault("provider") as string, ConnectionId = g.GetValueOrDefault("connectionId") as string,
                        AccessToken = g.GetValueOrDefault("accessToken") as string, RefreshToken = g.GetValueOrDefault("refreshToken") as string, ExpiresAt = Dbl(g["expiresAt"]),
                        Scopes = Strs(g.GetValueOrDefault("scopes")), Principal = au.GetValueOrDefault("principal") as string, AuthorityScopes = Strs(au.GetValueOrDefault("scopes")),
                        Audience = au.GetValueOrDefault("audience") as string,
                    }).ToJson();
                }
                else if (kind == "get")
                {
                    var g = (D)c["args"]!;
                    value = vault.GetConnectionToken(c["pcActn"], new GetConnectionTokenArgs { Provider = (string)g["provider"]!, ConnectionId = g.GetValueOrDefault("connectionId") as string, Scopes = Strs(g.GetValueOrDefault("scopes")) }).ToJson();
                }
                else if (kind == "proxy")
                {
                    var g = (D)c["args"]!;
                    var r = vault.ProxyCall(c["pcActn"], Request(c["request"]), new ProxyCallArgs { Provider = (string)g["provider"]!, ConnectionId = g.GetValueOrDefault("connectionId") as string, Scopes = Strs(g.GetValueOrDefault("scopes")) });
                    var v = new D { ["response"] = new D { ["status"] = (long)r.Response.Status, ["headers"] = r.Response.Headers!.ToDictionary(e => e.Key, e => (object?)e.Value), ["body"] = r.Response.Body } };
                    if (r.Receipt != null) v["receipt"] = r.Receipt;
                    value = v;
                }
                else if (kind == "delete")
                {
                    vault.DeleteConnection((string)c["agentId"]!, (string)c["provider"]!, c.GetValueOrDefault("connectionId") as string);
                    value = null;
                }
                else throw new InvalidOperationException("unknown op " + kind);
                res = new D { ["ok"] = true, ["value"] = value };
            }
            catch (Exception e) { res = ErrOut(e); }
            results.Add(res);
        }
        var watched = new L();
        foreach (var k in s.GetValueOrDefault("watch") as L ?? new L())
        {
            var kk = (D)k!;
            var g = store.Get(new ConnectionKey((string)kk["agentId"]!, (string)kk["provider"]!, (string)kk["connectionId"]!));
            watched.Add(g?.ToJson());
        }
        return new D { ["results"] = results, ["store"] = watched, ["receipts"] = receipts, ["fetchCalls"] = fetchLog, ["proxyCalls"] = proxyLog };
    }

    [Fact] public void VaultScenarios() { Prep(); Base.Check(M, "vault", a => Vault((D)a[0]!)); }

    // ---- what the oracle cannot pin (random IVs): round trips and tamper detection ----

    [Fact]
    public void EncryptedStoreRoundTripAndTamper()
    {
        var k2 = new byte[32];
        Array.Fill(k2, (byte)7);
        var w = new LocalKeyWrapper(new Dictionary<string, byte[]> { ["k1"] = new byte[32], ["k2"] = k2 }, "k1");
        var inner = new InMemoryConnectionStore();
        var store = new EncryptedConnectionStore(inner, w);
        var c = new StoredConnection
        {
            AgentId = "agent", Provider = "google", ConnectionId = "default", AccessToken = "AT-secret", RefreshToken = "RT-secret", ExpiresAt = 1000, Scopes = new List<string> { "read" },
            Authority = new ConnectionAuthority { Provider = "google", Principal = "p", Scopes = new List<string> { "read" } },
        };
        store.Set(c);
        var key = new ConnectionKey("agent", "google", "default");
        var raw = inner.Get(key)!;
        Assert.StartsWith("pca1.", raw.AccessToken);
        Assert.DoesNotContain("AT-secret", raw.AccessToken);
        Assert.True(store.Encrypted);
        var back = store.Get(key)!;
        Assert.Equal("AT-secret", back.AccessToken);
        Assert.Equal("RT-secret", back.RefreshToken);
        // rotation: a record sealed under k1 still opens after k2 becomes active, and re-encrypts under k2
        w.SetActive("k2");
        Assert.Equal("AT-secret", store.Get(key)!.AccessToken);
        Assert.True(store.Reencrypt(key));
        w.RemoveKey("k1");
        Assert.Equal("RT-secret", store.Get(key)!.RefreshToken);
        // a ciphertext moved to another connection fails to open
        var moved = inner.Get(key)!;
        moved.ConnectionId = "other";
        inner.Set(moved);
        var ex = Assert.Throws<StoreError>(() => store.Get(new ConnectionKey("agent", "google", "other")));
        Assert.Equal("store_error", ex.Code);
    }

    [Fact]
    public void StrictModeRequiresTheProductionPieces()
    {
        var o = new TokenVaultOptions();
        var e1 = Assert.Throws<ArgumentException>(() => new TokenVault(o));
        Assert.Equal("TokenVault strict mode requires an encrypting store, replay, isRevoked, audience", e1.Message);
        o.Strict = false;
        var e2 = Assert.Throws<ArgumentException>(() => new TokenVault(o));
        Assert.Equal("TokenVault requires a store", e2.Message);
    }

    [Fact]
    public void EveryFnIsCovered() { Base.Covers(M, new[]
    {
        "oauthScopeCaveat", "isOAuthScopeCaveat", "grantedOAuthScopes", "httpExtractor", "checkProxyHeaders", "DEFAULT_PROXY_HEADERS", "outboundRequestDigest",
        "signReleaseReceipt", "verifyReleaseReceipt", "receiptActionDigest", "refreshConnection", "decryptRecord", "vault",
    }); Assert.Equal(1690, Base.Total(M)); }
}

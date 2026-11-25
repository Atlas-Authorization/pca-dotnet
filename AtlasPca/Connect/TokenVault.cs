// An outbound connection/token vault for PCA agents. It holds an agent's third-party OAuth tokens and releases a FRESH access token only when a verified
// Proof-Carrying Action proves least-privilege authority over the requested provider + scopes, or (proxy mode) makes the outbound call itself so the agent never
// holds the credential. PCActns are parsed JSON trees (Pca.ParseStrict / ParseJson); calls are synchronous.
using System.Collections.Concurrent;
using System.Text;
using AtlasPca.InteropJs;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Connect;

/// <summary>The pinned definition of one action: where the scopes a credential may carry come from.</summary>
public sealed class VaultAction
{
    /// <summary>The verb a PCActn must carry for this action.</summary>
    public string? Verb { get; set; }
    /// <summary>Digest of the definition this mapping was written for (informational).</summary>
    public string? DefDigest { get; set; }
    /// <summary>True iff the definition carries a valid signed confirmation. Unconfirmed: nothing is released.</summary>
    public bool Confirmed { get; set; }
    public string Provider { get; set; } = "";
    /// <summary>The minimum scopes the action needs (a release is exactly these, and they must be inside the grant and the stored connection).</summary>
    public List<string> ScopesMin { get; set; } = new();
    /// <summary>Proxy mode: map the outbound request back to the action's parameters (<see cref="ConnectProxy.HttpExtractor"/>); null when none.</summary>
    public Func<object?, D>? Extract { get; set; }
}

/// <summary>Where signed release receipts go: <see cref="SecretKey"/> signs them, <see cref="Sink"/> (optional) receives each; a failing sink never fails the call.</summary>
public sealed class VaultReceipts
{
    public EdKey SecretKey { get; set; } = null!;
    public Action<D>? Sink { get; set; }
}

/// <summary>Vault options; unset members keep the reference defaults.</summary>
public sealed class TokenVaultOptions
{
    public IConnectionStore? Store { get; set; }
    public Dictionary<string, ProviderConfig> Providers { get; set; } = new();
    public VaultFetch? Fetch { get; set; }
    /// <summary>Clock, epoch ms.</summary>
    public Func<long> Now { get; set; } = () => AtlasPca.ReplayClock.NowMs();
    /// <summary>This vault's resource-server id, compared to each PCActn's signed aud. Null accepts any audience. A connection's own audience overrides it.</summary>
    public string? Audience { get; set; }
    /// <summary>Verifier-side issuer to pq_pk pins (b64u).</summary>
    public Dictionary<string, string>? PqPins { get; set; }
    /// <summary>The Merkle plan roots the principal authorized; required unless <see cref="InsecureSkipPlanRootCheck"/>.</summary>
    public List<string>? AuthorizedPlanRoots { get; set; }
    public bool InsecureSkipPlanRootCheck { get; set; }
    public double ExpiryLeewayMs { get; set; } = 30_000;
    public string DefaultConnectionId { get; set; } = "default";
    public bool RequireActionBinding { get; set; } = true;
    public Func<string, string, string> ResourceFor { get; set; } = (provider, _) => "oauth:" + provider;
    /// <summary>The action.verb a PCActn must carry; null skips the verb check.</summary>
    public string? UseVerb { get; set; } = "use_connection";
    public double DefaultTokenLifetimeMs { get; set; } = 300_000;
    /// <summary>One-time-use store for presented actions (a captured action cannot be replayed to the vault).</summary>
    public IStateStore? Replay { get; set; }
    /// <summary>Revocation source: true refuses the action; a throw refuses it too (fail closed).</summary>
    public Func<object?, bool>? IsRevoked { get; set; }
    /// <summary>Production profile (default on): requires an encrypting store, replay, isRevoked and an audience.</summary>
    public bool Strict { get; set; } = true;
    public Func<string, VaultAction?>? Actions { get; set; }
    /// <summary>DOCUMENTED INSECURE opt-in: without it GetConnectionToken throws bearer_release_disabled.</summary>
    public bool InsecureBearerRelease { get; set; }
    public ProxyFetch? ProxyFetch { get; set; }
    public IReadOnlyList<string> ProxyHeaders { get; set; } = ConnectProxy.DefaultProxyHeaders;
    public long MaxProxyResponseBytes { get; set; } = 4L * 1024 * 1024;
    public VaultReceipts? Receipts { get; set; }
}

public sealed class ConnectionToken
{
    public string Provider { get; set; } = "";
    public string ConnectionId { get; set; } = "";
    public string AccessToken { get; set; } = "";
    public List<string> Scopes { get; set; } = new();
    public double ExpiresAt { get; set; }
    /// <summary>True when the token was just refreshed at the provider.</summary>
    public bool Refreshed { get; set; }

    public D ToJson() => new()
    {
        ["provider"] = Provider, ["connectionId"] = ConnectionId, ["accessToken"] = AccessToken, ["scopes"] = Scopes.Cast<object?>().ToList(),
        ["expiresAt"] = JsX.Number(ExpiresAt), ["refreshed"] = Refreshed,
    };
}

public sealed class GetConnectionTokenArgs
{
    public string Provider { get; set; } = "";
    public string? ConnectionId { get; set; }
    /// <summary>Null = default to the connection's bound authority scopes (or the action's scopes_min).</summary>
    public List<string>? Scopes { get; set; }
}

public sealed class ProxyCallArgs
{
    public string Provider { get; set; } = "";
    public string? ConnectionId { get; set; }
    /// <summary>Scopes to request: fewer than the action's scopes_min is allowed, more is refused (null: the action's scopes_min).</summary>
    public List<string>? Scopes { get; set; }
}

public sealed class ProxyResult
{
    public ProxyResponse Response { get; set; } = null!;
    /// <summary>Present when the vault was constructed with receipts, else null.</summary>
    public D? Receipt { get; set; }
}

public sealed class PutConnectionArgs
{
    public string? AgentId { get; set; }
    public string? Provider { get; set; }
    public string? ConnectionId { get; set; }
    public string? AccessToken { get; set; }
    public string? RefreshToken { get; set; }
    public double ExpiresAt { get; set; }
    public List<string>? Scopes { get; set; }
    /// <summary>The binding: principal, optional scopes (default: <see cref="Scopes"/>) and optional audience.</summary>
    public string? Principal { get; set; }
    public List<string>? AuthorityScopes { get; set; }
    public string? Audience { get; set; }
}

public sealed class TokenVault
{
    readonly IConnectionStore _store;
    readonly Dictionary<string, ProviderConfig> _providers;
    readonly VaultFetch? _fetch;
    readonly Func<long> _now;
    readonly string? _audience;
    readonly IReadOnlyDictionary<string, string>? _pqPins;
    readonly List<string>? _authorizedPlanRoots;
    readonly bool _insecureSkipPlanRootCheck;
    readonly double _expiryLeewayMs;
    readonly string _defaultConnectionId;
    readonly bool _requireActionBinding;
    readonly Func<string, string, string> _resourceFor;
    readonly string? _useVerb;
    readonly double _defaultTokenLifetimeMs;
    readonly IStateStore? _replay;
    readonly Func<object?, bool>? _isRevoked;
    readonly Func<string, VaultAction?>? _actions;
    readonly bool _insecureBearerRelease;
    readonly ProxyFetch? _proxyFetch;
    readonly List<string> _proxyHeaders;
    readonly long _maxProxyResponseBytes;
    readonly VaultReceipts? _receipts;
    /// <summary>In-flight refreshes by connection, so two callers never spend one single-use refresh token twice.</summary>
    readonly ConcurrentDictionary<string, Lazy<Refreshed>> _inflight = new(StringComparer.Ordinal);

    public TokenVault(TokenVaultOptions o)
    {
        if (o.Strict)
        {
            var missing = new List<string>();
            if (o.Store == null || !o.Store.Encrypted) missing.Add("an encrypting store");
            if (o.Replay == null) missing.Add("replay");
            if (o.IsRevoked == null) missing.Add("isRevoked");
            if (string.IsNullOrEmpty(o.Audience)) missing.Add("audience");
            if (missing.Count > 0) throw new ArgumentException("TokenVault strict mode requires " + string.Join(", ", missing));
        }
        else if (o.Store == null) throw new ArgumentException("TokenVault requires a store");
        _store = o.Store!;
        _actions = o.Actions;
        _insecureBearerRelease = o.InsecureBearerRelease;
        _proxyFetch = o.ProxyFetch;
        _proxyHeaders = o.ProxyHeaders.Select(h => h.ToLowerInvariant()).ToList();
        _maxProxyResponseBytes = o.MaxProxyResponseBytes;
        _receipts = o.Receipts;
        _replay = o.Replay;
        _isRevoked = o.IsRevoked;
        _providers = o.Providers;
        _fetch = o.Fetch;
        _now = o.Now;
        _audience = o.Audience;
        _pqPins = o.PqPins;
        _authorizedPlanRoots = o.AuthorizedPlanRoots;
        _insecureSkipPlanRootCheck = o.InsecureSkipPlanRootCheck;
        _expiryLeewayMs = o.ExpiryLeewayMs;
        _defaultConnectionId = o.DefaultConnectionId;
        _requireActionBinding = o.RequireActionBinding;
        _resourceFor = o.ResourceFor;
        _useVerb = o.UseVerb;
        _defaultTokenLifetimeMs = o.DefaultTokenLifetimeMs;
    }

    static void NonEmpty(string k, string? v)
    {
        if (string.IsNullOrEmpty(v)) throw new ArgumentException($"putConnection: {k} must be a non-empty string");
    }

    /// <summary>Store (or replace) an agent's connection. The authority descriptor binds which capability may use it.</summary>
    public StoredConnection PutConnection(PutConnectionArgs args)
    {
        var connectionId = args.ConnectionId ?? _defaultConnectionId;
        NonEmpty("agentId", args.AgentId);
        NonEmpty("provider", args.Provider);
        NonEmpty("connectionId", connectionId);
        NonEmpty("accessToken", args.AccessToken);
        NonEmpty("principal", args.Principal);
        if (!double.IsFinite(args.ExpiresAt)) throw new ArgumentException("putConnection: expiresAt must be a finite number");
        if (args.RefreshToken != null && args.RefreshToken.Length == 0) throw new ArgumentException("putConnection: refreshToken must be a non-empty string when given");
        if (args.Scopes == null) throw new ArgumentException("putConnection: scopes must be a list of strings");
        var c = new StoredConnection
        {
            AgentId = args.AgentId!, Provider = args.Provider!, ConnectionId = connectionId, AccessToken = args.AccessToken!, ExpiresAt = args.ExpiresAt,
            Scopes = new List<string>(args.Scopes),
            Authority = new ConnectionAuthority
            {
                Provider = args.Provider!, Principal = args.Principal!, Scopes = new List<string>(args.AuthorityScopes ?? args.Scopes), Audience = args.Audience,
            },
            CreatedAt = _now(), UseCount = 0, RefreshToken = args.RefreshToken,
        };
        StoreSet(c);
        return c;
    }

    /// <summary>Resolve a FRESH access token iff (a) <paramref name="pcActn"/> verifies against the connection's bound principal and (b) the capability chain's grant
    /// covers the requested provider + scopes. Refreshes a stale token when a refresh token is present. INSECURE BY NATURE: the caller receives a bearer credential, so
    /// this is disabled unless the vault was built with InsecureBearerRelease; prefer <see cref="ProxyCall"/>.</summary>
    public ConnectionToken GetConnectionToken(object? pcActn, GetConnectionTokenArgs args)
    {
        if (!_insecureBearerRelease) throw new BearerReleaseDisabledError();
        var a = Authorize(pcActn, args.Provider, args.ConnectionId, args.Scopes, false, null);
        var (token, refreshed) = FreshToken(a);
        var done = RecordUse(a, token);
        IssueReceipt(pcActn, a, "bearer", null, null, "released", done.Scopes);
        var exp = JsX.NumOf(JsX.At(pcActn, "exp"));
        return new ConnectionToken
        {
            Provider = a.Provider, ConnectionId = a.ConnectionId, AccessToken = done.AccessToken, Scopes = new List<string>(done.Scopes),
            // derived mode: the release never outlives the action that asked for it
            ExpiresAt = a.Action != null && exp is double e && double.IsFinite(e) ? Math.Min(done.ExpiresAt, e) : done.ExpiresAt,
            Refreshed = refreshed,
        };
    }

    /// <summary>Proxy mode. The vault makes the outbound call itself: verify the PCActn and the pinned, CONFIRMED action; derive the scopes from the action; map the request
    /// back to the action's parameters and require paramsDigest to equal the PCActn's signed params_digest; spend the action (replay guard); attach the token; make the call
    /// without following redirects; sign a receipt linking the release to the effect.</summary>
    public ProxyResult ProxyCall(object? pcActn, ProxyRequest request, ProxyCallArgs args)
    {
        if (_actions == null) throw new InvalidOperationException("proxyCall requires the vault to be constructed with `actions`");
        if (_proxyFetch == null) throw new InvalidOperationException("proxyCall requires the vault to be constructed with `proxyFetch`");
        var sendHeaders = ConnectProxy.CheckProxyHeaders(request.Headers?.ToDictionary(e => e.Key, e => (object?)e.Value), _proxyHeaders); // before anything is spent
        var a = Authorize(pcActn, args.Provider, args.ConnectionId, args.Scopes, true, request);
        var (token, _) = FreshToken(a);
        var done = RecordUse(a, token);
        var headers = new Dictionary<string, string>(sendHeaders) { ["authorization"] = "Bearer " + done.AccessToken };
        var reqDigest = ConnectProxy.OutboundRequestDigest(request.Method, request.Url, sendHeaders, request.Body);
        ProxyResponse response;
        try { response = _proxyFetch(request.Method, request.Url, headers, request.Body); }
        catch (Exception)
        {
            IssueReceipt(pcActn, a, "proxy", reqDigest, null, "failed", done.Scopes);
            throw new ProxyFailedError("the outbound call failed before a response");
        }
        long size = response.Body == null ? long.MaxValue : Encoding.UTF8.GetByteCount(response.Body);
        var receipt = IssueReceipt(pcActn, a, "proxy", reqDigest, response.Status, "executed", done.Scopes);
        if (size > _maxProxyResponseBytes) throw new ProxyFailedError("the response is larger than maxProxyResponseBytes (the call was made and the action is spent)");
        // the credential must never travel back: a response header or body that echoes it is redacted
        var body = response.Body!.Replace(done.AccessToken, "[redacted]", StringComparison.Ordinal);
        var rh = new Dictionary<string, string>();
        if (response.Headers != null)
            foreach (var (k, v) in response.Headers)
                if (k.ToLowerInvariant() != "set-cookie") rh[k] = (v ?? "").Replace(done.AccessToken, "[redacted]", StringComparison.Ordinal);
        return new ProxyResult { Response = new ProxyResponse(response.Status, rh, body), Receipt = receipt };
    }

    sealed class Authz
    {
        public string AgentId = "", Provider = "", ConnectionId = "";
        public StoredConnection Connection = null!;
        public List<string> Requested = new();
        public long Now;
        public VaultAction? Action;
    }

    static object? Act(object? pcActn, string key) => JsX.At(JsX.At(pcActn, "action"), key);

    /// <summary>Steps 1-5b of a release: resolve, anchor and verify, revoke, bind, derive scopes, least-privilege, spend. Shared by both release modes.</summary>
    Authz Authorize(object? pcActn, string provider, string? connIdArg, List<string>? scopesArg, bool needAction, ProxyRequest? request)
    {
        var connectionId = connIdArg ?? _defaultConnectionId;

        var chainO = JsX.At(pcActn, "cap_chain");
        if (chainO is not L chain || chain.Count == 0) throw new NotAuthorizedError("PCActn has no capability chain");
        var leaf = chain[^1];
        var root = chain[0];
        var holderV = JsX.At(leaf, "holder");
        var agentId = holderV as string ?? JsX.Str(holderV); // a non-string holder is looked up by its text, as the reference's key template does

        // 1. Resolve the connection: it carries the trust anchor (bound principal), so it is looked up before verification is anchored.
        var connection = StoreGet(new ConnectionKey(agentId, provider, connectionId)) ?? throw new UnknownConnectionError(agentId, provider, connectionId);

        // 2. Anchor + verify. The chain must be rooted at the connection's bound principal, else a self-minted chain would verify against itself.
        var issuerV = JsX.At(root, "issuer");
        if (!(issuerV is string iss && iss == connection.Authority.Principal)) throw new NotAuthorizedError("capability chain is not rooted at the connection's bound principal");
        if (root is not D rootD) throw new NotAuthorizedError("PCActn capability chain is malformed");
        long nowMs = _now();
        var aud = connection.Authority.Audience ?? _audience;
        // The root comes from the presented artifact, so a non-ed25519 root verifies ONLY under a pin for its issuer. A null audience is the deliberate opt-out ("accept any").
        var audience = aud ?? (JsX.At(pcActn, "aud") as string) ?? "";
        var verdict = Pca.VerifyPcactnCore(pcActn, rootD, nowMs, audience, null, null, null, null, new PlanRootPolicy(_authorizedPlanRoots, _insecureSkipPlanRootCheck));
        string? why = verdict.Allow ? null : (string.IsNullOrEmpty(verdict.Reason) ? "rejected" : verdict.Reason);
        if (why == null)
        {
            // grantFromArtifact: the core above trusts the presented root as the verifier's own grant, so the root-pinning rules of an artifact-lifted grant run here.
            bool classical = !rootD.TryGetValue("alg", out var algV) || algV == null || (algV is string alg && alg == "ed25519");
            if (_pqPins != null && classical && _pqPins.ContainsKey(iss)) why = "pq_pin: the grant issuer is pinned to a post-quantum key; a classical grant is refused";
            else if (!classical)
            {
                var (cwhy, cok) = Pca.VerifyChain(chain, iss, true, null, _pqPins, null);
                if (!cok) why = "cap_chain: " + cwhy;
            }
        }
        if (why != null) throw new NotAuthorizedError("PCActn verification failed: " + why, verdict.Checks);

        // 2b. Revocation. No source configured means no check (opt in; strict makes it mandatory).
        if (_isRevoked != null)
        {
            bool revoked;
            try { revoked = _isRevoked(pcActn); }
            catch (Exception) { throw new NotAuthorizedError("revocation source unavailable"); }
            if (revoked) throw new NotAuthorizedError("the capability chain is revoked");
        }

        // 3. Bind the action. Derived mode: the verb resolves to a pinned, CONFIRMED action for this provider and the scopes come from that action.
        // Legacy mode: the action is a generic token-use action for this provider.
        VaultAction? action = null;
        if (_actions != null)
        {
            var verbV = Act(pcActn, "verb");
            var verb = JsX.Str(verbV);
            action = _actions(verb);
            if (action == null || action.Verb == null || !(verbV is string vs && vs == action.Verb)) throw new UnknownActionError(verb);
            if (!action.Confirmed) throw new UnconfirmedActionError(verb);
            if (action.Provider != provider) throw new NotAuthorizedError($"the action '{verb}' is not for provider '{provider}'");
            if (action.ScopesMin == null || action.ScopesMin.Count == 0) throw new NotAuthorizedError($"the action '{verb}' declares no upstream scopes (nothing to release)");
        }
        else if (needAction) throw new UnknownActionError(JsX.Str(Act(pcActn, "verb")));
        else if (_requireActionBinding)
        {
            var expectedResource = _resourceFor(provider, connectionId);
            var resV = Act(pcActn, "resource");
            if (!(resV is string rs && rs == expectedResource))
                throw new NotAuthorizedError($"PCActn action resource '{JsX.Str(resV)}' is not for this connection (expected '{expectedResource}')");
            var vbV = Act(pcActn, "verb");
            if (_useVerb != null && !(vbV is string vb && vb == _useVerb))
                throw new NotAuthorizedError($"PCActn action verb '{JsX.Str(vbV)}' is not a connection-use verb (expected '{_useVerb}')");
        }

        // 4. Authority coverage. null => the capability grants nothing for this provider.
        var granted = ConnectAuthority.GrantedOAuthScopes(chain, provider) ?? throw new NotAuthorizedError($"capability grants no authority for provider '{provider}'");

        // 5. Least-privilege. Legacy: requested scopes default to the connection's bound authority scopes. Derived: they ARE the action's scopes_min
        // (a caller may ask for fewer, never more), and the stored connection must hold them.
        List<string> requested;
        if (action != null)
        {
            var min = new List<string>(action.ScopesMin);
            requested = scopesArg ?? min;
            var beyond = requested.Where(s => !min.Contains(s)).ToList();
            if (beyond.Count > 0) throw new ScopeExceededError(provider, requested, min, beyond);
            var unheld = min.Where(s => !connection.Scopes.Contains(s) || !connection.Authority.Scopes.Contains(s)).ToList();
            if (unheld.Count > 0) throw new ScopeExceededError(provider, min, connection.Scopes, unheld);
            // a bare bearer token cannot be narrowed after issue: it may carry nothing beyond the action's scopes (use a connection per action)
            if (!needAction)
            {
                var extra = connection.Scopes.Where(s => !min.Contains(s)).ToList();
                if (extra.Count > 0) throw new ScopeExceededError(provider, min, connection.Scopes, extra);
            }
            var ungranted = min.Where(s => !granted.Contains(s)).ToList();
            if (ungranted.Count > 0) throw new ScopeExceededError(provider, min, granted.ToList(), ungranted);
        }
        else requested = scopesArg ?? connection.Authority.Scopes;
        var missingScopes = requested.Where(s => !granted.Contains(s)).ToList();
        if (missingScopes.Count > 0) throw new ScopeExceededError(provider, requested, granted.ToList(), missingScopes);

        // 5a. Proxy mode: the outbound request must re-derive EXACTLY the params the PCActn signed.
        if (needAction && action != null)
        {
            if (request == null || action.Extract == null) throw new RequestMismatchError("the action has no request extractor: proxy mode cannot bind the outbound request");
            D ps;
            try { ps = action.Extract(request.ToJson()); }
            catch (RequestMismatchError) { throw; }
            catch (Exception) { throw new RequestMismatchError("the outbound request could not be mapped to the action parameters"); }
            string d;
            try { d = Pca.ParamsDigest(ps); }
            catch (Exception) { throw new RequestMismatchError("the outbound request parameters are not canonical"); }
            if (!(Act(pcActn, "params_digest") is string pd && pd == d)) throw new RequestMismatchError("the outbound request does not carry the parameters the PCActn signed");
        }

        // 5b. One-time use, last of the authorization checks so a refused request does not burn the action.
        if (_replay != null)
        {
            var rv = ConnectReplayGuard.Guard(_replay, pcActn, JsX.At(pcActn, "aud") as string, nowMs);
            if (!rv.Ok) throw new NotAuthorizedError("replay guard refused the action: " + rv.Reason);
        }
        return new Authz { AgentId = agentId, Provider = provider, ConnectionId = connectionId, Connection = connection, Requested = requested, Now = nowMs, Action = action };
    }

    /// <summary>Step 6: refresh a stale token, else use it as is. A token whose expiry is not a finite number can never be shown fresh.</summary>
    (StoredConnection Token, bool Refreshed) FreshToken(Authz a)
    {
        var connection = a.Connection;
        if (!double.IsFinite(connection.ExpiresAt) || connection.ExpiresAt - a.Now <= _expiryLeewayMs)
        {
            if (connection.RefreshToken == null) throw new ExpiredNoRefreshError(a.Provider, a.ConnectionId);
            var flightKey = a.AgentId + "\0" + a.Provider + "\0" + a.ConnectionId;
            var mine = new Lazy<Refreshed>(() => ConnectRefresh.RefreshConnection(new RefreshArgs
            {
                Connection = connection, Config = _providers.GetValueOrDefault(a.Provider), RefreshToken = connection.RefreshToken, Requested = a.Requested,
                Fetch = _fetch, Now = a.Now, DefaultTokenLifetimeMs = _defaultTokenLifetimeMs,
            }));
            var flight = _inflight.GetOrAdd(flightKey, mine);
            Refreshed updated;
            try { updated = flight.Value; }
            finally { if (ReferenceEquals(flight, mine)) _inflight.TryRemove(new KeyValuePair<string, Lazy<Refreshed>>(flightKey, mine)); }
            var t = connection.Copy();
            t.AccessToken = updated.AccessToken;
            t.RefreshToken = updated.RefreshToken;
            t.ExpiresAt = updated.ExpiresAt;
            t.Scopes = new List<string>(updated.Scopes);
            return (t, true);
        }
        return (connection, false);
    }

    /// <summary>Step 7: record usage and persist.</summary>
    StoredConnection RecordUse(Authz a, StoredConnection token)
    {
        var t = token.Copy();
        t.LastUsedAt = a.Now;
        t.UseCount = token.UseCount + 1;
        StoreSet(t);
        return t;
    }

    D? IssueReceipt(object? pcActn, Authz a, string mode, string? requestDigest, int? httpStatus, string outcome, List<string> scopes)
    {
        if (_receipts == null) return null;
        var sorted = new List<string>(scopes);
        sorted.Sort(StringComparer.Ordinal);
        var body = new D
        {
            ["v"] = new Num("1"), ["kind"] = "pca-release-receipt", ["action_digest"] = ConnectProxy.ReceiptActionDigest((D)pcActn!), ["provider"] = a.Provider,
            ["connection_id"] = a.ConnectionId, ["mode"] = mode, ["scopes_released"] = sorted.Cast<object?>().ToList(), ["request_digest"] = requestDigest,
            ["http_status"] = httpStatus == null ? null : new Num(httpStatus.Value.ToString(System.Globalization.CultureInfo.InvariantCulture)),
            ["outcome"] = outcome, ["ts"] = new Num(a.Now.ToString(System.Globalization.CultureInfo.InvariantCulture)),
        };
        var receipt = ConnectProxy.SignReleaseReceipt(body, _receipts.SecretKey);
        try { _receipts.Sink?.Invoke(receipt); }
        catch (Exception) { /* a failing sink must not turn a made call into an error the caller retries; the receipt is still returned */ }
        return receipt;
    }

    /// <summary>Remove a stored connection.</summary>
    public void DeleteConnection(string agentId, string provider, string? connectionId = null)
    {
        try { _store.Delete(new ConnectionKey(agentId, provider, connectionId ?? _defaultConnectionId)); }
        catch (VaultError) { throw; }
        catch (Exception) { throw new StoreError(); }
    }

    // The store's own error text is never passed on: it can quote a connection string or a record.
    StoredConnection? StoreGet(ConnectionKey key)
    {
        try { return _store.Get(key); }
        catch (VaultError) { throw; }
        catch (Exception) { throw new StoreError(); }
    }

    void StoreSet(StoredConnection c)
    {
        try { _store.Set(c); }
        catch (VaultError) { throw; }
        catch (Exception) { throw new StoreError(); }
    }
}

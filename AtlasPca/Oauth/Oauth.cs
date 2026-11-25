// OAuth 2.1 / MCP-authorization interop bridge for Proof-Carrying Authority: RFC 9728 protected resource metadata, MCP 401 challenges
// (RFC 6750 / RFC 7235), RFC 8707 resource indicators, `pca_grant` authorization details (RFC 9396) and scopes derived from the confirmed
// action. Pure: every function is I/O-free. Option bags are JSON trees (Dictionary) with the reference's option names (camelCase).
using System.Text;
using AtlasPca.Js;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Oauth;

public static class OAuthBridge
{
    public const string WellKnownOauthPrm = "/.well-known/oauth-protected-resource";
    const string WellKnownPcaPath = "/.well-known/pca-configuration";
    const string DefaultPcaHint = "send PCA-Action: <base64url PCActn> or JSON body {pcactn}";

    static object? Opt(D? o, string k) => o != null && o.TryGetValue(k, out var v) ? v : null;
    static bool Truthy(object? v) => v switch { null => false, bool b => b, string s => s.Length > 0, Num n => IntentJs.NumOf(n) is double d && d != 0 && !double.IsNaN(d), _ => true };
    static L Copy(object? v) => v is L l ? new L(l) : new L { v };
    static Num N(long v) => IntentJs.OfLong(v);

    /// <summary>RFC 9728 section 1.2: a resource identifier is an https URL with no fragment. The reason it is not one, or null.</summary>
    public static string? ResourceIdentifierProblem(object? resource)
    {
        if (resource is not string s || s.Length == 0) return "resource identifier must be a non-empty string";
        var u = WhatwgUrl.TryParse(s);
        if (u == null) return "resource identifier is not an absolute URL";
        if (u.Scheme != "https") return "resource identifier must use the https scheme";
        if (s.Contains('#')) return "resource identifier must not contain a fragment";
        return null;
    }

    /// <summary>RFC 9728 section 3.1: the well-known path of a resource identifier (the suffix goes between host and path). Throws on an invalid identifier.</summary>
    public static string PrmPathForResource(string resource)
    {
        var problem = ResourceIdentifierProblem(resource);
        if (problem != null) throw new ArgumentException("prmPathForResource: " + problem);
        var u = WhatwgUrl.TryParse(resource)!;
        var path = u.Pathname == "/" ? "" : u.Pathname;
        return WellKnownOauthPrm + path + u.Search;
    }

    /// <summary>The absolute metadata URL of a resource identifier (the `resource_metadata` value).</summary>
    public static string PrmUrlForResource(string resource)
    {
        var path = PrmPathForResource(resource);
        return WhatwgUrl.TryParse(resource)!.Origin + path;
    }

    /// <summary>The PCA discovery document of the reference's buildDiscoveryDocument (the members the bridge forwards).</summary>
    static D BuildDiscovery(object? audience, D opts)
    {
        if (audience is not string a || a.Length == 0) throw new ArgumentException("buildDiscoveryDocument: audience is required");
        var d = new D
        {
            ["audience"] = a,
            ["pca_versions"] = Opt(opts, "pcaVersions") ?? new L { N(2) },
            ["signature_suites"] = Opt(opts, "signatureSuites") ?? new L { "ed25519", "ml-dsa-65", "hybrid-ed25519-ml-dsa-65" },
            ["action_header"] = Opt(opts, "actionHeader") ?? "PCA-Action",
            ["required_checks"] = Opt(opts, "requiredChecks") ?? new L { "counter_format", "replay", "revocation", "plan_root_authorized", "audience", "validity", "grant_ref_bound" },
        };
        if (Truthy(Opt(opts, "endpoints"))) d["endpoints"] = Opt(opts, "endpoints");
        if (Truthy(Opt(opts, "trustedRoots"))) d["trusted_roots"] = Opt(opts, "trustedRoots");
        if (Truthy(Opt(opts, "metadata"))) d["metadata"] = Opt(opts, "metadata");
        return d;
    }

    /// <summary>RFC 9728: the Protected Resource Metadata document served at WellKnownOauthPrm. Throws on an empty or (unless `strict` is false) invalid `resource`.</summary>
    public static D ProtectedResourceMetadata(D opts)
    {
        if (Opt(opts, "resource") is not string resource || resource.Length == 0)
            throw new ArgumentException("protectedResourceMetadata: `resource` (the RS id = PCActn audience) is required");
        if (Opt(opts, "strict") is not false)
        {
            var problem = ResourceIdentifierProblem(resource);
            if (problem != null) throw new ArgumentException("protectedResourceMetadata: " + problem);
        }
        var discovery = BuildDiscovery(resource, opts);
        var cut = resource.IndexOf('?');
        var pcaEndpoint = Opt(opts, "pcaConfigurationEndpoint") ?? ((cut < 0 ? resource : resource[..cut]).TrimEnd('/') + WellKnownPcaPath);
        var doc = new D
        {
            ["resource"] = resource,
            ["bearer_methods_supported"] = Opt(opts, "bearerMethodsSupported") ?? new L { "header" },
            ["pca_action_header"] = discovery["action_header"],
            ["pca_signature_suites"] = Copy(discovery["signature_suites"]),
            ["pca_versions"] = Copy(discovery["pca_versions"]),
            ["pca_configuration_endpoint"] = pcaEndpoint,
            ["pca"] = discovery,
        };
        if (Truthy(Opt(opts, "authorizationServers"))) doc["authorization_servers"] = Copy(Opt(opts, "authorizationServers"));
        if (Truthy(Opt(opts, "resourceDocumentation"))) doc["resource_documentation"] = Opt(opts, "resourceDocumentation");
        if (Truthy(Opt(opts, "scopesSupported"))) doc["scopes_supported"] = Copy(Opt(opts, "scopesSupported"));
        if (Truthy(Opt(opts, "resourceName"))) doc["resource_name"] = Opt(opts, "resourceName");
        if (Truthy(Opt(opts, "resourceSigningAlgValuesSupported"))) doc["resource_signing_alg_values_supported"] = Copy(Opt(opts, "resourceSigningAlgValuesSupported"));
        if (Truthy(Opt(opts, "authorizationDetailsTypesSupported"))) doc["authorization_details_types_supported"] = Copy(Opt(opts, "authorizationDetailsTypesSupported"));
        return doc;
    }

    static bool AllStrings(object? v) => v is L l && l.All(x => x is string);

    /// <summary>Validate and narrow an untrusted value into a metadata document. Throws on anything malformed. <paramref name="parseOpts"/>: expectedResource, strict.</summary>
    public static D ParseProtectedResourceMetadata(object? value, D? parseOpts = null)
    {
        const string P = "parseProtectedResourceMetadata: ";
        if (value is not D v) throw new ArgumentException(P + (value is L ? "missing `resource`" : "not an object"));
        if (Opt(v, "resource") is not string resource || resource.Length == 0) throw new ArgumentException(P + "missing `resource`");
        if (!AllStrings(Opt(v, "bearer_methods_supported"))) throw new ArgumentException(P + "bearer_methods_supported must be a string[]");
        if (Opt(v, "pca_action_header") is not string header || header.Length == 0) throw new ArgumentException(P + "missing pca_action_header");
        if (!AllStrings(Opt(v, "pca_signature_suites"))) throw new ArgumentException(P + "pca_signature_suites must be a string[]");
        if (Opt(v, "pca_versions") is not L versions || !versions.All(n => n is Num)) throw new ArgumentException(P + "pca_versions must be a number[]");
        if (Opt(v, "pca") is not D pca) throw new ArgumentException(P + "missing embedded `pca` discovery document");
        if (Opt(pca, "audience") is not string audience || audience.Length == 0) throw new ArgumentException(P + "embedded pca.audience is required");
        var hasExpected = parseOpts != null && parseOpts.ContainsKey("expectedResource");
        var expected = Opt(parseOpts, "expectedResource");
        if (hasExpected)
        {
            if (!Equals(resource, expected)) throw new ArgumentException(P + "`resource` does not match the expected resource identifier");
            if (!Equals(audience, expected)) throw new ArgumentException(P + "embedded pca.audience does not match the expected resource identifier");
        }
        var methods = (L)Opt(v, "bearer_methods_supported")!;
        if (Opt(parseOpts, "strict") is not false)
        {
            if (!hasExpected) throw new ArgumentException(P + "expectedResource is required (RFC 9728 section 3.3); pass strict: false to skip");
            var problem = ResourceIdentifierProblem(resource);
            if (problem != null) throw new ArgumentException(P + problem);
            if (!methods.All(m => m as string is "header" or "body" or "query")) throw new ArgumentException(P + "bearer_methods_supported has a value outside header/body/query");
        }
        var doc = new D
        {
            ["resource"] = resource,
            ["bearer_methods_supported"] = methods,
            ["pca_action_header"] = header,
            ["pca_signature_suites"] = Opt(v, "pca_signature_suites"),
            ["pca_versions"] = versions,
            ["pca"] = pca,
        };
        if (Opt(v, "pca_configuration_endpoint") is string ce) doc["pca_configuration_endpoint"] = ce;
        if (AllStrings(Opt(v, "authorization_servers"))) doc["authorization_servers"] = Opt(v, "authorization_servers");
        if (Opt(v, "resource_documentation") is string rd) doc["resource_documentation"] = rd;
        if (AllStrings(Opt(v, "scopes_supported"))) doc["scopes_supported"] = Opt(v, "scopes_supported");
        if (Opt(v, "resource_name") is string rn) doc["resource_name"] = rn;
        if (AllStrings(Opt(v, "resource_signing_alg_values_supported"))) doc["resource_signing_alg_values_supported"] = Opt(v, "resource_signing_alg_values_supported");
        return doc;
    }

    /// <summary>A value destined for a quoted auth-param (RFC 7235): a quote, backslash or control character is refused (header injection).</summary>
    static string QuotedParam(string value)
    {
        foreach (var c in value) if (c == '"' || c == '\\' || c <= 0x1f || c == 0x7f) throw new ArgumentException("pca-oauth: WWW-Authenticate parameter value may not contain a quote or newline");
        return value;
    }

    /// <summary>The `pca_need` value: the unpadded base64url of the strict canonical JSON of a validated need (throws on a malformed or over-long need).</summary>
    static string EncodePcaNeed(object? need)
    {
        var code = A2a.NeedError(need);
        if (code != null) throw new ArgumentException($"encodePcaNeed: malformed need ({code})");
        var enc = Pca.B64u(Encoding.UTF8.GetBytes(Pca.Canonicalize(need)));
        if (enc.Length > 2048) throw new ArgumentException("encodePcaNeed: the need is too large for a header");
        return enc;
    }

    /// <summary>The WWW-Authenticate value of a 401: `Bearer resource_metadata=...` plus (by default) the PCA challenge. <paramref name="opts"/>: error, errorDescription, scope, pcaNeed, includePca, pcaChallenge, realm, hint.</summary>
    public static string WwwAuthenticate(object? prmUrl, D? opts = null)
    {
        if (prmUrl is not string url || url.Length == 0) throw new ArgumentException("wwwAuthenticate: prmUrl is required");
        var bearer = new List<string> { $"resource_metadata=\"{QuotedParam(url)}\"" };
        if (Opt(opts, "error") is string e && e.Length > 0) bearer.Add($"error=\"{QuotedParam(e)}\"");
        if (Opt(opts, "errorDescription") is string ed && ed.Length > 0) bearer.Add($"error_description=\"{QuotedParam(ed)}\"");
        if (Opt(opts, "scope") is string sc && sc.Length > 0) bearer.Add($"scope=\"{QuotedParam(sc)}\"");
        if (Truthy(Opt(opts, "pcaNeed"))) bearer.Add($"pca_need=\"{QuotedParam(EncodePcaNeed(Opt(opts, "pcaNeed")))}\"");
        var challenges = new List<string> { "Bearer " + string.Join(", ", bearer) };
        var includePca = Opt(opts, "includePca") ?? true;
        if (Opt(opts, "pcaChallenge") is string pc && pc.Length > 0)
        {
            foreach (var c in pc) if ((c <= 0x08) || (c >= 0x0a && c <= 0x1f) || c == 0x7f) throw new ArgumentException("pca-oauth: pcaChallenge may not contain control characters or newlines");
            challenges.Add(pc);
        }
        else if (Truthy(includePca))
        {
            var realm = Opt(opts, "realm") ?? "pca";
            var hint = Opt(opts, "hint") ?? DefaultPcaHint;
            var pca = $"PCA realm=\"{QuotedParam((string)realm)}\"";
            if (Truthy(hint)) pca += $", hint=\"{QuotedParam((string)hint)}\"";
            challenges.Add(pca);
        }
        return string.Join(", ", challenges);
    }

    static D Result(bool ok, string? matched = null, string? reason = null)
    {
        var r = new D { ["ok"] = ok };
        if (matched != null) r["matched"] = matched;
        if (reason != null) r["reason"] = reason;
        return r;
    }

    /// <summary>RFC 8707: an incoming `resource` indicator (one value or the array form) against this resource server's audience (exact match of any value).</summary>
    public static D CheckResourceIndicator(object? resourceParam, object? expectedAudience)
    {
        if (expectedAudience is not string aud || aud.Length == 0) throw new ArgumentException("checkResourceIndicator: expectedAudience is required");
        if (resourceParam == null) return Result(false, reason: "no resource indicator presented");
        var values = resourceParam is L l ? l : new L { resourceParam };
        if (values.Count == 0) return Result(false, reason: "empty resource indicator");
        foreach (var r in values)
        {
            if (r is not string s || s.Length == 0) continue;
            if (s == aud) return Result(true, matched: s);
        }
        return Result(false, reason: $"resource indicator {JsJson.Stringify(values)} does not match audience {JsJson.Quote(aud)}");
    }

    /// <summary>Token-audience binding: the token's `aud` is, or contains, exactly this resource identifier; anything else fails closed.</summary>
    public static D CheckTokenAudience(object? aud, object? expectedResource)
    {
        if (expectedResource is not string res || res.Length == 0) throw new ArgumentException("checkTokenAudience: expectedResource is required");
        if (aud == null) return Result(false, reason: "token has no audience");
        var values = aud is L l ? l : new L { aud };
        if (values.Count == 0) return Result(false, reason: "token has an empty audience");
        if (values.Any(a => a is string s && s == res)) return Result(true, matched: res);
        return Result(false, reason: $"token audience {JsJson.Stringify(aud)} does not include resource {JsJson.Quote(res)}");
    }

    /// <summary>The path and body to serve the RFC 9728 document: {path, body, rfcPath}.</summary>
    public static D OauthDiscoveryHandler(D opts)
    {
        var body = ProtectedResourceMetadata(opts);
        var path = ResourceIdentifierProblem(Opt(opts, "resource")) == null ? PrmPathForResource((string)Opt(opts, "resource")!) : WellKnownOauthPrm;
        return new D { ["path"] = path, ["body"] = body, ["rfcPath"] = path };
    }

    /// <summary>The complete MCP/OAuth 401: {status, headers, body}.</summary>
    public static D McpUnauthorized(object? prmUrl, D? opts = null)
    {
        var body = new D { ["error"] = Opt(opts, "error") ?? "invalid_request", ["resource_metadata"] = prmUrl };
        if (Opt(opts, "errorDescription") is string ed && ed.Length > 0) body["error_description"] = ed;
        return new D
        {
            ["status"] = N(401),
            ["headers"] = new D { ["WWW-Authenticate"] = WwwAuthenticate(prmUrl, opts) },
            ["body"] = body,
        };
    }

    /// <summary>Upgrade a deny result's 401: its WWW-Authenticate also carries the `resource_metadata` pointer; every other field is kept.</summary>
    public static D UpgradeUnauthorizedChallenge(D result, object? prmUrl, D? opts = null)
    {
        var merged = opts == null ? new D() : new D(opts);
        if (Opt(result, "wwwAuthenticate") is string existing && existing.Length > 0) merged["pcaChallenge"] = existing;
        var header = WwwAuthenticate(prmUrl, merged);
        var o = new D(result) { ["wwwAuthenticate"] = header };
        return o;
    }

    // ---- pca_grant (RFC 9396 authorization details) ----

    /// <summary>Build a validated `pca_grant` detail from {chainIds, chainRef?, bundleRevision?, locations?}. Throws on anything the profile refuses.</summary>
    public static D BuildPcaGrantDetail(D o)
    {
        var ids = ((L)Opt(o, "chainIds")!).Select(x => (string)x!).ToList();
        var d = new D { ["type"] = PcaGrant.Type, ["chain_digest"] = PcaGrant.ChainDigest(ids), ["chain_len"] = N(ids.Count) };
        if (o.ContainsKey("chainRef")) d["chain_ref"] = o["chainRef"];
        if (o.ContainsKey("bundleRevision")) d["bundle_revision"] = o["bundleRevision"];
        if (o.ContainsKey("locations")) d["locations"] = Copy(o["locations"]);
        var code = PcaGrant.Validate(d);
        if (code != null) throw new ArgumentOutOfRangeException(nameof(o), $"buildPcaGrantDetail: refused ({code})");
        return d;
    }

    /// <summary>The form-encoded value of the `authorization_details` request parameter.</summary>
    public static string PcaGrantRequestParam(L details) => JsJson.EncodeUriComponent(JsJson.Stringify(details));

    /// <summary>Gate an access token carrying `pca_grant` details from {authorizationDetails, resource, chainIds, proofVerified}: allow only for well-formed details naming a prefix of the presented chain and this resource, with a verified per-action proof.</summary>
    public static D AuthorizePcaGrantToken(D o)
    {
        var parsed = PcaGrant.Parse(Opt(o, "authorizationDetails"));
        if (parsed.Code != null) return Deny(401, "invalid_token", parsed.Code);
        var ids = ((L)Opt(o, "chainIds")!).Select(x => (string)x!).ToList();
        var r = PcaGrant.Check(parsed.Details, (string)Opt(o, "resource")!, ids, Opt(o, "proofVerified") is true);
        if (r.Code == null) return new D { ["allow"] = true, ["detail"] = parsed.Details[r.Index] };
        var wrong = r.Code == "wrong_location";
        return Deny(wrong ? 403 : 401, wrong ? "insufficient_scope" : "invalid_token", r.Code);
    }

    static D Deny(long status, string error, string code) => new() { ["allow"] = false, ["status"] = N(status), ["error"] = error, ["code"] = code };

    // ---- scopes derived from the confirmed action ----

    static bool ScopeToken(string s)
    {
        if (s.Length == 0) return false;
        foreach (var c in s) if (!(c == 0x21 || (c >= 0x23 && c <= 0x5b) || (c >= 0x5d && c <= 0x7e))) return false;
        return true;
    }

    static D Refuse(string code) => new() { ["ok"] = false, ["code"] = code };

    /// <summary>The `scope` (and `resource`) an OAuth client should request for one action: its confirmed `upstream.scopes_min`, checked against `granted`. Anything unconfirmed, unknown, mismatched or outside the grant is a refusal. <paramref name="o"/>: provider, granted?, resource?.</summary>
    public static D OauthScopeForAction(object? action, D o)
    {
        if (action is null or not (D or L)) return Refuse("unknown_action");
        if (action is not D a || Opt(a, "confirmed") is not true) return Refuse("unconfirmed");
        var up = Opt(a, "upstream") as D;
        if (!(Opt(up, "provider") is string p && o.TryGetValue("provider", out var want) && want is string w && p == w)) return Refuse("provider_mismatch");
        if (Opt(up, "scopes_min") is not L min || min.Count == 0) return Refuse("no_scopes");
        if (!min.All(s => s is string t && t.Length <= 256 && ScopeToken(t))) return Refuse("bad_scope");
        var scopes = min.Select(s => (string)s!).Distinct(StringComparer.Ordinal).OrderBy(s => s, StringComparer.Ordinal).ToList();
        if (o.TryGetValue("granted", out var g) && g != null)
        {
            var set = new HashSet<object?>(((L)g).ToList());
            if (!scopes.All(s => set.Contains(s))) return Refuse("exceeds_grant");
        }
        var res = new D { ["ok"] = true, ["scope"] = string.Join(" ", scopes), ["scopes"] = scopes.Select(s => (object?)s).ToList() };
        if (o.ContainsKey("resource")) res["resource"] = o["resource"];
        return res;
    }
}

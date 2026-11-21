using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Gnap;

/// <summary>
/// A GNAP (RFC 9635) bridge for Proof-Carrying Authority: the Agent-GNAP profile. Mirrors the TypeScript package's main module
/// (access-rights normalization and mapping onto policy predicates, containment and clamping, grant request to capability,
/// action authorization, bound tokens, the <c>jwsd</c> detached-JWS proof, and continuation / step-up). Every verify path fails
/// closed. Values are JSON trees (<c>Dictionary&lt;string, object?&gt;</c>, <c>List&lt;object?&gt;</c>, string, bool, <see cref="Num"/>,
/// null); secrets are 32-byte Ed25519 seeds given as <c>byte[]</c> or base64url text.
/// Deliberate difference from the reference: <see cref="GrantRequestToCapability"/> refuses an <c>issuerPublic</c> that is not the
/// public key of <c>issuerSecret</c> (the reference would sign a chain that can never verify).
/// </summary>
public static class Gnap
{
    public const string GnapGrantCaveat = "gnap_grant";
    public const string GnapAccessCaveat = "gnap_access";
    /// <summary>Upper bound on an accepted detached JWS string (adversarial-size guard).</summary>
    public const int MaxDetachedJwsChars = 8192;
    const string JwsdTyp = "gnap-binding-jwsd";
    const string GnapResourcePrefix = "gnap";

    /// <summary>An argument that is absent (JavaScript undefined): a request body (the proof then covers no content) or a holder override.</summary>
    public static readonly object Absent = GnapJs.Absent;

    /// <summary>The replay store of <see cref="VerifyGnapRequest"/>: <c>false</c> means the proof is fresh; any other value (or a throw) means it was already seen.</summary>
    public delegate object? SeenProof(string proofId, double expiresSec);

    // ---- small guards ----

    static string? AsEd25519(object? x) => x is string s && Pca.B64uDecode(s, 32) != null ? s : null;

    static byte[] SecretBytes(object? o) => o switch
    {
        byte[] b => b,
        string s => Pca.B64uDecode(s) ?? throw new GnapException("a secret key must be 32 bytes (bytes or base64url text)"),
        _ => throw new GnapException("a secret key must be 32 bytes (bytes or base64url text)"),
    };

    static EdKey EdOf(object? secret)
    {
        var seed = SecretBytes(secret);
        if (seed is not { Length: 32 }) throw new AtlasPca.Grants.CodedException("ERR_CRYPTO_INVALID_JWK", "Invalid JWK: the Ed25519 private key must be 32 bytes");
        return EdKey.FromSeed(seed);
    }

    static L? StrArr(object? u) => u is L l ? new L(l.Where(x => x is string)) : null;

    /// <summary>The PCA <c>resource</c> string for a GNAP (type, location) pair: the namespace actions are matched in.</summary>
    public static string GnapActionResource(string type, string location) => GnapResourcePrefix + ":" + type + ":" + location;

    // ---- access-rights normalization and mapping onto predicates ----

    static D? TryNormalizeAccessItem(object? item)
    {
        if (item is string s) return s.Length > 0 ? new D { ["type"] = s } : null;
        if (item is not D m) return null;
        if (m.GetValueOrDefault("type") is not string type || type.Length == 0) return null;
        var o = new D { ["type"] = type };
        if (StrArr(m.GetValueOrDefault("actions")) is { Count: > 0 } actions) o["actions"] = actions;
        if (StrArr(m.GetValueOrDefault("locations")) is { Count: > 0 } locations) o["locations"] = locations;
        if (StrArr(m.GetValueOrDefault("datatypes")) is { Count: > 0 } datatypes) o["datatypes"] = datatypes;
        if (m.GetValueOrDefault("identifier") is string id) o["identifier"] = id;
        if (StrArr(m.GetValueOrDefault("privileges")) is { Count: > 0 } privileges) o["privileges"] = privileges;
        return o;
    }

    /// <summary>Normalize an access array for issuance (throws on any malformed entry).</summary>
    public static L NormalizeAccess(object? items)
    {
        if (items is not L l) throw new GnapException("access must be an array");
        var o = new L();
        foreach (var item in l) o.Add(TryNormalizeAccessItem(item) ?? throw new GnapException("malformed access item (needs a non-empty string `type`)"));
        return o;
    }

    /// <summary>Total, fail-closed read of a stored access array (reading signed caveats). Skips malformed entries.</summary>
    static L ReadAccessArray(object? u)
    {
        var o = new L();
        if (u is not L l) return o;
        foreach (var item in l) if (TryNormalizeAccessItem(item) is { } n) o.Add(n);
        return o;
    }

    static L? NonEmpty(object? l) => l is L { Count: > 0 } x ? x : null;

    /// <summary>Map a GNAP access right onto PCA predicates (one per location): <c>type</c> namespaces the resource, <c>actions</c> become verbs,
    /// <c>locations</c> become resources, and <c>datatypes</c> / <c>identifier</c> become <c>where</c> conditions on the action's params. An absent
    /// <c>actions</c> / <c>locations</c> means "any".</summary>
    public static L AccessToPredicates(D access)
    {
        var actions = NonEmpty(access.GetValueOrDefault("actions"));
        var locs = NonEmpty(access.GetValueOrDefault("locations"));
        var locations = locs ?? new L { "*" };
        var where = new L();
        if (NonEmpty(access.GetValueOrDefault("datatypes")) is { } datatypes)
            where.Add(new D { ["field"] = "action.params.datatype", ["op"] = "in", ["value"] = new L(datatypes) });
        if (access.GetValueOrDefault("identifier") is string id)
            where.Add(new D { ["field"] = "action.params.identifier", ["op"] = "eq", ["value"] = id });
        var type = GnapJs.Str(GnapJs.Get(access, "type"));
        var o = new L();
        foreach (var loc in locations)
        {
            var p = new D { ["verb"] = actions != null ? new L(actions) : "*", ["resource"] = GnapActionResource(type, GnapJs.Str(loc)) };
            if (where.Count > 0) p["where"] = new L(where.Select(c => (object?)new D((D)c!)));
            o.Add(p);
        }
        return o;
    }

    static L AccessArrayToPredicates(L access)
    {
        var o = new L();
        foreach (var a in access) o.AddRange(AccessToPredicates((D)a!));
        return o;
    }

    // ---- containment ----

    static bool CoversStrings(L? sup, L? sub)
    {
        if (sup == null) return true; // issuer allows all
        if (sub == null) return false; // request wants all, issuer has a concrete set
        foreach (var s in sub) if (!sup.Any(x => GnapJs.StrictEq(x, s))) return false;
        return true;
    }

    static bool CoversLocations(L? sup, L? sub)
    {
        if (sup == null) return true;
        if (sub == null) return sup.Any(x => x is "*");
        foreach (var so in sub)
        {
            var s = (string)so!;
            bool any = false;
            foreach (var go in sup)
            {
                var g = (string)go!;
                if (g == s || g == "*" || (g.EndsWith('*') && s.StartsWith(g[..^1], StringComparison.Ordinal))) { any = true; break; }
            }
            if (!any) return false;
        }
        return true;
    }

    static L? Strings(object? l) => l as L;

    /// <summary>Does the issuer's granted right <paramref name="g"/> fully contain the requested right <paramref name="r"/>?</summary>
    public static bool AccessContains(D g, D r)
    {
        if (!GnapJs.StrictEq(g.GetValueOrDefault("type"), r.GetValueOrDefault("type"))) return false;
        if (!CoversStrings(Strings(g.GetValueOrDefault("actions")), Strings(r.GetValueOrDefault("actions")))) return false;
        if (!CoversLocations(Strings(g.GetValueOrDefault("locations")), Strings(r.GetValueOrDefault("locations")))) return false;
        if (!CoversStrings(Strings(g.GetValueOrDefault("datatypes")), Strings(r.GetValueOrDefault("datatypes")))) return false;
        if (r.ContainsKey("identifier") && g.ContainsKey("identifier") && !GnapJs.StrictEq(g["identifier"], r["identifier"])) return false;
        return true;
    }

    /// <summary>Is <paramref name="r"/> within the issuer's granted set <paramref name="G"/> (covered by at least one of its rights)?</summary>
    public static bool AccessWithin(L G, D r)
    {
        foreach (var g in G) if (AccessContains((D)g!, r)) return true;
        return false;
    }

    /// <summary>Split a requested access array into the subset within the issuer's authority and the rest: <c>{granted, dropped}</c>.</summary>
    public static D ClampAccess(L issuerGranted, L requested)
    {
        var granted = new L(); var dropped = new L();
        foreach (var r in requested) (AccessWithin(issuerGranted, (D)r!) ? granted : dropped).Add(r);
        return new D { ["granted"] = granted, ["dropped"] = dropped };
    }

    // ---- provenance caveats ----

    /// <summary>The root grant's GNAP provenance caveat's granted access, or null when there is none.</summary>
    static L? ReadGnapGrantAccess(object? root)
    {
        var env = Pca.ReadEnvelope(root);
        if (env == null || env.GetValueOrDefault("caveats") is not L cavs) return null;
        D? cv = null;
        foreach (var c in cavs) if (c is D cm && cm.GetValueOrDefault("type") is GnapGrantCaveat) { cv = cm; break; }
        if (cv == null) return null;
        if (cv.GetValueOrDefault("client_id") is not string || cv.GetValueOrDefault("request_digest") is not string) return null;
        return ReadAccessArray(cv.GetValueOrDefault("granted_access"));
    }

    /// <summary>The EFFECTIVE granted access of a chain: the most-recent delegated hop's recorded rights, or (for a root-only grant) the root's
    /// recorded rights. Every hop is clamped to its issuer at issue time, so the leaf's rights are the narrowest.</summary>
    public static L GrantedAccessOf(object? chain)
    {
        if (chain is not L { Count: > 0 } ch) return new L();
        var leaf = ch[^1] ?? throw new ArgumentException("chain leaf is null");
        var cavs = GnapJs.Member(leaf, "caveats") as L ?? new L();
        for (int i = cavs.Count - 1; i >= 0; i--)
            if (cavs[i] is D cv && cv.GetValueOrDefault("type") is GnapAccessCaveat) return ReadAccessArray(cv.GetValueOrDefault("access"));
        return ReadGnapGrantAccess(ch[0]) ?? new L();
    }

    // ---- holder resolution ----

    /// <summary>Resolve the b64u Ed25519 holder key from a request's client key (or an explicit override; <see cref="Absent"/> for none).</summary>
    public static string ResolveHolder(object? req) => ResolveHolder(req, Absent);

    /// <summary>As above with an explicit holder override: <see cref="Absent"/> means none, a null is an override (and is refused).</summary>
    public static string ResolveHolder(object? req, object? holderOverride)
    {
        if (req == null) throw new GnapException("grant request is null");
        bool hasOverride = !ReferenceEquals(holderOverride, Absent);
        var client = GnapJs.Member(req, "client");
        var declared = client is D cd ? cd.GetValueOrDefault("key") : null;
        if (GnapJs.IsObject(declared))
        {
            var proof = GnapJs.Member(declared, "proof");
            var method = proof is string ? proof : proof is D pd ? pd.GetValueOrDefault("method") : null;
            if (method is not "jwsd")
                throw new GnapException("unsupported client key proof method: " + (method is string ms ? ms : "none") + " (only jwsd is supported)");
        }
        if (hasOverride)
        {
            var h = AsEd25519(holderOverride);
            if (h == null) throw new GnapException("holder override is not a canonical base64url Ed25519 public key");
            return h;
        }
        var key = client is D cd2 ? cd2.GetValueOrDefault("key") : null;
        if (GnapJs.IsObject(key))
        {
            var jwk = GnapJs.Member(key, "jwk");
            if (jwk is D jm && jm.GetValueOrDefault("kty") is "OKP" && jm.GetValueOrDefault("crv") is "Ed25519")
            {
                var x = AsEd25519(jm.GetValueOrDefault("x"));
                if (x != null) return x;
            }
        }
        throw new GnapException("cannot resolve holder: supply client.key.jwk (OKP/Ed25519) or a holder override");
    }

    /// <summary>The holder key, rendered as a GNAP JWK (for a bound access-token response).</summary>
    public static D HolderJwk(string holder) => new() { ["kty"] = "OKP", ["crv"] = "Ed25519", ["x"] = holder, ["use"] = "sig", ["alg"] = "EdDSA" };

    static L AccessOf(object? req)
    {
        if (GnapJs.Member(req, "access_token") is D at && at.GetValueOrDefault("access") is L access) return access;
        throw new GnapException("grant request must carry access_token.access (single-token request)");
    }

    static string RequestDigestOf(string holder, L granted, object? interact) =>
        Pca.HashCanonical(new D { ["d"] = "atlas-pca/gnap/request/v1", ["client_id"] = holder, ["access"] = granted, ["interact"] = interact });

    // ---- grant request -> PCA capability ----

    /// <summary>Convert a GNAP grant request into a PCA capability bound to the client key, ATTENUATED to never exceed the issuer. With no
    /// <c>parent</c> this MINTS a root grant whose policy-envelope predicates ARE the requested access rights; with a <c>parent</c> it DELEGATES a
    /// narrower hop, recording the (clamped) rights as an append-only <c>gnap_access</c> caveat. <paramref name="opts"/>: issuerSecret, issuerPublic,
    /// parent, issuerChain, clampToIssuer, holder, interacted, now, goal, riskPolicy, agentBinding, salt. Returns
    /// <c>{grant, chain, holder, grantedAccess, droppedAccess, provenance}</c>.</summary>
    public static D GrantRequestToCapability(object? req, D opts)
    {
        var holder = ResolveHolder(req, GnapJs.Get(opts, "holder"));
        var requested = NormalizeAccess(AccessOf(req));
        long now = opts.GetValueOrDefault("now") is { } nowO ? (long)Math.Floor(GnapJs.NumOf(nowO) ?? throw new GnapException("now is not a number")) : DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        bool interacted = opts.GetValueOrDefault("interacted") is true;
        var parent = opts.GetValueOrDefault("parent");
        bool delegated = GnapJs.Truthy(parent);

        L granted = requested, dropped = new L();
        object? issuerChain = null;
        if (delegated)
        {
            issuerChain = opts.GetValueOrDefault("issuerChain") ?? new L { parent };
            if (opts.GetValueOrDefault("clampToIssuer") is not false)
            {
                var split = ClampAccess(GrantedAccessOf(issuerChain), requested);
                granted = (L)split["granted"]!;
                dropped = (L)split["dropped"]!;
            }
        }
        var requestDigest = RequestDigestOf(holder, granted, GnapJs.Member(req, "interact"));
        var signer = EdOf(opts.GetValueOrDefault("issuerSecret"));

        if (delegated)
        {
            var provenance = new D
            {
                ["type"] = GnapAccessCaveat, ["access"] = granted, ["predicates"] = AccessArrayToPredicates(granted),
                ["request_digest"] = requestDigest, ["client_id"] = holder, ["ts"] = now,
            };
            var child = Issue.Delegate((D)parent!, holder, new L { provenance }, SuiteKey.Ed25519(signer), null);
            var chain = new L((L)issuerChain!) { child };
            return new D { ["grant"] = child, ["chain"] = chain, ["holder"] = holder, ["grantedAccess"] = granted, ["droppedAccess"] = dropped, ["provenance"] = provenance };
        }

        var prov = new D
        {
            ["type"] = GnapGrantCaveat, ["client_id"] = holder, ["granted_access"] = granted, ["request_digest"] = requestDigest,
            ["interacted"] = interacted, ["ts"] = now,
        };
        if (opts.GetValueOrDefault("issuerPublic") is not string ip || ip != signer.Id) throw new GnapException("issuerPublic is not the public key of issuerSecret");
        var goal = opts.GetValueOrDefault("goal") is { } g ? (string)g : "gnap:grant:" + holder;
        var envelope = new D
        {
            ["predicates"] = AccessArrayToPredicates(granted),
            ["caveats"] = new L { prov },
            ["agent_binding"] = opts.GetValueOrDefault("agentBinding") ?? new D(),
            ["risk_policy"] = opts.GetValueOrDefault("riskPolicy") ?? Issue.DefaultRiskPolicy(),
        };
        var salt = opts.GetValueOrDefault("salt");
        var minted = Issue.MintGrant(SuiteKey.Ed25519(signer), holder, null, envelope, goal, salt == null ? null : (string)salt);
        return new D { ["grant"] = minted.Grant, ["chain"] = new L { minted.Grant }, ["holder"] = holder, ["grantedAccess"] = granted, ["droppedAccess"] = dropped, ["provenance"] = prov };
    }

    // ---- action authorization ----

    static IReadOnlyDictionary<string, string>? PqPinsOf(D? opts) =>
        opts?.GetValueOrDefault("pqPins") is D m ? m.Where(e => e.Value is string).ToDictionary(e => e.Key, e => (string)e.Value!) : null;

    /// <summary>The reason a chain does not verify, or "" when it does.</summary>
    static string ChainReason(L chain, D? opts)
    {
        bool haveIssuer = opts != null && opts.ContainsKey("expectedRootIssuer");
        var (why, ok) = Pca.VerifyChain(chain, haveIssuer ? opts!["expectedRootIssuer"] : null, haveIssuer, null, PqPinsOf(opts), null);
        return ok ? "" : why;
    }

    /// <summary>The predicate evaluator's denial text (<c>evaluatePredicates(...).reason</c>), or null when the action is allowed.</summary>
    static string? DenialReason(object? predicates, D ctx)
    {
        if (Predicates.EvaluatePredicates(predicates, ctx)) return null;
        if (predicates is not L { Count: > 0 }) return "envelope grants no predicates";
        var a = ctx.GetValueOrDefault("action") as D ?? new D();
        var vr = IntentRevocation.JsText(a.GetValueOrDefault("verb"), a.ContainsKey("verb")) + " on " + IntentRevocation.JsText(a.GetValueOrDefault("resource"), a.ContainsKey("resource"));
        var limit = Predicates.FirstUnmetLimit(predicates, ctx);
        return limit != null ? limit + " not satisfied for " + vr : "no predicate permits " + vr;
    }

    /// <summary>Decide whether <paramref name="action"/> (verb, resource, optional params, reversibility_class) is authorized by a GNAP-issued
    /// capability chain. FAILS CLOSED. The chain must verify, the root policy envelope must permit the action AND every delegated hop's recorded
    /// <c>gnap_access</c> rights must permit it too. <paramref name="opts"/>: expectedRootIssuer, pqPins. Returns <c>{allowed, reason?}</c>.</summary>
    public static D AuthorizeGnapAction(object? chain, D action, D? opts = null)
    {
        if (chain is not L { Count: > 0 } ch) return new D { ["allowed"] = false, ["reason"] = "empty chain" };
        var vc = ChainReason(ch, opts);
        if (vc.Length > 0) return new D { ["allowed"] = false, ["reason"] = "capability chain invalid: " + vc };
        var env = Pca.ReadEnvelope(ch[0]);
        if (env == null) return new D { ["allowed"] = false, ["reason"] = "root grant carries no policy envelope" };

        var act = new D { ["verb"] = action.GetValueOrDefault("verb"), ["resource"] = action.GetValueOrDefault("resource") };
        if (action.ContainsKey("params")) act["params"] = action["params"];
        if (action.ContainsKey("reversibility_class")) act["reversibility_class"] = action["reversibility_class"];
        var ctx = new D { ["action"] = act };

        var preds = env.GetValueOrDefault("predicates");
        if (DenialReason(preds, ctx) is { } why)
            return new D { ["allowed"] = false, ["reason"] = "root authority denies: " + why };
        if (GnapJs.Member(ch[^1], "caveats") is L caveats)
        {
            foreach (var cv in caveats)
            {
                if (cv is not D cm || cm.GetValueOrDefault("type") is not GnapAccessCaveat) continue;
                var hopPreds = AccessArrayToPredicates(ReadAccessArray(cm.GetValueOrDefault("access")));
                if (DenialReason(hopPreds, ctx) is { } hopWhy) return new D { ["allowed"] = false, ["reason"] = "delegated hop denies: " + hopWhy };
            }
        }
        return new D { ["allowed"] = true };
    }

    // ---- bound token ----

    /// <summary>Encode a capability chain as a GNAP access-token <c>value</c>: base64url of the chain's JSON text (re-verified on use).</summary>
    public static string EncodeBoundToken(object? chain) => Pca.B64u(GnapJs.Utf8(GnapJs.Stringify(chain)));

    static bool StrOrAbsent(D m, string k) => !m.ContainsKey(k) || m[k] is string;

    static bool IsCapabilityShape(object? x) =>
        x is D m && m.GetValueOrDefault("id") is string && m.GetValueOrDefault("issuer") is string && m.GetValueOrDefault("holder") is string
        && m.GetValueOrDefault("body_digest") is string && m.GetValueOrDefault("sig") is string && m.GetValueOrDefault("caveats") is L
        && StrOrAbsent(m, "parent") && StrOrAbsent(m, "alg") && StrOrAbsent(m, "pq_pk") && StrOrAbsent(m, "pq_sig");

    static readonly UTF8Encoding StrictUtf8 = new(false, true);

    /// <summary>Total, fail-closed decode of a bound token back into a capability chain (null on any deviation).</summary>
    static L? DecodeBoundToken(string value)
    {
        try
        {
            var raw = Pca.B64uDecode(value);
            if (raw == null) return null;
            var text = StrictUtf8.GetString(raw); // TextDecoder (fatal, BOM not ignored): invalid UTF-8 is an error, a leading BOM is dropped
            if (text.Length > 0 && text[0] == '﻿') text = text[1..];
            if (Pca.ParseStrict(text) is not L parsed) return null;
            var chain = new L();
            foreach (var hop in parsed)
            {
                if (!IsCapabilityShape(hop)) return null;
                chain.Add(hop);
            }
            return chain;
        }
        catch (Exception) { return null; }
    }

    /// <summary>Render a (verified) PCA capability chain as a GNAP grant response with a bound access token. <paramref name="opts"/>: expiresIn,
    /// bearer, instanceId, manageUri, continue.</summary>
    public static D CapabilityToGrantResponse(object? chain, D? opts = null)
    {
        if (chain is not L { Count: > 0 } ch) throw new GnapException("capabilityToGrantResponse: empty chain");
        if (ch[^1] is not D leaf) throw new GnapException("capabilityToGrantResponse: malformed leaf");
        var o = opts ?? new D();
        var token = new D
        {
            ["value"] = EncodeBoundToken(chain),
            ["access"] = GrantedAccessOf(chain),
            ["key"] = o.GetValueOrDefault("bearer") is true ? (object)false : HolderJwk((string)leaf["holder"]!),
        };
        if (o.ContainsKey("expiresIn")) token["expires_in"] = o["expiresIn"];
        if (o.ContainsKey("manageUri")) token["manage"] = new D { ["uri"] = o["manageUri"] };
        var res = new D { ["access_token"] = token };
        if (o.ContainsKey("continue")) res["continue"] = o["continue"];
        if (o.ContainsKey("instanceId")) res["instance_id"] = o["instanceId"];
        return res;
    }

    /// <summary>Verify an incoming GNAP bound token, mapping it back to a PCA principal and capability. FAILS CLOSED: a token that is not a decodable
    /// chain, or whose chain does not verify (optionally against <c>expectedRootIssuer</c>), returns <c>{ok:false}</c>.</summary>
    public static D VerifyGnapToken(object? value, D? opts = null)
    {
        if (value is not string { Length: > 0 } v) return new D { ["ok"] = false, ["reason"] = "token value is empty" };
        var chain = DecodeBoundToken(v);
        if (chain == null || chain.Count == 0) return new D { ["ok"] = false, ["reason"] = "token is not a decodable PCA capability chain" };
        var vc = ChainReason(chain, opts);
        if (vc.Length > 0) return new D { ["ok"] = false, ["reason"] = "capability chain invalid: " + vc };
        var root = (D)chain[0]!; var leaf = (D)chain[^1]!;
        return new D { ["ok"] = true, ["principal"] = root["issuer"], ["capability"] = leaf, ["chain"] = chain, ["access"] = GrantedAccessOf(chain) };
    }

    // ---- jwsd detached JWS ----

    /// <summary>base64url(SHA-256(value)); a value that is not text is encoded as its JavaScript string (TextEncoder: null is "null").</summary>
    static string AthOf(object? accessTokenValue) => Pca.B64u(SHA256.HashData(GnapJs.Utf8(GnapJs.Str(accessTokenValue))));

    /// <summary>JSON.parse(JSON.stringify(v)): the plain JSON a value stands for (-0 prints as 0).</summary>
    static object? ToPlain(object? v) => v switch
    {
        Num n => n.Raw == "-0" ? new Num("0") : n,
        L l => new L(l.Select(ToPlain)),
        D m => m.ToDictionary(e => e.Key, e => ToPlain(e.Value)),
        _ => v,
    };

    /// <summary>The JWS payload of a jwsd proof (RFC 9635 7.3.3): the SHA-256 digest of the request CONTENT, or nothing when the request has none
    /// (<see cref="Absent"/>). A string or byte[] is the exact content bytes, hashed with no normalization; any other value is hashed as its strict
    /// canonical JSON, which is then the content the sender must transmit byte for byte.</summary>
    public static byte[] GnapContentDigest(object? body)
    {
        if (ReferenceEquals(body, Absent)) return Array.Empty<byte>();
        if (body is string s) return SHA256.HashData(GnapJs.Utf8(s));
        if (body is byte[] b) return SHA256.HashData(b);
        return SHA256.HashData(GnapJs.Utf8(Pca.Canonicalize(ToPlain(body))));
    }

    /// <summary>Produce a GNAP <c>jwsd</c> detached-JWS proof over <c>args.body</c>, signed by the client key. <paramref name="args"/>: body,
    /// key ({secretKey, publicKey}), htm, uri, created (epoch SECONDS), kid, accessTokenValue. Returns <c>{detachedJws, header, holder}</c>.</summary>
    public static D SignGnapRequest(D args)
    {
        object created = args.GetValueOrDefault("created") ?? new Num(DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture));
        var key = (D)args["key"]!;
        var ed = EdOf(key.GetValueOrDefault("secretKey"));
        var holder = Pca.B64u(SecretBytes(key.GetValueOrDefault("publicKey")));
        var header = new D { ["alg"] = "EdDSA", ["typ"] = JwsdTyp, ["htm"] = ((string)args["htm"]!).ToUpperInvariant(), ["uri"] = args.GetValueOrDefault("uri"), ["created"] = created };
        if (args.ContainsKey("kid")) header["kid"] = args["kid"];
        if (args.ContainsKey("accessTokenValue")) header["ath"] = AthOf(args["accessTokenValue"]);
        var payload = GnapContentDigest(args.ContainsKey("body") ? args["body"] : Absent);
        var protectedB64u = Pca.B64u(GnapJs.Utf8(GnapJs.Stringify(header)));
        var signingInput = Encoding.ASCII.GetBytes(protectedB64u + "." + Pca.B64u(payload));
        var sig = Pca.B64u(ed.Sign(signingInput));
        return new D { ["detachedJws"] = protectedB64u + ".." + sig, ["header"] = header, ["holder"] = holder };
    }

    static string? CanonicalB64uError(string seg)
    {
        foreach (var c in seg)
        {
            bool ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_';
            if (!ok) return "bad-character";
        }
        if (seg.Length % 4 == 1) return "non-canonical-base64url (impossible length)";
        return Pca.B64uDecode(seg) == null ? "non-canonical-base64url" : null;
    }

    const string JwsPrefix = "non-canonical compact JWS: ";

    /// <summary>The canonical-spelling gate for the protected and signature segments of a detached JWS: the header on success, else the message in <paramref name="err"/>.</summary>
    static D? CanonicalSegments(string p, string s, out string err)
    {
        err = "";
        if (p.Length + s.Length > 64 * 1024) { err = JwsPrefix + "too-long"; return null; }
        if (p.Length == 0 || s.Length == 0) { err = JwsPrefix + "empty-segment"; return null; }
        var e = CanonicalB64uError(p);
        if (e != null) { err = JwsPrefix + e; return null; }
        var bytes = Pca.B64uDecode(p)!;
        if (bytes.Length >= 3 && bytes[0] == 0xef && bytes[1] == 0xbb && bytes[2] == 0xbf) { err = JwsPrefix + "bom"; return null; }
        string text;
        try { text = StrictUtf8.GetString(bytes); }
        catch (ArgumentException) { err = JwsPrefix + "bad-utf8"; return null; }
        object? parsed;
        try { parsed = Pca.ParseStrict(text); }
        catch (Exception) { err = JwsPrefix + "bad-json"; return null; }
        if (parsed is not D header) { err = JwsPrefix + "not-an-object"; return null; }
        e = CanonicalB64uError(s);
        if (e != null) { err = JwsPrefix + e; return null; }
        return header;
    }

    static bool EdVerify(string holder, byte[] msg, string sigB64u)
    {
        try
        {
            var sig = Pca.B64uDecode(sigB64u, 64);
            var pub = Pca.B64uDecode(holder, 32);
            if (sig == null || pub == null) return false;
            var v = new Ed25519Signer();
            v.Init(false, new Ed25519PublicKeyParameters(pub, 0));
            v.BlockUpdate(msg, 0, msg.Length);
            return v.VerifySignature(sig);
        }
        catch (Exception) { return false; }
    }

    /// <summary>What the JOSE library accepts of the protected header before it checks the signature: a recognized <c>crit</c> only, an EdDSA alg.</summary>
    static bool JoseHeaderOk(D h)
    {
        if (h.ContainsKey("crit"))
        {
            if (h["crit"] is not L { Count: > 0 } crit) return false;
            foreach (var c in crit) if (c is not "b64") return false;
            if (h.GetValueOrDefault("b64") is not bool) return false;
        }
        return h.GetValueOrDefault("alg") is "EdDSA";
    }

    static D Fail(string reason) => new() { ["ok"] = false, ["reason"] = reason };

    /// <summary>Verify a GNAP <c>jwsd</c> detached-JWS proof and bind the request to the holder key. FAILS CLOSED on a bad signature, a tampered body,
    /// a wrong holder, a mismatched htm / uri, a stale or future <c>created</c>, an <c>ath</c> that does not bind the named access token, or a replayed
    /// proof. <paramref name="args"/>: detachedJws, body, holder, htm, uri, maxAgeSec, now (epoch ms), accessTokenValue, seenProof
    /// (<see cref="SeenProof"/>), replayCheck ("unchecked"). Throws <see cref="GnapException"/> when neither a replay store nor the explicit opt-out is given.</summary>
    public static D VerifyGnapRequest(D args)
    {
        var seen = args.GetValueOrDefault("seenProof") as SeenProof;
        if (seen == null && args.GetValueOrDefault("replayCheck") is not "unchecked")
            throw new GnapException("verifyGnapRequest: supply args.seenProof (a replay store) or set args.replayCheck to 'unchecked'");
        var dj = args.GetValueOrDefault("detachedJws");
        if (dj is string djs && djs.Length > MaxDetachedJwsChars) return Fail("detached JWS exceeds the size limit");
        try
        {
            if (dj is not string detached) return Fail("malformed jwsd request");
            var parts = detached.Split('.');
            if (parts.Length != 3) return Fail("not a compact JWS (expected three dot-separated parts)");
            string protectedB64u = parts[0], mid = parts[1], signature = parts[2];

            var holder = AsEd25519(args.GetValueOrDefault("holder"));
            if (holder == null) return Fail("holder is not a canonical base64url Ed25519 public key");

            var payloadB64u = Pca.B64u(GnapContentDigest(args.ContainsKey("body") ? args["body"] : Absent));
            if (mid.Length != 0 && mid != payloadB64u) return Fail("not a DETACHED compact JWS");

            var header = CanonicalSegments(protectedB64u, signature, out var err);
            if (header == null) return Fail("non-canonical detached JWS: " + err);
            const string sigFail = "jwsd signature does not verify under the holder key (or body was tampered)";
            if (!JoseHeaderOk(header)) return Fail(sigFail);
            if (!EdVerify(holder, Encoding.ASCII.GetBytes(protectedB64u + "." + payloadB64u), signature)) return Fail(sigFail);

            if (header.GetValueOrDefault("typ") is not JwsdTyp) return Fail("unexpected typ (not gnap-binding-jwsd)");
            if (header.GetValueOrDefault("alg") is not "EdDSA") return Fail("unexpected alg (not EdDSA)");

            var htm = header.GetValueOrDefault("htm");
            if (htm is not string htmS || htmS.ToUpperInvariant() != ((string)args["htm"]!).ToUpperInvariant()) return Fail("htm does not match the request method");
            var uri = header.GetValueOrDefault("uri");
            if (uri is not string uriS || args.GetValueOrDefault("uri") is not string argUri || uriS != argUri) return Fail("uri does not match the request target");
            var createdO = header.GetValueOrDefault("created");
            double? created = createdO is Num ? GnapJs.NumOf(createdO) : null;
            if (created is not double cr || double.IsNaN(cr) || double.IsInfinity(cr)) return Fail("missing or malformed created");

            double nowMs = args.GetValueOrDefault("now") is { } nowO ? GnapJs.NumOf(nowO) ?? double.NaN : DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            double nowSec = Math.Floor(nowMs / 1000);
            double maxAge = args.GetValueOrDefault("maxAgeSec") is { } maxO ? GnapJs.NumOf(maxO) ?? double.NaN : 300;
            if (!(double.IsFinite(nowSec) && cr <= nowSec + 60)) return Fail("created is in the future");
            if (!(double.IsFinite(maxAge) && nowSec - cr <= maxAge)) return Fail("jwsd proof is stale");

            var ath = header.GetValueOrDefault("ath");
            if (args.ContainsKey("accessTokenValue"))
            {
                if (ath is not string athS || athS != AthOf(args["accessTokenValue"])) return Fail("ath does not bind the named access token");
            }

            if (seen != null)
            {
                bool replayed;
                try { replayed = seen(AthOf(detached), cr + maxAge) is not false; } catch (Exception) { replayed = true; }
                if (replayed) return Fail("jwsd proof replayed (or the replay store failed)");
            }

            var o = new D { ["alg"] = "EdDSA", ["typ"] = JwsdTyp, ["htm"] = htm, ["uri"] = uri, ["created"] = createdO };
            if (header.GetValueOrDefault("kid") is string kid) o["kid"] = kid;
            if (ath is string athO) o["ath"] = athO;
            return new D { ["ok"] = true, ["holder"] = holder, ["header"] = o };
        }
        catch (Exception) { return Fail("malformed jwsd request"); }
    }

    // ---- continuation / step-up ----

    /// <summary>Decide whether a grant request needs a continuation / step-up: it does when GNAP interaction is requested, when an explicit higher
    /// tier is asked for, or when the request asks for rights BEYOND the issuer's own authority. <paramref name="opts"/>: issuerChain, tier.
    /// Returns <c>{required, reason, beyond, tier}</c>.</summary>
    public static D GnapRequestRequiresStepUp(object? req, D? opts = null)
    {
        var o = opts ?? new D();
        var beyond = new L();
        if (GnapJs.Truthy(o.GetValueOrDefault("issuerChain")))
        {
            var G = GrantedAccessOf(o["issuerChain"]);
            foreach (var r in NormalizeAccess(AccessOf(req))) if (!AccessWithin(G, (D)r!)) beyond.Add(r);
        }
        if (req == null) throw new GnapException("grant request is null");
        bool interactRequested = false;
        if (GnapJs.Has(req, "interact"))
        {
            var it = ((D)req)["interact"] ?? throw new GnapException("interact is null");
            interactRequested = GnapJs.Member(it, "start") is L { Count: > 0 };
        }
        var tierO = o.GetValueOrDefault("tier");
        double? tierN = tierO == null ? null : GnapJs.NumOf(tierO);
        bool required = interactRequested || beyond.Count > 0 || (tierN != null && tierN > 1);
        object tier = tierO ?? new Num(beyond.Count == 0 ? "2" : "3");
        var reason = !required ? "no step-up required"
            : beyond.Count > 0 ? "requested rights exceed the issuer's authority (" + beyond.Count + " right(s) beyond)"
            : interactRequested ? "GNAP interaction requested" : "tier " + GnapJs.Str(tier) + " step-up required";
        return new D { ["required"] = required, ["reason"] = reason, ["beyond"] = beyond, ["tier"] = tier };
    }

    /// <summary>Begin a GNAP continuation: emit the <c>continue</c> handle and the PCA step-up it resolves through. <paramref name="args"/>: signerSet,
    /// t, tier, continueUri, continueToken, wait, reason. Returns <c>{response, stepUp}</c>.</summary>
    public static D BeginGnapContinuation(D args)
    {
        var cont = new D { ["uri"] = args.GetValueOrDefault("continueUri"), ["access_token"] = new D { ["value"] = args.GetValueOrDefault("continueToken"), ["bound"] = true } };
        if (args.ContainsKey("wait")) cont["wait"] = args["wait"];
        var reason = args.GetValueOrDefault("reason");
        return new D
        {
            ["response"] = new D { ["continue"] = cont },
            ["stepUp"] = new D
            {
                ["tier"] = args.GetValueOrDefault("tier"), ["t"] = args.GetValueOrDefault("t"), ["signerSet"] = args.GetValueOrDefault("signerSet"),
                ["reason"] = reason ?? "tier " + GnapJs.Str(GnapJs.Get(args, "tier")) + " co-signature required to continue",
                ["continueToken"] = args.GetValueOrDefault("continueToken"),
            },
        };
    }

    static int ValidT(object? t)
    {
        var d = GnapJs.NumOf(t);
        if (d == null || (d != 1.0 && d != 2.0 && d != 3.0)) throw new ArgumentException("shareMessage: t must be 1, 2 or 3");
        return (int)d.Value;
    }

    /// <summary>One role's step-up co-signature share over the action's PCActn: the co-signature a guardian or principal device returns through
    /// the GNAP continuation. It binds the signer set and <c>t</c> (replay-safe).</summary>
    public static D GnapStepUpShare(D body, string role, object? secret, object? signerSet, object? t) =>
        // the reference hashes a signer set that is not an array as the empty set
        Signers.SignThresholdShare(role, SuiteKey.Ed25519(EdOf(secret)), Pca.ThresholdMessage(body), signerSet as L ?? new L(), ValidT(t));

    /// <summary>Resolve a continuation: build the action's PCActn (agent leaf signature) and FOLD the step-up co-signatures into its
    /// <c>threshold</c>, then verify the threshold <c>t</c> is reached. <paramref name="args"/>: grant, chain, plan, nodeId, params, counter, aud,
    /// now, ttlMs, agentLeafSecret, signerSet, t, cosignSecrets ([{role, secret}]). Returns <c>{pcactn, threshold, verdict}</c>.</summary>
    public static D CompleteGnapContinuation(D args)
    {
        if (args.GetValueOrDefault("chain") is not L { Count: > 0 } chain) throw new GnapException("completeGnapContinuation: empty chain");
        var agent = SuiteKey.Ed25519(EdOf(args.GetValueOrDefault("agentLeafSecret")));
        var spec = new ActSpec
        {
            Grant = (D)args["grant"]!,
            Chain = chain,
            Plan = Issue.CommitPlan(((L)args["plan"]!).Select(n => (D)n!).ToList()),
            NodeId = (string)args["nodeId"]!,
            Counter = IntentJs.Lng(args["counter"]),
            Signer = agent,
            Aud = (string)args["aud"]!,
        };
        if (args.ContainsKey("params")) spec.Params = (D?)args["params"];
        if (args.ContainsKey("now")) spec.Iat = IntentJs.Lng(args["now"]);
        if (args.ContainsKey("ttlMs")) spec.TtlMs = IntentJs.Lng(args["ttlMs"]);
        var pcactn = Issue.BuildPCActn(spec);
        var message = Pca.ThresholdMessage(pcactn);
        int t = ValidT(args["t"]);
        var signerSet = (L)args["signerSet"]!;
        var shares = new L { Signers.SignThresholdShare("agent", agent, message, signerSet, t) };
        foreach (var cso in (L)args.GetValueOrDefault("cosignSecrets")!)
        {
            var cs = (D)cso!;
            shares.Add(Signers.SignThresholdShare((string)cs["role"]!, SuiteKey.Ed25519(EdOf(cs["secret"])), message, signerSet, t));
        }
        var threshold = new D { ["shares"] = shares };
        var verdict = GnapThreshold.Verify(threshold, message, signerSet, t);
        var withThreshold = new D(pcactn) { ["threshold"] = threshold };
        return new D { ["pcactn"] = withThreshold, ["threshold"] = threshold, ["verdict"] = verdict };
    }

    // ---- the profile ----

    /// <summary>The machine-readable Agent-GNAP profile spec.</summary>
    public static D AgentGnapProfile() => GnapProfile.Profile();
}

// OAuth Transaction Tokens over a PCA custody chain: the RFC 8693 nested `act` projection, EdDSA issue and verify (the legacy profile and the
// draft-ietf-oauth-transaction-tokens-11 profile), over the shared JOSE kit.
// Maps onto the reference's subActChain / actDepth / toRfc8693Act / toTransactionToken / fromTransactionToken (PascalCase). Values are the JSON
// tree (Dictionary / List / string / bool / Num / null); the clock and the id generator are injectable and the replay store is a synchronous delegate.
using System.Globalization;
using AtlasPca;
using J = AtlasPca.Jose.Jose;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.TxnTokens;

/// <summary>A Transaction Token policy refusal that carries a code (only <c>replay_store_required</c>).</summary>
public sealed class TxnTokenException : Exception
{
    public string Code { get; }
    public TxnTokenException(string code, string message) : base(message) { Code = code; }
}

/// <summary>Atomically records a transaction id as seen; returns true when it was ALREADY seen (replay).</summary>
public delegate bool SeenTxn(string id, double expSec);

public sealed record ToTransactionTokenArgs
{
    /// <summary><c>legacy</c> or <c>draft-11</c> (default).</summary>
    public string? Profile { get; init; }
    public string? Scope { get; init; }
    public string? ReqWl { get; init; }
    public string? Txn { get; init; }
    public string? TrustDomain { get; init; }
    /// <summary>The custody chain: a non-empty list of hops with issuer and holder strings.</summary>
    public object? Chain { get; init; }
    /// <summary>The action: an object with string verb, resource and aud.</summary>
    public object? Action { get; init; }
    /// <summary>A raw 32-byte Ed25519 seed (<c>byte[]</c>), a private JWK, or a private <see cref="AtlasPca.Jose.JoseKey"/>.</summary>
    public object? IssuerKey { get; init; }
    public string? Issuer { get; init; }
    public double? TtlSec { get; init; }
    /// <summary>Clock in epoch ms (default: the system clock).</summary>
    public Func<long>? NowMs { get; init; }
    /// <summary>Generator of the random transaction / token id (default: a random UUID).</summary>
    public Func<string>? NewId { get; init; }
}

public sealed record FromTransactionTokenOptions
{
    public string? Profile { get; init; }
    public string? Audience { get; init; }
    public double? ClockToleranceSec { get; init; }
    /// <summary>Verification time in epoch ms (default: the system clock).</summary>
    public double? NowMs { get; init; }
    public SeenTxn? SeenTxn { get; init; }
    /// <summary>Set to <c>unchecked</c> to verify without a replay store.</summary>
    public string? ReplayCheck { get; init; }
}

public static class TxnTokens
{
    public const string TxnTokenTypDraft11 = "txntoken+jwt";
    public const string TxnTokenTypLegacy = "txn_token+jwt";
    public const int MaxTokenChars = 16384;
    const int DefaultTtlSec = 120;
    const string EdDsa = "EdDSA";

    // ===================== RFC 8693 nested actor claim =====================

    /// <summary>The nested <c>sub</c> / <c>act</c> claim of a custody chain: sub is the root issuer (the principal), act nests each holder, the last
    /// holder innermost. Throws <see cref="ArgumentException"/> (the reference's TypeError) for an empty chain or a hop without a holder / issuer.</summary>
    public static D SubActChain(object? chain)
    {
        if (chain is not L hops || hops.Count == 0) throw new ArgumentException("subActChain: chain must be a non-empty CapabilityChain");
        object? root = hops[0];
        D? act = null;
        for (int i = hops.Count - 1; i >= 0; i--)
        {
            // a hop that is not an object has no holder (the reference reads a member of it; null / undefined throw)
            if (hops[i] is null) throw new ArgumentException($"subActChain: hop {i} has no holder");
            var holder = (hops[i] as D)?.GetValueOrDefault("holder");
            if (holder is not string h || h.Length == 0) throw new ArgumentException($"subActChain: hop {i} has no holder");
            act = act != null ? new D { ["sub"] = h, ["act"] = act } : new D { ["sub"] = h };
        }
        if ((root as D)?.GetValueOrDefault("issuer") is not string iss || iss.Length == 0) throw new ArgumentException("subActChain: root hop has no issuer (principal)");
        return act != null ? new D { ["sub"] = iss, ["act"] = act } : new D { ["sub"] = iss };
    }

    static bool Truthy(object? v) => v switch
    {
        null => false,
        bool b => b,
        string s => s.Length > 0,
        Num n => IntentJs.NumOf(n) is double d && d != 0 && !double.IsNaN(d),
        _ => true,
    };

    /// <summary>The number of actors nested under the claim's sub (0 for a bare principal).</summary>
    public static long ActDepth(object? claim)
    {
        if (!(claim is D or L)) throw new ArgumentException("actDepth: expected a sub/act claim object");
        long depth = 0;
        object? cur = (claim as D)?.GetValueOrDefault("act");
        while (Truthy(cur)) { depth++; cur = (cur as D)?.GetValueOrDefault("act"); }
        return depth;
    }

    /// <summary>The RFC 8693 projection: actors listed outermost-first become a chain whose OUTERMOST act is the most recent actor (the order reversed).
    /// A member the input lacks is simply absent from the result.</summary>
    public static D ToRfc8693Act(object? claim)
    {
        if (claim == null) throw new ArgumentException("toRfc8693Act: claim is required");
        var actors = new List<(bool Has, object? Sub)>();
        object? c = (claim as D)?.GetValueOrDefault("act");
        while (Truthy(c))
        {
            actors.Add(c is D cd && cd.ContainsKey("sub") ? (true, cd["sub"]) : (false, null));
            c = (c as D)?.GetValueOrDefault("act");
        }
        D? act = null;
        foreach (var (has, sub) in actors)
        {
            var n = new D();
            if (has) n["sub"] = sub;
            if (act != null) n["act"] = act;
            act = n;
        }
        var o = new D();
        if (claim is D cl && cl.ContainsKey("sub")) o["sub"] = cl["sub"];
        if (act != null) o["act"] = act;
        return o;
    }

    // ===================== issue =====================

    static object SigningKey(object? key)
    {
        if (key is byte[] raw)
        {
            if (raw.Length != 32) throw new ArgumentException("toTransactionToken: a raw Ed25519 secret key must be 32 bytes");
            return J.ImportJwk(J.Ed25519SeedJwk(raw), EdDsa);
        }
        return key ?? throw new ArgumentException("toTransactionToken: issuerKey is required");
    }

    static object VerificationKey(object? key)
    {
        if (key is byte[] raw)
        {
            if (raw.Length != 32) throw new ArgumentException("fromTransactionToken: a raw Ed25519 public key must be 32 bytes");
            return J.ImportJwk(J.Ed25519PublicJwk(raw), EdDsa);
        }
        return key ?? throw new ArgumentException("fromTransactionToken: a verification key is required");
    }

    /// <summary>Issues a Transaction Token (EdDSA compact JWS) for a custody chain and action. Draft-11 needs scope and reqWl and carries tctx, act, txn,
    /// scope, req_wl with aud = the trust domain; the legacy profile carries tctx and act with aud = the action's aud and a jti.
    /// Throws <see cref="ArgumentException"/> / <see cref="ArgumentOutOfRangeException"/> for a bad argument.</summary>
    public static string ToTransactionToken(ToTransactionTokenArgs args)
    {
        if (string.IsNullOrEmpty(args.Issuer)) throw new ArgumentException("toTransactionToken: `issuer` is required");
        if (!(args.Action is D action && action.GetValueOrDefault("verb") is string verb && action.GetValueOrDefault("resource") is string resource && action.GetValueOrDefault("aud") is string aud))
            throw new ArgumentException("toTransactionToken: `action` must have string verb, resource and aud");
        var custody = SubActChain(args.Chain);
        double ttl = args.TtlSec ?? DefaultTtlSec;
        if (!double.IsFinite(ttl) || ttl <= 0) throw new ArgumentOutOfRangeException(nameof(args), "toTransactionToken: ttlSec must be > 0");
        long nowSec = (long)Math.Floor((args.NowMs?.Invoke() ?? AtlasPca.ReplayClock.NowMs()) / 1000.0);
        var key = SigningKey(args.IssuerKey);
        bool draft = (args.Profile ?? "draft-11") == "draft-11";
        if (args.Profile != null && args.Profile != "legacy" && !draft) throw new ArgumentException("toTransactionToken: profile must be legacy or draft-11");
        var newId = args.NewId ?? (() => Guid.NewGuid().ToString());
        var tctx = new D { ["verb"] = verb, ["resource"] = resource, ["aud"] = aud };

        if (draft)
        {
            if (string.IsNullOrEmpty(args.Scope)) throw new ArgumentException("toTransactionToken: draft-11 requires `scope`");
            if (string.IsNullOrEmpty(args.ReqWl)) throw new ArgumentException("toTransactionToken: draft-11 requires `reqWl`");
            var td = args.TrustDomain ?? aud;
            if (td.Length == 0) throw new ArgumentException("toTransactionToken: draft-11 requires a non-empty trust domain (aud)");
            var claims = new D { ["tctx"] = tctx };
            if (custody.ContainsKey("act")) claims["act"] = custody["act"];
            claims["txn"] = args.Txn ?? newId();
            claims["scope"] = args.Scope;
            claims["req_wl"] = args.ReqWl;
            claims["iat"] = nowSec; claims["iss"] = args.Issuer; claims["sub"] = custody["sub"]; claims["aud"] = td; claims["exp"] = nowSec + ttl;
            return J.SignJwt(new D { ["alg"] = EdDsa, ["typ"] = TxnTokenTypDraft11 }, claims, key);
        }

        var payload = new D { ["tctx"] = tctx };
        if (custody.ContainsKey("act")) payload["act"] = custody["act"];
        payload["iat"] = nowSec; payload["iss"] = args.Issuer; payload["sub"] = custody["sub"]; payload["aud"] = aud; payload["exp"] = nowSec + ttl; payload["jti"] = newId();
        return J.SignJwt(new D { ["alg"] = EdDsa, ["typ"] = TxnTokenTypLegacy }, payload, key);
    }

    // ===================== verify =====================

    static bool IsPlainObject(object? v) => v is D;

    static D? NormalizeAct(bool present, object? node)
    {
        if (!present) return null;
        if (node is not D obj) throw new InvalidOperationException("transaction token: malformed `act` claim");
        if (obj.GetValueOrDefault("sub") is not string sub || sub.Length == 0) throw new InvalidOperationException("transaction token: `act.sub` must be a non-empty string");
        var inner = NormalizeAct(obj.ContainsKey("act"), obj.GetValueOrDefault("act"));
        return inner != null ? new D { ["sub"] = sub, ["act"] = inner } : new D { ["sub"] = sub };
    }

    static (D Tctx, D? Action) ReadTctx(object? raw, bool draft)
    {
        if (raw is not D r) throw new InvalidOperationException("transaction token: missing or malformed `tctx`");
        bool usesPca = r.ContainsKey("verb") || r.ContainsKey("resource") || r.ContainsKey("aud");
        if (!draft || usesPca)
        {
            if (r.GetValueOrDefault("verb") is not string verb || r.GetValueOrDefault("resource") is not string resource || r.GetValueOrDefault("aud") is not string aud)
                throw new InvalidOperationException("transaction token: missing or malformed `tctx`");
            return (r, new D { ["verb"] = verb, ["resource"] = resource, ["aud"] = aud });
        }
        return (r, null);
    }

    /// <summary>Verifies a Transaction Token and returns {chain, action, tctx, claims}. The raw key must be 32 bytes. A replay store (or
    /// <c>ReplayCheck = "unchecked"</c>) is required and consulted last, so a token refused for another reason never burns its id.
    /// Throws <see cref="TxnTokenException"/> (replay_store_required), <see cref="AtlasPca.Jose.JoseException"/> (signature / claims),
    /// <see cref="AtlasPca.Jose.CanonicalJwsException"/>, <see cref="ArgumentException"/> or <see cref="InvalidOperationException"/>.</summary>
    public static D FromTransactionToken(object? jwt, object? verifyKey, FromTransactionTokenOptions? opts = null)
    {
        opts ??= new FromTransactionTokenOptions();
        bool draft = (opts.Profile ?? "draft-11") == "draft-11";
        if (opts.Profile != null && opts.Profile != "legacy" && !draft) throw new ArgumentException("fromTransactionToken: profile must be legacy or draft-11");
        if (draft && string.IsNullOrEmpty(opts.Audience)) throw new ArgumentException("fromTransactionToken: draft-11 requires opts.audience (the trust domain this verifier serves)");
        if (opts.SeenTxn == null && opts.ReplayCheck != "unchecked")
            throw new TxnTokenException("replay_store_required", "fromTransactionToken: supply opts.seenTxn (a replay store) or set opts.replayCheck to 'unchecked'");
        if (jwt is string js && js.Length > MaxTokenChars) throw new InvalidOperationException("transaction token: token exceeds the size limit");
        J.AssertCanonicalCompactJws(jwt); // canonical-spelling gate BEFORE the JOSE layer (one accepted string form)
        var key = VerificationKey(verifyKey);
        var verified = J.JwtVerify((string)jwt!, key, new AtlasPca.Jose.JwtVerifyOptions
        {
            Typ = draft ? TxnTokenTypDraft11 : TxnTokenTypLegacy,
            Algorithms = new[] { EdDsa },
            RequiredClaims = draft ? new[] { "iat", "exp", "aud", "sub", "txn", "scope", "req_wl" } : new[] { "exp" },
            AudienceString = opts.Audience,
            ClockTolerance = opts.ClockToleranceSec,
            CurrentDateMs = opts.NowMs,
        });
        var payload = verified.Payload;
        if (draft)
            foreach (var k in new[] { "txn", "scope", "req_wl" })
                if (payload.GetValueOrDefault(k) is not string v || v.Length == 0) throw new InvalidOperationException($"transaction token: `{k}` must be a non-empty string");
        if (payload.GetValueOrDefault("sub") is not string sub || sub.Length == 0) throw new InvalidOperationException("transaction token: missing `sub` (root principal)");
        var (tctx, action) = ReadTctx(payload.GetValueOrDefault("tctx"), draft);
        if (draft && payload.ContainsKey("rctx") && !IsPlainObject(payload["rctx"])) throw new InvalidOperationException("transaction token: malformed `rctx`");
        var act = NormalizeAct(payload.ContainsKey("act"), payload.GetValueOrDefault("act"));
        // consume the identifier last: a token refused for any other reason never burns its transaction id
        if (opts.SeenTxn != null)
        {
            if ((draft ? payload.GetValueOrDefault("txn") : payload.GetValueOrDefault("jti")) is not string id || id.Length == 0)
                throw new InvalidOperationException("transaction token: no transaction identifier to check for replay");
            if (opts.SeenTxn(id, J.NumberOf(payload.GetValueOrDefault("exp")) ?? double.NaN)) throw new InvalidOperationException("transaction token: replayed (transaction identifier already seen)");
        }
        var chain = act != null ? new D { ["sub"] = sub, ["act"] = act } : new D { ["sub"] = sub };
        var result = new D { ["chain"] = chain, ["tctx"] = tctx, ["claims"] = payload };
        if (action != null) result["action"] = action; // an opaque tctx carries no action (an undefined member is not printed)
        return result;
    }
}

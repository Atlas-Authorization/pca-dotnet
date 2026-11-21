// Agentic Commerce Protocol (ACP) + x402 for PCA: delegated one-time payment tokens minted FROM a PCActn, payment caveats, x402 v1
// challenge / settle, ACP delegate_payment allowance. x402 v2 lives in X402V2.cs, the v2 HTTP transport in X402Http.cs and Stripe
// Shared Payment Tokens in Spt.cs (all `partial class Acp`). Values are the house JSON tree (D / L / string / bool / Num / null); an
// options bag is a D with the same member names as the reference's options object (an absent member is JavaScript `undefined`, a
// member holding null is JSON null), so the reference's undefined / null / hostile-type behaviour is reproduced member by member.
// Non-JSON option members are delegates: `singleUse` is a <see cref="ClaimFn"/>.
using System.Text;
using AtlasPca.InteropJs;
using AtlasPca.Js;
using J = AtlasPca.Jose.Jose;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Acp;

/// <summary>Thrown when a delegated payment token cannot be minted (or an allowance cannot be expressed) because the request exceeds
/// the proof's authority or the claim is not representable (the reference's AcpAuthorityError).</summary>
public sealed class AcpAuthorityException(string message) : Exception(message);

/// <summary>The reference's plain <c>TypeError</c> with its message (x402 header and Stripe token refusals).</summary>
public sealed class AcpTypeException(string message) : Exception(message);

/// <summary>Atomic first-use claim: returns true exactly once per <paramref name="jti"/>. Anything but the boolean true (including a
/// truthy non-boolean) is "already redeemed"; a throw is "store unavailable" (both fail closed).</summary>
public delegate object? ClaimFn(string jti, double expiresAtMs);

public static partial class Acp
{
    public const int AcpDelegatedTokenVersion = 1;
    public const string AcpDelegatedTokenType = "acp-delegated-payment";
    public const string SpendCapCaveatType = "max_amount";
    public const string MerchantAllowCaveatType = "merchant_allow";
    public const string MerchantCategoryCaveatType = "merchant_category";
    public const string HumanPresentCaveatType = "human_present";

    /// <summary>JavaScript <c>undefined</c> as a return value of a settle step (as opposed to JSON null).</summary>
    public static readonly object Undefined = JsX.Undef;

    // ---- JavaScript-ish helpers ----
    static object? G(object? o, string k) => JsX.At(o, k);
    static bool Has(D o, string k) => o.ContainsKey(k);
    static bool IsUndef(object? v) => ReferenceEquals(v, JsX.Undef);
    static bool Nullish(object? v) => v == null || IsUndef(v);
    static object? Nn(object? v, object? dflt) => Nullish(v) ? dflt : v;
    static bool IsObj(object? v) => v is D;
    static bool NonEmpty(object? v) => v is string s && s.Length > 0;
    static bool IsAmount(object? x) => JsX.SafeInt(x) && JsX.NumOf(x)!.Value > 0;
    static string S(object? v) => JsX.Str(v);
    static double? Finite(object? v) => JsX.NumOf(v) is double d && double.IsFinite(d) ? d : null;
    static Num N(long v) => IntentJs.OfLong(v);
    static object? Num_(double d) => JsX.Number(d);
    static bool Includes(L list, object? v) => list.Any(x => JsX.StrictEq(x, v));
    /// <summary><c>a &gt; b</c> for a number <paramref name="a"/> against any value (ToNumber coercion of <paramref name="b"/>).</summary>
    static long Now(Func<long>? clock) => clock != null ? clock() : DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

    /// <summary>JavaScript <c>String.prototype.toLowerCase</c> as far as the three-letter ASCII checks can see it: ASCII and the Kelvin sign
    /// lower-case to ASCII, U+0130 to "i" + a combining dot; every other character is lower-cased by the invariant culture.</summary>
    internal static string JsLower(string s)
    {
        var sb = new StringBuilder(s.Length);
        foreach (var c in s)
        {
            if (c >= 'A' && c <= 'Z') sb.Append((char)(c + 32));
            else if (c == 'K') sb.Append('k');
            else if (c == 'İ') sb.Append("i̇");
            else if (c < 128) sb.Append(c);
            else sb.Append(char.ToLowerInvariant(c));
        }
        return sb.ToString();
    }

    internal static bool IsLower3(object? v) => v is string s && s.Length == 3 && s.All(c => c >= 'a' && c <= 'z');

    // ===== caveat builders =====

    public static D SpendCapCaveat(double max, string? currency = null)
    {
        var d = new D { ["type"] = SpendCapCaveatType, ["max"] = Num_(max) };
        if (currency != null) d["currency"] = currency;
        return d;
    }
    public static D MerchantAllowCaveat(IEnumerable<string> merchants) => new() { ["type"] = MerchantAllowCaveatType, ["merchants"] = merchants.Cast<object?>().ToList() };
    public static D MerchantCategoryCaveat(IEnumerable<string> categories) => new() { ["type"] = MerchantCategoryCaveatType, ["categories"] = categories.Cast<object?>().ToList() };
    public static D HumanPresentCaveat(bool required = true) => new() { ["type"] = HumanPresentCaveatType, ["required"] = required };

    // ===== payment authority =====

    static L AsStringArray(object? v, string label)
    {
        if (v is not L l || !l.All(x => x is string)) throw new AcpAuthorityException($"malformed {label} caveat: expected a string[] (fail closed)");
        return l;
    }

    /// <summary>Collapse a leaf capability's cumulative caveat list into its effective payment authority
    /// <c>{maxAmount?, currency?, merchants|null, categories|null, humanPresentRequired}</c>. A malformed payment caveat throws; other caveat types are ignored.</summary>
    public static D ExtractPaymentAuthority(object? caveats)
    {
        IEnumerable<object?> items = caveats switch
        {
            L l => l,
            string => Array.Empty<object?>(), // iterates characters, none of which has a type
            _ => throw JsX.TypeError("caveats is not iterable"),
        };
        double? maxAmount = null;
        string? currency = null;
        L? merchants = null, categories = null;
        bool human = false;
        foreach (var c in items)
        {
            switch (G(c, "type") as string)
            {
                case SpendCapCaveatType:
                    {
                        var max = G(c, "max");
                        if (!IntentJs.IsNonNeg(max)) throw new AcpAuthorityException("malformed max_amount caveat: max must be an integer >= 0 in minor units (fail closed)");
                        var m = JsX.NumOf(max)!.Value;
                        maxAmount = maxAmount == null ? m : Math.Min(maxAmount.Value, m);
                        var cur = G(c, "currency");
                        if (!IsUndef(cur))
                        {
                            if (cur is not string cs || cs.Length == 0) throw new AcpAuthorityException("malformed max_amount caveat: currency must be a non-empty string (fail closed)");
                            if (currency != null && currency != cs) throw new AcpAuthorityException($"conflicting spend-cap currencies \"{currency}\" vs \"{cs}\" (fail closed)");
                            currency = cs;
                        }
                        break;
                    }
                case MerchantAllowCaveatType:
                    {
                        var list = AsStringArray(G(c, "merchants"), "merchant_allow");
                        merchants = merchants == null ? Dedup(list) : merchants.Where(x => Includes(list, x)).ToList();
                        break;
                    }
                case MerchantCategoryCaveatType:
                    {
                        var list = AsStringArray(G(c, "categories"), "merchant_category");
                        categories = categories == null ? Dedup(list) : categories.Where(x => Includes(list, x)).ToList();
                        break;
                    }
                case HumanPresentCaveatType:
                    {
                        if (G(c, "required") is not bool req) throw new AcpAuthorityException("malformed human_present caveat: required must be a boolean (fail closed)");
                        human = human || req;
                        break;
                    }
            }
        }
        var r = new D();
        if (maxAmount != null) r["maxAmount"] = Num_(maxAmount.Value);
        if (currency != null) r["currency"] = currency;
        r["merchants"] = merchants;
        r["categories"] = categories;
        r["humanPresentRequired"] = human;
        return r;
    }

    static L Dedup(L list)
    {
        var o = new L();
        foreach (var x in list) if (!Includes(o, x)) o.Add(x);
        return o;
    }

    static D Fail(string reason) => new() { ["ok"] = false, ["reason"] = reason };

    /// <summary>Check a purchase request <c>{amount, currency, merchant, category?, humanPresent?}</c> against a payment authority. Pure, fail closed: <c>{ok, reason?}</c>.</summary>
    public static D CheckPaymentAuthority(D authority, D request)
    {
        var amount = G(request, "amount");
        if (!IsAmount(amount)) return Fail("amount must be a positive integer in minor units");
        var currency = G(request, "currency");
        if (!NonEmpty(currency)) return Fail("currency must be a non-empty string");
        var merchant = G(request, "merchant");
        if (!NonEmpty(merchant)) return Fail("merchant must be a non-empty string");
        var aCur = G(authority, "currency");
        if (!IsUndef(aCur) && !JsX.StrictEq(aCur, currency)) return Fail($"currency \"{S(currency)}\" is not the authorized currency \"{S(aCur)}\"");
        var aMax = G(authority, "maxAmount");
        if (!IsUndef(aMax) && !(JsX.SafeInt(aMax) && JsX.NumOf(aMax)!.Value >= 0 && !double.IsNegative(JsX.NumOf(aMax)!.Value)))
            return Fail("authorized spend cap is not a non-negative integer (fail closed)");
        if (!IsUndef(aMax) && !(JsX.NumOf(amount)!.Value <= JsJson.ToJsNumber(aMax))) return Fail($"amount {S(amount)} exceeds the authorized spend cap {S(aMax)}");
        var merchants = G(authority, "merchants");
        if (merchants != null)
        {
            if (merchants is not L ml) throw JsX.TypeError("authority.merchants.includes is not a function");
            if (!Includes(ml, merchant)) return Fail($"merchant \"{S(merchant)}\" is not in the authorized allowlist");
        }
        var categories = G(authority, "categories");
        if (categories != null)
        {
            var cat = G(request, "category");
            if (IsUndef(cat)) return Fail("the proof constrains merchant categories but no category was supplied");
            if (categories is not L cl) throw JsX.TypeError("authority.categories.includes is not a function");
            if (!Includes(cl, cat)) return Fail($"category \"{S(cat)}\" is not in the authorized allowlist");
        }
        if (JsX.Truthy(G(authority, "humanPresentRequired")) && G(request, "humanPresent") is not true)
            return Fail("the proof requires a human-present charge but humanPresent was not asserted");
        return new D { ["ok"] = true };
    }

    static object? LeafCapability(object? pcActn)
    {
        var chain = G(pcActn, "cap_chain");
        if (chain is not L l || l.Count == 0) throw new AcpAuthorityException("PCActn carries no capability chain (fail closed)");
        return l[^1];
    }

    static D AuthorityRef(object? pcActn)
    {
        var leaf = LeafCapability(pcActn);
        var r = new D { ["digest"] = Pca.HashCanonical(pcActn) };
        SetDefined(r, "aud", G(pcActn, "aud"));
        SetDefined(r, "grant_ref", G(pcActn, "grant_ref"));
        SetDefined(r, "leaf_holder", G(leaf, "holder"));
        var action = G(pcActn, "action");
        SetDefined(r, "verb", G(action, "verb"));
        SetDefined(r, "resource", G(action, "resource"));
        SetDefined(r, "params_digest", G(action, "params_digest"));
        return r;
    }

    /// <summary>An object member holding <c>undefined</c> is dropped by JSON.stringify: do not add it.</summary>
    static void SetDefined(D d, string k, object? v) { if (!IsUndef(v)) d[k] = v; }

    // ===== mint =====

    /// <summary>Mint a one-time ACP delegated payment token (a compact JWS) FROM a PCActn. <paramref name="opts"/> carries the reference's
    /// MintOptions members (amount, currency, merchant, session, expiresAt, paymentMethod, signingKey (a private JWK), alg, category,
    /// humanPresent, issuer, kid, jti, now). The proof's caveats gate issuance; the mint is refused (throws) when the request exceeds them.</summary>
    public static string MintDelegatedPaymentToken(D pcActn, D opts, Func<long>? clock = null)
    {
        double now = Finite(G(opts, "now")) ?? Now(clock);
        var authority = ExtractPaymentAuthority(G(LeafCapability(pcActn), "caveats"));
        var req = new D();
        foreach (var k in new[] { "amount", "currency", "merchant" }) SetDefined(req, k, G(opts, k));
        foreach (var k in new[] { "category", "humanPresent" }) SetDefined(req, k, G(opts, k));
        var check = CheckPaymentAuthority(authority, req);
        if (check["ok"] is not true) throw new AcpAuthorityException("refused: " + (check.GetValueOrDefault("reason") as string ?? "request exceeds the proof authority"));

        var expiresAt = G(opts, "expiresAt");
        if (Finite(expiresAt) is not double exp) throw new AcpAuthorityException("refused: expiresAt must be a finite epoch-ms timestamp");
        if (!(exp > now)) throw new AcpAuthorityException("refused: expiresAt is not in the future");
        if (!(Finite(G(pcActn, "exp")) is double pxe && exp <= pxe)) throw new AcpAuthorityException($"refused: token expiry {S(expiresAt)} would outlive the proof's exp {S(G(pcActn, "exp"))}");
        if (!JsX.Truthy(G(opts, "session"))) throw new AcpAuthorityException("refused: a session id is required");

        var pca = AuthorityRef(pcActn);
        var jtiOpt = G(opts, "jti");
        object? jti;
        if (!Nullish(jtiOpt)) jti = jtiOpt;
        else
        {
            var seed = JsX.Spread(pcActn);
            seed["nonce"] = $"acp:{S(G(opts, "session"))}:{S(G(opts, "merchant"))}:{S(G(opts, "amount"))}:{S(G(opts, "currency"))}:{S(expiresAt)}:{S(pca["digest"])}";
            jti = Pca.HashCanonical(seed);
        }

        var claims = new D
        {
            ["typ"] = AcpDelegatedTokenType,
            ["ver"] = N(AcpDelegatedTokenVersion),
            ["jti"] = jti,
            ["session"] = G(opts, "session"),
            ["merchant"] = G(opts, "merchant"),
            ["amount"] = G(opts, "amount"),
            ["currency"] = G(opts, "currency"),
            ["iat"] = Num_(now),
            ["exp"] = expiresAt,
            ["paymentMethod"] = JsX.Spread(G(opts, "paymentMethod")),
            ["humanPresent"] = G(opts, "humanPresent") is true,
        };
        var category = G(opts, "category");
        if (!IsUndef(category)) claims["category"] = category;
        var issuer = G(opts, "issuer");
        if (!IsUndef(issuer)) claims["iss"] = issuer;
        claims["pca"] = pca;

        var algO = Nn(G(opts, "alg"), "EdDSA");
        if (algO is not string alg) throw JsX.TypeError("alg must be a string");
        var keyO = G(opts, "signingKey");
        if (keyO is not D jwk || !jwk.ContainsKey("kty")) throw JsX.TypeError("signingKey is not a JWK");
        // node:crypto imports a signing OKP key from its JWK: a private part that is not a 32-byte base64url string is refused with the import's code
        if (jwk.GetValueOrDefault("kty") is "OKP" && !(jwk.GetValueOrDefault("d") is string dtext && Pca.B64uDecode(dtext, 32) != null))
            throw new AtlasPca.Grants.CodedException("ERR_CRYPTO_INVALID_JWK", "Invalid JWK OKP key");
        var key = J.ImportJwk(jwk, alg);
        var header = new D { ["alg"] = alg, ["typ"] = AcpDelegatedTokenType };
        var kid = G(opts, "kid");
        if (!IsUndef(kid)) header["kid"] = kid;
        return J.SignCompact(header, Encoding.UTF8.GetBytes(JsJson.Stringify(claims)), key);
    }

    // ===== verify =====

    static D Res(bool ok, string? reason = null, object? claims = null, D? pcaResult = null)
    {
        var r = new D { ["ok"] = ok };
        if (reason != null) r["reason"] = reason;
        if (claims != null) r["claims"] = claims;
        if (pcaResult != null) r["pcaResult"] = pcaResult;
        return r;
    }

    /// <summary>Verify a delegated payment token at settlement: JWS signature, then merchant / amount / expiry / session / currency, the bound
    /// PCActn digest (and a full core re-verify with a grant), then the single-use claim. Returns <c>{ok, reason?, claims?, pcaResult?}</c>.
    /// <paramref name="opts"/> are the reference's VerifyTokenOptions (expectedMerchant, amount, verifyKey, alg, now, expectedSession, expectedCurrency,
    /// pcActn, grant, audience, authorizedPlanRoots, insecureSkipPlanRootCheck, singleUse (a <see cref="ClaimFn"/>), strict).</summary>
    public static D VerifyDelegatedPaymentToken(object? token, D opts, Func<long>? clock = null)
    {
        if (G(opts, "strict") is not false)
        {
            if (G(opts, "singleUse") is not ClaimFn) return Res(false, "strict settlement requires a singleUse store (fail closed)");
            if (!NonEmpty(G(opts, "expectedCurrency"))) return Res(false, "strict settlement requires expectedCurrency (fail closed)");
        }
        var res = VerifyBinding(token, opts, clock);
        if (res["ok"] is not true || !Has(opts, "singleUse")) return res;
        var claims = (D)res["claims"]!;
        bool first = false;
        try
        {
            var su = G(opts, "singleUse");
            if (su is not ClaimFn claim) throw JsX.TypeError("singleUse.claim is not a function");
            first = claim((string)claims["jti"]!, JsX.NumOf(claims["exp"])!.Value) is true;
        }
        catch (Exception) { return Res(false, "single-use store unavailable (fail closed)", claims); }
        return first ? res : Res(false, "the delegated payment token was already redeemed", claims);
    }

    static D VerifyBinding(object? token, D opts, Func<long>? clock)
    {
        var algO = Nn(G(opts, "alg"), "EdDSA");
        double now = Finite(G(opts, "now")) ?? Now(clock);

        D? claims;
        try
        {
            var gate = J.AssertCanonicalCompactJws(token);
            if (algO is not string alg) throw JsX.TypeError("alg must be a string");
            var vk = G(opts, "verifyKey");
            object? key = vk is D jwk && jwk.ContainsKey("kty") ? J.ImportJwk(jwk, alg) : (IsUndef(vk) ? null : vk);
            J.CompactVerify((string)token!, key, new AtlasPca.Jose.JwtVerifyOptions { Algorithms = new[] { alg } });
            claims = ParseClaims(gate.Payload);
        }
        catch (Exception e) { return Res(false, "token signature did not verify: " + e.Message); }
        if (claims == null) return Res(false, "token payload is not a well-formed delegated payment token");

        var expectedMerchant = G(opts, "expectedMerchant");
        if (!JsX.StrictEq(claims["merchant"], expectedMerchant)) return Res(false, $"token merchant \"{S(claims["merchant"])}\" does not match expected \"{S(expectedMerchant)}\"", claims);
        var amount = G(opts, "amount");
        if (!IsAmount(amount)) return Res(false, "settlement amount must be a positive integer in minor units", claims);
        if (!(JsX.NumOf(amount)!.Value <= JsX.NumOf(claims["amount"])!.Value)) return Res(false, $"settlement amount {S(amount)} exceeds the token's authorized amount {S(claims["amount"])}", claims);
        if (!(now <= JsX.NumOf(claims["exp"])!.Value)) return Res(false, "the delegated payment token has expired", claims);
        var expectedSession = G(opts, "expectedSession");
        if (!IsUndef(expectedSession) && !JsX.StrictEq(claims["session"], expectedSession)) return Res(false, $"token session \"{S(claims["session"])}\" does not match expected \"{S(expectedSession)}\"", claims);
        var expectedCurrency = G(opts, "expectedCurrency");
        if (!IsUndef(expectedCurrency) && !JsX.StrictEq(claims["currency"], expectedCurrency)) return Res(false, $"token currency \"{S(claims["currency"])}\" does not match expected \"{S(expectedCurrency)}\"", claims);

        var grant = G(opts, "grant");
        var pcActn = G(opts, "pcActn");
        if (!IsUndef(grant) && IsUndef(pcActn)) return Res(false, "a grant was supplied without the pcActn to re-verify (fail closed)", claims);
        if (!IsUndef(pcActn))
        {
            if (Pca.HashCanonical(pcActn) != (string)((D)claims["pca"]!)["digest"]!) return Res(false, "pcactn_digest mismatch: the supplied proof is not the one that minted this token", claims);
            if (!IsUndef(grant))
            {
                var core = RunCore(pcActn, grant, now, opts);
                var pr = new D { ["allow"] = core.Allow, ["reason"] = core.Reason };
                if (!core.Allow) return Res(false, $"bound proof failed to verify: {(core.Reason.Length > 0 ? core.Reason : "denied")}", claims, pr);
                return Res(true, null, claims, pr);
            }
        }
        return Res(true, null, claims);
    }

    static Verdict RunCore(object? pcActn, object? grant, double now, D opts)
    {
        var aud = G(opts, "audience");
        if (grant is not D g || aud is not string audience) return new Verdict { Allow = false, Reason = "audience and grant are required (fail closed)" };
        var roots = G(opts, "authorizedPlanRoots");
        bool skip = G(opts, "insecureSkipPlanRootCheck") is true;
        var policy = roots is L rl ? new PlanRootPolicy(rl.OfType<string>().ToList(), skip) : new PlanRootPolicy(null, skip);
        return Pca.VerifyPcactnCore(pcActn, g, (long)Math.Floor(now), audience, null, null, null, null, policy);
    }

    static D? ParseClaims(D? c)
    {
        if (c == null) return null;
        if (!JsX.StrictEq(G(c, "typ"), AcpDelegatedTokenType) || !JsX.StrictEq(G(c, "ver"), N(AcpDelegatedTokenVersion))) return null;
        if (!NonEmpty(G(c, "jti")) || !NonEmpty(G(c, "session")) || !NonEmpty(G(c, "merchant")) || !IsAmount(G(c, "amount")) || !NonEmpty(G(c, "currency"))) return null;
        if (Finite(G(c, "iat")) == null || Finite(G(c, "exp")) == null) return null;
        if (G(c, "humanPresent") is not bool) return null;
        if (G(c, "paymentMethod") is not D pm || G(pm, "type") is not string) return null;
        if (G(c, "pca") is not D p) return null;
        foreach (var k in new[] { "digest", "aud", "grant_ref", "leaf_holder", "verb", "resource", "params_digest" })
            if (G(p, k) is not string) return null;
        return c;
    }

    // ===== x402 v1 =====

    /// <summary>The HTTP 402 challenge for a protected resource (x402 v1): <c>{status, headers, body: {x402Version, error, accepts}}</c>.
    /// <paramref name="opts"/>: amount, currency (the asset), payTo, network, description, scheme, mimeType, error, maxTimeoutSeconds.</summary>
    public static D X402Challenge(object? resource, D opts)
    {
        if (!IsAmount(G(opts, "amount"))) throw new AcpTypeException("x402Challenge: amount must be a positive integer in atomic/minor units");
        if (!NonEmpty(G(opts, "payTo"))) throw new AcpTypeException("x402Challenge: payTo is required");
        if (!NonEmpty(G(opts, "currency"))) throw new AcpTypeException("x402Challenge: currency (the x402 asset) is required");
        var timeout = Nn(G(opts, "maxTimeoutSeconds"), N(60));
        if (!JsX.SafeInt(timeout) || JsX.NumOf(timeout)!.Value <= 0) throw new AcpTypeException("x402Challenge: maxTimeoutSeconds must be a positive integer");
        var req = new D
        {
            ["maxTimeoutSeconds"] = timeout,
            ["scheme"] = Nn(G(opts, "scheme"), "exact"),
            ["network"] = Nn(G(opts, "network"), "base-sepolia"),
            ["maxAmountRequired"] = S(G(opts, "amount")),
            ["resource"] = resource,
            ["description"] = Nn(G(opts, "description"), $"Payment required for {S(resource)}"),
            ["payTo"] = G(opts, "payTo"),
            ["asset"] = G(opts, "currency"),
            ["mimeType"] = Nn(G(opts, "mimeType"), "application/json"),
        };
        return new D
        {
            ["status"] = N(402),
            ["headers"] = new D { ["Content-Type"] = "application/json" },
            ["body"] = new D { ["x402Version"] = N(1), ["error"] = Nn(G(opts, "error"), "X-PAYMENT header is required"), ["accepts"] = new L { req } },
        };
    }

    /// <summary>Gate an x402 settlement on a verified, PCActn-bound payment. <paramref name="verify"/> is the injected verifier (see
    /// <see cref="AcpX402Verifier"/>), <paramref name="settle"/> an optional settlement step run after it passes (its result is the receipt;
    /// return <see cref="Undefined"/> for none). Returns <c>{settled, status, reason?, claims?, receipt?}</c>.</summary>
    public static D X402Settle(object? payload, Func<object?, D> verify, Func<object?, object?, object?>? settle = null)
    {
        var norm = NormalizeX402(payload);
        if (!norm.Ok) return new D { ["settled"] = false, ["status"] = N(402), ["reason"] = norm.Reason };
        var v = verify(payload);
        if (!JsX.Truthy(G(v, "ok")))
        {
            var r = new D { ["settled"] = false, ["status"] = N(402), ["reason"] = Nn(G(v, "reason"), "payment verification failed") };
            if (JsX.Truthy(G(v, "claims"))) r["claims"] = G(v, "claims");
            return r;
        }
        var claims = G(v, "claims");
        if (IsUndef(claims)) return new D { ["settled"] = false, ["status"] = N(402), ["reason"] = "verifier admitted the payment but returned no claims (fail closed)" };
        var receipt = settle != null ? settle(payload, claims) : Undefined;
        var o = new D { ["settled"] = true, ["status"] = N(200), ["claims"] = claims };
        if (!IsUndef(receipt)) o["receipt"] = receipt;
        return o;
    }

    /// <summary>Adapt <see cref="VerifyDelegatedPaymentToken"/> into the verifier <see cref="X402Settle"/> takes: reads the token (and, unless
    /// strict, the merchant and amount) from the x402 payload of either version. <paramref name="opts"/>: verifyKey, alg, now, expectedMerchant,
    /// offered, amount, expectedSession, expectedCurrency, pcActn, grant, audience, authorizedPlanRoots, insecureSkipPlanRootCheck, singleUse, strict.</summary>
    public static Func<object?, D> AcpX402Verifier(D opts, Func<long>? clock = null) => payload =>
    {
        var norm = NormalizeX402(payload);
        if (!norm.Ok) return Res(false, norm.Reason);
        var offered = G(opts, "offered");
        if (norm.Version == 2 && !IsUndef(offered) && !X402AcceptedMatchesAny(offered, norm.Accepted))
            return Res(false, "x402 v2 payload.accepted is not one of the requirements this server offered");
        if (G(opts, "strict") is not false && (IsUndef(G(opts, "expectedMerchant")) || IsUndef(G(opts, "amount"))))
            return Res(false, "strict settlement requires the server to supply expectedMerchant and amount (fail closed)");
        var merchant = Nn(G(opts, "expectedMerchant"), norm.Merchant);
        if (!NonEmpty(merchant)) return Res(false, "x402 payload has no merchant to check the token against");
        var amount = Nn(G(opts, "amount"), norm.Amount);
        if (!IsAmount(amount)) return Res(false, "x402 payload has no amount to check the token against");
        var vo = new D { ["expectedMerchant"] = merchant, ["amount"] = amount, ["verifyKey"] = G(opts, "verifyKey") };
        foreach (var k in new[] { "alg", "now", "expectedSession", "expectedCurrency", "pcActn", "grant", "audience", "authorizedPlanRoots", "insecureSkipPlanRootCheck", "singleUse", "strict" })
            if (Has(opts, k)) vo[k] = opts[k];
        var res = VerifyDelegatedPaymentToken(norm.Token, vo, clock);
        var o = new D { ["ok"] = res["ok"] };
        if (res.TryGetValue("reason", out var rs)) o["reason"] = rs;
        if (res.TryGetValue("claims", out var cl) && cl != null) o["claims"] = cl;
        return o;
    };

    // ===== ACP delegate_payment allowance =====

    /// <summary>Map VERIFIED token claims to the ACP delegate_payment <c>allowance</c>; throws when a claim cannot be expressed in the ACP shape.</summary>
    public static D ToAcpAllowance(D claims)
    {
        var amount = G(claims, "amount");
        if (!IsAmount(amount)) throw new AcpAuthorityException("allowance: amount must be a positive integer in minor units");
        var currency = G(claims, "currency") is string cs ? JsLower(cs) : "";
        if (!IsLower3(currency)) throw new AcpAuthorityException("allowance: currency must be a three-letter ISO-4217 code");
        var merchant = G(claims, "merchant");
        if (merchant is not string m || m.Length == 0 || m.Length > 256) throw new AcpAuthorityException("allowance: merchant_id must be 1 to 256 characters");
        var session = G(claims, "session");
        if (session is not string ss || ss.Length == 0) throw new AcpAuthorityException("allowance: checkout_session_id is required");
        var exp = G(claims, "exp");
        string iso;
        try { iso = Finite(exp) == null ? throw new ArgumentException("not finite") : JsX.ToIsoString(exp); }
        catch (ArgumentException) { throw new AcpAuthorityException("allowance: expiry is not a valid time"); }
        return new D { ["reason"] = "one_time", ["max_amount"] = amount, ["currency"] = currency, ["checkout_session_id"] = ss, ["merchant_id"] = m, ["expires_at"] = iso };
    }
}

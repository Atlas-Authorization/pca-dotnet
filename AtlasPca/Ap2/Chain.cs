// AP2 delegation chains: issuing open mandates, presenting closed mandates (key-binding hops), and verifying checkout / payment chains,
// the purchase pair and a redeem with a spend ledger. Options are D bags with the reference's member names; key resolvers and the ledger are delegates.
using AtlasPca.InteropJs;
using AtlasPca.Js;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Ap2;

/// <summary>Resolves the verification key (a public P-256 JWK) for a JWT header, or null when there is none.</summary>
public delegate object? KeyResolver(D header);

/// <summary>The issuer of an open mandate: its signing key and the header members to stamp.</summary>
public sealed class MandateIssuer(Ap2KeyPair privateKey, string? kid = null, L? x5c = null)
{
    public Ap2KeyPair PrivateKey { get; } = privateKey;
    public string? Kid { get; } = kid;
    public L? X5c { get; } = x5c;
}

/// <summary>A verified hop of a delegation chain.</summary>
public sealed class VerifiedHop
{
    public int Index;
    public string Kind = "";
    public SdJwtHop Hop = new();
    public D Claims = new();
    public D Mandate = new();
}

/// <summary>The result of a chain verification: <c>Ok</c> with the hops (and, for a checkout / payment chain, the open and closed mandates,
/// the checkout JWT and projected checkout, and the open mandate's hash), or a <c>Reason</c> (and the constraint <c>Violations</c>).</summary>
public sealed class ChainResult
{
    public bool Ok;
    public string Reason = "";
    public List<string>? Violations;
    public List<VerifiedHop> Hops = new();
    public D? Open;
    public D? Closed;
    public string? CheckoutJwt;
    public D? Checkout;
    public string? OpenHash;
    public static ChainResult Fail(string reason, List<string>? violations = null) => new() { Ok = false, Reason = reason, Violations = violations };
}

/// <summary>The result of a purchase (checkout chain + payment chain) verification.</summary>
public sealed class PurchaseResult
{
    public bool Ok;
    public string Reason = "";
    public ChainResult? Checkout;
    public ChainResult? Payment;
    public static PurchaseResult Fail(string reason) => new() { Ok = false, Reason = reason };
}

/// <summary>The spend ledger of <see cref="Ap2.RedeemPurchase"/>: <c>Reserve</c> returns the mandate context, the string "replayed", or throws;
/// <c>Release</c> drops a reservation.</summary>
public sealed class PurchaseLedger(Func<string, string, double, object?> reserve, Action<string, string> release)
{
    public Func<string, string, double, object?> Reserve { get; } = reserve;
    public Action<string, string> Release { get; } = release;
}

public static partial class Ap2
{
    const string RootTyp = "dc+sd-jwt";
    const int MaxHops = 8;

    // ===== issuing =====

    static D CommonClaims(D c)
    {
        var jwk = AssertP256Jwk(G(c, "agentJwk"), "agentJwk");
        var iat = G(c, "iat");
        var exp = G(c, "exp");
        if (!JsX.SafeInt(iat) || !JsX.SafeInt(exp) || Dbl(exp) <= Dbl(iat)) throw new Ap2Exception("open mandate: need integer iat < exp (epoch seconds)");
        var r = new D
        {
            ["cnf"] = new D { ["jwk"] = new D { ["crv"] = "P-256", ["kty"] = "EC", ["x"] = jwk["x"], ["y"] = jwk["y"] } },
            ["iat"] = iat,
            ["exp"] = exp,
        };
        if (Truthy(G(c, "pca"))) r[PcaClaim] = G(c, "pca");
        return r;
    }

    static string SignRoot(D c, MandateIssuer issuer, D mandate, DisclosureBuilder b)
    {
        var element = b.Element(mandate);
        var header = new D { ["typ"] = Nn(G(c, "typ"), RootTyp) };
        if (issuer.Kid != null) header["kid"] = issuer.Kid;
        if (issuer.X5c != null) header["x5c"] = issuer.X5c;
        var payload = new D { ["delegate_payload"] = new L { element }, ["_sd_alg"] = Nn(G(c, "sdAlg"), "sha-256") };
        return SignSdJwt(header, payload, b.Disclosures, issuer.PrivateKey);
    }

    static L AllowedElements(object? allowed, DisclosureBuilder b)
    {
        if (allowed is not L l) throw JsX.TypeError("c.allowed.map is not a function");
        return l.Select(x => (object?)b.Element(x)).ToList();
    }

    static object? SdPaymentConstraint(object? c, DisclosureBuilder b)
    {
        var type = G(c, "type");
        if (JsX.StrictEq(type, "payment.allowed_payees") || JsX.StrictEq(type, "payment.allowed_payment_instruments"))
            return new D { ["type"] = type, ["allowed"] = AllowedElements(G(c, "allowed"), b) };
        return c;
    }

    static object? SdCheckoutConstraint(object? c, DisclosureBuilder b)
    {
        var type = G(c, "type");
        if (JsX.StrictEq(type, "checkout.allowed_merchants")) return new D { ["type"] = type, ["allowed"] = AllowedElements(G(c, "allowed"), b) };
        if (G(c, "items") is not L items) throw JsX.TypeError("c.items.map is not a function");
        return new D
        {
            ["type"] = type,
            ["items"] = items.Select(it => (object?)new D { ["id"] = G(it, "id"), ["acceptable_items"] = AllowedElements(G(it, "acceptable_items"), b), ["quantity"] = G(it, "quantity") }).ToList(),
        };
    }

    static void AssertWellFormed(D wrapped, Func<object?, List<string>> problems, string what, object? plainConstraints)
    {
        var plain = new D(wrapped) { ["constraints"] = plainConstraints };
        var p = problems(plain);
        if (p.Count > 0) throw new Ap2Exception($"{what}: {string.Join("; ", p)}");
    }

    /// <summary>Issue (sign) an open payment mandate. <paramref name="input"/>: agentJwk, iat, exp, pca?, sdAlg?, typ?, constraints, payee?, paymentAmount?,
    /// paymentInstrument?, pisp?, executionDate?. <paramref name="salt"/> supplies the disclosure salts (default random).</summary>
    public static string IssueOpenPaymentMandate(D input, MandateIssuer issuer, Func<string>? salt = null)
    {
        var b = NewDisclosureBuilder(Nn(G(input, "sdAlg"), "sha-256") as string ?? "", salt);
        var constraints = G(input, "constraints") as L ?? throw JsX.TypeError("input.constraints.map is not a function");
        var mandate = new D { ["vct"] = VctPaymentOpen, ["constraints"] = constraints.Select(c => SdPaymentConstraint(c, b)).ToList() };
        if (Truthy(G(input, "payee"))) mandate["payee"] = G(input, "payee");
        if (Truthy(G(input, "paymentAmount"))) mandate["payment_amount"] = G(input, "paymentAmount");
        if (Truthy(G(input, "paymentInstrument"))) mandate["payment_instrument"] = G(input, "paymentInstrument");
        if (Truthy(G(input, "pisp"))) mandate["pisp"] = G(input, "pisp");
        if (!IsUndef(G(input, "executionDate"))) mandate["execution_date"] = G(input, "executionDate");
        foreach (var kv in CommonClaims(input)) mandate[kv.Key] = kv.Value;
        AssertWellFormed(mandate, OpenPaymentMandateProblems, "open payment mandate", constraints);
        return SignRoot(input, issuer, mandate, b);
    }

    /// <summary>Issue (sign) an open checkout mandate. <paramref name="input"/>: agentJwk, iat, exp, pca?, sdAlg?, typ?, constraints.</summary>
    public static string IssueOpenCheckoutMandate(D input, MandateIssuer issuer, Func<string>? salt = null)
    {
        var b = NewDisclosureBuilder(Nn(G(input, "sdAlg"), "sha-256") as string ?? "", salt);
        var constraints = G(input, "constraints") as L ?? throw JsX.TypeError("input.constraints.map is not a function");
        var mandate = new D { ["vct"] = VctCheckoutOpen, ["constraints"] = constraints.Select(c => SdCheckoutConstraint(c, b)).ToList() };
        foreach (var kv in CommonClaims(input)) mandate[kv.Key] = kv.Value;
        AssertWellFormed(mandate, OpenCheckoutMandateProblems, "open checkout mandate", constraints);
        return SignRoot(input, issuer, mandate, b);
    }

    static string PresentHop(D c, Ap2KeyPair agentKey, Func<string>? salt, Func<DisclosureBuilder, D> build)
    {
        if (!Truthy(G(c, "aud")) || !Truthy(G(c, "nonce"))) throw new Ap2Exception("closed mandate: aud and nonce are required");
        if (!JsX.SafeInt(G(c, "iat"))) throw new Ap2Exception("closed mandate: iat must be an integer");
        var prev = ParseSdJwtHop(G(c, "open"));
        var b = NewDisclosureBuilder(prev.SdAlg, salt);
        var mandate = build(b);
        var element = b.Element(mandate);
        var mode = Nn(G(c, "hashMode"), "sd_hash");
        var payload = new D { ["delegate_payload"] = new L { element }, ["iat"] = G(c, "iat"), ["aud"] = G(c, "aud"), ["nonce"] = G(c, "nonce") };
        payload[S(mode)] = JsX.StrictEq(mode, "sd_hash") ? SdHashOf(prev) : IssuerJwtHashOf(prev);
        payload["_sd_alg"] = prev.SdAlg;
        var hop = SignSdJwt(new D { ["typ"] = "kb+sd-jwt" }, payload, b.Disclosures, agentKey);
        return $"{(string)G(c, "open")!}~{hop}";
    }

    /// <summary>Present (sign) a closed payment mandate as the next hop after <c>input.open</c>. <paramref name="input"/>: open, aud, nonce, iat, exp?, pca?,
    /// hashMode?, transactionId, payee, paymentAmount, paymentInstrument, pisp?, executionDate?, riskData?.</summary>
    public static string PresentClosedPayment(D input, Ap2KeyPair agentKey, Func<string>? salt = null) => PresentHop(input, agentKey, salt, _ =>
    {
        var mandate = new D
        {
            ["vct"] = VctPayment,
            ["transaction_id"] = G(input, "transactionId"),
            ["payee"] = G(input, "payee"),
            ["payment_amount"] = G(input, "paymentAmount"),
            ["payment_instrument"] = G(input, "paymentInstrument"),
        };
        foreach (var k in new[] { "payee", "payment_amount", "payment_instrument", "transaction_id" }) if (IsUndef(mandate[k])) mandate.Remove(k);
        if (Truthy(G(input, "pisp"))) mandate["pisp"] = G(input, "pisp");
        if (!IsUndef(G(input, "executionDate"))) mandate["execution_date"] = G(input, "executionDate");
        if (Truthy(G(input, "riskData"))) mandate["risk_data"] = G(input, "riskData");
        if (!IsUndef(G(input, "exp"))) mandate["exp"] = G(input, "exp");
        if (Truthy(G(input, "pca"))) mandate[PcaClaim] = G(input, "pca");
        var p = PaymentMandateProblems(mandate);
        if (p.Count > 0) throw new Ap2Exception($"closed payment mandate: {string.Join("; ", p)}");
        return mandate;
    });

    /// <summary>Present (sign) a closed checkout mandate. <paramref name="input"/>: open, aud, nonce, iat, exp?, pca?, hashMode?, checkoutJwt.</summary>
    public static string PresentClosedCheckout(D input, Ap2KeyPair agentKey, Func<string>? salt = null) => PresentHop(input, agentKey, salt, b =>
    {
        var prevAlg = ParseSdJwtHop(G(input, "open")).SdAlg;
        var jwt = G(input, "checkoutJwt");
        var mandate = new D
        {
            ["_sd"] = new L { b.Property("checkout_jwt", jwt) },
            ["vct"] = VctCheckout,
            ["checkout_hash"] = SdDigest(jwt, prevAlg),
        };
        if (!IsUndef(G(input, "exp"))) mandate["exp"] = G(input, "exp");
        if (Truthy(G(input, "pca"))) mandate[PcaClaim] = G(input, "pca");
        var withJwt = new D(mandate) { ["checkout_jwt"] = jwt };
        var p = CheckoutMandateProblems(withJwt);
        if (p.Count > 0) throw new Ap2Exception($"closed checkout mandate: {string.Join("; ", p)}");
        return mandate;
    });

    // ===== verifying =====

    /// <summary>Split a chain token at its <c>~~</c> hop boundaries (each hop keeps its trailing <c>~</c>); at most 8 hops.</summary>
    public static List<string> SplitChain(object? token)
    {
        if (token is not string t || t.Length == 0) throw new Ap2Exception("chain: empty");
        var parts = t.Split("~~");
        if (parts.Length > MaxHops) throw new Ap2Exception($"chain: more than {MaxHops} hops");
        return parts.Select((p, i) => i == parts.Length - 1 ? p : p + "~").ToList();
    }

    static void CheckTimes(string label, D o, double now, double skew)
    {
        var exp = G(o, "exp");
        if (!IsUndef(exp))
        {
            if (!IsInt(exp)) throw new Ap2Exception($"{label}: exp must be an integer");
            if (!(double.IsFinite(now) && double.IsFinite(skew) && now <= Dbl(exp) + skew)) throw new Ap2Exception($"{label}: expired at {S(exp)}");
        }
        var iat = G(o, "iat");
        if (!IsUndef(iat))
        {
            if (!IsInt(iat)) throw new Ap2Exception($"{label}: iat must be an integer");
            if (!(double.IsFinite(now) && double.IsFinite(skew) && Dbl(iat) <= now + skew)) throw new Ap2Exception($"{label}: iat is in the future");
        }
    }

    static D DelegateMandate(D claims, string label)
    {
        if (G(claims, "delegate_payload") is not L dp) throw new Ap2Exception($"{label}: delegate_payload missing");
        if (dp.Count != 1 || dp[0] is not D m) throw new Ap2Exception($"{label}: delegate_payload must disclose exactly one mandate (got {dp.Count})");
        return m;
    }

    static D CnfJwk(D mandate, string label)
    {
        if (G(mandate, "cnf") is not D cnf || G(cnf, "jwk") is not D jwk) throw new Ap2Exception($"{label}: no cnf.jwk to delegate to");
        return AssertP256Jwk(jwk, $"{label} cnf.jwk");
    }

    /// <summary>Verify a key-binding hop against the preceding hop and its mandate. <paramref name="o"/>: terminal, expectedAudience?, expectedNonce?, now, skew.</summary>
    public static VerifiedHop VerifyKbHop(SdJwtHop hop, SdJwtHop prevHop, D prevMandate, D o, string label)
    {
        var typ = G(hop.Header, "typ");
        var terminal = JsX.Truthy(G(o, "terminal"));
        var allowed = terminal ? TypTerminal : TypIntermediate;
        if (typ is not string ts || !allowed.Contains(ts)) throw new Ap2Exception($"{label}: typ must be one of {string.Join(", ", allowed)}");
        if (!IsUndef(G(hop.Header, "crit"))) throw new Ap2Exception($"{label}: crit headers are not supported");
        var key = CnfJwk(prevMandate, "preceding mandate");
        if (!VerifyHopSignature(hop, key)) throw new Ap2Exception($"{label}: signature does not verify under the preceding mandate's cnf.jwk");
        var claims = ProcessDisclosures(hop.Payload, hop.Disclosures, hop.SdAlg);
        bool hasSd = claims.ContainsKey("sd_hash"), hasIss = claims.ContainsKey("issuer_jwt_hash");
        if (hasSd == hasIss) throw new Ap2Exception($"{label}: exactly one of sd_hash / issuer_jwt_hash is required");
        var expected = hasSd ? SdHashOf(prevHop) : IssuerJwtHashOf(prevHop);
        var actual = hasSd ? claims["sd_hash"] : claims["issuer_jwt_hash"];
        if (!JsX.StrictEq(actual, expected)) throw new Ap2Exception($"{label}: {(hasSd ? "sd_hash" : "issuer_jwt_hash")} does not match the preceding hop");
        if (IsUndef(G(claims, "iat"))) throw new Ap2Exception($"{label}: iat is required");
        double now = Dbl(G(o, "now")), skew = Dbl(G(o, "skew"));
        CheckTimes(label, claims, now, skew);
        var mandate = DelegateMandate(claims, label);
        CheckTimes($"{label} mandate", mandate, now, skew);
        bool hasCnf = IsObject(G(mandate, "cnf"));
        if (terminal && hasCnf) throw new Ap2Exception($"{label}: a terminal hop must not carry cnf");
        if (!terminal && !hasCnf) throw new Ap2Exception($"{label}: an intermediate hop requires cnf");
        if (terminal)
        {
            var aud = G(o, "expectedAudience");
            if (IsUndef(aud) || !JsX.StrictEq(G(claims, "aud"), aud)) throw new Ap2Exception($"{label}: aud mismatch");
            var nonce = G(o, "expectedNonce");
            if (IsUndef(nonce) || !JsX.StrictEq(G(claims, "nonce"), nonce)) throw new Ap2Exception($"{label}: nonce mismatch");
        }
        return new VerifiedHop { Index = -1, Kind = terminal ? "terminal" : "intermediate", Hop = hop, Claims = claims, Mandate = mandate };
    }

    static KeyResolver? Resolver(D o, string name) => G(o, name) as KeyResolver;

    /// <summary>Verify a delegation chain: the root under the resolved issuer key, then each key-binding hop under the preceding mandate's cnf.jwk.
    /// <paramref name="o"/>: resolveIssuerKey (<see cref="KeyResolver"/>), expectedAudience, expectedNonce, now?, clockSkewSeconds?.</summary>
    public static ChainResult VerifyDelegationChain(object? token, D o, Func<long>? clock = null)
    {
        try
        {
            if (!Truthy(G(o, "expectedAudience")) || !Truthy(G(o, "expectedNonce"))) throw new Ap2Exception("verify: expectedAudience and expectedNonce are required");
            double now = Nn(G(o, "now"), null) is { } nv ? Dbl(nv) : (clock != null ? clock() : NowSeconds());
            double skew = Nn(G(o, "clockSkewSeconds"), null) is { } sv ? Dbl(sv) : 60;
            var segments = SplitChain(token).Select(t => ParseSdJwtHop(t)).ToList();
            var root = segments[0];
            if (!IsUndef(G(root.Header, "crit"))) throw new Ap2Exception("root: crit headers are not supported");
            var resolver = Resolver(o, "resolveIssuerKey") ?? throw JsX.TypeError("o.resolveIssuerKey is not a function");
            var issuerKey = resolver(root.Header);
            if (!Truthy(issuerKey)) throw new Ap2Exception("root: no issuer key for this header");
            if (!VerifyHopSignature(root, issuerKey)) throw new Ap2Exception("root: signature does not verify under the issuer key");
            var rootClaims = ProcessDisclosures(root.Payload, root.Disclosures, root.SdAlg);
            CheckTimes("root", rootClaims, now, skew);
            var rootMandate = DelegateMandate(rootClaims, "root");
            CheckTimes("root mandate", rootMandate, now, skew);
            var hops = new List<VerifiedHop> { new() { Index = 0, Kind = "root", Hop = root, Claims = rootClaims, Mandate = rootMandate } };
            for (int i = 1; i < segments.Count; i++)
            {
                var prev = hops[i - 1];
                var kbo = new D { ["terminal"] = i == segments.Count - 1, ["expectedAudience"] = G(o, "expectedAudience"), ["expectedNonce"] = G(o, "expectedNonce"), ["now"] = Num_(now), ["skew"] = Num_(skew) };
                var v = VerifyKbHop(segments[i], prev.Hop, prev.Mandate, kbo, $"hop {i}");
                v.Index = i;
                hops.Add(v);
            }
            return new ChainResult { Ok = true, Hops = hops };
        }
        catch (Exception e) { return ChainResult.Fail(e.Message); }
    }

    static (VerifiedHop, VerifiedHop) Pair(ChainResult r)
    {
        if (r.Hops.Count != 2) throw new Ap2Exception($"expected an open mandate followed by one closed mandate, got {r.Hops.Count} hop(s)");
        return (r.Hops[0], r.Hops[1]);
    }

    static void RequireOpenExpiry(D m, string label)
    {
        if (!JsX.SafeInt(G(m, "exp"))) throw new Ap2Exception($"{label}: an open mandate must carry exp");
    }

    /// <summary>Verify a checkout chain (open checkout mandate then closed checkout mandate) and the merchant's checkout JWT against the open
    /// constraints. <paramref name="o"/> adds resolveMerchantKey (<see cref="KeyResolver"/>) to the chain options.</summary>
    public static ChainResult VerifyCheckoutChain(object? token, D o, Func<long>? clock = null)
    {
        var r = VerifyDelegationChain(token, o, clock);
        if (!r.Ok) return r;
        try
        {
            var (openHop, closedHop) = Pair(r);
            var open = openHop.Mandate;
            var closed = closedHop.Mandate;
            var op = OpenCheckoutMandateProblems(open);
            if (op.Count > 0) throw new Ap2Exception($"open checkout mandate: {string.Join("; ", op)}");
            RequireOpenExpiry(open, "open checkout mandate");
            var cp = CheckoutMandateProblems(closed);
            if (cp.Count > 0) throw new Ap2Exception($"closed checkout mandate: {string.Join("; ", cp)}");
            var checkoutJwt = (string)closed["checkout_jwt"]!;
            if (SdDigest(checkoutJwt, closedHop.Hop.SdAlg) != (string)closed["checkout_hash"]!) throw new Ap2Exception("checkout_hash does not match checkout_jwt");
            var jwt = ParseJwt(checkoutJwt, "checkout_jwt");
            var resolver = Resolver(o, "resolveMerchantKey") ?? throw JsX.TypeError("o.resolveMerchantKey is not a function");
            var key = resolver(jwt.Header);
            if (!Truthy(key)) throw new Ap2Exception("checkout_jwt: no merchant key for this header");
            if (!VerifyJwtEs256(jwt, key)) throw new Ap2Exception("checkout_jwt: merchant signature does not verify");
            var checkout = ProjectCheckout(jwt.Payload);
            var violations = CheckCheckoutConstraints(open, checkout);
            if (violations.Count > 0) return ChainResult.Fail($"open checkout constraints violated: {string.Join("; ", violations)}", violations);
            return new ChainResult { Ok = true, Open = open, Closed = closed, CheckoutJwt = checkoutJwt, Checkout = checkout, OpenHash = SdHashOf(openHop.Hop), Hops = r.Hops };
        }
        catch (Exception e) { return ChainResult.Fail(e.Message); }
    }

    /// <summary>Verify a payment chain (open payment mandate then closed payment mandate) against the open constraints. <paramref name="o"/> adds
    /// openCheckoutHash, context?, expectedTransactionId? to the chain options.</summary>
    public static ChainResult VerifyPaymentChain(object? token, D o, Func<long>? clock = null)
    {
        var r = VerifyDelegationChain(token, o, clock);
        if (!r.Ok) return r;
        try
        {
            var (openHop, closedHop) = Pair(r);
            var open = openHop.Mandate;
            var closed = closedHop.Mandate;
            var op = OpenPaymentMandateProblems(open);
            if (op.Count > 0) throw new Ap2Exception($"open payment mandate: {string.Join("; ", op)}");
            RequireOpenExpiry(open, "open payment mandate");
            var cp = PaymentMandateProblems(closed);
            if (cp.Count > 0) throw new Ap2Exception($"closed payment mandate: {string.Join("; ", cp)}");
            var expectedTx = G(o, "expectedTransactionId");
            if (!IsUndef(expectedTx) && !JsX.StrictEq(closed["transaction_id"], expectedTx)) throw new Ap2Exception("transaction_id does not match the checkout being settled");
            var co = new D { ["openCheckoutHash"] = G(o, "openCheckoutHash") };
            if (Truthy(G(o, "context"))) co["context"] = G(o, "context");
            co["now"] = Nn(G(o, "now"), null) ?? N(clock != null ? clock() : NowSeconds());
            var violations = CheckPaymentConstraints(open, closed, co);
            if (violations.Count > 0) return ChainResult.Fail($"open payment constraints violated: {string.Join("; ", violations)}", violations);
            return new ChainResult { Ok = true, Open = open, Closed = closed, OpenHash = SdHashOf(openHop.Hop), Hops = r.Hops };
        }
        catch (Exception e) { return ChainResult.Fail(e.Message); }
    }

    static D Merge(params object?[] parts)
    {
        var d = new D();
        foreach (var p in parts) if (p is D pd) foreach (var kv in pd) d[kv.Key] = kv.Value;
        return d;
    }

    /// <summary>Verify a checkout chain and a payment chain together and check that they describe the same purchase. <paramref name="o"/>:
    /// resolveIssuerKey, resolveMerchantKey, checkout {expectedAudience, expectedNonce}, payment {expectedAudience, expectedNonce}, context?, now?, clockSkewSeconds?.</summary>
    public static PurchaseResult VerifyPurchase(object? checkoutToken, object? paymentToken, D o, Func<long>? clock = null)
    {
        var bas = new D { ["resolveIssuerKey"] = G(o, "resolveIssuerKey") };
        if (!IsUndef(G(o, "now"))) bas["now"] = G(o, "now");
        if (!IsUndef(G(o, "clockSkewSeconds"))) bas["clockSkewSeconds"] = G(o, "clockSkewSeconds");
        var co = VerifyCheckoutChain(checkoutToken, Merge(bas, G(o, "checkout"), new D { ["resolveMerchantKey"] = G(o, "resolveMerchantKey") }), clock);
        if (!co.Ok) return PurchaseResult.Fail($"checkout: {co.Reason}");
        var payOpts = Merge(bas, G(o, "payment"), new D { ["openCheckoutHash"] = co.OpenHash, ["expectedTransactionId"] = co.Closed!["checkout_hash"] });
        if (Truthy(G(o, "context"))) payOpts["context"] = G(o, "context");
        var pay = VerifyPaymentChain(paymentToken, payOpts, clock);
        if (!pay.Ok) return PurchaseResult.Fail($"payment: {pay.Reason}");
        var total = CheckoutTotal(co.Checkout!);
        if (total == null) return PurchaseResult.Fail("checkout: needs exactly one total entry");
        var amt = pay.Closed!["payment_amount"];
        if (!JsX.StrictEq(G(amt, "currency"), co.Checkout!["currency"])) return PurchaseResult.Fail("payment currency differs from the checkout currency");
        if (!JsX.StrictEq(G(amt, "amount"), total)) return PurchaseResult.Fail($"payment amount {S(G(amt, "amount"))} differs from the checkout total {S(total)}");
        if (!co.Checkout.TryGetValue("merchant", out var merchant) || merchant == null) return PurchaseResult.Fail("checkout: no merchant to compare the payee with");
        if (!JsX.StrictEq(G(merchant, "id"), G(pay.Closed["payee"], "id"))) return PurchaseResult.Fail("payee differs from the checkout merchant");
        return new PurchaseResult { Ok = true, Checkout = co, Payment = pay };
    }

    /// <summary>Redeem a purchase against a spend ledger: verify with an empty context, reserve the spend, verify again with the ledger's context,
    /// release the reservation when the second verification fails. Reasons beyond verification: <c>replayed</c>, <c>ledger_unavailable</c>, <c>ledger_required</c>.</summary>
    public static PurchaseResult RedeemPurchase(object? checkoutToken, object? paymentToken, D o, PurchaseLedger? ledger, Func<long>? clock = null)
    {
        if (ledger == null) return PurchaseResult.Fail("ledger_required");
        var first = VerifyPurchase(checkoutToken, paymentToken, Merge(o, new D { ["context"] = new D { ["totalAmount"] = N(0), ["totalUses"] = N(0) } }), clock);
        if (!first.Ok) return first;
        var openHash = first.Payment!.OpenHash!;
        var txId = (string)first.Payment.Closed!["transaction_id"]!;
        var amount = Dbl(G(first.Payment.Closed["payment_amount"], "amount"));
        object? ctx;
        try { ctx = ledger.Reserve(openHash, txId, amount); }
        catch (Exception) { return PurchaseResult.Fail("ledger_unavailable"); }
        if (ctx is "replayed") return PurchaseResult.Fail("replayed");
        var final = VerifyPurchase(checkoutToken, paymentToken, Merge(o, new D { ["context"] = ctx }), clock);
        if (!final.Ok)
        {
            try { ledger.Release(openHash, txId); }
            catch (Exception) { /* the reservation stays: a failed release only ever over-counts spend */ }
        }
        return final;
    }
}

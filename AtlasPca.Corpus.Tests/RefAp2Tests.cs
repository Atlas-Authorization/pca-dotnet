using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using AtlasPca.Ap2;
using AtlasPca.InteropJs;
using Xunit;
using Ap2Api = AtlasPca.Ap2.Ap2;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Differential replay of the AP2 mandate package against the TypeScript reference (test-data/ref-ap2.json.gz). Keys are derived
/// from labels, salts are counters, and a signing fn is compared with every signature replaced by "SIG" (ECDSA is not reproducible).</summary>
public class RefAp2Tests
{
    const string M = "ref-ap2";

    // ---- keys and salts ----
    static readonly Dictionary<string, Ap2KeyPair> KeyCache = new();

    static byte[] KeyScalar(string label) => SHA256.HashData(Encoding.UTF8.GetBytes("atlas-pca-conformance/ap2/" + label));

    static Ap2KeyPair KeyFor(string label)
    {
        lock (KeyCache)
        {
            if (!KeyCache.TryGetValue(label, out var kp))
                KeyCache[label] = kp = Ap2Api.Ap2KeyPairFromPrivateJwk(new D { ["kty"] = "EC", ["crv"] = "P-256", ["d"] = Ap2Api.B64uEncode(KeyScalar(label)), ["kid"] = label });
            return kp;
        }
    }

    static D PubOf(string label)
    {
        var p = KeyFor(label).PublicJwk;
        return new D { ["kty"] = "EC", ["crv"] = "P-256", ["x"] = p["x"], ["y"] = p["y"] };
    }

    static Func<string> CounterSalt()
    {
        int n = 0;
        return () => Ap2Api.B64uEncode(Encoding.ASCII.GetBytes("salt-" + (++n).ToString("D12")));
    }

    static readonly Regex Jwt3 = new(@"\A[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\z", RegexOptions.CultureInvariant);
    static string StripSig(string t) => string.Join("~", t.Split('~').Select(s => Jwt3.IsMatch(s) ? Regex.Replace(s, @"\.[A-Za-z0-9_-]+\z", ".SIG") : s));

    static readonly D Merch = new() { ["id"] = "merchant_1", ["name"] = "Demo Merchant", ["website"] = "https://demo-merchant.example" };
    static readonly D Merch2 = new() { ["id"] = "merchant_2", ["name"] = "Other Merchant" };

    static object? Arg(L a, int i) => i < a.Count ? a[i] : JsX.Undef;
    static object? Of(object? o, string k) => o is D d && d.TryGetValue(k, out var v) ? v : JsX.Undef;
    static bool Has(object? o, string k) => !ReferenceEquals(Of(o, k), JsX.Undef);

    // ---- option and result wrappers ----
    static KeyResolver Resolver(object? map) => h => map is D m && h.TryGetValue("kid", out var kid) && kid is string k && m.ContainsKey(k) ? m[k] : null;

    static D BaseOpts(D c)
    {
        var o = new D { ["resolveIssuerKey"] = Resolver(Of(c, "issuerKeys")), ["resolveMerchantKey"] = Resolver(Of(c, "merchantKeys")) };
        foreach (var k in new[] { "expectedAudience", "expectedNonce", "now", "clockSkewSeconds" }) if (Has(c, k)) o[k] = c[k];
        return o;
    }

    static string Mask(string s) => Regex.Replace(s, @"invalid JSON \(.*\)\z", "invalid JSON (*)", RegexOptions.Singleline);

    static D HopOut(VerifiedHop h) => new() { ["index"] = h.Index, ["kind"] = h.Kind, ["claims"] = h.Claims, ["mandate"] = h.Mandate };

    static D ProjChain(ChainResult r)
    {
        if (!r.Ok)
        {
            var f = new D { ["ok"] = false, ["reason"] = Mask(r.Reason) };
            if (r.Violations != null) f["violations"] = r.Violations.Cast<object?>().ToList();
            return f;
        }
        var o = new D { ["ok"] = true, ["hops"] = r.Hops.Select(h => (object?)HopOut(h)).ToList() };
        if (r.Open != null) { o["open"] = r.Open; o["closed"] = r.Closed; }
        if (r.CheckoutJwt != null) { o["checkoutJwt"] = r.CheckoutJwt; o["checkout"] = r.Checkout; }
        if (r.OpenHash != null) o["openHash"] = r.OpenHash;
        return o;
    }

    static D ProjPurchase(PurchaseResult r) => r.Ok
        ? new D { ["ok"] = true, ["checkout"] = ProjChain(r.Checkout!), ["payment"] = ProjChain(r.Payment!) }
        : new D { ["ok"] = false, ["reason"] = Mask(r.Reason) };

    static D PurchOptsOf(D c)
    {
        var o = new D { ["resolveIssuerKey"] = Resolver(Of(c, "issuerKeys")), ["resolveMerchantKey"] = Resolver(Of(c, "merchantKeys")), ["checkout"] = Of(c, "checkout"), ["payment"] = Of(c, "payment") };
        foreach (var k in new[] { "context", "now", "clockSkewSeconds" }) if (Has(c, k)) o[k] = c[k];
        return o;
    }

    static D PayOptsOf(D c)
    {
        var o = BaseOpts(c);
        foreach (var k in new[] { "openCheckoutHash", "context", "expectedTransactionId" }) if (Has(c, k)) o[k] = c[k];
        return o;
    }

    static D HopD(SdJwtHop h) => new()
    {
        ["raw"] = h.Raw, ["jwt"] = h.Jwt, ["header"] = h.Header, ["payload"] = h.Payload, ["disclosures"] = h.Disclosures.Cast<object?>().ToList(),
        ["sdAlg"] = h.SdAlg, ["signingInput"] = h.SigningInput, ["signature"] = h.Signature,
    };

    static L Strings(object? l) => (L)l!;
    static List<string> StrList(object? l) => ((L)l!).Cast<string>().ToList();

    // ---- issuance wrappers ----
    static MandateIssuer IssuerOf(D a) => new(KeyFor(Of(a, "issuerKey") as string ?? "issuer"), Of(a, "kid") as string, Has(a, "x5c") && JsX.Truthy(a["x5c"]) ? a["x5c"] as L : null);

    static D OpenInput(D a)
    {
        var o = new D { ["agentJwk"] = Has(a, "agentJwk") && a["agentJwk"] != null ? a["agentJwk"] : PubOf(Of(a, "agentKey") as string ?? "agent") };
        foreach (var k in new[] { "iat", "exp", "constraints", "typ" }) if (Has(a, k)) o[k] = a[k];
        foreach (var k in new[] { "pca", "sdAlg", "payee", "paymentAmount", "paymentInstrument", "pisp" }) if (Has(a, k) && JsX.Truthy(a[k])) o[k] = a[k];
        if (Has(a, "executionDate")) o["executionDate"] = a["executionDate"];
        return o;
    }

    static D PresentInput(D a, params string[] extra)
    {
        var o = new D();
        foreach (var k in new[] { "open", "aud", "nonce", "iat", "exp" }.Concat(extra)) if (Has(a, k)) o[k] = a[k];
        if (Has(a, "pca") && JsX.Truthy(a["pca"])) o["pca"] = a["pca"];
        if (Has(a, "hashMode") && JsX.Truthy(a["hashMode"])) o["hashMode"] = a["hashMode"];
        return o;
    }

    static Ap2KeyPair AgentKey(D a) => KeyFor(Of(a, "agentKey") as string ?? "agent");

    static MandateIssuer FromIssuer() => new(KeyFor("issuer"), "issuer-1");

    static D FromIn(D x)
    {
        var o = new D { ["agentJwk"] = PubOf("agent"), ["merchants"] = Has(x, "merchants") && x["merchants"] != null ? x["merchants"] : new L { Merch, Merch2 }, ["iat"] = Has(x, "iat") && x["iat"] != null ? x["iat"] : new Num("1800000000") };
        if (Has(x, "exp")) o["exp"] = x["exp"];
        return o;
    }

    static readonly Dictionary<string, Func<object?, List<string>>> ProblemFns = new()
    {
        ["openPaymentMandateProblems"] = Ap2Api.OpenPaymentMandateProblems,
        ["paymentMandateProblems"] = Ap2Api.PaymentMandateProblems,
        ["openCheckoutMandateProblems"] = Ap2Api.OpenCheckoutMandateProblems,
        ["checkoutMandateProblems"] = Ap2Api.CheckoutMandateProblems,
    };

    // ================================================================== tests

    [Fact]
    public void Constants() => Base.Check(M, "constants", _ => new D
    {
        ["VCT_CHECKOUT"] = Ap2Api.VctCheckout, ["VCT_CHECKOUT_OPEN"] = Ap2Api.VctCheckoutOpen, ["VCT_PAYMENT"] = Ap2Api.VctPayment, ["VCT_PAYMENT_OPEN"] = Ap2Api.VctPaymentOpen,
        ["PCA_CLAIM"] = Ap2Api.PcaClaim, ["FREQUENCIES"] = Ap2Api.Frequencies.Cast<object?>().ToList(), ["AP2_COMMIT"] = Ap2Api.Ap2Commit,
        ["PCA_BINDING_VERSION"] = Ap2Api.PcaBindingVersion, ["TYP_TERMINAL"] = Ap2Api.TypTerminal.Cast<object?>().ToList(), ["TYP_INTERMEDIATE"] = Ap2Api.TypIntermediate.Cast<object?>().ToList(),
    });

    [Fact] public void B64uEncode() => Base.Check(M, "b64uEncode", a => Ap2Api.B64uEncode((string)a[0]!));
    [Fact] public void B64uDecode() => Base.Check(M, "b64uDecode", a => Ap2Api.B64uDecode((string)a[0]!, (string)a[1]!));
    [Fact] public void ParseJson() => Base.Check(M, "parseJson", a => Ap2Api.ParseJson((string)a[0]!, (string)a[1]!));
    [Fact] public void IsSdAlg() => Base.Check(M, "isSdAlg", a => Ap2Api.IsSdAlg(a[0]));
    [Fact] public void SdDigest() => Base.Check(M, "sdDigest", a => a.Count > 1 ? Ap2Api.SdDigest(a[0], (string)a[1]!) : Ap2Api.SdDigest(a[0]));
    [Fact] public void AssertP256Jwk() => Base.Check(M, "assertP256Jwk", a => Ap2Api.AssertP256Jwk(a[0], (string)a[1]!));
    [Fact] public void JwkThumbprint() => Base.Check(M, "jwkThumbprint", a => Ap2Api.JwkThumbprint(a[0]));

    [Fact]
    public void KeyPairFromPrivateJwk() => Base.Check(M, "ap2KeyPairFromPrivateJwk", a =>
    {
        var label = (string)a[0]!;
        var p = KeyFor(label).PublicJwk;
        var jwk = new D { ["kty"] = "EC", ["crv"] = "P-256", ["d"] = Ap2Api.B64uEncode(KeyScalar(label)), ["x"] = p["x"], ["y"] = p["y"], ["kid"] = label };
        foreach (var kv in (D)a[1]!) jwk[kv.Key] = kv.Value;
        return Ap2Api.Ap2KeyPairFromPrivateJwk(jwk).PublicJwk;
    });

    [Fact] public void HopSdJwt() => Base.Check(M, "hopSdJwt", a => { var h = Ap2Api.ParseSdJwtHop(a[0]); return Ap2Api.HopSdJwt(h.Jwt, h.Disclosures); });
    [Fact] public void ParseSdJwtHop() => Base.Check(M, "parseSdJwtHop", a => HopD(Ap2Api.ParseSdJwtHop(a[0])));
    [Fact] public void SdHashOf() => Base.Check(M, "sdHashOf", a => Ap2Api.SdHashOf(Ap2Api.ParseSdJwtHop(a[0]), a.Count > 1 ? (string?)a[1] : null));
    [Fact] public void IssuerJwtHashOf() => Base.Check(M, "issuerJwtHashOf", a => Ap2Api.IssuerJwtHashOf(Ap2Api.ParseSdJwtHop(a[0]), a.Count > 1 ? (string?)a[1] : null));
    [Fact] public void VerifyHopSignature() => Base.Check(M, "verifyHopSignature", a => Ap2Api.VerifyHopSignature(Ap2Api.ParseSdJwtHop(a[0]), a[1]));
    [Fact] public void VerifyJwtEs256() => Base.Check(M, "verifyJwtEs256", a => Ap2Api.VerifyJwtEs256(Ap2Api.ParseJwt((string)a[0]!, "jwt"), a[1]));

    [Fact]
    public void ParseJwt() => Base.Check(M, "parseJwt", a =>
    {
        var p = Ap2Api.ParseJwt((string)a[0]!, (string)a[1]!);
        return new D { ["header"] = p.Header, ["payload"] = p.Payload, ["signingInput"] = p.SigningInput, ["signature"] = p.Signature };
    });

    [Fact]
    public void ProcessDisclosures() => Base.Check(M, "processDisclosures", a =>
    {
        if (a[0] is string)
        {
            var h = Ap2Api.ParseSdJwtHop(a[0]);
            return Ap2Api.ProcessDisclosures(h.Payload, h.Disclosures, h.SdAlg);
        }
        return Ap2Api.ProcessDisclosures((D)a[0]!, StrList(a[1]), (string)a[2]!);
    });

    [Fact]
    public void DisclosureBuilder() => Base.Check(M, "disclosureBuilder", a =>
    {
        var b = Ap2Api.NewDisclosureBuilder((string?)a[0], CounterSalt());
        var results = new L();
        foreach (D op in (L)a[1]!)
            results.Add((string)op["kind"]! == "element" ? b.Element(op["value"]) : b.Property((string)op["name"]!, op["value"]));
        return new D { ["results"] = results, ["disclosures"] = b.Disclosures.Cast<object?>().ToList() };
    });

    [Fact]
    public void SignSdJwt() => Base.Check(M, "signSdJwt", a =>
    {
        var x = (D)a[0]!;
        return StripSig(Ap2Api.SignSdJwt((D)x["header"]!, (D)x["payload"]!, StrList(x["disclosures"]), KeyFor((string)x["key"]!)));
    });

    [Fact]
    public void SignJwtEs256() => Base.Check(M, "signJwtEs256", a =>
    {
        var x = (D)a[0]!;
        return StripSig(Ap2Api.SignJwtEs256((D)x["header"]!, (D)x["payload"]!, KeyFor((string)x["key"]!)));
    });

    [Fact] public void CurrencyExponent() => Base.Check(M, "currencyExponent", a => Ap2Api.CurrencyExponent(a[0]));
    [Fact] public void ToMinorUnits() => Base.Check(M, "toMinorUnits", a => Ap2Api.ToMinorUnits(a[0], Arg(a, 1)));
    [Fact] public void FromMinorUnits() => Base.Check(M, "fromMinorUnits", a => Ap2Api.FromMinorUnits(a[0], Arg(a, 1)));
    [Fact] public void OpenPaymentProblems() => Base.Check(M, "openPaymentMandateProblems", a => Ap2Api.OpenPaymentMandateProblems(a[0]));
    [Fact] public void PaymentProblems() => Base.Check(M, "paymentMandateProblems", a => Ap2Api.PaymentMandateProblems(a[0]));
    [Fact] public void OpenCheckoutProblems() => Base.Check(M, "openCheckoutMandateProblems", a => Ap2Api.OpenCheckoutMandateProblems(a[0]));
    [Fact] public void CheckoutProblems() => Base.Check(M, "checkoutMandateProblems", a => Ap2Api.CheckoutMandateProblems(a[0]));
    [Fact] public void AssertValid() => Base.Check(M, "assertValid", a => Ap2Api.AssertValid(a[1], ProblemFns[(string)a[0]!], (string)a[2]!));

    [Fact] public void MerchantMatches() => Base.Check(M, "merchantMatches", a => Ap2Api.MerchantMatches(a[0], a[1]));
    [Fact] public void CheckPayment() => Base.Check(M, "checkPaymentConstraints", a => Ap2Api.CheckPaymentConstraints(a[0], a[1], a[2]));
    [Fact] public void ProjectCheckout() => Base.Check(M, "projectCheckout", a => a[0] is D d ? Ap2Api.ProjectCheckout(d) : Base.Refused);
    [Fact] public void CheckoutTotal() => Base.Check(M, "checkoutTotal", a => a[0] is D d ? Ap2Api.CheckoutTotal(d) : Base.Refused);
    [Fact] public void CheckCheckout() => Base.Check(M, "checkCheckoutConstraints", a => a[1] is D d ? Ap2Api.CheckCheckoutConstraints(a[0], d) : Base.Refused);
    [Fact] public void SplitChain() => Base.Check(M, "splitChain", a => Ap2Api.SplitChain(a[0]));

    [Fact]
    public void VerifyKbHop() => Base.Check(M, "verifyKbHop", a =>
    {
        var v = Ap2Api.VerifyKbHop(Ap2Api.ParseSdJwtHop(a[0]), Ap2Api.ParseSdJwtHop(a[1]), (D)a[2]!, (D)a[3]!, (string)a[4]!);
        return new D { ["index"] = v.Index, ["kind"] = v.Kind, ["claims"] = v.Claims, ["mandate"] = v.Mandate };
    });

    [Fact] public void VerifyDelegation() => Base.Check(M, "verifyDelegationChain", a => ProjChain(Ap2Api.VerifyDelegationChain(a[0], BaseOpts((D)a[1]!))));
    [Fact] public void VerifyCheckout() => Base.Check(M, "verifyCheckoutChain", a => ProjChain(Ap2Api.VerifyCheckoutChain(a[0], BaseOpts((D)a[1]!))));
    [Fact] public void VerifyPayment() => Base.Check(M, "verifyPaymentChain", a => ProjChain(Ap2Api.VerifyPaymentChain(a[0], PayOptsOf((D)a[1]!))));
    [Fact] public void VerifyPurchase() => Base.Check(M, "verifyPurchase", a => ProjPurchase(Ap2Api.VerifyPurchase(a[0], a[1], PurchOptsOf((D)a[2]!))));

    [Fact]
    public void RedeemPurchase() => Base.Check(M, "redeemPurchase", a =>
    {
        var calls = new L();
        var spec = a[3];
        PurchaseLedger? ledger = spec is D s ? new PurchaseLedger(
            (h, t, amt) =>
            {
                calls.Add(new L { "reserve", h, t, amt });
                var mode = Of(s, "mode");
                if (mode is "throw") throw new InvalidOperationException("down");
                if (mode is "replayed") return "replayed";
                if (mode is "undefined") return null;
                return Has(s, "ctx") && s["ctx"] != null ? s["ctx"] : new D { ["totalAmount"] = new Num("0"), ["totalUses"] = new Num("0") };
            },
            (h, t) =>
            {
                calls.Add(new L { "release", h, t });
                if (Has(s, "releaseThrows") && JsX.Truthy(s["releaseThrows"])) throw new InvalidOperationException("release failed");
            }) : null;
        var r = Ap2Api.RedeemPurchase(a[0], a[1], PurchOptsOf((D)a[2]!), ledger);
        return new D { ["result"] = r.Ok ? ProjPurchase(r) : new D { ["ok"] = false, ["reason"] = Mask(r.Reason) }, ["calls"] = calls };
    });

    [Fact] public void IssueOpenPayment() => Base.Check(M, "issueOpenPaymentMandate", a => StripSigOf(Ap2Api.IssueOpenPaymentMandate(OpenInput((D)a[0]!), IssuerOf((D)a[0]!), CounterSalt())));
    [Fact] public void IssueOpenCheckout() => Base.Check(M, "issueOpenCheckoutMandate", a => StripSigOf(Ap2Api.IssueOpenCheckoutMandate(OpenInput((D)a[0]!), IssuerOf((D)a[0]!), CounterSalt())));

    static string StripSigOf(string t) => StripSig(t);

    [Fact]
    public void PresentPayment() => Base.Check(M, "presentClosedPayment", a =>
    {
        var x = (D)a[0]!;
        var input = PresentInput(x, "transactionId", "payee", "paymentAmount", "paymentInstrument", "riskData");
        if (Has(x, "pisp") && JsX.Truthy(x["pisp"])) input["pisp"] = x["pisp"];
        if (Has(x, "executionDate")) input["executionDate"] = x["executionDate"];
        if (Has(x, "riskData") && !JsX.Truthy(x["riskData"])) input.Remove("riskData");
        return StripSig(Ap2Api.PresentClosedPayment(input, AgentKey(x), CounterSalt()));
    });

    [Fact]
    public void PresentCheckout() => Base.Check(M, "presentClosedCheckout", a =>
    {
        var x = (D)a[0]!;
        return StripSig(Ap2Api.PresentClosedCheckout(PresentInput(x, "checkoutJwt"), AgentKey(x), CounterSalt()));
    });

    [Fact] public void BudgetMax() => Base.Check(M, "ap2BudgetMax", a => Ap2Api.Ap2BudgetMax(a[0], Arg(a, 1)));
    [Fact] public void BudgetReads() => Base.Check(M, "ap2BudgetReads", a => Ap2Api.Ap2BudgetReads(a[0], Arg(a, 1)));
    [Fact] public void RiskRatio() => Base.Check(M, "riskRatio", a => Ap2Api.RiskRatio(JsX.NumOf(a[0])!.Value, JsX.NumOf(a[1])!.Value));
    [Fact] public void BindingNonce() => Base.Check(M, "pcaBindingNonce", a => Ap2Api.PcaBindingNonce((D)a[0]!));
    [Fact] public void ConstraintsFromTerms() => Base.Check(M, "paymentConstraintsFromTerms", a => Ap2Api.PaymentConstraintsFromTerms(a[0], a[1], (string)a[2]!));
    [Fact] public void OpenClaim() => Base.Check(M, "pcaOpenClaim", a => Ap2Api.PcaOpenClaim(a[0]));

    [Fact]
    public void OpenPaymentFromPca() => Base.Check(M, "openPaymentMandateFromPca", a =>
    {
        var x = (D)a[0]!;
        var o = FromIn(x);
        o["checkoutReference"] = Has(x, "checkoutReference") && x["checkoutReference"] != null ? x["checkoutReference"] : "REF";
        return StripSig(Ap2Api.OpenPaymentMandateFromPca(Of(x, "mandate"), o, FromIssuer(), CounterSalt()));
    });

    [Fact]
    public void OpenCheckoutFromPca() => Base.Check(M, "openCheckoutMandateFromPca", a =>
    {
        var x = (D)a[0]!;
        var o = FromIn(x);
        o["lineItems"] = Has(x, "lineItems") && x["lineItems"] != null ? x["lineItems"]
            : new L { new D { ["id"] = "line_1", ["acceptable_items"] = new L { new D { ["id"] = "sku-1", ["title"] = "Widget" } }, ["quantity"] = new Num("2") } };
        return StripSig(Ap2Api.OpenCheckoutMandateFromPca(Of(x, "mandate"), o, FromIssuer(), CounterSalt()));
    });

    [Fact] public void ToAtomicUnits() => Base.Check(M, "toAtomicUnits", a => Ap2Api.ToAtomicUnits(a[0], Arg(a, 1)));
    [Fact] public void X402Settlement() => Base.Check(M, "x402Settlement", a => Ap2Api.X402Settlement(a[0], a.Count > 1 ? a[1] : null));
    [Fact] public void StripeSptSettlement() => Base.Check(M, "stripeSptSettlement", a => Ap2Api.StripeSptSettlement(a[0], a.Count > 1 ? a[1] : null));

    [Fact]
    public void BuildPcaPaymentBinding() => Base.Check(M, "buildPcaPaymentBinding", a =>
    {
        var s = (D)a[0]!;
        var input = new D
        {
            ["mandate"] = s["mandate"],
            ["open"] = s["open"],
            ["agentJwk"] = PubOf("agent"),
            ["agentSecret"] = SHA256.HashData(Encoding.UTF8.GetBytes("atlas-pca-conformance/" + (string)s["agentSeed"]!)),
            ["audience"] = s["audience"],
            ["counter"] = s["counter"],
            ["transactionId"] = s["transactionId"],
            ["payee"] = s["payee"],
            ["amount"] = s["amount"],
            ["instrumentId"] = s["instrumentId"],
        };
        if (s.ContainsKey("category")) input["category"] = s["category"];
        if (s.ContainsKey("now")) input["now"] = s["now"];
        Func<D, object?>? cosign = s.ContainsKey("cosign") ? (Func<D, object?>)(_ => s["cosign"]) : null;
        return Ap2Api.BuildPcaPaymentBinding(input, cosign);
    });

    [Fact]
    public void EveryFn() { Base.Covers(M, new[]
    {
        "constants", "b64uEncode", "b64uDecode", "parseJson", "isSdAlg", "sdDigest", "assertP256Jwk", "jwkThumbprint", "ap2KeyPairFromPrivateJwk", "hopSdJwt",
        "parseSdJwtHop", "sdHashOf", "issuerJwtHashOf", "verifyHopSignature", "verifyJwtEs256", "parseJwt", "processDisclosures", "disclosureBuilder", "signSdJwt",
        "signJwtEs256", "currencyExponent", "toMinorUnits", "fromMinorUnits", "openPaymentMandateProblems", "paymentMandateProblems", "openCheckoutMandateProblems",
        "checkoutMandateProblems", "assertValid", "merchantMatches", "checkPaymentConstraints", "projectCheckout", "checkoutTotal", "checkCheckoutConstraints", "splitChain",
        "verifyKbHop", "verifyDelegationChain", "verifyCheckoutChain", "verifyPaymentChain", "verifyPurchase", "redeemPurchase", "issueOpenPaymentMandate",
        "issueOpenCheckoutMandate", "presentClosedPayment", "presentClosedCheckout", "ap2BudgetMax", "ap2BudgetReads", "riskRatio", "pcaBindingNonce",
        "paymentConstraintsFromTerms", "pcaOpenClaim", "openPaymentMandateFromPca", "openCheckoutMandateFromPca", "toAtomicUnits", "x402Settlement", "stripeSptSettlement",
        "buildPcaPaymentBinding",
    }); Assert.Equal(3528, Base.Total(M)); }
}

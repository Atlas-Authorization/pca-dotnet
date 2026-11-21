using AtlasPca.Acp;
using AtlasPca.InteropJs;
using Xunit;
using AcpApi = AtlasPca.Acp.Acp;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Differential replay of the ACP + x402 + Stripe SPT surface against the TypeScript reference (test-data/ref-acp.json.gz).</summary>
public class RefAcpTests
{
    const string M = "ref-acp";

    sealed class OnceStore
    {
        readonly HashSet<string> seen = new();
        public object? Claim(string jti, double exp) => seen.Add(jti);
    }

    /// <summary>The oracle's store specs: once / always / never / throw / truthy; anything else is passed through as is.</summary>
    static object? Store(object? spec) => spec as string switch
    {
        "once" => (ClaimFn)new OnceStore().Claim,
        "always" => (ClaimFn)((_, _) => true),
        "never" => (ClaimFn)((_, _) => false),
        "throw" => (ClaimFn)((_, _) => throw new InvalidOperationException("store down")),
        "truthy" => (ClaimFn)((_, _) => 1),
        _ => spec,
    };

    static D WithStore(D opts)
    {
        var o = new D(opts);
        if (o.ContainsKey("singleUse")) o["singleUse"] = Store(o["singleUse"]);
        return o;
    }

    static D NormRes(D r)
    {
        var o = new D(r);
        if (o.TryGetValue("reason", out var re) && re is string s)
            foreach (var p in new[] { "token signature did not verify", "bound proof failed to verify" })
                if (s.StartsWith(p + ": ", StringComparison.Ordinal)) o["reason"] = p;
        if (o.TryGetValue("pcaResult", out var pr) && pr is D pd) o["pcaResult"] = new D { ["allow"] = pd["allow"] };
        return o;
    }

    static object? Times(L a, int idx, Func<D> once)
    {
        int times = a.Count > idx ? (int)Base.Long(a[idx]) : 1;
        var rs = new L();
        for (int i = 0; i < times; i++) rs.Add(once());
        return times == 1 ? rs[0] : rs;
    }

    static object? OnD(object? a, Func<D, object?> f) => a is D d ? f(d) : Base.Refused;
    static object? OnStr(object? a, Func<string, object?> f) => a is string s ? f(s) : Base.Refused;

    [Fact]
    public void Constants() => Base.Check(M, "constants", _ => new D
    {
        ["v"] = AcpApi.AcpDelegatedTokenVersion, ["t"] = AcpApi.AcpDelegatedTokenType, ["s"] = AcpApi.SpendCapCaveatType,
        ["m"] = AcpApi.MerchantAllowCaveatType, ["c"] = AcpApi.MerchantCategoryCaveatType, ["h"] = AcpApi.HumanPresentCaveatType,
        ["x1"] = AcpApi.X402Version1, ["x2"] = AcpApi.X402Version2, ["sup"] = AcpApi.X402SupportedVersions.Cast<object?>().ToList(),
        ["pr"] = AcpApi.X402V2PaymentRequiredHeader, ["ps"] = AcpApi.X402PaymentSignatureHeader, ["pe"] = AcpApi.X402PaymentResponseHeader,
        ["st"] = new D
        {
            ["payment_required"] = AcpApi.X402StatusPaymentRequired, ["malformed"] = AcpApi.X402StatusMalformed, ["failed"] = AcpApi.X402StatusFailed,
            ["internal_error"] = AcpApi.X402StatusInternalError, ["settled"] = AcpApi.X402StatusSettled,
        },
        ["spt"] = AcpApi.StripeSptObject,
    });

    [Fact] public void SpendCap() => Base.Check(M, "spendCapCaveat", a => AcpApi.SpendCapCaveat(JsX.NumOf(a[0])!.Value, a.Count > 1 ? (string?)a[1] : null));
    [Fact] public void MerchantAllow() => Base.Check(M, "merchantAllowCaveat", a => AcpApi.MerchantAllowCaveat(((L)a[0]!).Cast<string>()));
    [Fact] public void MerchantCategory() => Base.Check(M, "merchantCategoryCaveat", a => AcpApi.MerchantCategoryCaveat(((L)a[0]!).Cast<string>()));
    [Fact] public void HumanPresent() => Base.Check(M, "humanPresentCaveat", a => a.Count > 0 ? AcpApi.HumanPresentCaveat((bool)a[0]!) : AcpApi.HumanPresentCaveat());
    [Fact] public void Extract() => Base.Check(M, "extractPaymentAuthority", a => AcpApi.ExtractPaymentAuthority(a[0]));
    [Fact] public void Check() => Base.Check(M, "checkPaymentAuthority", a => AcpApi.CheckPaymentAuthority((D)a[0]!, (D)a[1]!));

    [Fact]
    public void Mint() => Base.Check(M, "mintDelegatedPaymentToken", a => OnD(a[0], pc => OnD(a[1], o => AcpApi.MintDelegatedPaymentToken(pc, o))));

    [Fact]
    public void Verify() => Base.Check(M, "verifyDelegatedPaymentToken", a =>
    {
        var o = WithStore((D)a[1]!);
        return Times(a, 2, () => NormRes(AcpApi.VerifyDelegatedPaymentToken(a[0], o)));
    });

    [Fact]
    public void AcpVerifier() => Base.Check(M, "acpX402Verifier", a =>
    {
        var fn = AcpApi.AcpX402Verifier(WithStore((D)a[1]!));
        return Times(a, 2, () => NormRes(fn(a[0])));
    });

    [Fact] public void Challenge() => Base.Check(M, "x402Challenge", a => OnD(a[1], o => AcpApi.X402Challenge(a[0], o)));
    [Fact] public void ChallengeV2() => Base.Check(M, "x402ChallengeV2", a => OnD(a[1], o => AcpApi.X402ChallengeV2(a[0], o)));

    [Fact]
    public void Settle() => Base.Check(M, "x402Settle", a =>
    {
        var vspec = a[1];
        D Verify(object? _)
        {
            if (vspec is string) throw new InvalidOperationException("verify down");
            return (D)Base.Deep(vspec)!;
        }
        Func<object?, object?, object?>? settle = (a.Count > 2 ? a[2] as string : null) switch
        {
            "echo" => (p, c) =>
            {
                var r = new D();
                var jti = JsX.At(c, "jti");
                if (!ReferenceEquals(jti, JsX.Undef)) r["jti"] = jti;
                var tok = JsX.At(p, "token");
                if (!ReferenceEquals(tok, JsX.Undef)) r["token"] = tok;
                return r;
            },
            "value" => (_, _) => "receipt-1",
            "throw" => (_, _) => throw new InvalidOperationException("settle down"),
            "undef" => (_, _) => AcpApi.Undefined,
            _ => null,
        };
        return AcpApi.X402Settle(a[0], Verify, settle);
    });

    [Fact] public void Allowance() => Base.Check(M, "toAcpAllowance", a => OnD(a[0], AcpApi.ToAcpAllowance));

    [Fact] public void ResourceInfo() => Base.Check(M, "resourceInfoProblems", a => AcpApi.ResourceInfoProblems(a[0]));
    [Fact] public void RequirementV2() => Base.Check(M, "requirementV2Problems", a => AcpApi.RequirementV2Problems(a[0]));
    [Fact] public void PaymentRequiredV2() => Base.Check(M, "paymentRequiredV2Problems", a => AcpApi.PaymentRequiredV2Problems(a[0]));
    [Fact] public void PaymentPayloadV2() => Base.Check(M, "paymentPayloadV2Problems", a => AcpApi.PaymentPayloadV2Problems(a[0]));
    [Fact] public void SettlementProblems() => Base.Check(M, "settlementResponseProblems", a => AcpApi.SettlementResponseProblems(a[0]));
    [Fact] public void SptProblems() => Base.Check(M, "stripeSptProblems", a => AcpApi.StripeSptProblems(a[0]));

    [Fact] public void EncodeRequired() => Base.Check(M, "encodePaymentRequiredHeader", a => AcpApi.EncodePaymentRequiredHeader(a[0]));
    [Fact] public void DecodeRequired() => Base.Check(M, "decodePaymentRequiredHeader", a => OnStr(a[0], AcpApi.DecodePaymentRequiredHeader));
    [Fact] public void EncodeSignature() => Base.Check(M, "encodePaymentSignatureHeader", a => AcpApi.EncodePaymentSignatureHeader(a[0]));
    [Fact] public void DecodeSignature() => Base.Check(M, "decodePaymentSignatureHeader", a => OnStr(a[0], AcpApi.DecodePaymentSignatureHeader));
    [Fact] public void EncodeResponse() => Base.Check(M, "encodePaymentResponseHeader", a => AcpApi.EncodePaymentResponseHeader(a[0]));
    [Fact] public void DecodeResponse() => Base.Check(M, "decodePaymentResponseHeader", a => OnStr(a[0], AcpApi.DecodePaymentResponseHeader));

    [Fact]
    public void Negotiate() => Base.Check(M, "x402Negotiate", a => a[0] is L offered ? AcpApi.X402Negotiate(offered, a.Count > 1 ? (L?)a[1] : null) : Base.Refused);

    [Fact] public void AcceptedMatches() => Base.Check(M, "x402AcceptedMatches", a => AcpApi.X402AcceptedMatches((L)a[0]!, a[1]));
    [Fact] public void NormalizePayload() => Base.Check(M, "normalizeX402Payload", a => AcpApi.NormalizeX402Payload(a[0]));
    [Fact] public void ReadSignature() => Base.Check(M, "readPaymentSignature", a => AcpApi.ReadPaymentSignature((D)a[0]!));
    [Fact] public void SettlementResponse() => Base.Check(M, "x402SettlementResponse", a => AcpApi.X402SettlementResponse((D)a[0]!, a[1]));
    [Fact] public void SignatureHeaders() => Base.Check(M, "x402PaymentSignatureHeaders", a => AcpApi.X402PaymentSignatureHeaders(a[0]));

    [Fact] public void ParseSpt() => Base.Check(M, "parseStripeSpt", a => AcpApi.ParseStripeSpt(a[0]));
    [Fact] public void SptUsable() => Base.Check(M, "stripeSptUsable", a => AcpApi.StripeSptUsable(a[0], a[1]));
    [Fact] public void UsageLimits() => Base.Check(M, "stripeUsageLimitsFor", a => OnD(a[0], AcpApi.StripeUsageLimitsFor));
    [Fact] public void WithinClaims() => Base.Check(M, "stripeSptWithinClaims", a => AcpApi.StripeSptWithinClaims(a[0], a[1]));

    [Fact]
    public void EveryFn() { Base.Covers(M, new[]
    {
        "constants", "spendCapCaveat", "merchantAllowCaveat", "merchantCategoryCaveat", "humanPresentCaveat", "extractPaymentAuthority",
        "checkPaymentAuthority", "mintDelegatedPaymentToken", "verifyDelegatedPaymentToken", "acpX402Verifier", "x402Challenge", "x402ChallengeV2",
        "x402Settle", "toAcpAllowance", "resourceInfoProblems", "requirementV2Problems", "paymentRequiredV2Problems", "paymentPayloadV2Problems",
        "settlementResponseProblems", "stripeSptProblems", "encodePaymentRequiredHeader", "decodePaymentRequiredHeader", "encodePaymentSignatureHeader",
        "decodePaymentSignatureHeader", "encodePaymentResponseHeader", "decodePaymentResponseHeader", "x402Negotiate", "x402AcceptedMatches",
        "normalizeX402Payload", "readPaymentSignature", "x402SettlementResponse", "x402PaymentSignatureHeaders", "parseStripeSpt", "stripeSptUsable",
        "stripeUsageLimitsFor", "stripeSptWithinClaims",
    }); Assert.Equal(6406, Base.Total(M)); }
}

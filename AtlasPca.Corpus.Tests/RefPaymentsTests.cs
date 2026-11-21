using AtlasPca;
using AtlasPca.Payments;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Differential oracle of the payments package (test-data/ref-payments.json.gz, TS reference packages/pca-payments): mandates, charge decision input and
/// assembly, charge actions, Shared Payment Token and rail limits, settlement reconciliation, the Stripe Issuing adapter and network-token bindings. The policy
/// decision is the core engine: authorizeCharge cases carry the reference's recorded decision as the last argument, which the native feeds back through its
/// injected decider. Bytes travel as {"$bytes": b64url}. Not covered (asynchronous; need a budget store and timers): authorizeChargeAtomic,
/// applyHumanCosignAtomic, createRailAuthorizer and the partner adapters.</summary>
public class RefPaymentsTests
{
    const string M = "ref-payments";

    static object? Unb(object? x) => x switch
    {
        D d when Base.IsBytes(d) => Base.Bytes(d),
        D d => d.ToDictionary(e => e.Key, e => Unb(e.Value)),
        L l => l.Select(Unb).ToList(),
        _ => x,
    };

    static string S(object? o) => (string)o!;

    [Fact] public void IsPlainId() => Base.Check(M, "isPlainId", a => Payments.Payments.IsPlainId(a[0]));
    [Fact] public void IsMinorUnits() => Base.Check(M, "isMinorUnits", a => Payments.Payments.IsMinorUnits(a[0]));
    [Fact] public void MandatePredicates() => Base.Check(M, "mandatePredicates", a => Payments.Payments.MandatePredicates(a[0]));
    [Fact] public void MandateCaveats() => Base.Check(M, "mandateCaveats", a => Payments.Payments.MandateCaveats(a[0]));
    [Fact] public void MandateRiskPolicy() => Base.Check(M, "mandateRiskPolicy", a => Payments.Payments.MandateRiskPolicy(a[0], a[1]));
    [Fact] public void AutoSpendBound() => Base.Check(M, "autoSpendBound", a => Payments.Payments.AutoSpendBound(a[0]));
    [Fact] public void BuildPaymentMandate() => Base.Check(M, "buildPaymentMandate", a => Payments.Payments.BuildPaymentMandate(Unb(a[0])));
    [Fact] public void ChargeActionContext() => Base.Check(M, "chargeActionContext", a => Payments.Payments.ChargeActionContext(a[0], a[1]));
    [Fact] public void ChargeParams() => Base.Check(M, "chargeParams", a => Payments.Payments.ChargeParams(a[0], a[1]));
    [Fact] public void ChargePlanNode() => Base.Check(M, "chargePlanNode", a => Payments.Payments.ChargePlanNode(a[0], a[1], S(a[2])));
    [Fact] public void ChargeToPCActn() => Base.Check(M, "chargeToPCActn", a => Payments.Payments.ChargeToPCActn(a[0], a[1], Unb(a[2])));
    [Fact] public void ChargeDecideInput() => Base.Check(M, "chargeDecideInput", a => Payments.Payments.ChargeDecideInput(a[0], a[1], a[2], a[3]));
    [Fact] public void AuthorizeCharge() => Base.Check(M, "authorizeCharge", a => Payments.Payments.AuthorizeCharge(a[0], a[1], a[2], _ => (D)a[3]!));
    [Fact] public void SettleCharge() => Base.Check(M, "settleCharge", a => Payments.Payments.SettleCharge(a[0], a[1]));
    [Fact] public void ApplyHumanCosign() => Base.Check(M, "applyHumanCosign", a => Payments.Payments.ApplyHumanCosign(a[0], a[1], a.Count > 2 && a[2] == null ? throw new ArgumentException("opts is null (a default applies only to undefined)") : a.Count > 2 ? a[2] : null));
    [Fact] public void SharedPaymentTokenLimits() => Base.Check(M, "sharedPaymentTokenLimits", a => Payments.Payments.SharedPaymentTokenLimits(a[0], a[1]));
    [Fact] public void RailLimits() => Base.Check(M, "railLimits", a => Rails.RailLimits(a[0], a[1], a.Count > 2 && a[2] == null ? throw new ArgumentException("opts is null (a default applies only to undefined)") : a.Count > 2 ? a[2] : null));
    [Fact] public void CategoriesFromTraits() => Base.Check(M, "categoriesFromTraits", a => Rails.CategoriesFromTraits(a[0]));
    [Fact] public void ReconcileSettlement() => Base.Check(M, "reconcileSettlement", a => Rails.ReconcileSettlement(a[0], a[1]));

    [Fact] public void VerifyStripeSignature() => Base.Check(M, "verifyStripeSignature", a => StripeRails.VerifyStripeSignature(a[0], a[1], a[2], a[3], a.Count > 4 ? a[4] : null));
    [Fact] public void SignStripePayload() => Base.Check(M, "signStripePayload", a => StripeRails.SignStripePayload(S(a[0]), S(a[1]), a[2]));
    [Fact] public void StripeCardParams() => Base.Check(M, "stripeCardParams", a => StripeRails.StripeCardParams(a[0], a[1], a[2], a[3]));
    [Fact] public void StripeAuthorizationFromEvent() => Base.Check(M, "stripeAuthorizationFromEvent", a => StripeRails.StripeAuthorizationFromEvent(a[0]));
    [Fact] public void StripeSettlementFromTransaction() => Base.Check(M, "stripeSettlementFromTransaction", a => StripeRails.StripeSettlementFromTransaction(a[0]));

    [Fact]
    public void StripeIssuingWebhook() => Base.Check(M, "stripeIssuingWebhook", a =>
        StripeRails.StripeIssuingWebhook(S(a[0]), a[1] as string, S(a[2]), Base.Long(a[3]), _ => new D { ["approved"] = a[4], ["reasons"] = new L() }));

    [Fact] public void LooksLikePan() => Base.Check(M, "looksLikePan", a => NetworkTokens.LooksLikePan(S(a[0])));
    [Fact] public void TokenRefError() => Base.Check(M, "tokenRefError", a => NetworkTokens.TokenRefError(a[0]));
    [Fact] public void BindingMessage() => Base.Check(M, "bindingMessage", a => NetworkTokens.BindingMessage(a[0]));
    [Fact] public void BindNetworkToken() => Base.Check(M, "bindNetworkToken", a => NetworkTokens.BindNetworkToken(Unb(a[0])));
    [Fact] public void VerifyNetworkTokenBinding() => Base.Check(M, "verifyNetworkTokenBinding", a => NetworkTokens.VerifyNetworkTokenBinding(a[0], a[1]));
    [Fact] public void ControlsFromLimits() => Base.Check(M, "controlsFromLimits", a => NetworkTokens.ControlsFromLimits(a[0], a[1]));
    [Fact] public void SettlementMetadata() => Base.Check(M, "settlementMetadata", a => NetworkTokens.SettlementMetadata(a[0], a[1]));
    [Fact] public void ReconcileNetworkSettlement() => Base.Check(M, "reconcileNetworkSettlement", a => NetworkTokens.ReconcileNetworkSettlement(a[0], a[1]));
    [Fact] public void ChargeWithNetworkToken() => Base.Check(M, "chargeWithNetworkToken", a => NetworkTokens.ChargeWithNetworkToken(a[0], a[1], a[2], Unb(a[3])));

    [Fact]
    public void EveryFn() { Base.Covers(M, new[]
    {
        "isPlainId", "isMinorUnits", "mandatePredicates", "mandateCaveats", "mandateRiskPolicy", "autoSpendBound", "buildPaymentMandate", "chargeActionContext", "chargeParams",
        "chargePlanNode", "chargeToPCActn", "chargeDecideInput", "authorizeCharge", "settleCharge", "applyHumanCosign", "sharedPaymentTokenLimits", "railLimits",
        "categoriesFromTraits", "reconcileSettlement", "verifyStripeSignature", "signStripePayload", "stripeCardParams", "stripeAuthorizationFromEvent",
        "stripeSettlementFromTransaction", "stripeIssuingWebhook", "looksLikePan", "tokenRefError", "bindingMessage", "bindNetworkToken", "verifyNetworkTokenBinding",
        "controlsFromLimits", "settlementMetadata", "reconcileNetworkSettlement", "chargeWithNetworkToken",
    }); Assert.Equal(3123, Base.Total(M)); }
}

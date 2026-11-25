// Verification of the PCA side of a verified AP2 payment chain (the reference verifyPcaBinding): the grant in the open mandate (signed by the expected
// principal, consistent with the terms it claims and with the open constraints), and the closed mandate's PCActn (valid under that grant, for this
// audience, committing to exactly this AP2 charge). Run it after the AP2 chain verification, which establishes the AP2 signatures. Everything is parsed
// JSON (D / L). The PCActn is verified by the stateless core verifier with the plan-root check skipped (the open mandate commits to the charge, not to a plan).
using AtlasPca.Authzen;
using AtlasPca.InteropJs;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Ap2;

/// <summary>Thrown when <see cref="Ap2.VerifyPcaBinding"/> lacks the server-held state the policy decision needs. Code: mandate_required | charge_history_required.</summary>
public sealed class PcaBindingException(string code, string message) : Exception(message)
{
    public string Code { get; } = code;
}

/// <summary>What <see cref="Ap2.VerifyPcaBinding"/> reads. <c>Mandate</c> is the PCA mandate state THIS verifier holds (its live budget); without it the binding is
/// refused. <c>RecentChargeTimes</c> (epoch ms of this holder's earlier admitted charges, from your own records) is REQUIRED when the mandate limits the charge count.
/// <c>ThresholdHook</c> verifies a human co-sign (build it with <see cref="ThresholdVerifiers.Create"/>); a charge needing t &gt; 1 is refused without one.</summary>
public sealed class VerifyPcaBindingInput
{
    public D Open { get; set; } = new();
    public D Closed { get; set; } = new();
    /// <summary><c>sd_hash</c> of the open payment mandate hop.</summary>
    public string OpenHash { get; set; } = "";
    /// <summary>The Ed25519 key (b64u) of the principal who must have signed the grant. Required.</summary>
    public string ExpectedPrincipal { get; set; } = "";
    public IReadOnlyDictionary<string, string>? PqPins { get; set; }
    /// <summary>This verifier's PCA audience; the PCActn's signed <c>aud</c> must equal it.</summary>
    public string Audience { get; set; } = "";
    public long? Now { get; set; }
    public D? Mandate { get; set; }
    public IReadOnlyList<object?>? RecentChargeTimes { get; set; }
    public Func<D, D, ThresholdHookResult?>? ThresholdHook { get; set; }
    /// <summary>Other core hooks, evaluated in the reference order (attestation, threshold, revocation, zk): an enforced failing hook denies. A PCActn that
    /// carries a <c>zk_compliance</c> proof is denied unless <see cref="ZkHook"/> enforces it.</summary>
    public Func<D, D, ThresholdHookResult?>? AttestationHook { get; set; }
    public Func<D, D, ThresholdHookResult?>? RevocationHook { get; set; }
    public Func<D, D, ThresholdHookResult?>? ZkHook { get; set; }
    /// <summary>The freshness gate (<c>enforce.freshness</c>): a missing, future or older-than-this signed freshness anchor denies.</summary>
    public double? FreshnessMaxAgeMs { get; set; }
    /// <summary>Milliseconds per freshness epoch, mapping <c>freshness.epoch</c> to a wall-clock anchor (default 60000; it must be positive).</summary>
    public double? FreshnessEpochMs { get; set; }
    /// <summary>The clock (epoch ms) of the age computation (default: the verifier's <see cref="Now"/>).</summary>
    public double? FreshnessNow { get; set; }
    /// <summary>Tolerated clock skew (ms) for an anchor that appears slightly in the future (default 0; negative or non-finite counts as 0).</summary>
    public double? FreshnessClockSkewMs { get; set; }
    /// <summary>The information-flow taint gate (<c>enforce.taint</c>): the registry and resource graph the server re-classifies every declared provenance ref with, and the
    /// highest taint it tolerates. Unverifiable or empty lineage, or taint above the maximum, denies.</summary>
    public TaintGate? EnforceTaint { get; set; }
    /// <summary>The TEE attestation gate (<c>enforce.attestation</c>): the real attestation verifier, which takes the place of <see cref="AttestationHook"/>. With
    /// <see cref="AttestationRequired"/> (the default) a verifier that reports not-enforced, or none at all, denies.</summary>
    public Func<D, D, ThresholdHookResult?>? AttestationGate { get; set; }
    /// <summary>With <see cref="AttestationGate"/> set: deny when the verifier reports not-enforced / no document (default true).</summary>
    public bool AttestationRequired { get; set; } = true;
    public IReadOnlyCollection<string>? AllowedSuites { get; set; }
}

/// <summary>Success: the verified <c>Pcactn</c>, <c>Grant</c> and <c>Terms</c>; else <c>Reason</c>.</summary>
public sealed record PcaBindingResult(bool Ok, string? Reason = null, D? Pcactn = null, D? Grant = null, D? Terms = null);

public static partial class Ap2
{
    // open.cnf.jwk: reading a member of an absent or null cnf is the reference's TypeError message
    static object? CnfOf(object? open)
    {
        var cnf = G(open, "cnf");
        if (cnf == null || ReferenceEquals(cnf, JsX.Undef)) throw new ArgumentException($"Cannot read properties of {(cnf == null ? "null" : "undefined")} (reading 'jwk')");
        return cnf;
    }

    static D? FindConstraint(object? open, string type) =>
        (G(open, "constraints") as L ?? new L()).OfType<D>().FirstOrDefault(c => G(c, "type") is string t && t == type);

    /// <summary>Check the open mandate's constraints never exceed the PCA terms (the AP2 side only narrows the grant). Null when they do not.</summary>
    static string? ConstraintsWithinTerms(D open, D terms)
    {
        var cur = G(terms, "currency");
        var perTx = MinorTerm(G(terms, "perTransactionCap"), "perTransactionCap");
        var range = FindConstraint(open, "payment.amount_range");
        if (range == null) return "open mandate has no amount_range to compare with the PCA per-transaction cap";
        if (!JsX.StrictEq(G(range, "currency"), cur)) return "amount_range currency differs from the PCA terms";
        if (!(Dbl(G(range, "max")) <= perTx)) return $"amount_range.max {S(G(range, "max"))} exceeds the PCA per-transaction cap {JsX.JsNumString(perTx)}";
        var payees = FindConstraint(open, "payment.allowed_payees");
        var merchants = G(terms, "merchants") as L ?? new L();
        if (payees != null && (G(payees, "allowed") as L ?? new L()).Any(m => !merchants.Any(x => JsX.StrictEq(x, G(m, "id"))))) return "allowed_payees names a merchant outside the PCA allowlist";
        if (payees == null) return "open mandate has no allowed_payees; the PCA allowlist would not be enforced on the AP2 side";
        var budget = FindConstraint(open, "payment.budget");
        if (budget == null) return "open mandate has no budget to compare with the PCA cumulative cap";
        if (!JsX.StrictEq(G(budget, "currency"), cur)) return "budget exceeds the PCA cumulative cap";
        var reads = Ap2BudgetReads(G(budget, "max"), cur);
        var capMinor = MinorTerm(G(terms, "cumulativeCap"), "cumulativeCap");
        if (Dbl(reads["sdk"]) > capMinor || Dbl(reads["major"]) > capMinor) return "budget exceeds the PCA cumulative cap";
        var rec = FindConstraint(open, "payment.agent_recurrence");
        var maxTx = G(terms, "maxTransactionsPerPeriod");
        if (!IsUndef(maxTx) && (rec == null || IsUndef(G(rec, "max_occurrences")) || Dbl(G(rec, "max_occurrences")) > Dbl(maxTx))) return "max_occurrences is missing or exceeds the PCA transaction limit";
        var pe = G(terms, "periodEnd");
        if (!IsUndef(pe) && (IsUndef(G(open, "exp")) || Dbl(G(open, "exp")) > Math.Floor(Dbl(pe) / 1000))) return "open mandate outlives the PCA period";
        return null;
    }

    /// <summary>Verify the PCA side of a verified AP2 payment chain. Throws <see cref="PcaBindingException"/> when the server-held state is missing;
    /// every other refusal is a result with a reason.</summary>
    public static PcaBindingResult VerifyPcaBinding(VerifyPcaBindingInput i)
    {
        if (i?.Mandate == null) throw new PcaBindingException("mandate_required", "verifyPcaBinding needs the server-held PCA mandate (its live budget); the policy decision is never skipped");
        if (!IsUndef(G(G(i.Mandate, "terms"), "maxTransactionsPerPeriod")) && (i.RecentChargeTimes == null || i.RecentChargeTimes.Any(t => !(t is Num n && JsX.NumOf(n) is double d && double.IsFinite(d)))))
            throw new PcaBindingException("charge_history_required", "the mandate limits the charge count: pass recentChargeTimes from your own records");
        PcaBindingResult Fail(string reason) => new(false, reason);
        try
        {
            var oc = G(i.Open, "x_pca");
            if (oc is not D ocd || !(JsX.NumOf(G(ocd, "v")) == PcaBindingVersion) || G(ocd, "grant") is not D grant || G(ocd, "terms") is not D terms) return Fail("open mandate carries no x_pca grant");
            var (why, chainOk) = Pca.VerifyChain(new L { grant }, i.ExpectedPrincipal, true, null, i.PqPins);
            if (!chainOk) return Fail($"PCA grant: {(why.Length == 0 ? "invalid" : why)}");
            var env = Pca.ReadEnvelope(grant);
            if (env == null) return Fail("PCA grant has no envelope");
            if (Pca.HashCanonical(env["predicates"]) != Pca.HashCanonical(AtlasPca.Payments.Payments.MandatePredicates(terms))
                || Pca.HashCanonical(env["caveats"]) != Pca.HashCanonical(AtlasPca.Payments.Payments.MandateCaveats(terms))) return Fail("x_pca terms do not match the grant envelope");
            var rp = (D)env["risk_policy"]!;
            if (!(IntentJs.NumOf(rp["kappa"]) == JsX.NumOf(G(terms, "perTransactionCap"))) || !(IntentJs.NumOf(rp["bMax"]) == JsX.NumOf(G(terms, "cumulativeCap")))) return Fail("x_pca terms do not match the grant risk policy");
            var within = ConstraintsWithinTerms(i.Open, terms);
            if (within != null) return Fail(within);

            var cc = G(i.Closed, "x_pca");
            if (cc is not D ccd || !(JsX.NumOf(G(ccd, "v")) == PcaBindingVersion) || G(ccd, "pcactn") is not D pcactn || G(ccd, "charge") is not D charge) return Fail("closed mandate carries no x_pca PCActn");
            var amt = G(i.Closed, "payment_amount");
            var payee = G(i.Closed, "payee");
            if (!JsX.StrictEq(G(charge, "currency"), G(amt, "currency")) || !JsX.StrictEq(G(charge, "amount"), G(amt, "amount"))) return Fail("x_pca charge differs from the mandate payment_amount");
            var categories = G(terms, "categories") as L ?? new L();
            var category = G(charge, "category");
            if (categories.Count > 0 && (category is not string cat || !categories.Any(x => JsX.StrictEq(x, cat)))) return Fail("x_pca charge lacks an allowed category");

            var now = i.Now ?? AtlasPca.ReplayClock.NowMs();
            var core = Pca.VerifyPcactnCore(pcactn, grant, now, i.Audience, i.AllowedSuites, planRoots: PlanRootPolicy.Skip); // the reference skips the plan-root check here: the mandate binding is the authority
            if (!core.Allow) return Fail($"PCActn: {(string.IsNullOrEmpty(core.Reason) ? "rejected" : core.Reason)}");
            double? enforcedT = null;
            // the gates, in the reference order: taint, freshness, attestation, then the other hooks; the first failing check is the reason
            if (i.EnforceTaint is { } taintGate)
            {
                try
                {
                    var (tok, twhy) = Taint.Gate(G(pcactn, "provenance"), taintGate.Context, taintGate.MaxTaint);
                    if (!tok) return Fail($"PCActn: taint_gate: {twhy}");
                }
                catch (Exception e) { return Fail($"PCActn: taint_gate: taint gate error (fail closed): {e.Message}"); }
            }
            if (i.FreshnessMaxAgeMs is double maxAge)
            {
                var fr = G(pcactn, "freshness");
                var epoch = G(fr, "epoch");
                var epochMs = i.FreshnessEpochMs ?? 60_000;
                var fnow = i.FreshnessNow ?? now;
                var skew = i.FreshnessClockSkewMs is double sk && double.IsFinite(sk) ? Math.Max(0, sk) : 0;
                if (!(epochMs > 0) || !double.IsFinite(maxAge) || maxAge < 0 || !double.IsFinite(fnow)) return Fail("PCActn: freshness: freshness gate misconfigured: epochMs must be > 0 and maxAgeMs >= 0 (fail closed)");
                if (G(fr, "beacon_ref") is not string br || br.Length == 0 || !IntentJs.IsSafeInteger(epoch) || Dbl(epoch) <= 0)
                    return Fail("PCActn: freshness: freshness anchor is missing (empty beacon_ref or non-positive epoch stub)");
                var anchor = Dbl(epoch) * epochMs;
                if (anchor > fnow + skew) return Fail("PCActn: freshness: freshness anchor is in the future");
                if (fnow - anchor > maxAge) return Fail($"PCActn: freshness: freshness anchor is stale (older than {JsX.JsNumString(maxAge)} ms)");
            }
            ThresholdHookResult? RunHook(Func<D, D, ThresholdHookResult?>? h)
            {
                if (h == null) return null;
                try { return h(pcactn, grant); } catch (Exception) { return new ThresholdHookResult(true, false, null, "hook error (fail closed)"); }
            }
            foreach (var (name, hook) in new (string, Func<D, D, ThresholdHookResult?>?)[] { ("attestation", i.AttestationGate ?? i.AttestationHook), ("threshold", i.ThresholdHook), ("revocation", i.RevocationHook) })
            {
                var hr = RunHook(hook);
                if (hr is { Enforced: true, Ok: false }) return Fail($"PCActn: {name}: {hr.Reason ?? "rejected"}");
                if (name == "attestation" && i.AttestationGate != null && i.AttestationRequired && hr is not { Enforced: true })
                    return Fail("PCActn: attestation: attestation required but the verifier reported not-enforced / no document (fail closed)");
                if (name == "threshold" && hr is { Enforced: true, Ok: true, T: double t }) enforcedT = t;
            }
            if (G(pcactn, "zk_compliance") is not null && !IsUndef(G(pcactn, "zk_compliance")))
            {
                var hr = RunHook(i.ZkHook);
                if (hr is { Enforced: true, Ok: false }) return Fail($"PCActn: zk_compliance: {hr.Reason ?? "rejected"}");
                if (hr is not { Enforced: true, Ok: true }) return Fail("PCActn: zk_compliance: PCActn carries a zk_compliance proof but no zk verifier enforced it (fail closed): configure hooks.zk or do not present a proof");
            }
            var action = G(pcactn, "action");
            if (G(action, "verb") as string != "charge" || G(action, "resource") as string != $"merchant:{S(G(payee, "id"))}") return Fail("PCActn action is not a charge at this payee");
            var prm = new D { ["amount"] = G(charge, "amount"), ["currency"] = G(charge, "currency") };
            if (category is string) prm["category"] = category;
            if (!JsX.StrictEq(G(action, "params_digest"), Pca.ParamsDigest(prm))) return Fail("PCActn params do not commit to the x_pca charge");
            var expectedNonce = PcaBindingNonce(new D
            {
                ["transactionId"] = G(i.Closed, "transaction_id"), ["payeeId"] = G(payee, "id"), ["amount"] = G(amt, "amount"), ["currency"] = G(amt, "currency"),
                ["instrumentId"] = G(G(i.Closed, "payment_instrument"), "id"), ["openHash"] = i.OpenHash, ["agentJkt"] = JwkThumbprint(G(CnfOf(i.Open), "jwk")),
            });
            if (!JsX.StrictEq(G(pcactn, "nonce"), expectedNonce)) return Fail("PCActn nonce does not bind this AP2 transaction, open mandate and agent key");
            var perTx = MinorTerm(G(terms, "perTransactionCap"), "perTransactionCap");
            if (!(double.IsFinite(Dbl(G(amt, "amount"))) && Dbl(G(amt, "amount")) <= perTx)) return Fail("payment exceeds the PCA per-transaction cap");
            // the agent may not understate the risk of its own charge
            var recomputed = Dbl(RiskRatio(Dbl(G(amt, "amount")), Dbl(G(terms, "perTransactionCap"))));
            var claimedV = G(G(pcactn, "risk_claim"), "r");
            if (JsX.NumOf(claimedV) is not double claimed || !(claimed >= recomputed - 1e-9)) return Fail("PCActn understates the risk of this charge");
            var need = Risk.Required(claimed, Dbl(rp["theta1"]), Dbl(rp["theta2"]));
            if (need.T > 1 && i.ThresholdHook == null) return Fail($"this charge needs a threshold of {need.T} (human co-sign); supply hooks.threshold to verify it");
            if (need.T > 1 && !(enforcedT is double et && et >= need.T))
                return Fail($"this charge needs a threshold of {need.T} but the threshold hook enforced t={(enforcedT is double e2 ? JsX.JsNumString(e2) : "unreported")}; build it with createThresholdVerifier({{ t: {need.T} }})");
            if (!JsX.StrictEq(G(amt, "currency"), G(terms, "currency")) || !(G(terms, "merchants") as L ?? new L()).Any(x => JsX.StrictEq(x, G(payee, "id")))) return Fail("payment currency or payee is outside the PCA terms");

            if (Pca.HashCanonical(G(i.Mandate, "grant")) != Pca.HashCanonical(grant)) return Fail("the supplied PCA mandate is not the one in the open mandate");
            var chargeIn = new D { ["merchant"] = G(payee, "id"), ["amount"] = G(amt, "amount"), ["currency"] = G(amt, "currency"), ["recentChargeTimes"] = new L(i.RecentChargeTimes ?? new List<object?>()) };
            if (category is string) chargeIn["category"] = category;
            if (i.Now != null) chargeIn["now"] = N(i.Now.Value);
            var decision = AtlasPca.Payments.Payments.AuthorizeCharge(i.Mandate, chargeIn, grant, PolicyVmDecide.Decide);
            var outcome = G(decision, "outcome") as string;
            if (outcome == "deny") return Fail($"PCA denies this charge: {string.Join("; ", (G(decision, "reasons") as L ?? new L()).Select(S))}");
            if (outcome == "step_up" && !(enforcedT is double e3 && e3 >= 2)) return Fail("PCA requires a human co-sign for this charge and no verified threshold (t >= 2) was enforced");
            return new PcaBindingResult(true, null, pcactn, grant, terms);
        }
        catch (Exception e) { return Fail(e.Message); }
    }
}

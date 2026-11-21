// The real-time rail authorization callback (the reference rails.ts createRailAuthorizer): a rail request goes through authorizeChargeAtomic inside a latency
// budget. The rail is a SECOND enforcement point: its limits are an upper-bounded copy of the PCA limits, PCA never relaxes because the rail would have blocked,
// and an answer is only ever "approve" when PCA's own decision is `auto`. A step-up, a deny, an unknown card, a timeout, an exception: all decline.
// Heuristic-free: the merchant id and the category come from the rail's structured fields.
// shortcut: a decision that finishes after the timeout may still have debited the budget with no approval sent (under-spend, the safe direction); an operator reconciles by cosign / refill.
using System.Text.RegularExpressions;
using JD = System.Collections.Generic.Dictionary<string, object?>;
using JL = System.Collections.Generic.List<object?>;

namespace AtlasPca.Payments;

/// <summary>The mandate, verified grant and optional budget key (default: the grant hash) an instrument id resolves to.</summary>
public sealed record InstrumentBinding(JD Mandate, JD Grant, string? BudgetKey = null);

/// <summary>What <see cref="Rails.CreateRailAuthorizer"/> reads. <c>LatencyBudgetMs</c> (default 1500; Stripe waits 2000) must be positive.
/// <c>OnStepUp</c> may notify the principal: a step-up cannot wait at a card terminal, so it is declined here.</summary>
public sealed class RailAuthorizerOptions
{
    public Func<string, Task<InstrumentBinding?>> Instruments { get; set; } = _ => Task.FromResult<InstrumentBinding?>(null);
    public IChargeBudgetStore Store { get; set; } = null!;
    public double LatencyBudgetMs { get; set; } = 1500;
    public Func<long>? Now { get; set; }
    public Func<JD, JD, Task>? OnStepUp { get; set; }
}

public static partial class Rails
{
    /// <summary>Action-kit convention: a custom trait <c>mcc.c5734</c> on the verb says the verb may spend in MCC 5734. Traits only narrow.</summary>
    public static Regex MccTraitRe { get; } = new(@"\Amcc\.c(\d{4})\z", RegexOptions.CultureInvariant);

    static JD Decline(params string[] reasons) => new() { ["approved"] = false, ["reasons"] = new JL(reasons.Cast<object?>()) };

    /// <summary>The single code path from a rail request (<c>{id, instrumentId, amount, currency, merchantId?, mcc?}</c>) to a PCA decision: <c>{approved, reasons, decision?}</c>.
    /// Total: every failure is a decline.</summary>
    public static Func<JD, Task<JD>> CreateRailAuthorizer(RailAuthorizerOptions opts)
    {
        var budgetMs = opts.LatencyBudgetMs;
        if (!double.IsFinite(budgetMs) || budgetMs <= 0) throw new ArgumentOutOfRangeException(nameof(opts), "createRailAuthorizer: latencyBudgetMs must be positive");
        var now = opts.Now ?? (() => DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());

        async Task<JD> Decide(JD a)
        {
            if (a == null || a.GetValueOrDefault("id") is not string id || a.GetValueOrDefault("instrumentId") is not string instrumentId || id.Length == 0) return Decline("malformed_authorization");
            var amount = a.GetValueOrDefault("amount");
            if (!(IntentJs.IsSafeInteger(amount) && IntentJs.NumOf(amount)! > 0)) return Decline("amount_not_positive_minor_units");
            if (a.GetValueOrDefault("currency") is not string currency || currency.Length == 0) return Decline("currency_missing");
            if (a.GetValueOrDefault("merchantId") is not string merchant || merchant.Length == 0) return Decline("merchant_unknown");
            var inst = await opts.Instruments(instrumentId).ConfigureAwait(false);
            if (inst == null) return Decline("instrument_unknown");
            var charge = new JD { ["merchant"] = merchant, ["amount"] = amount, ["currency"] = currency.ToUpperInvariant(), ["now"] = new Num(now().ToString()) };
            if (a.TryGetValue("mcc", out var mcc) && mcc != null) charge["category"] = mcc;
            var d = await Payments.AuthorizeChargeAtomicAsync(inst.Mandate, charge, inst.Grant, opts.Store, inst.BudgetKey).ConfigureAwait(false);
            var outcome = d.GetValueOrDefault("outcome") as string;
            var reasons = d.GetValueOrDefault("reasons") as JL ?? new JL();
            if (outcome == "auto") return new JD { ["approved"] = true, ["reasons"] = new JL(), ["decision"] = d };
            if (outcome == "step_up")
            {
                try { if (opts.OnStepUp != null) await opts.OnStepUp(a, d).ConfigureAwait(false); } catch (Exception) { /* a failing notifier must not change the answer */ }
                var r = new JL { "step_up_required" }; r.AddRange(reasons);
                return new JD { ["approved"] = false, ["reasons"] = r, ["decision"] = d };
            }
            return new JD { ["approved"] = false, ["reasons"] = reasons.Count > 0 ? reasons : new JL { "denied" }, ["decision"] = d };
        }

        return async a =>
        {
            using var cts = new CancellationTokenSource();
            var work = Decide(a).ContinueWith(t => t.IsCompletedSuccessfully ? t.Result : Decline("authorizer_error"), TaskScheduler.Default);
            var late = Task.Delay(TimeSpan.FromMilliseconds(budgetMs), cts.Token).ContinueWith(t => Decline("latency_budget_exceeded"), TaskContinuationOptions.OnlyOnRanToCompletion);
            var first = await Task.WhenAny(work, late).ConfigureAwait(false);
            cts.Cancel();
            return await first.ConfigureAwait(false);
        };
    }
}

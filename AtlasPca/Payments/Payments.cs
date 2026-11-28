// PAYMENT MANDATES as PCA Root Intent Grants (packages/pca-payments mandate.ts, authorize.ts, charge-action.ts, spt-limits.ts; the TypeScript is
// authoritative). A mandate is a minted grant whose predicates, caveats and risk policy encode caps, an allowlist, a human-co-sign line (Y) and a hard
// ceiling (X). Mandates, charges and terms are JSON trees read with the reference's JavaScript semantics; the policy decision itself is the core
// engine and is INJECTED (<see cref="DecideFn"/>), so this package assembles its input and applies its refusals, exact money arithmetic and budget threading.
using System.Numerics;
using System.Text.RegularExpressions;
using JD = System.Collections.Generic.Dictionary<string, object?>;
using JL = System.Collections.Generic.List<object?>;

namespace AtlasPca.Payments;

/// <summary>Why a mandate was refused before any decision: verified_grant_required, mandate_grant_mismatch or mandate_terms_mismatch.</summary>
public sealed class MandateGrantError : Exception
{
    public string Code { get; }
    public MandateGrantError(string code, string message) : base(message) { Code = code; }
}

/// <summary>The PCA policy decision: the decide input (<c>{grant, action, risk, budget, now, caveatContext}</c>) in, the decision
/// (<c>{admit, releaseGuardianShare, requiredThreshold, r, budget, reasons, ...}</c>) out.</summary>
public delegate JD DecideFn(JD input);

public static partial class Payments
{
    public const string ChargeReversibilityClass = "reversible";
    public const string ChargeVerb = "charge";
    public const string AmountNotMinorUnits = "amount_not_integer_minor_units";
    public const string MerchantInvalid = "merchant_invalid";
    static readonly Regex Ctl = new(@"[*\u0000-\u001f\u007f]", RegexOptions.CultureInvariant);

    /// <summary>A merchant id that cannot act as a resource pattern: no <c>*</c>, no control characters.</summary>
    public static bool IsPlainId(object? x) => x is string s && s.Length > 0 && !Ctl.IsMatch(s);

    /// <summary>True for a non-negative safe integer (amounts are integer minor units).</summary>
    public static bool IsMinorUnits(object? x) => x is Num && IntentJs.IsSafeInteger(x) && Js.D(x) >= 0 && !IntentJs.IsNegZero(Js.D(x));

    static bool Finite(object? x) => Js.IsFiniteNum(x);

    // ---- the mandate ----

    static void Validate(JD p)
    {
        // -0 is a number the strict canonicalizer refuses (the grant digest): refuse it here too instead of signing it
        foreach (var k in new[] { "perTransactionCap", "autoApproveThreshold", "cumulativeCap", "replenishPerCosign", "periodMs", "maxTransactionsPerPeriod", "periodStart", "now" })
            if (Js.Prop(p, k) is Num nz && IntentJs.NumOf(nz) is double zd && IntentJs.IsNegZero(zd)) throw new ArgumentException($"buildPaymentMandate: {k} must not be negative zero");
        if (!(Js.Prop(p, "strictMinorUnits") is false))
            foreach (var k in new[] { "perTransactionCap", "autoApproveThreshold", "cumulativeCap", "replenishPerCosign" })
            {
                var v = Js.Prop(p, k);
                if (!IntentJs.IsSafeInteger(k == "replenishPerCosign" && v == null ? new Num("0") : v)) throw new ArgumentException($"buildPaymentMandate: {k} must be a safe integer in minor units (strictMinorUnits)");
            }
        if (Js.Prop(p, "merchants") is not JL m || m.Count == 0) throw new ArgumentException("buildPaymentMandate: at least one allowlisted merchant is required");
        if (m.Any(x => x is not string s || s.Length == 0)) throw new ArgumentException("buildPaymentMandate: merchant ids must be non-empty strings");
        if (m.Any(x => !IsPlainId(x))) throw new ArgumentException("buildPaymentMandate: merchant ids must not contain `*` or control characters");
        if (Js.Prop(p, "currency") is not string c || c.Length == 0) throw new ArgumentException("buildPaymentMandate: currency is required");
        var x0 = Js.Prop(p, "perTransactionCap"); var y = Js.Prop(p, "autoApproveThreshold"); var cap = Js.Prop(p, "cumulativeCap");
        if (!Finite(x0) || Js.D(x0) <= 0) throw new ArgumentException("buildPaymentMandate: perTransactionCap (X) must be a finite number > 0");
        if (!Finite(y) || Js.D(y) < 0 || Js.D(y) > Js.D(x0)) throw new ArgumentException("buildPaymentMandate: autoApproveThreshold (Y) must satisfy 0 <= Y <= X");
        if (!Finite(cap) || Js.D(cap) < Js.D(x0)) throw new ArgumentException("buildPaymentMandate: cumulativeCap must be a finite number >= perTransactionCap (X)");
        if (p.ContainsKey("periodMs") && (!Finite(p["periodMs"]) || Js.D(p["periodMs"]) <= 0)) throw new ArgumentException("buildPaymentMandate: periodMs must be a finite number > 0 when given");
        if (p.ContainsKey("maxTransactionsPerPeriod") && !(p["maxTransactionsPerPeriod"] is Num mt && IntentJs.NumOf(mt) is double md && double.IsFinite(md) && md == Math.Round(md) && md > 0))
            throw new ArgumentException("buildPaymentMandate: maxTransactionsPerPeriod must be a positive integer when given");
        if (p.ContainsKey("replenishPerCosign") && (!Finite(p["replenishPerCosign"]) || Js.D(p["replenishPerCosign"]) < 0)) throw new ArgumentException("buildPaymentMandate: replenishPerCosign must be a finite number >= 0 when given");
    }

    /// <summary>The allowlist predicates: one per merchant, each carrying the hard-ceiling, currency, non-negative amount and category guards.</summary>
    // the grant body is written through JSON, which prints -0 as 0
    static object? NoNegativeZero(object? v) => v switch
    {
        Num { Raw: "-0" } => new Num("0"),
        JL l => new JL(l.Select(NoNegativeZero)),
        JD d => d.ToDictionary(e => e.Key, e => NoNegativeZero(e.Value)),
        _ => v,
    };

    public static JL MandatePredicates(object? terms)
    {
        var merchants = Js.Prop(terms, "merchants") as JL ?? throw new InvalidOperationException("terms.merchants.map is not a function");
        var o = new JL();
        foreach (var m in merchants)
        {
            var cats = Js.Read(terms, "categories");
            var hasCats = Js.Length(cats) is double n && n > 0;
            var conds = new JL
            {
                Cond("action.params.amount", "lte", terms, "perTransactionCap"),
                Cond("action.params.currency", "eq", terms, "currency"),
                new JD { ["field"] = "action.params.amount", ["op"] = "gte", ["value"] = new Num("0") },
            };
            if (hasCats) conds.Add(new JD { ["field"] = "action.params.category", ["op"] = "in", ["value"] = cats });
            o.Add(new JD { ["verb"] = ChargeVerb, ["resource"] = "merchant:" + Js.Str(m), ["where"] = conds });
        }
        return o;
    }

    static JD Cond(string field, string op, object? terms, string key)
    {
        var c = new JD { ["field"] = field, ["op"] = op };
        if (Js.Has(terms, key)) c["value"] = Js.Prop(terms, key); // an absent term is undefined: no value member
        return c;
    }

    /// <summary>The envelope caveats: period window, velocity cap and the reversibility floor.</summary>
    public static JL MandateCaveats(object? terms)
    {
        var o = new JL();
        var start = Js.Read(terms, "periodStart");
        bool hasStart = Js.Has(terms, "periodStart"), hasEnd = Js.Has(terms, "periodEnd");
        if (Js.Gt(start, new Num("0"))) o.Add(new JD { ["type"] = "not_before", ["at"] = start });
        if (hasEnd) o.Add(new JD { ["type"] = "expires", ["at"] = Js.Prop(terms, "periodEnd") });
        if (Js.Has(terms, "maxTransactionsPerPeriod") && hasEnd)
        {
            var perSecs = Math.Max(1, Js.Round((Js.ToNumber(Js.Prop(terms, "periodEnd")) - (hasStart ? Js.ToNumber(start) : double.NaN)) / 1000));
            o.Add(new JD { ["type"] = "rate", ["max"] = Js.Prop(terms, "maxTransactionsPerPeriod"), ["per_secs"] = Js.Out(perSecs) });
        }
        o.Add(new JD { ["type"] = "reversibility_max", ["class"] = "reversible" });
        return o;
    }

    /// <summary>The risk policy that makes "spend = risk" exact: gamma = 1, theta1 = theta2 = Y/X, kappa = X, bMax = the cumulative cap.</summary>
    public static JD MandateRiskPolicy(object? terms, object? replenishPerCosign)
    {
        Js.NotNull(terms);
        var y = Js.ToNumber(Js.Has(terms, "autoApproveThreshold") ? Js.Prop(terms, "autoApproveThreshold") : double.NaN);
        var x = Js.ToNumber(Js.Has(terms, "perTransactionCap") ? Js.Prop(terms, "perTransactionCap") : double.NaN);
        var o = new JD
        {
            ["weights"] = new JD { ["alpha"] = new Num("0"), ["beta"] = new Num("0"), ["gamma"] = new Num("1"), ["delta"] = new Num("0"), ["epsilon"] = new Num("0"), ["zeta"] = new Num("0") },
            ["theta1"] = Js.Out(y / x), ["theta2"] = Js.Out(y / x),
        };
        if (Js.Has(terms, "perTransactionCap")) o["kappa"] = Js.Prop(terms, "perTransactionCap");
        o["lambda"] = new Num("0");
        o["rho"] = replenishPerCosign;
        if (Js.Has(terms, "cumulativeCap")) o["bMax"] = Js.Prop(terms, "cumulativeCap");
        return o;
    }

    /// <summary>The most an agent can spend autonomously between two human co-signs: safetyBound(policy) * kappa. <paramref name="mandate"/>: <c>{policy: {kappa, bMax}}</c>.</summary>
    public static object? AutoSpendBound(object? mandate)
    {
        var policy = Js.NotNull(Js.Read(mandate, "policy"));
        var kappa = Js.ToNumber(Js.Has(policy, "kappa") ? Js.Prop(policy, "kappa") : double.NaN);
        var bMax = Js.ToNumber(Js.Has(policy, "bMax") ? Js.Prop(policy, "bMax") : double.NaN);
        var bound = kappa > 0 ? Math.Max(0, bMax) / kappa : 0;
        return Js.Out(bound * kappa);
    }

    /// <summary>Build a payment mandate: the params as a PCA Root Intent Grant envelope plus the initial trust budget.
    /// <paramref name="p"/>: the mandate params; <c>principalSecret</c> is the 32-byte Ed25519 seed (a byte[]).</summary>
    public static JD BuildPaymentMandate(object? p, Func<long>? clock = null)
    {
        if (p is not JD pp) throw new ArgumentException("buildPaymentMandate: params must be an object");
        Validate(pp);
        long NowMs() => clock?.Invoke() ?? AtlasPca.ReplayClock.NowMs();
        object nowV = Finite(Js.Prop(pp, "now")) ? pp["now"]! : new Num(NowMs().ToString());
        object startV = Finite(Js.Prop(pp, "periodStart")) ? pp["periodStart"]! : nowV;
        var terms = new JD
        {
            ["merchants"] = new JL((JL)pp["merchants"]!),
            ["categories"] = Js.Truthy(Js.Prop(pp, "categories")) ? Js.SpreadList(pp["categories"]) : new JL(),
            ["currency"] = pp["currency"], ["perTransactionCap"] = pp["perTransactionCap"], ["autoApproveThreshold"] = pp["autoApproveThreshold"],
            ["cumulativeCap"] = pp["cumulativeCap"], ["periodStart"] = startV,
        };
        if (pp.ContainsKey("periodMs")) terms["periodEnd"] = Js.Out(Js.D(startV) + Js.D(pp["periodMs"]));
        if (pp.ContainsKey("maxTransactionsPerPeriod")) terms["maxTransactionsPerPeriod"] = pp["maxTransactionsPerPeriod"];
        var replenish = Js.Prop(pp, "replenishPerCosign") ?? pp["cumulativeCap"];
        var policy = MandateRiskPolicy(terms, replenish);
        var goal = Js.Prop(pp, "goal") is { } g ? g
            : $"spend ≤ {Js.Str(terms["autoApproveThreshold"])} {Js.Str(terms["currency"])} autonomously / ≤ {Js.Str(terms["perTransactionCap"])} with co-sign, ≤ {Js.Str(terms["cumulativeCap"])} cumulative, at [{string.Join(", ", ((JL)terms["merchants"]!).Select(x => Js.Str(x)))}]";
        if (goal is not string goalText) throw new ArgumentException("mintGrant: goal must be a string");
        if (Js.Prop(pp, "principalSecret") is not byte[] seed || Js.Prop(pp, "agentPublic") is not string holder) throw new ArgumentException("buildPaymentMandate: principalSecret and agentPublic are required");
        var envelope = new JD { ["predicates"] = NoNegativeZero(MandatePredicates(terms)), ["caveats"] = MandateCaveats(terms), ["agent_binding"] = new JD(), ["risk_policy"] = policy };
        using var key = SuiteKey.Ed25519(EdKey.FromSeed(seed));
        var minted = Issue.MintGrant(key, holder, null, envelope, goalText, pp.ContainsKey("goalSalt") ? pp["goalSalt"] as string : null);
        var budget = new JD { ["B"] = terms["cumulativeCap"], ["tau"] = nowV, ["asOf"] = nowV };
        return new JD { ["grant"] = minted.Grant, ["policy"] = policy, ["budget"] = budget, ["terms"] = terms, ["goalCommit"] = minted.GoalCommit, ["goalSalt"] = minted.GoalSalt };
    }

    // ---- charges ----

    /// <summary>The charge params committed in both the plan node and the PCActn action: <c>{amount, currency (defaults to the mandate's), category?}</c>.</summary>
    public static JD ChargeParams(object? mandate, object? charge)
    {
        if (charge == null) throw new InvalidOperationException("cannot read a member of undefined");
        var o = new JD();
        if (Js.Has(charge, "amount")) o["amount"] = Js.Prop(charge, "amount");
        if (Js.Has(charge, "currency")) o["currency"] = Js.Prop(charge, "currency");
        else
        {
            var terms = Js.NotNull(Js.Read(mandate, "terms"));
            if (Js.Has(terms, "currency")) o["currency"] = Js.Prop(terms, "currency"); // an absent currency is undefined: no member
        }
        if (Js.Has(charge, "category")) o["category"] = Js.Prop(charge, "category");
        return o;
    }

    /// <summary>The action context a charge denotes: <c>{action: {verb, resource, params, reversibility_class}}</c>.</summary>
    public static JD ChargeActionContext(object? mandate, object? charge)
    {
        if (charge == null) throw new InvalidOperationException("cannot read a member of undefined");
        var prm = ChargeParams(mandate, charge);
        var o = new JD
        {
            ["verb"] = ChargeVerb, ["resource"] = "merchant:" + Js.Str(Js.Prop(charge, "merchant"), Js.Has(charge, "merchant")),
            ["params"] = prm, ["reversibility_class"] = ChargeReversibilityClass,
        };
        return new JD { ["action"] = o };
    }

    /// <summary>The committed plan node of a charge; its <c>params_digest</c> is pinned to the charge params.</summary>
    public static JD ChargePlanNode(object? mandate, object? charge, string id) => new()
    {
        ["id"] = id, ["verb"] = ChargeVerb, ["resource"] = "merchant:" + Js.Str(Js.Prop(charge, "merchant"), Js.Has(charge, "merchant")),
        ["reversibility_class"] = ChargeReversibilityClass, ["params_digest"] = Pca.ParamsDigest(ChargeParams(mandate, charge)),
    };

    // ---- binding a mandate to the verified grant ----

    /// <summary>The mandate bound to the grant the caller verified: the mandate's grant must be that grant, the terms and policy must be the ones signed
    /// into its envelope, and the budget is clamped to the signed bMax. Throws <see cref="MandateGrantError"/>.</summary>
    static JD Bind(object? mandate, object? verifiedGrant)
    {
        if (!Js.IsObject(verifiedGrant)) throw new MandateGrantError("verified_grant_required", "a verified (or stored) grant is required; the mandate's own grant is never the authority");
        if (!Js.IsObject(mandate)) throw new MandateGrantError("mandate_grant_mismatch", "the mandate grant is not the verified grant");
        if (!Js.Has(mandate, "grant")) throw new InvalidOperationException("canonicalize: unsupported type undefined");
        if (Pca.HashCanonical(Js.Prop(mandate, "grant")) != Pca.HashCanonical(verifiedGrant)) throw new MandateGrantError("mandate_grant_mismatch", "the mandate grant is not the verified grant");
        var env = Pca.ReadEnvelope(verifiedGrant);
        var terms = Js.Prop(mandate, "terms"); var policy = Js.Prop(mandate, "policy");
        static bool Same(object? a, object? b) => Pca.HashCanonical(a) == Pca.HashCanonical(b);
        if (env == null || !Js.Truthy(terms) || !Js.Truthy(policy) || !Same(Js.Prop(env, "predicates"), MandatePredicates(terms))
            || !Same(Js.Prop(env, "caveats"), MandateCaveats(terms)) || !Same(Js.Prop(env, "risk_policy"), policy))
            throw new MandateGrantError("mandate_terms_mismatch", "the mandate terms / policy are not the ones signed into the verified grant");
        var bMax = Js.D(Js.Prop(Js.Prop(env, "risk_policy"), "bMax"));
        var bv = Js.Prop(Js.Prop(mandate, "budget"), "B");
        var b = bv is Num && Finite(bv) ? Math.Max(0, Math.Min(Js.D(bv), bMax)) : 0;
        var budget = Js.Spread(Js.Prop(mandate, "budget"));
        budget["B"] = Js.Out(b);
        var o = new JD((JD)mandate!);
        o["grant"] = verifiedGrant;
        o["budget"] = budget;
        return o;
    }

    static double Amount(object? charge) { var a = Js.Prop(charge, "amount"); return Finite(a) ? Js.D(a) : double.PositiveInfinity; }

    /// <summary>The decide input of a charge: risk is collapsed to the normalized amount (spend = risk). A mandate whose grant, terms or policy differ is refused.</summary>
    public static JD ChargeDecideInput(object? mandate0, object? charge, object? now, object? verifiedGrant)
    {
        var mandate = Bind(mandate0, verifiedGrant);
        var x = Js.Prop(Js.Prop(mandate, "terms"), "perTransactionCap");
        var amount = Amount(charge);
        var blast = Js.Gt(x, new Num("0")) ? amount / Js.ToNumber(x) : 1;
        var ctx = new JD { ["reversibilityClass"] = ChargeReversibilityClass };
        if (Js.Has(charge, "recentChargeTimes")) ctx["recentActionTimes"] = Js.Prop(charge, "recentChargeTimes");
        return new JD
        {
            ["grant"] = verifiedGrant, ["action"] = ChargeActionContext(mandate, charge),
            ["risk"] = new JD { ["semanticDistance"] = new Num("0"), ["reversibility"] = new Num("1"), ["blastRadius"] = Js.Out(blast), ["taint"] = new Num("0"), ["confidence"] = new Num("1"), ["age"] = new Num("0") },
            ["budget"] = mandate["budget"], ["now"] = now, ["caveatContext"] = ctx,
        };
    }

    // ---- the decision ----

    static object? Prop(object? o, string k) => Js.Prop(o, k);

    /// <summary>Run a charge through the PCA decision against the grant you VERIFIED. Returns <c>{outcome, t, r, requiredThreshold, cost, budgetBefore,
    /// budgetAfter, reasons, decision}</c>; throws <see cref="MandateGrantError"/> when the mandate is not bound to that grant. Never throws on a charge.
    /// An amount that is not integer minor units, or a merchant that is not a plain id, is refused whatever the policy says.</summary>
    public static JD AuthorizeCharge(object? mandate0, object? charge, object? verifiedGrant, DecideFn decide, Func<long>? clock = null)
    {
        var mandate = Bind(mandate0, verifiedGrant);
        var nv = Prop(charge, "now");
        object now = Finite(nv) ? nv! : new Num((clock?.Invoke() ?? AtlasPca.ReplayClock.NowMs()).ToString());
        var input = ChargeDecideInput(mandate, charge, now, verifiedGrant);
        var raw = decide(input);
        var refusal = !IsMinorUnits(Prop(charge, "amount")) ? AmountNotMinorUnits : !IsPlainId(Prop(charge, "merchant")) ? MerchantInvalid : null;
        JD decision;
        if (refusal == null) decision = raw;
        else
        {
            decision = new JD(raw) { ["admit"] = false, ["releaseGuardianShare"] = false };
            var reasons = new JL { refusal };
            if (Prop(raw, "reasons") is JL rr) reasons.AddRange(rr);
            decision["reasons"] = reasons;
            decision["budget"] = mandate["budget"];
        }
        string outcome = !Js.Truthy(Prop(decision, "releaseGuardianShare")) ? "deny" : Js.Truthy(Prop(decision, "admit")) ? "auto" : "step_up";
        var policy = Prop(mandate, "policy"); var terms = Prop(mandate, "terms"); var budget = Prop(mandate, "budget");
        var amount = Prop(charge, "amount");
        bool exact = outcome == "auto" && IsMinorUnits(amount) && Finite(Prop(policy, "kappa")) && Finite(Prop(terms, "perTransactionCap"))
            && Js.D(Prop(policy, "kappa")) == Js.D(Prop(terms, "perTransactionCap")) && IntentJs.IsSafeInteger(Prop(budget, "B"));
        object? cost = outcome != "auto" ? new Num("0") : exact ? amount : Js.Out(Risk.Cost(Js.D(Prop(decision, "r")), Js.D(Prop(policy, "kappa"))));
        object? after = exact ? new JD(Js.Spread(Prop(decision, "budget"))) { ["B"] = Js.Out(Js.D(Prop(budget, "B")) - Js.D(amount)) } : Prop(decision, "budget");
        return new JD
        {
            ["outcome"] = outcome, ["t"] = Prop(Prop(decision, "requiredThreshold"), "t"), ["r"] = Prop(decision, "r"), ["requiredThreshold"] = Prop(decision, "requiredThreshold"),
            ["cost"] = cost, ["budgetBefore"] = budget, ["budgetAfter"] = after, ["reasons"] = Prop(decision, "reasons"), ["decision"] = decision,
        };
    }

    /// <summary>Advance the mandate's budget after a decision (functional): <c>{...mandate, budget: decision.budgetAfter}</c>.</summary>
    public static JD SettleCharge(object? mandate, object? decision)
    {
        var o = Js.Spread(mandate);
        o["budget"] = Prop(decision, "budgetAfter");
        return o;
    }

    static double Nz(double x) => double.IsFinite(x) && x > 0 ? x : 0;

    /// <summary>Apply a human co-sign: restore autonomous budget by <c>rho</c> (partial) or fully re-confirm to <c>bMax</c>. The ONLY way the budget goes up.
    /// <paramref name="opts"/>: <c>{full?}</c> (null: partial).</summary>
    public static JD ApplyHumanCosign(object? mandate, object? now, object? opts, bool? full = null)
    {
        var policy = Js.NotNull(Js.Read(mandate, "policy"));
        var budget = Js.Read(mandate, "budget");
        bool isFull = full ?? Js.Truthy(Prop(opts, "full"));
        var bMax = Js.ToNumber(Js.Has(policy, "bMax") ? Prop(policy, "bMax") : double.NaN);
        double b;
        if (isFull) b = Nz(bMax);
        else
        {
            var bv = Js.Read(budget, "B");
            var rho = Js.ToNumber(Js.Has(policy, "rho") ? Prop(policy, "rho") : double.NaN);
            double sum = (bv is string or JL or JD) ? Js.StrToNumber(Js.Str(bv) + Js.Str(Js.Out(Nz(rho)))) : Js.ToNumber(Js.Has(budget, "B") ? bv : double.NaN) + Nz(rho);
            b = Math.Min(Nz(bMax), sum);
        }
        var o = Js.Spread(mandate);
        o["budget"] = new JD { ["B"] = Js.Out(b), ["tau"] = now, ["asOf"] = now };
        return o;
    }

    // ---- the plan node and the PCActn of a charge ----

    /// <summary>A signed PCActn for a charge: <c>{pcactn, node}</c>. <paramref name="opts"/>: <c>{signerSecret (byte[] seed), aud, counter, nodeId?, now?, chain?}</c>.</summary>
    public static JD ChargeToPCActn(object? mandate, object? charge, object? opts)
    {
        if (!IsMinorUnits(Prop(charge, "amount"))) throw new ArgumentException("chargeToPCActn: amount must be a non-negative integer in minor units");
        var counterV = Prop(opts, "counter");
        var nodeId = Js.Has(opts, "nodeId") && Prop(opts, "nodeId") != null ? Js.Str(Prop(opts, "nodeId")) : $"charge:{Js.Str(Prop(charge, "merchant"), Js.Has(charge, "merchant"))}:{Js.Str(counterV, Js.Has(opts, "counter"))}";
        var node = ChargePlanNode(mandate, charge, nodeId);
        var terms = Prop(mandate, "terms");
        var x = Js.Prop(terms, "perTransactionCap");
        var amountV = Prop(charge, "amount");
        var amount = Finite(amountV) ? Js.D(amountV) : Js.D(x);
        var r = Js.Gt(x, new Num("0")) ? amount / Js.ToNumber(x) : 1;
        r = r < 0 ? 0 : r > 1 ? 1 : r;
        var prm = ChargeParams(mandate, charge);
        var chain = Prop(opts, "chain") as JL ?? new JL { Prop(mandate, "grant") };
        if (chain.Count == 0 || chain[0] is not JD grant) throw new ArgumentException("chargeToPCActn: a chain rooted at a grant is required");
        if (Prop(opts, "signerSecret") is not byte[] seed) throw new ArgumentException("chargeToPCActn: signerSecret is required");
        var inputs = new JD(prm) { ["blastRadius"] = Js.Out(r) };
        using var signer = SuiteKey.Ed25519(EdKey.FromSeed(seed));
        var spec = new ActSpec
        {
            Grant = grant, Chain = chain, Plan = Issue.CommitPlan(new[] { node }), NodeId = nodeId, Params = prm,
            Counter = Js.Has(opts, "counter") && Pca.SafeInt(counterV, out var c) ? c : throw new ArgumentException("chargeToPCActn: counter is required"),
            Signer = signer, Aud = Prop(opts, "aud") as string ?? "",
            RiskClaim = new JD { ["r"] = Js.Out(r), ["inputs"] = inputs },
        };
        if (Js.Has(opts, "now") && Pca.SafeInt(Prop(opts, "now"), out var iat)) spec.Iat = iat;
        return new JD { ["pcactn"] = Issue.BuildPCActn(spec), ["node"] = node };
    }

    // ---- Shared Payment Token limits ----

    /// <summary>The <c>usage_limits</c> of a Shared Payment Token that fits what the mandate lets an agent spend WITHOUT a human co-sign: at most the auto-approve
    /// threshold, at most the remaining autonomous budget, in the mandate currency (lowercase), expiring with the mandate period.</summary>
    public static JD SharedPaymentTokenLimits(object? mandate, object? now)
    {
        if (!Finite(now)) throw new ArgumentException("sharedPaymentTokenLimits: now must be an epoch-ms time");
        var t = Js.NotNull(Js.Read(mandate, "terms"));
        var budgetObj = Js.NotNull(Js.Read(mandate, "budget"));
        var b = Js.ToNumber(Js.Has(budgetObj, "B") ? Prop(budgetObj, "B") : double.NaN);
        var budget = Math.Floor(b);
        var y = Js.ToNumber(Js.Has(t, "autoApproveThreshold") ? Prop(t, "autoApproveThreshold") : double.NaN);
        var max = double.IsNaN(y) || double.IsNaN(budget) ? double.NaN : Math.Min(y, budget);
        if (!(double.IsFinite(max) && max == Math.Floor(max) && Math.Abs(max) <= 9007199254740991.0) || max <= 0) throw new ArgumentException("sharedPaymentTokenLimits: no autonomous spend capacity is left; a human co-sign is needed");
        var hasEnd = Js.Has(t, "periodEnd");
        // an infinite period end would serialize as a null expiry, read as no expiry
        if (hasEnd && !Finite(Prop(t, "periodEnd"))) throw new InvalidOperationException("TypeError: sharedPaymentTokenLimits: periodEnd must be an epoch-ms time");
        if (hasEnd && !(Js.ToNumber(now) < Js.ToNumber(Prop(t, "periodEnd")))) throw new ArgumentException("sharedPaymentTokenLimits: the mandate period has ended");
        if (Prop(t, "currency") is not string cur) throw new InvalidOperationException("currency.toLowerCase is not a function");
        var o = new JD { ["currency"] = cur.ToLowerInvariant(), ["max_amount"] = Js.Out(max) };
        if (hasEnd) o["expires_at"] = Js.Out(Math.Floor(Js.ToNumber(Prop(t, "periodEnd")) / 1000));
        return o;
    }
}

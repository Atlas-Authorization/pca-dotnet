// The server-stack surface of the TypeScript core under its names: the required-check profiles, enforceRequired, createAuthorizer /
// requireAuthorized (build the configuration once, call per operation) and the money-risk helper. The verifier itself is Pca.Authorize.
using JD = System.Collections.Generic.Dictionary<string, object?>;

namespace AtlasPca;

/// <summary>The verdict <see cref="PcaServer.EnforceRequired"/> returns: checks keep their order, a check added by enforcement is appended.</summary>
public sealed record EnforcedVerdict(bool Allow, IReadOnlyList<KeyValuePair<string, string>> Checks, IReadOnlyList<string> Reasons);

public static class PcaServer
{
    /// <summary>The stateless profile of the verifier: a verdict allows only when these passed (the reference <c>DEFAULT_REQUIRED_CHECKS</c>).</summary>
    public static IReadOnlyList<string> DefaultRequiredChecks { get; } = new[] { "counter_format", "revocation", "plan_root_authorized", "audience", "validity", "grant_ref_bound" };

    /// <summary>The profile a STATEFUL resource server demands: the stateless one plus <c>replay</c> (not-enforced without a store, so denied).</summary>
    public static IReadOnlyList<string> StatefulRequiredChecks { get; } = new[] { "counter_format", "replay", "revocation", "plan_root_authorized", "audience", "validity", "grant_ref_bound" };

    /// <summary>The checks a full-policy decision must PASS: the stateful profile plus the params digest and the policy itself.</summary>
    public static IReadOnlyList<string> ExecutionRequiredChecks { get; } = StatefulRequiredChecks.Concat(new[] { "params_digest", "policy" }).ToList();

    /// <summary>Fold the required checks into a verdict: every named check MUST be <c>pass</c>; one that is not turns the verdict to deny and, unless it
    /// already failed, is recorded as <c>fail</c> with a reason. The result never allows more than the input and reasons only grow. The legacy name
    /// <c>counter</c> means <c>replay</c> when the verdict has that check, else <c>counter_format</c>.</summary>
    public static EnforcedVerdict EnforceRequired(bool allow, IEnumerable<KeyValuePair<string, string>> checks, IEnumerable<string> reasons, IEnumerable<string> required)
    {
        var cs = checks.ToList();
        var rs = reasons.ToList();
        int Find(string n) => cs.FindIndex(c => c.Key == n);
        foreach (var raw in required)
        {
            var name = raw == "counter" && Find("counter") < 0 ? (Find("replay") >= 0 ? "replay" : "counter_format") : raw;
            var i = Find(name);
            var was = i >= 0 ? cs[i].Value : null;
            if (was == "pass") continue;
            allow = false;
            if (was == "fail") continue;
            var shown = was ?? "absent";
            var cur = was == "unsupported" ? "unsupported" : shown;
            if (i >= 0) cs[i] = new(name, "fail"); else cs.Add(new(name, "fail"));
            rs.Add($"{name}: required check is {cur} (default-deny: not enforced by this resource server)");
        }
        return new EnforcedVerdict(allow, cs, rs);
    }

    /// <summary>Build an authorizer once and call it per operation: the configuration is validated and frozen here (a shallow copy, so later edits of
    /// <paramref name="config"/> do not reach it); an incomplete configuration refuses every call (fail closed, never throws). The per-call
    /// operation and PCActn come from the server, never from the PCActn.</summary>
    public static Func<object?, Operation?, Task<AuthorizeResult>> CreateAuthorizer(AuthorizeInput config)
    {
        var frozen = config.CloneForCall();
        return (pcactn, operation) =>
        {
            var call = frozen.CloneForCall();
            call.Operation = operation;
            return Pca.AuthorizeAsync(pcactn, call);
        };
    }

    /// <summary>A request guard over <see cref="CreateAuthorizer"/>: <paramref name="operation"/> maps a request to the operation it will execute (from the
    /// server's routing; null, or an exception, refuses) and <paramref name="extract"/> reads the presented PCActn (object or header text).</summary>
    public static Func<TReq, Task<AuthorizeResult>> RequireAuthorized<TReq>(AuthorizeInput config, Func<TReq, Operation?> operation, Func<TReq, object?> extract)
    {
        var az = CreateAuthorizer(config);
        return req =>
        {
            Operation? op = null;
            try { op = operation(req); } catch { /* no operation: refused by the authorizer */ }
            object? presented = null;
            try { presented = extract(req); } catch { /* unreadable: refused by the authorizer */ }
            return az(presented, op);
        };
    }

    /// <summary>The server's risk input for a money-moving operation: <c>blastRadius = amount / kappa</c> clamped to [0, 1], from the verified
    /// <c>params[amountField]</c> and the grant's own risk policy. Null without a finite numeric amount or a positive kappa (the verifier then prices
    /// the missing input at the worst case).</summary>
    public static double? AmountRisk(JD grant, JD prms, string amountField = "amount")
    {
        if (prms.GetValueOrDefault(amountField) is not Num a || !double.TryParse(a.Raw, System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out var amount) || !double.IsFinite(amount)) return null;
        var env = Pca.ReadEnvelope(grant);
        if (env?.GetValueOrDefault("risk_policy") is not JD rp || rp.GetValueOrDefault("kappa") is not Num k
            || !double.TryParse(k.Raw, System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out var kappa) || !(kappa > 0)) return null;
        return Math.Min(1, Math.Max(0, amount / kappa));
    }

    /// <summary>Null when <paramref name="a"/> is a usable undo admission <c>{id, window_end, compensation: {verb}}</c>, else the reason: an id of 1 to 128 characters, a
    /// non-negative safe-integer <c>window_end</c> and a compensation with a non-empty <c>verb</c>.</summary>
    public static string? UndoAdmissionError(object? a)
    {
        if (a is not JD m) return "an admission must be an object";
        if (m.GetValueOrDefault("id") is not string { Length: > 0 and <= 128 }) return "admission id must be a non-empty string of at most 128 characters";
        if (!IntentJs.IsNonNeg(m.GetValueOrDefault("window_end"))) return "admission window_end must be a non-negative safe integer";
        if (m.GetValueOrDefault("compensation") is not JD c || c.GetValueOrDefault("verb") is not string { Length: > 0 }) return "admission compensation.verb must be a non-empty string";
        return null;
    }

    /// <summary>The same rule over a typed admission.</summary>
    public static string? UndoAdmissionError(UndoAdmission? a) => a == null
        ? "an admission must be an object"
        : UndoAdmissionError(new JD { ["id"] = a.Id, ["window_end"] = a.WindowEnd, ["compensation"] = new JD { ["verb"] = a.Compensation?.Verb } });

    /// <summary>The ternary decision of a guard result: <c>allow</c> for an ok result, <c>escalate</c> for a refusal that asks the principal, else <c>deny</c> (a refusal without a decision is a deny).</summary>
    public static string DecisionOfResult(bool ok, string? decision) => ok ? "allow" : decision == "escalate" ? "escalate" : "deny";

    /// <summary>The ternary decision of an <see cref="AuthorizeResult"/>.</summary>
    public static string DecisionOfResult(AuthorizeResult r) => DecisionOfResult(r.Allow, r.Decision);

    /// <summary>True for a state store that can claim an action in ONE atomic compare-and-set and raise a monotone pin (the <see cref="IStateStore"/> claim and the
    /// <see cref="IPinStore"/> pin), so it is correct across every process that shares the backend.</summary>
    public static bool IsAtomicStateStore(object? store) => store is IStateStore and IPinStore;

    /// <summary>The escalation answer a request carries: header <c>PCA-Escalation-Answer</c> (strict base64url of the JSON), else the member <c>escalation_answer</c> of a JSON body
    /// (an unparsable body presents none). A header that does not decode or parse throws <see cref="FormatException"/>.</summary>
    public static object? DefaultEscalationAnswer(string? header, string? body)
    {
        if (!string.IsNullOrEmpty(header))
        {
            var text = Pca.DecodePcaHeader(header) ?? throw new FormatException("the PCA-Escalation-Answer header is not canonical base64url");
            return Pca.ParseStrict(text);
        }
        if (string.IsNullOrWhiteSpace(body)) return null;
        try { return Pca.ParseStrict(body) is JD env ? IntentJs.Get(env, "escalation_answer") : null; }
        catch (Exception) { return null; }
    }
}

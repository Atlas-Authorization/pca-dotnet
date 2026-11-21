// The undo-window coordinator (0.5): admission, the durable ledger, the human surface and the real rollback (the reference server/undo).
// The pure record, token, receipts and state machine are in Undo.cs (UndoWindows), the store contract in UndoStore.cs.
//
//   AdmitAsync       ELIGIBILITY. An action gets a veto window only when the policy does not turn windows off, its signed reversibility class is
//                    `reversible`, the engine (the verifier's own CONFIRMED action definitions) returns a plan, and the compensating action is
//                    AUTHORIZED under the original grant (the Policy VM releases it over the original PCActn's verified chain).
//   OpenAsync        writes the record DURABLY before the effect may run (a store that is not durable is refused), signs the `opened` receipt, mints the
//                    one-click undo token and notifies the principal. A window nobody was told about is no window: a failed notification aborts the
//                    record and raises an alert.
//   VetoAsync        a valid token (or an operator, a fraud proof, a revocation policy) inside the window moves open -> vetoed exactly once and starts
//                    the compensation.
//   CompensateAsync  re-decides the compensating action under the grant AS IT STOOD AT ADMISSION, then runs it at most once per attempt through the
//                    operations store and the compensator. Success: compensated, the budget reservation released. Anything
//                    else: compensation_failed, the reservation kept and an alert raised (never silent).
//   FinalizeDueAsync closes the windows whose time is up (open -> finalized) and commits their budget reservations.
//
// Records, plans, grants and PCActns are the parsed JSON tree (Dictionary<string, object?>, Num, ...), exactly as the store holds them.
using System.Globalization;
using System.Net.Http;
using System.Text;
using AtlasPca.Authzen;
using AtlasPca.Js;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca;

/// <summary>The policy of one (operation, grant): <c>Mode</c> always (default) | escalations | off; <c>WindowMs</c> the requested window (clamped); <c>OnRevocation</c> keep (default) | veto.</summary>
public sealed record UndoPolicy(string? Mode = null, object? WindowMs = null, string? OnRevocation = null);

/// <summary>The bounds the coordinator clamps a window into (the minimum is never below 30 s).</summary>
public sealed record UndoWindowBounds(double? MinMs = null, double? MaxMs = null, double? DefaultMs = null);

/// <summary>Where a failure that needs a human goes. Code: compensation_failed | notify_failed | effect_unknown | slash_after_window | budget_settle_failed | revoked_open_window | compensation_denied | veto_relay_failed.</summary>
public sealed record UndoAlert(string Level, string Code, string Record, string Reason);

/// <summary>A notice for the principal. Kind: opened | vetoed | compensated | compensation_failed | finalized | revoked. <c>Record</c> has no pcactn or receipts; <c>Token</c> and <c>Render</c> only on `opened`.</summary>
public sealed record UndoNotice(string Kind, D Record, string? Token = null, D? Render = null);

public sealed record UndoNotifyResult(bool Delivered, string? Reason = null);

public interface IUndoNotifier
{
    /// <summary>Resolves (never throws) with whether at least one of the principal's channels accepted the notice.</summary>
    Task<UndoNotifyResult> NotifyAsync(UndoNotice notice);
}

/// <summary>The source of confirmed reversibility. It must answer from SIGNED, reviewer-confirmed definitions only. A plan is
/// <c>{def_digest, compensation: {verb, params, def_digest, target_param?}, render?, render_digest?}</c>; null = not undoable.</summary>
public interface IUndoEngine
{
    Task<D?> PlanAsync(D operation, string operationId);
}

public static class UndoEngines
{
    sealed class FuncEngine(Func<D, D?> f) : IUndoEngine
    {
        public Task<D?> PlanAsync(D operation, string operationId) => Task.FromResult(f(operation));
    }

    /// <summary>An engine over a synchronous plan function (for example <see cref="ActionsKit.ActionUndoEngine.UndoEngine"/>).</summary>
    public static IUndoEngine From(Func<D, D?> plan) => new FuncEngine(plan);
}

/// <summary>What the compensating-action executor receives.</summary>
public sealed record UndoCompensationCall(D Operation, string IdempotencyKey, string UndoOf, D Record)
{
    public bool HasOriginalResult { get; init; }
    public object? OriginalResult { get; init; }
}

/// <summary>A veto taken by a relay: the principal's token and the time the relay received it (the only thing the relay is trusted for).</summary>
public sealed record UndoRelayedVeto(string Id, object? Token, double At);

public interface IUndoVetoRelay
{
    Task<IReadOnlyList<UndoRelayedVeto>> PendingAsync();
}

/// <summary>Aggregate budgets held during the window: committed on finalize, released on compensation or abort (with the <c>Evidence</c> the caller supplies, none otherwise).</summary>
public sealed record UndoBudget(IBudgetLedger Ledger, Func<D, string, D?>? Evidence = null);

/// <summary>A bond ledger that can slash a bond (the ledger re-verifies the fraud proof itself and refuses outside the challenge window).</summary>
public interface IUndoBonds
{
    Task<object?> SlashBondAsync(D parameters);
}

/// <summary>How a veto is made: with the principal's one-click token, as an authenticated operator, or with a prepared veto (revocation, fraud proof).</summary>
public sealed class UndoVetoBy
{
    internal object? TokenValue { get; private init; }
    internal bool IsToken { get; private init; }
    internal double? At { get; private init; }
    internal string? Operator { get; private init; }
    internal bool IsOperator { get; private init; }
    internal D? Veto { get; private init; }

    /// <summary>The one-click token (the encoded string or the decoded object); <paramref name="at"/> is the relayed veto time.</summary>
    public static UndoVetoBy Token(object? token, double? at = null) => new() { IsToken = true, TokenValue = token, At = at };
    public static UndoVetoBy OperatorId(string op) => new() { IsOperator = true, Operator = op };
    public static UndoVetoBy Prepared(D veto) => new() { Veto = veto };
}

/// <summary>Ok with the record (and whether the veto was a replay), or a refusal code (an UndoTokenCheck code, an UndoTransition code, unknown or malformed).</summary>
public sealed record VetoResult(bool Ok, D? Record = null, bool Replayed = false, string? Code = null, string? Reason = null);

/// <summary>An admission the coordinator granted: pass it to <see cref="UndoCoordinator.OpenAsync"/> before the effect runs.</summary>
public sealed class UndoAdmitted
{
    public string Id { get; init; } = "";
    public long OpenedAt { get; init; }
    public long WindowEnd { get; init; }
    public bool Converted { get; init; }
    public D Plan { get; init; } = new();
    public D Compensation { get; init; } = new();
    public D Pcactn { get; init; } = new();
    public D Grant { get; init; } = new();
    public D Operation { get; init; } = new();

    /// <summary>The admission <see cref="AuthorizeInput.Undo"/> takes.</summary>
    public UndoAdmission ToAdmission() => new(Id, WindowEnd, new UndoCompensationRef((string)Compensation["verb"]!, (string)Compensation["resource"]!));
}

public sealed record UndoAdmitResult(UndoAdmitted? Admission, string? Refused = null);

/// <summary>What an allowed result carries when the action got a window.</summary>
public sealed record UndoWindowInfo(string Id, long WindowEnd, bool Converted, string CompensationVerb, string CompensationResource, string Token, D Obligation);

public sealed class UndoCoordinatorOptions
{
    /// <summary>REQUIRED: the durable undo ledger (Durable = true).</summary>
    public IUndoStore? Store { get; set; }
    /// <summary>REQUIRED: confirmed reversibility and compensations.</summary>
    public IUndoEngine? Engine { get; set; }
    /// <summary>REQUIRED: the undo service key (32-byte Ed25519 seed): signs tokens and receipts.</summary>
    public byte[]? SignerSecret { get; set; }
    /// <summary>REQUIRED: this resource server's audience (bound into the token).</summary>
    public string? Audience { get; set; }
    /// <summary>REQUIRED: the grant by reference, from YOUR store (the same function authorize uses).</summary>
    public Func<string, D, Task<D?>>? ResolveGrant { get; set; }
    /// <summary>REQUIRED: runs a compensating action (your connector). Throw on failure.</summary>
    public Func<UndoCompensationCall, Task<object?>>? Compensate { get; set; }
    /// <summary>REQUIRED: at-most-once records for compensation attempts (shared and durable in production).</summary>
    public IOperationStore? Operations { get; set; }
    /// <summary>REQUIRED: the principal's channels (<see cref="UndoNotifiers.FromDispatcher"/>).</summary>
    public IUndoNotifier? Notifier { get; set; }
    /// <summary>REQUIRED: where a failure that needs a human goes (pager, SIEM). Never silent.</summary>
    public Func<UndoAlert, Task>? Alert { get; set; }
    public Func<D, D, Task<UndoPolicy?>>? Policy { get; set; }
    public UndoWindowBounds? Window { get; set; }
    /// <summary>The value of the compensating action's target parameter. Default: <c>effect.result.id</c> when it is a non-empty string.</summary>
    public Func<D, string?>? ResolveTarget { get; set; }
    public UndoBudget? Budget { get; set; }
    /// <summary>Verifier-side PQ pins forwarded to the compensation decision.</summary>
    public IReadOnlyDictionary<string, string>? PqPins { get; set; }
    /// <summary>A vetoed record whose effect was never reported is compensated anyway after this long (ms). Default 5 minutes.</summary>
    public long EffectTimeoutMs { get; set; } = 5 * 60_000;
    public Func<long>? Now { get; set; }
    /// <summary>Vetoes received somewhere else (the hosted veto endpoint): read before every finalize sweep. A relay that cannot be read finalizes NOTHING.</summary>
    public IUndoVetoRelay? Relay { get; set; }
    /// <summary>TESTS ONLY: accept a store whose Durable is false (every open window is lost on restart).</summary>
    public bool InsecureVolatileStore { get; set; }
}

public sealed class UndoCoordinator
{
    sealed record Applied(D? Record, bool IsApplied, string? Refused, string? Reason)
    {
        public bool IsRefused => Refused != null;
    }

    const int MaxCas = 64;
    /// <summary>With a veto relay, a window is finalized only this long after it ended (a veto in flight at the relay still lands).</summary>
    public const long RelayGraceMs = 60_000;

    readonly UndoCoordinatorOptions _o;
    readonly IUndoStore _store;
    readonly byte[] _secret;
    readonly Func<long> _clock;
    readonly long _effectTimeoutMs;

    /// <summary>The undo service key's public half (base64url), for verifying tokens and receipts elsewhere.</summary>
    public string SignerPublic { get; }

    internal UndoCoordinator(UndoCoordinatorOptions o)
    {
        _o = o;
        _store = o.Store!;
        _secret = (byte[])o.SignerSecret!.Clone();
        _clock = o.Now ?? (() => DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());
        _effectTimeoutMs = o.EffectTimeoutMs;
        SignerPublic = UndoNotifiers.SignerPublic(_secret);
    }

    // ---- plumbing ----
    static string? S(object? r, string k) => IntentJs.Get(r, k) as string;
    static long Ln(object? r, string k) => IntentJs.Lng(IntentJs.Get(r, k));
    static Num N(long v) => IntentJs.OfLong(v);
    static D Ev(string kind, params (string, object?)[] more)
    {
        var d = new D { ["kind"] = kind };
        foreach (var (k, v) in more) d[k] = v;
        return d;
    }

    long Now()
    {
        var t = _clock();
        if (t < -Pca.MaxSafeInt || t > Pca.MaxSafeInt) throw new UndoError("invalid", "the clock returned a non-finite time");
        return t;
    }

    static D Strip(D r)
    {
        var o = new D();
        foreach (var kv in r) if (kv.Key != "pcactn" && kv.Key != "receipts") o[kv.Key] = kv.Value;
        return o;
    }

    async Task AlertAsync(UndoAlert a)
    {
        try { await _o.Alert!(a).ConfigureAwait(false); }
        catch (Exception)
        {
            // an alert sink that throws is itself a failure the operator must see: write it where a host always looks
            Console.Error.WriteLine("pca undo alert (" + a.Code + ") for " + a.Record + ": " + a.Reason);
        }
    }

    async Task<UndoNotifyResult> NotifyAsync(UndoNotice n)
    {
        try
        {
            var r = await _o.Notifier!.NotifyAsync(n).ConfigureAwait(false);
            return r != null && r.Delivered ? new UndoNotifyResult(true) : new UndoNotifyResult(false, r?.Reason ?? "no channel delivered the notice");
        }
        catch (Exception e) { return new UndoNotifyResult(false, string.IsNullOrEmpty(e.Message) ? "notifier error" : e.Message); }
    }

    /// <summary>Apply one event with compare-and-swap retries; returns the stored record and whether this call applied it.</summary>
    async Task<Applied> ApplyAsync(string id, D ev, long? checkAt = null)
    {
        for (var i = 0; i < MaxCas; i++)
        {
            var cur = await _store.GetAsync(id).ConfigureAwait(false);
            if (cur == null) return new Applied(null, false, "unknown", "no undo record " + id);
            var t = Now();
            // a relayed veto is judged as of when the principal made it; its receipt is still written at the current time
            var tr = UndoWindows.Transition(cur, ev, N(checkAt ?? t));
            if (tr.Outcome == "refused") return new Applied(null, false, tr.Code, tr.Reason);
            if (tr.Outcome == "replayed") return new Applied(tr.Record, false, null, null);
            var next = UndoWindows.WithReceipt(tr.Record!, tr.Event!, tr.Note ?? "", t, _secret);
            if (await _store.ReplaceAsync(id, Ln(cur, "ver"), next).ConfigureAwait(false)) return new Applied(next, true, null, null);
        }
        throw new UndoError("conflict_exhausted", "undo record " + id + " kept changing");
    }

    async Task<Applied> MustAsync(string id, D ev)
    {
        var r = await ApplyAsync(id, ev).ConfigureAwait(false);
        if (r.IsRefused) throw new UndoError("invalid", r.Refused + ": " + r.Reason);
        return r;
    }

    async Task SettleBudgetAsync(D rec, string how)
    {
        var b = _o.Budget;
        if (b == null || IntentJs.Get(rec, "budget") is not L list || list.Count == 0) return;
        foreach (D r in list.Cast<D>())
        {
            var key = (string)r["key"]!;
            var rid = (string)r["id"]!;
            try
            {
                BudgetSettleOutcome o;
                if (how == "commit") o = b.Ledger.Commit(key, rid);
                else
                {
                    // no evidence unless the caller supplies it
                    D? ev = b.Evidence?.Invoke(r, how);
                    o = b.Ledger.Release(key, rid, ev);
                }
                if (o.Outcome != "settled" && o.Outcome != "replayed")
                    await AlertAsync(new UndoAlert("warning", "budget_settle_failed", (string)rec["id"]!, how + " of " + key + "/" + rid + ": " + o.Outcome)).ConfigureAwait(false);
            }
            catch (Exception e)
            {
                await AlertAsync(new UndoAlert("warning", "budget_settle_failed", (string)rec["id"]!, how + " of " + key + "/" + rid + ": " + (string.IsNullOrEmpty(e.Message) ? "error" : e.Message))).ConfigureAwait(false);
            }
        }
    }

    async Task<UndoPolicy> PolicyOfAsync(D op, D grant) =>
        _o.Policy != null ? await _o.Policy(op, grant).ConfigureAwait(false) ?? new UndoPolicy() : new UndoPolicy();

    /// <summary>The Policy VM on the compensating action under the original chain, at <paramref name="at"/> (the admission time).</summary>
    (bool Ok, string Reason) CompensationAllowed(D pc, D grant, D op, long at)
    {
        var input = new D { ["grant"] = grant, ["trustedRoot"] = grant, ["chain"] = pc.GetValueOrDefault("cap_chain") };
        if (_o.PqPins != null)
        {
            var pins = new D();
            foreach (var kv in _o.PqPins) pins[kv.Key] = kv.Value;
            input["pqPins"] = pins;
        }
        input["action"] = new D { ["action"] = new D { ["verb"] = op["verb"], ["resource"] = op["resource"], ["params"] = op.GetValueOrDefault("params") ?? new D() } };
        input["risk"] = new D();
        input["budget"] = new D { ["B"] = N(0), ["tau"] = N(at) };
        input["now"] = N(at);
        var d = PolicyVmDecide.Decide(input);
        if (d.GetValueOrDefault("releaseGuardianShare") is true) return (true, "");
        var why = (d.GetValueOrDefault("reasons") as L)?.OfType<string>().FirstOrDefault(r => !r.StartsWith("risk input", StringComparison.Ordinal));
        return (false, why ?? "the grant does not authorize the compensating action");
    }

    // ---- admission ----
    /// <summary>ELIGIBILITY: an admission, or the reason the action gets no window (the normal path: a plain allow stays an allow). Never throws.</summary>
    public async Task<UndoAdmitResult> AdmitAsync(D pcactn, D operation, bool converted, D? grant = null)
    {
        try
        {
            var pc = pcactn;
            var op = operation;
            if (pc == null || op == null || op.GetValueOrDefault("verb") is not string verb || op.GetValueOrDefault("resource") is not string resource) return new UndoAdmitResult(null, "no operation");
            var g = grant ?? await _o.ResolveGrant!(S(pc, "grant_ref")!, pc).ConfigureAwait(false);
            if (g == null) return new UndoAdmitResult(null, "unknown grant");
            var pol = await PolicyOfAsync(op, g).ConfigureAwait(false);
            var mode = pol.Mode ?? "always";
            if (mode == "off") return new UndoAdmitResult(null, "policy: undo windows are off");
            if (mode == "escalations" && !converted) return new UndoAdmitResult(null, "policy: windows only replace approvals");
            // the stricter of the signed class and the definition applies: an agent signing `irreversible` is taken at its word
            var cls = IntentJs.Get(IntentJs.Get(pc, "action"), "reversibility_class");
            if (Pca.ClassRank(cls) != 0) return new UndoAdmitResult(null, "the signed class is " + (IntentJs.Own(IntentJs.Get(pc, "action"), "reversibility_class") ? JsJson.ToJsString(cls) : "undefined"));
            var id = Pca.HashCanonical(pc);
            var plan = await _o.Engine!.PlanAsync(op, id).ConfigureAwait(false);
            if (plan == null) return new UndoAdmitResult(null, "not confirmed reversible, or no confirmed compensating action");
            var pcomp = (D)plan["compensation"]!;
            var comp = new D
            {
                ["verb"] = pcomp["verb"], ["resource"] = resource, ["params"] = IntentJs.Normalize(pcomp["params"]), ["undo_of"] = id, ["def_digest"] = pcomp["def_digest"],
            };
            if (pcomp.TryGetValue("target_param", out var tp) && tp != null) comp["target_param"] = tp;
            var t = Now();
            var allowed = CompensationAllowed(pc, g, new D { ["verb"] = comp["verb"], ["resource"] = comp["resource"], ["params"] = comp["params"] }, t);
            if (!allowed.Ok) return new UndoAdmitResult(null, "the compensating action is not authorized under the grant: " + allowed.Reason);
            var windowMs = UndoWindows.ResolveWindow(pol.WindowMs, _o.Window?.MinMs, _o.Window?.MaxMs, _o.Window?.DefaultMs);
            return new UndoAdmitResult(new UndoAdmitted
            {
                Id = id, OpenedAt = t, WindowEnd = t + windowMs, Converted = converted, Plan = plan, Compensation = comp, Pcactn = pc, Grant = g,
                Operation = new D { ["verb"] = verb, ["resource"] = resource, ["params"] = IntentJs.Normalize(op.GetValueOrDefault("params") ?? new D()) },
            });
        }
        catch (Exception e) { return new UndoAdmitResult(null, "undo admission error (fail closed): " + (string.IsNullOrEmpty(e.Message) ? "unknown" : e.Message)); }
    }

    UndoWindowInfo InfoOf(D rec)
    {
        var comp = (D)rec["compensation"]!;
        return new UndoWindowInfo(
            (string)rec["id"]!, Ln(rec, "window_end"), rec["converted"] is true, (string)comp["verb"]!, (string)comp["resource"]!,
            UndoWindows.EncodeToken(UndoWindows.SignToken(rec, _secret)),
            new D { ["kind"] = "undo_window", ["params"] = new D { ["id"] = rec["id"], ["window_end"] = rec["window_end"] }, ["due"] = rec["window_end"] });
    }

    /// <summary>Write the record durably, sign the `opened` receipt, mint the one-click token and tell the principal. <paramref name="bondRef"/> and
    /// <paramref name="bondChallengeEndsAt"/> bind the window to a bond (the window then lasts at least until the challenge window ends).</summary>
    public async Task<UndoWindowInfo> OpenAsync(UndoAdmitted adm, string? bondRef = null, double? bondChallengeEndsAt = null)
    {
        var chain = (L)adm.Pcactn["cap_chain"]!;
        var windowEnd = bondRef != null && bondChallengeEndsAt != null ? Math.Max(adm.WindowEnd, (long)Math.Floor(bondChallengeEndsAt.Value)) : adm.WindowEnd;
        var cdig = UndoWindows.CompensationDigest(adm.Compensation);
        var b = new D
        {
            ["v"] = N(1), ["id"] = adm.Id, ["aud"] = _o.Audience, ["grant_ref"] = adm.Pcactn["grant_ref"], ["holder"] = ((D)chain[^1]!)["holder"],
            ["principal"] = adm.Grant["issuer"],
            ["action"] = new D { ["verb"] = adm.Operation["verb"], ["resource"] = adm.Operation["resource"], ["params_digest"] = ((D)adm.Pcactn["action"]!)["params_digest"], ["def_digest"] = adm.Plan["def_digest"] },
            ["compensation"] = adm.Compensation, ["compensation_digest"] = cdig,
        };
        if (adm.Plan.TryGetValue("render_digest", out var rd) && rd != null) b["render_digest"] = rd;
        b["opened_at"] = N(adm.OpenedAt);
        b["window_end"] = N(windowEnd);
        b["converted"] = adm.Converted;
        b["state"] = "open";
        b["ver"] = N(0);
        b["pcactn"] = Pca.Canonicalize(adm.Pcactn);
        if (bondRef != null) b["bond_ref"] = bondRef;
        b["attempt"] = N(0);
        b["receipts"] = new L();
        var rec = UndoWindows.WithReceipt(b, "opened", adm.Converted ? "converted" : "", adm.OpenedAt, _secret);
        var c = await _store.CreateAsync(rec).ConfigureAwait(false);
        if (!c.Created)
        {
            // a retry of the same admission returns the same window; anything else is a different action under the same id
            if (S(c.Record, "compensation_digest") != cdig || S(c.Record, "state") != "open")
                throw new UndoError("invalid", "undo record " + adm.Id + " already exists with other terms or state " + S(c.Record, "state"));
            return InfoOf(c.Record!);
        }
        var info = InfoOf(rec);
        var n = await NotifyAsync(new UndoNotice("opened", Strip(rec), info.Token, adm.Plan.GetValueOrDefault("render") as D)).ConfigureAwait(false);
        if (!n.Delivered)
        {
            await ApplyAsync((string)rec["id"]!, Ev("abort", ("reason", "notify_failed"))).ConfigureAwait(false);
            await AlertAsync(new UndoAlert("critical", "notify_failed", (string)rec["id"]!, "the principal could not be told about the undo window: " + (n.Reason ?? "not delivered"))).ConfigureAwait(false);
            throw new UndoError("invalid", "notify_failed: the undo window could not be announced (" + (n.Reason ?? "not delivered") + ")");
        }
        return info;
    }

    public Task<D?> GetAsync(string id) => _store.GetAsync(id);

    /// <summary>Hold aggregate budget reservations (<c>[{key, id}]</c>) until the window closes.</summary>
    public async Task<D> HoldBudgetAsync(string id, IEnumerable<(string Key, string Id)> reservations)
    {
        var add = reservations.Select(r => (object?)new D { ["key"] = r.Key, ["id"] = r.Id }).ToList();
        for (var i = 0; i < MaxCas; i++)
        {
            var cur = await _store.GetAsync(id).ConfigureAwait(false);
            if (cur == null) throw new UndoError("invalid", "no undo record " + id);
            var state = S(cur, "state");
            if (state != "open" && state != "vetoed") throw new UndoError("invalid", "a " + state + " record holds no budget");
            var next = new D(cur) { ["budget"] = new L((IntentJs.Get(cur, "budget") as L ?? new L()).Concat(add)), ["ver"] = N(Ln(cur, "ver") + 1) };
            if (await _store.ReplaceAsync(id, Ln(cur, "ver"), next).ConfigureAwait(false)) return next;
        }
        throw new UndoError("conflict_exhausted", "undo record " + id + " kept changing");
    }

    /// <summary>Report the original effect (its result names the compensation target). A veto that arrived while it ran is acted on now.</summary>
    public async Task<D> RecordEffectAsync(string id, object? result = null, bool hasResult = false)
    {
        var ev = Ev("effect");
        if (hasResult || result != null) ev["result"] = result;
        var r = await MustAsync(id, ev).ConfigureAwait(false);
        return S(r.Record, "state") == "vetoed" ? await RunCompensationAsync(r.Record!).ConfigureAwait(false) : r.Record!;
    }

    /// <summary>The effect did not run (or failed): nothing to undo; held budget is released.</summary>
    public async Task<D> AbortAsync(string id, string reason)
    {
        var r = await MustAsync(id, Ev("abort", ("reason", reason))).ConfigureAwait(false);
        if (r.IsApplied) await SettleBudgetAsync(r.Record!, "effect_not_run").ConfigureAwait(false);
        return r.Record!;
    }

    async Task<D> FinishCompensatedAsync(D rec)
    {
        if (S(rec, "state") == "compensated")
        {
            await SettleBudgetAsync(rec, "rollback").ConfigureAwait(false);
            await NotifyAsync(new UndoNotice("compensated", Strip(rec))).ConfigureAwait(false);
        }
        return rec;
    }

    async Task<D> RunCompensationAsync(D rec0)
    {
        var rec = rec0;
        if (S(rec, "state") != "vetoed") return rec;
        var t = Now();
        var id = (string)rec["id"]!;
        if (!rec.ContainsKey("effect") && t - (IntentJs.Get(rec, "veto") is D v0 && v0.ContainsKey("at") ? Ln(v0, "at") : t) < _effectTimeoutMs) return rec; // wait for the effect report (RecordEffectAsync resumes)
        var pc = DecodePcactn((string)rec["pcactn"]!);
        var grant = await _o.ResolveGrant!(S(rec, "grant_ref")!, pc).ConfigureAwait(false);

        async Task<D> Fail(string reason, string code = "compensation_failed")
        {
            var r = await ApplyAsync(id, Ev("compensation_failed", ("reason", reason))).ConfigureAwait(false);
            var o = r.IsRefused ? (await _store.GetAsync(id).ConfigureAwait(false) ?? rec) : r.Record!;
            if (!r.IsRefused && r.IsApplied)
            {
                await AlertAsync(new UndoAlert("critical", code, id, reason)).ConfigureAwait(false);
                await NotifyAsync(new UndoNotice("compensation_failed", Strip(o))).ConfigureAwait(false);
            }
            return o;
        }

        if (grant == null) return await Fail("the grant is no longer known: the compensation cannot be authorized", "compensation_denied").ConfigureAwait(false);
        var comp = (D)rec["compensation"]!;
        var prms = new D((D)comp["params"]!);
        if (comp.TryGetValue("target_param", out var tpo) && tpo is string tp)
        {
            string? target;
            if (_o.ResolveTarget != null) target = _o.ResolveTarget(rec);
            else
            {
                var res = IntentJs.Get(IntentJs.Get(rec, "effect"), "result");
                target = res is D rd && rd.GetValueOrDefault("id") is string rid && rid.Length > 0 ? rid : null;
            }
            if (target == null) return await Fail("the target '" + tp + "' of the compensation is unknown (no effect result names it)").ConfigureAwait(false);
            prms[tp] = target;
        }
        var op = new D { ["verb"] = comp["verb"], ["resource"] = comp["resource"], ["params"] = prms };
        var dec = CompensationAllowed(pc, grant, op, Ln(rec, "opened_at"));
        if (!dec.Ok) return await Fail("the compensating action is not authorized under the grant: " + dec.Reason, "compensation_denied").ConfigureAwait(false);
        var ops = _o.Operations!;
        // at most once per attempt: the operation record is created before the compensator runs
        var opId = Pca.HashCanonical(new D { ["d"] = "atlas-pca/undo-compensation-op/v1", ["record"] = id, ["attempt"] = rec["attempt"] });
        var orec = new OperationRecord(opId, OperationStates.Pending, (string)op["verb"]!, (string)op["resource"]!, Pca.HashCanonical(prms), "irreversible", t);
        var claimed = ops.Create(orec);
        if (!claimed.Created)
        {
            var prev = claimed.Existing!;
            if (prev.State == OperationStates.Committed)
            {
                var ev = Ev("compensated");
                if (prev.Result != null) ev["result"] = prev.Result;
                var r = await ApplyAsync(id, ev).ConfigureAwait(false);
                rec = r.IsRefused ? rec : r.Record!;
                return await FinishCompensatedAsync(rec).ConfigureAwait(false);
            }
            if (prev.State is OperationStates.Failed or OperationStates.Uncertain)
                return await Fail("compensation attempt " + JsJson.ToJsString(rec["attempt"]) + " " + prev.State + ": " + (prev.Error ?? "")).ConfigureAwait(false);
            if (prev.State == OperationStates.Aborted)
            {
                var r = await ApplyAsync(id, Ev("compensation_failed", ("reason", "attempt never started"))).ConfigureAwait(false);
                if (r.IsRefused) return rec;
                var again = await ApplyAsync(id, Ev("retry")).ConfigureAwait(false);
                return again.IsRefused ? r.Record! : await RunCompensationAsync(again.Record!).ConfigureAwait(false);
            }
            // pending / executing: another worker holds it, or a crash; stale ones are settled by recover()
            if (t - (prev.ExecutingAt ?? prev.StartedAt) > _effectTimeoutMs)
            {
                var settled = prev.State == OperationStates.Pending
                    ? prev with { State = OperationStates.Aborted, Error = "never started", FinishedAt = t }
                    : prev with { State = OperationStates.Uncertain, Error = "no outcome recorded: the compensation may or may not have run", FinishedAt = t };
                ops.Transition(prev.Id, prev.State, settled);
                return await RunCompensationAsync(await _store.GetAsync(id).ConfigureAwait(false) ?? rec).ConfigureAwait(false);
            }
            return rec;
        }
        // re-read under the record: a concurrent retry or resolution wins
        var cur = await _store.GetAsync(id).ConfigureAwait(false);
        if (cur == null || S(cur, "state") != "vetoed" || !Equals(JsJson.ToJsString(cur["attempt"]), JsJson.ToJsString(rec["attempt"])))
        {
            ops.Transition(opId, OperationStates.Pending, orec with { State = OperationStates.Aborted, Error = "the undo record moved on", FinishedAt = Now() });
            return cur ?? rec;
        }
        var running = orec with { State = OperationStates.Executing, ExecutingAt = Now() };
        if (!ops.Transition(opId, OperationStates.Pending, running)) return await _store.GetAsync(id).ConfigureAwait(false) ?? rec;
        var recNoPc = new D();
        foreach (var kv in cur) if (kv.Key != "pcactn") recNoPc[kv.Key] = kv.Value;
        var effRes = IntentJs.Get(rec, "effect") is D eff && eff.ContainsKey("result") ? eff["result"] : null;
        var call = new UndoCompensationCall(op, opId, id, recNoPc) { HasOriginalResult = effRes != null, OriginalResult = effRes };
        object? result;
        try { result = await _o.Compensate!(call).ConfigureAwait(false); }
        catch (Exception e)
        {
            var error = e.Message;
            try { ops.Transition(opId, OperationStates.Executing, running with { State = OperationStates.Failed, Error = error, FinishedAt = Now() }); } catch (Exception) { /* best effort */ }
            return await Fail("the compensating action failed: " + error).ConfigureAwait(false);
        }
        try { ops.Transition(opId, OperationStates.Executing, running with { State = OperationStates.Committed, Result = result, FinishedAt = Now() }); } catch (Exception) { /* best effort */ }
        var cev = Ev("compensated");
        if (result != null) cev["result"] = result;
        var done = await ApplyAsync(id, cev).ConfigureAwait(false);
        if (done.IsRefused) return await _store.GetAsync(id).ConfigureAwait(false) ?? rec;
        return await FinishCompensatedAsync(done.Record!).ConfigureAwait(false);
    }

    static D DecodePcactn(string text)
    {
        if (Encoding.UTF8.GetByteCount(text) > Pca.MaxArtifactBytes) throw new ArgumentOutOfRangeException(nameof(text), Pca.ArtifactSizeReason);
        return Pca.ParseStrict(text) as D ?? throw new ArgumentException("decodePCActn: not an object");
    }

    // ---- veto ----
    /// <summary>Veto with the one-click token (the principal), as an authenticated operator of this server, or with a prepared veto. Never throws.</summary>
    public async Task<VetoResult> VetoAsync(string id, UndoVetoBy by)
    {
        try
        {
            var cur = await _store.GetAsync(id).ConfigureAwait(false);
            if (cur == null) return new VetoResult(false, Code: "unknown", Reason: "no undo record " + id);
            D v;
            var t = Now();
            long? checkAt = null;
            if (by.IsToken)
            {
                if (by.At is double at)
                {
                    if (!double.IsFinite(at) || Math.Floor(at) != at || Math.Abs(at) > Pca.MaxSafeInt || (at == 0 && double.IsNegative(at)) || at > t || at < Ln(cur, "opened_at"))
                        return new VetoResult(false, Code: "malformed", Reason: "a relayed veto time must lie between the opening of the window and now");
                    t = (long)at;
                    checkAt = t;
                }
                var tok = by.TokenValue is string s ? UndoWindows.DecodeToken(s) : by.TokenValue;
                var chk = UndoWindows.TokenCheck(tok, SignerPublic, cur, N(t));
                if (chk != "ok") return new VetoResult(false, Code: chk, Reason: "the undo token was refused (" + chk + ")");
                v = new D { ["at"] = N(t), ["via"] = "token", ["by"] = cur["principal"], ["evidence"] = UndoWindows.TokenDigest((D)tok!) };
            }
            else if (by.IsOperator)
            {
                if (string.IsNullOrEmpty(by.Operator)) return new VetoResult(false, Code: "malformed", Reason: "an operator veto names the operator");
                v = new D { ["at"] = N(t), ["via"] = "operator", ["by"] = by.Operator };
            }
            else
            {
                v = new D(by.Veto ?? new D()) { ["at"] = N(t) };
            }
            var r = await ApplyAsync(id, Ev("veto", ("veto", v)), checkAt).ConfigureAwait(false);
            if (r.IsRefused) return new VetoResult(false, Code: r.Refused, Reason: r.Reason);
            if (r.IsApplied) await NotifyAsync(new UndoNotice("vetoed", Strip(r.Record!))).ConfigureAwait(false);
            var done = await RunCompensationAsync(r.Record!).ConfigureAwait(false);
            return new VetoResult(true, done, !r.IsApplied);
        }
        catch (Exception e) { return new VetoResult(false, Code: "malformed", Reason: "veto error (fail closed): " + (string.IsNullOrEmpty(e.Message) ? "unknown" : e.Message)); }
    }

    /// <summary>Apply the relay's pending vetoes now (also done by every <see cref="FinalizeDueAsync"/>). Throws when the relay cannot be read.</summary>
    public async Task<List<VetoResult>> SyncRelayAsync()
    {
        var res = new List<VetoResult>();
        if (_o.Relay == null) return res;
        var list = await _o.Relay.PendingAsync().ConfigureAwait(false);
        if (list == null) throw new UndoError("invalid", "the veto relay returned no list");
        foreach (var x in list)
        {
            if (x == null || x.Id == null) continue;
            // a forged or late relay entry is refused by the same checks as any veto
            res.Add(await VetoAsync(x.Id, UndoVetoBy.Token(x.Token, x.At)).ConfigureAwait(false));
        }
        return res;
    }

    public async Task<D> CompensateAsync(string id)
    {
        var cur = await _store.GetAsync(id).ConfigureAwait(false) ?? throw new UndoError("invalid", "no undo record " + id);
        return await RunCompensationAsync(cur).ConfigureAwait(false);
    }

    public async Task<D> RetryAsync(string id)
    {
        var r = await MustAsync(id, Ev("retry")).ConfigureAwait(false);
        return await RunCompensationAsync(r.Record!).ConfigureAwait(false);
    }

    /// <summary>Close the windows whose time is up (open -> finalized) and commit their budget reservations; returns the finalized ids.</summary>
    public async Task<List<string>> FinalizeDueAsync()
    {
        var res = new List<string>();
        try { await SyncRelayAsync().ConfigureAwait(false); }
        catch (Exception e)
        {
            // a veto may be waiting at the relay: closing any window now could finalize an action the principal undid
            await AlertAsync(new UndoAlert("critical", "veto_relay_failed", "*", "the veto relay could not be read; no window was finalized: " + (string.IsNullOrEmpty(e.Message) ? "error" : e.Message))).ConfigureAwait(false);
            return res;
        }
        // with a relay, a veto accepted there just before the window closed may still be in flight: wait out a grace period
        foreach (var rec in await _store.ListAsync(new UndoQuery("open", WindowEndedBy: Now() - 1 - (_o.Relay != null ? RelayGraceMs : 0))).ConfigureAwait(false))
        {
            var id = (string)rec["id"]!;
            var r = await ApplyAsync(id, Ev("finalize")).ConfigureAwait(false);
            if (r.IsRefused || !r.IsApplied) continue;
            res.Add(id);
            if (!r.Record!.ContainsKey("effect"))
                await AlertAsync(new UndoAlert("warning", "effect_unknown", id, "the window closed without an effect report: reconcile the original operation")).ConfigureAwait(false);
            await SettleBudgetAsync(r.Record!, "commit").ConfigureAwait(false);
            await NotifyAsync(new UndoNotice("finalized", Strip(r.Record!))).ConfigureAwait(false);
        }
        return res;
    }

    /// <summary>After a restart: resume every vetoed record's compensation, then finalize what is due.</summary>
    public async Task<List<string>> RecoverAsync()
    {
        var res = new List<string>();
        foreach (var rec in await _store.ListAsync(new UndoQuery("vetoed")).ConfigureAwait(false))
        {
            var r = await RunCompensationAsync(rec).ConfigureAwait(false);
            if (S(r, "state") != "vetoed") res.Add((string)rec["id"]!);
        }
        res.AddRange(await FinalizeDueAsync().ConfigureAwait(false));
        return res;
    }

    /// <summary>A grant was revoked: veto its open windows when the policy says so, else alert and tell the principal.</summary>
    public async Task<List<string>> OnRevocationAsync(string grantRef)
    {
        var res = new List<string>();
        foreach (var rec in await _store.ListAsync(new UndoQuery("open", GrantRef: grantRef)).ConfigureAwait(false))
        {
            var id = (string)rec["id"]!;
            var pc = DecodePcactn((string)rec["pcactn"]!);
            var grant = await _o.ResolveGrant!(S(rec, "grant_ref")!, pc).ConfigureAwait(false);
            var act = (D)rec["action"]!;
            var pol = grant != null ? await PolicyOfAsync(new D { ["verb"] = act["verb"], ["resource"] = act["resource"] }, grant).ConfigureAwait(false) : new UndoPolicy();
            if ((pol.OnRevocation ?? "keep") == "veto")
            {
                var v = await VetoAsync(id, UndoVetoBy.Prepared(new D { ["at"] = N(0), ["via"] = "revocation", ["by"] = grantRef })).ConfigureAwait(false);
                if (v.Ok) res.Add(id);
            }
            else
            {
                await AlertAsync(new UndoAlert("warning", "revoked_open_window", id, "grant " + grantRef + " was revoked while this window is open; the principal can still undo it")).ConfigureAwait(false);
                await NotifyAsync(new UndoNotice("revoked", Strip(rec))).ConfigureAwait(false);
            }
        }
        return res;
    }

    /// <summary>Slash a bond (the ledger re-verifies the fraud proof itself and refuses outside the challenge window), then undo the record. <paramref name="parameters"/> carries <c>claimId</c>.</summary>
    public async Task<(object? Settlement, VetoResult Veto)> RollbackOnSlashAsync(IUndoBonds bonds, D parameters)
    {
        var settlement = await bonds.SlashBondAsync(parameters).ConfigureAwait(false);
        var evidence = Pca.HashCanonical(new D { ["d"] = "atlas-pca/undo-slash-ref/v1", ["settlement"] = settlement });
        var claim = (string)parameters["claimId"]!;
        var recs = await _store.ListAsync(new UndoQuery("open", BondRef: claim)).ConfigureAwait(false);
        var target = recs.Count > 0 ? recs[0] : await _store.GetAsync(claim).ConfigureAwait(false);
        if (target == null) return (settlement, new VetoResult(false, Code: "unknown", Reason: "no undo record for bond " + claim));
        var v = await VetoAsync((string)target["id"]!, UndoVetoBy.Prepared(new D { ["at"] = N(0), ["via"] = "fraud_proof", ["by"] = claim, ["evidence"] = evidence })).ConfigureAwait(false);
        if (!v.Ok) await AlertAsync(new UndoAlert("critical", "slash_after_window", (string)target["id"]!, "the bond was slashed but the effect could not be rolled back: " + v.Reason)).ConfigureAwait(false);
        return (settlement, v);
    }
}

/// <summary>The undo notifier over the approval channels, the hosted veto relay and the small helpers of the server undo module.</summary>
public static class UndoNotifiers
{
    sealed class DispatcherNotifier(ApprovalDispatcher dispatcher, Func<string, string, string> undoUrl, string? inboxUrl) : IUndoNotifier
    {
        public async Task<UndoNotifyResult> NotifyAsync(UndoNotice n)
        {
            var r = n.Record;
            var act = (D)r["action"]!;
            var until = DateTimeOffset.FromUnixTimeMilliseconds(IntentJs.Lng(r["window_end"])).UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", CultureInfo.InvariantCulture);
            var what = JsJson.ToJsString(act["verb"]) + " on " + JsJson.ToJsString(act["resource"]);
            var reason = n.Kind switch
            {
                "opened" => "Already done: " + what + ". You can undo it until " + until + ".",
                "vetoed" => "Undo started for " + what + ".",
                "compensated" => "Undone: " + what + ".",
                "compensation_failed" => "UNDO FAILED for " + what + ": " + (IntentJs.Get(IntentJs.Get(r, "outcome"), "reason") is string orr ? orr : "unknown") + ". An operator has been alerted.",
                "revoked" => "The agent's grant was revoked. " + what + " can still be undone until " + until + ".",
                _ => "Final: " + what + " can no longer be undone.",
            };
            var comp = (D)r["compensation"]!;
            var req = new D
            {
                ["id"] = "undo:" + JsJson.ToJsString(r["id"]) + ":" + n.Kind, ["verb"] = act["verb"], ["resource"] = act["resource"], ["tier"] = IntentJs.OfLong(3), ["reason"] = reason, ["goalCommit"] = "",
                ["lineage"] = new D
                {
                    ["goalCommit"] = "", ["goalVerified"] = false,
                    ["chain"] = new L { new D { ["kind"] = "action", ["label"] = JsJson.ToJsString(act["verb"]) + " " + JsJson.ToJsString(act["resource"]), ["detail"] = "undo: " + JsJson.ToJsString(comp["verb"]) } },
                    ["because"] = reason,
                },
                ["r"] = IntentJs.OfLong(0), ["requestedAt"] = r["opened_at"],
            };
            if (n.Render != null && r.GetValueOrDefault("render_digest") != null) { req["render"] = n.Render; req["renderDigest"] = r["render_digest"]; }
            var link = n.Kind == "opened" && n.Token != null ? undoUrl(n.Token, (string)r["id"]!) : inboxUrl;
            var outc = await dispatcher.NotifyAllAsync(req, link != null ? new ApprovalNotifyContext(link) : null).ConfigureAwait(false);
            if (outc.Any(d => d.Delivered)) return new UndoNotifyResult(true);
            return new UndoNotifyResult(false, outc.Count == 0 ? "no enabled channel" : string.Join("; ", outc.Select(d => d.Kind + ": " + (d.Reason ?? "not delivered"))));
        }
    }

    /// <summary>An undo notifier over the existing approval channels (Slack, webhook, email, SMS, push). The notice becomes a step-up-shaped message
    /// whose link is the one-click undo URL (<paramref name="undoUrl"/>(token, record id)) and whose render is the WYSIWYS render of the action.</summary>
    public static IUndoNotifier FromDispatcher(ApprovalDispatcher dispatcher, Func<string, string, string> undoUrl, string? inboxUrl = null) => new DispatcherNotifier(dispatcher, undoUrl, inboxUrl);

    /// <summary>The undo service key's public half (base64url), for verifying tokens and receipts elsewhere (e.g. the hosted veto route).</summary>
    public static string SignerPublic(byte[] secret)
    {
        using var k = EdKey.FromSeed(secret);
        return k.Id;
    }

    /// <summary>The names of the required coordinator components that are absent or malformed (the reference's missingUndoComponents).</summary>
    public static List<string> Missing(UndoCoordinatorOptions? o)
    {
        var x = o ?? new UndoCoordinatorOptions();
        var m = new List<string>();
        if (!UndoStores.IsUndoStore(x.Store)) m.Add("store");
        if (x.Engine == null) m.Add("engine");
        if (x.SignerSecret is not { Length: 32 }) m.Add("signerSecret");
        if (string.IsNullOrEmpty(x.Audience)) m.Add("audience");
        if (x.ResolveGrant == null) m.Add("resolveGrant");
        if (x.Compensate == null) m.Add("compensate");
        if (x.Operations == null) m.Add("operations");
        if (x.Notifier == null) m.Add("notifier");
        if (x.Alert == null) m.Add("alert");
        return m;
    }

    /// <summary>The transport of <see cref="HostedVetoRelay"/>: GET a URL with headers.</summary>
    public delegate Task<UndoRelayResponse> UndoRelayFetch(string url, IReadOnlyDictionary<string, string> headers);

    public sealed record UndoRelayResponse(bool Ok, int Status, Func<Task<object?>> Json);

    sealed class HostedRelay(string baseUrl, string secretKey, UndoRelayFetch? fetch, int limit) : IUndoVetoRelay
    {
        static readonly HttpClient Http = new();

        static async Task<UndoRelayResponse> Default(string url, IReadOnlyDictionary<string, string> headers)
        {
            using var req = new HttpRequestMessage(HttpMethod.Get, url);
            foreach (var kv in headers) req.Headers.TryAddWithoutValidation(kv.Key, kv.Value);
            using var res = await Http.SendAsync(req).ConfigureAwait(false);
            var text = await res.Content.ReadAsStringAsync().ConfigureAwait(false);
            return new UndoRelayResponse(res.IsSuccessStatusCode, (int)res.StatusCode, () => Task.FromResult(Pca.ParseJson(text)));
        }

        public async Task<IReadOnlyList<UndoRelayedVeto>> PendingAsync()
        {
            var f = fetch ?? Default;
            var res = await f(baseUrl + "/v1/pca/undo/vetoes?limit=" + Math.Min(200, Math.Max(1, limit)).ToString(CultureInfo.InvariantCulture),
                new Dictionary<string, string> { ["authorization"] = "Bearer " + secretKey, ["accept"] = "application/json" }).ConfigureAwait(false);
            if (!res.Ok) throw new UndoError("invalid", "the veto relay answered " + res.Status.ToString(CultureInfo.InvariantCulture));
            var body = await res.Json().ConfigureAwait(false);
            if (body is not D bd || bd.GetValueOrDefault("data") is not L data) throw new UndoError("invalid", "the veto relay answered without a data list");
            var outl = new List<UndoRelayedVeto>();
            foreach (var row in data)
            {
                var v = IntentJs.Get(row, "veto");
                if (IntentJs.Get(row, "record_id") is not string rid || IntentJs.Get(v, "token") is not string token || IntentJs.NumOf(IntentJs.Get(v, "at")) is not double at)
                    throw new UndoError("invalid", "the veto relay answered a malformed entry");
                outl.Add(new UndoRelayedVeto(rid, token, at));
            }
            return outl;
        }
    }

    /// <summary>The relay over a hosted undo ledger: <c>GET {baseUrl}/v1/pca/undo/vetoes</c> with the instance secret key. A non-2xx answer or a malformed
    /// body throws (and so finalizes nothing). <paramref name="fetch"/> defaults to an HttpClient.</summary>
    public static IUndoVetoRelay HostedVetoRelay(string baseUrl, string secretKey, UndoRelayFetch? fetch = null, int limit = 200) =>
        new HostedRelay(baseUrl.TrimEnd('/'), secretKey, fetch, limit);
}

public static partial class Pca
{
    /// <summary>Build the coordinator. Throws <c>config</c> for a missing component and <c>not_durable</c> for a volatile store (fail closed).</summary>
    public static UndoCoordinator CreateUndoCoordinator(UndoCoordinatorOptions opts)
    {
        var missing = UndoNotifiers.Missing(opts);
        if (missing.Count > 0) throw new UndoError("config", "undo coordinator: missing required component(s): " + string.Join(", ", missing));
        if (!opts.Store!.Durable && !opts.InsecureVolatileStore) throw new UndoError("not_durable", "an undo ledger must be durable: a restart would lose every open window and its compensation");
        return new UndoCoordinator(opts);
    }

    /// <summary>The window the coordinator waits before it finalizes a window that a veto relay may still hold a veto for.</summary>
    public const long UndoRelayGraceMs = UndoCoordinator.RelayGraceMs;

    /// <summary>Execute an allowed result that carries an undo window, then report the effect: a committed effect is recorded (its result names the compensation
    /// target), an effect that failed or never started aborts the window (nothing to undo; held budget released); pending or uncertain leaves it running.</summary>
    public static async Task<D> ReportUndoEffect(UndoCoordinator undo, string id, string status, object? result = null, bool hasResult = false)
    {
        if (status == "committed") return await undo.RecordEffectAsync(id, result, hasResult).ConfigureAwait(false);
        if (status is "failed" or "aborted" or "refused") return await undo.AbortAsync(id, "effect_" + status).ConfigureAwait(false);
        return await undo.GetAsync(id).ConfigureAwait(false) ?? throw new UndoError("invalid", "no undo record " + id);
    }

    /// <summary>Default provenance-bundle extraction: header <c>PCA-Provenance</c> (strict base64url JSON), else body member <c>pca_provenance</c>. Malformed header text throws.</summary>
    public static object? DefaultProvenanceBundle(Func<string, string?> header, object? body)
    {
        var h = header("pca-provenance");
        if (!string.IsNullOrEmpty(h))
        {
            var decoded = DecodePcaHeader(h) ?? throw new FormatException("the PCA-Provenance header is not strict base64url");
            return ParseStrict(decoded);
        }
        if (body is string text)
        {
            try { body = ParseStrict(text); }
            catch (Exception) { return null; }
        }
        return body is D m && m.TryGetValue("pca_provenance", out var p) ? p : null;
    }
}

using AtlasPca.Js;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca;

/// <summary>One reservation made by an admission.</summary>
public sealed record BudgetReservation(string Key, string Id);

/// <summary>The outcome of <see cref="Budgets.AdmitAggregateAction"/>.</summary>
public sealed class BudgetAdmission
{
    public bool Admitted;
    public string? Reason;
    /// <summary>The host verifier's verdict (a map with at least <c>allow</c>); may be null on a refusal.</summary>
    public D? Verdict;
    public List<BudgetReservation>? Reservations;
    public D? State;
}

/// <summary>The scoped-admission and signed-release side of the aggregate <see cref="IBudgetLedger"/>: scope keys, <see cref="AdmitAggregateAction"/>,
/// <see cref="StartAggregate"/> / <see cref="SettleAggregate"/>, and signed releases that can be anchored in an <see cref="ILedgerStore"/>.
///
/// A release is a signed statement by the releaser (the verifier or sequencer) that a reservation's effect did NOT happen; a release that never arrives only
/// over-restricts (a crash costs budget, never safety).</summary>
public static class Budgets
{
    public const string ReleaseDomain = "atlas-pca/budget-release/v1\0";
    static readonly string[] ReleaseReasons = { "effect_failed", "effect_not_run", "denied_downstream", "rollback" };

    /// <summary>The ledger key of a scope (<c>principal</c>, <c>org</c>, <c>fleet</c>) and its id; injective (the id is percent-encoded).</summary>
    public static string ScopeKey(string scope, string id)
    {
        if (!BudgetDoc.IdOk(id)) throw new BudgetLedgerError("invalid", "a scope id is a non-empty string of at most 256 characters without control characters");
        return scope + "/" + JsJson.EncodeUriComponent(id);
    }

    // ---- signed, anchored releases ----

    static byte[] ReleaseMessage(D r)
    {
        var body = new D();
        foreach (var k in new[] { "v", "key", "id", "reason", "at", "signer" }) body[k] = r.GetValueOrDefault(k);
        return Pca.Concat(IntentJs.Utf8(ReleaseDomain), IntentJs.CanonBytes(body));
    }

    /// <summary>Sign a release of <paramref name="key"/>/<paramref name="id"/>: reason is one of effect_failed, effect_not_run, denied_downstream, rollback.</summary>
    public static D SignRelease(string key, string id, string reason, long at, EdKey secret)
    {
        if (!ReleaseReasons.Contains(reason) || at < -9007199254740991L || at > 9007199254740991L || !BudgetDoc.IdOk(key) || !BudgetDoc.IdOk(id))
            throw new ArgumentException("signRelease: a malformed release");
        var b = new D
        {
            ["v"] = IntentJs.OfLong(1),
            ["key"] = key,
            ["id"] = id,
            ["reason"] = reason,
            ["at"] = IntentJs.OfLong(at),
            ["signer"] = secret.Id,
        };
        b["sig"] = Pca.B64u(secret.Sign(ReleaseMessage(b)));
        return b;
    }

    /// <summary>True iff <paramref name="ro"/> is well formed and signed by <paramref name="expectedSigner"/> over exactly its content. Never throws.</summary>
    public static bool VerifyRelease(object? ro, string expectedSigner)
    {
        try
        {
            if (ro is not D r || !IntentJs.IsInt(r.GetValueOrDefault("v")) || IntentJs.Lng(r["v"]) != 1 || r.GetValueOrDefault("signer") as string != expectedSigner
                || r.GetValueOrDefault("reason") is not string reason || !ReleaseReasons.Contains(reason) || !IntentJs.IsInt(r.GetValueOrDefault("at"))
                || !BudgetDoc.IdOk(r.GetValueOrDefault("key")) || !BudgetDoc.IdOk(r.GetValueOrDefault("id")) || Pca.B64uDecode(r.GetValueOrDefault("sig"), 64) == null)
                return false;
            return Pca.VerifyEdInternal(expectedSigner, ReleaseMessage(r), r["sig"]);
        }
        catch (Exception) { return false; }
    }

    public static string ReleaseDigest(D r) => Pca.HashCanonical(new D { ["d"] = "atlas-pca/budget-release-ref/v1", ["r"] = r });

    /// <summary>The log leaf of a release.</summary>
    public static string ReleaseCommit(D r) => Pca.HashCanonical(new D { ["d"] = "atlas-pca/budget-release-leaf/v1", ["digest"] = ReleaseDigest(r) });

    /// <summary>Anchor a signed release in a transparency log store (retries on a position conflict). Returns the leaf index.</summary>
    public static long AnchorRelease(ILedgerStore log, D r)
    {
        var commit = ReleaseCommit(r);
        for (int i = 0; i < 64; i++)
        {
            long size = log.Size();
            var o = log.Append(size, new[] { commit });
            if (o.Outcome is "appended" or "replayed") return size;
        }
        throw new BudgetLedgerError("conflict_exhausted", "could not anchor the release: the log kept moving");
    }

    // ---- scoped admission ----

    /// <summary>The ledger key of an accumulator for this admission, or null when it is session-scoped. Throws <c>scope_unbound</c>.</summary>
    public static string? AggregateKeyOf(D a, IReadOnlyDictionary<string, string> ids)
    {
        var scope = a.GetValueOrDefault("scope");
        if (scope == null || scope as string == "session") return null;
        if (!ids.TryGetValue((string)scope, out var id)) throw new BudgetLedgerError("scope_unbound", $"accumulator {a.GetValueOrDefault("id")} is {scope}-scoped but no {scope} id was given");
        return ScopeKey((string)scope, id);
    }

    static bool IsScoped(D a) => a.GetValueOrDefault("scope") != null && a.GetValueOrDefault("scope") as string != "session";

    /// <summary>Admit one action against every non-session accumulator, atomically per key: read each key's snapshot and compute the pre-states, call
    /// <paramref name="verify"/>(state), and on allow <c>Reserve</c> in every key with <c>ExpectedVersion</c> = the snapshot's. A moved key repeats from the top
    /// (optimistic concurrency); a key over its cap denies and releases what the earlier keys reserved. Throws <c>not_durable</c> for a ledger that is not durable, always.</summary>
    public static BudgetAdmission AdmitAggregateAction(IBudgetLedger? ledger, IReadOnlyDictionary<string, string> ids, IEnumerable<D> accumulators, object? schema, D evt,
        Func<D, D> verify, long? expiresAt = null, int? maxAttempts = null)
    {
        var scoped = accumulators.Where(IsScoped).ToList();
        if (scoped.Count > 0 && (ledger == null || !ledger.Durable))
            throw new BudgetLedgerError("not_durable", "a principal, org or fleet aggregate needs a durable BudgetLedger (a restart would reset every cap)");
        var byKey = new SortedDictionary<string, List<D>>(StringComparer.Ordinal);
        try
        {
            foreach (var a in scoped)
            {
                var k = AggregateKeyOf(a, ids)!;
                if (!byKey.TryGetValue(k, out var list)) byKey[k] = list = new List<D>();
                list.Add(a);
            }
        }
        catch (BudgetLedgerError e) when (e.Code == "scope_unbound")
        {
            return new BudgetAdmission { Admitted = false, Reason = "scope_unbound: " + e.Message };
        }
        var keys = byKey.Keys.ToList();
        int attempts = maxAttempts ?? 256;
        for (int attempt = 0; attempt < attempts; attempt++)
        {
            var snaps = new Dictionary<string, BudgetSnapshot>();
            var state = new D();
            foreach (var k in keys)
            {
                var s = ledger!.Snapshot(k);
                snaps[k] = s;
                var history = s.Events.Cast<object?>().ToList();
                foreach (var a in byKey[k])
                {
                    if (a.GetValueOrDefault("holder") is not D holder || holder.GetValueOrDefault("kind") as string != "site_local") continue;
                    var ps = evt.GetValueOrDefault("params") as D;
                    if (a.GetValueOrDefault("key") != null && IntentHistory.AccKeyOf(a, ps) == null) continue; // the verifier fails the claim (missing key)
                    state[(string)a["id"]!] = IntentHistory.AccPreState(a, history, ps, evt.GetValueOrDefault("t"), schema);
                }
            }
            var verdict = verify(state);
            if (verdict.GetValueOrDefault("allow") is not true) return new BudgetAdmission { Admitted = false, Reason = "verifier denied", Verdict = verdict };
            var done = new List<BudgetReservation>();
            bool moved = false;
            foreach (var k in keys)
            {
                var req = new BudgetReserveRequest { Event = evt, Accumulators = byKey[k], Schema = schema, ExpectedVersion = snaps[k].Version, ExpiresAt = expiresAt };
                var r = ledger!.Reserve(k, req);
                if (r.Outcome == "reserved" || (r.Outcome == "replayed" && r.Status == "reserved"))
                {
                    done.Add(new BudgetReservation(k, (string)evt["id"]!));
                    continue;
                }
                foreach (var d in done) ledger.Release(d.Key, d.Id, null);
                if (r.Outcome == "conflict")
                {
                    moved = true;
                    break;
                }
                var why = r.Outcome == "over_cap" ? $"over_cap: {r.Acc} would reach {r.PostValue} (cap {StoreJs.Number(r.Cap!.Value).Raw})"
                    : r.Outcome == "replayed" ? "already " + r.Status : r.Outcome;
                return new BudgetAdmission { Admitted = false, Reason = "aggregate: " + why, Verdict = verdict };
            }
            if (!moved) return new BudgetAdmission { Admitted = true, Verdict = verdict, Reservations = done, State = state };
        }
        throw new BudgetLedgerError("conflict_exhausted", "the aggregate kept moving under this admission");
    }

    /// <summary>BEFORE the effect: mark every reservation started (non-expirable). Returns false when any is refused (released or expired in the meantime): the effect must NOT run then.</summary>
    public static bool StartAggregate(IBudgetLedger ledger, IEnumerable<BudgetReservation> reservations)
    {
        foreach (var r in reservations)
        {
            var o = ledger.Start(r.Key, r.Id);
            if (o.Outcome is not ("settled" or "replayed")) return false;
        }
        return true;
    }

    /// <summary>After the effect: <c>committed</c> (it happened) or <c>released</c> (it did not; a signed <paramref name="evidence"/> is stored and can be anchored).</summary>
    public static List<BudgetSettleOutcome> SettleAggregate(IBudgetLedger ledger, IEnumerable<BudgetReservation> reservations, string status, Func<BudgetReservation, D>? evidence = null) =>
        reservations.Select(r => status == "committed" ? ledger.Commit(r.Key, r.Id) : ledger.Release(r.Key, r.Id, evidence?.Invoke(r))).ToList();
}

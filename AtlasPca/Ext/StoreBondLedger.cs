// Durable, restart-safe bond settlement over an IBondStore (the reference StoreBondLedger). INTERNAL ACCOUNTING ONLY: nothing here moves money.
//
// Each transition is planned by the same BondSettlementPlanner a deployment's in-memory ledger would use (so a slash is authorised by a verdict the ledger recomputes, never by the
// challenger), stamped from a clock the claimant cannot touch, and committed atomically and idempotently. It FAILS CLOSED: no store (store_missing), no guardian key (guardian_key_missing),
// a non-finite clock (clock_invalid), a store that throws (store_unavailable), malformed stored state (store_corrupt), a claim that fails verification or the window floor (invalid_claim), a
// release inside the challenge window (window_open), a fraud or dispute slash after it (window_closed), a release or slash of an unregistered bond (unregistered), a claim differing from the
// registered one (claim_mismatch) and a conflicting concurrent transition (conflict) are each a BondStoreError with that code.
//
// The challenge window opens at the ledger's own registeredAt, lasts the claim's challenge_window_ms, and is never derived from the claim's issued_at. "Now" is max(clock(), highest time the
// store ever recorded), so a clock that steps backwards cannot reopen a closed window or release early. Records, bond rows and statuses are JSON objects.
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca;

/// <summary>The planner options plus the store, clock and window policy.</summary>
public sealed class StoreBondLedgerOptions : BondPlannerOptions
{
    /// <summary>REQUIRED. There is deliberately no default store.</summary>
    public IBondStore? Store { get; set; }
    /// <summary>The epoch-ms clock (default the system clock). A non-finite reading fails the operation.</summary>
    public Func<double>? Clock { get; set; }
    /// <summary>Window bounds applied by <see cref="StoreBondLedger.OpenClaim"/> (default <see cref="ChallengeWindowPolicy.Default"/>); a window is never below the 30 s realistic floor.</summary>
    public ChallengeWindowPolicy? WindowPolicy { get; set; }
}

public sealed class StoreBondLedger
{
    readonly BondSettlementPlanner _planner;
    readonly IBondStore _store;
    readonly Func<double> _clock;
    readonly ChallengeWindowPolicy _windowPolicy;

    public StoreBondLedger(StoreBondLedgerOptions o)
    {
        if (o.Store == null) throw new BondStoreError("store_missing", "a BondStore is required (there is no in-memory default)");
        if (o.GuardianKey == null || o.GuardianKey.IsDestroyed) throw new BondStoreError("guardian_key_missing", "a guardian secret key is required");
        _store = o.Store;
        _planner = new BondSettlementPlanner(o);
        _clock = o.Clock ?? (() => AtlasPca.ReplayClock.NowMs());
        _windowPolicy = o.WindowPolicy ?? ChallengeWindowPolicy.Default;
    }

    /// <summary>The guardian / settlement public key (b64u) the records verify under.</summary>
    public string GuardianPublicKey => _planner.GuardianPublicKey;

    static T Guard<T>(Func<T> fn)
    {
        try { return fn(); }
        catch (BondStoreError) { throw; }
        catch (Exception e) { throw new BondStoreError("store_unavailable", string.IsNullOrEmpty(e.Message) ? "store failed" : e.Message, e); }
    }

    sealed class View(D? bond, Dictionary<string, double> balances, long count, double sum) : IBondView
    {
        public D? Bond(string id) => bond != null && bond.GetValueOrDefault("claimId") as string == id ? bond : null;
        public double BalanceOf(string a) => balances.TryGetValue(a, out var v) ? v : 0;
        public (long Count, double Sum) OpenTotals(string depositor) => (count, sum);
    }

    sealed record Loaded(BondSnapshot Snap, IBondView View, double Now);

    Loaded Load(string claimId, string? depositor)
    {
        var snap = Guard(() => _store.Read(claimId, depositor));
        double t = _clock();
        if (!double.IsFinite(t)) throw new BondStoreError("clock_invalid", "the clock returned a non-finite time");
        return new Loaded(snap, new View(snap.Bond, snap.Balances, snap.OpenCount, snap.OpenSum), JsMax(t, snap.HighWater));
    }

    static double JsMax(double a, double b) => double.IsNaN(a) || double.IsNaN(b) ? double.NaN : Math.Max(a, b);

    static D? LastRecord(D bond) => bond["records"] is L { Count: > 0 } recs ? recs[^1] as D : null;

    D Submit(D plan, double now)
    {
        var o = Guard(() => _store.Commit(plan, now));
        if (o.Outcome == "conflict") throw new BondStoreError("conflict", o.Reason ?? "conflict");
        return o.Record!;
    }

    /// <summary>Settle: plan against the true view; if the bond is already settled, a retry that would have produced the same settlement returns the stored record.</summary>
    D Settle(string claimId, Func<IBondView, double, D> plan, Action<D, double>? gate)
    {
        var l = Load(claimId, null);
        var bond = l.Snap.Bond;
        if (bond != null && bond.GetValueOrDefault("status") as string != "open")
        {
            var last = LastRecord(bond);
            var reopened = new D(bond) { ["status"] = "open" };
            var again = plan(new View(reopened, l.Snap.Balances, l.Snap.OpenCount, l.Snap.OpenSum), l.Now); // throws if the evidence no longer holds
            if (last != null && BondDoc.SameSettlement(last, (D)again["record"]!)) return last;
            return (D)plan(l.View, l.Now)["record"]!; // throws the standard double-settle refusal
        }
        if (bond != null) gate?.Invoke(bond, l.Now);
        return Submit(plan(l.View, l.Now), l.Now);
    }

    /// <summary>Top up an account of the internal books (a positive finite amount).</summary>
    public double Deposit(string account, double amount) => Guard(() => _store.Deposit(account, amount));

    public double BalanceOf(string account)
    {
        var snap = Guard(() => _store.Read("", account));
        return snap.Balances.TryGetValue(account, out var d) ? d : 0;
    }

    /// <summary><c>none</c>, <c>open</c>, <c>released</c> or <c>slashed</c>.</summary>
    public string BondStatus(string claimId)
    {
        var s = Guard(() => _store.Read(claimId, null));
        return s.Bond == null ? "none" : (string)s.Bond["status"]!;
    }

    /// <summary>The bond row <c>{claimId, amount, depositor, status, window?, records}</c>, or null.</summary>
    public D? GetBond(string claimId) => Guard(() => _store.Read(claimId, null)).Bond;

    static double Dbl(object? o) => IntentJs.NumOf(o) ?? double.NaN;

    /// <summary><c>{phase: open|finalized, endsAt, now}</c> on the ledger's clock; throws <c>unregistered</c> for a bond with no claim.</summary>
    public D ChallengeStatus(string claimId)
    {
        var l = Load(claimId, null);
        if (l.Snap.Bond?.GetValueOrDefault("window") is not D w) throw new BondStoreError("unregistered", $"bond {claimId} has no registered claim");
        double endsAt = Dbl(w["registeredAt"]) + Dbl(w["windowMs"]);
        return new D { ["phase"] = l.Now > endsAt ? "finalized" : "open", ["endsAt"] = StoreJs.Number(endsAt), ["now"] = StoreJs.Number(l.Now) };
    }

    /// <summary>Register an optimistic claim and lock its bond in one atomic commit. The claim must pass <see cref="Optimistic.VerifyClaim"/> against the ledger's clock and its window must be at least the
    /// realistic floor; the window then runs from the ledger's own <c>registeredAt</c>. Retrying the same call returns the original <c>open</c> record. <paramref name="exposure"/> may be null.</summary>
    public D OpenClaim(D? claim, object? pcactn, string signerPublic, double amount, string depositor, double? exposure = null)
    {
        var bondRef = claim?.GetValueOrDefault("bond_ref");
        var l = Load(bondRef == null ? (claim != null && claim.ContainsKey("bond_ref") ? "null" : "undefined") : IntentRevocation.JsText(bondRef, true), depositor);
        var verdict = Optimistic.VerifyClaim(claim, pcactn, signerPublic, l.Now, _windowPolicy);
        if (verdict.GetValueOrDefault("ok") is not true) throw new BondStoreError("invalid_claim", IntentRevocation.JsText(verdict.GetValueOrDefault("reason"), verdict.ContainsKey("reason")));
        double floor = JsMax(_windowPolicy.MinWindowMs, Optimistic.DefaultMinChallengeWindowMs);
        double windowMs = Dbl(claim!.GetValueOrDefault("challenge_window_ms"));
        if (windowMs < floor) throw new BondStoreError("invalid_claim", $"challenge window {JsCanon.NumberString(windowMs)} ms is below the {JsCanon.NumberString(floor)} ms floor");
        if (bondRef is not string { Length: > 0 } bond) throw new BondStoreError("invalid_claim", "claim has no bond_ref");
        var window = new D { ["registeredAt"] = StoreJs.Number(l.Now), ["windowMs"] = StoreJs.Number(windowMs), ["claimDigest"] = BondSettlement.HashLenient(claim) };
        if (l.Snap.Bond != null) return ReplayOpen(l.Snap.Bond, depositor, amount, window);
        return Submit(_planner.PlanOpen(l.View, bond, amount, depositor, exposure, l.Now, window), l.Now);
    }

    /// <summary>A retried open: the same terms return the original <c>open</c> record; anything else is the standard double-open refusal.</summary>
    static D ReplayOpen(D prior, string depositor, double amount, D? window)
    {
        var pw = prior.GetValueOrDefault("window") as D;
        bool sameWindow = pw == null ? window == null : window != null && Equals(pw.GetValueOrDefault("claimDigest"), window.GetValueOrDefault("claimDigest"));
        bool same = Equals(prior.GetValueOrDefault("depositor"), depositor) && Dbl(prior["amount"]) == amount && sameWindow;
        if (same && prior["records"] is L { Count: > 0 } recs) return (D)recs[0]!;
        throw new BondStoreError("conflict", $"openBond: bond {prior.GetValueOrDefault("claimId")} already exists (double-open refused)");
    }

    /// <summary>Open a bond that backs no claim (a challenger's counter-bond). It has no window; settle it with <see cref="SlashCounterBond"/> or <see cref="ReleaseUnregistered"/>.</summary>
    public D OpenBond(string claimId, double amount, string depositor, double? exposure = null)
    {
        var l = Load(claimId, depositor);
        if (l.Snap.Bond != null) return ReplayOpen(l.Snap.Bond, depositor, amount, null);
        return Submit(_planner.PlanOpen(l.View, claimId, amount, depositor, exposure, l.Now, null), l.Now);
    }

    /// <summary>Release a registered claim's bond once its challenge window has closed on the ledger's clock.</summary>
    public D Release(string claimId) => Settle(claimId, (view, now) => _planner.PlanRelease(view, claimId, now), (bond, now) =>
    {
        if (bond.GetValueOrDefault("window") is not D w) throw new BondStoreError("unregistered", $"bond {claimId} has no registered claim; use releaseUnregistered for a counter-bond");
        double end = Dbl(w["registeredAt"]) + Dbl(w["windowMs"]);
        if (!(now > end)) throw new BondStoreError("window_open", $"the challenge window of {claimId} closes at {JsCanon.NumberString(end)}");
    });

    /// <summary>Release a bond that backs no claim (a counter-bond).</summary>
    public D ReleaseUnregistered(string claimId) => Settle(claimId, (view, now) => _planner.PlanRelease(view, claimId, now), (bond, _) =>
    {
        if (bond.GetValueOrDefault("window") is D) throw new BondStoreError("conflict", $"bond {claimId} backs a registered claim; use release");
    });

    static Action<D, double> ChallengeGate(D? claim) => (bond, now) =>
    {
        if (bond.GetValueOrDefault("window") is not D w) throw new BondStoreError("unregistered", $"bond {bond.GetValueOrDefault("claimId")} has no registered claim");
        if (!Equals(w.GetValueOrDefault("claimDigest"), BondSettlement.HashLenient(claim))) throw new BondStoreError("claim_mismatch", $"the claim is not the one registered for {bond.GetValueOrDefault("claimId")}");
        double end = Dbl(w["registeredAt"]) + Dbl(w["windowMs"]);
        if (!(now <= end)) throw new BondStoreError("window_closed", $"the challenge window of {bond.GetValueOrDefault("claimId")} closed at {JsCanon.NumberString(end)}");
    };

    static string IdOf(D p, string k) => p.GetValueOrDefault(k) is string s ? s : p.ContainsKey(k) && p[k] == null ? "null" : p.ContainsKey(k) ? IntentRevocation.JsText(p[k], true) : "undefined";

    /// <summary>Slash on a fraud proof the ledger re-verifies itself, inside the challenge window. <paramref name="p"/>: see <see cref="BondSettlementPlanner.PlanSlash"/>.</summary>
    public D SlashBond(D p) => Settle(IdOf(p, "claimId"), (view, now) => _planner.PlanSlash(view, p, now), ChallengeGate(p.GetValueOrDefault("claim") as D));

    /// <summary>Slash on a dispute the ledger re-adjudicates itself, inside the challenge window.</summary>
    public D SlashBondOnDispute(D p) => Settle(IdOf(p, "claimId"), (view, now) => _planner.PlanSlashOnDispute(view, p, now), ChallengeGate(p.GetValueOrDefault("claim") as D));

    /// <summary>Slash because a capability in the claim's chain was revoked (server-derived evidence; not window-gated).</summary>
    public D SlashBondOnRevocation(D p)
    {
        var claim = p.GetValueOrDefault("claim") as D;
        return Settle(IdOf(p, "claimId"), (view, now) => _planner.PlanSlashOnRevocation(view, p, now), (bond, _) =>
        {
            if (bond.GetValueOrDefault("window") is D w && !Equals(w.GetValueOrDefault("claimDigest"), BondSettlement.HashLenient(claim)))
                throw new BondStoreError("claim_mismatch", $"the claim is not the one registered for {bond.GetValueOrDefault("claimId")}");
        });
    }

    /// <summary>Slash a challenger's counter-bond after a frivolous dispute.</summary>
    public D SlashCounterBond(D p) => Settle(IdOf(p, "counterBondId"), (view, now) => _planner.PlanSlashCounterBond(view, p, now), null);
}

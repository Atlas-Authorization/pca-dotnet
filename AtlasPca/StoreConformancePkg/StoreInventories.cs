// The check inventories of the store conformance profiles (lease, ledger, budget, bond and mesh-witness): the name of every check, the claim it
// tests and what the store must declare for it to run (durable / crash). The profile runners themselves live with the store contracts they exercise;
// this is the catalogue a report or an adapter author reads.
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.StoreConformancePkg;

public static class StoreInventories
{
    static readonly (string Name, string Claim, string? Needs)[] Lease = {
        ("empty-store-has-no-lease", "a new store has no lease and a finite clock", null),
        ("first-acquire-is-epoch-1", "the first holder gets epoch 1 and an expiry from the store clock", null),
        ("wrong-expected-record-never-writes", "cas with an expected record that is not the stored one returns false and changes nothing", null),
        ("racing-acquirers-have-one-winner", "many contenders at once: exactly one acquires, at epoch 1", null),
        ("takeover-after-release-bumps-the-epoch", "a released lease is free at once and the next holder gets a strictly higher epoch", null),
        ("epoch-never-goes-down", "cas refuses a record with a lower epoch even when the expected record matches", null),
        ("stale-holder-cannot-renew-or-release", "after a takeover the old (holder, epoch) is refused as stale for renew and release", null),
        ("state-survives-reopen", "an acknowledged lease is there when another client opens the same backend", "durable"),
        ("acknowledged-lease-survives-a-crash", "after an abrupt backend kill the lease and its epoch are still there, and the next epoch is higher", "crash"),
    };

    static readonly (string Name, string Claim, string? Needs)[] Ledger = {
        ("empty-store-is-empty", "a new store has no entries and no checkpoints, and reads of the empty range succeed", null),
        ("append-assigns-the-next-position", "an append at the current length adds its commits in order at exactly those positions", null),
        ("append-at-another-position-conflicts-without-trace", "an append whose expected length is not the current length conflicts, reports the real length, and writes nothing", null),
        ("append-retry-is-a-replay", "repeating a batch already stored at that position is a replay (a prefix of it too); a different batch there conflicts", null),
        ("invalid-input-is-refused", "empty batches, empty or non-string commits and a bad expected length throw and write nothing", null),
        ("commit-strings-are-stored-exactly", "unicode, quotes, separators and long commits come back byte for byte", null),
        ("racing-appends-at-one-position-have-one-winner", "clients appending at the same expected length: exactly one is appended, none is lost or duplicated, the log is the winner batch", null),
        ("racing-writers-with-retry-fill-every-position-once", "sixteen writers each retrying until their commit is in: positions are unique, there are no holes, every commit is present exactly once", null),
        ("a-batch-is-all-or-nothing", "a batch that conflicts leaves none of its commits behind, and a batch that lands lands every commit", null),
        ("checkpoints-append-by-count-and-replay", "a checkpoint appends at the exact count; the same one again is a replay; another at that position conflicts", null),
        ("checkpoints-stay-inside-the-log-and-never-go-back", "a checkpoint beyond the end of the log, below the previous one, or equal in size with another root is refused", null),
        ("racing-checkpoints-have-one-winner", "checkpoints racing for one position: exactly one lands", null),
        ("reads-are-snapshots", "mutating what a read returned cannot change the store", null),
        ("state-survives-reopen", "every acknowledged append and checkpoint is visible to a new client after the backend restarts", "durable"),
        ("acknowledged-writes-survive-a-crash", "after an abrupt kill every acknowledged write is present and the log is a prefix of what was written: no holes, no partial batch", "crash"),
    };

    static readonly (string Name, string Claim, string? Needs)[] Budget = {
        ("empty-key-is-empty", "a key nobody reserved on has version 0 and no events", null),
        ("reservation-counts-at-once-and-cap-is-inclusive", "a reservation counts as soon as it is made; one that would pass the cap is refused with the post-value, one that reaches it exactly is admitted", null),
        ("a-refusal-writes-nothing", "an over-cap reservation leaves no event and does not move the version", null),
        ("reserve-retry-is-a-replay", "the same event again is a replay that changes nothing and does not count twice; another event under the same id conflicts", null),
        ("expected-version-is-compare-and-swap", "a reservation naming a stale version conflicts and writes nothing; the current version succeeds; a replay wins over a stale version", null),
        ("racing-reserves-never-pass-the-cap", "forty reservations of 30 racing from four clients against a cap of 200: exactly six land, the total is never above the cap, none is lost or counted twice", null),
        ("racing-reserves-at-one-version-have-one-winner", "clients reserving with the same expected version: exactly one lands, the others conflict", null),
        ("racing-writers-with-retry-fill-the-cap-exactly", "twenty writers of 10 each retrying on conflict against a cap of 200: all twenty land, the twenty-first is refused", null),
        ("settle-rules", "commit and release settle only a reservation, are idempotent, and refuse the opposite settlement; an unknown id changes nothing", null),
        ("release-frees-budget-and-commit-keeps-it", "a released reservation no longer counts; a committed one still does; an open one keeps counting until settled", null),
        ("release-without-reserve-credits-nothing", "releasing an id that was never reserved does not create headroom, now or after the id is reserved later", null),
        ("a-late-commit-cannot-overspend", "after a reservation was released and its budget reused, committing it is refused, so the committed total never passes the cap", null),
        ("expiry-releases-only-open-reservations-past-their-deadline", "expire frees a reservation at or after its deadline, never an earlier one, never a committed, started or deadline-less one, and a late commit or start of it is refused", null),
        ("start-rules", "start marks an open reservation non-expirable and is idempotent; an unknown id changes nothing; a started one can still be committed, or released (the effect did not happen); a released one cannot start", null),
        ("keys-are-independent", "two keys have their own caps, versions and events", null),
        ("windows-reset-the-count", "a period window counts only the events of the period of the new event", null),
        ("release-evidence-is-stored-and-bound", "evidence for the reservation is kept with the released event; evidence for another reservation is refused and the reservation stays open", null),
        ("invalid-input-is-refused", "a malformed event or request throws and writes nothing", null),
        ("snapshots-are-copies", "mutating what a snapshot returned cannot change the ledger", null),
        ("durable-claim-matches-the-adapter", "a ledger says durable: true exactly when its adapter declares durability, so a volatile ledger can never satisfy the non-session refusal", null),
        ("state-survives-reopen", "every acknowledged reserve, commit and release is visible to a new client after the backend restarts, and the cap still holds", "durable"),
        ("acknowledged-writes-survive-a-crash", "after an abrupt kill every acknowledged reservation still counts, so a crash can only over-restrict, never reset a cap", "crash"),
    };

    static readonly (string Name, string Claim, string? Needs)[] Bond = {
        ("empty-store-reads-empty", "an unknown bond reads as absent, an unknown account as balance 0, and the time high-water mark starts at 0", null),
        ("deposit-validates-and-accumulates", "deposit credits exactly, returns the new balance, and refuses a non-positive, non-finite or unnamed deposit", null),
        ("open-is-atomic-and-recorded", "an open moves the collateral, stores the row with its record, and raises the high-water mark, all together", null),
        ("open-overdraft-refused-without-trace", "an open the depositor cannot fund is a conflict and leaves balances, bonds and the high-water mark untouched", null),
        ("open-retry-is-replayed-and-different-terms-conflict", "committing the same open again returns the stored record and moves nothing; other terms for that bond conflict", null),
        ("open-caps-are-rechecked-at-commit", "the per-depositor open-claim and open-amount caps hold inside the store, whatever the planner saw", null),
        ("settle-applies-every-move-once", "a release and a slash apply all their balance moves, store the record, and conserve the total", null),
        ("settle-needs-the-expected-phase", "settling an absent bond or from the wrong phase is a conflict that changes nothing, high-water mark included", null),
        ("settle-overdraw-refused-without-trace", "a settlement whose debit would overdraw an account is refused whole: no credit lands, the phase does not change", null),
        ("settle-retry-returns-the-stored-record", "the same settlement again is replayed with the first record and moves nothing; the same action with other evidence conflicts", null),
        ("racing-identical-settles-commit-once", "eight clients racing the same release: one commits, seven are replays, funds move once", null),
        ("racing-conflicting-settles-have-one-winner", "a release racing a slash on one bond: exactly one commits, the books show only the winner, the total is conserved", null),
        ("racing-opens-for-the-same-bond-commit-once", "concurrent identical opens collect the collateral once; a differing open loses", null),
        ("racing-opens-cannot-overdraw", "concurrent opens by one depositor that together exceed the balance: the sum committed never exceeds what was deposited", null),
        ("concurrent-deposits-lose-nothing", "sixteen racing deposits add up exactly", null),
        ("time-high-water-only-moves-forward", "the recorded time is the maximum of every committed observedAt; a smaller or non-finite one never lowers it", null),
        ("reads-are-snapshots", "mutating a returned snapshot cannot change the store", null),
        ("hostile-names-are-plain-keys", "claim and account names such as __proto__, constructor and toString behave like any other name", null),
        ("state-survives-reopen", "every acknowledged commit and deposit is visible to a new client after the backend restarts", "durable"),
        ("acknowledged-commits-survive-a-crash", "after an abrupt kill, every acknowledged transition is present, and a transition that was in flight is applied entirely or not at all", "crash"),
    };

    static readonly string[] MeshWitness = {
        "a fresh store loads nothing",
        "save then load returns the same state",
        "a later save replaces the earlier one",
        "load returns a copy: changing it does not change the store",
        "save keeps its own copy: changing the argument afterwards does not change the store",
        "a witness persists every cosignature before returning it",
        "a failed save refuses the cosignature and leaves the witness unchanged",
    };

    static readonly string[] MeshWitnessReopen = {
        "a fresh store loads nothing",
        "save then load returns the same state",
        "a later save replaces the earlier one",
        "load returns a copy: changing it does not change the store",
        "save keeps its own copy: changing the argument afterwards does not change the store",
        "a witness persists every cosignature before returning it",
        "a failed save refuses the cosignature and leaves the witness unchanged",
        "state survives reopening the store",
        "a restarted witness remembers what it cosigned: it refuses a fork and a rollback",
    };

    static readonly string[] MeshWitnessDamage = {
        "a fresh store loads nothing",
        "save then load returns the same state",
        "a later save replaces the earlier one",
        "load returns a copy: changing it does not change the store",
        "save keeps its own copy: changing the argument afterwards does not change the store",
        "a witness persists every cosignature before returning it",
        "a failed save refuses the cosignature and leaves the witness unchanged",
        "damaged storage makes load throw, so a witness never starts empty over it",
    };

    static readonly string[] MeshWitnessReopenDamage = {
        "a fresh store loads nothing",
        "save then load returns the same state",
        "a later save replaces the earlier one",
        "load returns a copy: changing it does not change the store",
        "save keeps its own copy: changing the argument afterwards does not change the store",
        "a witness persists every cosignature before returning it",
        "a failed save refuses the cosignature and leaves the witness unchanged",
        "state survives reopening the store",
        "a restarted witness remembers what it cosigned: it refuses a fork and a rollback",
        "damaged storage makes load throw, so a witness never starts empty over it",
    };

    static L Checks((string Name, string Claim, string? Needs)[] cs) => new(cs.Select(c => (object?)new D { ["name"] = c.Name, ["claim"] = c.Claim, ["needs"] = c.Needs }));

    /// <summary>The check inventory of a profile: <c>lease</c>, <c>ledger</c>, <c>budget</c>, <c>bond</c> (a list of {name, claim, needs}), or <c>mesh-witness</c> with
    /// <c>+reopen</c> and / or <c>+damage</c> (the case names, in run order). Throws on an unknown profile.</summary>
    public static object Of(string profile) => profile switch
    {
        "lease" => Checks(Lease),
        "ledger" => Checks(Ledger),
        "budget" => Checks(Budget),
        "bond" => Checks(Bond),
        "mesh-witness" => Names(MeshWitness),
        "mesh-witness+reopen" => Names(MeshWitnessReopen),
        "mesh-witness+damage" => Names(MeshWitnessDamage),
        "mesh-witness+reopen+damage" => Names(MeshWitnessReopenDamage),
        _ => throw new ArgumentException("unknown conformance profile: " + profile),
    };

    static L Names(string[] ns) => new(ns.Select(n => (object?)n));
}

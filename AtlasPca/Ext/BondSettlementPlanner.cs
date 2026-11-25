// The pure half of bond settlement (the reference BondSettlementPlanner): validates a transition against a read view, re-derives every slash verdict itself (a slash is never authorised by
// challenger assertion), computes the balance movements and signs the record. It holds no state and touches no store; StoreBondLedger commits the plans it returns to an IBondStore atomically.
//
// A plan is {claimId, expect, next, open?: {amount, depositor, maxOpenClaims, maxOpenAmount, window?}, moves: [{account, op, amount}], record} (see IBondStore); a window is
// {registeredAt, windowMs, claimDigest}.
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca;

/// <summary>What deciding a transition needs to read.</summary>
public interface IBondView
{
    /// <summary>The bond head <c>{claimId, amount, depositor, status, ...}</c>, or null.</summary>
    D? Bond(string claimId);

    double BalanceOf(string account);

    /// <summary>The count and summed amount of the depositor's currently open bonds.</summary>
    (long Count, double Sum) OpenTotals(string depositor);
}

/// <summary>Planner configuration; only <see cref="GuardianKey"/> is required.</summary>
public class BondPlannerOptions
{
    /// <summary>The guardian / settlement key that signs every record.</summary>
    public EdKey? GuardianKey { get; set; }
    /// <summary>Bound into every signed record when set (a non-negative safe integer).</summary>
    public long? GuardianEpoch { get; set; }
    /// <summary>The signature suite (null: ed25519). A PQ or hybrid suite binds its public key into the signed body; its Ed25519 key must be <see cref="GuardianKey"/>.</summary>
    public SuiteKey? Suite { get; set; }
    public string? EscrowAccount { get; set; }
    /// <summary><c>{floor, k, maxOpenClaims, maxOpenAmount, curve?}</c> (null: <see cref="BondSettlement.DefaultBondPolicy"/>).</summary>
    public D? BondPolicy { get; set; }
    /// <summary><c>{challengerBps, victimBps}</c> (null: <see cref="BondSettlement.DefaultSlashSplitPolicy"/>).</summary>
    public D? SlashSplitPolicy { get; set; }
}

public sealed class BondSettlementPlanner
{
    readonly SuiteKey _suite;
    readonly long? _epoch;

    public string GuardianPublicKey { get; }
    public string Escrow { get; }
    public D BondPolicy { get; }
    public D SlashSplitPolicy { get; }

    public BondSettlementPlanner(BondPlannerOptions o)
    {
        if (o.GuardianKey == null) throw new ArgumentException("BondLedger: guardianSecret must be a Uint8Array");
        GuardianPublicKey = o.GuardianKey.Id;
        if (o.GuardianEpoch is long e && (e < 0 || e > Pca.MaxSafeInt)) throw new ArgumentException("BondLedger: guardianEpoch must be a non-negative safe integer");
        _epoch = o.GuardianEpoch;
        if (o.Suite?.Ed != null && o.Suite.Ed.Id != GuardianPublicKey) throw new ArgumentException("BondLedger: the suite's Ed25519 key is not the guardian key");
        _suite = o.Suite ?? SuiteKey.Ed25519(o.GuardianKey);
        Escrow = o.EscrowAccount ?? BondSettlement.EscrowAccount;
        BondPolicy = o.BondPolicy ?? BondSettlement.DefaultBondPolicy;
        SlashSplitPolicy = o.SlashSplitPolicy ?? BondSettlement.DefaultSlashSplitPolicy;
    }

    D SignRecord(D @base)
    {
        var withEpoch = new D(@base);
        if (_epoch is long e) withEpoch["guardian_epoch"] = IntentJs.OfLong(e);
        var body = IntentJs.BindSuiteFields(withEpoch, _suite.Alg, true, _suite.PqPk, true);
        var (sig, pqSig) = _suite.Sign(BondSettlement.SettlementMessage(body));
        var rec = new D(body) { ["sig"] = sig };
        if (pqSig != null) rec["pq_sig"] = pqSig;
        return rec;
    }

    static D Mv(string account, string op, double amount) => new() { ["account"] = account, ["op"] = op, ["amount"] = StoreJs.Number(amount) };

    static D Base(string claimId, string action, double amount, string from, string to, double at, string evidenceDigest) => new()
    {
        ["claimId"] = claimId, ["action"] = action, ["amount"] = StoreJs.Number(amount), ["from"] = from, ["to"] = to, ["at"] = StoreJs.Number(at), ["evidenceDigest"] = evidenceDigest,
    };

    static D Plan(string claimId, string expect, string next, L moves, D record) => new() { ["claimId"] = claimId, ["expect"] = expect, ["next"] = next, ["moves"] = moves, ["record"] = record };

    static double AmountOf(D bond) => IntentJs.NumOf(bond["amount"])!.Value;

    D OpenBondOrThrow(IBondView view, string who, string? claimId)
    {
        var bond = claimId == null ? null : view.Bond(claimId);
        if (bond == null) throw new InvalidOperationException($"{who}: no bond for {claimId}");
        if (bond.GetValueOrDefault("status") as string != "open") throw new InvalidOperationException($"{who}: bond {claimId} is already {bond.GetValueOrDefault("status")} (double-settle refused)");
        return bond;
    }

    static string? StringParam(D p, string k) => p.GetValueOrDefault(k) as string;

    static void NeedTreasury(D p, string who)
    {
        if (string.IsNullOrEmpty(StringParam(p, "treasury"))) throw new InvalidOperationException(who + ": treasury is required");
    }

    static D ClaimOf(D p) => p.GetValueOrDefault("claim") as D ?? throw new InvalidOperationException("the claim is required");

    /// <summary>The balance movements of a slash: the full bond leaves escrow and is divided per <see cref="BondSettlement.ComputeSlashSplit"/>.</summary>
    D SlashPlan(D bond, string claimId, double now, string evidenceDigest, D p)
    {
        var treasury = (string)p["treasury"]!;
        double amount = AmountOf(bond);
        var policy = p.GetValueOrDefault("splitPolicy") as D ?? SlashSplitPolicy;
        var dest = new D
        {
            ["challengerAccount"] = p.GetValueOrDefault("challengerAccount"),
            ["victimAccount"] = p.GetValueOrDefault("compensationAccount") ?? BondSettlement.CompensationPoolAccount,
            ["treasuryAccount"] = treasury,
        };
        var split = BondSettlement.ComputeSlashSplit(amount, policy, dest);
        var moves = new L { Mv(Escrow, "debit", amount) }; // the full bond leaves escrow
        if (!string.IsNullOrEmpty(split.ChallengerAccount) && split.ChallengerReward > 0) moves.Add(Mv(split.ChallengerAccount, "credit", split.ChallengerReward));
        if (split.VictimCompensation > 0) moves.Add(Mv(split.VictimAccount, "credit", split.VictimCompensation));
        if (split.TreasuryRemainder > 0) moves.Add(Mv(split.TreasuryAccount, "credit", split.TreasuryRemainder));
        var b = Base(claimId, "slash", amount, Escrow, treasury, now, evidenceDigest);
        b["split"] = split.ToJson();
        return Plan(claimId, "open", "slashed", moves, SignRecord(b));
    }

    /// <summary>Open (lock) a bond: refuses an unaffordable bond, one below <c>bondAmount(policy, exposure)</c>, one that breaches the depositor's caps and a double-open. <paramref name="exposure"/> and
    /// <paramref name="window"/> may be null. The bond moves from the depositor into escrow.</summary>
    public D PlanOpen(IBondView view, string claimId, double amount, string depositor, double? exposure, double now, D? window)
    {
        if (string.IsNullOrEmpty(claimId)) throw new InvalidOperationException("openBond: claimId is required");
        if (!double.IsFinite(amount) || amount <= 0) throw new InvalidOperationException("openBond: amount must be a positive finite number");
        if (string.IsNullOrEmpty(depositor)) throw new InvalidOperationException("openBond: depositor is required");
        if (view.Bond(claimId) != null) throw new InvalidOperationException($"openBond: bond {claimId} already exists (double-open refused)");

        double required = BondSettlement.BondAmount(BondPolicy, exposure ?? 0);
        if (!(amount >= required)) throw new InvalidOperationException($"openBond: amount {JsCanon.NumberString(amount)} is below the required bond {JsCanon.NumberString(required)}");
        var (count, sum) = view.OpenTotals(depositor);
        double maxClaims = IntentJs.NumOf(BondPolicy.GetValueOrDefault("maxOpenClaims")) ?? double.NaN, maxAmount = IntentJs.NumOf(BondPolicy.GetValueOrDefault("maxOpenAmount")) ?? double.NaN;
        if (!(count + 1 <= maxClaims)) throw new InvalidOperationException("openBond: depositor open-claim cap reached");
        if (!(double.IsFinite(sum + amount) && sum + amount <= maxAmount)) throw new InvalidOperationException("openBond: depositor aggregate open-bond cap exceeded");
        if (!(double.IsFinite(view.BalanceOf(depositor)) && view.BalanceOf(depositor) >= amount)) throw new InvalidOperationException("openBond: insufficient balance for the bond");

        var record = SignRecord(Base(claimId, "open", amount, depositor, Escrow, now, ""));
        var open = new D
        {
            ["amount"] = StoreJs.Number(amount), ["depositor"] = depositor, ["maxOpenClaims"] = BondPolicy.GetValueOrDefault("maxOpenClaims"), ["maxOpenAmount"] = BondPolicy.GetValueOrDefault("maxOpenAmount"),
        };
        if (window != null) open["window"] = window;
        var p = Plan(claimId, "none", "open", new L { Mv(depositor, "debit", amount), Mv(Escrow, "credit", amount) }, record); // collateral is really taken
        p["open"] = open;
        return p;
    }

    /// <summary>Release a bond back to its depositor after an unchallenged window; refuses a missing or already settled bond.</summary>
    public D PlanRelease(IBondView view, string claimId, double now)
    {
        var bond = view.Bond(claimId) ?? throw new InvalidOperationException($"releaseBond: no bond for {claimId}");
        if (bond.GetValueOrDefault("status") as string != "open") throw new InvalidOperationException($"releaseBond: bond {claimId} is already {bond.GetValueOrDefault("status")} (double-settle refused)");
        double amount = AmountOf(bond);
        var depositor = (string)bond["depositor"]!;
        return Plan(claimId, "open", "released", new L { Mv(Escrow, "debit", amount), Mv(depositor, "credit", amount) }, SignRecord(Base(claimId, "release", amount, Escrow, depositor, now, "")));
    }

    /// <summary>Slash against a VERIFIED fraud verdict; re-runs the Policy VM itself. <paramref name="p"/>: claimId, claim, fraudProof, grant, openSnapshot, treasury, and optionally
    /// challengerAccount, compensationAccount, splitPolicy.</summary>
    public D PlanSlash(IBondView view, D p, double now)
    {
        var claimId = StringParam(p, "claimId");
        var bond = OpenBondOrThrow(view, "slashBond", claimId);
        NeedTreasury(p, "slashBond");
        var claim = ClaimOf(p);
        if (!Equals(claim.GetValueOrDefault("bond_ref"), claimId)) throw new InvalidOperationException("slashBond: claim.bond_ref does not match claimId");
        var verdict = Optimistic.VerifyFraudProof(claim, p.GetValueOrDefault("fraudProof"), p.GetValueOrDefault("grant"), p.GetValueOrDefault("openSnapshot"));
        if (verdict.GetValueOrDefault("fraudulent") is not true || !Equals(verdict.GetValueOrDefault("slashBondRef"), claimId))
            throw new InvalidOperationException($"slashBond: refused — no verified fraud verdict slashing {claimId} ({verdict.GetValueOrDefault("reason")})");
        return SlashPlan(bond, claimId!, now, BondSettlement.SettlementEvidenceDigest(claim, verdict), p);
    }

    /// <summary>Slash because a capability in the claim's chain was revoked after the bond opened (server-derived evidence). <paramref name="p"/> adds revokedCapId.</summary>
    public D PlanSlashOnRevocation(IBondView view, D p, double now)
    {
        var claimId = StringParam(p, "claimId");
        var bond = OpenBondOrThrow(view, "slashBondOnRevocation", claimId);
        NeedTreasury(p, "slashBondOnRevocation");
        var claim = ClaimOf(p);
        if (!Equals(claim.GetValueOrDefault("bond_ref"), claimId)) throw new InvalidOperationException("slashBondOnRevocation: claim.bond_ref does not match claimId");
        var revoked = StringParam(p, "revokedCapId");
        if (string.IsNullOrEmpty(revoked)) throw new InvalidOperationException("slashBondOnRevocation: revokedCapId is required");
        return SlashPlan(bond, claimId!, now, BondSettlement.RevocationEvidenceDigest(claim, revoked), p);
    }

    static ObjectiveOracle? OracleOf(D p) => p.GetValueOrDefault("oracle") as ObjectiveOracle;

    static double? RMargin(D p) => IntentJs.NumOf(p.GetValueOrDefault("rMargin"));

    /// <summary>Slash the AGENT's bond because a dispute proved it understated a risk input; re-runs the adjudication itself. <paramref name="p"/> adds dispute, oracle (an <see cref="ObjectiveOracle"/>), rMargin?.</summary>
    public D PlanSlashOnDispute(IBondView view, D p, double now)
    {
        var claimId = StringParam(p, "claimId");
        var bond = OpenBondOrThrow(view, "slashBondOnDispute", claimId);
        NeedTreasury(p, "slashBondOnDispute");
        var claim = ClaimOf(p);
        if (!Equals(claim.GetValueOrDefault("bond_ref"), claimId)) throw new InvalidOperationException("slashBondOnDispute: claim.bond_ref does not match claimId");
        var verdict = Optimistic.AdjudicateDispute(claim, p.GetValueOrDefault("dispute"), p.GetValueOrDefault("grant"), p.GetValueOrDefault("openSnapshot"), OracleOf(p), RMargin(p));
        if (verdict.GetValueOrDefault("outcome") as string != "agent-fraud" || verdict.GetValueOrDefault("fraudulent") is not true || !Equals(verdict.GetValueOrDefault("slashBondRef"), claimId))
            throw new InvalidOperationException($"slashBondOnDispute: refused — no verified agent-fraud verdict slashing {claimId} ({verdict.GetValueOrDefault("outcome")}: {verdict.GetValueOrDefault("reason")})");
        return SlashPlan(bond, claimId!, now, BondSettlement.DisputeEvidenceDigest(claim, verdict), p);
    }

    /// <summary>Slash the CHALLENGER's counter-bond because the dispute was frivolous (anti-griefing); an anonymous slash, 100% to the treasury. <paramref name="p"/>: counterBondId, claim, dispute, grant,
    /// openSnapshot, oracle, treasury.</summary>
    public D PlanSlashCounterBond(IBondView view, D p, double now)
    {
        var counterBondId = StringParam(p, "counterBondId");
        var bond = (counterBondId == null ? null : view.Bond(counterBondId)) ?? throw new InvalidOperationException($"slashCounterBond: no counter-bond for {counterBondId}");
        if (bond.GetValueOrDefault("status") as string != "open") throw new InvalidOperationException($"slashCounterBond: counter-bond {counterBondId} is already {bond.GetValueOrDefault("status")} (double-settle refused)");
        NeedTreasury(p, "slashCounterBond");
        var claim = ClaimOf(p);
        var verdict = Optimistic.AdjudicateDispute(claim, p.GetValueOrDefault("dispute"), p.GetValueOrDefault("grant"), p.GetValueOrDefault("openSnapshot"), OracleOf(p), RMargin(p));
        if (verdict.GetValueOrDefault("outcome") as string != "claim-upheld" || verdict.GetValueOrDefault("slashCounterBond") is not true)
            throw new InvalidOperationException($"slashCounterBond: refused — the dispute is not frivolous ({verdict.GetValueOrDefault("outcome")}: {verdict.GetValueOrDefault("reason")})");
        var q = new D
        {
            ["treasury"] = p.GetValueOrDefault("treasury"), ["challengerAccount"] = null, ["compensationAccount"] = p.GetValueOrDefault("compensationAccount"), ["splitPolicy"] = p.GetValueOrDefault("splitPolicy"),
        };
        return SlashPlan(bond, counterBondId!, now, BondSettlement.DisputeEvidenceDigest(claim, verdict), q);
    }
}

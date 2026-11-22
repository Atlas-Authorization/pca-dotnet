// The pure accounting of bond settlement (the reference bond-settlement module): exact micro-unit money arithmetic, the slash split, bond sizing, the evidence digests a signed
// settlement record commits to, record verification and anchoring, and the finite insurance capital pool. INTERNAL ACCOUNTING ONLY: no money moves. Policies and records are JSON
// trees; amounts are doubles on the micro grid. See BondSettlementPlanner for the signing half and StoreBondLedger for the durable ledger.
using System.Globalization;
using System.Numerics;
using System.Security.Cryptography;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca;

/// <summary>The exact division of one slashed bond: the three payouts sum EXACTLY to <see cref="Amount"/>. <see cref="ChallengerAccount"/> is the identified challenger's payout account;
/// <see cref="HasChallengerAccount"/> with a null account is an anonymous challenge (the whole bond goes to the treasury).</summary>
public sealed record SlashSplit(double Amount, double ChallengerReward, double VictimCompensation, double TreasuryRemainder, string? ChallengerAccount, bool HasChallengerAccount,
    string VictimAccount, string TreasuryAccount)
{
    /// <summary>The reference object (the <c>split</c> of a slash record).</summary>
    public D ToJson()
    {
        var m = new D
        {
            ["amount"] = StoreJs.Number(Amount), ["challengerReward"] = StoreJs.Number(ChallengerReward), ["victimCompensation"] = StoreJs.Number(VictimCompensation),
            ["treasuryRemainder"] = StoreJs.Number(TreasuryRemainder),
        };
        if (HasChallengerAccount) m["challengerAccount"] = ChallengerAccount;
        m["victimAccount"] = VictimAccount;
        m["treasuryAccount"] = TreasuryAccount;
        return m;
    }
}

public static class BondSettlement
{
    /// <summary>The default escrow account label.</summary>
    public const string EscrowAccount = "escrow";
    /// <summary>The default victim-compensation pool account (it contains ':', so it can never be a challenger payout account).</summary>
    public const string CompensationPoolAccount = "pca:pool:compensation";
    /// <summary>Micro-units per whole unit.</summary>
    public const long MicrosPerUnit = 1_000_000;
    /// <summary>Domain-separated tag of the settlement transparency leaf.</summary>
    public const string SettlementLeafDomain = "atlas-pca/settlement-leaf/v1";

    const double MaxSafeMicros = 1e15;
    static readonly double MinShareQuantum = Math.Pow(2, -30);

    /// <summary>The conservative reference split: challenger 50%, victim pool 40%, treasury the remainder. Tunable, not a product decision.</summary>
    public static D DefaultSlashSplitPolicy => new() { ["challengerBps"] = IntentJs.OfLong(5000), ["victimBps"] = IntentJs.OfLong(4000) };

    /// <summary><c>{floor: 1, k: 1, maxOpenClaims: 100, maxOpenAmount: Infinity}</c> (no curve: linear).</summary>
    public static D DefaultBondPolicy => new()
    {
        ["floor"] = IntentJs.OfLong(1), ["k"] = IntentJs.OfLong(1), ["maxOpenClaims"] = IntentJs.OfLong(100), ["maxOpenAmount"] = StoreJs.Number(double.PositiveInfinity),
    };

    // ---- exact money ----

    /// <summary>Integer micro-units of <paramref name="x"/> when it is a micro-grid amount below 1e15 micros, else null.</summary>
    public static long? ToMicros(double x) => BondDoc.ToMicros(x);

    /// <summary>The number for an integer micro-unit amount (round-trips through <see cref="ToMicros"/>).</summary>
    public static double FromMicros(long m) => (double)m / MicrosPerUnit;

    /// <summary>Snap a computed amount UP onto the micro grid (a bond is never rounded down: under-collateralisation is the unsafe direction); float noise below 1e-3 micro-units is absorbed.</summary>
    public static double QuantizeUp(double x)
    {
        if (!double.IsFinite(x) || x <= 0) return x;
        double scaled = x * MicrosPerUnit;
        if (scaled > MaxSafeMicros) return x;
        double r = Math.Floor(scaled + 0.5); // JavaScript Math.round
        double m = r / MicrosPerUnit == x || Math.Abs(scaled - r) <= 1e-3 ? r : Math.Ceiling(scaled);
        return m / MicrosPerUnit;
    }

    /// <summary><paramref name="a"/> + sign * <paramref name="b"/> in exact micro-unit integers when both are micro-grid amounts; plain float otherwise.</summary>
    public static double ExactAdd(double a, double b, int sign) => BondDoc.ExactAdd(a, b, sign);

    // ---- slash split ----

    static bool IsInteger(double? v) => v is double d && double.IsFinite(d) && d == Math.Floor(d);

    static void AssertSplitPolicy(D? p)
    {
        double sum = 0;
        foreach (var k in new[] { "challengerBps", "victimBps" })
        {
            double? v = p == null ? null : IntentJs.NumOf(p.GetValueOrDefault(k));
            if (!IsInteger(v) || v < 0 || v > 10_000) throw new InvalidOperationException($"slash split: {k} must be an integer in [0,10000]");
            sum += v!.Value;
        }
        if (sum > 10_000) throw new InvalidOperationException("slash split: challengerBps + victimBps must not exceed 10000");
    }

    static long ShareMicros(long micros, double bps) => (long)(new BigInteger(micros) * new BigInteger(bps) / 10_000);

    static double ShareQuantum(double amount)
    {
        double u = Math.BitIncrement(amount) - amount; // the exact power-of-two unit in the last place of a positive finite double
        return amount == Math.Floor(amount) ? Math.Max(1, u) : Math.Max(MinShareQuantum, u);
    }

    static double ShareOf(double amount, double bps, double quantum) => Math.Floor(amount * bps / 10_000 / quantum) * quantum;

    /// <summary>The challenger / victim / treasury division of a slashed <paramref name="amount"/>. Exact (treasury = amount - challenger - victim) and integer-safe. <paramref name="dest"/> carries
    /// <c>challengerAccount</c> (a string, or an explicit null for an anonymous challenge, which pays the whole bond to the treasury), <c>victimAccount</c> and <c>treasuryAccount</c>.</summary>
    public static SlashSplit ComputeSlashSplit(double amount, D policy, D dest)
    {
        if (!double.IsFinite(amount) || amount <= 0) throw new InvalidOperationException("computeSlashSplit: amount must be a positive finite number");
        AssertSplitPolicy(policy);
        if (dest.GetValueOrDefault("victimAccount") is not string { Length: > 0 } victim) throw new InvalidOperationException("computeSlashSplit: victimAccount is required");
        if (dest.GetValueOrDefault("treasuryAccount") is not string { Length: > 0 } treasury) throw new InvalidOperationException("computeSlashSplit: treasuryAccount is required");
        bool has = dest.ContainsKey("challengerAccount");
        var ch = dest.GetValueOrDefault("challengerAccount");
        var chAcct = ch as string;
        if (has && ch == null) return new SlashSplit(amount, 0, 0, amount, null, true, victim, treasury); // anonymous: 100% treasury, no pool pre-funding
        long? micros = amount == Math.Floor(amount) ? null : ToMicros(amount); // integer bonds keep whole-unit shares
        double cbps = IntentJs.NumOf(policy["challengerBps"])!.Value, vbps = IntentJs.NumOf(policy["victimBps"])!.Value;
        if (micros is long mi)
        {
            long c = ShareMicros(mi, cbps), v = ShareMicros(mi, vbps);
            long t = mi - c - v; // >= 0 because challengerBps + victimBps <= 10000
            return new SlashSplit(FromMicros(mi), FromMicros(c), FromMicros(v), FromMicros(t), chAcct, has, victim, treasury);
        }
        // outside the exact micro range (huge or sub-micro): the dyadic-grid float split
        double q = ShareQuantum(amount);
        double challengerReward = Math.Min(ShareOf(amount, cbps, q), amount);
        double victimCompensation = Math.Min(ShareOf(amount, vbps, q), amount - challengerReward);
        double treasuryRemainder = amount - challengerReward - victimCompensation;
        return new SlashSplit(amount, challengerReward, victimCompensation, treasuryRemainder, chAcct, has, victim, treasury);
    }

    // ---- bond sizing ----

    static double Dnum(object? o) => IntentJs.NumOf(o) ?? double.NaN;

    /// <summary>The largest gamma of the power curve.</summary>
    internal const double PowerCurveMaxGamma = 64;

    /// <summary>e^gamma for gamma a multiple of 1/8 in [1, 64] by operations every platform computes identically (a bond amount is money, and Pow is not correctly rounded):
    /// with gamma = n/8, e is multiplied in floor(n/8) times one multiplication at a time, then the square roots s1, s2, s3 of e are multiplied in for the bits 4, 2 and 1 of n mod 8,
    /// in that order. A gamma that is not a multiple of 1/8 (or above 64) is refused, never rounded.</summary>
    internal static double PowEighths(double e, double gamma)
    {
        double n = gamma * 8;
        if (!(n == Math.Floor(n) && !double.IsInfinity(n) && gamma <= PowerCurveMaxGamma)) throw new InvalidOperationException("bondAmount: power curve gamma must be a multiple of 1/8 and at most 64");
        double r = 1;
        long whole = (long)Math.Floor(n / 8);
        for (long i = 0; i < whole; i++) r = r * e;
        long f = (long)(n % 8);
        double s1 = Math.Sqrt(e), s2 = Math.Sqrt(s1), s3 = Math.Sqrt(s2);
        if ((f & 4) != 0) r = r * s1;
        if ((f & 2) != 0) r = r * s2;
        if ((f & 1) != 0) r = r * s3;
        return r;
    }

    static double CurveComponent(D? curve, double k, double e)
    {
        var kind = curve?.GetValueOrDefault("kind");
        if (curve == null || kind as string == "linear") return k * e;
        if (kind as string == "power")
        {
            double gamma = Dnum(curve.GetValueOrDefault("gamma"));
            if (!(double.IsFinite(gamma) && gamma >= 1)) throw new InvalidOperationException("bondAmount: power curve requires finite gamma >= 1");
            return k * PowEighths(e, gamma);
        }
        if (curve.GetValueOrDefault("tiers") is not L { Count: > 0 } tiers) throw new InvalidOperationException("bondAmount: piecewise curve requires at least one tier");
        double acc = 0, prevUpTo = 0, prevMarginal = 0;
        foreach (var to in tiers)
        {
            if (to is not D tier) throw new InvalidOperationException("bondAmount: malformed tier");
            double upTo = Dnum(tier.GetValueOrDefault("upTo")), mk = Dnum(tier.GetValueOrDefault("marginalK"));
            if (!(double.IsFinite(upTo) && upTo > prevUpTo) && upTo != double.PositiveInfinity) throw new InvalidOperationException("bondAmount: piecewise tier `upTo` must be strictly increasing");
            if (!(double.IsFinite(mk) && mk >= 0)) throw new InvalidOperationException("bondAmount: piecewise `marginalK` must be a finite number >= 0");
            if (mk < prevMarginal) throw new InvalidOperationException("bondAmount: piecewise marginal rates must be non-decreasing (convex)");
            double width = Math.Min(e, upTo) - prevUpTo;
            if (width > 0) acc += width * mk;
            prevUpTo = upTo;
            prevMarginal = mk;
            if (e <= upTo) break;
        }
        if (e > prevUpTo) acc += (e - prevUpTo) * prevMarginal; // beyond the last tier: extend its marginal rate
        return k * acc;
    }

    /// <summary><c>max(floor, curve(k, exposure))</c> snapped up onto the micro grid; no curve is linear. A non-finite or non-positive exposure gives the floor.</summary>
    public static double BondAmount(D policy, double exposure)
    {
        double e = double.IsFinite(exposure) && exposure > 0 ? exposure : 0;
        return QuantizeUp(JsMax(Dnum(policy.GetValueOrDefault("floor")), CurveComponent(policy.GetValueOrDefault("curve") as D, Dnum(policy.GetValueOrDefault("k")), e)));
    }

    /// <summary>Math.max: NaN when either is NaN.</summary>
    static double JsMax(double a, double b) => double.IsNaN(a) || double.IsNaN(b) ? double.NaN : Math.Max(a, b);

    // ---- evidence digests ----

    /// <summary>The lenient canonical bytes of the reference (server-only digests: no exponent or digit-count limit on numbers); throws when a value cannot be canonicalized.</summary>
    internal static byte[] LenientBytes(object? v) => System.Text.Encoding.UTF8.GetBytes(JsCanon.Lenient(v) ?? throw new InvalidOperationException("canonicalize: unsupported value"));

    /// <summary>The reference <c>hashCanonicalLenient</c>: base64url(SHA-256(lenient canonical bytes)).</summary>
    internal static string HashLenient(object? v) => Pca.B64u(Pca.Sha(LenientBytes(v)));

    /// <summary>The claim identity <c>{claimDigest, bond_ref}</c>; a member the claim lacks is left out (JavaScript <c>undefined</c> is not serialized).</summary>
    static D ClaimIdentity(D claim)
    {
        var m = new D();
        if (claim.TryGetValue("pcactn_digest", out var d)) m["claimDigest"] = d;
        if (claim.TryGetValue("bond_ref", out var b)) m["bond_ref"] = b;
        return m;
    }

    /// <summary>Copy <paramref name="keys"/> of <paramref name="from"/> into <paramref name="to"/>: absent members stay absent, or become null with <paramref name="nullish"/> (<c>x ?? null</c>).</summary>
    static void Take(D to, D from, bool nullish, params string[] keys)
    {
        foreach (var k in keys)
            if (from.TryGetValue(k, out var v) && (v != null || !nullish)) to[k] = v;
            else if (nullish) to[k] = null;
            else if (from.ContainsKey(k)) to[k] = null;
    }

    /// <summary>Binds a slash to the server-derived fraud verdict (<c>fraudulent</c>, <c>slashBondRef</c>, <c>reason</c>): never to challenger-supplied fields.</summary>
    public static string SettlementEvidenceDigest(D claim, D fraudVerdict)
    {
        var m = ClaimIdentity(claim);
        Take(m, fraudVerdict, false, "fraudulent");
        Take(m, fraudVerdict, true, "slashBondRef");
        Take(m, fraudVerdict, false, "reason");
        return HashLenient(m);
    }

    /// <summary>Evidence digest of a revocation slash (a capability in the claim's chain was revoked after the bond opened).</summary>
    public static string RevocationEvidenceDigest(D claim, string revokedCapId)
    {
        var m = ClaimIdentity(claim);
        m["kind"] = "revocation";
        m["revokedCapId"] = revokedCapId;
        return HashLenient(m);
    }

    /// <summary>Evidence digest of a dispute-game slash: the adjudicator's own verdict, never a challenger assertion.</summary>
    public static string DisputeEvidenceDigest(D claim, D verdict)
    {
        var m = ClaimIdentity(claim);
        m["kind"] = "dispute";
        Take(m, verdict, false, "outcome", "input");
        Take(m, verdict, true, "agentValue", "oracleValue", "slashBondRef");
        Take(m, verdict, false, "reason");
        return HashLenient(m);
    }

    // ---- verification and anchoring ----

    /// <summary>The bytes a settlement record signs: the domain, then the canonical body without <c>sig</c> and <c>pq_sig</c> (<c>alg</c> and <c>pq_pk</c> stay in).</summary>
    internal static byte[] SettlementMessage(D body) => Pca.Cat(IntentJs.Utf8(Optimistic.SettlementDomain), LenientBytes(body));

    /// <summary>Verify a settlement record's signature under the guardian public key; suite-agile (a PQ half needs a pin in <paramref name="pins"/>). Never throws.</summary>
    public static bool VerifySettlement(object? record, string guardianPublicKey, IReadOnlyDictionary<string, string>? pins = null)
    {
        try
        {
            if (record is not D r) return false;
            var body = r.Where(kv => kv.Key is not ("sig" or "pq_sig")).ToDictionary(kv => kv.Key, kv => kv.Value);
            if (r.GetValueOrDefault("sig") is not string || IntentJs.SuiteOf(r.GetValueOrDefault("alg"), r.ContainsKey("alg")) == null) return false;
            return IntentJs.VerifyPinnedSuite(r.GetValueOrDefault("alg"), r.ContainsKey("alg"), guardianPublicKey, r.GetValueOrDefault("pq_pk"), SettlementMessage(body), r["sig"], r.GetValueOrDefault("pq_sig"), pins);
        }
        catch (Exception) { return false; }
    }

    /// <summary>Canonical digest of a signed settlement record (the whole record, signature included).</summary>
    public static string SettlementRecordDigest(D record) => HashLenient(new D { ["t"] = SettlementLeafDomain, ["record"] = record });

    /// <summary>The salted commitment of a settlement record (the opaque transparency-log leaf).</summary>
    public static string SettlementCommit(string salt, D record)
    {
        if (string.IsNullOrEmpty(salt)) throw new ArgumentException("settlementCommit: salt must be a non-empty string");
        return HashLenient(new D { ["salt"] = salt, ["settlement_digest"] = SettlementRecordDigest(record) });
    }

    /// <summary>True iff <paramref name="salt"/> and <paramref name="record"/> reproduce the anchored <paramref name="commit"/>. Never throws.</summary>
    public static bool VerifySettlementCommit(string? commit, string? salt, D? record)
    {
        try { return SettlementCommit(salt!, record!) == commit; }
        catch (Exception) { return false; }
    }

    /// <summary>Append a settlement record as a salted commitment through <paramref name="append"/> (it takes the commit and returns the 0-based leaf index; for example a transparency ledger's
    /// <c>AppendCommitment</c>). Returns <c>{index, commit, salt}</c>; the caller retains the salt to open the leaf later. A null <paramref name="salt"/> draws 16 random bytes.</summary>
    public static D AppendSettlement(Func<string, long> append, D record, string? salt = null)
    {
        var s = salt ?? Pca.B64u(RandomNumberGenerator.GetBytes(16));
        var commit = SettlementCommit(s, record);
        var index = append(commit);
        return new D { ["index"] = IntentJs.OfLong(index), ["commit"] = commit, ["salt"] = s };
    }

    /// <summary>True iff <paramref name="s"/> is a bond store (the reference <c>isBondStore</c>).</summary>
    public static bool IsBondStore(object? s) => s is IBondStore;
}

/// <summary>An immutable snapshot of the pool's accounting. Invariant: <c>Initial + PremiumsIn - PayoutsOut == Balance</c>.</summary>
public sealed record InsurancePoolState(double Initial, double PremiumsIn, double PayoutsOut, double Balance)
{
    public D ToJson() => new()
    {
        ["initial"] = StoreJs.Number(Initial), ["premiumsIn"] = StoreJs.Number(PremiumsIn), ["payoutsOut"] = StoreJs.Number(PayoutsOut), ["balance"] = StoreJs.Number(Balance),
    };
}

/// <summary>Prices coverage of <c>exposure</c> for a reputation: <c>{premium, declined, ...}</c> (the reference <c>priceCoverage</c>).</summary>
public delegate D CoveragePricer(object? reputation, double exposure, D? options);

/// <summary>A finite, fail-closed insurance capital pool (scarce collateral). Premiums are credited; victim payouts are debited and REFUSED when they exceed the free capital. The three ledgers
/// (initial, premiums in, payouts out) always reconcile to the balance exactly. Pricing is a <see cref="CoveragePricer"/> given at construction; <see cref="CollectPremium(D)"/> takes an
/// already priced quote.</summary>
public sealed class InsuranceCapitalPool
{
    readonly double _initial;
    readonly CoveragePricer? _pricer;
    readonly object _lock = new();
    double _premiumsIn, _payoutsOut;

    public InsuranceCapitalPool(double initial = 0, CoveragePricer? pricer = null)
    {
        if (!double.IsFinite(initial) || initial < 0) throw new InvalidOperationException("InsuranceCapitalPool: initial capital must be a non-negative finite number");
        _initial = initial;
        _pricer = pricer;
    }

    public double Balance { get { lock (_lock) return _initial + _premiumsIn - _payoutsOut; } }
    public double PremiumsIn { get { lock (_lock) return _premiumsIn; } }
    public double PayoutsOut { get { lock (_lock) return _payoutsOut; } }

    /// <summary>The current accounting snapshot (the conservation invariant holds over it).</summary>
    public InsurancePoolState State()
    {
        lock (_lock) return new InsurancePoolState(_initial, _premiumsIn, _payoutsOut, _initial + _premiumsIn - _payoutsOut);
    }

    /// <summary>Price coverage of <paramref name="exposure"/> for <paramref name="reputation"/> WITHOUT mutating the pool.</summary>
    public D Quote(object? reputation, double exposure, D? options = null) =>
        (_pricer ?? throw new InvalidOperationException("InsuranceCapitalPool: no coverage pricer was given")).Invoke(reputation, exposure, options);

    /// <summary>Price coverage and, if not declined, credit the premium. A declined quote credits nothing. Returns <c>{pricing, state}</c>.</summary>
    public D CollectPremium(object? reputation, double exposure, D? options = null) => CollectPremium(Quote(reputation, exposure, options));

    /// <summary>Credit the premium of an already priced quote (<c>{premium, declined}</c>); a declined quote credits nothing. Returns <c>{pricing, state}</c>.</summary>
    public D CollectPremium(D pricing)
    {
        lock (_lock)
        {
            double premium = Dnum(pricing.GetValueOrDefault("premium"));
            if (pricing.GetValueOrDefault("declined") is not true && premium > 0)
            {
                if (!double.IsFinite(premium) || premium < 0) throw new InvalidOperationException("collectPremium: priced premium is not a non-negative finite number");
                _premiumsIn += premium;
            }
            return new D { ["pricing"] = pricing, ["state"] = State().ToJson() };
        }
    }

    static double Dnum(object? o) => IntentJs.NumOf(o) ?? double.NaN;

    /// <summary>True iff the pool currently holds at least <paramref name="amount"/> of free capital.</summary>
    public bool CanCover(double amount) => double.IsFinite(amount) && amount >= 0 && double.IsFinite(Balance) && Balance >= amount;

    /// <summary>Pay <paramref name="amount"/> of victim compensation out of the pool. REFUSED (throws) when it is non-positive, non-finite or above the free capital: the pool never pays what it does not hold.</summary>
    public InsurancePoolState PayClaim(double amount)
    {
        lock (_lock)
        {
            if (!double.IsFinite(amount) || amount <= 0) throw new InvalidOperationException("payClaim: amount must be a positive finite number");
            double balance = _initial + _premiumsIn - _payoutsOut;
            if (!(double.IsFinite(balance) && amount <= balance)) throw new InvalidOperationException($"payClaim: insufficient pool capital (need {JsCanon.NumberString(amount)}, have {JsCanon.NumberString(balance)})");
            _payoutsOut += amount;
            return State();
        }
    }
}

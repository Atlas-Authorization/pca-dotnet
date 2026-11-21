using JD = System.Collections.Generic.Dictionary<string, object?>;

namespace AtlasPca;

/// <summary>A verdict of the beacon checks: <c>Ok</c>, or the <c>Reason</c> it was refused.</summary>
public sealed record BeaconVerdict(bool Ok, string? Reason = null);

/// <summary>What <see cref="Beacons.Verify"/> checks a beacon against: the pinned issuer keys, the clock, the instance and (optionally) the grant the beacon must cover.</summary>
public sealed class BeaconCheck
{
    /// <summary>The pinned issuer keys (b64u Ed25519 identities): the grant's principal and/or the operator or guardian.</summary>
    public IReadOnlyList<string> Issuers { get; set; } = Array.Empty<string>();
    public double Now { get; set; }
    public string Instance { get; set; } = "";
    /// <summary>The grant being exercised: the beacon's scope must be <c>*</c> or equal this. Null: not checked.</summary>
    public string? Scope { get; set; }
    /// <summary>PQ keys by issuer identity; a pure-PQ or hybrid beacon verifies only under these.</summary>
    public IReadOnlyDictionary<string, string>? PqPins { get; set; }
}

/// <summary>The dead-man liveness beacon of one authorization (<see cref="AuthorizeInput.Beacon"/>): the beacon, the issuers pinned for it and the highest sequence already accepted.</summary>
public sealed record BeaconPresented(object? Beacon, IReadOnlyList<string> Issuers, string Instance, long? LastAcceptedSeq = null, IReadOnlyDictionary<string, string>? PqPins = null);

/// <summary>Dead-man liveness beacons v2 and the global kill switch. An issuer (the grant's principal, or the operator or guardian) signs short-lived beacons
/// <c>{v, instance, scope, epoch, seq, issued_at, not_after, issuer}</c>; authority is live only while a valid beacon covers the current moment, so an issuer that
/// stops issuing freezes every agent by the next epoch. A beacon binds an instance, enforces a strictly increasing <c>seq</c> and has a hard maximum validity.
/// The PCActn commits a beacon through its signed <c>freshness.beacon_ref</c> (<see cref="Ref"/>). Everything here is total: a fault is a refusal.</summary>
public static class Beacons
{
    public const string GlobalScope = "*";
    public const string Domain = "atlas-pca/beacon/v2\0";
    public const long EpochMs = 60_000;
    /// <summary>The hard ceiling on <c>not_after - issued_at</c>: no issuer can mint a longer-lived beacon.</summary>
    public const long MaxValidityMs = 60 * 60_000;
    public const long ClockSkewMs = 30_000;

    static bool IsInt(object? v) => IntentJs.NumOf(v) is double d && double.IsFinite(d) && Math.Floor(d) == d;

    static JD Body(JD b)
    {
        var body = new JD();
        foreach (var k in new[] { "v", "instance", "scope", "epoch", "seq", "issued_at", "not_after", "issuer" }) body[k] = b.GetValueOrDefault(k);
        return IntentJs.BindSuiteFields(body, b.GetValueOrDefault("alg"), b.ContainsKey("alg"), b.GetValueOrDefault("pq_pk"), b.ContainsKey("pq_pk"));
    }

    /// <summary>The signature, the pinned issuer, the instance and scope binding, the hard maximum validity and the freshness window. Never throws.</summary>
    public static BeaconVerdict Verify(object? beacon, BeaconCheck o)
    {
        try
        {
            if (beacon is not JD b || !(IntentJs.NumOf(b.GetValueOrDefault("v")) == 2) || IntentJs.SuiteOf(b) == null) return new(false, "malformed beacon");
            if (!Equals(b.GetValueOrDefault("instance"), o.Instance)) return new(false, "wrong instance");
            if (b.GetValueOrDefault("issuer") is not string issuer || !o.Issuers.Contains(issuer)) return new(false, "issuer not pinned");
            if (!IntentJs.VerifyPinnedSuite(b.GetValueOrDefault("alg"), b.ContainsKey("alg"), issuer, b.GetValueOrDefault("pq_pk"), IntentJs.Message(Domain, Body(b)),
                    b.GetValueOrDefault("sig"), b.GetValueOrDefault("pq_sig"), o.PqPins)) return new(false, "bad signature");
            if (!(IsInt(b.GetValueOrDefault("epoch")) && IsInt(b.GetValueOrDefault("seq")) && IsInt(b.GetValueOrDefault("issued_at")) && IsInt(b.GetValueOrDefault("not_after"))) || IntentJs.NumOf(b["seq"]) < 0)
                return new(false, "malformed window");
            double epoch = IntentJs.NumOf(b["epoch"])!.Value, issued = IntentJs.NumOf(b["issued_at"])!.Value, notAfter = IntentJs.NumOf(b["not_after"])!.Value;
            if (notAfter <= issued || notAfter - issued > MaxValidityMs) return new(false, "validity exceeds the hard maximum");
            if (epoch != Math.Floor(issued / EpochMs)) return new(false, "epoch does not match issued_at");
            if (o.Now + ClockSkewMs < issued) return new(false, "not yet valid");
            if (o.Now > notAfter) return new(false, "expired");
            if (o.Scope != null && !Equals(b.GetValueOrDefault("scope"), GlobalScope) && !Equals(b.GetValueOrDefault("scope"), o.Scope)) return new(false, "scope not covered");
            return new(true);
        }
        catch (Exception) { return new(false, "malformed beacon"); }
    }

    /// <summary>The stable reference of a beacon: what a PCActn commits in <c>freshness.beacon_ref</c>.</summary>
    public static string Ref(object? beacon) => Pca.HashCanonical(beacon);

    /// <summary>Monotonic acceptance: a beacon replaces the stored one only with a STRICTLY higher <c>seq</c>. <paramref name="prevSeq"/> is null when none is stored.</summary>
    public static BeaconVerdict Accept(double? prevSeq, object? next)
    {
        if (next is not JD n || !IntentJs.IsSafeInteger(n.GetValueOrDefault("seq")) || IntentJs.NumOf(n["seq"]) is not double seq || seq < 0 || IntentJs.IsNegZero(seq)) return new(false, "malformed beacon");
        if (prevSeq is double prev && !(seq > prev)) return new(false, $"replayed beacon: seq {JsCanon.NumberString(seq)} <= {JsCanon.NumberString(prev)}");
        return new(true);
    }

    /// <summary>Frozen unless at least one beacon verifies for (instance, scope, now). Absence is a freeze.</summary>
    public static bool IsFrozen(IEnumerable<object?> beacons, BeaconCheck o) => !beacons.Any(b => Verify(b, o).Ok);

    /// <summary>Issues a beacon signed by <paramref name="issuer"/> (any suite it can sign). The validity defaults to five epochs and may not exceed <see cref="MaxValidityMs"/>.</summary>
    public static JD Mint(SuiteKey issuer, string instance, long seq, long issuedAt, string? scope = null, long? validityMs = null)
    {
        var validity = validityMs ?? 5 * EpochMs;
        if (seq < 0) throw new ArgumentOutOfRangeException(nameof(seq), "issueLivenessBeacon: seq must be a non-negative integer");
        if (issuedAt < 0) throw new ArgumentOutOfRangeException(nameof(issuedAt), "issueLivenessBeacon: issuedAt must be an integer");
        if (validity <= 0 || validity > MaxValidityMs) throw new ArgumentOutOfRangeException(nameof(validityMs), $"issueLivenessBeacon: validity must be in (0, {MaxValidityMs}] ms");
        var body = new JD
        {
            ["v"] = 2L, ["instance"] = instance, ["scope"] = scope ?? GlobalScope, ["epoch"] = issuedAt / EpochMs, ["seq"] = seq, ["issued_at"] = issuedAt,
            ["not_after"] = issuedAt + validity, ["issuer"] = issuer.Id,
        };
        if (issuer.Alg != "ed25519") { body["alg"] = issuer.Alg; body["pq_pk"] = issuer.PqPk; }
        var n = AtlasPca.Issue.NormJ(body);
        var (sig, pqSig) = issuer.Sign(IntentJs.Message(Domain, n));
        n["sig"] = sig;
        if (pqSig != null) n["pq_sig"] = pqSig;
        return n;
    }

    /// <summary>The durable replay protection of beacons: the highest accepted <c>seq</c> per (instance, scope, issuer) in an <see cref="IAtomicKv"/>, under one atomic read-modify-write.</summary>
    public sealed class Acceptor
    {
        readonly IAtomicKv _kv;
        public Acceptor(IAtomicKv kv) { _kv = kv ?? throw new ArgumentException("createBeaconAcceptor: a durable key-value store is required"); }

        static string KeyOf(JD b) => "beacon-seq/v1/" + Pca.Canonicalize(new List<object?> { b.GetValueOrDefault("instance"), b.GetValueOrDefault("scope"), b.GetValueOrDefault("issuer") });

        /// <summary>Verifies <paramref name="beacon"/> against <paramref name="check"/>, then records its seq iff it is STRICTLY above the highest already accepted. A store that
        /// cannot decide, or holds a malformed value, refuses the beacon (<c>beacon state unavailable</c>). Never throws.</summary>
        public BeaconVerdict Accept(object? beacon, BeaconCheck check)
        {
            var v = Verify(beacon, check);
            if (!v.Ok) return v;
            var b = (JD)beacon!;
            var seq = IntentJs.NumOf(b["seq"])!.Value;
            double? replayOf = null;
            try
            {
                _kv.Update(KeyOf(b), prev =>
                {
                    replayOf = null;
                    if (prev != null)
                    {
                        if (!long.TryParse(prev, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var p) || p > Pca.MaxSafeInt) throw new FormatException("malformed stored seq");
                        if (!(seq > p)) { replayOf = p; return null; }
                    }
                    return ((long)seq).ToString(System.Globalization.CultureInfo.InvariantCulture);
                });
            }
            catch (Exception) { return new(false, "beacon state unavailable"); }
            return replayOf is double r ? new(false, $"replayed beacon: seq {JsCanon.NumberString(seq)} <= {JsCanon.NumberString(r)}") : new(true);
        }
    }
}

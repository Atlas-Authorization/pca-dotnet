// Dead-man liveness beacons v2 and the kill switch of the reference (beacons.ts) over the JSON tree: the signed message, issuing under the Ed25519, ML-DSA and hybrid suites, the reference hash, verification with
// the reference's reason texts (never a throw), replay acceptance, the frozen-liveness check and the durable acceptor that refuses replays across restarts. A beacon is <c>{v, instance, scope, epoch, seq, issued_at,
// not_after, issuer, sig, alg?, pq_pk?, pq_sig?}</c>; authority is live only while a valid beacon covers now. The typed Beacons class is the pipeline's own helper; this is the reference's surface.
using AtlasPca.Js;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca;

/// <summary>The durable replay protection: the highest accepted <c>seq</c> per (instance, scope, issuer) under one atomic read-modify-write of an <see cref="IAtomicKv"/>.</summary>
public sealed class BeaconAcceptor
{
    readonly IAtomicKv _kv;

    /// <summary>Throws without a store.</summary>
    public BeaconAcceptor(IAtomicKv? kv) { _kv = kv ?? throw new ArgumentException("createBeaconAcceptor: a DurableKv is required"); }

    static string KeyOf(D b) => "beacon-seq/v1/" + Pca.Canonicalize(new L { b.GetValueOrDefault("instance"), b.GetValueOrDefault("scope"), b.GetValueOrDefault("issuer") });

    /// <summary>The storage key of a beacon's sequence slot.</summary>
    public static string SlotKey(D b) => KeyOf(b);

    /// <summary>Verify <paramref name="beacon"/> against <paramref name="check"/>, then record its seq iff it is STRICTLY above the highest already accepted: <c>{ok}</c> or <c>{ok: false, reason}</c>. A store that cannot
    /// decide, or holds a malformed value (negative, fractional, unsafe, not a number), refuses the beacon (<c>beacon state unavailable</c>). Never throws.</summary>
    public D Accept(object? beacon, D check)
    {
        var v = BeaconOps.VerifyLivenessBeacon(beacon, check);
        if (v["ok"] is not true) return v;
        var b = (D)beacon!;
        var seq = IntentJs.NumOf(b["seq"])!.Value;
        object? replayOf = null;
        try
        {
            _kv.Update(KeyOf(b), prev =>
            {
                replayOf = null;
                if (prev != null)
                {
                    var p = Pca.ParseJson(prev);
                    if (!(IntentJs.IsSafeInteger(p) && IntentJs.NumOf(p)!.Value >= 0 && !IntentJs.IsNegZero(IntentJs.NumOf(p)!.Value))) throw new InvalidOperationException("malformed stored seq");
                    if (!(seq > IntentJs.NumOf(p)!.Value)) { replayOf = p; return null; }
                }
                return Pca.Canonicalize(b["seq"]);
            });
        }
        catch (Exception) { return new D { ["ok"] = false, ["reason"] = "beacon state unavailable" }; }
        return replayOf == null ? new D { ["ok"] = true } : new D { ["ok"] = false, ["reason"] = $"replayed beacon: seq {Pca.Canonicalize(b["seq"])} <= {Pca.Canonicalize(replayOf)}" };
    }
}

public static class BeaconOps
{
    public const string GlobalScope = "*";
    const string Domain = "atlas-pca/beacon/v2\0";
    public const double EpochMs = 60_000, MaxValidityMs = 60 * 60_000, ClockSkewMs = 30_000;

    static object Undef => AttestationSoft.Undef;

    /// <summary>The published constants of the module.</summary>
    public static D Constants() => new() { ["GLOBAL_SCOPE"] = GlobalScope, ["BEACON_EPOCH_MS"] = Facade.JsNumber(EpochMs), ["BEACON_MAX_VALIDITY_MS"] = Facade.JsNumber(MaxValidityMs), ["BEACON_CLOCK_SKEW_MS"] = Facade.JsNumber(ClockSkewMs) };

    static object? Member(D b, string k) => b.TryGetValue(k, out var v) ? v : throw new InvalidOperationException("canonicalize: unsupported type undefined");

    static byte[] Msg(D b)
    {
        var body = new D();
        foreach (var k in new[] { "v", "instance", "scope", "epoch", "seq", "issued_at", "not_after", "issuer" }) body[k] = Member(b, k);
        // every non-ed25519 suite carries its PQ key in the signed body: an absent pq_pk (JavaScript undefined) has no canonical form
        if (IntentJs.SuiteOf(b.GetValueOrDefault("alg"), b.ContainsKey("alg")) is { } suite && suite != "ed25519" && !b.ContainsKey("pq_pk")) throw new InvalidOperationException("canonicalize: unsupported type undefined");
        return IntentJs.Message(Domain, IntentJs.BindSuiteFields(body, b.GetValueOrDefault("alg"), b.ContainsKey("alg"), b.GetValueOrDefault("pq_pk"), b.ContainsKey("pq_pk")));
    }

    /// <summary><c>"atlas-pca/beacon/v2\0" || strictCanonical({v, instance, scope, epoch, seq, issued_at, not_after, issuer} + alg and pq_pk for a non-ed25519 suite)</c>. Throws on a missing member or a value the strict
    /// canonical form refuses.</summary>
    public static byte[] LivenessBeaconMessage(D body) => Msg(body);

    static bool IsInteger(object? x) => IntentJs.NumOf(x) is double d && double.IsFinite(d) && d == Math.Floor(d);

    /// <summary>Issue a beacon. <c>seq</c> and <c>issuedAt</c> must be non-negative integers; <c>validityMs</c> (null: five epochs) an integer in (0, 3600000]; <c>scope</c> null is <c>*</c>; <paramref name="alg"/> null is
    /// ed25519, another suite needs its PQ key in <paramref name="keys"/>. Throws on any violation and on a value the strict canonical form refuses.</summary>
    public static D IssueLivenessBeacon(byte[] issuerSecret, object? instance, object? scope, object? seq, object? issuedAt, object? validityMs = null, string? alg = null, SuiteSecretKeys? keys = null)
    {
        var validity = validityMs ?? Facade.JsNumber(5 * EpochMs);
        if (ReferenceEquals(instance, Undef)) throw new InvalidOperationException("canonicalize: unsupported type undefined"); // a missing instance (JavaScript undefined) has no canonical form
        if (!IsInteger(seq) || IntentJs.NumOf(seq)!.Value < 0) throw new ArgumentException("issueLivenessBeacon: seq must be a non-negative integer");
        if (!IsInteger(issuedAt) || IntentJs.NumOf(issuedAt)!.Value < 0) throw new ArgumentException("issueLivenessBeacon: issuedAt must be an integer");
        if (!IsInteger(validity) || IntentJs.NumOf(validity)!.Value <= 0 || IntentJs.NumOf(validity)!.Value > MaxValidityMs) throw new ArgumentException($"issueLivenessBeacon: validity must be in (0, {(long)MaxValidityMs}] ms");
        if (IntentJs.SuiteOf(alg, alg != null) is not { } resolved) throw new ArgumentException($"unknown signature alg '{alg}'");
        var pqPk = PqSuites.SuitePqPublicKey(alg, keys);
        double iat = IntentJs.NumOf(issuedAt)!.Value;
        using var key = EdKey.FromSeed(issuerSecret);
        var body = new D
        {
            ["v"] = IntentJs.OfLong(2), ["instance"] = instance, ["scope"] = scope ?? GlobalScope, ["epoch"] = Facade.JsNumber(Math.Floor(iat / EpochMs)), ["seq"] = seq, ["issued_at"] = issuedAt,
            ["not_after"] = Facade.JsNumber(iat + IntentJs.NumOf(validity)!.Value), ["issuer"] = key.Id,
        };
        if (resolved != "ed25519") { body["alg"] = resolved; if (pqPk != null) body["pq_pk"] = pqPk; }
        var fields = PqSuites.SignSuiteArtifact(alg, PqSuites.SuiteKeysOf(issuerSecret, keys), Msg(body));
        var o = new D(body) { ["sig"] = fields.Sig };
        if (fields.PqSig != null) o["pq_sig"] = fields.PqSig;
        return o;
    }

    /// <summary>The strict hash of the WHOLE beacon, signature included: what a PCActn commits as <c>freshness.beacon_ref</c>.</summary>
    public static string BeaconRef(object? beacon) => Pca.HashCanonical(beacon);

    static D No(string reason) => new() { ["ok"] = false, ["reason"] = reason };

    /// <summary>Verify a beacon against <c>check</c> = <c>{issuers, now, instance, scope?, pqPins?}</c>: <c>{ok}</c> or <c>{ok: false, reason}</c> (malformed beacon, wrong instance, issuer not pinned, bad signature,
    /// malformed window, validity exceeds the hard maximum, epoch does not match issued_at, not yet valid, expired, scope not covered). Never throws.</summary>
    public static D VerifyLivenessBeacon(object? beacon, D check)
    {
        try
        {
            if (beacon is not D b || IntentJs.NumOf(b.GetValueOrDefault("v")) != 2 || IntentJs.SuiteOf(b.GetValueOrDefault("alg"), b.ContainsKey("alg")) == null) return No("malformed beacon");
            if (!AttestationSoft.Seq(AttestationSoft_G(b, "instance"), AttestationSoft_G(check, "instance"))) return No("wrong instance");
            // Array.prototype.includes (strict equality), or String.prototype.includes (a substring of the text of the issuer) when the pin is a string
            bool pinned = check.GetValueOrDefault("issuers") switch
            {
                L issuers => issuers.Any(i => AttestationSoft.Seq(i, AttestationSoft_G(b, "issuer"))),
                string text => text.Contains(AttestationSoft.Js(AttestationSoft_G(b, "issuer")), StringComparison.Ordinal),
                _ => throw new InvalidOperationException("o.issuers.includes is not a function"),
            };
            if (!pinned) return No("issuer not pinned");
            var pins = check.GetValueOrDefault("pqPins") is D pd ? pd.Where(e => e.Value is string).ToDictionary(e => e.Key, e => (string)e.Value!) : null;
            if (!IntentJs.VerifyPinnedSuite(b.GetValueOrDefault("alg"), b.ContainsKey("alg"), b.GetValueOrDefault("issuer") as string ?? "", b.GetValueOrDefault("pq_pk"), Msg(b), b.GetValueOrDefault("sig"), b.GetValueOrDefault("pq_sig"), pins)) return No("bad signature");
            if (!(IsInteger(b.GetValueOrDefault("epoch")) && IsInteger(b.GetValueOrDefault("seq")) && IsInteger(b.GetValueOrDefault("issued_at")) && IsInteger(b.GetValueOrDefault("not_after"))) || IntentJs.NumOf(b["seq"])!.Value < 0)
                return No("malformed window");
            double epoch = IntentJs.NumOf(b["epoch"])!.Value, issued = IntentJs.NumOf(b["issued_at"])!.Value, notAfter = IntentJs.NumOf(b["not_after"])!.Value;
            if (notAfter <= issued || notAfter - issued > MaxValidityMs) return No("validity exceeds the hard maximum");
            if (epoch != Math.Floor(issued / EpochMs)) return No("epoch does not match issued_at");
            double now = check.GetValueOrDefault("now") is { } n ? JsJson.ToJsNumber(n) : double.NaN;
            if (now + ClockSkewMs < issued) return No("not yet valid"); // a NaN clock is not "early": it fails the expiry test below
            if (!(now <= notAfter)) return No("expired");
            if (check.TryGetValue("scope", out var scope) && !AttestationSoft.Seq(b.GetValueOrDefault("scope"), GlobalScope) && !AttestationSoft.Seq(AttestationSoft_G(b, "scope"), scope)) return No("scope not covered");
            return new D { ["ok"] = true };
        }
        catch (Exception) { return No("malformed beacon"); }
    }

    static object? AttestationSoft_G(D d, string k) => d.TryGetValue(k, out var v) ? v : Undef;

    /// <summary>Monotonic acceptance: <c>next.seq</c> must be a non-negative safe integer (negative zero refused) strictly above <c>prev.seq</c> (null: none stored).</summary>
    public static D AcceptBeacon(object? prev, object? next)
    {
        if (next is not D n || !IntentJs.IsSafeInteger(n.GetValueOrDefault("seq")) || IntentJs.NumOf(n["seq"])!.Value < 0 || IntentJs.IsNegZero(IntentJs.NumOf(n["seq"])!.Value)) return No("malformed beacon");
        if (AttestationSoft.Truthy(prev))
        {
            var ps = prev is D pd ? AttestationSoft_G(pd, "seq") : Undef; // compared as a JavaScript number: a numeric string counts
            if (!(!ReferenceEquals(ps, Undef) && IntentJs.NumOf(n["seq"])!.Value > JsJson.ToJsNumber(ps))) return No($"replayed beacon: seq {AttestationSoft.Js(n["seq"])} <= {AttestationSoft.Js(ps)}");
        }
        return new D { ["ok"] = true };
    }

    /// <summary>Frozen unless at least one beacon verifies for the check: absence is a freeze.</summary>
    public static bool IsFrozenLiveness(object? beacons, D check)
    {
        if (beacons is not L l) throw new InvalidOperationException("beacons.some is not a function");
        return !l.Any(b => VerifyLivenessBeacon(b, check)["ok"] is true);
    }
}

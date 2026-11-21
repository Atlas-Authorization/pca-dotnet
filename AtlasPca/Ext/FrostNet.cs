// Multi-process network FROST for guardian custody: the allow token (a policy authority's signed "allow action digest X under group key G"), the signer proof of possession (rogue-key defense), the
// equivocation guard, the single-share signer service and the t-of-n network coordinator over signer transports. Group arithmetic and the two signing rounds are the core FROST module (Frost).
//
// The signer holds exactly one share and never emits it; it releases a signature share only for a valid allow token that names the exact message digest and its own group key, checked against the
// policy authority key it was CONFIGURED with (never the token's own claim). The coordinator holds no share: it collects commitments, forms the signing set, collects the shares and aggregates
// with Frost.Aggregate. Wire values are the JSON tree (a request or response is a Dictionary, a list a List, byte strings base64url text; the only byte arrays are keys and shares in enrollment records).
// Randomness is drawn through an injectable seam (32 bytes per draw), exactly where the reference draws it: the PoP nonce at construction, then the hiding and binding randomness of every round 1.
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using AtlasPca.Js;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca;

/// <summary>Thrown by enrollment when a signer's key has no valid proof of possession.</summary>
public sealed class PoPError(string message, long? identifier = null) : Exception(message)
{
    public long? Identifier { get; } = identifier;
}

/// <summary>Thrown when a signer sends two DIFFERENT messages for the same (session, round).</summary>
public sealed class EquivocationError(string sessionId, long round, long identifier, string previousDigest, string offendingDigest)
    : Exception($"equivocation: signer {identifier} sent two different messages for session '{sessionId}' round {round}")
{
    public string SessionId { get; } = sessionId;
    public long Round { get; } = round;
    public long Identifier { get; } = identifier;
    public string PreviousDigest { get; } = previousDigest;
    public string OffendingDigest { get; } = offendingDigest;
}

/// <summary>A coordinator refusal; <see cref="Refusals"/> lists {identifier, reason} per refusing signer.</summary>
public class CoordinatorError(string message, IReadOnlyList<D>? refusals = null) : Exception(message)
{
    public IReadOnlyList<D> Refusals { get; } = refusals ?? Array.Empty<D>();
}

/// <summary>A signing session that did not reach the threshold inside its bounded round deadline; no signature is produced.</summary>
public sealed class CoordinatorTimeoutError(string message, double timeoutMs, IReadOnlyList<D>? refusals = null) : CoordinatorError(message, refusals)
{
    public double TimeoutMs { get; } = timeoutMs;
}

/// <summary>Records the FIRST message seen per (session, round, signer) and fails CLOSED on a second, DIFFERING one; an identical repeat is idempotent.</summary>
public sealed class EquivocationGuard
{
    readonly Dictionary<string, string> _seen = new(StringComparer.Ordinal);
    readonly object _lock = new();

    static string Key(string sid, long round, long id) => $"{sid}\0{round}\0{id}";

    /// <summary>Observe a round message; throws <see cref="EquivocationError"/> on a second, differing message for the tuple. Arguments are JavaScript-typed values (a non-string session, a non-integer round) and are refused.</summary>
    public void Observe(object? sessionId, object? round, object? identifier, object? message)
    {
        if (sessionId is not string sid || sid.Length == 0) throw new ArgumentException("EquivocationGuard: session_id must be a non-empty string");
        if (round is string || !IntentJs.IsSafeInteger(round) || IntentJs.NumOf(round)!.Value < 1) throw new ArgumentException("EquivocationGuard: round must be a positive integer");
        if (identifier is string || !IntentJs.IsSafeInteger(identifier) || IntentJs.NumOf(identifier)!.Value <= 0) throw new ArgumentException("EquivocationGuard: identifier must be a positive integer");
        var key = Key(sid, IntentJs.Lng(round), IntentJs.Lng(identifier));
        var digest = Pca.HashCanonical(message);
        lock (_lock)
        {
            if (!_seen.TryGetValue(key, out var prev)) { _seen[key] = digest; return; }
            if (prev != digest) throw new EquivocationError(sid, IntentJs.Lng(round), IntentJs.Lng(identifier), prev, digest);
        }
    }

    /// <summary>Forget every binding for a session id (bounded-memory housekeeping).</summary>
    public void Forget(string sessionId)
    {
        var prefix = sessionId + "\0";
        lock (_lock)
            foreach (var k in _seen.Keys.Where(k => k.StartsWith(prefix, StringComparison.Ordinal)).ToList()) _seen.Remove(k);
    }
}

/// <summary>The options of <see cref="FrostNet.IssueAllowToken"/>.</summary>
public sealed class IssueAllowOpts
{
    /// <summary>The exact FROST message being authorized (its sha256 becomes action_digest).</summary>
    public byte[]? Message;
    /// <summary>...or the action digest directly. One of Message and FrostActionDigest is required; a digest wins.</summary>
    public string? FrostActionDigest;
    public byte[]? GroupPublicKey;
    public string? Nonce;
    /// <summary>Epoch milliseconds (a JSON number); null = absent.</summary>
    public object? NotBefore, ExpiresAt;
}

/// <summary>The options of a <see cref="GuardianSignerService"/>. Numbers are JavaScript numbers (doubles) so a fraction or a non-finite value is refused by the constructor, as in the reference.</summary>
public sealed class GuardianSignerOptions
{
    public double Identifier;
    /// <summary>This signer's ONE secret FROST share (32-byte little-endian scalar). Never leaves the service.</summary>
    public byte[]? Share;
    public byte[]? GroupPublicKey;
    /// <summary>The threshold t: a signing set smaller than t is refused.</summary>
    public double Threshold;
    /// <summary>The policy authority's Ed25519 public key this signer trusts for allow tokens.</summary>
    public byte[]? PolicyAuthorityPublicKey;
    /// <summary>Stale-session guard: the maximum age in milliseconds of a round-1 session before round 2 is refused; null keeps sessions until completion.</summary>
    public double? SessionTtlMs;
    /// <summary>The clock in milliseconds (default: the system clock).</summary>
    public Func<long>? Now;
    /// <summary>Durable round-1 nonce store. With it a restarted signer resumes live sessions, a session is marked spent BEFORE its share is computed and any store failure is a refusal.</summary>
    public IFrostNonceStore? NonceStore;
    /// <summary>The 32-byte randomness source (default: the operating system's).</summary>
    public Func<byte[]>? Random;
}

/// <summary>One signer reachable by a coordinator.</summary>
public interface ISignerTransport
{
    long Identifier { get; }
    Task<D> Round1Async(D request);
    Task<D> Round2Async(D request);
}

/// <summary>A signer transport over a service in this process: a separate object with its own session state, reached only through async calls.</summary>
public sealed class InProcessSignerTransport(GuardianSignerService service) : ISignerTransport
{
    public long Identifier => service.Identifier;
    public Task<D> Round1Async(D request) => Task.FromResult(service.Round1(request));
    public Task<D> Round2Async(D request) => Task.FromResult(service.Round2(request));
}

public static class FrostNet
{
    public const string AllowTokenTyp = "pca.frost.allow.v1", SignerPopDst = "pca.frost.signer-pop.v1";
    /// <summary>The largest signing set a signer or coordinator will decode: it bounds the per-request interpolation work a hostile peer can demand.</summary>
    public const int MaxFrostSigningSet = 256;
    internal const string Round1Typ = "pca.frost.round1.v1", Round2Typ = "pca.frost.round2.v1";

    static byte[] Utf8(string s) => Encoding.UTF8.GetBytes(s);
    internal static byte[] DefaultRandom() => RandomNumberGenerator.GetBytes(32);
    internal static bool SafePositive(object? v) => v is not string && IntentJs.IsSafeInteger(v) && IntentJs.NumOf(v)!.Value > 0;
    internal static object? Get(object? o, string k) => o is D d && d.TryGetValue(k, out var v) ? v : null;
    internal static bool JsEq(object? a, object? b) => IntentJs.JsonEquals(a, b);

    internal static byte[] Ed25519Sign(byte[] seed, byte[] msg)
    {
        var s = new Ed25519Signer();
        s.Init(true, new Ed25519PrivateKeyParameters(seed, 0));
        s.BlockUpdate(msg, 0, msg.Length);
        return s.GenerateSignature();
    }

    /// <summary>base64url(sha256(message)): the "action digest" an allow token authorizes.</summary>
    public static string FrostActionDigest(byte[] message)
    {
        if (message == null) throw new ArgumentException("frostActionDigest: message must be bytes");
        return Pca.B64u(SHA256.HashData(message));
    }

    // ---- allow token ----

    /// <summary>Mint an allow token with the policy authority's Ed25519 SECRET key: {body, authority, sig}. A token carries a fresh random nonce unless one is given.</summary>
    public static D IssueAllowToken(byte[] policySecretKey, IssueAllowOpts opts, Func<byte[]>? random = null)
    {
        var digest = opts.FrostActionDigest ?? (opts.Message != null ? FrostActionDigest(opts.Message) : null);
        if (string.IsNullOrEmpty(digest)) throw new ArgumentException("issueAllowToken: provide message or frostActionDigest");
        var body = new D
        {
            ["typ"] = AllowTokenTyp,
            ["action_digest"] = digest,
            ["group_pk"] = Pca.B64u(opts.GroupPublicKey ?? throw new ArgumentException("issueAllowToken: groupPublicKey must be bytes")),
            ["nonce"] = opts.Nonce ?? Pca.B64u((random ?? DefaultRandom)()),
        };
        if (opts.NotBefore != null) body["not_before"] = IntentJs.Normalize(opts.NotBefore);
        if (opts.ExpiresAt != null) body["expires_at"] = IntentJs.Normalize(opts.ExpiresAt);
        if (policySecretKey is not { Length: 32 }) throw new ArgumentException("issueAllowToken: the policy secret key must be 32 bytes");
        var authority = Pca.B64u(new Ed25519PrivateKeyParameters(policySecretKey, 0).GeneratePublicKey().GetEncoded());
        var sig = Pca.B64u(Ed25519Sign(policySecretKey, Pca.Canon(body)));
        return new D { ["body"] = body, ["authority"] = authority, ["sig"] = sig };
    }

    /// <summary>Independently verify an allow token against the signer's CONFIGURED authority key (never <c>token.authority</c>): well-formed, the configured typ, signed by that key, naming the configured group
    /// key and the exact message's action digest, inside its validity window. <paramref name="now"/> is a JSON number (epoch ms). Returns {ok} or {ok: false, reason}; never throws.</summary>
    public static D VerifyAllowToken(object? token, byte[]? policyAuthorityPublicKey, byte[]? groupPublicKey, byte[]? message, object? now)
    {
        D No(string reason) => new() { ["ok"] = false, ["reason"] = reason };
        try
        {
            if (token is not (D or L)) return No("allow token missing or malformed");
            var body = Get(token, "body");
            if (body is not (D or L)) return No("allow token has no body");
            var typ = Get(body, "typ");
            if (!(typ is string ts && ts == AllowTokenTyp)) return No($"allow token wrong typ ({(body is D bd && bd.ContainsKey("typ") ? JsJson.ToJsString(typ) : "undefined")})");
            if (Get(token, "sig") is not string sigText) return No("allow token missing signature");
            var sigBytes = Pca.B64uDecode(sigText, 64);
            if (sigBytes == null) return No("allow token signature not canonical base64url");
            var canon = Pca.Canon(body);
            if (policyAuthorityPublicKey == null || !Pca.VerifyEd25519Strict(policyAuthorityPublicKey, canon, sigBytes)) return No("allow token not signed by the trusted policy authority");
            if (!(Get(body, "group_pk") is string gp && gp == Pca.B64u(groupPublicKey!))) return No("allow token authorizes a different group key");
            if (!(Get(body, "action_digest") is string ad && ad == FrostActionDigest(message!))) return No("allow token authorizes a different action digest");
            if (now is string || !IntentJs.IsFinite(now)) return No("invalid verification time");
            var t = IntentJs.NumOf(now)!.Value;
            if (body is D b)
            {
                if (b.TryGetValue("not_before", out var nb) && t < JsJson.ToJsNumber(nb)) return No("allow token not yet valid");
                if (b.TryGetValue("expires_at", out var ex) && t >= JsJson.ToJsNumber(ex)) return No("allow token expired");
            }
            return new D { ["ok"] = true };
        }
        catch (Exception e) { return No("allow token verification error (fail closed): " + e.Message); }
    }

    // ---- signer proof of possession ----

    static BigInteger PopChallenge(byte[] groupPublicKey, long identifier, byte[] pk, byte[] r)
    {
        var h = SHA512.HashData(Utf8(SignerPopDst).Concat(groupPublicKey).Concat(Frost.ScalarToBytes(new BigInteger(identifier))).Concat(pk).Concat(r).ToArray());
        var e = Frost.BytesToScalar(h);
        return e.IsZero ? BigInteger.One : e;
    }

    /// <summary>A signer's Schnorr proof of possession of the verification share derived from <paramref name="share"/>, bound to the group key: {identifier, publicKey, R, s}. The nonce is fixed only for
    /// reproducible vectors; otherwise it is drawn from <paramref name="random"/> (a draw that reduces to 0 is redrawn).</summary>
    public static D CreateSignerPoP(long identifier, byte[]? share, byte[]? groupPublicKey, byte[]? nonce = null, Func<byte[]>? random = null)
    {
        if (identifier <= 0 || identifier > 9007199254740991L) throw new ArgumentException("createSignerPoP: identifier must be a positive integer");
        if (share is not { Length: 32 }) throw new ArgumentException("createSignerPoP: share must be 32 bytes");
        if (groupPublicKey is not { Length: 32 }) throw new ArgumentException("createSignerPoP: groupPublicKey must be 32 bytes");
        var x = Frost.BytesToScalar(share);
        var pk = Frost.MulBase(x).ToBytes();
        var k = nonce != null ? Frost.BytesToScalar(nonce) : BigInteger.Zero;
        while (k.IsZero) k = Frost.BytesToScalar((random ?? DefaultRandom)());
        var rBytes = Frost.MulBase(k).ToBytes();
        var e = PopChallenge(groupPublicKey, identifier, pk, rBytes);
        var s = CtScalar.Add(Frost.ScalarToBytes(k), CtScalar.Mul(Frost.ScalarToBytes(e), Frost.ScalarToBytes(x)));
        return new D { ["identifier"] = identifier, ["publicKey"] = Pca.B64u(pk), ["R"] = Pca.B64u(rBytes), ["s"] = Pca.B64u(s) };
    }

    /// <summary>Verify a signer proof of possession: s*B == R + e*PK with R and PK decoded through the STRICT point rules. Never throws; any malformed input or bad proof is false.</summary>
    public static bool VerifySignerPoP(object? pop, byte[]? groupPublicKey)
    {
        try
        {
            if (pop is not D p) return false;
            if (!SafePositive(p.GetValueOrDefault("identifier"))) return false;
            if (groupPublicKey is not { Length: 32 }) return false;
            var pk = Pca.B64uDecode(p.GetValueOrDefault("publicKey"), 32);
            var rb = Pca.B64uDecode(p.GetValueOrDefault("R"), 32);
            var sb = Pca.B64uDecode(p.GetValueOrDefault("s"), 32);
            if (pk == null || rb == null || sb == null) return false;
            var pkPt = Frost.DecodeSafePoint(pk);
            var rPt = Frost.DecodeSafePoint(rb);
            if (!Frost.IsCanonicalScalar(sb)) return false; // s and s + L must not both verify
            var s = Frost.BytesToScalar(sb);
            var e = PopChallenge(groupPublicKey, IntentJs.Lng(p["identifier"]), pk, rb);
            return Frost.MulBase(s).SameAs(rPt.Add(Frost.MulPoint(pkPt, e)));
        }
        catch (Exception) { return false; }
    }

    /// <summary>The ENFORCED enrollment surface. <paramref name="enrollments"/> is a list of {identifier, publicKey (byte[]), pop}; each signer is accepted only with a valid PoP binding its verification share under
    /// the group key. A missing, mismatched or invalid PoP (a rogue key) throws <see cref="PoPError"/>, as does a duplicate id.</summary>
    public static List<Frost.VerificationShare> EnrollVerificationShares(object? enrollments, byte[]? groupPublicKey)
    {
        if (enrollments is not L list || list.Count == 0) throw new PoPError("enrollVerificationShares: no signer enrollments");
        if (groupPublicKey is not { Length: 32 }) throw new PoPError("enrollVerificationShares: groupPublicKey must be 32 bytes");
        var outp = new List<Frost.VerificationShare>();
        var seen = new HashSet<long>();
        foreach (var e in list)
        {
            if (e is not D en || !SafePositive(en.GetValueOrDefault("identifier"))) throw new PoPError("enrollVerificationShares: enrollment with invalid identifier");
            var id = IntentJs.Lng(en["identifier"]);
            if (!seen.Add(id)) throw new PoPError($"enrollVerificationShares: duplicate enrollment for signer {id}", id);
            if (en.GetValueOrDefault("publicKey") is not byte[] { Length: 32 } pub) throw new PoPError($"enrollVerificationShares: signer {id} verification share must be 32 bytes", id);
            if (en.GetValueOrDefault("pop") is not D pop || !JsEq(pop.GetValueOrDefault("identifier"), en["identifier"]) || !(pop.GetValueOrDefault("publicKey") is string pks && pks == Pca.B64u(pub)))
                throw new PoPError($"enrollVerificationShares: signer {id} missing or mismatched proof-of-possession (rogue key rejected)", id);
            if (!VerifySignerPoP(pop, groupPublicKey)) throw new PoPError($"enrollVerificationShares: signer {id} invalid proof-of-possession (rogue key rejected)", id);
            outp.Add(new Frost.VerificationShare(id, pub));
        }
        return outp;
    }

    // ---- wire decoding ----

    internal static D EncodeCommitment(Frost.FrostCommitment c) => new() { ["identifier"] = c.Identifier, ["hiding"] = Pca.B64u(c.Hiding), ["binding"] = Pca.B64u(c.Binding) };

    /// <summary>Strict decode of one wire commitment {identifier, hiding, binding}. Total: anything malformed is a typed error.</summary>
    public static Frost.FrostCommitment DecodeCommitment(object? w)
    {
        if (w is not (D or L)) throw new ArgumentException("bad commitment");
        var hiding = Pca.B64uDecode(Get(w, "hiding"), 32);
        var binding = Pca.B64uDecode(Get(w, "binding"), 32);
        if (!SafePositive(Get(w, "identifier"))) throw new ArgumentException("bad commitment identifier");
        if (hiding == null || binding == null) throw new ArgumentException("bad commitment point encoding");
        return new Frost.FrostCommitment(IntentJs.Lng(Get(w, "identifier")), hiding, binding);
    }

    /// <summary>Strict decode of a list of wire commitments, bounded by <see cref="MaxFrostSigningSet"/>.</summary>
    public static List<Frost.FrostCommitment> DecodeCommitments(object? list)
    {
        if (list is not L l) throw new ArgumentException("commitments must be a list");
        if (l.Count > MaxFrostSigningSet) throw new ArgumentException("commitments list exceeds the maximum signing set");
        return l.Select(DecodeCommitment).ToList();
    }

    /// <summary>Strict decode of the signing set's public verification shares {identifier, publicKey}, bounded by <see cref="MaxFrostSigningSet"/>.</summary>
    public static List<Frost.VerificationShare> DecodeVerificationShares(object? list)
    {
        if (list is not L l) throw new ArgumentException("verification_shares must be a list");
        if (l.Count > MaxFrostSigningSet) throw new ArgumentException("verification_shares list exceeds the maximum signing set");
        return l.Select(v =>
        {
            if (v is not (D or L)) throw new ArgumentException("bad verification share");
            var pk = Pca.B64uDecode(Get(v, "publicKey"), 32);
            if (!SafePositive(Get(v, "identifier"))) throw new ArgumentException("bad verification-share identifier");
            if (pk == null) throw new ArgumentException("bad verification-share key encoding");
            return new Frost.VerificationShare(IntentJs.Lng(Get(v, "identifier")), pk);
        }).ToList();
    }
}

/// <summary>A single-share FROST signer: one instance is one trust domain. It keeps, per session, only its own secret nonces and releases a signature share in round 2 iff it has live round-1 state, the request
/// names its group key and the allow token verifies independently and binds the exact message. A refusal keeps the round-1 nonces (an honest retry still works); success consumes them one-shot.</summary>
public sealed class GuardianSignerService
{
    sealed record Session(Frost.FrostNonces Nonces, Frost.FrostCommitment Commitment, long CreatedAt);

    public long Identifier { get; }
    public byte[] VerificationShare { get; }
    readonly byte[] _share;
    readonly Dictionary<string, Session> _sessions = new(StringComparer.Ordinal);
    readonly HashSet<string> _spent = new(StringComparer.Ordinal);
    readonly D _pop;
    readonly byte[] _groupPublicKey, _policyAuthorityPublicKey;
    readonly int _threshold;
    readonly double? _ttl;
    readonly Func<long> _now;
    readonly IFrostNonceStore? _store;
    readonly Func<byte[]> _random;
    readonly object _lock = new();

    public GuardianSignerService(GuardianSignerOptions opts)
    {
        if (!(opts.Identifier > 0 && FrostNet.SafePositive(opts.Identifier))) throw new ArgumentException("GuardianSignerService: identifier must be a positive integer");
        if (opts.Share is not { Length: 32 }) throw new ArgumentException("GuardianSignerService: share must be 32 bytes");
        if (opts.GroupPublicKey is not { Length: 32 }) throw new ArgumentException("GuardianSignerService: groupPublicKey must be 32 bytes");
        if (!(FrostNet.SafePositive(opts.Threshold) && opts.Threshold >= 1)) throw new ArgumentException("GuardianSignerService: threshold must be a positive integer");
        if (opts.PolicyAuthorityPublicKey is not { Length: 32 }) throw new ArgumentException("GuardianSignerService: policyAuthorityPublicKey must be 32 bytes");
        if (opts.SessionTtlMs is double ttl && (!double.IsFinite(ttl) || ttl <= 0)) throw new ArgumentException("GuardianSignerService: sessionTtlMs must be a positive finite number");
        _share = (byte[])opts.Share.Clone(); // the caller cannot mutate it out from under us, and we never hand it back
        Identifier = (long)opts.Identifier;
        _groupPublicKey = (byte[])opts.GroupPublicKey.Clone();
        _threshold = (int)Math.Min(opts.Threshold, int.MaxValue);
        _policyAuthorityPublicKey = (byte[])opts.PolicyAuthorityPublicKey.Clone();
        _ttl = opts.SessionTtlMs;
        _now = opts.Now ?? (() => DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());
        _store = opts.NonceStore;
        _random = opts.Random ?? FrostNet.DefaultRandom;
        VerificationShare = Frost.VerifyingShare(_share);
        // rogue-key defense: prove possession of the secret scalar behind our verification share once, up front
        _pop = FrostNet.CreateSignerPoP(Identifier, _share, _groupPublicKey, null, _random);
    }

    /// <summary>This signer's proof of possession of its verification share (safe to publish).</summary>
    public D ProofOfPossession => new(_pop);

    /// <summary>A ready-to-enroll record {identifier, publicKey, pop} for <see cref="FrostNet.EnrollVerificationShares"/>.</summary>
    public D Enrollment() => new() { ["identifier"] = Identifier, ["publicKey"] = (byte[])VerificationShare.Clone(), ["pop"] = new D(_pop) };

    /// <summary>Round 1: commit to a fresh nonce pair for the session; the SECRET nonces stay here. Returns {ok, identifier, commitment, pop} or {ok: false, identifier, reason}.</summary>
    public D Round1(object? req)
    {
        D No(string reason) => new() { ["ok"] = false, ["identifier"] = Identifier, ["reason"] = reason };
        lock (_lock)
            try
            {
                if (req is not D r || !(r.GetValueOrDefault("typ") is string t && t == FrostNet.Round1Typ) || r.GetValueOrDefault("session_id") is not string sid || sid.Length == 0) return No("malformed round-1 request");
                if (_spent.Contains(sid) || (_store?.IsSpent(sid) ?? false)) return No("session already signed");
                // never overwrite live nonces for a session (a nonce-reuse foot-gun)
                if (_sessions.ContainsKey(sid) || _store?.Load(sid) != null) return No("duplicate round-1 for session");
                var hidingRandomness = _random();
                var bindingRandomness = _random();
                var c = Frost.Commit(new Frost.FrostParticipantShare(Identifier, _share, VerificationShare), hidingRandomness, bindingRandomness);
                var createdAt = _now();
                // durable BEFORE the commitment leaves this process: a crash then can only lose the session, never reuse a nonce
                _store?.Create(sid, new FrostNonceRecord { Hiding = (byte[])c.HidingNonce.Clone(), Binding = (byte[])c.BindingNonce.Clone(), HidingCommitment = c.Commitment.Hiding, BindingCommitment = c.Commitment.Binding, CreatedAt = createdAt });
                _sessions[sid] = new Session(new Frost.FrostNonces(c.HidingNonce, c.BindingNonce), c.Commitment, createdAt);
                return new D { ["ok"] = true, ["identifier"] = Identifier, ["commitment"] = FrostNet.EncodeCommitment(c.Commitment), ["pop"] = new D(_pop) };
            }
            catch (Exception e) { return No(e.Message); }
    }

    /// <summary>Round 2: release a signature share iff the allow token verifies and the session has live round-1 state. Returns {ok, identifier, sig_share} or {ok: false, identifier, refused: true, reason}.</summary>
    public D Round2(object? req)
    {
        D Refuse(string reason) => new() { ["ok"] = false, ["identifier"] = Identifier, ["refused"] = true, ["reason"] = reason };
        lock (_lock)
            try
            {
                if (req is not D r || !(r.GetValueOrDefault("typ") is string t && t == FrostNet.Round2Typ) || r.GetValueOrDefault("session_id") is not string sid) return Refuse("malformed round-2 request");
                if (_spent.Contains(sid) || (_store?.IsSpent(sid) ?? false)) return Refuse("session already signed (one-shot)");
                if (!_sessions.TryGetValue(sid, out var state) && _store != null)
                {
                    // restart recovery: resume a live session from the durable store
                    var rec = _store.Load(sid);
                    if (rec != null)
                    {
                        state = new Session(new Frost.FrostNonces(rec.Hiding, rec.Binding), new Frost.FrostCommitment(Identifier, rec.HidingCommitment, rec.BindingCommitment), rec.CreatedAt);
                        _sessions[sid] = state;
                    }
                }
                if (state == null) return Refuse("no round-1 state for this session");

                // stale-session guard: a session not completed within its window is dropped, not signed
                if (_ttl is double ttl && _now() - state.CreatedAt > ttl)
                {
                    _sessions.Remove(sid);
                    _store?.Drop(sid);
                    return Refuse($"session expired (stale-session guard: round-1 older than {JsJson.NumberToString(ttl)}ms)");
                }

                var message = Pca.B64uDecode(r.GetValueOrDefault("message"));
                if (message == null) return Refuse("message not canonical base64url");
                if (!(r.GetValueOrDefault("group_pk") is string gp && gp == Pca.B64u(_groupPublicKey))) return Refuse("request names a different group key");

                // independent policy authorization: the heart of coordinator-compromise resistance
                var allow = FrostNet.VerifyAllowToken(r.GetValueOrDefault("allow"), _policyAuthorityPublicKey, _groupPublicKey, message, _now());
                if (allow["ok"] is not true) return Refuse($"policy authorization failed: {allow["reason"]}");

                var commitments = FrostNet.DecodeCommitments(r.GetValueOrDefault("commitments") ?? new L());
                if (commitments.Count < _threshold) return Refuse($"signing set below threshold t={_threshold}");
                var own = commitments.FirstOrDefault(c => c.Identifier == Identifier);
                if (own == null) return Refuse("our commitment is not in the signing set");
                // equivocation defense: the commitment the coordinator put in the set for OUR id must byte-match the one emitted in round 1
                if (!own.Hiding.AsSpan().SequenceEqual(state.Commitment.Hiding) || !own.Binding.AsSpan().SequenceEqual(state.Commitment.Binding))
                    return Refuse("equivocation detected: our commitment in the signing set differs from our round-1 commitment");
                var verificationShares = FrostNet.DecodeVerificationShares(r.GetValueOrDefault("verification_shares"));

                // spent marker first (durable), then sign: a crash or refusal after this line burns the session, never reuses it
                _store?.Spend(sid);
                var sigShare = Frost.Sign(Identifier, _share, _groupPublicKey, state.Nonces, message, commitments,
                    new Frost.FrostSignOpts { Threshold = _threshold, VerificationShare = VerificationShare, VerificationShares = verificationShares });

                _sessions.Remove(sid);
                _spent.Add(sid);
                return new D { ["ok"] = true, ["identifier"] = Identifier, ["sig_share"] = Pca.B64u(sigShare.SigShare) };
            }
            catch (Exception e) { return Refuse(e.Message); }
    }
}

/// <summary>The options of a <see cref="NetworkCoordinator"/>.</summary>
public sealed class NetworkCoordinatorOptions
{
    public byte[]? GroupPublicKey;
    public double Threshold;
    /// <summary>One transport per available signer.</summary>
    public IReadOnlyList<ISignerTransport> Signers = [];
    /// <summary>The public verification shares of every signer (each signer checks they interpolate to G). Provide this OR <see cref="Enroll"/>; the rogue-key defense is still enforced per round by each signer's round-1 PoP.</summary>
    public IReadOnlyList<Frost.VerificationShare>? VerificationShares;
    /// <summary>The hardened alternative: PoP-bearing enrollment records ({identifier, publicKey, pop}). Every PoP is verified at construction and a rogue key throws.</summary>
    public object? Enroll;
    /// <summary>Session id generator (default: random).</summary>
    public Func<string>? NewSessionId;
    /// <summary>Bounded round deadline in milliseconds for a whole signing call; null = no deadline. A per-call deadline overrides it.</summary>
    public double? TimeoutMs;
    public Func<byte[]>? Random;
}

/// <summary>The outcome of one network signing session.</summary>
public sealed record NetworkSignResult(byte[] Signature, string SessionId, List<long> Signers);

/// <summary>The network coordinator: round 1 collects at least t commitments, the signing set is formed, round 2 collects the matching shares, and Frost.Aggregate combines them. It holds NO share and cannot
/// forge the allow token, so it cannot make honest signers release without a genuine authorization.</summary>
public sealed class NetworkCoordinator
{
    readonly byte[] _groupPublicKey;
    readonly int _threshold;
    readonly List<ISignerTransport> _signers;
    readonly List<Frost.VerificationShare> _verificationShares;
    readonly Dictionary<double, string> _pkById;
    readonly EquivocationGuard _equivocation = new();
    readonly Func<string> _newSessionId;
    readonly double? _timeoutMs;

    public NetworkCoordinator(NetworkCoordinatorOptions opts)
    {
        if (opts.GroupPublicKey is not { Length: 32 }) throw new ArgumentException("NetworkCoordinator: groupPublicKey must be 32 bytes");
        if (!(FrostNet.SafePositive(opts.Threshold) && opts.Threshold >= 1)) throw new ArgumentException("NetworkCoordinator: threshold must be a positive integer");
        if (opts.TimeoutMs is double t && (!double.IsFinite(t) || t <= 0)) throw new ArgumentException("NetworkCoordinator: timeoutMs must be a positive finite number");
        _groupPublicKey = opts.GroupPublicKey;
        _threshold = (int)Math.Min(opts.Threshold, int.MaxValue);
        _signers = [.. opts.Signers];
        // rogue-key defense at the enrollment surface: Enroll verifies every PoP (throws on a rogue key)
        if (opts.Enroll != null) _verificationShares = FrostNet.EnrollVerificationShares(opts.Enroll, opts.GroupPublicKey);
        else if (opts.VerificationShares != null) _verificationShares = [.. opts.VerificationShares];
        else throw new ArgumentException("NetworkCoordinator: provide verificationShares or enroll");
        _pkById = _verificationShares.GroupBy(v => (double)v.Identifier).ToDictionary(g => g.Key, g => Pca.B64u(g.Last().PublicKey));
        var rnd = opts.Random ?? FrostNet.DefaultRandom;
        _newSessionId = opts.NewSessionId ?? (() => Pca.B64u(rnd()));
        _timeoutMs = opts.TimeoutMs;
    }

    static bool Truthy(object? v) => v switch
    {
        null => false,
        bool b => b,
        string s => s.Length > 0,
        _ when IntentJs.NumOf(v) is double d => d != 0 && !double.IsNaN(d),
        _ => true,
    };

    static object? JsKey(object? v) => IntentJs.NumOf(v) is double d && v is not string ? d : v;

    /// <summary>Drive one t-of-n signing session. <paramref name="signerIds"/> picks which signers to use (default: the first t). Returns the aggregate Ed25519 signature or throws <see cref="CoordinatorError"/> with
    /// the per-signer refusal reasons, or <see cref="CoordinatorTimeoutError"/> if the bounded round deadline elapses. <paramref name="timeoutMs"/> overrides the constructor's deadline (a non-finite or non-positive value
    /// means no deadline).</summary>
    public async Task<NetworkSignResult> SignAsync(byte[]? message, object? allow, IReadOnlyList<long>? signerIds = null, double? timeoutMs = null)
    {
        var windowMs = timeoutMs ?? _timeoutMs;
        var run = Drive(message, allow, signerIds);
        if (windowMs is not double w || !double.IsFinite(w) || w <= 0) return await run.ConfigureAwait(false);
        _ = run.ContinueWith(t => _ = t.Exception, TaskContinuationOptions.OnlyOnFaulted); // a late failure of an abandoned run must not surface
        var timeout = Task.Delay(TimeSpan.FromMilliseconds(w));
        if (await Task.WhenAny(run, timeout).ConfigureAwait(false) == run) return await run.ConfigureAwait(false);
        throw new CoordinatorTimeoutError($"coordinator: signing session did not reach threshold within {JsJson.NumberToString(w)}ms", w);
    }

    async Task<NetworkSignResult> Drive(byte[]? message, object? allow, IReadOnlyList<long>? signerIds)
    {
        if (message == null) throw new ArgumentException("coordinator.sign: message must be bytes");
        var chosen = signerIds != null ? _signers.Where(s => signerIds.Contains(s.Identifier)).ToList() : _signers.Take(_threshold).ToList();
        if (chosen.Count < _threshold) throw new CoordinatorError($"coordinator: only {chosen.Count} signer(s) selected, need t={_threshold}");
        var sessionId = _newSessionId();

        // round 1: collect commitments
        var r1 = await Task.WhenAll(chosen.Select(async s =>
        {
            try { return (s, resp: await s.Round1Async(new D { ["typ"] = FrostNet.Round1Typ, ["session_id"] = sessionId }).ConfigureAwait(false)); }
            catch (Exception e) { return (s, resp: new D { ["ok"] = false, ["identifier"] = s.Identifier, ["reason"] = e.Message }); }
        })).ConfigureAwait(false);
        var refusals = new List<D>();
        void Refuse(object? id, object? reason) => refusals.Add(new D { ["identifier"] = id, ["reason"] = reason });
        var committed = new List<(ISignerTransport Transport, object? Commitment)>();
        foreach (var (s, resp) in r1)
        {
            if (!Truthy(resp.GetValueOrDefault("ok"))) { Refuse(resp.GetValueOrDefault("identifier"), resp.GetValueOrDefault("reason")); continue; }
            var rid = resp.GetValueOrDefault("identifier");
            // rogue-key defense: the signer must prove possession of the verification share we have on record
            if (!(IntentJs.NumOf(rid) is double key && rid is not string && _pkById.TryGetValue(key, out var expectedPk))) { Refuse(rid, "no verification share on record for this signer"); continue; }
            var pop = resp.GetValueOrDefault("pop");
            if (!resp.ContainsKey("pop") || !FrostNet.JsEq(FrostNet.Get(pop, "identifier"), rid) || !(FrostNet.Get(pop, "publicKey") is string ppk && ppk == expectedPk) || !FrostNet.VerifySignerPoP(pop, _groupPublicKey))
            {
                Refuse(rid, "invalid or missing proof-of-possession (rogue-key defense)");
                continue;
            }
            // equivocation defense: a signer cannot bind this (session, round 1) to two different commitments
            try { _equivocation.Observe(sessionId, 1, rid, resp.TryGetValue("commitment", out var cm) ? cm : new object()); }
            catch (Exception e) { Refuse(rid, e is EquivocationError ? e.Message : "equivocation check failed"); continue; }
            committed.Add((s, resp.GetValueOrDefault("commitment")));
        }
        if (committed.Count < _threshold) throw new CoordinatorError($"coordinator: round 1 produced {committed.Count} commitment(s), need t={_threshold}", refusals);
        // exactly t committed signers form the signing set (the verification shares must match this set)
        var set = committed.Take(_threshold).ToList();
        var commitments = set.Select(c => c.Commitment).ToList();
        var setIds = new HashSet<object?>(set.Select(c => JsKey(FrostNet.Get(c.Commitment, "identifier"))));
        var verificationShares = _verificationShares.Where(v => setIds.Contains((double)v.Identifier)).Select(v => (object?)new D { ["identifier"] = v.Identifier, ["publicKey"] = Pca.B64u(v.PublicKey) }).ToList();
        if (verificationShares.Count != set.Count) throw new CoordinatorError("coordinator: missing a verification share for a signer in the set");

        // round 2: collect signature shares
        D R2Req() => new() { ["typ"] = FrostNet.Round2Typ, ["session_id"] = sessionId, ["message"] = Pca.B64u(message), ["group_pk"] = Pca.B64u(_groupPublicKey), ["commitments"] = commitments, ["verification_shares"] = verificationShares, ["allow"] = allow };
        var r2 = await Task.WhenAll(set.Select(async c =>
        {
            try { return await c.Transport.Round2Async(R2Req()).ConfigureAwait(false); }
            catch (Exception e) { return new D { ["ok"] = false, ["identifier"] = c.Transport.Identifier, ["refused"] = true, ["reason"] = e.Message }; }
        })).ConfigureAwait(false);
        var sigShares = new List<Frost.FrostSignatureShare>();
        foreach (var resp in r2)
        {
            var rid = resp.GetValueOrDefault("identifier");
            if (!Truthy(resp.GetValueOrDefault("ok"))) { Refuse(rid, resp.GetValueOrDefault("reason")); continue; }
            // equivocation defense: a signer cannot bind this (session, round 2) to two different shares
            try { _equivocation.Observe(sessionId, 2, rid, new D { ["sig_share"] = resp.TryGetValue("sig_share", out var ss) ? ss : new object() }); }
            catch (Exception e) { Refuse(rid, e is EquivocationError ? e.Message : "equivocation check failed"); continue; }
            var sb = Pca.B64uDecode(resp.GetValueOrDefault("sig_share"), 32);
            if (sb == null) Refuse(rid, "malformed signature share");
            else sigShares.Add(new Frost.FrostSignatureShare(IntentJs.Lng(rid), sb));
        }
        if (sigShares.Count < _threshold) throw new CoordinatorError($"coordinator: round 2 produced {sigShares.Count} share(s), need t={_threshold}", refusals);

        // aggregate with the core primitive (it re-verifies every share and the aggregate)
        var aggCommitments = commitments.Select(FrostNet.DecodeCommitment).ToList();
        var signature = Frost.Aggregate(message, aggCommitments, sigShares, _groupPublicKey, _threshold, _verificationShares.Where(v => setIds.Contains((double)v.Identifier)).ToList());
        return new NetworkSignResult(signature, sessionId, set.Select(c => IntentJs.Lng(FrostNet.Get(c.Commitment, "identifier"))).ToList());
    }
}

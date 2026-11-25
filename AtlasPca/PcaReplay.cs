// The standalone replay guard of a verifier (packages/pca replay.ts): decide whether a signature-verified PCActn may be accepted ONCE. The check order
// follows the formally verified replay decision: every shape and window check before the first store call, the nonce consumed once, then the optional
// counter stream advanced. Never throws: every failure, including a store failure, is a denial.
using AtlasPca.Events;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca;

/// <summary>Strictly-monotonic counter store, one stream per key: true iff <c>counter</c> is greater than the stored value (and it is then stored).</summary>
public interface ICounterStore
{
    Task<bool> Advance(string streamKey, double counter);
}

/// <summary>The guard's verdict: <see cref="Ok"/>, else a denial <see cref="Code"/> (malformed, audience, not_yet_valid, expired, replay, store_unavailable) and a reason.</summary>
public sealed record PcaReplayVerdict(bool Ok, string? Code = null, string? Reason = null);

/// <summary>Options of <see cref="PcaReplay.GuardPCActnReplay"/>: the audience this verifier answers for, its clock (epoch ms), the tolerated skew (default and ceiling: the
/// protocol maximum), whether a PCActn without a nonce is refused (default) and the optional counter stream.</summary>
public sealed record ReplayGuardOptions(string Aud, double Now, double? ClockSkewMs = null, bool RequireNonce = true, ICounterStore? Counters = null);

public static class PcaReplay
{
    /// <summary>Upper bound (UTF-8 bytes) accepted for a grant ref / holder key / stream key component.</summary>
    public const int MaxReplayComponentLen = 512;

    /// <summary>How long a store must remember a consumed key: the longest lifetime plus skew on both sides.</summary>
    public const long ReplayMinRetentionMs = Pca.MaxLifetimeMs + 2 * Pca.MaxSkewMs;

    const double MaxSafe = 9007199254740991;
    const int MaxAudLen = 256, MaxNonceLen = 128;

    /// <summary>The length-prefixed, injective key of the parts, hashed to a fixed size: <c>namespace:b64u(sha256)</c>. Throws on a part with a lone surrogate.</summary>
    public static string ReplayKey(string ns, params string[] parts) => Connect.ConnectReplayGuard.ReplayKey(ns, parts);

    static PcaReplayVerdict Deny(string code, string reason) => new(false, code, reason);

    static int U8(string s) => System.Text.Encoding.UTF8.GetByteCount(s);

    static bool SafeNonNegInt(object? o) => IntentJs.IsNonNeg(o) && IntentJs.NumOf(o) is double d && d <= MaxSafe && !IntentJs.IsNegZero(d);

    static bool Bounded(string s) => s.Length != 0 && !Pca.HasLoneSurrogate(s) && U8(s) <= MaxReplayComponentLen;

    /// <summary>Decide whether the signature-verified PCActn <paramref name="p"/> may be accepted once. Run it AFTER the PCActn verified: consuming a nonce for an
    /// unauthenticated action would let anyone burn another party's nonces, and the keys embed <c>grant_ref</c>, which only the chain verification binds.</summary>
    public static async Task<PcaReplayVerdict> GuardPCActnReplay(IReplayStore store, object? p, ReplayGuardOptions opts)
    {
        var skew = Math.Min(double.IsFinite(opts.ClockSkewMs ?? double.NaN) && opts.ClockSkewMs >= 0 ? opts.ClockSkewMs!.Value : Pca.MaxSkewMs, Pca.MaxSkewMs);
        var pm = p as D;
        var objectOk = pm != null;
        var leaf = objectOk && pm!.GetValueOrDefault("cap_chain") is L chain && chain.Count > 0 ? chain[^1] as D : null;
        var leafOk = leaf != null && leaf.GetValueOrDefault("holder") is string && pm!.GetValueOrDefault("grant_ref") is string;
        var componentsOk = leafOk && Bounded((string)pm!["grant_ref"]!) && Bounded((string)leaf!["holder"]!);
        var hasNonce = objectOk && pm!.ContainsKey("nonce");
        var nonce = hasNonce ? pm!["nonce"] as string : null;
        var nonceOk = hasNonce && nonce != null && nonce.Length != 0 && U8(nonce) <= MaxNonceLen && !Pca.HasLoneSurrogate(nonce);
        var nowOk = double.IsFinite(opts.Now) && opts.Now == Math.Truncate(opts.Now) && Math.Abs(opts.Now) <= MaxSafe;
        var verifierAudOk = opts.Aud is { Length: > 0 } && U8(opts.Aud) <= MaxAudLen && !Pca.HasLoneSurrogate(opts.Aud);
        var audMatches = objectOk && pm!.GetValueOrDefault("aud") is string pa && pa == opts.Aud;
        var iatOk = objectOk && SafeNonNegInt(pm!.GetValueOrDefault("iat"));
        var expOk = objectOk && SafeNonNegInt(pm!.GetValueOrDefault("exp"));
        double iat = iatOk ? IntentJs.NumOf(pm!["iat"])!.Value : 0, exp = expOk ? IntentJs.NumOf(pm!["exp"])!.Value : 0;
        var counterOk = objectOk && SafeNonNegInt(pm!.GetValueOrDefault("counter"));
        var windowOk = iatOk && expOk && exp > iat && exp - iat <= Pca.MaxLifetimeMs;
        var skewWhole = Math.Floor(skew);

        // the verified Pre: everything before the first store call, in the normative order
        if (!nowOk) return Deny("malformed", "verifier clock is not an integer epoch-ms");
        if (!verifierAudOk) return Deny("malformed", "verifier audience is invalid");
        if (!objectOk) return Deny("malformed", "not a PCActn");
        if (!audMatches) return Deny("audience", "the PCActn is for another audience");
        if (!windowOk) return Deny("malformed", "iat / exp are not a valid bounded window");
        if (iat > opts.Now + skewWhole) return Deny("not_yet_valid", "iat is in the future beyond the clock-skew allowance");
        if (opts.Now > exp) return Deny("expired", "the PCActn has expired");
        if (!leafOk) return Deny("malformed", "no leaf holder / grant");
        if (!componentsOk) return Deny("malformed", "grant / holder is not a bounded string");
        if (!counterOk) return Deny("malformed", "counter is not a non-negative safe integer");
        // the store contract takes the horizon as a JS number: a sum past 2^53-1 would round (a rounded horizon could free a live nonce early)
        if (exp + Math.Ceiling(skew) > MaxSafe) return Deny("malformed", "exp + clock skew exceeds the safe-integer range (retention horizon not representable)");
        var retainUntil = exp + skew;
        var grantRef = (string)pm!["grant_ref"]!;
        var holder = (string)leaf!["holder"]!;
        try
        {
            var stage = hasNonce ? (nonceOk ? "consume" : "deny") : opts.RequireNonce ? "deny" : "skip";
            if (stage == "deny") return Deny("malformed", hasNonce ? "nonce must be a non-empty well-formed string of <= 128 UTF-8 bytes" : "a nonce is required");
            if (stage == "consume" && !await store.ConsumeOnce(ReplayKey("pca-nonce/v1", opts.Aud, grantRef, holder, nonce!), retainUntil, opts.Now).ConfigureAwait(false))
                return Deny("replay", "nonce already consumed");
            if (opts.Counters != null && !await opts.Counters.Advance(ReplayKey("pca-counter/v1", opts.Aud, grantRef, holder), IntentJs.NumOf(pm["counter"])!.Value).ConfigureAwait(false))
                return Deny("replay", "counter is not greater than the last accepted");
        }
        catch (Exception e) { return Deny("store_unavailable", "replay store failed closed: " + (string.IsNullOrEmpty(e.Message) ? "error" : e.Message)); }
        return new PcaReplayVerdict(true);
    }
}

/// <summary>Reference store: correct ONLY for a single verifier process whose lifetime covers the action lifetime (state is lost on restart and is not shared
/// between instances). When full of live entries, <c>ConsumeOnce</c> REJECTS (fail closed) rather than evicting.</summary>
public sealed class InMemoryReplayStore(int maxEntries = 100_000) : IReplayStore, ICounterStore
{
    readonly object _gate = new();
    readonly Dictionary<string, double> _seen = new(StringComparer.Ordinal);
    readonly Dictionary<string, double> _streams = new(StringComparer.Ordinal);

    /// <summary>Number of live (unpruned) entries.</summary>
    public int Size { get { lock (_gate) return _seen.Count; } }

    /// <summary>Drop only entries whose retention has fully elapsed (<c>retainUntil &lt; now</c>). Never frees a still-valid key.</summary>
    public int Prune(double nowMs)
    {
        lock (_gate)
        {
            var old = _seen.Where(e => e.Value < nowMs).Select(e => e.Key).ToList();
            foreach (var k in old) _seen.Remove(k);
            return old.Count;
        }
    }

    public Task<bool> ConsumeOnce(string key, double retainUntilMs, double nowMs)
    {
        if (string.IsNullOrEmpty(key) || !double.IsFinite(retainUntilMs) || !double.IsFinite(nowMs) || retainUntilMs < nowMs)
            return Task.FromException<bool>(new ArgumentOutOfRangeException(nameof(key), "consumeOnce: invalid key or retention horizon"));
        lock (_gate)
        {
            var has = _seen.TryGetValue(key, out var until);
            if (has && until >= nowMs) return Task.FromResult(false);
            if (!has && _seen.Count >= maxEntries)
            {
                Prune(nowMs);
                if (_seen.Count >= maxEntries) return Task.FromException<bool>(new InvalidOperationException("replay store full of live entries"));
            }
            _seen[key] = Math.Max(retainUntilMs, has ? until : 0);
            return Task.FromResult(true);
        }
    }

    public Task<bool> Advance(string streamKey, double counter)
    {
        if (string.IsNullOrEmpty(streamKey) || !(counter >= 0 && counter <= 9007199254740991 && counter == Math.Truncate(counter)))
            return Task.FromException<bool>(new ArgumentOutOfRangeException(nameof(streamKey), "advance: invalid stream or counter"));
        lock (_gate)
        {
            if (_streams.TryGetValue(streamKey, out var last) && !(counter > last)) return Task.FromResult(false);
            _streams[streamKey] = counter;
            return Task.FromResult(true);
        }
    }
}

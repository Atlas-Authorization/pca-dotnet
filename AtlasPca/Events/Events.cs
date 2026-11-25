// Typed step-up lifecycle events and Stripe-style signed webhooks for Proof-Carrying Authority. A transport contract only: a stable
// event shape (content-addressed id) plus an HMAC-SHA256 signature so a receiver can tell a real delivery from a forged or replayed one.
// Events and option bags are JSON trees (Dictionary); numbers are JSON numbers (Num).
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using AtlasPca.Js;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Events;

/// <summary>The consume-once store a delivery is checked against: true iff the key was not yet consumed (until <c>retainUntilMs</c>). It throws when it cannot decide.</summary>
public interface IReplayStore
{
    Task<bool> ConsumeOnce(string key, double retainUntilMs, double nowMs);
}

/// <summary>The in-memory replay store (single process).</summary>
public sealed class MemoryReplayStore(int maxEntries = 100_000) : IReplayStore
{
    readonly object _gate = new();
    readonly Dictionary<string, double> _seen = new();

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
                foreach (var k in _seen.Where(e => e.Value < nowMs).Select(e => e.Key).ToList()) _seen.Remove(k);
                if (_seen.Count >= maxEntries) return Task.FromException<bool>(new InvalidOperationException("replay store full of live entries"));
            }
            _seen[key] = Math.Max(retainUntilMs, has ? until : 0);
            return Task.FromResult(true);
        }
    }
}

public static class StepUpEvents
{
    /// <summary>Smallest secret accepted (bytes): a short or empty HMAC key makes every signature guessable.</summary>
    public const int MinSecretBytes = 16;
    const int MaxHeaderChars = 2048;
    static readonly string[] EventTypes = { "step_up.created", "step_up.approved", "step_up.denied", "step_up.expired" };

    static double? Fin(object? v) => v is Num n && double.TryParse(n.Raw, NumberStyles.Float, CultureInfo.InvariantCulture, out var d) && double.IsFinite(d) ? d : null;
    static string Js(double d) => JsJson.NumberToString(d);
    static double NowSec() => Math.Floor(AtlasPca.ReplayClock.NowMs() / 1000.0);

    /// <summary>base64url(sha256(strictCanonical(fields))), domain-separated. A number outside the strict profile fails with a "canonicalize:" error.</summary>
    static string EventId(object? type, object? at, object? grantRef, object? verb, object? resource, object? tier, bool hasActor, object? actor)
    {
        var b = new D
        {
            ["d"] = "atlas-pca/stepup-event/v1", ["type"] = type, ["at"] = at, ["grant_ref"] = grantRef,
            ["action"] = new D { ["verb"] = verb, ["resource"] = resource }, ["tier"] = tier,
        };
        if (hasActor) b["actor"] = actor;
        try { return Pca.HashCanonical(IntentJs.Normalize(b)); }
        catch (Exception e) when (!e.Message.StartsWith("canonicalize:", StringComparison.Ordinal)) { throw new InvalidOperationException("canonicalize: " + e.Message); }
    }

    static object Req(D d, string k) => d.TryGetValue(k, out var v) ? v! : throw new InvalidOperationException("canonicalize: unsupported type undefined");

    /// <summary>Build a step-up event: <c>at</c> defaults to the clock, and <c>id</c> is the content address of every other field. data: {at?, grant_ref, action: {verb, resource}, tier, actor?}.</summary>
    public static D BuildStepUpEvent(object? type, object? data)
    {
        CheckEventFields("buildStepUpEvent", new D(data as D ?? new D()) { ["type"] = type }, false);
        if (data is not D d) throw new ArgumentException("buildStepUpEvent: data is required");
        var at = d.GetValueOrDefault("at") ?? new Num(AtlasPca.ReplayClock.NowMs().ToString(CultureInfo.InvariantCulture));
        if (d.GetValueOrDefault("action") is not D action) throw new ArgumentException("buildStepUpEvent: action is required");
        var grantRef = d.ContainsKey("grant_ref") ? d["grant_ref"] : throw new InvalidOperationException("canonicalize: unsupported type undefined");
        var verb = action.ContainsKey("verb") ? action["verb"] : throw new InvalidOperationException("canonicalize: unsupported type undefined");
        var resource = action.ContainsKey("resource") ? action["resource"] : throw new InvalidOperationException("canonicalize: unsupported type undefined");
        var tier = d.ContainsKey("tier") ? d["tier"] : throw new InvalidOperationException("canonicalize: unsupported type undefined");
        var hasActor = d.ContainsKey("actor");
        var actor = d.GetValueOrDefault("actor");
        var e = new D { ["type"] = type, ["at"] = at, ["grant_ref"] = grantRef, ["action"] = new D { ["verb"] = verb, ["resource"] = resource }, ["tier"] = tier };
        if (hasActor) e["actor"] = actor;
        e["id"] = EventId(type, at, grantRef, verb, resource, tier, hasActor, actor);
        return e;
    }

    /// <summary>The JSON wire form (JSON.stringify: insertion order, integer-like keys first).</summary>
    public static string SerializeEvent(object? e)
    {
        CheckEventFields("serializeEvent", e, true);
        if (Fin(((D)e!).GetValueOrDefault("at")) == null) throw new ArgumentException("serializeEvent: at must be a finite number");
        return JsJson.Stringify(e);
    }

    static bool WellFormed(object? x) => x is string s && !Pca.HasLoneSurrogate(s);

    /// <summary>The fields every event carries, checked the same way at build and at serialize time (fail closed on anything else).</summary>
    static void CheckEventFields(string who, object? e, bool withId)
    {
        static Exception Bad(string who, string m) => new ArgumentException($"{who}: {m}");
        if (e is not D o) throw Bad(who, "not an object");
        var tier = o.GetValueOrDefault("tier");
        if (o.GetValueOrDefault("type") is not string t || !EventTypes.Contains(t) || !(tier is Num && (Fin(tier) == 2 || Fin(tier) == 3))) throw Bad(who, "unknown event type or tier");
        if (o.ContainsKey("at") && Fin(o["at"]) == null) throw Bad(who, "at must be a finite number");
        if (!WellFormed(o.GetValueOrDefault("grant_ref"))) throw Bad(who, "grant_ref must be a well-formed string");
        if (o.GetValueOrDefault("action") is not D a || !WellFormed(a.GetValueOrDefault("verb")) || !WellFormed(a.GetValueOrDefault("resource")))
            throw Bad(who, "action must carry well-formed verb and resource strings");
        if (o.ContainsKey("actor") && !WellFormed(o["actor"])) throw Bad(who, "actor must be a well-formed string");
        if (withId && !WellFormed(o.GetValueOrDefault("id"))) throw Bad(who, "id must be a well-formed string");
    }

    static bool IsStr(object? v) => v is string;

    /// <summary>Parse and validate a JSON step-up event. Throws on anything that is not a well-formed event whose id is the digest of its fields.</summary>
    public static D ParseEvent(object? s)
    {
        if (s is not string text) throw new ArgumentException("parseEvent: not a string");
        var raw = Pca.ParseStrict(text); // the strict canonical JSON profile: no duplicate member, exponent, trailing-zero fraction or lone surrogate
        if (raw is not D o) throw new ArgumentException("parseEvent: " + (raw is L ? "bad id" : "not an object"));
        if (o.GetValueOrDefault("id") is not string id || id.Length == 0) throw new ArgumentException("parseEvent: bad id");
        if (o.GetValueOrDefault("type") is not string type || !EventTypes.Contains(type)) throw new ArgumentException("parseEvent: bad type");
        if (o.GetValueOrDefault("at") is not Num at || Fin(at) is null) throw new ArgumentException("parseEvent: bad at");
        if (o.GetValueOrDefault("grant_ref") is not string grantRef) throw new ArgumentException("parseEvent: bad grant_ref");
        var actionV = o.GetValueOrDefault("action");
        if (actionV is not (D or L)) throw new ArgumentException("parseEvent: bad action"); // typeof null / undefined / a scalar is not "object"; an array is
        var action = actionV as D;
        if (action?.GetValueOrDefault("verb") is not string verb || action.GetValueOrDefault("resource") is not string resource) throw new ArgumentException("parseEvent: bad action fields");
        var tv = Fin(o.GetValueOrDefault("tier"));
        if (tv != 2 && tv != 3) throw new ArgumentException("parseEvent: bad tier");
        var tier = new Num(tv == 2 ? "2" : "3");
        // JSON null is not undefined: a present actor must be a string
        var hasActor = o.ContainsKey("actor");
        var actor = o.GetValueOrDefault("actor");
        if (hasActor && actor is not string) throw new ArgumentException("parseEvent: bad actor");
        var e = new D { ["id"] = id, ["type"] = type, ["at"] = at, ["grant_ref"] = grantRef, ["action"] = new D { ["verb"] = verb, ["resource"] = resource }, ["tier"] = tier };
        if (hasActor) e["actor"] = actor;
        if (EventId(type, at, grantRef, verb, resource, tier, hasActor, actor) != id) throw new ArgumentException("parseEvent: id does not match the event content");
        return e;
    }

    // ---- signed webhooks ----

    static byte[]? SecretBytes(object? secret)
    {
        var b = secret is string s ? Encoding.UTF8.GetBytes(s) : secret as byte[];
        return b != null && b.Length >= MinSecretBytes ? b : null;
    }

    static string Hex(byte[] b) => Convert.ToHexString(b).ToLowerInvariant();

    static byte[]? HexToBytes(string s)
    {
        if (s.Length % 2 != 0) return null;
        var o = new byte[s.Length / 2];
        for (var i = 0; i < o.Length; i++)
        {
            int h = Nib(s[2 * i]), l = Nib(s[2 * i + 1]);
            if (h < 0 || l < 0) return null;
            o[i] = (byte)(h * 16 + l);
        }
        return o;
    }

    static int Nib(char c) => c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : c >= 'A' && c <= 'F' ? c - 'A' + 10 : -1;

    static string TrimJs(string s)
    {
        int a = 0, z = s.Length;
        while (a < z && JsJson.IsJsSpace(s[a])) a++;
        while (z > a && JsJson.IsJsSpace(s[z - 1])) z--;
        return s[a..z];
    }

    /// <summary>`t=<digits>,v1=<hex>[,v1=<hex>...]`: several v1 are allowed (secret rotation), two different t are not.</summary>
    static (double T, List<string> V1)? ParseSignatureHeader(object? h)
    {
        if (h is not string header || header.Length > MaxHeaderChars) return null;
        double? t = null;
        var v1 = new List<string>();
        foreach (var part in header.Split(','))
        {
            var eq = part.IndexOf('=');
            if (eq < 0) continue;
            var key = TrimJs(part[..eq]);
            var val = TrimJs(part[(eq + 1)..]);
            if (key == "t")
            {
                if (val.Length is < 1 or > 15 || !val.All(char.IsAsciiDigit)) return null;
                var n = double.Parse(val, CultureInfo.InvariantCulture);
                if (t != null && t != n) return null;
                t = n;
            }
            else if (key == "v1") v1.Add(val);
        }
        if (t == null || v1.Count == 0) return null;
        return (t.Value, v1);
    }

    static byte[] Mac(byte[] key, double t, string payload) => HMACSHA256.HashData(key, Encoding.UTF8.GetBytes($"{Js(t)}.{payload}"));

    /// <summary>`t=<unixSeconds>,v1=<hex HMAC-SHA256 of "<t>.<payload>">`. <paramref name="secret"/>: a string or byte[]; opts.timestamp pins the seconds. Throws on a secret under 16 bytes and on a timestamp that is not a non-negative safe integer.</summary>
    public static string SignWebhook(object? secret, string payload, D? opts = null)
    {
        var key = SecretBytes(secret) ?? throw new ArgumentOutOfRangeException(nameof(secret), $"signWebhook: the secret must be at least {MinSecretBytes} bytes");
        var tv = opts?.GetValueOrDefault("timestamp");
        double t;
        if (tv == null) t = NowSec();
        else if (tv is Num n && Fin(n) is double d && d == Math.Floor(d) && Math.Abs(d) <= Pca.MaxSafeInt) t = d;
        else throw new ArgumentOutOfRangeException(nameof(opts), "signWebhook: timestamp must be a non-negative integer (unix seconds)");
        if (t < 0) throw new ArgumentOutOfRangeException(nameof(opts), "signWebhook: timestamp must be a non-negative integer (unix seconds)");
        return $"t={Js(t)},v1={Hex(Mac(key, t, payload))}";
    }

    /// <summary>Verify a signature header against the payload: constant-time HMAC compare plus the timestamp tolerance (default 300 s). Never throws: false on a malformed header, bad signature, stale timestamp, short secret, or a tolerance / clock that is not a finite non-negative number. opts: {toleranceSec?, now?} (unix seconds).</summary>
    public static bool VerifyWebhook(object? secret, string payload, object? signatureHeader, D? opts = null)
    {
        try
        {
            var key = SecretBytes(secret);
            if (key == null) return false;
            var parsed = ParseSignatureHeader(signatureHeader);
            if (parsed == null) return false;
            var tolV = opts?.GetValueOrDefault("toleranceSec");
            var nowV = opts?.GetValueOrDefault("now");
            double tol = 300, now = NowSec();
            if (tolV != null) { if (Fin(tolV) is not double td) return false; tol = td; }
            if (nowV != null) { if (Fin(nowV) is not double nd) return false; now = nd; }
            if (tol < 0) return false;
            if (!(Math.Abs(now - parsed.Value.T) <= tol)) return false;
            var expected = Mac(key, parsed.Value.T, payload);
            var match = false;
            foreach (var v in parsed.Value.V1)
            {
                var provided = HexToBytes(v);
                if (provided == null) continue;
                if (CryptographicOperations.FixedTimeEquals(expected, provided)) match = true; // no early exit: every candidate costs the same
            }
            return match;
        }
        catch (Exception) { return false; }
    }

    /// <summary>The length-prefixed, injective key of the parts, hashed: `&lt;namespace&gt;:&lt;b64u sha256&gt;`. Throws on a lone surrogate.</summary>
    static string ReplayKey(string ns, params string[] parts)
    {
        var buf = new List<byte>();
        foreach (var part in new[] { ns }.Concat(parts))
        {
            if (Pca.HasLoneSurrogate(part)) throw new ArgumentException("replayKey: every part must be a well-formed string (no lone surrogates)");
            var bytes = Encoding.UTF8.GetBytes(part);
            buf.Add((byte)(bytes.Length >> 24)); buf.Add((byte)(bytes.Length >> 16)); buf.Add((byte)(bytes.Length >> 8)); buf.Add((byte)bytes.Length);
            buf.AddRange(bytes);
        }
        return ns + ":" + Pca.B64u(SHA256.HashData(buf.ToArray()));
    }

    /// <summary>Accept one webhook delivery: signature and freshness, a well-formed event whose id matches its content, and a first sight of that event id in <paramref name="replay"/>. Never throws; no reason contains the secret or the payload. Returns {ok: true, event} or {ok: false, reason}.</summary>
    public static async Task<D> VerifyDelivery(object? secret, string payload, object? signatureHeader, D? opts, IReplayStore? replay)
    {
        static D No(string reason) => new() { ["ok"] = false, ["reason"] = reason };
        try
        {
            if (opts == null || replay == null) return No("a replay store is required");
            if (!VerifyWebhook(secret, payload, signatureHeader, opts)) return No("bad signature");
            D evt;
            try { evt = ParseEvent(payload); }
            catch (Exception e) { return No(e.Message); }
            var sig = ParseSignatureHeader(signatureHeader)!.Value;
            var nowSec = Fin(opts.GetValueOrDefault("now")) ?? NowSec();
            var tolerance = Fin(opts.GetValueOrDefault("toleranceSec")) ?? 300;
            try
            {
                var first = await replay.ConsumeOnce(ReplayKey("pca-stepup-event/v1", (string)evt["id"]!), (sig.T + tolerance) * 1000 + 1, nowSec * 1000).ConfigureAwait(false);
                if (!first) return No("replayed delivery");
            }
            catch (Exception) { return No("replay store unavailable"); }
            return new D { ["ok"] = true, ["event"] = evt };
        }
        catch (Exception) { return No("bad signature"); }
    }

    /// <summary>The headers to attach to an outbound webhook POST: {PCA-Signature, content-type}.</summary>
    public static D WebhookHeaders(object? secret, string payload, D? opts = null) => new()
    {
        ["PCA-Signature"] = SignWebhook(secret, payload, opts),
        ["content-type"] = "application/json",
    };
}

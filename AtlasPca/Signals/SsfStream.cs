// SSF stream plumbing around the SET channel: stream configuration validation, stream health (verification round trips), the SSF 1.0 section 8.1.4
// verification endpoint, the RFC 8936 poll queue, the RFC 8935 push response, and the CAEP risk / assurance level change events.
// Hostile JSON (the shapes a network peer can send) is handled with JavaScript semantics: every refusal is a value or an exception, never a crash.
using System.Security.Cryptography;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Signals;

/// <summary>An outcome of the verification endpoint: 204 carries the verification SET; 400 / 404 / 429 carry an error.</summary>
public sealed record VerificationOutcome(int Status, string? Set = null, string? Error = null);

/// <summary>A stream the verification endpoint serves: its config (a JSON object) and when a verification was last sent (seconds).</summary>
public sealed class StreamEntry
{
    public D? Config { get; set; }
    public double? LastVerification { get; set; }
}

public sealed class StreamHealthOptions
{
    public double? VerifyTimeoutSec { get; init; }
    public double? VerifiedWithinSec { get; init; }
    public double? FailAfter { get; init; }
    public double? MaxPending { get; init; }
}

public sealed record StreamHealthReport(string State, string Status, List<string> Reasons, double? LastEventAt, double? LastVerifiedAt,
    int PendingVerifications, int ConsecutiveVerificationFailures, int RejectedVerifications);

public static class SsfStream
{
    public const string DeliveryPush = "urn:ietf:rfc:8935";
    public const string DeliveryPoll = "urn:ietf:rfc:8936";
    public static readonly string[] StreamStatuses = { "enabled", "paused", "disabled" };

    /// <summary>JavaScript's <c>\s</c>.</summary>
    internal static bool JsSpace(char c) =>
        c is '\t' or '\n' or '\v' or '\f' or '\r' or ' ' or ' ' or ' ' or '\u2028' or '\u2029' or ' ' or ' ' or '　' or '﻿' || (c >= ' ' && c <= ' ');

    /// <summary>The reference's <c>/^https:\/\/[^\s]+$/</c>.</summary>
    internal static bool IsHttpsUrl(string s) => s.StartsWith("https://", StringComparison.Ordinal) && s.Length > 8 && !s.Skip(8).Any(JsSpace);

    internal static bool SafeNonNegInt(object? v)
    {
        if (v is not Num n) return false;
        var d = Signals.V(n);
        return double.IsFinite(d) && d == Math.Floor(d) && Math.Abs(d) <= 9007199254740991d && d >= 0 && !(d == 0 && n.Raw.StartsWith('-'));
    }

    static bool NonEmpty(object? x) => x is string s && s.Length > 0;
    static bool Strs(object? x) => x is L l && l.All(NonEmpty);

    /// <summary>Validate a stream configuration (SSF 1.0 section 8.1.1) and return the problems (empty = valid).</summary>
    public static List<string> ValidateStreamConfig(object? c)
    {
        var e = new List<string>();
        if (c is not D o) return new() { "not an object" };
        o.TryGetValue("aud", out var aud);
        o.TryGetValue("events_delivered", out var delivered);
        o.TryGetValue("events_supported", out var supported);
        var hasSupported = o.ContainsKey("events_supported");
        if (!NonEmpty(o.GetValueOrDefault("stream_id"))) e.Add("stream_id is required");
        if (!NonEmpty(o.GetValueOrDefault("iss"))) e.Add("iss is required");
        if (!(NonEmpty(aud) || (aud is L al && al.Count > 0 && al.All(NonEmpty)))) e.Add("aud must be a non-empty string or array");
        if (!Strs(delivered) || ((L)delivered!).Count == 0) e.Add("events_delivered must be a non-empty array of event type URIs");
        if (hasSupported && !Strs(supported)) e.Add("events_supported must be an array of URIs");
        if (o.TryGetValue("events_requested", out var requested) && (!Strs(requested) || ((L)requested!).Count == 0)) e.Add("events_requested must be a non-empty array of URIs");
        if (Strs(delivered) && Strs(supported) && !((L)delivered!).All(x => ((L)supported!).Contains(x))) e.Add("events_delivered must be a subset of events_supported");
        var d = o.GetValueOrDefault("delivery") as D;
        if (d == null || !(d.GetValueOrDefault("method") is DeliveryPush or DeliveryPoll)) e.Add("delivery.method must be the RFC 8935 or RFC 8936 URI");
        else if (d.GetValueOrDefault("endpoint_url") is not string url || !IsHttpsUrl(url)) e.Add("delivery.endpoint_url must be an https URL");
        if (o.TryGetValue("min_verification_interval", out var mvi) && !SafeNonNegInt(mvi)) e.Add("min_verification_interval must be a non-negative integer (seconds)");
        return e;
    }

    /// <summary>Tracks the SSF verification round trip of one stream and reports whether it is healthy. A receiver proves the stream is alive by acknowledging a
    /// state the transmitter issued; unanswered requests time out and count as failures.</summary>
    public sealed class StreamHealth(D config, StreamHealthOptions? o = null)
    {
        readonly StreamHealthOptions _o = o ?? new();
        string _status = "enabled";
        double? _lastEvent, _lastVerified, _lastRequested;
        int _fails, _rejected;
        readonly Dictionary<string, double> _pending = new();

        public D Config { get; } = config;

        public void SetStatus(string? s)
        {
            if (s == null || !StreamStatuses.Contains(s)) throw new ArgumentOutOfRangeException(nameof(s), "unknown stream status");
            _status = s;
        }

        public void RecordEvent(double nowSec) => _lastEvent = Math.Max(_lastEvent ?? 0, nowSec);

        /// <summary>A fresh opaque verification state, or null when the stream is not enabled, was asked too recently, or too many are pending.</summary>
        public string? RequestVerification(double nowSec)
        {
            if (_status != "enabled") return null;
            if (!double.IsFinite(nowSec)) return null;
            var min = Config.GetValueOrDefault("min_verification_interval") is Num n ? Signals.V(n) : 0;
            if (_lastRequested != null && !(nowSec - _lastRequested.Value >= min)) return null;
            Expire(nowSec);
            if (!(_pending.Count < (_o.MaxPending ?? 16))) return null;
            var state = Pca.B64u(RandomNumberGenerator.GetBytes(16));
            var exp = nowSec + (_o.VerifyTimeoutSec ?? 60);
            if (!double.IsFinite(exp)) return null; // a NaN or infinite timeout would leave the request pending forever
            _pending[state] = exp;
            _lastRequested = nowSec;
            return state;
        }

        public bool AckVerification(object? state, double nowSec)
        {
            if (!double.IsFinite(nowSec)) { _rejected++; return false; }
            Expire(nowSec);
            if (state is not string s || !_pending.Remove(s))
            {
                _rejected++;
                return false;
            }
            _lastVerified = nowSec;
            _lastEvent = Math.Max(_lastEvent ?? 0, nowSec);
            _fails = 0;
            return true;
        }

        void Expire(double nowSec)
        {
            foreach (var k in _pending.Where(e => nowSec > e.Value).Select(e => e.Key).ToList())
            {
                _pending.Remove(k);
                _fails++;
            }
        }

        public StreamHealthReport Report(double nowSec)
        {
            Expire(nowSec);
            var reasons = new List<string>();
            var within = _o.VerifiedWithinSec ?? 300;
            string state;
            if (_status == "disabled") { state = "disabled"; reasons.Add("stream is disabled: no events are transmitted or held"); }
            else if (_status == "paused") { state = "paused"; reasons.Add("stream is paused: events may be delayed"); }
            else if (!(_fails < (_o.FailAfter ?? 3))) { state = "failing"; reasons.Add($"{_fails} consecutive verification requests timed out"); }
            else if (_lastVerified == null) { state = "unverified"; reasons.Add("no verification round trip has completed"); }
            else if (!(double.IsFinite(nowSec) && nowSec - _lastVerified.Value <= within)) { state = "degraded"; reasons.Add($"last verified {Signals.JsNum(nowSec - _lastVerified.Value)}s ago, over {Signals.JsNum(within)}s"); }
            else state = "healthy";
            return new StreamHealthReport(state, _status, reasons, _lastEvent, _lastVerified, _pending.Count, _fails, _rejected);
        }

        /// <summary>True only when the stream is enabled and a verification completed within <paramref name="maxAgeSec"/>.</summary>
        public bool RevocationFreshWithin(double maxAgeSec, double nowSec) => _status == "enabled" && _lastVerified != null && double.IsFinite(nowSec) && nowSec - _lastVerified.Value <= maxAgeSec;
    }

    /// <summary>The transmitter side of SSF verification: validate the request, enforce the minimum interval, and mint the verification SET (state echoed back).</summary>
    public static VerificationOutcome HandleVerificationRequest(Dictionary<string, StreamEntry> streams, object? req, double nowSec, object? key)
    {
        if (req is not D r || r.GetValueOrDefault("stream_id") is not string id || (r.TryGetValue("state", out var st) && st is not string))
            return new(400, Error: "stream_id (string) is required; state must be a string");
        if (!streams.TryGetValue(id, out var s)) return new(404, Error: "no such stream");
        var cfg = s.Config ?? throw new InvalidOperationException("Cannot read properties of undefined (reading 'min_verification_interval')");
        var min = cfg.GetValueOrDefault("min_verification_interval") is Num n ? Signals.V(n) : 0;
        if (!double.IsFinite(nowSec) || (s.LastVerification != null && !(nowSec - s.LastVerification.Value >= min))) return new(429, Error: "verification requested too soon");
        s.LastVerification = nowSec;
        var ev = r.TryGetValue("state", out var state) ? new D { ["state"] = state } : new D();
        var set = Signals.BuildSet(new D { [Signals.EventTypes.Verification] = ev }, cfg.GetValueOrDefault("iss") as string ?? throw new InvalidOperationException("iss is required"),
            cfg.GetValueOrDefault("aud") ?? throw new InvalidOperationException("aud is required"), cfg.GetValueOrDefault("stream_id") as string, key!);
        return new(204, set);
    }

    /// <summary>The RFC 8936 poll queue: SETs waiting for a receiver, acknowledged by jti.</summary>
    public sealed class PollQueue
    {
        readonly List<(string Jti, string Set)> _q = new();

        /// <summary>One entry per rejected SET: <c>{jti, err, description}</c> (a missing member stays missing).</summary>
        public List<D> Errors { get; } = new();

        public void Enqueue(string jti, string set)
        {
            var i = _q.FindIndex(e => e.Jti == jti);
            if (i >= 0) _q[i] = (jti, set); else _q.Add((jti, set));
        }

        public int Depth => _q.Count;

        bool Delete(string jti)
        {
            var i = _q.FindIndex(e => e.Jti == jti);
            if (i < 0) return false;
            _q.RemoveAt(i);
            return true;
        }

        /// <summary>Serve a poll request ({maxEvents?, ack?, setErrs?}); returns <c>{sets: {jti: set}, moreAvailable?: true}</c>. A malformed request throws.</summary>
        public D Poll(object? req)
        {
            if (req == null) throw new InvalidOperationException("Cannot read properties of null (reading 'maxEvents')");
            var r = req as D;
            double max = double.PositiveInfinity;
            if (r != null && r.TryGetValue("maxEvents", out var me))
            {
                if (!SafeNonNegInt(me)) throw new ArgumentOutOfRangeException(nameof(req), "maxEvents must be a non-negative integer");
                max = Signals.V((Num)me!);
            }
            var ack = r?.GetValueOrDefault("ack");
            IEnumerable<object?> acks = ack switch
            {
                null => Array.Empty<object?>(),
                L l => l,
                string s => s.Select(c => (object?)c.ToString()),
                _ => throw new InvalidOperationException("req.ack is not iterable"),
            };
            foreach (var j in acks) if (j is string js) Delete(js);
            foreach (var (jti, e) in Signals.Entries(r?.GetValueOrDefault("setErrs") ?? new D()))
            {
                if (!Delete(jti)) continue;
                var rec = new D { ["jti"] = jti };
                var err = Signals.Prop(e, "err");
                if (e is D ed && ed.ContainsKey("err")) rec["err"] = err;
                if (e is D ed2 && ed2.ContainsKey("description")) rec["description"] = ed2["description"];
                Errors.Add(rec);
            }
            var sets = new D();
            int n = 0;
            foreach (var (jti, set) in _q)
            {
                if (n >= max) break;
                sets[jti] = set;
                n++;
            }
            var res = new D { ["sets"] = sets };
            if (_q.Count > n) res["moreAvailable"] = true;
            return res;
        }
    }

    static bool Truthy(object? v) => v switch
    {
        null => false,
        bool b => b,
        string s => s.Length > 0,
        Num n => Signals.V(n) != 0,
        _ => true,
    };

    /// <summary>Map a receive result ({ok, code, reason}) to the RFC 8935 push response: 202, or 400 with the SET error code.</summary>
    public static D PushResponse(object? r)
    {
        var ok = Signals.Prop(r, "ok");
        if (Truthy(ok)) return new D { ["status"] = new Num("202") };
        var code = Signals.Prop(r, "code") as string;
        var err = code == "verify_failed" ? "invalid_key"
            : code is "malformed" or "oversize" ? "invalid_request"
            : code is "misconfigured" or "replay_store_error" ? "access_denied" : "invalid_request";
        var body = new D { ["err"] = err };
        if (r is D rd && rd.TryGetValue("reason", out var reason)) body["description"] = reason;
        return new D { ["status"] = new Num("400"), ["body"] = body };
    }

    /// <summary>A CAEP 1.0 risk-level-change SET.</summary>
    public static string RiskLevelChangeSet(string issuer, object audience, object key, D ev) =>
        Signals.BuildSet(new D { [Signals.EventTypes.RiskLevelChange] = ev }, issuer, audience, null, key);

    /// <summary>A CAEP 1.0 assurance-level-change SET. When the event names a previous_level but no change_direction and <paramref name="order"/> (a JSON array of
    /// levels, lowest first) ranks both levels differently, the direction is derived.</summary>
    public static string AssuranceLevelChangeSet(string issuer, object audience, object key, D ev, object? order = null)
    {
        var e = new D(ev);
        if (e.ContainsKey("previous_level") && !e.ContainsKey("change_direction") && order is L ord)
        {
            var i = ord.FindIndex(x => x is string xs && e["previous_level"] is string ps && xs == ps);
            var j = ord.FindIndex(x => x is string xs && e.GetValueOrDefault("current_level") is string cs && xs == cs);
            if (i >= 0 && j >= 0 && i != j) e["change_direction"] = j > i ? "increase" : "decrease";
        }
        return Signals.BuildSet(new D { [Signals.EventTypes.AssuranceLevelChange] = e }, issuer, audience, null, key);
    }
}

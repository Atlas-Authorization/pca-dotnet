// Shared Signals Framework (SSF / CAEP) for Proof-Carrying Authority: the ACTIVE revocation and mid-run kill-switch channel.
// PCA's native enforcement is passive (a signed PCActn checked default-deny, bounded by the grant's counter / budget / revocation epoch). This is
// the PUSH: a transmitter emits a Security Event Token (RFC 8417), a subscriber folds the events into local revocation state it consults on every
// request. Specs: OpenID SSF 1.0, CAEP 1.0, RFC 8417 (SET), RFC 9493 (subject identifiers). Signing: EdDSA. No I/O, no framework.
//
// JSON values are the core tree (Dictionary<string, object?>, List<object?>, string, bool, Num, null). Timestamps stay <see cref="Num"/> (exact JSON
// number text) and compare as doubles, as in the reference.
using System.Globalization;
using AtlasPca.Jose;
using J = AtlasPca.Jose.Jose;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Signals;

/// <summary>A misconfiguration or malformed input; <see cref="Code"/> names the check (misconfigured, bad_snapshot, unmapped_subject, ...).</summary>
public sealed class SignalsException(string code, string message) : Exception(message)
{
    public string Code { get; } = code;
}

/// <summary>The parsed result of a verified SET. <see cref="Events"/> and <see cref="Payload"/> are JSON values (hostile shapes are tolerated by the
/// state functions the way the reference tolerates them).</summary>
public sealed class ParsedSet
{
    public object? Events { get; init; }
    public string? Iss { get; init; }
    public string? Jti { get; init; }
    public string? Sub { get; init; }
    public object? Payload { get; init; }
}

/// <summary>Subscriber-side revocation state. Every map stores the <c>event_timestamp</c> of the revoking event; revocation is MONOTONE.</summary>
public sealed class SetRevocationState
{
    public Dictionary<string, Num> RevokedGrants { get; } = new();
    public Dictionary<string, Num> KilledAgents { get; } = new();
    /// <summary>Created on first use.</summary>
    public Dictionary<string, Num>? RevokedIntentIds { get; set; }
}

public sealed class VerifySetOptions
{
    /// <summary>A string or a list of strings.</summary>
    public object? Issuer { get; init; }
    public object? Audience { get; init; }
    public double? ClockTolerance { get; init; }
    /// <summary>"Now" in epoch milliseconds.</summary>
    public double? CurrentDateMs { get; init; }
    public string? Typ { get; init; }
    /// <summary>False skips the typ check entirely.</summary>
    public bool? RequireTyp { get; init; }
}

public interface ISetReplayStore
{
    /// <summary>MUST be atomic: of N concurrent calls with the same jti exactly one returns true.</summary>
    bool AddIfAbsent(string jti, double expiresAtSec, double nowSec);
}

public sealed record StandardRevocationPlan(List<(string Agent, Num Timestamp)> Agents, List<string> Unmapped);

public sealed class StandardRevocationOptions
{
    /// <summary>Maps an event's RFC 9493 subject to an agent id; any non-string / empty result means "no agent". Default: an opaque subject's id.</summary>
    public Func<D, object?>? SubjectToAgent { get; init; }
    /// <summary>Throw (unmapped_subject) instead of reporting when a revoking event's subject cannot be mapped (only true counts).</summary>
    public bool? FailOnUnmapped { get; init; }
}

public sealed class ReceiveSetOptions
{
    public object? Issuer { get; init; }
    public object? Audience { get; init; }
    public ISetReplayStore? ReplayStore { get; init; }
    public SetRevocationState? State { get; init; }
    /// <summary>Required, finite and positive.</summary>
    public double? MaxAgeSec { get; init; }
    public double? ClockSkewSec { get; init; }
    public double? NowSec { get; init; }
    public double? MaxBytes { get; init; }
    public StandardRevocationOptions? StandardRevocations { get; init; }
}

/// <summary>A receive result; every refusal is a value, never a throw. Codes: misconfigured, oversize, malformed, verify_failed, iat_missing,
/// iat_future, iat_stale, unmapped_subject, replay, replay_store_error.</summary>
public sealed record ReceiveSetResult(bool Ok, ParsedSet? Parsed = null, string? Code = null, string? Reason = null);

public sealed record RevocationHookResult(bool Enforced, bool Ok, string? Reason = null);

public sealed class RevocationAdapterOptions
{
    /// <summary>The agent id a kill-switch names for (pcactn, grant). Default: the PCActn's leaf holder key.</summary>
    public Func<object?, object?, object?>? AgentOf { get; init; }
}

public static class Signals
{
    /// <summary>RFC 8417 section 2.3: a SET SHOULD carry typ secevent+jwt.</summary>
    public const string SetTyp = "secevent+jwt";
    public const string SetAlg = "EdDSA";
    public const int SetInMemoryMaxEntries = 100_000;

    public static class EventTypes
    {
        public const string SessionRevoked = "https://schemas.openid.net/secevent/caep/event-type/session-revoked";
        public const string CredentialChange = "https://schemas.openid.net/secevent/caep/event-type/credential-change";
        public const string GrantRevoked = "https://atlasauth.net/caep/grant-revoked";
        public const string KillSwitch = "https://atlasauth.net/caep/kill-switch";
        public const string IntentRevoked = "https://atlasauth.net/caep/intent-revoked";
        public const string Verification = "https://schemas.openid.net/secevent/ssf/event-type/verification";
        public const string RiskLevelChange = "https://schemas.openid.net/secevent/caep/event-type/risk-level-change";
        public const string AssuranceLevelChange = "https://schemas.openid.net/secevent/caep/event-type/assurance-level-change";
    }

    /// <summary>RISC event types that end an account's standing: treated as revoking every grant of the mapped agent.</summary>
    public static class RiscEventTypes
    {
        public const string SessionsRevoked = "https://schemas.openid.net/secevent/risc/event-type/sessions-revoked";
        public const string AccountDisabled = "https://schemas.openid.net/secevent/risc/event-type/account-disabled";
        public const string AccountPurged = "https://schemas.openid.net/secevent/risc/event-type/account-purged";
        public const string CredentialCompromise = "https://schemas.openid.net/secevent/risc/event-type/credential-compromise";
    }

    static readonly string[] RiscTypes = { RiscEventTypes.SessionsRevoked, RiscEventTypes.AccountDisabled, RiscEventTypes.AccountPurged, RiscEventTypes.CredentialCompromise };

    // ---------------------------------------------------------------- small JS-semantics helpers

    internal static double V(Num n) => double.Parse(n.Raw, NumberStyles.Float, CultureInfo.InvariantCulture);
    static readonly Num Zero = new("0");

    static bool IsRecord(object? v) => v is D;

    /// <summary>A property read the way JavaScript does it: a null / undefined receiver throws, an object yields its member, anything else undefined.</summary>
    internal static object? Prop(object? o, string name) => o switch
    {
        null => throw new InvalidOperationException("Cannot read properties of null (reading '" + name + "')"),
        D d => d.GetValueOrDefault(name),
        _ => null,
    };

    /// <summary>Object.entries: an object's members, an array's index entries, a string's characters; a number / boolean has none; null / undefined throw.</summary>
    internal static IEnumerable<(string Type, object? Ev)> Entries(object? events) => events switch
    {
        null => throw new InvalidOperationException("Cannot convert undefined or null to object"),
        D d => d.Select(e => (e.Key, e.Value)).ToList(),
        L l => l.Select((v, i) => (i.ToString(CultureInfo.InvariantCulture), v)).ToList(),
        string s => s.Select((c, i) => (i.ToString(CultureInfo.InvariantCulture), (object?)c.ToString())).ToList(),
        _ => new List<(string, object?)>(),
    };

    static Num TsOf(object? ev) => Prop(ev, "event_timestamp") is Num n ? n : Zero;

    static void RecordMax(Dictionary<string, Num> m, string key, Num ts)
    {
        if (!m.TryGetValue(key, out var prev) || V(ts) > V(prev)) m[key] = ts;
    }

    // ---------------------------------------------------------------- build / verify

    /// <summary>Build a signed Security Event Token (RFC 8417): typ secevent+jwt, iss, iat, a random jti, aud, the events map and (if given) sub + sub_id.</summary>
    public static string BuildSet(D events, string issuer, object audience, string? subject, object privateKey)
    {
        if (events.Count == 0) throw new InvalidOperationException("buildSET: at least one event is required in the `events` map (RFC 8417 \u00a72.2)");
        // the reference imports the key through node:crypto: a JWK that is not an object, or carries no private part, is refused with its code
        if (privateKey is D kj)
        {
            if (kj.Count == 0) throw new AtlasPca.Grants.CodedException("ERR_CRYPTO_INVALID_JWK", "Invalid JWK format");
            if (!kj.ContainsKey("d") && kj.GetValueOrDefault("kty") is string) throw new AtlasPca.Grants.CodedException("ERR_CRYPTO_INVALID_JWK", "JWK does not contain private key material");
        }
        var payload = new D { ["events"] = events };
        if (subject != null) payload["sub_id"] = new D { ["format"] = "opaque", ["id"] = subject };
        payload["iss"] = issuer;
        payload["iat"] = new Num(DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture));
        payload["jti"] = Guid.NewGuid().ToString();
        payload["aud"] = audience;
        if (subject != null) payload["sub"] = subject;
        return J.SignJwt(new D { ["alg"] = SetAlg, ["typ"] = SetTyp }, payload, privateKey);
    }

    static D ParseEvents(object? raw)
    {
        if (raw is not D d) throw new InvalidOperationException("SET invalid: `events` claim is missing or not a JSON object (RFC 8417 \u00a72.2)");
        if (d.Count == 0) throw new InvalidOperationException("SET invalid: `events` claim is empty (RFC 8417 \u00a72.2)");
        foreach (var (k, v) in d)
            if (!IsRecord(v)) throw new InvalidOperationException($"SET invalid: event payload for `{k}` is not a JSON object (RFC 8417 \u00a72.2)");
        return d;
    }

    /// <summary>Verify a SET's signature (EdDSA) and standard claims, then parse it. Throws on a bad signature, wrong key, failed claim check or malformed events map.</summary>
    public static ParsedSet VerifySet(object? set, object? verifyKey, VerifySetOptions? opts = null)
    {
        opts ??= new VerifySetOptions();
        J.AssertCanonicalCompactJws(set); // canonical-spelling gate BEFORE the JOSE layer (one accepted string form)
        var jo = new AtlasPca.Jose.JwtVerifyOptions
        {
            Algorithms = new[] { SetAlg },
            IssuerString = opts.Issuer as string,
            IssuerList = ListOf(opts.Issuer),
            AudienceString = opts.Audience as string,
            AudienceList = ListOf(opts.Audience),
            ClockTolerance = opts.ClockTolerance,
            CurrentDateMs = opts.CurrentDateMs,
            Typ = opts.RequireTyp == false ? null : opts.Typ ?? SetTyp,
        };
        var payload = J.JwtVerify((string)set!, verifyKey, jo).Payload;
        if (payload.GetValueOrDefault("iss") is not string iss) throw new InvalidOperationException("SET invalid: missing or non-string `iss`");
        if (payload.GetValueOrDefault("jti") is not string jti) throw new InvalidOperationException("SET invalid: missing or non-string `jti` (RFC 8417 \u00a72.2 requires it)");
        var events = ParseEvents(payload.GetValueOrDefault("events"));
        return new ParsedSet { Events = events, Iss = iss, Jti = jti, Sub = payload.GetValueOrDefault("sub") as string, Payload = payload };
    }

    static IReadOnlyList<string>? ListOf(object? v) => v switch
    {
        IReadOnlyList<string> s => s,
        L l => l.Select(x => x as string ?? throw new ArgumentException("an issuer / audience list holds strings")).ToList(),
        _ => null,
    };

    // ---------------------------------------------------------------- revocation state

    public static SetRevocationState CreateRevocationState() => new();

    static SetRevocationState AssertState(SetRevocationState? state) =>
        state ?? throw new SignalsException("misconfigured", "state must come from createRevocationState()");

    /// <summary>Fold one verified SET into the state: grant-revoked adds its grant_ref, kill-switch revokes every grant of its agent (and any explicit
    /// grant_ref), intent-revoked records its namespaced ids. Each key keeps the MAX timestamp, so a stale event never regresses the state.</summary>
    public static SetRevocationState ApplySet(SetRevocationState state, ParsedSet parsed)
    {
        foreach (var (type, ev) in Entries(parsed.Events))
        {
            var ts = TsOf(ev);
            if (type == EventTypes.GrantRevoked)
            {
                if (Prop(ev, "grant_ref") is string g && g.Length > 0) RecordMax(state.RevokedGrants, g, ts);
            }
            else if (type == EventTypes.KillSwitch)
            {
                if (Prop(ev, "agent") is string a && a.Length > 0) RecordMax(state.KilledAgents, a, ts);
                if (Prop(ev, "grant_ref") is string g && g.Length > 0) RecordMax(state.RevokedGrants, g, ts);
            }
            else if (type == EventTypes.IntentRevoked)
            {
                if (Prop(ev, "ids") is L ids)
                    foreach (var id in ids)
                        if (id is string s && s.StartsWith("pca-intent:", StringComparison.Ordinal)) RecordMax(state.RevokedIntentIds ??= new(), s, ts);
            }
        }
        return state;
    }

    /// <summary>Has a pushed intent-revoked event named this intent revocation id? (Best effort; the epoch pull bound decides.)</summary>
    public static bool IsIntentRevoked(SetRevocationState state, string id) => state.RevokedIntentIds?.ContainsKey(id) == true;

    /// <summary>True if the grant_ref was revoked directly or, when <paramref name="agent"/> is given, a kill-switch revoked that agent.</summary>
    public static bool IsRevoked(SetRevocationState state, string grantRef, string? agent = null) =>
        state.RevokedGrants.ContainsKey(grantRef) || (agent != null && state.KilledAgents.ContainsKey(agent));

    static double SetTimestamp(ParsedSet p)
    {
        double min = double.PositiveInfinity;
        foreach (var (_, ev) in Entries(p.Events))
            if (Prop(ev, "event_timestamp") is Num n && V(n) < min) min = V(n);
        return double.IsFinite(min) ? min : 0;
    }

    /// <summary>Fold a sequence of verified SETs into one state in ascending event_timestamp order (stable); returns the (optionally supplied) state.</summary>
    public static SetRevocationState StreamProcessor(IEnumerable<ParsedSet> parsedSets, SetRevocationState? state = null)
    {
        state ??= CreateRevocationState();
        var all = parsedSets.ToList();
        var keyed = all.Count < 2 ? all : all.OrderBy(SetTimestamp).ToList(); // the reference's sort never calls its comparator on fewer than two
        foreach (var p in keyed) ApplySet(state, p);
        return state;
    }

    // ---------------------------------------------------------------- replay store

    sealed class InMemoryReplayStore(double max) : ISetReplayStore
    {
        readonly object _gate = new();
        readonly Dictionary<string, double> _seen = new();

        public bool AddIfAbsent(string jti, double expiresAtSec, double nowSec)
        {
            if (!double.IsFinite(nowSec) || !double.IsFinite(expiresAtSec)) return false;
            lock (_gate)
            {
                var found = _seen.TryGetValue(jti, out var held);
                if (found && !(nowSec >= held)) return false;
                if (!found && _seen.Count >= max)
                {
                    foreach (var k in _seen.Where(e => nowSec >= e.Value).Select(e => e.Key).ToList()) _seen.Remove(k);
                    if (_seen.Count >= max) throw new InvalidOperationException("replay store is full");
                }
                _seen[jti] = expiresAtSec;
                return true;
            }
        }
    }

    /// <summary>Single-process store, explicitly bounded: at <c>maxEntries</c> live entries a further new jti makes <c>AddIfAbsent</c> THROW (receive then refuses
    /// with replay_store_error) instead of evicting a live entry, so a flood can never reopen a replay window. <paramref name="maxEntries"/> is a JSON value
    /// (null = the default); anything but a positive integer is refused.</summary>
    public static ISetReplayStore CreateInMemorySetReplayStore(object? maxEntries = null)
    {
        double max = SetInMemoryMaxEntries;
        if (maxEntries != null)
        {
            var v = maxEntries is Num n ? V(n) : maxEntries is int or long ? Convert.ToDouble(maxEntries, CultureInfo.InvariantCulture) : double.NaN;
            if (double.IsNaN(v) || v != Math.Floor(v) || double.IsInfinity(v) || v < 1) throw new SignalsException("misconfigured", "maxEntries must be a positive integer");
            max = v;
        }
        return new InMemoryReplayStore(max);
    }

    /// <summary>Conformance suite for a replay store: returns the failed checks (empty = conformant). <paramref name="make"/> returns a FRESH, empty store each call.</summary>
    public static List<string> RunSetReplayStoreConformance(Func<ISetReplayStore> make)
    {
        var failures = new List<string>();
        void Check(bool ok, string name) { if (!ok) failures.Add(name); }
        var s = make();
        Check(s.AddIfAbsent("a", 200, 100), "first sight of a jti returns true");
        Check(!s.AddIfAbsent("a", 200, 101), "second sight of the same jti returns false");
        Check(s.AddIfAbsent("b", 200, 101), "a different jti is independent");
        Check(!s.AddIfAbsent("a", 200, 199), "still seen one second before expiry");
        var t = make();
        t.AddIfAbsent("c", 200, 100);
        Check(t.AddIfAbsent("c", 400, 200), "an expired entry may be added again (nowSec >= expiresAtSec)");
        var u = make();
        var tasks = Enumerable.Range(0, 16).Select(_ => Task.Run(() => u.AddIfAbsent("race", 200, 100))).ToArray();
        Task.WaitAll(tasks);
        int wins = tasks.Count(x => x.Result);
        Check(wins == 1, $"16 concurrent adds of one jti: exactly one wins (got {wins})");
        return failures;
    }

    // ---------------------------------------------------------------- receiver

    static ReceiveSetResult Fails(string code, string reason) => new(false, null, code, reason);

    internal static string JsNum(double v) => v == Math.Floor(v) && Math.Abs(v) < 1e15 ? ((long)v).ToString(CultureInfo.InvariantCulture) : v.ToString("R", CultureInfo.InvariantCulture);

    /// <summary>The recommended receive path: size cap, canonical spelling, EdDSA signature, typ, required iss and aud, iat freshness window, atomic jti replay
    /// guard, then fold into the state. The jti is recorded only after every other check passed, so a forged token cannot burn a real SET's id. Fails closed on
    /// every error, including a replay store that throws (the SET is NOT applied).</summary>
    public static ReceiveSetResult ReceiveSet(object? set, object? verifyKey, ReceiveSetOptions? opts)
    {
        if (opts == null || opts.Issuer == null || opts.Audience == null || opts.ReplayStore == null || opts.State == null
            || opts.MaxAgeSec is not double maxAge || !double.IsFinite(maxAge) || maxAge <= 0)
            return Fails("misconfigured", "issuer, audience, replayStore, state and a positive maxAgeSec are all required");
        if (set is not string str || str.Length > (opts.MaxBytes ?? 16384)) return Fails("oversize", "SET is not a string or exceeds maxBytes");
        try { J.AssertCanonicalCompactJws(str); }
        catch (Exception e) { return Fails("malformed", e.Message); }
        double nowSec = opts.NowSec ?? Math.Floor(DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() / 1000.0);
        ParsedSet parsed;
        try { parsed = VerifySet(str, verifyKey, new VerifySetOptions { Issuer = opts.Issuer, Audience = opts.Audience, CurrentDateMs = nowSec * 1000 }); }
        catch (Exception e) { return Fails("verify_failed", e.Message); }
        if (((D)parsed.Payload!).GetValueOrDefault("iat") is not Num iatNum || !double.IsFinite(V(iatNum))) return Fails("iat_missing", "SET has no numeric iat");
        double iat = V(iatNum);
        double skew = opts.ClockSkewSec ?? 60;
        if (!(double.IsFinite(nowSec) && double.IsFinite(skew) && iat <= nowSec + skew)) return Fails("iat_future", "SET iat is in the future");
        if (!(nowSec - iat <= maxAge)) return Fails("iat_stale", $"SET is older than {JsNum(maxAge)}s");
        StandardRevocationPlan? plan = null;
        if (opts.StandardRevocations != null)
        {
            try { plan = PlanStandardRevocations(parsed, opts.StandardRevocations); }
            catch (Exception e) { return Fails("unmapped_subject", e.Message); }
        }
        bool fresh;
        try { fresh = opts.ReplayStore.AddIfAbsent(parsed.Jti!, iat + maxAge + skew, nowSec); }
        catch (Exception e) { return Fails("replay_store_error", e.Message); }
        if (!fresh) return Fails("replay", $"jti '{parsed.Jti}' has already been received");
        ApplySet(opts.State, parsed);
        if (plan != null) ApplyStandardPlan(opts.State, plan);
        return new ReceiveSetResult(true, parsed);
    }

    // ---------------------------------------------------------------- standard (CAEP / RISC) revocation events

    static object? DefaultSubjectToAgent(D subject) =>
        subject.GetValueOrDefault("format") is "opaque" && subject.GetValueOrDefault("id") is string id && id.Length > 0 ? id : null;

    static bool IsRevokingStandardEvent(string type, object? ev)
    {
        if (type == EventTypes.SessionRevoked) return true;
        if (type == EventTypes.CredentialChange) return Prop(ev, "change_type") is not "create"; // unknown / absent => revoke (fail closed)
        return RiscTypes.Contains(type);
    }

    /// <summary>Decide, without touching any state, which agents a verified SET's standard events revoke: CAEP session-revoked, CAEP credential-change (every
    /// change_type except create; an absent or unknown one counts) and the RISC types. The subject is the event's own, else the SET-level sub_id. A revoking
    /// event with no mappable subject is listed in <c>Unmapped</c> (or throws under FailOnUnmapped).</summary>
    public static StandardRevocationPlan PlanStandardRevocations(ParsedSet parsed, StandardRevocationOptions? opts = null)
    {
        var toAgent = opts?.SubjectToAgent ?? DefaultSubjectToAgent;
        var plan = new StandardRevocationPlan(new(), new());
        var subId = Prop(parsed.Payload, "sub_id");
        D? setSubject = subId as D;
        foreach (var (type, ev) in Entries(parsed.Events))
        {
            if (!IsRevokingStandardEvent(type, ev)) continue;
            var own = Prop(ev, "subject") as D ?? setSubject;
            object? agent = null;
            if (own != null && own.GetValueOrDefault("format") is string)
            {
                try { agent = toAgent(own); }
                catch (Exception) { agent = null; }
            }
            if (agent is not string a || a.Length == 0)
            {
                if (opts?.FailOnUnmapped == true) throw new SignalsException("unmapped_subject", $"event '{type}' names no mappable agent");
                plan.Unmapped.Add(type);
                continue;
            }
            plan.Agents.Add((a, TsOf(ev)));
        }
        return plan;
    }

    static void ApplyStandardPlan(SetRevocationState state, StandardRevocationPlan plan)
    {
        foreach (var (agent, ts) in plan.Agents) RecordMax(state.KilledAgents, agent, ts);
    }

    /// <summary>Plan then apply: monotone, max-timestamp. Returns the plan that was applied.</summary>
    public static StandardRevocationPlan ApplyStandardRevocations(SetRevocationState? state, ParsedSet parsed, StandardRevocationOptions? opts = null)
    {
        AssertState(state);
        var plan = PlanStandardRevocations(parsed, opts);
        ApplyStandardPlan(state!, plan);
        return plan;
    }

    // ---------------------------------------------------------------- adapters for authorize()

    static object? LeafHolderAgent(object? pcactn, object? _)
    {
        var chain = Prop(pcactn, "cap_chain");
        if (chain == null) throw new InvalidOperationException("Cannot read properties of undefined (reading 'length')");
        return chain is L l && l.Count > 0 && l[^1] is D last ? last.GetValueOrDefault("holder") : null;
    }

    /// <summary>The reason a PCActn under <paramref name="grant"/> is revoked by <paramref name="state"/>, or null when it is not. Anything undecidable is a reason.</summary>
    static string? RevocationReason(SetRevocationState state, object? pcactn, object? grant, Func<object?, object?, object?> agentOf)
    {
        try
        {
            if (Prop(pcactn, "grant_ref") is not string reference || reference.Length == 0) return "grant_ref is missing";
            if (state.RevokedGrants.ContainsKey(reference)) return "grant revoked by signal";
            if (grant is D g && g.GetValueOrDefault("id") is string gid && state.RevokedGrants.ContainsKey(gid)) return "grant revoked by signal";
            if (agentOf(pcactn, grant) is not string agent || agent.Length == 0) return "agent could not be determined";
            if (state.KilledAgents.ContainsKey(agent)) return "agent killed by signal";
            return null;
        }
        catch (Exception) { return "revocation check error (fail closed)"; }
    }

    /// <summary>A revocation hook for authorize(): reads <paramref name="state"/> LIVE on every call, always reports Enforced = true; a revoked grant, a revoked or
    /// undeterminable agent, or any error denies.</summary>
    public static Func<object?, object?, RevocationHookResult> CreateRevocationHook(SetRevocationState? state, RevocationAdapterOptions? opts = null)
    {
        var st = AssertState(state);
        var agentOf = opts?.AgentOf ?? LeafHolderAgent;
        return (pcactn, grant) => RevocationReason(st, pcactn, grant, agentOf) is { } reason ? new(true, false, reason) : new(true, true);
    }

    /// <summary>The same decision as authorizeExecution's isRevoked(grant, pcactn): true when revoked or undeterminable (fail closed).</summary>
    public static Func<object?, object?, bool> CreateIsRevoked(SetRevocationState? state, RevocationAdapterOptions? opts = null)
    {
        var st = AssertState(state);
        var agentOf = opts?.AgentOf ?? LeafHolderAgent;
        return (grant, pcactn) => RevocationReason(st, pcactn, grant, agentOf) != null;
    }

    // ---------------------------------------------------------------- snapshot / restore

    /// <summary>Copy the state into a plain JSON-safe snapshot {v: 1, grants, agents, intents} (arrays of [key, timestamp]). Persist it after every accepted SET.</summary>
    public static D SnapshotRevocationState(SetRevocationState? state)
    {
        var st = AssertState(state);
        static L Pairs(IEnumerable<KeyValuePair<string, Num>>? m) => (m ?? Enumerable.Empty<KeyValuePair<string, Num>>()).Select(e => (object?)new L { e.Key, e.Value }).ToList();
        return new D { ["v"] = new Num("1"), ["grants"] = Pairs(st.RevokedGrants), ["agents"] = Pairs(st.KilledAgents), ["intents"] = Pairs(st.RevokedIntentIds) };
    }

    static List<(string, Num)> PairsOf(object? v, string what)
    {
        if (v is not L list) throw new SignalsException("bad_snapshot", $"{what} is not an array");
        var o = new List<(string, Num)>();
        foreach (var p in list)
        {
            if (p is not L { Count: 2 } pair || pair[0] is not string k || k.Length == 0 || pair[1] is not Num t || !double.IsFinite(V(t)))
                throw new SignalsException("bad_snapshot", $"{what} holds an entry that is not [string, number]");
            o.Add((k, t));
        }
        return o;
    }

    /// <summary>Merge a snapshot into a fresh state.</summary>
    public static SetRevocationState RestoreRevocationState(object? snapshot) => RestoreRevocationState(snapshot, CreateRevocationState());

    /// <summary>Merge a snapshot into <paramref name="into"/>. Strict: any shape error throws bad_snapshot and <paramref name="into"/> is not touched. Merging is
    /// monotone (max timestamp), so restoring never un-revokes anything already in <paramref name="into"/>.</summary>
    public static SetRevocationState RestoreRevocationState(object? snapshot, SetRevocationState? into)
    {
        var st = AssertState(into);
        if (snapshot is not D s || s.GetValueOrDefault("v") is not Num v || v.Raw != "1" && V(v) != 1) throw new SignalsException("bad_snapshot", "snapshot is not a version 1 object");
        var extra = s.Keys.FirstOrDefault(k => k is not ("v" or "grants" or "agents" or "intents"));
        if (extra != null) throw new SignalsException("bad_snapshot", $"snapshot has unknown member '{extra}'");
        var grants = PairsOf(s.GetValueOrDefault("grants"), "grants");
        var agents = PairsOf(s.GetValueOrDefault("agents"), "agents");
        var intents = PairsOf(s.GetValueOrDefault("intents"), "intents");
        foreach (var (k, t) in grants) RecordMax(st.RevokedGrants, k, t);
        foreach (var (k, t) in agents) RecordMax(st.KilledAgents, k, t);
        foreach (var (k, t) in intents) RecordMax(st.RevokedIntentIds ??= new(), k, t);
        return st;
    }
}

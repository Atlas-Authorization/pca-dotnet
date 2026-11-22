// Realtime revocation and a mid-run kill-switch for Proof-Carrying Authority: a pluggable registry of revocations keyed by capability id,
// holder key, issuer key or delegation-subtree prefix; the chain check (fail closed); the core-verify AND revocation gate; the CAEP bridge.
// Entries, inputs and PCActns are JSON trees (Dictionary), like the reference's plain objects; every store call is a Task.
using System.Globalization;
using AtlasPca.Js;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Revoke;

/// <summary>The backing store of a <see cref="RevocationRegistry"/>. Point kinds are addressed by (kind, value); prefix entries are scanned via <c>All</c>.</summary>
public interface IRevocationStore
{
    /// <summary>Insert or replace the entry at its (kind, value) key; atomic: once it completes every reader sees it.</summary>
    Task Add(D entry);
    Task<bool> Remove(string kind, string value);
    Task<D?> Get(string kind, string value);
    /// <summary>Every stored entry (a snapshot).</summary>
    Task<IReadOnlyList<D>> All();
    Task Clear();
}

/// <summary>The in-memory store (the default): single process, insertion order kept (a replaced entry keeps its place).</summary>
public sealed class InMemoryRevocationStore : IRevocationStore
{
    readonly object _gate = new();
    readonly List<string> _order = new();
    readonly Dictionary<string, D> _entries = new();

    /// <summary>The store key: the JavaScript template string of kind and value joined by NUL (a missing member prints "undefined").</summary>
    internal static string Key(string kind, string value) => kind + "\u0000" + value;

    public Task Add(D entry)
    {
        var k = Key(RevokeApi.Text(entry, "kind"), RevokeApi.Text(entry, "value"));
        lock (_gate)
        {
            if (!_entries.ContainsKey(k)) _order.Add(k);
            _entries[k] = entry;
        }
        return Task.CompletedTask;
    }

    public Task<bool> Remove(string kind, string value)
    {
        var k = Key(kind, value);
        lock (_gate)
        {
            if (!_entries.Remove(k)) return Task.FromResult(false);
            _order.Remove(k);
            return Task.FromResult(true);
        }
    }

    public Task<D?> Get(string kind, string value)
    {
        lock (_gate) return Task.FromResult(_entries.GetValueOrDefault(Key(kind, value)));
    }

    public Task<IReadOnlyList<D>> All()
    {
        lock (_gate) return Task.FromResult<IReadOnlyList<D>>(_order.Select(k => _entries[k]).ToList());
    }

    public Task Clear()
    {
        lock (_gate) { _entries.Clear(); _order.Clear(); }
        return Task.CompletedTask;
    }
}

/// <summary>A live, mutable registry of revocations. An entry is {kind, value, prefix?, reason, revokedAt, notBefore?}.</summary>
public sealed class RevocationRegistry
{
    readonly IRevocationStore _store;
    readonly Func<double> _now;

    public RevocationRegistry(IRevocationStore? store = null, Func<double>? now = null)
    {
        _store = store ?? new InMemoryRevocationStore();
        _now = now ?? (() => AtlasPca.ReplayClock.NowMs());
    }

    internal double Now() => _now();

    static bool FiniteNum(object? v) => v is Num n && double.TryParse(n.Raw, NumberStyles.Float, CultureInfo.InvariantCulture, out var d) && double.IsFinite(d);
    static Num Ms(double v) => new(JsJson.NumberToString(v));

    /// <summary>Revoke a capability id, holder key, issuer key or subtree prefix. <paramref name="input"/>: {kind, value | prefix, reason?, revokedAt?, notBefore?}. Throws (TypeError in the reference) on a malformed input. Returns the stored entry.</summary>
    public async Task<D> Revoke(D? input)
    {
        if (input == null) throw new ArgumentException("revoke: input is required");
        var revokedAt = input.GetValueOrDefault("revokedAt") ?? Ms(_now());
        var reason = input.GetValueOrDefault("reason") ?? "";
        if (!FiniteNum(revokedAt)) throw new ArgumentException("revoke: revokedAt must be a finite number");
        if (input.TryGetValue("notBefore", out var nb) && !FiniteNum(nb)) throw new ArgumentException("revoke: notBefore must be a finite number");
        if (reason is not string reasonText) throw new ArgumentException("revoke: reason must be a string");
        D entry;
        if (input.GetValueOrDefault("kind") as string == "prefix")
        {
            if (input.GetValueOrDefault("prefix") is not L prefix || prefix.Count == 0) throw new ArgumentException("revoke: a prefix revocation requires a non-empty cap-id path");
            if (prefix.Any(id => id is not string s || s.Length == 0 || s.Contains(RevokeApi.PrefixSep))) throw new ArgumentException("revoke: every prefix element must be a non-empty string without ','");
            entry = new D { ["kind"] = "prefix", ["value"] = RevokeApi.SerializePrefix(prefix), ["prefix"] = new L(prefix), ["reason"] = reasonText, ["revokedAt"] = revokedAt };
        }
        else
        {
            if (input.GetValueOrDefault("value") is not string value || value.Length == 0)
                throw new ArgumentException($"revoke: a {RevokeApi.Text(input, "kind")} revocation requires a non-empty value");
            entry = new D();
            if (input.TryGetValue("kind", out var kind)) entry["kind"] = kind;
            entry["value"] = value;
            entry["reason"] = reasonText;
            entry["revokedAt"] = revokedAt;
        }
        if (input.ContainsKey("notBefore")) entry["notBefore"] = input["notBefore"];
        await _store.Add(entry).ConfigureAwait(false);
        return entry;
    }

    /// <summary>Revoke a whole delegation subtree: a string target revokes the capability (and so every chain through it), an array target the cap-id path prefix.</summary>
    public Task<D> RevokeSubtree(object? target, D? opts = null)
    {
        var input = new D();
        if (target is L) { input["kind"] = "prefix"; input["prefix"] = target; }
        else { input["kind"] = "cap"; input["value"] = target; }
        if (opts != null) foreach (var e in opts) input[e.Key] = e.Value;
        return Revoke(input);
    }

    /// <summary>Remove a revocation: {kind, value} or {kind: "prefix", prefix}. True when one was removed.</summary>
    public async Task<bool> Unrevoke(D? key)
    {
        if (key == null) throw new ArgumentException("unrevoke: key is required");
        if (key.GetValueOrDefault("kind") as string == "prefix")
        {
            if (key.GetValueOrDefault("prefix") is not L prefix || prefix.Count == 0) return false;
            return await _store.Remove("prefix", RevokeApi.SerializePrefix(prefix)).ConfigureAwait(false);
        }
        return await _store.Remove(RevokeApi.Text(key, "kind"), RevokeApi.Text(key, "value")).ConfigureAwait(false);
    }

    /// <summary>Every active-or-scheduled revocation (a snapshot).</summary>
    public Task<IReadOnlyList<D>> List() => _store.All();

    /// <summary>Point lookup of a cap / holder / issuer revocation.</summary>
    public Task<D?> Lookup(string kind, string value) => _store.Get(kind, value);

    /// <summary>Every subtree-prefix revocation.</summary>
    public async Task<IReadOnlyList<D>> Prefixes() => (await _store.All().ConfigureAwait(false)).Where(e => e.GetValueOrDefault("kind") as string == "prefix").ToList();

    public Task Clear() => _store.Clear();

    /// <summary>KILL-SWITCH: instantly revoke an agent by its holder key. <paramref name="opts"/>: reason?, revokedAt?.</summary>
    public Task<D> KillAgent(object? holder, D? opts = null) => Revoke(new D
    {
        ["kind"] = "holder", ["value"] = holder, ["reason"] = opts?.GetValueOrDefault("reason") ?? "kill-switch: agent killed", ["revokedAt"] = opts?.GetValueOrDefault("revokedAt"),
    });

    /// <summary>KILL-SWITCH: instantly revoke the delegation subtree rooted at a capability id.</summary>
    public Task<D> KillSubtree(object? rootCapId, D? opts = null) => Revoke(new D
    {
        ["kind"] = "cap", ["value"] = rootCapId, ["reason"] = opts?.GetValueOrDefault("reason") ?? "kill-switch: subtree killed", ["revokedAt"] = opts?.GetValueOrDefault("revokedAt"),
    });
}

public static class RevokeApi
{
    public const string PrefixSep = ",";
    public const string SessionRevoked = "https://schemas.openid.net/secevent/caep/event-type/session-revoked";
    public const string GrantRevoked = "https://atlasauth.net/caep/grant-revoked";
    public const string KillSwitch = "https://atlasauth.net/caep/kill-switch";

    /// <summary>The CAEP / PCA event-type URIs: {sessionRevoked, grantRevoked, killSwitch}.</summary>
    public static D CaepEventTypes() => new() { ["sessionRevoked"] = SessionRevoked, ["grantRevoked"] = GrantRevoked, ["killSwitch"] = KillSwitch };

    /// <summary>The JavaScript template-string text of a member (missing: "undefined").</summary>
    internal static string Text(D? d, string k) => d != null && d.TryGetValue(k, out var v) ? (v == null ? "null" : JsJson.ToJsString(v)) : "undefined";

    internal static string SerializePrefix(L prefix) => string.Join(PrefixSep, prefix.Select(p => p == null ? "" : JsJson.ToJsString(p)));

    /// <summary>True when the revocation is in effect at <paramref name="now"/> (a future `notBefore` has not yet been reached). Fail closed: a non-finite clock or schedule always bites.</summary>
    public static bool IsActiveAt(D entry, object? now)
    {
        if (!entry.TryGetValue("notBefore", out var nb)) return true;
        if (Fin(now) is not double n || Fin(nb) is not double b) return true;
        return n >= b;
    }

    static double? Fin(object? v) => v is Num x && double.TryParse(x.Raw, NumberStyles.Float, CultureInfo.InvariantCulture, out var d) && double.IsFinite(d) ? d : null;

    static D Closed(string why) => new() { ["revoked"] = true, ["reason"] = "revocation check failed closed: " + why };

    static string MatchReason(D entry)
    {
        var b = $"{Text(entry, "kind")} {Text(entry, "value")} is revoked";
        return ((string)entry["reason"]!).Length > 0 ? b + ": " + (string)entry["reason"]! : b;
    }

    static bool StartsWith(List<string> ids, L prefix)
    {
        if (prefix.Count == 0 || ids.Count < prefix.Count) return false;
        for (var i = 0; i < prefix.Count; i++) if (prefix[i] as string != ids[i]) return false;
        return true;
    }

    static string? Str(object? hop, string k) => hop is D h && h.GetValueOrDefault(k) is string s && s.Length > 0 ? s : null;

    /// <summary>The revocation check; never throws and never reports "not revoked" because it could not look: a missing or malformed chain, a hop without a non-empty id / issuer / holder, a non-finite clock or a failing store all yield {revoked: true, reason: "revocation check failed closed: ..."}. <paramref name="opts"/>: {now?}.</summary>
    public static async Task<D> CheckRevocation(object? p, RevocationRegistry registry, D? opts = null)
    {
        var nowV = opts?.GetValueOrDefault("now") ?? new Num(JsJson.NumberToString(registry.Now()));
        if (Fin(nowV) is not double now) return Closed("clock is not a finite number");
        if ((p as D)?.GetValueOrDefault("cap_chain") is not L chain || chain.Count == 0) return Closed("the action carries no capability chain");
        foreach (var hop in chain)
            foreach (var k in new[] { "id", "issuer", "holder" })
                if (Str(hop, k) == null) return Closed($"a chain hop has no {k}");
        try
        {
            var ids = new List<string>();
            foreach (var hop in chain)
            {
                foreach (var (kind, key) in new[] { ("cap", Str(hop, "id")), ("issuer", Str(hop, "issuer")), ("holder", Str(hop, "holder")) })
                {
                    if (key == null) continue;
                    var entry = await registry.Lookup(kind, key).ConfigureAwait(false);
                    if (entry != null && IsActiveAt(entry, new Num(JsJson.NumberToString(now)))) return new D { ["revoked"] = true, ["matched"] = entry, ["reason"] = MatchReason(entry) };
                }
                if (Str(hop, "id") is { } id) ids.Add(id);
            }
            foreach (var entry in await registry.Prefixes().ConfigureAwait(false))
                if (entry.GetValueOrDefault("prefix") is L prefix && StartsWith(ids, prefix) && IsActiveAt(entry, new Num(JsJson.NumberToString(now))))
                    return new D { ["revoked"] = true, ["matched"] = entry, ["reason"] = MatchReason(entry) };
            return new D { ["revoked"] = false };
        }
        catch (Exception)
        {
            // the reference names the error class; every native store failure is an Error
            return Closed("the revocation store failed (Error)");
        }
    }

    /// <summary>The core outcome ANDed with the revocation gate: allow only if the core allowed AND nothing in the chain is revoked.</summary>
    public static async Task<D> VerifyWithRevocation(object? p, object? coreVerifyResult, RevocationRegistry registry, D? opts = null)
    {
        var core = coreVerifyResult as D;
        var coreAllow = core != null && core.GetValueOrDefault("allow") is true;
        var revocation = await CheckRevocation(p, registry, opts).ConfigureAwait(false);
        var allow = coreAllow && revocation["revoked"] is not true;
        var res = new D { ["allow"] = allow, ["coreAllow"] = coreAllow, ["revocation"] = revocation };
        if (allow) return res;
        res["reason"] = !coreAllow ? (core?.GetValueOrDefault("reason") ?? "core verification failed") : (revocation.GetValueOrDefault("reason") ?? "revoked");
        return res;
    }

    // ---- CAEP bridge ----

    static string? StringField(object? subject, string key)
    {
        if (subject == null) throw new ArgumentException("subject is null");
        return subject is D d && d.GetValueOrDefault(key) is string s && s.Length > 0 ? s : null;
    }

    /// <summary>CAEP `event_timestamp` is integer seconds; the registry records epoch ms (Math.round semantics).</summary>
    static object RevokedAtFrom(object? ts, RevocationRegistry registry)
    {
        if (Fin(ts) is double d)
        {
            var x = d * 1000;
            return new Num(JsJson.NumberToString(Math.Abs(x) >= 4503599627370496.0 ? x : Math.Floor(x + 0.5)));
        }
        return new Num(JsJson.NumberToString(registry.Now()));
    }

    static object? Field(object payload, string k) => (payload as D)?.GetValueOrDefault(k);

    /// <summary>Bridge a CAEP / PCA revocation event ({type, payload}) into registry entries; returns the entries added. grant-revoked revokes the cap id, kill-switch kills the agent (and the named grant), anything else is read as session-revoked (the subject's holder / agent / id is killed).</summary>
    public static async Task<List<D>> IngestCaepEvent(object? evt, RevocationRegistry registry)
    {
        if (evt == null) throw new ArgumentException("event is required");
        var e = evt as D;
        var type = e?.GetValueOrDefault("type") as string;
        var payload = e?.GetValueOrDefault("payload") ?? throw new ArgumentException("event.payload is required");
        var added = new List<D>();
        if (type == GrantRevoked)
        {
            if (Field(payload, "grant_ref") is string gr && gr.Length > 0)
                added.Add(await registry.Revoke(new D { ["kind"] = "cap", ["value"] = gr, ["reason"] = Field(payload, "reason") ?? "CAEP grant-revoked", ["revokedAt"] = RevokedAtFrom(Field(payload, "event_timestamp"), registry) }).ConfigureAwait(false));
        }
        else if (type == KillSwitch)
        {
            var revokedAt = RevokedAtFrom(Field(payload, "event_timestamp"), registry);
            if (Field(payload, "agent") is string agent && agent.Length > 0)
                added.Add(await registry.KillAgent(agent, new D { ["reason"] = Field(payload, "reason") ?? "CAEP kill-switch", ["revokedAt"] = revokedAt }).ConfigureAwait(false));
            if (Field(payload, "grant_ref") is string gr && gr.Length > 0)
                added.Add(await registry.Revoke(new D { ["kind"] = "cap", ["value"] = gr, ["reason"] = Field(payload, "reason") ?? "CAEP kill-switch", ["revokedAt"] = revokedAt }).ConfigureAwait(false));
        }
        else
        {
            // a missing subject reads as undefined (no holder); a JSON null subject is a TypeError in the reference
            var holder = payload is D pd && pd.TryGetValue("subject", out var subject) ? (StringField(subject, "holder") ?? StringField(subject, "agent") ?? StringField(subject, "id")) : null;
            if (holder != null)
                added.Add(await registry.KillAgent(holder, new D { ["reason"] = Field(payload, "reason_admin") ?? Field(payload, "reason_user") ?? "CAEP session-revoked", ["revokedAt"] = RevokedAtFrom(Field(payload, "event_timestamp"), registry) }).ConfigureAwait(false));
        }
        return added;
    }
}

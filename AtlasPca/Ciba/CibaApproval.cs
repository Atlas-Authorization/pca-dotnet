using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using AtlasPca.Gnap;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Ciba;

/// <summary>A versioned value; version 0 means absent and every successful write bumps it.</summary>
public sealed record Versioned(long Version, object? Value);

/// <summary>Persistence seam: a JSON key-value store with compare-and-set. <see cref="Cas"/> writes the value only if the stored version equals
/// <c>expectedVersion</c> (0 = the key must be absent) and returns whether it wrote. Any failure must throw.</summary>
public interface IApprovalStore
{
    /// <summary>The stored record, or null when the key is absent.</summary>
    Versioned? Get(string key);
    bool Cas(string key, long expectedVersion, object? value);
}

/// <summary>The synchronous broker contract: start, poll, token (POLL-mode token endpoint semantics), resolve and read a session.</summary>
public interface IApprovalBroker
{
    D Start(D stepUp, D? opts);
    D Poll(string authReqId);
    D Token(string authReqId);
    D Resolve(string authReqId, string? decision, string? by);
    /// <summary>The session snapshot, or null when unknown.</summary>
    D? Get(string authReqId);
}

/// <summary>Options of <see cref="CibaApproval.CreateDurableCibaBroker"/>.</summary>
public sealed class DurableBrokerOptions
{
    public IApprovalStore? Store;
    public Func<long> Now = () => DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
    /// <summary>How long an approval stays redeemable after the human decided, in seconds. Default 300.</summary>
    public double? DecisionTtlSec;
    /// <summary>Called after a decision is durably recorded (PING/PUSH). A throw does not undo the decision.</summary>
    public Action<D>? OnComplete;
    /// <summary>Defaults to 160 random bits, base64url (a test hook).</summary>
    public Func<string> AuthReqIdSource = CibaApproval.RandomAuthReqId;
}

/// <summary>Options of <see cref="CibaApproval.CreateCibaBroker"/>.</summary>
public sealed class BrokerOptions
{
    public Func<long> Now = () => DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
    /// <summary>PING/PUSH: called once, synchronously, when a session is resolved. A throw propagates after the decision is recorded.</summary>
    public Action<D>? OnComplete;
    public Func<string> AuthReqIdSource = CibaApproval.RandomAuthReqId;
}

/// <summary>
/// The durable approval broker: the production-shaped counterpart of the in-memory broker. State lives behind an <see cref="IApprovalStore"/> (compare-and-set), so a
/// restart or a second process cannot lose, double-apply or replay a human decision. Sessions are JSON objects with the reference's member names
/// (<c>auth_req_id, request, status, createdAt, expiresAt, decidedBy, decidedAt</c>).
/// </summary>
public static class CibaApproval
{
    internal const int MaxCasTries = 8;

    internal static string RandomAuthReqId() => Pca.B64u(RandomNumberGenerator.GetBytes(20));

    // ---- file store ----

    /// <summary>Durable reference store: one JSON file, rewritten atomically (temp file then rename) on each write. Correct for ONE process at a time; use a
    /// database store when several processes share the approvals.</summary>
    public static IApprovalStore CreateFileApprovalStore(string path) => new FileStore(path);

    sealed class FileStore(string path) : IApprovalStore
    {
        D Load()
        {
            if (!File.Exists(path)) return new D();
            var parsed = Pca.ParseJson(File.ReadAllText(path, Encoding.UTF8)); // a corrupt file throws: fail closed
            return parsed as D ?? throw new InvalidOperationException("ciba: approval store file is corrupt");
        }

        public Versioned? Get(string key)
        {
            var v = Load().GetValueOrDefault(key);
            if (v == null) return null;
            var ver = GnapJs.Member(v, "version");
            return new Versioned(ver == null ? 0 : (long)GnapJs.NumOf(ver)!.Value, GnapJs.Member(v, "value"));
        }

        public bool Cas(string key, long expectedVersion, object? value)
        {
            var all = Load();
            var cur = all.GetValueOrDefault(key);
            var cv = cur == null ? null : GnapJs.NumOf(GnapJs.Member(cur, "version"));
            if ((cv == null ? 0 : (long)cv.Value) != expectedVersion) return false;
            all[key] = new D { ["version"] = expectedVersion + 1, ["value"] = value };
            var tmp = path + "." + Environment.ProcessId.ToString(CultureInfo.InvariantCulture) + ".tmp";
            File.WriteAllBytes(tmp, Encoding.UTF8.GetBytes(GnapJs.Stringify(all)));
            OwnerOnly.File(tmp);
            File.Move(tmp, path, true);
            return true;
        }
    }

    /// <summary>Single-process in-memory store (a test double: not durable).</summary>
    public static IApprovalStore CreateMemoryApprovalStore() => new MemoryStore();

    sealed class MemoryStore : IApprovalStore
    {
        readonly Dictionary<string, Versioned> m = new();

        public Versioned? Get(string k)
        {
            lock (m) return m.TryGetValue(k, out var v) ? new Versioned(v.Version, CibaJs.DeepCopy(v.Value)) : null;
        }

        public bool Cas(string k, long exp, object? value)
        {
            lock (m)
            {
                var cur = m.TryGetValue(k, out var v) ? v.Version : 0;
                if (cur != exp) return false;
                m[k] = new Versioned(exp + 1, CibaJs.DeepCopy(value));
                return true;
            }
        }
    }

    // ---- shared helpers ----

    static bool Finite(object? o) => GnapJs.NumOf(o) is double d && double.IsFinite(d);

    static double N(object? o) => GnapJs.NumOf(o) ?? double.NaN;

    /// <summary>The stored record, checked: a malformed one throws (fail closed).</summary>
    static D AsRec(object? v)
    {
        if (v is not D m || GnapJs.Member(m.GetValueOrDefault("request"), "auth_req_id") is not string || !Finite(m.GetValueOrDefault("createdAt"))
            || !Finite(m.GetValueOrDefault("expiresAt")) || !Finite(m.GetValueOrDefault("interval")))
            throw new InvalidOperationException("ciba: stored approval record is malformed");
        return m;
    }

    static D Snapshot(D r, string status)
    {
        var s = new D { ["auth_req_id"] = ((D)r["request"]!)["auth_req_id"], ["request"] = r["request"], ["status"] = status, ["createdAt"] = r["createdAt"], ["expiresAt"] = r["expiresAt"] };
        if (r.ContainsKey("decidedBy")) s["decidedBy"] = r["decidedBy"];
        if (r.ContainsKey("decidedAt")) s["decidedAt"] = r["decidedAt"];
        return s;
    }

    static D Outcome(bool ok, string error, object? interval) => new() { ["ok"] = ok, ["error"] = error, ["interval"] = interval };

    static string StepUpKey(D stepUp) => "s:" + GnapJs.Str(GnapJs.Get(stepUp, "id"));

    // ---- the durable broker ----

    /// <summary>The durable broker over <c>opts.Store</c>: every transition is a compare-and-set, so concurrent callers cannot double-apply a decision.</summary>
    public static IApprovalBroker CreateDurableCibaBroker(DurableBrokerOptions opts)
    {
        if (opts == null || opts.Store == null) throw new ArgumentException("createDurableCibaBroker: `store` is required");
        double ttlMs = (opts.DecisionTtlSec ?? 300.0) * 1000;
        if (double.IsNaN(ttlMs) || double.IsInfinity(ttlMs) || ttlMs <= 0) throw new ArgumentException("createDurableCibaBroker: decisionTtlSec must be a positive number");
        return new Durable(opts, ttlMs);
    }

    sealed class Durable(DurableBrokerOptions opts, double ttlMs) : IApprovalBroker
    {
        readonly IApprovalStore store = opts.Store!;
        readonly Func<long> clock = opts.Now;

        string Status(D r, long now)
        {
            var dec = r.GetValueOrDefault("decision");
            if (dec is "deny") return "denied";
            if (dec is "approve") return !(now < N(r.GetValueOrDefault("decidedAt")) + ttlMs) ? "expired" : "approved";
            return !(now < N(r.GetValueOrDefault("expiresAt"))) ? "expired" : "pending";
        }

        D Snap(D r, long now) => Snapshot(r, Status(r, now));

        (D Rec, long Version)? Load(string id)
        {
            var v = store.Get("a:" + id);
            return v == null ? null : (AsRec(v.Value), v.Version);
        }

        T Mutate<T>(string id, Func<D?, long, (D? Next, T Out)> fn)
        {
            for (int i = 0; i < MaxCasTries; i++)
            {
                var cur = Load(id);
                var res = fn(cur == null ? null : (D)CibaJs.DeepCopy(cur.Value.Rec)!, clock());
                if (res.Next == null) return res.Out;
                if (store.Cas("a:" + id, cur == null ? 0 : cur.Value.Version, res.Next)) return res.Out;
            }
            throw new InvalidOperationException("ciba: approval store contention, gave up");
        }

        public D Start(D stepUp, D? reqOpts)
        {
            var liveKey = StepUpKey(stepUp);
            for (int i = 0; i < MaxCasTries; i++)
            {
                long now = clock();
                var idx = store.Get(liveKey);
                if (idx != null)
                {
                    var ex = Load(GnapJs.Str(idx.Value));
                    // Never reset a flow that is still waiting or already approved: that would discard a decision.
                    if (ex != null)
                    {
                        var st = Status(ex.Value.Rec, now);
                        if ((st == "pending" || st == "approved") && !GnapJs.Truthy(ex.Value.Rec.GetValueOrDefault("consumed"))) return (D)ex.Value.Rec["request"]!;
                    }
                }
                var o = reqOpts == null ? new D() : new D(reqOpts);
                o["authReqId"] = opts.AuthReqIdSource();
                var request = Ciba.ToCibaAuthRequest(stepUp, o);
                var rec = new D { ["request"] = request, ["createdAt"] = now, ["expiresAt"] = (long)(now + N(request["requested_expiry"]) * 1000), ["interval"] = request["interval"] };
                var id = (string)request["auth_req_id"]!;
                if (!store.Cas("a:" + id, 0, rec)) continue;
                if (store.Cas(liveKey, idx?.Version ?? 0, id)) return request;
            }
            throw new InvalidOperationException("ciba: approval store contention, gave up");
        }

        public D Poll(string id)
        {
            var c = Load(id) ?? throw new InvalidOperationException("ciba: unknown auth_req_id " + id);
            return new D { ["status"] = Status(c.Rec, clock()) };
        }

        public D Token(string id) => Mutate<D>(id, (r, now) =>
        {
            if (r == null) return (null, Outcome(false, "invalid_grant", 5L));
            if (GnapJs.Truthy(r.GetValueOrDefault("consumed"))) return (null, Outcome(false, "invalid_grant", r["interval"]));
            bool tooSoon = r.ContainsKey("lastPollAt") && !(now - N(r["lastPollAt"]) >= N(r["interval"]) * 1000);
            r["lastPollAt"] = now;
            if (tooSoon)
            {
                r["interval"] = N(r["interval"]) + 5;
                return (r, Outcome(false, "slow_down", r["interval"]));
            }
            var st = Status(r, now);
            if (st == "pending") return (r, Outcome(false, "authorization_pending", r["interval"]));
            if (st == "denied") return (r, Outcome(false, "access_denied", r["interval"]));
            if (st == "expired") return (r, Outcome(false, "expired_token", r["interval"]));
            r["consumed"] = true; // single use: a replayed approval gets invalid_grant
            return (r, new D { ["ok"] = true, ["session"] = Snap(r, now) });
        });

        public D Resolve(string id, string? decision, string? by)
        {
            if (decision != "approve" && decision != "deny") throw new ArgumentException("ciba: decision must be \"approve\" or \"deny\"");
            if (string.IsNullOrEmpty(by)) throw new ArgumentException("ciba: `by` (the authenticated decider) is required");
            var session = Mutate<D>(id, (r, now) =>
            {
                if (r == null) throw new InvalidOperationException("ciba: unknown auth_req_id " + id);
                var cur = Status(r, now);
                if (cur != "pending") throw new InvalidOperationException("ciba: cannot resolve " + id + " — already " + cur);
                r["decision"] = decision;
                r["decidedBy"] = by;
                r["decidedAt"] = now;
                return (r, Snap(r, now));
            });
            if (opts.OnComplete != null)
            {
                try { opts.OnComplete(session); } catch (Exception) { /* the decision is already recorded; a failing notifier must not undo or hide it */ }
            }
            return session;
        }

        public D? Get(string id)
        {
            var c = Load(id);
            return c == null ? null : Snap(c.Value.Rec, clock());
        }
    }

    // ---- the in-memory broker (test double) ----

    /// <summary>An in-memory CIBA broker: models the backchannel lifecycle without any network. Single-process, loses everything on restart: for tests of code
    /// that takes a broker, never to guard a real approval.</summary>
    public static IApprovalBroker CreateCibaBroker(BrokerOptions? opts = null) => new Mem(opts ?? new BrokerOptions());

    sealed class Mem(BrokerOptions o) : IApprovalBroker
    {
        readonly Dictionary<string, D> sessions = new();
        readonly Dictionary<string, string> liveByStepUp = new();
        readonly object gate = new();

        static string Effective(D s, long now)
        {
            if (s.GetValueOrDefault("decision") is "approve") return "approved";
            if (s.GetValueOrDefault("decision") is "deny") return "denied";
            return !(now < N(s.GetValueOrDefault("expiresAt"))) ? "expired" : "pending";
        }

        public D Start(D stepUp, D? reqOpts)
        {
            lock (gate)
            {
                long now = o.Now();
                var existing = liveByStepUp.TryGetValue(StepUpKey(stepUp)[2..], out var existingId) && sessions.TryGetValue(existingId, out var ex) ? ex : null;
                if (existing != null)
                {
                    var st = Effective(existing, now);
                    if (st == "pending" || st == "approved") return (D)existing["request"]!;
                }
                var ro = reqOpts == null ? new D() : new D(reqOpts);
                ro["authReqId"] = o.AuthReqIdSource();
                var request = Ciba.ToCibaAuthRequest(stepUp, ro);
                var stored = new D { ["request"] = request, ["createdAt"] = now, ["expiresAt"] = (long)(now + N(request["requested_expiry"]) * 1000), ["interval"] = request["interval"] };
                sessions[(string)request["auth_req_id"]!] = stored;
                liveByStepUp[StepUpKey(stepUp)[2..]] = (string)request["auth_req_id"]!;
                return request;
            }
        }

        public D Poll(string id)
        {
            lock (gate)
            {
                var s = sessions.GetValueOrDefault(id) ?? throw new InvalidOperationException("ciba: unknown auth_req_id " + id);
                return new D { ["status"] = Effective(s, o.Now()) };
            }
        }

        public D Token(string id)
        {
            lock (gate)
            {
                var s = sessions.GetValueOrDefault(id);
                if (s == null) return Outcome(false, "invalid_grant", 5L);
                long now = o.Now();
                if (GnapJs.Truthy(s.GetValueOrDefault("consumed"))) return Outcome(false, "invalid_grant", s["interval"]);
                bool tooSoon = s.ContainsKey("lastPollAt") && !(now - N(s["lastPollAt"]) >= N(s["interval"]) * 1000);
                s["lastPollAt"] = now;
                if (tooSoon)
                {
                    s["interval"] = N(s["interval"]) + 5;
                    return Outcome(false, "slow_down", s["interval"]);
                }
                var st = Effective(s, now);
                if (st == "pending") return Outcome(false, "authorization_pending", s["interval"]);
                if (st == "denied") return Outcome(false, "access_denied", s["interval"]);
                if (st == "expired") return Outcome(false, "expired_token", s["interval"]);
                s["consumed"] = true;
                return new D { ["ok"] = true, ["session"] = Snapshot(s, st) };
            }
        }

        public D Resolve(string id, string? decision, string? by)
        {
            lock (gate)
            {
                var s = sessions.GetValueOrDefault(id) ?? throw new InvalidOperationException("ciba: unknown auth_req_id " + id);
                long now = o.Now();
                var current = Effective(s, now);
                if (current != "pending") throw new InvalidOperationException("ciba: cannot resolve " + id + " — already " + current);
                s["decision"] = decision;
                s["decidedBy"] = by;
                s["decidedAt"] = now;
                var snap = Snapshot(s, Effective(s, now));
                o.OnComplete?.Invoke(snap);
                return snap;
            }
        }

        public D? Get(string id)
        {
            lock (gate)
            {
                var s = sessions.GetValueOrDefault(id);
                return s == null ? null : Snapshot(s, Effective(s, o.Now()));
            }
        }
    }

    /// <summary>All the session statuses a broker reports.</summary>
    public static IReadOnlyList<string> Statuses() => new[] { "pending", "approved", "denied", "expired" };
}

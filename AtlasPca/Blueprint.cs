// Agent blueprints (verification side): a record signed by an operator for a blueprint KEY; an instance is a chain with a hop issued
// by that key. BlueprintRegistry keeps the newest record per key (pinned operators, a strictly higher epoch replaces, the same epoch
// with different content is a fork). A non-empty ceiling is never evaluated here: it denies (ceiling_unevaluable). Attestation-gated
// admission is delegated to an optional hook: a record carrying runtime_pins is accepted; its instances deny (admission_required) unless the hook
// admits the instance key (a hook that answers false or throws denies not_admitted). The registry REQUIRES a store. Total.
using JD = System.Collections.Generic.Dictionary<string, object?>;

namespace AtlasPca;

public sealed record BlueprintAccept(bool Ok, bool Replaced, string? Code);

public sealed record BlueprintDecision(string Decision, string? Code = null, string? Blueprint = null, IReadOnlyList<string>? Governed = null, long Have = 0, long Need = 0);

/// <summary>Where a blueprint registry keeps its records. A disabled blueprint must stay disabled across a restart, so the registry REQUIRES a store
/// (<see cref="MemoryBlueprintStore"/> is for tests and single-process use; <see cref="AtomicKvBlueprintStore"/> keeps the records in a durable
/// <see cref="IAtomicKv"/>). A method that cannot decide MUST throw (the registry then fails closed).</summary>
public interface IBlueprintStore
{
    /// <summary>The stored record of a blueprint key, or null.</summary>
    Dictionary<string, object?>? Get(string key);

    /// <summary>Store a record under its key.</summary>
    void Put(Dictionary<string, object?> blueprint);

    /// <summary>The highest epoch across every stored record (0 when empty).</summary>
    long MaxEpoch();
}

/// <summary>The in-process store (tests and single-process tools). Its records die with the process.</summary>
public sealed class MemoryBlueprintStore : IBlueprintStore
{
    readonly Dictionary<string, JD> m = new(StringComparer.Ordinal);
    readonly object gate = new();

    public int Count { get { lock (gate) return m.Count; } }

    public JD? Get(string key) { lock (gate) return m.TryGetValue(key, out var b) ? b : null; }

    public void Put(JD blueprint) { lock (gate) m[(string)blueprint["key"]!] = blueprint; }

    public long MaxEpoch() { lock (gate) { long e = 0; foreach (var b in m.Values) { Pca.SafeNat(b["epoch"], out var x); e = Math.Max(e, x); } return e; } }
}

/// <summary>A blueprint store over an <see cref="IAtomicKv"/>: one record per key (<c>blueprint/rec/&lt;key&gt;</c>) and the highest epoch ever stored
/// (<c>blueprint/max_epoch</c>, raised atomically, never lowered), so a restart or a second instance sharing the store sees a disabled blueprint.</summary>
public sealed class AtomicKvBlueprintStore : IBlueprintStore
{
    const string MaxKey = "blueprint/max_epoch";
    readonly IAtomicKv kv;

    public AtomicKvBlueprintStore(IAtomicKv kv) { this.kv = kv ?? throw new ArgumentNullException(nameof(kv)); }

    static string Rec(string key) => "blueprint/rec/" + key;

    public JD? Get(string key)
    {
        var t = kv.Get(Rec(key));
        return t == null ? null : Pca.ParseJson(t) as JD;
    }

    public void Put(JD b)
    {
        kv.Update(Rec((string)b["key"]!), _ => Pca.Canonicalize(b));
        Pca.SafeNat(b["epoch"], out var e);
        kv.Update(MaxKey, prev => prev != null && Pca.SafeNat(Pca.ParseJson(prev), out var cur) && cur >= e ? null : e.ToString(System.Globalization.CultureInfo.InvariantCulture));
    }

    public long MaxEpoch()
    {
        var t = kv.Get(MaxKey);
        return t != null && Pca.SafeNat(Pca.ParseJson(t), out var e) ? e : 0;
    }
}

public sealed class BlueprintRegistry
{
    readonly IReadOnlyList<string> operators;
    readonly IBlueprintStore store;

    /// <param name="operators">The operator keys (b64u) whose records this verifier accepts; a record from any other key is refused.</param>
    /// <param name="store">The store (required: a disabled blueprint must stay disabled across a restart).</param>
    public BlueprintRegistry(IReadOnlyList<string> operators, IBlueprintStore store)
    {
        if (store == null) throw new ArgumentException("BlueprintRegistry: a durable BlueprintStore is required (MemoryBlueprintStore is for tests and single-process use)", nameof(store));
        this.operators = operators;
        this.store = store;
    }

    /// <summary>The highest blueprint epoch this verifier has accepted: its contribution to a <c>fresh_at</c> <c>revocation_epoch</c>. Throws when the store cannot answer.</summary>
    public long Epoch() => store.MaxEpoch();

    /// <summary>The stored record of a blueprint key, or null. Throws when the store cannot answer.</summary>
    public JD? Get(string key) => store.Get(key);

    public BlueprintAccept Accept(object? v)
    {
        if (!Blueprint.Verify(v)) return new(false, false, "bad_record");
        var b = (JD)v!;
        if (!operators.Contains((string)b["operator"]!)) return new(false, false, "unknown_operator");
        try
        {
            var cur = store.Get((string)b["key"]!);
            if (cur != null)
            {
                if ((string)cur["operator"]! != (string)b["operator"]!) return new(false, false, "operator_changed");
                Pca.SafeNat(cur["epoch"], out var ce); Pca.SafeNat(b["epoch"], out var be);
                if (be < ce) return new(false, false, "stale_epoch");
                if (be == ce) return (string)cur["sig"]! == (string)b["sig"]! ? new(true, false, null) : new(false, false, "epoch_fork");
            }
            store.Put(b);
            return new(true, true, null);
        }
        catch (Exception) { return new(false, false, "store_unreachable"); }
    }
}

public static class Blueprint
{
    public const string Domain = "atlas-pca/agent-blueprint/v1\0";
    static string[] BodyKeys => new string[] { "v", "id", "key", "ceiling", "max_depth", "expires_at", "runtime_pins", "epoch", "status", "issued_at", "operator" };

    static string[] PinKeys => new string[] { "runtime_measurement", "model_id", "weights_digest", "operator", "spiffe_id" };

    static bool Str(object? x, int max) => x is string s && s.Length > 0 && s.Length <= max;

    static bool WellFormed(object? v)
    {
        if (v is not JD b || !b.TryGetValue("v", out var one) || !Pca.SafeNat(one, out var ov) || ov != 1) return false;
        if (!Str(b.GetValueOrDefault("id"), 128) || !Str(b.GetValueOrDefault("key"), 128) || !Str(b.GetValueOrDefault("operator"), 128)) return false;
        if (!Pca.SafeNat(b.GetValueOrDefault("epoch"), out _) || !Pca.SafeNat(b.GetValueOrDefault("issued_at"), out _)) return false;
        if (b.GetValueOrDefault("status") is not string st || (st != "active" && st != "disabled")) return false;
        if (b.TryGetValue("max_depth", out var d) && !(Pca.SafeNat(d, out var dv) && dv >= 1)) return false;
        if (b.TryGetValue("expires_at", out var e) && !Pca.SafeNat(e, out _)) return false;
        var pinKeys = PinKeys;
        if (b.TryGetValue("runtime_pins", out var pins) &&
            !(pins is List<object?> pl && pl.Count >= 1 && pl.Count <= 16 && pl.All(x => x is JD pin && pin.Count > 0 && pin.All(kv => pinKeys.Contains(kv.Key) && Str(kv.Value, 256)))))
            return false;
        return b.GetValueOrDefault("ceiling") is List<object?> c && c.Count <= 32 && c.All(x => x is JD m && m.GetValueOrDefault("type") is string);
    }

    public static bool Verify(object? v)
    {
        if (!WellFormed(v)) return false;
        var b = (JD)v!;
        var body = new JD();
        foreach (var k in BodyKeys) if (b.TryGetValue(k, out var x)) body[k] = x;
        return Pca.VerifyDomain(Domain, body, b["operator"], b.GetValueOrDefault("sig"));
    }

    static BlueprintDecision Deny(string code, string? bp = null) => new("deny", code, bp);

    /// <summary>Gate a chain (hops with issuer and holder, root first). mode is "require" or "any"; minEpoch is the revocation_epoch of the newest fresh_at token shown.</summary>
    public static BlueprintDecision Check(object? chain, BlueprintRegistry reg, object? now, string mode, long? minEpoch = null, Func<string, JD, bool>? admitted = null)
    {
        if (chain is not List<object?> hops || hops.Count == 0 || !Pca.SafeNat(now, out var nowMs)) return Deny("bad_input");
        var hs = new List<(string issuer, string holder)>();
        foreach (var h in hops)
        {
            if (h is not JD m || !Str(m.GetValueOrDefault("issuer"), 128) || !Str(m.GetValueOrDefault("holder"), 128)) return Deny("bad_input");
            hs.Add(((string)m["issuer"]!, (string)m["holder"]!));
        }
        try
        {
            if (minEpoch is long me)
            {
                var have = reg.Epoch();
                if (have < me) return new("escalate", "stale_blueprint_state", null, null, have, me);
            }
            var governed = new List<string>();
            for (var i = 0; i < hs.Count; i++)
            {
                var bp = reg.Get(hs[i].issuer);
                if (bp == null) continue;
                var id = (string)bp["id"]!;
                if (i == 0 || hs[i - 1].holder != (string)bp["key"]!) return Deny("broken_link", id);
                if ((string)bp["status"]! != "active") return Deny("blueprint_disabled", id);
                if (bp.TryGetValue("expires_at", out var ex) && Pca.SafeNat(ex, out var at) && nowMs >= at) return Deny("blueprint_expired", id);
                if (bp.TryGetValue("max_depth", out var md) && Pca.SafeNat(md, out var depth) && hs.Count - i > depth) return Deny("too_deep", id);
                if (bp.ContainsKey("runtime_pins"))
                {
                    // pins present: no admission hook denies admission_required; a hook that answers anything but true, or throws, denies not_admitted
                    if (admitted == null) return Deny("admission_required", id);
                    bool ok;
                    try { ok = admitted(hs[i].holder, bp); }
                    catch (Exception) { ok = false; }
                    if (!ok) return Deny("not_admitted", id);
                }
                if (((List<object?>)bp["ceiling"]!).Count > 0) return Deny("ceiling_unevaluable", id);
                governed.Add(id);
            }
            if (governed.Count == 0 && mode == "require") return Deny("no_blueprint");
            return new("allow", null, null, governed);
        }
        catch (Exception) { return Deny("store_unreachable"); }
    }
}

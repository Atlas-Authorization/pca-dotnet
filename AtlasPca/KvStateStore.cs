// The durable state store of the verifier over any atomic key/value store (the reference durablePcaStateStore): replay counters, one-time
// slots, the rollback pin and the trust budget, each atomic through IAtomicKv.Update. Pair it with SqlAtomicKv (shared) or MemoryAtomicKv (tests).
using System.Globalization;

namespace AtlasPca;

/// <summary>An <see cref="IStateStore"/> (plus last / pin / budget sides) over an <see cref="IAtomicKv"/>. <c>Scope</c> defaults to
/// <see cref="StoreScope.Shared"/>: pass <see cref="StoreScope.Process"/> for an in-process kv. Every mutation is one atomic <c>Update</c>; a kv that
/// cannot decide throws and the verifier fails closed.</summary>
public sealed class KvStateStore : IStateStore, ILastStore, IPinStore, IBudgetStore
{
    readonly IAtomicKv _kv;
    readonly string _prefix;
    public StoreScope Scope { get; }

    public KvStateStore(IAtomicKv kv, string prefix = "pca-state:", StoreScope scope = StoreScope.Shared)
    {
        _kv = kv ?? throw new ArgumentNullException(nameof(kv));
        _prefix = prefix ?? "";
        Scope = scope;
    }

    string K(string kind, string key) => _prefix + kind + ":" + key;
    static string L(long v) => v.ToString(CultureInfo.InvariantCulture);
    static long? ParseLong(string? s) => s != null && long.TryParse(s, NumberStyles.Integer, CultureInfo.InvariantCulture, out var v) ? v : null;

    public long? Last(string key) => ParseLong(_kv.Get(K("c", key)));

    public ClaimResult? Claim(string key, long counter)
    {
        if (key is null) return new ClaimResult(false);
        var ok = false;
        long? last = null;
        _kv.Update(K("c", key), prev =>
        {
            last = ParseLong(prev);
            ok = prev == null || (last != null && counter > last);
            return ok ? L(counter) : null;
        });
        return ok ? new ClaimResult(true) : new ClaimResult(false, last);
    }

    public bool ConsumeOnce(string key, long retainUntilMs, long nowMs)
    {
        if (string.IsNullOrEmpty(key) || retainUntilMs < nowMs) throw new ArgumentException("ConsumeOnce needs a non-empty key and retainUntilMs >= nowMs");
        var fresh = false;
        _kv.Update(K("o", key), prev =>
        {
            var r = ParseLong(prev);
            if (r != null && r >= nowMs)
            {
                fresh = false;
                return retainUntilMs > r ? L(retainUntilMs) : null; // a live record is never shortened
            }
            fresh = true;
            return L(retainUntilMs);
        });
        return fresh;
    }

    public long? Pin(string key) => ParseLong(_kv.Get(K("p", key)));

    public long RaisePin(string key, long value)
    {
        if (string.IsNullOrEmpty(key) || value < 0) throw new ArgumentException("RaisePin needs a non-empty key and a non-negative value");
        long result = value;
        _kv.Update(K("p", key), prev =>
        {
            var cur = ParseLong(prev);
            if (cur != null && value <= cur) { result = cur.Value; return null; }
            result = value;
            return L(value);
        });
        return result;
    }

    // stored as a JSON string: a kv whose values are JSON documents (the durable state directory) refuses any other text
    static string BudgetText(TrustBudget b) => AtlasPca.Js.JsJson.Quote(string.Join("|", new[] { b.B, b.Tau, b.AsOf ?? double.NaN }.Select(x => x.ToString("R", CultureInfo.InvariantCulture))));

    static TrustBudget? ParseBudget(string? v)
    {
        if (v == null) return null;
        if (v.Length > 0 && v[0] == '"') v = (string)Pca.ParseJson(v)!; // the JSON string form (a record written before it was quoted is read as it is)
        var f = v.Split('|');
        if (f.Length != 3) throw new InvalidOperationException("kv state store: corrupt budget record");
        var n = f.Select(x => double.Parse(x, CultureInfo.InvariantCulture)).ToArray();
        return new TrustBudget(n[0], n[1], double.IsNaN(n[2]) ? null : n[2]);
    }

    public TrustBudget? Budget(string key) => ParseBudget(_kv.Get(K("b", key)));

    public bool BudgetCas(string key, TrustBudget? old, TrustBudget @new)
    {
        var ok = false;
        _kv.Update(K("b", key), prev =>
        {
            ok = Equals(ParseBudget(prev), old);
            return ok ? BudgetText(@new) : null;
        });
        return ok;
    }
}

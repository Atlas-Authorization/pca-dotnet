// Durable round-1 nonce persistence for a FROST signer, built so a restart can neither lose a session nor reuse a nonce.
//
// Reusing one nonce pair across two messages reveals the signing share. The rule that prevents it across restarts is ORDER: the nonce is durably marked spent BEFORE the
// signature share is computed. A crash after the mark loses that session (liveness cost, the coordinator opens a new one); a crash before it leaves an unspent nonce that can
// still be used exactly once. The store never has to be trusted to forget a nonce: Spend removes the secret bytes and keeps only the marker.
//
// Contract every implementation must meet (checked by FrostNonceStores.AssertContract):
//  - Create is durable before it returns and throws if the session id exists in ANY state (live or spent);
//  - Load returns the live record or null (spent, dropped and unknown ids all give null);
//  - Spend is atomic and durable: it throws unless the session is live, deletes the secret nonces, and records the id as spent forever; a second Spend throws;
//  - IsSpent is true for every spent id, including after a restart;
//  - every method throws on failure. The signer treats any throw as a refusal (fail closed): no commitment is released when Create fails and no share is released when Spend fails.
// The records hold SECRET nonces: a durable store must encrypt them at rest.
namespace AtlasPca;

/// <summary>One session's round-1 state: the secret nonce scalars and the public commitments emitted for them.</summary>
public sealed class FrostNonceRecord
{
    /// <summary>32-byte little-endian hiding nonce scalar (secret).</summary>
    public byte[] Hiding = [];
    /// <summary>32-byte little-endian binding nonce scalar (secret).</summary>
    public byte[] Binding = [];
    /// <summary>The public commitments emitted in round 1 (32-byte points).</summary>
    public byte[] HidingCommitment = [], BindingCommitment = [];
    /// <summary>Wall-clock milliseconds at which round 1 opened the session.</summary>
    public long CreatedAt;

    public FrostNonceRecord Copy() => new() { Hiding = (byte[])Hiding.Clone(), Binding = (byte[])Binding.Clone(), HidingCommitment = (byte[])HidingCommitment.Clone(), BindingCommitment = (byte[])BindingCommitment.Clone(), CreatedAt = CreatedAt };
}

public interface IFrostNonceStore
{
    void Create(string sessionId, FrostNonceRecord record);
    FrostNonceRecord? Load(string sessionId);
    void Spend(string sessionId);
    void Drop(string sessionId);
    bool IsSpent(string sessionId);
}

/// <summary>Reference implementation: correct, not durable (a process restart loses it, which fails closed). Use it as the model.</summary>
public class FrostMemoryNonceStore : IFrostNonceStore
{
    readonly Dictionary<string, FrostNonceRecord> _live = new(StringComparer.Ordinal);
    readonly HashSet<string> _spent = new(StringComparer.Ordinal);
    readonly object _lock = new();

    public virtual void Create(string sessionId, FrostNonceRecord record)
    {
        if (string.IsNullOrEmpty(sessionId)) throw new InvalidOperationException("nonce-store: session id must be a non-empty string");
        lock (_lock)
        {
            if (_live.ContainsKey(sessionId) || _spent.Contains(sessionId)) throw new InvalidOperationException("nonce-store: session already exists");
            _live[sessionId] = record.Copy();
        }
    }

    public virtual FrostNonceRecord? Load(string sessionId)
    {
        lock (_lock) return _live.TryGetValue(sessionId, out var r) ? r.Copy() : null;
    }

    public virtual void Spend(string sessionId)
    {
        lock (_lock)
        {
            if (!_live.TryGetValue(sessionId, out var r)) throw new InvalidOperationException("nonce-store: cannot spend a session that is not live");
            Array.Clear(r.Hiding);
            Array.Clear(r.Binding);
            _live.Remove(sessionId);
            _spent.Add(sessionId);
        }
    }

    public virtual void Drop(string sessionId)
    {
        lock (_lock)
            if (_live.TryGetValue(sessionId, out var r))
            {
                Array.Clear(r.Hiding);
                Array.Clear(r.Binding);
                _live.Remove(sessionId);
            }
    }

    public virtual bool IsSpent(string sessionId)
    {
        lock (_lock) return _spent.Contains(sessionId);
    }
}

public static class FrostNonceStores
{
    /// <summary>Conformance check for a store. <paramref name="reopen"/> must return a store over the SAME durable state (a simulated restart); for the in-memory reference it returns the same
    /// instance. Throws on the first violation.</summary>
    public static void AssertContract(Func<IFrostNonceStore> make, Func<IFrostNonceStore, IFrostNonceStore>? reopen = null)
    {
        reopen ??= s => s;
        static FrostNonceRecord Rec(byte n) => new()
        {
            Hiding = Enumerable.Repeat(n, 32).ToArray(), Binding = Enumerable.Repeat((byte)(n + 1), 32).ToArray(),
            HidingCommitment = Enumerable.Repeat((byte)(n + 2), 32).ToArray(), BindingCommitment = Enumerable.Repeat((byte)(n + 3), 32).ToArray(), CreatedAt = n,
        };
        static void Must(bool ok, string what) { if (!ok) throw new InvalidOperationException("nonce-store contract: " + what); }
        static bool Throws(Action f)
        {
            try { f(); } catch (Exception) { return true; }
            return false;
        }
        var s = make();
        Must(s.Load("a") == null && !s.IsSpent("a"), "an unknown id is neither live nor spent");
        s.Create("a", Rec(1));
        Must(Throws(() => s.Create("a", Rec(9))), "create must refuse an existing live id");
        s.Create("b", Rec(5));
        s = reopen(s);
        var got = s.Load("a");
        Must(got != null && got.Hiding[0] == 1 && got.CreatedAt == 1, "a live record survives a restart");
        Array.Fill(got!.Hiding, (byte)0xee);
        Must(s.Load("a")!.Hiding[0] == 1, "load returns a copy");
        s.Spend("a");
        Must(s.Load("a") == null && s.IsSpent("a"), "spend removes the secret and records the marker");
        Must(Throws(() => s.Spend("a")), "a second spend must throw");
        Must(Throws(() => s.Create("a", Rec(2))), "create must refuse a spent id");
        Must(Throws(() => s.Spend("zzz")), "spend of an unknown id must throw");
        s = reopen(s);
        Must(s.IsSpent("a") && s.Load("a") == null, "a spent marker survives a restart");
        Must(s.Load("b") != null, "the other live record survives");
        s.Drop("b");
        Must(s.Load("b") == null && !s.IsSpent("b"), "drop removes a live record without marking it spent");
        s.Drop("never-existed");
    }
}

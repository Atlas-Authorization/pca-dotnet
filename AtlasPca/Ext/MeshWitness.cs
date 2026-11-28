using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca;

/// <summary>Where a mesh log witness keeps what it has cosigned. <see cref="Save"/> MUST be durable and atomic: when it returns, a restarted witness
/// loads exactly this state. A witness that forgets across a restart can be walked back to cosign a fork. Synchronous on purpose: a cosignature
/// must not be returned before the state behind it is on disk. The state is the JSON object <c>{seen: [{head, rev_ids}]}</c>.</summary>
public interface IMeshWitnessStore
{
    /// <summary>The last saved state (a copy), or null for a store that has never been written. Throws on corrupt data (never returns a partial state).</summary>
    D? Load();

    void Save(D state);
}

/// <summary>In-process <see cref="IMeshWitnessStore"/>: a test double, and the default when no store is given. It does not survive a restart.</summary>
public sealed class MemoryMeshWitnessStore : IMeshWitnessStore
{
    string? _state;
    readonly object _lock = new();

    public D? Load()
    {
        lock (_lock) return _state == null ? null : Pca.ParseJson(_state) as D;
    }

    public void Save(D state)
    {
        var text = JsCanon.Lenient(state) ?? throw new InvalidOperationException("MemoryMeshWitnessStore: the state is not canonicalizable");
        lock (_lock) _state = text;
    }
}

/// <summary>A durable <see cref="IMeshWitnessStore"/> over an <see cref="IAtomicKv"/>: the state is one document with a digest. <see cref="Save"/> returns
/// only after the kv acknowledged the write; <see cref="Load"/> refuses damaged or edited content (it throws, so a witness never starts empty over it).</summary>
public sealed class KvMeshWitnessStore : IMeshWitnessStore
{
    public const string DocKey = "pca-mesh-witness/v1";
    readonly IAtomicKv _kv;
    readonly string _key;

    public KvMeshWitnessStore(IAtomicKv kv, string key = DocKey)
    {
        _kv = kv ?? throw new ArgumentException("KvMeshWitnessStore needs an IAtomicKv");
        _key = key;
    }

    public D? Load()
    {
        var text = _kv.Get(_key);
        if (text == null) return null;
        object? doc;
        try { doc = Pca.ParseJson(text); }
        catch (Exception) { throw new InvalidOperationException("KvMeshWitnessStore: the stored state is not JSON; refusing to start empty"); }
        return MeshWitnessDoc.State(doc, "KvMeshWitnessStore: the stored state");
    }

    public void Save(D state)
    {
        var text = Pca.Canonicalize(MeshWitnessDoc.Wrap(state));
        _kv.Update(_key, _ => text);
    }
}

/// <summary>The stored form shared by the durable witness stores: <c>{v:1, state, digest}</c> with the digest of the state.</summary>
internal static class MeshWitnessDoc
{
    internal static D Wrap(D state) => new() { ["v"] = IntentJs.OfLong(1), ["state"] = StoreJs.DeepCopy(state), ["digest"] = Pca.HashCanonical(state) };

    /// <summary>The state of a stored document; throws (never an empty state) on a wrong shape or a failed digest.</summary>
    internal static D State(object? doc, string who)
    {
        if (doc is not D d || !IntentJs.IsInt(d.GetValueOrDefault("v")) || IntentJs.Lng(d["v"]) != 1 || d.GetValueOrDefault("digest") is not string digest
            || d.GetValueOrDefault("state") is not D)
            throw new InvalidOperationException(who + " has an unexpected shape; refusing to start empty");
        var st = (D)StoreJs.DeepCopy(d["state"])!;
        string actual;
        try { actual = Pca.HashCanonical(st); }
        catch (Exception) { throw new InvalidOperationException(who + " fails its digest; refusing to start empty"); }
        if (actual != digest) throw new InvalidOperationException(who + " fails its digest; refusing to start empty");
        return st;
    }
}

/// <summary>Small JSON-tree helpers shared by the durable store classes.</summary>
internal static class StoreJs
{
    /// <summary>A deep copy of a JSON tree (Dictionary, List, scalars). Stores never hand out or keep a caller's mutable structure.</summary>
    internal static object? DeepCopy(object? v)
    {
        if (v is D m)
        {
            var o = new D();
            foreach (var e in m) o[e.Key] = DeepCopy(e.Value);
            return o;
        }
        if (v is L l) return l.Select(DeepCopy).ToList();
        return v;
    }

    internal static Num Number(double v) => v == Math.Floor(v) && Math.Abs(v) < 9e15 ? IntentJs.OfLong((long)v) : new Num(JsCanon.NumberString(v));
}

/// <summary>An independent mesh log witness. It cosigns a domain head only if (1) the domain signed it, (2) it is an RFC 9162-verified append-only
/// extension of the last head THIS witness cosigned for that domain, (3) its revocation list reproduces <c>rev_root</c> and is a superset of the
/// previously cosigned list, and (4) the timestamp does not regress (nor run ahead of the witness's own clock, when configured). State is committed
/// only after every check passes, and (with a store) persisted BEFORE the cosignature is returned. First sight of a domain is trust-on-first-use.
/// Every refusal throws <see cref="InvalidOperationException"/> with the reference's message.</summary>
public sealed class MeshWitness
{
    public const double DefaultMaxClockSkewMs = 60_000;
    const int MaxRevIds = 1_000_000;

    /// <summary>Optional witness configuration.</summary>
    public sealed class Options
    {
        public IMeshWitnessStore? Store;
        /// <summary>The witness's own clock; when set, heads timestamped beyond <c>now + MaxClockSkewMs</c> are refused.</summary>
        public Func<double>? Clock;
        public double? MaxClockSkewMs;
    }

    sealed record Seen(D Head, List<string> Rev);

    public string Id { get; }
    readonly EdKey _key;
    readonly Options _opts;
    readonly Dictionary<string, Seen> _seen = new(StringComparer.Ordinal);
    readonly object _lock = new();

    public MeshWitness(EdKey key, Options? opts = null)
    {
        _key = key;
        _opts = opts ?? new Options();
        Id = key.Id;
        if (_opts.Store != null)
        {
            var loaded = _opts.Store.Load();
            if (loaded != null) ImportState(loaded);
        }
    }

    static byte[] Msg(string domain, object? body) => IntentJs.Message(domain, body);

    static D StateOf(Dictionary<string, Seen> seen)
    {
        var all = seen.Values.ToList();
        all.Sort((a, b) => string.CompareOrdinal((string)a.Head["domain"]!, (string)b.Head["domain"]!));
        var o = new L();
        foreach (var s in all)
            o.Add(new D { ["head"] = StoreJs.DeepCopy(s.Head), ["rev_ids"] = s.Rev.Cast<object?>().ToList() });
        return new D { ["seen"] = o };
    }

    /// <summary>The newest head this witness cosigned for <paramref name="domain"/> (a copy), or null.</summary>
    public D? LastSeen(string domain)
    {
        lock (_lock) return _seen.TryGetValue(domain, out var s) ? (D)StoreJs.DeepCopy(s.Head)! : null;
    }

    static InvalidOperationException Refuse(string why) => new("witness: " + why);

    static D? Head(object? h) => Mesh.ValidHead(h) ? (D)h! : null;

    /// <summary>Cosign a head request <c>{head: {head, sig, cosigs}, consistency?, rev_ids}</c>; returns <c>{witness, sig}</c>. Throws (and changes nothing) if any rule is violated.</summary>
    public D Cosign(D req)
    {
        lock (_lock)
        {
            var ch = req?.GetValueOrDefault("head") as D;
            var h = ch == null ? null : Head(ch.GetValueOrDefault("head"));
            if (ch == null || h == null || ch.GetValueOrDefault("sig") is not string sig) throw Refuse("malformed head");
            var domain = (string)h["domain"]!;
            if (!Pca.VerifyEdInternal(domain, Msg(Mesh.HeadDomain, h), sig)) throw Refuse("head not signed by its domain");
            double ts = IntentJs.NumOf(h["timestamp"])!.Value;
            if (_opts.Clock != null)
            {
                double skew = _opts.MaxClockSkewMs ?? DefaultMaxClockSkewMs;
                var clk = _opts.Clock();
                if (!(double.IsFinite(clk) && double.IsFinite(skew) && ts <= clk + skew)) throw Refuse("head timestamp is in the future");
            }
            if (req!.GetValueOrDefault("rev_ids") is not L idsO || idsO.Count > MaxRevIds) throw Refuse("malformed revocation list");
            var ids = new List<string>();
            foreach (var o in idsO)
            {
                if (o is not string s) throw Refuse("malformed revocation list");
                ids.Add(s);
            }
            var set = new MeshRevocationSet(ids);
            if (set.Size != IntentJs.Lng(h["rev_size"]) || set.Root() != (h["rev_root"] as string)) throw Refuse("revocation list does not match head");
            if (_seen.TryGetValue(domain, out var prev))
            {
                var why = Mesh.CheckHeadAdvance(prev.Head, h, req.GetValueOrDefault("consistency"));
                if (!string.IsNullOrEmpty(why)) throw Refuse(why);
                if (ts < IntentJs.NumOf(prev.Head["timestamp"])!.Value) throw Refuse("timestamp regresses");
                var now = new HashSet<string>(set.List(), StringComparer.Ordinal);
                if (!prev.Rev.All(now.Contains)) throw Refuse("revocation set drops a previously cosigned revocation");
            }
            var next = new Seen((D)StoreJs.DeepCopy(h)!, set.List());
            if (_opts.Store != null)
            {
                // Persist first, commit to memory second: if the disk write fails nothing was cosigned and nothing changed.
                var copy = new Dictionary<string, Seen>(_seen, StringComparer.Ordinal) { [domain] = next };
                try { _opts.Store.Save(StateOf(copy)); }
                catch (Exception) { throw Refuse("could not persist state; refusing to cosign"); }
            }
            _seen[domain] = next;
            return new D { ["witness"] = Id, ["sig"] = Pca.B64u(_key.Sign(Msg(Mesh.CosigDomain, h))) };
        }
    }

    /// <summary>Export memory for persistence. Deterministic order.</summary>
    public D ExportState()
    {
        lock (_lock) return StateOf(_seen);
    }

    /// <summary>Restore memory; each record must be internally consistent (its revocation list reproduces its root).</summary>
    public void ImportState(D state)
    {
        lock (_lock)
        {
            var next = new Dictionary<string, Seen>(StringComparer.Ordinal);
            var list = state?.GetValueOrDefault("seen");
            if (list != null && list is not L) throw Refuse("malformed state");
            if (list is L items)
            {
                foreach (var so in items)
                {
                    var s = so as D;
                    var head = s == null ? null : Head(s.GetValueOrDefault("head"));
                    if (s == null || head == null || s.GetValueOrDefault("rev_ids") is not L revs) throw Refuse("malformed state");
                    var ids = new List<string>();
                    foreach (var o in revs)
                    {
                        if (o is not string str) throw Refuse("malformed state");
                        ids.Add(str);
                    }
                    var set = new MeshRevocationSet(ids);
                    if (set.Size != IntentJs.Lng(head["rev_size"]) || set.Root() != (head["rev_root"] as string)) throw Refuse("malformed state");
                    next[(string)head["domain"]!] = new Seen((D)StoreJs.DeepCopy(head)!, set.List());
                }
            }
            _seen.Clear();
            foreach (var e in next) _seen[e.Key] = e.Value;
        }
    }
}

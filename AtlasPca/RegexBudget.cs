// Per-DOCUMENT and per-REQUEST regex work budgets (the reference regex-budget.ts) and the bounded compiled-regex cache (regex-cache.ts).
//
// A document budget (opened by every library entry point: decide, evaluatePredicates, evaluateCaveats, predicateMatches, evaluateConditionTri, ...)
// sums, across every `re:` pattern and `matches` condition evaluated inside it, the number of regex evaluations, the pattern source size and the worst-case
// NFA steps (instructions x (subject length + 1)). Charging happens BEFORE matching; once any cap is exceeded every further evaluation in the scope is
// refused (fail closed). The charge is a pure function of the document and the subject, never of timing. A REQUEST budget (RegexBudget.Request) is opened by
// the server once per request: every document budget opened inside it also charges it, with caps RequestScale documents' worth.
using System.Security.Cryptography;

namespace AtlasPca;

public sealed class RegexBudget
{
    public const int MaxEvaluationsPerDocument = SafeRegex.MaxRegexEvaluationsPerDocument;
    public const int MaxSourceCharsPerDocument = SafeRegex.MaxRegexSourceCharsPerDocument;
    public const long MaxStepsPerDocument = SafeRegex.MaxRegexStepsPerDocument;
    /// <summary>A request-level budget allows this many documents' worth of regex work in total.</summary>
    public const int RequestScale = 4;

    readonly int _scale;
    int _evaluations, _chars;
    long _steps;
    public int Refusals { get; private set; }
    public bool IsDocument { get; }
    /// <summary>The request's source (the server's client key), used for per-source admission to the regex cache.</summary>
    public string? Source { get; }
    /// <summary>The enclosing budget this one also charges (null for a top-level budget).</summary>
    public RegexBudget? ParentBudget { get; }
    readonly object _lock = new();

    public RegexBudget(int scale = 1, RegexBudget? parent = null, bool isDocument = true, string? source = null)
    {
        _scale = scale; ParentBudget = parent; IsDocument = isDocument; Source = source;
    }

    public int Evaluations { get { lock (_lock) return _evaluations; } }
    public int Chars { get { lock (_lock) return _chars; } }
    public long Steps { get { lock (_lock) return _steps; } }

    /// <summary>A request-scoped budget: run the request's synchronous regex-evaluating sections through <see cref="Run{T}"/>. <paramref name="source"/> (optional) is
    /// the request's client key; compiled patterns first seen in this request count against that source's cache share.</summary>
    public static RegexBudget Request(string? source = null) => new(RequestScale, null, false, source);

    /// <summary>Charge one evaluation of <paramref name="src"/> against a subject of <paramref name="subjectLen"/> chars; false = refused (the caller must NOT match).</summary>
    public bool Charge(string src, int subjectLen)
    {
        var len = SafeRegex.ProgramLength(src);
        lock (_lock)
        {
            if (len == null) { Refusals++; return false; }
            var ev = _evaluations + 1;
            var chars = _chars + src.Length;
            var steps = _steps + (long)len.Value * (subjectLen + 1);
            var k = _scale;
            if (ev > (long)MaxEvaluationsPerDocument * k || chars > (long)MaxSourceCharsPerDocument * k || steps > MaxStepsPerDocument * k
                || (ParentBudget != null && !ParentBudget.Charge(src, subjectLen)))
            {
                // poison the budget so a later, cheaper pattern cannot sneak in after an over-budget one (order-independent refusal)
                _evaluations = MaxEvaluationsPerDocument * k + 1;
                Refusals++;
                return false;
            }
            _evaluations = ev; _chars = chars; _steps = steps;
            return true;
        }
    }

    /// <summary>Make this the open scope for the synchronous <paramref name="fn"/> (the previous scope is restored afterwards).</summary>
    public T Run<T>(Func<T> fn)
    {
        var prev = SafeRegex.Current;
        SafeRegex.SetCurrent(this);
        try { return fn(); }
        finally { SafeRegex.SetCurrent(prev); }
    }
}

/// <summary>The ONE bounded cache of compiled regex programs: keys are the SHA-256 of the pattern's UTF-16 code units (injective over strings); eviction is
/// least-recently-used, one entry at a time, nothing on a request path clears it; each entry is owned by the source that inserted it and a source at its share
/// replaces its OWN oldest entry; a total weight cap bounds memory and a single program heavier than 1/16 of it is used but never cached. Thread safe.</summary>
public static class RegexCache
{
    public const int MaxEntries = 512;
    public const int MaxPerSource = 64;
    public const int MaxWeight = 131_072;

    sealed record Entry(object? Value, string Source, int Weight);

    static readonly object Lock = new();
    // least-recently-used first (insertion order of a linked list)
    static readonly LinkedList<string> Order = new();
    static readonly Dictionary<string, (Entry E, LinkedListNode<string> Node)> Entries = new(StringComparer.Ordinal);
    static readonly Dictionary<string, LinkedList<string>> BySource = new(StringComparer.Ordinal);
    static int totalWeight;
    static Func<string?>? sourceProvider;

    /// <summary>Install the provider of the CURRENT source (the server's per-request client key). Null uninstalls.</summary>
    public static void SetSourceProvider(Func<string?>? fn) => sourceProvider = fn;

    static string CurrentSource()
    {
        try { return (sourceProvider != null ? sourceProvider() : SafeRegex.CurrentRegexSource()) ?? ""; } catch (Exception) { return ""; }
    }

    static string KeyOf(string src)
    {
        var b = new byte[src.Length * 2];
        for (var i = 0; i < src.Length; i++) { b[2 * i] = (byte)(src[i] >> 8); b[2 * i + 1] = (byte)(src[i] & 0xff); }
        return Convert.ToHexString(SHA256.HashData(b)).ToLowerInvariant();
    }

    static void Remove(string key)
    {
        if (!Entries.TryGetValue(key, out var x)) return;
        Entries.Remove(key);
        Order.Remove(x.Node);
        totalWeight -= x.E.Weight;
        if (BySource.TryGetValue(x.E.Source, out var owned))
        {
            owned.Remove(key);
            if (owned.Count == 0) BySource.Remove(x.E.Source);
        }
    }

    /// <summary>The cached value for pattern <paramref name="src"/>, computing (and admitting) it on a miss. <paramref name="weigh"/> gives the memory weight of a value (at least 1).</summary>
    public static V Get<V>(string src, Func<string, V> compute, Func<V, int> weigh)
    {
        var key = KeyOf(src);
        lock (Lock)
        {
            if (Entries.TryGetValue(key, out var hit))
            {
                Order.Remove(hit.Node);
                var node = Order.AddLast(key);
                Entries[key] = (hit.E, node);
                if (BySource.TryGetValue(hit.E.Source, out var own)) { own.Remove(key); own.AddLast(key); }
                return (V)hit.E.Value!;
            }
        }
        var value = compute(src);
        var w = Math.Max(1, weigh(value));
        if (w > MaxWeight / 16) return value; // too heavy to cache: never evict others for it
        var source = CurrentSource();
        lock (Lock)
        {
            if (Entries.ContainsKey(key)) return value; // admitted concurrently
            while (BySource.TryGetValue(source, out var owned) && owned.Count >= MaxPerSource) Remove(owned.First!.Value);
            while (Entries.Count >= MaxEntries || totalWeight + w > MaxWeight)
            {
                if (Order.First == null) break;
                Remove(Order.First.Value);
            }
            var n = Order.AddLast(key);
            Entries[key] = (new Entry(value, source, w), n);
            totalWeight += w;
            if (!BySource.TryGetValue(source, out var set)) BySource[source] = set = new LinkedList<string>();
            set.AddLast(key);
        }
        return value;
    }

    /// <summary>Whether pattern <paramref name="src"/> is currently cached (tests / diagnostics).</summary>
    public static bool Has(string src) { lock (Lock) return Entries.ContainsKey(KeyOf(src)); }

    /// <summary>Cache occupancy (tests / diagnostics).</summary>
    public static (int Entries, int Weight, int MaxWeight, IReadOnlyDictionary<string, int> BySource) Stats()
    {
        lock (Lock) return (Entries.Count, totalWeight, RegexCache.MaxWeight, BySource.ToDictionary(kv => kv.Key, kv => kv.Value.Count));
    }
}

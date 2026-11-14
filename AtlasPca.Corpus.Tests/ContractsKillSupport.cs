using AtlasPca;
using JD = System.Collections.Generic.Dictionary<string, object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Shared helpers of the contracts / enforcer / break-glass / lease / policy-link kill suites.</summary>
internal static class ContractsKillSupport
{
    /// <summary>Parses JSON written with single quotes (no apostrophes inside the values).</summary>
    internal static object? J(string s) => Pca.ParseJson(s.Replace('\'', '"'));

    internal static JD M(string s) => (JD)J(s)!;

    internal static EdKey Key(byte fill) => EdKey.FromSeed(Enumerable.Repeat(fill, 32).ToArray());

    /// <summary>The body plus its signature over <paramref name="domain"/>.</summary>
    internal static JD Sign(JD body, string domain, EdKey key)
    {
        var b = Issue.NormJ(body);
        return new JD(b) { ["sig"] = Issue.SignBody(key, domain, b) };
    }

    internal static double Nv(object? o) => IntentJs.NumOf(o)!.Value;
}

/// <summary>A store whose calls can be made to throw or to do nothing, for the keys <see cref="Affects"/> selects.</summary>
internal sealed class ContractsKillFaultKv : IAtomicKv
{
    internal readonly MemoryAtomicKv Inner = new();
    internal bool GetThrows, UpdateThrows, UpdateSkips;
    internal Func<string, bool> Affects = _ => true;
    internal int Updates;

    public string? Get(string key)
    {
        if (GetThrows && Affects(key)) throw new InvalidOperationException("get down");
        return Inner.Get(key);
    }

    public void Update(string key, Func<string?, string?> fn)
    {
        Updates++;
        if (Affects(key))
        {
            if (UpdateThrows) throw new InvalidOperationException("update down");
            if (UpdateSkips) return;
        }
        Inner.Update(key, fn);
    }
}

/// <summary>A dictionary comparer that throws from the <c>throwOn</c>-th hashing of one key on (an insertion of the key counts as one), to inject a fault at an exact read.</summary>
internal sealed class ContractsKillProbeComparer : IEqualityComparer<string>
{
    readonly string key;
    readonly int throwOn;
    int seen;

    internal ContractsKillProbeComparer(string key, int throwOn) { this.key = key; this.throwOn = throwOn; }

    public bool Equals(string? x, string? y) => string.Equals(x, y, StringComparison.Ordinal);

    public int GetHashCode(string obj)
    {
        if (obj == key && ++seen >= throwOn) throw new InvalidOperationException("probe");
        return StringComparer.Ordinal.GetHashCode(obj);
    }
}

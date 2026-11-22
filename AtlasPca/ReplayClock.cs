namespace AtlasPca;

/// <summary>The wall clock every library default reads, in epoch milliseconds. A corpus replay pins it for its own execution flow (the reference generator ran under a frozen clock);
/// in production nothing sets it and it is the system clock.</summary>
internal static class ReplayClock
{
    static readonly AsyncLocal<Func<long>?> Pinned = new();

    internal static Func<long>? Ms
    {
        get => Pinned.Value;
        set => Pinned.Value = value;
    }

    internal static long NowMs() => Pinned.Value?.Invoke() ?? DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
}

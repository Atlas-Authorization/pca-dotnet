namespace AtlasPca.Corpus.Tests;

/// <summary>
/// The racers of a racy double meet between their read and their write: every racer reads, then waits until a partner on the same
/// key has read too (racers pair off in arrival order: the harness's retry race has two racers and its bursts sixteen, so a barrier of
/// a fixed size would not fit both), and only then do the two write, so a pair always loses an update whatever the scheduler or the
/// machine speed does (a wall-clock sleep, or a wait that times out silently, let a late racer run alone). A call from the thread that
/// built the double is serial setup and never waits. A racer left without a partner for 30 s fails: the failure is kept in
/// <see cref="Broken"/>, which the tests assert is null.
/// </summary>
internal sealed class PairRendezvous
{
    readonly Thread _owner = Thread.CurrentThread;
    readonly System.Collections.Concurrent.ConcurrentDictionary<string, ManualResetEventSlim> _pending = new();
    Exception? _broken;

    public Exception? Broken => Volatile.Read(ref _broken);

    public void Meet(string key)
    {
        if (Thread.CurrentThread == _owner) return;
        while (true)
        {
            var mine = new ManualResetEventSlim(false);
            var first = _pending.GetOrAdd(key, mine);
            if (ReferenceEquals(first, mine))
            {
                if (mine.Wait(TimeSpan.FromSeconds(30))) return;
                _pending.TryRemove(new KeyValuePair<string, ManualResetEventSlim>(key, mine));
                var e = new TimeoutException($"no partner reached the rendezvous on {key}");
                Interlocked.CompareExchange(ref _broken, e, null);
                throw e;
            }
            if (_pending.TryRemove(new KeyValuePair<string, ManualResetEventSlim>(key, first)))
            {
                first.Set();
                return;
            }
        }
    }
}

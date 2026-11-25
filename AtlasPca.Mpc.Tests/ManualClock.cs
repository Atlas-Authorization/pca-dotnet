using AtlasPca.Mpc.Net;

namespace AtlasPca.Mpc.Tests;

/// <summary>A virtual clock: time moves only when the test says so. Timers fire in order of due time (then creation) during <see cref="Advance"/>.</summary>
sealed class ManualClock : IMeshClock
{
    sealed record Timer(long Due, Action Fn);

    long _t;
    long _seq;
    readonly Dictionary<long, Timer> _timers = new();
    readonly object _gate = new();

    public long Now() { lock (_gate) return _t; }

    public object SetTimer(Action fn, long ms)
    {
        lock (_gate)
        {
            long id = ++_seq;
            _timers[id] = new Timer(_t + ms, fn);
            return id;
        }
    }

    public void ClearTimer(object h) { lock (_gate) _timers.Remove((long)h); }

    public int Pending() { lock (_gate) return _timers.Count; }

    public void Advance(long ms)
    {
        long target;
        lock (_gate) target = _t + ms;
        for (;;)
        {
            Action fn;
            lock (_gate)
            {
                KeyValuePair<long, Timer>? best = null;
                foreach (var e in _timers.OrderBy(e => e.Key))
                    if (e.Value.Due <= target && (best == null || e.Value.Due < best.Value.Value.Due)) best = e;
                if (best == null)
                {
                    _t = target;
                    return;
                }
                _timers.Remove(best.Value.Key);
                _t = Math.Max(_t, best.Value.Value.Due);
                fn = best.Value.Value.Fn;
            }
            fn();
        }
    }
}

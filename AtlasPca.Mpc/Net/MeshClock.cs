using System.Diagnostics;

namespace AtlasPca.Mpc.Net;

/// <summary>
/// Time source for every DECISION the mesh makes by time (receive deadlines, connect deadline, dial retry window). The default
/// is the real clock; tests inject a virtual clock so an outcome never depends on how loaded the machine is.
/// </summary>
public interface IMeshClock
{
    /// <summary>Current time in milliseconds (monotonic; only differences matter).</summary>
    long Now();

    /// <summary>Run <paramref name="fn"/> after <paramref name="ms"/> of clock time; returns a handle for <see cref="ClearTimer"/>.</summary>
    object SetTimer(Action fn, long ms);

    void ClearTimer(object handle);
}

public static class MeshClock
{
    private sealed class WallClock : IMeshClock
    {
        public long Now() => Stopwatch.GetTimestamp() / (Stopwatch.Frequency / 1000L);

        public object SetTimer(Action fn, long ms) =>
            new Timer(_ => fn(), null, Math.Max(0L, ms), Timeout.Infinite);

        public void ClearTimer(object handle)
        {
            if (handle is Timer t) t.Dispose();
        }
    }

    /// <summary>Real time (monotonic).</summary>
    public static readonly IMeshClock Wall = new WallClock();
}

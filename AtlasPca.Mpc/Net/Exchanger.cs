namespace AtlasPca.Mpc.Net;

/// <summary>One un-echoed all-to-all round among the parties; a throw inside <c>parse</c> aborts the run naming that peer.</summary>
public interface IExchanger
{
    /// <summary>Send <c>mine(peer)</c> to every peer, collect theirs and validate each with <c>parse</c>; a null <paramref name="timeoutMs"/> means the mesh default.</summary>
    Dictionary<int, T> Exchange<T>(string rd, Func<int, object?> mine, Func<int, object?, T> parse, long? timeoutMs = null);

    /// <summary>A malformed-data abort naming peer <paramref name="p"/>; callers <c>throw</c> the result.</summary>
    Exception Bad(int p, string what);
}

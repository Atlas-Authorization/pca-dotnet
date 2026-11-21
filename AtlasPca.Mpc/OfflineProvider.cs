using System.Numerics;

namespace AtlasPca.Mpc;

/// <summary>A source of the SPDZ offline phase: the MAC key, authenticated triples and authenticated input sharings.</summary>
public interface IOfflineProvider
{
    int N();
    Spdz.MacContext MacContext();
    Spdz.AuthTriple GenAuthTriple();
    /// <summary>Authenticated sharing of <paramref name="value"/> contributed by party <paramref name="owner"/>.</summary>
    Spdz.AuthSV AuthInput(BigInteger value, int owner);
}

using System.Runtime.CompilerServices;

[assembly: InternalsVisibleTo("AtlasPca.Pairing.Tests")]

namespace AtlasPca.Aggsig;

/// <summary>
/// A public key whose proof of possession has been verified. The constructor is internal and the class is sealed, so the
/// only producers are <see cref="Aggsig.RegisterKey"/> and <see cref="KeyRegistry.Register"/>, and both run the proof-of-possession check first.
/// </summary>
public sealed class RegisteredKey
{
    readonly byte[] bytes;

    internal RegisteredKey(byte[] bytes) { this.bytes = (byte[])bytes.Clone(); }

    /// <summary>A copy of the 48-byte compressed G1 public key.</summary>
    public byte[] Bytes() => (byte[])bytes.Clone();
}

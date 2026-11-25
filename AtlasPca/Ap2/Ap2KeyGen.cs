// The AP2 key generator (the reference generateAp2KeyPair): a fresh P-256 key pair from the platform ECDSA implementation.
using System.Security.Cryptography;
using D = System.Collections.Generic.Dictionary<string, object?>;

namespace AtlasPca.Ap2;

public static partial class Ap2
{
    /// <summary>A fresh P-256 key pair: the public JWK <c>{kty, crv, x, y, kid?}</c> (never carrying <c>d</c>) and the private scalar.</summary>
    public static Ap2KeyPair GenerateAp2KeyPair(string? kid = null)
    {
        using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var p = ec.ExportParameters(true);
        var pub = new D { ["kty"] = "EC", ["crv"] = "P-256", ["x"] = B64uOf(p.Q.X!), ["y"] = B64uOf(p.Q.Y!) };
        if (kid != null) pub["kid"] = kid;
        return new Ap2KeyPair(pub, p.D!);
    }
}

using AtlasPca.Mpc.Net;
using Xunit;

namespace AtlasPca.Mpc.Tests;

/// <summary>Certs.GenerateIdentity / Certs.ReadPem: the identity files of a node (key + self-signed cert) and the refusal of a bad common name.</summary>
public class MpcCertsFilesTests
{
    [Fact]
    public void GeneratedIdentityFilesRoundTripThroughReadPem()
    {
        var dir = Path.Combine(Directory.CreateTempSubdirectory("pca-id-").FullName, "node");
        var id = Certs.GenerateIdentity(dir, "node-a");
        Assert.Equal(Path.Combine(dir, "key.pem"), id.KeyPath);
        Assert.Equal(Path.Combine(dir, "cert.pem"), id.CertPath);
        var key = Certs.ReadPem(id.KeyPath);
        var cert = Certs.ReadPem(id.CertPath);
        Assert.Contains("PRIVATE KEY", key);
        Assert.Contains("BEGIN CERTIFICATE", cert);
        using var parsed = Certs.WithKey(cert, key);
        Assert.True(parsed.HasPrivateKey);
        Assert.Equal(Certs.FingerprintOf(cert), Certs.Fingerprint(parsed));
        Assert.True(AtlasPca.OwnerOnly.IsOwnerOnly(id.KeyPath));
        Assert.True(AtlasPca.OwnerOnly.IsOwnerOnly(dir, true));
    }

    [Fact]
    public void ABadCommonNameIsRefused() =>
        Assert.Throws<ArgumentException>(() => Certs.GenerateIdentity(Path.Combine(Path.GetTempPath(), "pca-id-bad"), "bad name"));
}

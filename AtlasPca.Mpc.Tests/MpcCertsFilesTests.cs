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

    // A peer that concatenates the cert files (python's cadata) needs each PEM to end in a newline.
    [Fact]
    public void IdentityFilesEndInANewlineSoConcatenatedPemsParse()
    {
        var root = Directory.CreateTempSubdirectory("pca-id-nl-").FullName;
        var a = Certs.GenerateIdentity(Path.Combine(root, "a"), "node-a");
        var sw = new StringWriter();
        Assert.Equal(0, PartyMain.Run(new[] { "keygen", Path.Combine(root, "b"), "node-b" }, sw));
        foreach (var path in new[] { a.KeyPath, a.CertPath, Path.Combine(root, "b", "key.pem"), Path.Combine(root, "b", "cert.pem") })
            Assert.EndsWith("-----\n", File.ReadAllText(path));
        var both = File.ReadAllText(a.CertPath) + File.ReadAllText(Path.Combine(root, "b", "cert.pem"));
        Assert.Equal(2, System.Text.RegularExpressions.Regex.Matches(both, "^-----BEGIN CERTIFICATE-----$", System.Text.RegularExpressions.RegexOptions.Multiline).Count);
    }

    [Fact]
    public void ABadCommonNameIsRefused() =>
        Assert.Throws<ArgumentException>(() => Certs.GenerateIdentity(Path.Combine(Path.GetTempPath(), "pca-id-bad"), "bad name"));
}

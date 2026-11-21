using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;

namespace AtlasPca.Mpc.Net;

/// <summary>
/// Per-run identity material for the TLS mesh: one fresh P-256 key and self-signed certificate per node, generated with the platform
/// crypto (no hand-rolled primitive, no X.509 encoder of our own). The key lives only on the node that generated it; only the PUBLIC
/// certificates are exchanged and pinned.
/// </summary>
public static class Certs
{
    /// <summary>A node identity: PKCS#8 private key PEM and X.509 certificate PEM.</summary>
    public sealed record Identity(string KeyPem, string CertPem);

    private static readonly Regex CommonName = new(@"\A[A-Za-z0-9._-]{1,64}\z", RegexOptions.CultureInvariant);

    /// <summary>Generate a throw-away identity for <paramref name="cn"/> (valid 2 days). Fails closed on a bad common name.</summary>
    public static Identity Generate(string cn)
    {
        if (cn == null || !CommonName.IsMatch(cn)) throw new ArgumentException("certs: bad common name");
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        return FromKey(key, cn);
    }

    /// <summary>Where a generated identity was written.</summary>
    public sealed record NodeIdentity(string KeyPath, string CertPath);

    /// <summary>Generate <c>&lt;dir&gt;/key.pem</c> and <c>&lt;dir&gt;/cert.pem</c> for <paramref name="cn"/> (valid 2 days: per-run, throw-away). The directory is
    /// created private (0700 on Unix) and the key file is written mode 0600; the platform crypto does the work, no external <c>openssl</c> is run.</summary>
    public static NodeIdentity GenerateIdentity(string dir, string cn)
    {
        var id = Generate(cn);
        if (OperatingSystem.IsWindows()) { Directory.CreateDirectory(dir); AtlasPca.OwnerOnly.Directory(dir); }
        else Directory.CreateDirectory(dir, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        var keyPath = Path.Combine(dir, "key.pem");
        var certPath = Path.Combine(dir, "cert.pem");
        var o = new FileStreamOptions { Mode = FileMode.Create, Access = FileAccess.Write };
        if (!OperatingSystem.IsWindows()) o.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
        using (var f = new StreamWriter(keyPath, o))
        {
            if (OperatingSystem.IsWindows()) AtlasPca.OwnerOnly.File(keyPath); // before the key is written
            f.Write(id.KeyPem);
        }
        File.WriteAllText(certPath, id.CertPem);
        return new NodeIdentity(keyPath, certPath);
    }

    /// <summary>The text of a PEM file (the TypeScript <c>readPem</c>).</summary>
    public static string ReadPem(string path) => File.ReadAllText(path);

    /// <summary>Self-sign an identity for an existing P-256 key (callers that derive the key themselves, e.g. tests from a fixed seed).</summary>
    public static Identity FromKey(ECDsa key, string cn)
    {
        if (cn == null || !CommonName.IsMatch(cn)) throw new ArgumentException("certs: bad common name");
        if (key.KeySize != 256) throw new ArgumentException("certs: a P-256 key is required");
        var req = new CertificateRequest("CN=" + cn, key, HashAlgorithmName.SHA256);
        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        req.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        req.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
            new OidCollection { new Oid("1.3.6.1.5.5.7.3.1"), new Oid("1.3.6.1.5.5.7.3.2") }, false));
        var now = DateTimeOffset.UtcNow;
        using var cert = req.CreateSelfSigned(now.AddMinutes(-5), now.AddDays(2));
        return new Identity(key.ExportPkcs8PrivateKeyPem(), cert.ExportCertificatePem());
    }

    private static byte[] PemBody(string pem, string label)
    {
        string begin = "-----BEGIN " + label + "-----", end = "-----END " + label + "-----";
        if (pem == null || !pem.Contains(begin, StringComparison.Ordinal)) throw new ArgumentException("certs: not a " + label + " PEM");
        string b = Regex.Replace(pem.Replace(begin, "").Replace(end, ""), @"\s", "");
        if (b.Length == 0) throw new ArgumentException("certs: not a " + label + " PEM");
        return Convert.FromBase64String(b);
    }

    public static X509Certificate2 ParseCert(string certPem)
    {
        try
        {
            return new X509Certificate2(PemBody(certPem, "CERTIFICATE"));
        }
        catch (Exception e)
        {
            throw new ArgumentException("certs: bad certificate: " + e.Message, e);
        }
    }

    public static ECDsa ParseKey(string keyPem)
    {
        ECDsa? k = null;
        try
        {
            k = ECDsa.Create();
            k.ImportPkcs8PrivateKey(PemBody(keyPem, "PRIVATE KEY"), out _);
            if (k.KeySize != 256) throw new CryptographicException("not a P-256 key");
            string? oid = k.ExportParameters(false).Curve.Oid?.Value;
            if (oid != null && oid != "1.2.840.10045.3.1.7") throw new CryptographicException("not a P-256 key");
            return k;
        }
        catch (Exception e)
        {
            k?.Dispose();
            throw new ArgumentException("certs: bad private key (PKCS#8 EC expected)", e);
        }
    }

    /// <summary>The certificate with its private key attached, round-tripped through PFX so SslStream accepts an ephemeral key on every platform.</summary>
    public static X509Certificate2 WithKey(string certPem, string keyPem)
    {
        using var cert = ParseCert(certPem);
        using var key = ParseKey(keyPem);
        using var paired = cert.CopyWithPrivateKey(key);
        return new X509Certificate2(paired.Export(X509ContentType.Pfx));
    }

    /// <summary>SHA-256 fingerprint of a DER certificate, lowercase hex.</summary>
    public static string Fingerprint(X509Certificate c) => Fingerprint(c.GetRawCertData());

    public static string Fingerprint(byte[] der) => Convert.ToHexString(SHA256.HashData(der)).ToLowerInvariant();

    public static string FingerprintOf(string certPem)
    {
        using var c = ParseCert(certPem);
        return Fingerprint(c);
    }
}

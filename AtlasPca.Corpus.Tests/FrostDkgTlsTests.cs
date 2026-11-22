using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using AtlasPca;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>The mutual-TLS DKG node over real loopback links: a three-party 2-of-3 ceremony in which every party ends with the same group key, and the refusals before any DKG byte is read
/// (a peer certificate that is not the pinned one, a client without a certificate, a TLS 1.2 client, the wrong direction of dialling). The certificates are generated here, at test time.</summary>
public class FrostDkgTlsTests
{
    static (string Key, string Cert) MakeCert(string cn, DateTimeOffset? notAfter = null)
    {
        using var k = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var req = new CertificateRequest("CN=" + cn, k, HashAlgorithmName.SHA256);
        req.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        req.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new Oid("1.3.6.1.5.5.7.3.1"), new Oid("1.3.6.1.5.5.7.3.2") }, false));
        using var c = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddHours(-1), notAfter ?? DateTimeOffset.UtcNow.AddHours(1));
        return (k.ExportPkcs8PrivateKeyPem(), c.ExportCertificatePem());
    }

    // macOS's TLS library does not serve TLS 1.3 to .NET; the node is for platforms that do (OpenSSL on Linux, Schannel on Windows 11 / Server 2022), so these tests run there.
    static bool NoTls13Server => OperatingSystem.IsMacOS();

    static readonly byte[] Sid = Enumerable.Repeat((byte)7, 32).ToArray();

    static TlsDkgNode Node(long self, Dictionary<long, (string Key, string Cert)> pki, IEnumerable<long> pinned, Dictionary<long, string>? override_ = null) =>
        FrostDkgTls.StartTlsDkgNode(new TlsDkgNodeOpts
        {
            Self = self, SessionId = Sid, KeyPem = pki[self].Key, CertPem = pki[self].Cert,
            PeerCerts = pinned.Select(o => new TlsDkgPeerCert(o, override_?.GetValueOrDefault(o) ?? pki[o].Cert)).ToList(),
        });

    [Fact]
    public async Task ThreePartyCeremonyOverMutualTlsLinks()
    {
        if (NoTls13Server) return;
        long[] ids = [1, 2, 3];
        var pki = ids.ToDictionary(i => i, i => MakeCert("p" + i));
        var nodes = ids.ToDictionary(i => i, i => Node(i, pki, ids.Where(o => o != i)));
        try
        {
            var addrs = ids.Select(i => new TlsDkgAddress(i, "127.0.0.1", nodes[i].Port)).ToList();
            var results = await Task.WhenAll(ids.Select(async i =>
            {
                var ch = await nodes[i].ConnectAsync(addrs.Where(x => x.Id != i).ToList(), 10_000); // a node dials its peers, not itself
                return await FrostDkgChannel.RunAsync(ch, new FrostDkgChannel.RunOpts { T = 2, Participants = ids.Select(x => (double)x).ToList(), SessionId = Sid, TimeoutMs = 10_000 });
            }));
            var groupKeys = results.Select(r => Pca.B64u((byte[])((D)r["keyPackage"]!)["groupPublicKey"]!)).Distinct().ToList();
            Assert.Single(groupKeys);
        }
        finally { foreach (var n in nodes.Values) await n.CloseAsync(); }
    }

    [Fact]
    public async Task APeerShowingAnUnpinnedCertificateIsNeverLinked()
    {
        if (NoTls13Server) return;
        var pki = new Dictionary<long, (string Key, string Cert)> { [1] = MakeCert("p1"), [2] = MakeCert("p2") };
        var foreign = MakeCert("foreign").Cert;
        await using var a = Node(1, pki, [2]);
        // node 2 pins a certificate that is not node 1's: the dialled peer's certificate fails the pin
        await using var b = Node(2, pki, [1], new Dictionary<long, string> { [1] = foreign });
        var e = await Assert.ThrowsAsync<DkgChannelError>(() => b.ConnectAsync([new TlsDkgAddress(1, "127.0.0.1", a.Port)], 600));
        Assert.Equal("timeout", e.Code);
    }

    [Fact]
    public async Task ADialerThatPinsTheWrongOwnCertificateIsRefusedByTheListener()
    {
        if (NoTls13Server) return;
        var pki = new Dictionary<long, (string Key, string Cert)> { [1] = MakeCert("p1"), [2] = MakeCert("p2") };
        var foreign = MakeCert("foreign").Cert;
        // node 1 pins a foreign certificate for node 2: the listener refuses node 2's real certificate, so node 1 never links
        await using var a = Node(1, pki, [2], new Dictionary<long, string> { [2] = foreign });
        await using var b = Node(2, pki, [1]);
        var waiting = a.ConnectAsync([], 700);
        await Assert.ThrowsAsync<DkgChannelError>(() => Task.WhenAll(waiting, b.ConnectAsync([new TlsDkgAddress(1, "127.0.0.1", a.Port)], 700)));
    }

    [Fact]
    public async Task PlaintextTls12AndCertificatelessClientsAreRefused()
    {
        if (NoTls13Server) return;
        var pki = new Dictionary<long, (string Key, string Cert)> { [1] = MakeCert("p1"), [2] = MakeCert("p2") };
        await using var a = Node(1, pki, [2]);

        // plaintext bytes: the listener drops the connection
        using (var plain = new TcpClient())
        {
            await plain.ConnectAsync("127.0.0.1", a.Port);
            var s = plain.GetStream();
            await s.WriteAsync(new byte[] { 0, 0, 0, 5, 1, 2, 3, 4, 5 });
            Assert.True(await Closed(s));
        }

        // a valid pinned certificate but TLS 1.2 only
        await Assert.ThrowsAnyAsync<Exception>(() => Handshake(a.Port, pki[2], SslProtocols.Tls12));
        // TLS 1.3 without any client certificate
        await Assert.ThrowsAnyAsync<Exception>(() => Handshake(a.Port, null, SslProtocols.Tls13));
        // the right protocol and certificate, so the handshake itself succeeds (the only link a listener of id 1 accepts is from a higher id: 2)
        await Handshake(a.Port, pki[2], SslProtocols.Tls13);
    }

    static async Task<bool> Closed(NetworkStream s)
    {
        try
        {
            var buf = new byte[16];
            using var cts = new CancellationTokenSource(3000);
            return await s.ReadAsync(buf, cts.Token) == 0;
        }
        catch (Exception e) when (e is IOException or SocketException) { return true; }
    }

    static async Task Handshake(int port, (string Key, string Cert)? client, SslProtocols protocols)
    {
        using var tcp = new TcpClient();
        await tcp.ConnectAsync("127.0.0.1", port);
        using var ssl = new SslStream(tcp.GetStream(), false); // the validation callback lives in the options (both at once is refused)
        var opts = new SslClientAuthenticationOptions { TargetHost = "127.0.0.1", EnabledSslProtocols = protocols, RemoteCertificateValidationCallback = (_, _, _, _) => true };
        if (client is { } c)
        {
            using var pem = X509Certificate2.CreateFromPem(c.Cert, c.Key);
            opts.ClientCertificates = new X509CertificateCollection { new X509Certificate2(pem.Export(X509ContentType.Pkcs12)) };
        }
        using var cts = new CancellationTokenSource(5000);
        await ssl.AuthenticateAsClientAsync(opts, cts.Token);
        // TLS 1.3 reports a rejected client certificate on the first read after the handshake
        var buf = new byte[1];
        if (client == null && await ssl.ReadAsync(buf, cts.Token) == 0) throw new IOException("the listener closed the link");
    }
}

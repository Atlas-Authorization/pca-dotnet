using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Numerics;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using AtlasPca.Mpc;
using AtlasPca.Mpc.Net;
using Org.BouncyCastle.Asn1.X9;
using Xunit;
using JD = System.Collections.Generic.Dictionary<string, object?>;

namespace AtlasPca.Mpc.Tests;

using Mesh = AtlasPca.Mpc.Net.Mesh;

/// <summary>Shared helpers for the networked-driver tests: dedicated-thread tasks, free ports, seed-derived identities, and a hand-driven TLS peer.</summary>
internal static class MpcNetSupport
{
    public const string Sid = "mesh-test-session";

    /// <summary>Blocking tasks need real threads: the pool can be as small as one thread on a small CI machine.</summary>
    public static Task Run(Action a) => Task.Factory.StartNew(a, CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default);

    public static Task<T> Run<T>(Func<T> f) => Task.Factory.StartNew(f, CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default);

    public static int FreePort()
    {
        var l = new TcpListener(IPAddress.Loopback, 0);
        l.Start();
        try { return ((IPEndPoint)l.LocalEndpoint).Port; }
        finally { l.Stop(); }
    }

    private static readonly BigInteger P256Order = BigInteger.Parse("0FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", System.Globalization.NumberStyles.HexNumber);

    /// <summary>A P-256 identity whose private scalar is derived from a fixed seed label (no committed private key).</summary>
    public static Certs.Identity SeedIdentity(string label)
    {
        byte[] h = SHA256.HashData(Encoding.UTF8.GetBytes("atlas-pca-conformance/mpc-net/" + label));
        BigInteger d = (new BigInteger(h, isUnsigned: true, isBigEndian: true) % (P256Order - 1)) + 1;
        byte[] db = d.ToByteArray(isUnsigned: true, isBigEndian: true);
        if (db.Length < 32) db = new byte[32 - db.Length].Concat(db).ToArray();
        X9ECParameters curve = ECNamedCurveTable.GetByName("secp256r1");
        var q = curve.G.Multiply(new Org.BouncyCastle.Math.BigInteger(1, db)).Normalize();
        var prm = new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            D = db,
            Q = new System.Security.Cryptography.ECPoint { X = q.AffineXCoord.GetEncoded(), Y = q.AffineYCoord.GetEncoded() },
        };
        using var key = ECDsa.Create(prm);
        return Certs.FromKey(key, label);
    }

    public static Mesh.Config Cfg(int self, List<Mesh.NodeAddr> nodes, Certs.Identity id, long connectMs, long recvMs) => new()
    {
        SelfId = self,
        Nodes = nodes,
        KeyPem = id.KeyPem,
        CertPem = id.CertPem,
        SessionId = Sid,
        ListenHost = "127.0.0.1",
        ConnectTimeoutMs = connectMs,
        RecvTimeoutMs = recvMs,
    };

    /// <summary>The exception a faulted task carries (unwrapped from AggregateException); fails when the task does not fault in time.</summary>
    public static Exception FaultOf(Task t, int seconds)
    {
        try
        {
            if (!t.Wait(seconds * 1000)) Assert.Fail("task did not finish within " + seconds + "s");
        }
        catch (AggregateException ae)
        {
            return ae.GetBaseException();
        }
        Assert.Fail("expected the task to fault");
        throw new InvalidOperationException();
    }

    public static NetWire.NetAbort AbortOf(Exception? e)
    {
        while (e != null && e is not NetWire.NetAbort) e = e.InnerException;
        Assert.NotNull(e);
        return (NetWire.NetAbort)e!;
    }

    /// <summary>A raw TLS client speaking the frame format, standing in for a peer node.</summary>
    internal sealed class RawPeer : IDisposable
    {
        public readonly TcpClient Tcp;
        public readonly SslStream Ssl;

        public RawPeer(Certs.Identity me, string serverCertPem, int port)
        {
            string serverFp = Certs.FingerprintOf(serverCertPem);
            using X509Certificate2 mine = Certs.WithKey(me.CertPem, me.KeyPem);
            long end = Environment.TickCount64 + 10_000;
            for (;;)
            {
                TcpClient? tcp = null;
                SslStream? ssl = null;
                try
                {
                    tcp = new TcpClient();
                    if (!tcp.ConnectAsync("127.0.0.1", port).Wait(2000)) throw new IOException("connect timed out");
                    ssl = new SslStream(tcp.GetStream(), false);
                    ssl.AuthenticateAsClient(new SslClientAuthenticationOptions
                    {
                        TargetHost = "127.0.0.1",
                        ClientCertificates = new X509CertificateCollection { mine },
                        EnabledSslProtocols = SslProtocols.Tls13,
                        CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
                        RemoteCertificateValidationCallback = (s, c, ch, e) => c != null && Certs.Fingerprint(c) == serverFp,
                    });
                    Tcp = tcp;
                    Ssl = ssl;
                    return;
                }
                catch (Exception)
                {
                    try { ssl?.Dispose(); } catch (Exception) { /* gone */ }
                    try { tcp?.Dispose(); } catch (Exception) { /* gone */ }
                    if (Environment.TickCount64 > end) throw;
                    Thread.Sleep(100);
                }
            }
        }

        public void Write(byte[] b)
        {
            Ssl.Write(b, 0, b.Length);
            Ssl.Flush();
        }

        public void Frame(string ty, string rd, long seq, object? d) =>
            Write(NetWire.EncodeFrame(new NetWire.Frame(NetWire.WIRE_VERSION, ty, Sid, seq, rd, d)));

        public void Hello(int claimedId) => Frame("hello", "hello", 0, new JD { ["id"] = claimedId });

        public void Dispose()
        {
            try { Ssl.Dispose(); } catch (Exception) { /* gone */ }
            try { Tcp.Dispose(); } catch (Exception) { /* gone */ }
        }
    }
}

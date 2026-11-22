using AtlasPca.Mpc;
using AtlasPca.Mpc.Net;
using Xunit;
using JD = System.Collections.Generic.Dictionary<string, object?>;
using static AtlasPca.Mpc.Tests.MpcNetSupport;

namespace AtlasPca.Mpc.Tests;

using Mesh = AtlasPca.Mpc.Net.Mesh;

/// <summary>The mutual-TLS mesh over loopback: an honest 3-node exchange, and the refusals (wrong pin, wrong hello id, oversize, replay, wrong round, early close). Identities derive from fixed seeds.</summary>
[Collection("MpcNet")]
public class MpcMeshTests
{
    [TlsFact]
    public void HonestThreeNodeExchange()
    {
        const int n = 3;
        var ids = new Certs.Identity[n];
        var nodes = new List<Mesh.NodeAddr>();
        for (int i = 0; i < n; i++)
        {
            ids[i] = SeedIdentity("node" + i);
            nodes.Add(new Mesh.NodeAddr(i, "127.0.0.1", FreePort(), ids[i].CertPem));
        }
        var meshes = new Mesh[n];
        for (int i = 0; i < n; i++) meshes[i] = new Mesh(Cfg(i, nodes, ids[i], 20_000, 10_000));
        var conn = meshes.Select(m => Run(() => m.Connect())).ToArray();
        Assert.True(Task.WaitAll(conn, 30_000));

        var runs = new Task<SortedDictionary<int, object?>>[n];
        for (int i = 0; i < n; i++)
        {
            int me = i;
            runs[i] = Run(() =>
            {
                meshes[me].Broadcast("r1", new JD { ["x"] = me });
                return meshes[me].Collect("r1");
            });
        }
        Assert.True(Task.WaitAll(runs, 30_000));
        for (int i = 0; i < n; i++)
        {
            var got = runs[i].Result;
            Assert.Equal(n - 1, got.Count);
            foreach (var e in got)
            {
                Assert.NotEqual(i, e.Key);
                Assert.Equal(e.Key.ToString(), ((Num)((JD)e.Value!)["x"]!).Raw);
            }
        }
        // signatures are verifiable against the pinned certificate only
        byte[] data = System.Text.Encoding.UTF8.GetBytes("statement");
        byte[] sig = meshes[0].Sign(data);
        Assert.True(meshes[1].Verify(0, data, sig));
        Assert.False(meshes[1].Verify(2, data, sig));
        Assert.False(meshes[1].Verify(0, System.Text.Encoding.UTF8.GetBytes("other"), sig));
        Assert.False(meshes[0].Verify(0, data, sig));
        foreach (var m in meshes) m.Finish();
    }

    [TlsFact]
    public void PinnedCertMismatchRefusesTheLink()
    {
        var real0 = SeedIdentity("real0");
        var imposter = SeedIdentity("imposter");
        var id1 = SeedIdentity("node1");
        int p0 = FreePort(), p1 = FreePort();
        // node 1 pins an imposter certificate for node 0, so the real node 0 must be refused
        var view0 = new List<Mesh.NodeAddr> { new(0, "127.0.0.1", p0, real0.CertPem), new(1, "127.0.0.1", p1, id1.CertPem) };
        var view1 = new List<Mesh.NodeAddr> { new(0, "127.0.0.1", p0, imposter.CertPem), new(1, "127.0.0.1", p1, id1.CertPem) };
        var m0 = new Mesh(Cfg(0, view0, real0, 2_500, 2_000));
        var m1 = new Mesh(Cfg(1, view1, id1, 2_500, 2_000));
        var c0 = Run(() => m0.Connect());
        var c1 = Run(() => m1.Connect());
        var e1 = FaultOf(c1, 20);
        Assert.Contains(AbortOf(e1).Kind, new[] { "timeout", "identity" });
        FaultOf(c0, 20);
    }

    [TlsFact]
    public void TamperHookNeedsExplicitOptIn()
    {
        var id0 = SeedIdentity("n0");
        var id1 = SeedIdentity("n1");
        var nodes = new List<Mesh.NodeAddr> { new(0, "127.0.0.1", 1, id0.CertPem), new(1, "127.0.0.1", 2, id1.CertPem) };
        var c = Cfg(0, nodes, id0, 1000, 1000);
        c.Tamper = ev => new List<byte[]> { ev.Raw };
        Assert.ThrowsAny<ArgumentException>(() => new Mesh(c));
        // a node whose own certificate differs from the one listed for it is refused
        Assert.ThrowsAny<ArgumentException>(() => new Mesh(Cfg(0, nodes, id1, 1000, 1000)));
    }

    // ---- refusals from a hand-driven peer (node 1 dials node 0) ----

    private sealed record Rig(Certs.Identity Id0, Certs.Identity Id1, Mesh M0, Task Connect, int Port);

    private static Rig MakeRig(long connectMs, long recvMs)
    {
        var id0 = SeedIdentity("n0");
        var id1 = SeedIdentity("n1");
        int p0 = FreePort();
        var nodes = new List<Mesh.NodeAddr> { new(0, "127.0.0.1", p0, id0.CertPem), new(1, "127.0.0.1", 1, id1.CertPem) };
        var m0 = new Mesh(Cfg(0, nodes, id0, connectMs, recvMs));
        return new Rig(id0, id1, m0, Run(() => m0.Connect()), p0);
    }

    [TlsFact]
    public void HelloWithWrongPartyIdIsRefused()
    {
        var r = MakeRig(10_000, 5_000);
        using var p = new RawPeer(r.Id1, r.Id0.CertPem, r.Port);
        p.Hello(5);
        var a = AbortOf(FaultOf(r.Connect, 15));
        Assert.Equal("identity", a.Kind);
        Assert.Equal(1, a.Blamed);
    }

    [TlsFact]
    public void OversizeLengthPrefixIsRefused()
    {
        var r = MakeRig(10_000, 5_000);
        using var p = new RawPeer(r.Id1, r.Id0.CertPem, r.Port);
        p.Hello(1);
        Assert.True(r.Connect.Wait(15_000));
        int bad = NetWire.MAX_FRAME_BYTES + 1;
        p.Write(new[] { (byte)(bad >>> 24), (byte)(bad >>> 16), (byte)(bad >>> 8), (byte)bad });
        var a = Assert.Throws<NetWire.NetAbort>(() => r.M0.Recv(1, "x", 5_000));
        Assert.Equal("oversize", a.Kind);
        Assert.Equal(1, a.Blamed);
    }

    static NetWire.NetAbort AbortWithin(int reads, Func<object?> read)
    {
        for (int i = 1; i < reads; i++)
        {
            try { read(); }
            catch (NetWire.NetAbort e) { return e; }
        }
        return Assert.Throws<NetWire.NetAbort>(() => read());
    }

    [TlsFact]
    public void ReplayedSequenceNumberIsRefused()
    {
        var r = MakeRig(10_000, 5_000);
        using var p = new RawPeer(r.Id1, r.Id0.CertPem, r.Port);
        p.Hello(1);
        Assert.True(r.Connect.Wait(15_000));
        p.Frame("msg", "x", 1, "a");
        p.Frame("msg", "x", 1, "b");
        // the first frame is a valid message and is delivered; the replay of its sequence number aborts the read after it, or already the first read when the
        // reader thread has handled both frames by then: either way the abort is a duplicate
        var a = AbortWithin(2, () => r.M0.Recv(1, "x", 5_000));
        Assert.Equal("duplicate", a.Kind);
    }

    [TlsFact]
    public void SkippedSequenceNumberIsRefused()
    {
        var r = MakeRig(10_000, 5_000);
        using var p = new RawPeer(r.Id1, r.Id0.CertPem, r.Port);
        p.Hello(1);
        Assert.True(r.Connect.Wait(15_000));
        p.Frame("msg", "x", 5, "a");
        var a = Assert.Throws<NetWire.NetAbort>(() => r.M0.Recv(1, "x", 5_000));
        Assert.Equal("out-of-order", a.Kind);
    }

    [TlsFact]
    public void WrongRoundIsRefused()
    {
        var r = MakeRig(10_000, 5_000);
        using var p = new RawPeer(r.Id1, r.Id0.CertPem, r.Port);
        p.Hello(1);
        Assert.True(r.Connect.Wait(15_000));
        p.Frame("msg", "other", 1, "a");
        var a = Assert.Throws<NetWire.NetAbort>(() => r.M0.Recv(1, "x", 5_000));
        Assert.Equal("wrong-round", a.Kind);
        Assert.Equal(1, a.Blamed);
    }

    [TlsFact]
    public void EarlyCloseIsADisconnect()
    {
        var r = MakeRig(10_000, 5_000);
        var p = new RawPeer(r.Id1, r.Id0.CertPem, r.Port);
        p.Hello(1);
        Assert.True(r.Connect.Wait(15_000));
        p.Dispose();
        var a = Assert.Throws<NetWire.NetAbort>(() => r.M0.Recv(1, "x", 5_000));
        Assert.Equal("disconnect", a.Kind);
        Assert.Equal(1, a.Blamed);
    }

    [TlsFact]
    public void SilentPeerIsBlamedAfterTheDeadline()
    {
        var r = MakeRig(10_000, 5_000);
        using var p = new RawPeer(r.Id1, r.Id0.CertPem, r.Port);
        p.Hello(1);
        Assert.True(r.Connect.Wait(15_000));
        var a = Assert.Throws<NetWire.NetAbort>(() => r.M0.Recv(1, "x", 300));
        Assert.Equal("timeout", a.Kind);
        Assert.Equal(1, a.Blamed);
        Assert.Equal(300, a.DeadlineMs);
    }

    [TlsFact]
    public void ClientWithAnUnpinnedCertificateNeverLinks()
    {
        var r = MakeRig(2_000, 1_000);
        var stranger = SeedIdentity("stranger");
        try
        {
            using var p = new RawPeer(stranger, r.Id0.CertPem, r.Port);
            p.Hello(1);
        }
        catch (Exception)
        {
            // the server may refuse the unpinned client before or after the handshake completes on our side
        }
        var a = AbortOf(FaultOf(r.Connect, 15));
        Assert.Equal("timeout", a.Kind);
    }
}

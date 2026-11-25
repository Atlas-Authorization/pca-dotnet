using System.Net;
using System.Net.Sockets;
using AtlasPca.Mpc;
using AtlasPca.Mpc.Net;
using Xunit;
using static AtlasPca.Mpc.Net.FaultProxy;
using D = System.Collections.Generic.Dictionary<string, object?>;

namespace AtlasPca.Mpc.Tests;

using Mesh = AtlasPca.Mpc.Net.Mesh;

/// <summary>The byte-level fault proxy (each kind driven through a scripted pipe, then over real sockets), the frame tamperer, and a wire fault through the launcher.</summary>
[Collection("MpcNet")]
public class MpcNetFaultsTests
{
    static byte[] B(params int[] n) => n.Select(x => (byte)x).ToArray();

    static List<int> L(params int[] n) => n.ToList();

    sealed class Rec : ISink
    {
        public readonly List<byte[]> Writes = new();
        public int Ended, Destroys;
        public bool IsDestroyed;
        public void Write(byte[] b) => Writes.Add(b);
        public void End() => Ended++;
        public void Destroy() { Destroys++; IsDestroyed = true; }
        public bool Destroyed() => IsDestroyed;
        public List<List<int>> Seen() => Writes.Select(w => w.Select(v => (int)v).ToList()).ToList();
    }

    sealed class Rig
    {
        public readonly Rec Dst = new();
        public readonly ManualClock Clock = new();
        public readonly List<string> Log = new();
        public readonly Pipe Pipe;
        public Rig(WireFault f, Dir? d = null) { Pipe = new Pipe(f, d ?? f.Dir, Dst, Clock, Log); }
        public void Send(params byte[][] cs) { foreach (var c in cs) Pipe.Data(c); }
    }

    static void SameSeen(List<List<int>> want, Rec got) => Assert.Equal(want.Select(w => string.Join(",", w)), got.Seen().Select(w => string.Join(",", w)));

    [Fact] public void KindNonePassesEverythingAndLogsNothing()
    {
        var r = new Rig(new WireFault(Kind.None, Dir.C2S, 0));
        r.Send(B(1, 2, 3), B(4));
        SameSeen(new() { L(1, 2, 3), L(4) }, r.Dst);
        Assert.Empty(r.Log);
    }

    [Fact] public void AFaultForOneDirectionLeavesTheOtherAlone()
    {
        var r = new Rig(new WireFault(Kind.Drop, Dir.C2S, 0), Dir.S2C);
        r.Send(B(7, 7));
        SameSeen(new() { L(7, 7) }, r.Dst);
        Assert.Empty(r.Log);
    }

    [Fact] public void DropPassesUpToAfterBytesThenBlackHoles()
    {
        var a = new Rig(new WireFault(Kind.Drop, Dir.C2S, 3));
        a.Send(B(1, 2, 3), B(4, 5), B(6, 7));
        a.Clock.Advance(10_000);
        SameSeen(new() { L(1, 2, 3) }, a.Dst); // a chunk ending exactly at afterBytes passes
        Assert.Equal(new[] { "fault drop c2s after 3B" }, a.Log);
        var b = new Rig(new WireFault(Kind.Drop, Dir.S2C, 2));
        b.Send(B(1, 2, 3), B(4));
        Assert.Empty(b.Dst.Writes); // the straddling chunk is faulted whole
        Assert.Equal(new[] { "fault drop s2c after 2B" }, b.Log);
    }

    [Fact] public void DelayDeliversAfterExactlyMsInOrder()
    {
        var r = new Rig(new WireFault(Kind.Delay, Dir.C2S, 2, 300));
        r.Send(B(1, 2), B(3, 4), B(5));
        SameSeen(new() { L(1, 2) }, r.Dst);
        r.Clock.Advance(299);
        Assert.Single(r.Dst.Writes);
        r.Clock.Advance(1);
        SameSeen(new() { L(1, 2), L(3, 4), L(5) }, r.Dst);
        Assert.Equal(new[] { "fault delay c2s after 2B" }, r.Log);
        Assert.Equal(0, r.Dst.Ended);
    }

    [Fact] public void DelayDefaultsToOneSecond()
    {
        var r = new Rig(new WireFault(Kind.Delay, Dir.C2S, 0));
        r.Send(B(9));
        r.Clock.Advance(999);
        Assert.Empty(r.Dst.Writes);
        r.Clock.Advance(1);
        SameSeen(new() { L(9) }, r.Dst);
    }

    [Fact] public void ASourceEndWhileWritesArePendingEndsTheDestinationAfterTheLastDelayedWrite()
    {
        var r = new Rig(new WireFault(Kind.Delay, Dir.C2S, 0, 100));
        r.Send(B(1));
        r.Clock.Advance(50);
        r.Send(B(2));
        r.Pipe.End();
        Assert.Equal(0, r.Dst.Ended);
        r.Clock.Advance(50);
        SameSeen(new() { L(1) }, r.Dst);
        Assert.Equal(0, r.Dst.Ended);
        r.Clock.Advance(50);
        SameSeen(new() { L(1), L(2) }, r.Dst);
        Assert.Equal(1, r.Dst.Ended);
    }

    [Fact] public void ASourceCloseWhileWritesArePendingDestroysTheDestinationOnlyAfterTheDelayedWrite()
    {
        var r = new Rig(new WireFault(Kind.Delay, Dir.C2S, 0, 100));
        r.Send(B(1));
        r.Pipe.Close();
        Assert.Equal(0, r.Dst.Destroys);
        r.Clock.Advance(100);
        SameSeen(new() { L(1) }, r.Dst);
        Assert.Equal(1, r.Dst.Destroys);
    }

    [Fact] public void NothingIsWrittenToADestinationDestroyedMeanwhile()
    {
        var r = new Rig(new WireFault(Kind.Delay, Dir.C2S, 0, 100));
        r.Send(B(1));
        r.Dst.IsDestroyed = true;
        r.Clock.Advance(100);
        Assert.Empty(r.Dst.Writes);
    }

    [Fact] public void ASourceEndWithNothingPendingEndsTheDestinationAtOnce()
    {
        var r = new Rig(new WireFault(Kind.Delay, Dir.C2S, 0, 100));
        r.Pipe.End();
        Assert.Equal(1, r.Dst.Ended);
        r.Pipe.Close();
        Assert.Equal(1, r.Dst.Destroys);
    }

    [Fact] public void TruncateCutsTheStraddlingChunkToHalfAndEndsOnceThenPassesLaterChunks()
    {
        var r = new Rig(new WireFault(Kind.Truncate, Dir.C2S, 2));
        r.Send(B(1, 2), B(3, 4, 5, 6, 7), B(8, 9));
        SameSeen(new() { L(1, 2), L(3, 4), L(8, 9) }, r.Dst);
        Assert.Equal(1, r.Dst.Ended);
        Assert.Equal(new[] { "fault truncate c2s after 2B" }, r.Log);
    }

    [Fact] public void BitflipFlipsBitZeroOfTheMiddleByteOnceOnACopy()
    {
        var r = new Rig(new WireFault(Kind.Bitflip, Dir.C2S, 1));
        var c = B(10, 20, 30, 40);
        r.Send(B(0), c, B(50, 60));
        SameSeen(new() { L(0), L(10, 20, 31, 40), L(50, 60) }, r.Dst);
        Assert.Equal(B(10, 20, 30, 40), c);
        var odd = new Rig(new WireFault(Kind.Bitflip, Dir.C2S, 0));
        odd.Send(B(4, 4, 4, 4, 4));
        SameSeen(new() { L(4, 4, 5, 4, 4) }, odd.Dst);
    }

    [Fact] public void DuplicateWritesTheStraddlingChunkTwiceOnce()
    {
        var r = new Rig(new WireFault(Kind.Duplicate, Dir.C2S, 1));
        r.Send(B(0), B(1, 2), B(3));
        SameSeen(new() { L(0), L(1, 2), L(1, 2), L(3) }, r.Dst);
    }

    [Fact] public void ReorderSwapsOnceThenPassesInOrderAndFlushesAHeldChunkOnEnd()
    {
        var a = new Rig(new WireFault(Kind.Reorder, Dir.C2S, 1));
        a.Send(B(0), B(1, 2), B(3, 4), B(5), B(6));
        SameSeen(new() { L(0), L(3, 4), L(1, 2), L(5), L(6) }, a.Dst);
        var b = new Rig(new WireFault(Kind.Reorder, Dir.C2S, 1));
        b.Send(B(0), B(1, 2));
        SameSeen(new() { L(0) }, b.Dst);
        b.Pipe.End();
        SameSeen(new() { L(0), L(1, 2) }, b.Dst);
        Assert.Equal(1, b.Dst.Ended);
    }

    // ------------------------------------------------------------------------- real sockets (plain TCP: the proxy sees only bytes)

    static byte[] ReadN(NetworkStream s, int n)
    {
        var b = new byte[n];
        int got = 0;
        while (got < n)
        {
            int r = s.Read(b, got, n - got);
            if (r <= 0) break;
            got += r;
        }
        Assert.Equal(n, got);
        return b;
    }

    [Fact] public void KindNoneRelaysBothDirections()
    {
        var target = new TcpListener(IPAddress.Loopback, 0);
        target.Start(1);
        var p = new FaultProxy(0, "127.0.0.1", ((IPEndPoint)target.LocalEndpoint).Port, new WireFault(Kind.None, Dir.C2S, 0));
        p.Listen();
        try
        {
            using var c = new TcpClient("127.0.0.1", p.Port());
            using var s = target.AcceptTcpClient();
            c.ReceiveTimeout = 10_000;
            s.ReceiveTimeout = 10_000;
            var cs = c.GetStream();
            var ss = s.GetStream();
            cs.Write(B(1, 2, 3));
            Assert.Equal(B(1, 2, 3), ReadN(ss, 3));
            ss.Write(B(9, 8));
            Assert.Equal(B(9, 8), ReadN(cs, 2));
        }
        finally { p.Close(); target.Stop(); }
    }

    [Fact] public void ADropFaultAfterTheFirstBytesBlackHolesTheRestAndLogsIt()
    {
        var target = new TcpListener(IPAddress.Loopback, 0);
        target.Start(1);
        var p = new FaultProxy(0, "127.0.0.1", ((IPEndPoint)target.LocalEndpoint).Port, new WireFault(Kind.Drop, Dir.C2S, 2));
        p.Listen();
        try
        {
            using var c = new TcpClient("127.0.0.1", p.Port());
            using var s = target.AcceptTcpClient();
            s.ReceiveTimeout = 500;
            var ss = s.GetStream();
            c.GetStream().Write(B(1, 2));
            Assert.Equal(B(1, 2), ReadN(ss, 2));
            c.GetStream().Write(B(3, 4));
            Assert.Throws<IOException>(() => ss.ReadByte());
            for (int i = 0; i < 100 && p.LogSnapshot().Count == 0; i++) Thread.Sleep(20);
            Assert.Equal(new[] { "fault drop c2s after 2B" }, p.LogSnapshot());
        }
        finally { p.Close(); target.Stop(); }
    }

    [Fact] public void ListenFailsWhenThePortIsTakenAndCloseStopsAccepting()
    {
        var p = new FaultProxy(0, "127.0.0.1", 1, new WireFault(Kind.None, Dir.C2S, 0));
        p.Listen();
        int port = p.Port();
        Assert.ThrowsAny<SocketException>(() => new FaultProxy(port, "127.0.0.1", 1, new WireFault(Kind.None, Dir.C2S, 0)).Listen());
        p.Close();
        Assert.ThrowsAny<SocketException>(() => new TcpClient("127.0.0.1", port).Close());
    }

    [Fact] public void AnUpstreamThatRefusesClosesTheClientSide()
    {
        // an upstream port nobody listens on, held for the whole test: a socket bound but never put to listening refuses every connection and keeps the port ours
        using var held = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        held.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        var p = new FaultProxy(0, "127.0.0.1", ((IPEndPoint)held.LocalEndPoint!).Port, new WireFault(Kind.None, Dir.C2S, 0));
        p.Listen();
        try
        {
            using var c = new TcpClient("127.0.0.1", p.Port());
            c.ReceiveTimeout = 10_000;
            int r;
            try { r = c.GetStream().ReadByte(); } catch (IOException) { r = -1; }
            Assert.Equal(-1, r);
        }
        finally { p.Close(); }
    }

    // ------------------------------------------------------------------------- the frame tamperer

    static NetWire.Frame Fr(long seq, string rd) => new(new Num("2"), "msg", "sess", new Num(seq.ToString()), rd, new D { ["a"] = new Num("1") });

    static Mesh.TamperEvent Ev(int to, long seq, string rd) { var f = Fr(seq, rd); return new Mesh.TamperEvent(to, f, NetWire.EncodeFrame(f)); }

    static D Parse(byte[] raw)
    {
        var sp = new NetWire.FrameSplitter();
        var bodies = sp.Push(raw);
        Assert.Single(bodies);
        return NetWire.ParseFrame(bodies[0]) ?? throw new Xunit.Sdk.XunitException("frame does not parse");
    }

    static readonly string[] AllKinds = { "duplicate", "reorder", "skip-seq", "garbage", "truncate", "bitflip", "wrong-round", "wrong-session", "oversize", "drop", "silent-from", "extra-field", "false-accuse" };

    [Fact] public void TamperPassesOtherRoundsAndRecipientsUntouched()
    {
        foreach (var k in AllKinds)
        {
            var ev = Ev(1, 5, "other");
            var o = FrameFaults.TamperFor(new FrameFaults.FrameFault(k, "mul0"))(ev);
            Assert.Single(o);
            Assert.Equal(ev.Raw, o[0]);
            var ev2 = Ev(1, 5, "mul0");
            var o2 = FrameFaults.TamperFor(new FrameFaults.FrameFault(k, "mul0", To: 2))(ev2);
            Assert.Single(o2);
            Assert.Equal(ev2.Raw, o2[0]);
        }
        Assert.Empty(FrameFaults.TamperFor(new FrameFaults.FrameFault("drop", "mul0", To: 0))(Ev(0, 1, "mul0")));
    }

    [Fact] public void TamperKinds()
    {
        var ev = Ev(1, 5, "mul0");
        List<byte[]> T(string k) => FrameFaults.TamperFor(new FrameFaults.FrameFault(k, "mul0", Accuse: 2))(ev);
        Assert.Equal(new[] { ev.Raw, ev.Raw }, T("duplicate"));
        Assert.Equal("6", ((Num)Parse(T("skip-seq")[0])["seq"]!).Raw);
        var g = T("garbage")[0];
        Assert.Equal(ev.Raw.Length, g.Length);
        Assert.Equal(0x5a, g[4]);
        Assert.Equal(ev.Raw.Length - 4, (g[0] << 24) | (g[1] << 16) | (g[2] << 8) | g[3]);
        Assert.Equal(Math.Max(5, ev.Raw.Length / 2), T("truncate")[0].Length);
        var bf = T("bitflip")[0];
        Assert.Equal(ev.Raw.Length, bf.Length);
        Assert.Equal(1, bf.Zip(ev.Raw, (x, y) => x != y).Count(d => d));
        Assert.Equal("zzz-mul0", Parse(T("wrong-round")[0])["rd"]);
        Assert.Equal("not-this-session", Parse(T("wrong-session")[0])["sid"]);
        Assert.Equal(new byte[] { 0x7f, 0xff, 0xff, 0xff }, T("oversize")[0]);
        Assert.Empty(T("drop"));
        var acc = FrameFaults.TamperFor(new FrameFaults.FrameFault("false-accuse", "mul0", Accuse: 2))(ev);
        var ab = Parse(acc[0]);
        Assert.Equal("abort", ab["ty"]);
        Assert.Equal("timeout", ((D)ab["d"]!)["kind"]);
        // an extra field makes the envelope malformed: the receiver's strict parse refuses it
        Assert.Null(NetWire.ParseFrame(new NetWire.FrameSplitter().Push(T("extra-field")[0])[0]));
    }

    [Fact] public void TamperSilenceIsStickyAndReorderHoldsPerRecipient()
    {
        var s = FrameFaults.TamperFor(new FrameFaults.FrameFault("silent-from", "mul0"));
        Assert.Empty(s(Ev(1, 1, "mul0")));
        Assert.Empty(s(Ev(1, 2, "other"))); // silent from then on, every round
        var r = FrameFaults.TamperFor(new FrameFaults.FrameFault("reorder", "mul0"));
        var a = Ev(1, 1, "mul0");
        var b = Ev(1, 2, "mul0");
        var c = Ev(2, 1, "mul0");
        Assert.Empty(r(a)); // held for recipient 1
        Assert.Empty(r(c)); // held for recipient 2: per recipient
        var out1 = r(b);
        Assert.Equal(new[] { b.Raw, a.Raw }, out1);
    }

    // ------------------------------------------------------------------------- through the launcher

    [TlsFact] public void ABitflipOnTheWireIsAttributedToTheLinkNeverAValue()
    {
        var o = new LaunchLocal.Options
        {
            N = 3,
            Q = 4,
            Vectors = new() { new(1, 1, 1), new(1, 2, 3), new(1, 1, 2) },
            RecvTimeoutMs = 30_000,
            KillAfterMs = 120_000,
            WireFault = new LaunchLocal.WireFaultSpec(2, 0, new WireFault(Kind.Bitflip, Dir.C2S, 6000)),
        };
        var l = LaunchLocal.Launch(o);
        foreach (var node in l.Outputs)
        {
            Assert.Null(node.Result); // a tampered link yields no output
            Assert.NotNull(node.Error); // every node stops with an abort
        }
        Assert.Contains(l.Outputs, x => x.Abort() != null); // some node names the failure
    }
}

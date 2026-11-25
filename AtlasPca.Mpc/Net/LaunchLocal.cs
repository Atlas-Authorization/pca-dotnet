using System.Net;
using System.Net.Sockets;
using System.Numerics;
using System.Diagnostics;
using System.Security.Cryptography;

namespace AtlasPca.Mpc.Net;

/// <summary>
/// Launches n parties (and, for the trusted-dealer mode, a dealer node) in this process on loopback, each with its own fresh
/// per-run identity, its own mutual-TLS mesh and its own thread, and collects what every node ended with. The nodes talk only
/// over TLS sockets, exactly as separate hosts would; a stuck run is cut off after <c>KillAfterMs</c>.
/// </summary>
public static class LaunchLocal
{
    public sealed class Options
    {
        public int N;
        public int? Q;
        public List<Party.DecisionVector>? Vectors;
        public long RecvTimeoutMs = 30_000;
        public long ConnectTimeoutMs = 120_000;
        /// <summary>Hard wall-clock cap for the whole run.</summary>
        public long KillAfterMs = 120_000;
        /// <summary>TEST ONLY: protocol misbehaviour per node id (parties only).</summary>
        public Dictionary<int, Protocol.Behavior> Behaviors = new();
        /// <summary>"no-dealer" (default) or "trusted-dealer" (spawns a dealer node; needs InsecureTrustedDealer).</summary>
        public string Offline = "no-dealer";
        public bool InsecureTrustedDealer;
        public BigInteger? DealerSeed;
        public Spdz.DealerFault? DealerFault;
        public int? MacFaultAtInput;
        /// <summary>Route node Dialer's link to node Target through a byte-level fault proxy (test only).</summary>
        public WireFaultSpec? WireFault;
    }

    /// <summary>What a node ended with: a result (parties only), or the exception that stopped it.</summary>
    public sealed record WireFaultSpec(int Dialer, int Target, FaultProxy.WireFault Fault);

    public sealed record NodeOutput(int Id, string Role, Protocol.PartyResult? Result, Exception? Error)
    {
        public NetWire.NetAbort? Abort() => Error as NetWire.NetAbort;
    }

    public sealed record Launched(List<NodeOutput> Outputs, long WallMs);

    private static string RoleOf(bool dealerMode, int id, int n) => dealerMode && id == n ? "dealer" : "party";

    public static Launched Launch(Options o)
    {
        int n = o.N;
        if (o.Vectors == null || o.Vectors.Count != n) throw new ArgumentException("launchLocal: one decision vector per party");
        bool dealerMode = o.Offline == "trusted-dealer";
        if (dealerMode && !o.InsecureTrustedDealer) throw new ArgumentException("launchLocal: offline 'trusted-dealer' requires insecureTrustedDealer");
        int nodeCount = dealerMode ? n + 1 : n;
        string sessionId = Convert.ToHexString(RandomNumberGenerator.GetBytes(8)).ToLowerInvariant();
        var nodes = new List<Mesh.NodeAddr>();
        var ids = new Certs.Identity[nodeCount];
        for (int i = 0; i < nodeCount; i++)
        {
            ids[i] = Certs.Generate("mpc-node-" + i);
            nodes.Add(new Mesh.NodeAddr(i, "127.0.0.1", 0, ids[i].CertPem)); // port 0: each node binds its own
        }
        FaultProxy? proxy = null;
        var meshes = new Mesh[nodeCount];
        for (int i = 0; i < nodeCount; i++)
        {
            var c = new Mesh.Config
            {
                SelfId = i,
                Nodes = nodes,
                KeyPem = ids[i].KeyPem,
                CertPem = ids[i].CertPem,
                SessionId = sessionId,
                ListenHost = "127.0.0.1",
                RecvTimeoutMs = o.RecvTimeoutMs,
                ConnectTimeoutMs = o.ConnectTimeoutMs,
            };
            if (dealerMode && i == n)
            {
                c.LinkTo = new List<int>();
                for (int j = 0; j < n; j++) c.LinkTo.Add(j);
            }
            meshes[i] = new Mesh(c);
        }
        // every node binds port 0 itself and reports the port it got; only then is anyone told an address (no port is probed and released)
        int[] bound;
        try
        {
            bound = meshes.Select(m => m.Listen()).ToArray();
            int dialerView = -1, proxyPort = 0;
            if (o.WireFault != null)
            {
                proxy = new FaultProxy(0, "127.0.0.1", bound[o.WireFault.Target], o.WireFault.Fault);
                proxy.Listen();
                proxyPort = proxy.Port();
                dialerView = o.WireFault.Dialer;
            }
            for (int i = 0; i < nodeCount; i++)
                for (int j = 0; j < nodeCount; j++)
                    if (i != j) meshes[i].SetPeerPort(j, o.WireFault != null && i == dialerView && j == o.WireFault.Target ? proxyPort : bound[j]);
        }
        catch (Exception)
        {
            foreach (Mesh m in meshes) m.Kill();
            proxy?.Close();
            throw;
        }
        var sw = Stopwatch.StartNew();
        int active = nodeCount, idle = 0;
        var fs = new Task<NodeOutput>[nodeCount];
        for (int i = 0; i < nodeCount; i++)
        {
            int id = i;
            fs[i] = Task.Factory.StartNew(() =>
            {
                try
                {
                    return RunNode(o, id, n, dealerMode, meshes[id], sessionId, () => Volatile.Read(ref active), () => Volatile.Read(ref idle), () => Interlocked.Increment(ref idle));
                }
                finally
                {
                    Interlocked.Decrement(ref active);
                }
            }, CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default);
        }
        var outs = new List<NodeOutput>();
        long deadline = Stopwatch.GetTimestamp() + o.KillAfterMs * Stopwatch.Frequency / 1000L;
        try
        {
            for (int i = 0; i < nodeCount; i++)
            {
                long leftMs = Math.Max(1L, (deadline - Stopwatch.GetTimestamp()) * 1000L / Stopwatch.Frequency);
                if (fs[i].Wait((int)Math.Min(int.MaxValue, leftMs)))
                {
                    outs.Add(fs[i].Result);
                }
                else
                {
                    // a hang is a failure: cut the straggler off and record it
                    foreach (Mesh m in meshes) m.Kill();
                    outs.Add(new NodeOutput(i, RoleOf(dealerMode, i, n), null, new NetWire.NetAbort("local", null, i, "killed after " + o.KillAfterMs + "ms")));
                }
            }
        }
        finally
        {
            foreach (Mesh m in meshes) m.Kill();
            proxy?.Close();
        }
        return new Launched(outs, sw.ElapsedMilliseconds);
    }

    private static NodeOutput RunNode(Options o, int id, int n, bool dealerMode, Mesh mesh, string sessionId, Func<int> active, Func<int> idle, Func<int> goIdle)
    {
        string role = RoleOf(dealerMode, id, n);
        try
        {
            mesh.Connect();
            if (role == "dealer")
            {
                Protocol.RunDealer(new Protocol.DealerConfig
                {
                    InsecureTrustedDealer = o.InsecureTrustedDealer,
                    N = n,
                    Q = o.Q,
                    Mesh = mesh,
                    Seed = o.DealerSeed,
                    Fault = o.DealerFault,
                    MacFaultAtInput = o.MacFaultAtInput,
                });
                return new NodeOutput(id, role, null, null);
            }
            var c = new Protocol.PartyConfig
            {
                Id = id,
                N = n,
                Q = o.Q,
                Input = o.Vectors![id],
                Mesh = mesh,
                Offline = dealerMode ? "trusted-dealer" : "no-dealer",
                InsecureTrustedDealer = o.InsecureTrustedDealer,
                SessionId = sessionId,
            };
            if (o.Behaviors.TryGetValue(id, out Protocol.Behavior? b) && b != null)
            {
                c.Behavior = b;
                c.UnsafeTestHooks = true;
            }
            return new NodeOutput(id, role, Protocol.RunParty(c), null);
        }
        catch (Protocol.CrashParty e)
        {
            mesh.Kill();
            return new NodeOutput(id, role, null, e);
        }
        catch (Protocol.SilentParty e)
        {
            // stays connected and stops participating; peers must time out. Idle until every other node has finished.
            goIdle();
            while (active() > idle()) Thread.Sleep(50);
            return new NodeOutput(id, role, null, e);
        }
        catch (Exception e)
        {
            NetWire.NetAbort? f = mesh.Failed();
            return new NodeOutput(id, role, null, e is NetWire.NetAbort ? e : (f ?? e));
        }
    }
}

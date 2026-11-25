using System.Numerics;
using AtlasPca.Mpc;
using AtlasPca.Mpc.Net;
using Xunit;
using static AtlasPca.Mpc.Tests.MpcNetSupport;

namespace AtlasPca.Mpc.Tests;

using Mesh = AtlasPca.Mpc.Net.Mesh;

/// <summary>The networked SPDZ-style protocol over loopback mutual TLS, trusted-dealer mode: agreement with the in-process engine, and refusals of a lying dealer and lying parties.</summary>
[Collection("MpcNet")]
public class MpcProtocolTests
{
    private const int Q = 4;

    /// <summary>n parties (ids 0..n-1) plus a dealer node (id n), every mesh connected.</summary>
    internal static Mesh[] Cluster(int n, long recvMs)
    {
        int total = n + 1;
        var ids = new Certs.Identity[total];
        var nodes = new List<Mesh.NodeAddr>();
        for (int i = 0; i < total; i++)
        {
            ids[i] = SeedIdentity("p" + i);
            nodes.Add(new Mesh.NodeAddr(i, "127.0.0.1", 0, ids[i].CertPem)); // port 0: each node binds its own
        }
        var meshes = new Mesh[total];
        var conn = new Task[total];
        for (int i = 0; i < total; i++) meshes[i] = new Mesh(Cfg(i, nodes, ids[i], 30_000, recvMs));
        BindAll(meshes);
        for (int i = 0; i < total; i++)
        {
            Mesh m = meshes[i];
            conn[i] = Run(() => m.Connect());
        }
        Assert.True(Task.WaitAll(conn, 60_000));
        return meshes;
    }

    /// <summary>What a node ended with: a result, or the exception that stopped it.</summary>
    internal sealed record Outcome(Protocol.PartyResult? Result, Exception? Error)
    {
        public NetWire.NetAbort? Abort() => Error as NetWire.NetAbort;
    }

    internal static List<Outcome> RunAll(Mesh[] meshes, List<Party.DecisionVector> input, Protocol.DealerConfig dealerCfg, Protocol.Behavior?[]? behaviors)
    {
        int n = input.Count;
        var fs = new List<Task<Outcome>>();
        fs.Add(Run(() =>
        {
            try
            {
                dealerCfg.Mesh = meshes[n];
                Protocol.RunDealer(dealerCfg);
                return new Outcome(null, null);
            }
            catch (Exception t)
            {
                return new Outcome(null, t);
            }
        }));
        for (int i = 0; i < n; i++)
        {
            int me = i;
            fs.Add(Run(() =>
            {
                try
                {
                    var c = new Protocol.PartyConfig
                    {
                        Id = me,
                        N = n,
                        Q = Q,
                        Input = input[me],
                        Mesh = meshes[me],
                        Offline = "trusted-dealer",
                        InsecureTrustedDealer = true,
                        SessionId = meshes[me].SessionId(),
                    };
                    if (behaviors != null && behaviors[me] != null)
                    {
                        c.Behavior = behaviors[me];
                        c.UnsafeTestHooks = true;
                    }
                    return new Outcome(Protocol.RunParty(c), null);
                }
                catch (Exception t)
                {
                    return new Outcome(null, t);
                }
            }));
        }
        Assert.True(Task.WaitAll(fs.ToArray(), 120_000));
        return fs.Skip(1).Select(f => f.Result).ToList(); // the parties; the dealer's own outcome is not asserted
    }

    internal static Protocol.DealerConfig Dealer(int n) => new()
    {
        InsecureTrustedDealer = true,
        N = n,
        Q = Q,
        Seed = new BigInteger(7),
    };

    internal static readonly List<Party.DecisionVector> Inputs = new()
    {
        new Party.DecisionVector(1, 1, 1), new Party.DecisionVector(1, 2, 3), new Party.DecisionVector(1, 1, 2),
    };

    [TlsFact]
    public void DealerModeAgreesWithTheInProcessEngine()
    {
        var outs = RunAll(Cluster(3, 60_000), Inputs, Dealer(3), null);
        var clear = Compose.ComposeClear(Inputs.Cast<Party.DecisionVector?>().ToList(), Q);
        var rc = new SpdzRunner.MaliciousMpcConfig { Q = Q, Seed = BigInteger.One, InsecureTrustedDealer = true };
        var engine = SpdzRunner.ComposeSecureMalicious(Inputs.Cast<Party.DecisionVector?>().ToList(), rc).Composed;
        Assert.Equal(clear, engine);
        string? digest = null;
        foreach (Outcome o in outs)
        {
            Assert.True(o.Error == null, o.Error?.ToString());
            Assert.Equal(clear, o.Result!.Composed);
            Assert.Equal("trusted-dealer", o.Result.OfflineMode);
            Assert.True(o.Result.IdentifiableAbort);
            digest ??= o.Result.TranscriptDigest;
            Assert.Equal(digest, o.Result.TranscriptDigest);
        }
    }

    [TlsFact]
    public void AWrongProductFromTheDealerIsDetectedAndBlamed()
    {
        Protocol.DealerConfig d = Dealer(3);
        d.Fault = new Spdz.DealerFault(BigInteger.One, null);
        var outs = RunAll(Cluster(3, 30_000), Inputs, d, null);
        bool named = false;
        foreach (Outcome o in outs)
        {
            Assert.Null(o.Result);
            NetWire.NetAbort? a = o.Abort();
            Assert.True(a != null, o.Error?.ToString());
            if (a!.Kind == "dealer" && a.Blamed == 3) named = true;
        }
        Assert.True(named, "an honest party names the dealer");
    }

    [TlsFact]
    public void ALyingOpenedShareIsNamedByItsPairwiseTag()
    {
        var b = new Protocol.Behavior?[3];
        b[1] = new Protocol.Behavior("open-lie", "mul0");
        var outs = RunAll(Cluster(3, 30_000), Inputs, Dealer(3), b);
        bool named = false;
        foreach (Outcome o in outs)
        {
            Assert.Null(o.Result);
            NetWire.NetAbort? a = o.Abort();
            if (a != null && a.Kind == "mac-check" && a.Blamed == 1) named = true;
        }
        Assert.True(named, "an honest verifier names party 1");
    }

    [TlsFact]
    public void ANonCanonicalFieldElementIsRefused()
    {
        var b = new Protocol.Behavior?[3];
        b[2] = new Protocol.Behavior("noncanonical", "mul0");
        var outs = RunAll(Cluster(3, 30_000), Inputs, Dealer(3), b);
        bool named = false;
        foreach (Outcome o in outs)
        {
            Assert.Null(o.Result);
            NetWire.NetAbort? a = o.Abort();
            if (a != null && a.Kind == "malformed" && a.Blamed == 2) named = true;
        }
        Assert.True(named, "an honest party names party 2");
    }

    /// <summary>Runs dealer mode with <paramref name="culprit"/> misbehaving; no honest party may finish, and at least one names the culprit with one of <paramref name="kinds"/>.</summary>
    private static void AssertNamed(string kind, string? round, int culprit, string[] kinds, long recvMs = 30_000)
    {
        var b = new Protocol.Behavior?[3];
        b[culprit] = new Protocol.Behavior(kind, round);
        var outs = RunAll(Cluster(3, recvMs), Inputs, Dealer(3), b);
        bool named = false;
        for (int i = 0; i < outs.Count; i++)
        {
            if (i == culprit) continue;
            Assert.Null(outs[i].Result);
            NetWire.NetAbort? a = outs[i].Abort();
            Assert.True(a != null, outs[i].Error?.ToString());
            if (kinds.Contains(a!.Kind) && a.Blamed == culprit) named = true;
        }
        Assert.True(named, kind + ": an honest party names party " + culprit);
    }

    [TlsFact]
    public void ABadPairwiseTagIsNamed() => AssertNamed("bad-tag", "mul0", 1, new[] { "mac-check" });

    [TlsFact]
    public void AForgedMacShareIsCaughtByTheMacCheck() => AssertNamed("mac-lie", "mul1", 1, new[] { "mac-check" });

    [TlsFact]
    public void AWrongLengthArrayIsMalformed() => AssertNamed("short-array", "mul0", 1, new[] { "malformed" });

    [TlsFact]
    public void ACoinSeedThatDoesNotMatchItsCommitmentIsNamed() => AssertNamed("bad-coin-open", null, 1, new[] { "commitment" });

    [TlsFact]
    public void AMacResidualThatDoesNotMatchItsCommitmentIsNamed() => AssertNamed("bad-sigma-open", null, 1, new[] { "commitment" });

    [TlsFact]
    public void ALyingMacResidualIsNamedByTheBlameRound() => AssertNamed("sigma-lie", null, 2, new[] { "mac-check" });

    [TlsFact]
    public void ACrashedPartyIsNamedAsDisconnectedOrTimedOut() => AssertNamed("crash", "mul1", 1, new[] { "disconnect", "timeout" }, 5_000);

    [TlsFact]
    public void ASilentPartyIsNamedByTheTimeout() => AssertNamed("silent", "mul1", 1, new[] { "timeout", "disconnect" }, 5_000);

    [TlsFact]
    public void EquivocationNeverYieldsAnOutput()
    {
        var b = new Protocol.Behavior?[3];
        b[1] = new Protocol.Behavior("equivocate", "mul0");
        var outs = RunAll(Cluster(3, 30_000), Inputs, Dealer(3), b);
        foreach (Outcome o in outs) Assert.Null(o.Result);
    }

    [TlsFact]
    public void TestHooksAndDealerOptInAreEnforcedBeforeAnyTraffic()
    {
        var c = new Protocol.PartyConfig { Id = 0, N = 3, Q = Q, Input = Inputs[0], SessionId = "s", Offline = "trusted-dealer" };
        var a = Assert.Throws<NetWire.NetAbort>(() => Protocol.RunParty(c));
        Assert.Equal("local", a.Kind);
        c.InsecureTrustedDealer = true;
        c.Behavior = new Protocol.Behavior("open-lie", "out");
        Assert.Equal("local", Assert.Throws<NetWire.NetAbort>(() => Protocol.RunParty(c)).Kind);
        var d = new Protocol.DealerConfig { N = 3 };
        Assert.ThrowsAny<ArgumentException>(() => Protocol.RunDealer(d));
    }
}

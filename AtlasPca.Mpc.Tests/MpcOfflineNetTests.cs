using System.Numerics;
using AtlasPca.Mpc;
using AtlasPca.Mpc.Net;
using Xunit;
using static AtlasPca.Mpc.Tests.MpcNetSupport;

namespace AtlasPca.Mpc.Tests;

using Mesh = AtlasPca.Mpc.Net.Mesh;

/// <summary>The no-dealer (OT-based) offline phase and the in-process launcher over loopback mutual TLS, with refusals of lying parties.</summary>
[Collection("MpcNet")]
public class MpcOfflineNetTests
{
    private const int Q = 4;
    private static readonly List<Party.DecisionVector> Inputs = new()
    {
        new Party.DecisionVector(1, 1, 1), new Party.DecisionVector(1, 2, 3), new Party.DecisionVector(1, 1, 2),
    };

    private static LaunchLocal.Options Opts(Dictionary<int, Protocol.Behavior>? beh = null) => new()
    {
        N = 3,
        Q = Q,
        Vectors = Inputs,
        RecvTimeoutMs = 60_000,
        KillAfterMs = 240_000,
        Behaviors = beh ?? new Dictionary<int, Protocol.Behavior>(),
    };

    private static List<Party.DecisionVector?> AsNullable(List<Party.DecisionVector> v) => v.Cast<Party.DecisionVector?>().ToList();

    [TlsFact]
    public void NoDealerAgreesWithTheInProcessEngine()
    {
        LaunchLocal.Launched l = LaunchLocal.Launch(Opts());
        var clear = Compose.ComposeClear(AsNullable(Inputs), Q);
        var rc = new SpdzRunner.MaliciousMpcConfig { Q = Q, Seed = BigInteger.One };
        Assert.Equal(clear, SpdzRunner.ComposeSecureMalicious(AsNullable(Inputs), rc).Composed);
        string? digest = null;
        Assert.Equal(3, l.Outputs.Count);
        foreach (LaunchLocal.NodeOutput o in l.Outputs)
        {
            Assert.True(o.Error == null, o.Error?.ToString());
            Assert.Equal(clear, o.Result!.Composed);
            Assert.Equal("no-dealer", o.Result.OfflineMode);
            Assert.True(o.Result.IdentifiableAbort);
            digest ??= o.Result.TranscriptDigest;
            Assert.Equal(digest, o.Result.TranscriptDigest);
        }
    }

    [TlsFact]
    public void TrustedDealerThroughTheLauncher()
    {
        LaunchLocal.Options o = Opts();
        o.Offline = "trusted-dealer";
        o.InsecureTrustedDealer = true;
        o.DealerSeed = new BigInteger(11);
        LaunchLocal.Launched l = LaunchLocal.Launch(o);
        Assert.Equal(4, l.Outputs.Count);
        var clear = Compose.ComposeClear(AsNullable(Inputs), Q);
        foreach (LaunchLocal.NodeOutput output in l.Outputs)
        {
            if (output.Role == "party")
            {
                Assert.True(output.Error == null, output.Error?.ToString());
                Assert.Equal(clear, output.Result!.Composed);
            }
        }
    }

    [TlsFact]
    public void TheDealerOptInIsRequired()
    {
        LaunchLocal.Options o = Opts();
        o.Offline = "trusted-dealer";
        Assert.ThrowsAny<ArgumentException>(() => LaunchLocal.Launch(o));
    }

    private static NetWire.NetAbort AssertNobodySucceedsAndSomeoneNames(LaunchLocal.Launched l, string kind, int blamed)
    {
        NetWire.NetAbort? named = null;
        foreach (LaunchLocal.NodeOutput o in l.Outputs)
        {
            Assert.Null(o.Result);
            NetWire.NetAbort? a = o.Abort();
            if (a != null && a.Kind == kind && a.Blamed == blamed) named = a;
        }
        Assert.True(named != null, "an honest party names party " + blamed + " with kind " + kind);
        return named!;
    }

    [TlsFact]
    public void AWrongOtOperandInATripleProductIsCaughtByTheSacrificeAndAttributed()
    {
        var l = LaunchLocal.Launch(Opts(new() { [1] = new Protocol.Behavior("offline-lie", null) }));
        AssertNobodySucceedsAndSomeoneNames(l, "mac-check", 1);
    }

    [TlsFact]
    public void AnInconsistentOtExtensionMatrixIsCaughtByTheKosCheck()
    {
        var l = LaunchLocal.Launch(Opts(new() { [2] = new Protocol.Behavior("ot-u-lie", null) }));
        AssertNobodySucceedsAndSomeoneNames(l, "ot-check", 2);
    }

    [TlsFact]
    public void ABadBaseOtProofIsRefused()
    {
        var l = LaunchLocal.Launch(Opts(new() { [1] = new Protocol.Behavior("ot-proof-lie", null) }));
        AssertNobodySucceedsAndSomeoneNames(l, "ot-check", 1);
    }

    [TlsFact]
    public void ASilentPartyIsBlamedByTimeout()
    {
        LaunchLocal.Options o = Opts(new() { [2] = new Protocol.Behavior("silent", "in-share") });
        o.RecvTimeoutMs = 15_000;
        o.KillAfterMs = 120_000;
        LaunchLocal.Launched l = LaunchLocal.Launch(o);
        bool named = false;
        foreach (LaunchLocal.NodeOutput output in l.Outputs)
        {
            Assert.Null(output.Result);
            NetWire.NetAbort? a = output.Abort();
            if (a != null && a.Kind == "timeout" && a.Blamed == 2) named = true;
        }
        Assert.True(named);
    }

    [TlsFact]
    public void ANodeRefusesToStartWithTestHooksOutsideATestEnvironment()
    {
        // only meaningful when the environment does not enable the hooks
        if (Environment.GetEnvironmentVariable("PCA_MPC_UNSAFE_TEST_HOOKS") != null) return;
        string f = Path.GetTempFileName();
        try
        {
            File.WriteAllText(f, "{\"role\":\"party\",\"id\":0,\"unsafeTestHooks\":true,\"behavior\":{\"kind\":\"crash\",\"round\":\"out\"}}");
            Assert.Equal(3, PartyMain.Run(new[] { f }, new StringWriter()));
            File.WriteAllText(f, "{\"role\":\"party\",\"id\":0,\"unsafeTestHooks\":true,\"frameFault\":{}}");
            Assert.Equal(3, PartyMain.Run(new[] { f }, new StringWriter()));
        }
        finally
        {
            File.Delete(f);
        }
    }

    [TlsFact]
    public void PairwiseBaseOtMatchesOverTheNetwork()
    {
        var i0 = SeedIdentity("ot0");
        var i1 = SeedIdentity("ot1");
        var nodes = new List<Mesh.NodeAddr> { new(0, "127.0.0.1", 0, i0.CertPem), new(1, "127.0.0.1", 0, i1.CertPem) }; // port 0: each node binds its own
        var m0 = new Mesh(Cfg(0, nodes, i0, 30_000, 30_000));
        var m1 = new Mesh(Cfg(1, nodes, i1, 30_000, 30_000));
        BindAll(new[] { m0, m1 });
        Task<OtNet.Result> s = Run(() => { m0.Connect(); return OtNet.RunOtSender(m0, 1, 32); });
        Task<OtNet.Result> r = Run(() => { m1.Connect(); return OtNet.RunOtReceiver(m1, 0, 32); });
        Assert.True(Task.WaitAll(new Task[] { s, r }, 60_000));
        Assert.True(s.Result.Matched);
        Assert.True(r.Result.Matched);
    }
}

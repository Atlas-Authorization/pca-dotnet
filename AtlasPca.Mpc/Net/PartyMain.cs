using System.Globalization;
using System.Numerics;
using System.Text;
using JD = System.Collections.Generic.Dictionary<string, object?>;

namespace AtlasPca.Mpc.Net;

/// <summary>
/// One MPC node (a party, the dealer, or one end of a base-OT demo) as its OWN OS process, talking to the others only over the
/// mutual-TLS mesh. Usage: <c>Run(["config.json"])</c> or <c>Run(["keygen", dir, cn])</c>. Writes exactly one JSON line
/// (the result or the attributable abort) to the output; exit code 3 on an abort. Test hooks need both <c>unsafeTestHooks</c> in the
/// config and the environment variable <c>PCA_MPC_UNSAFE_TEST_HOOKS=1</c>, else the node refuses to start.
/// </summary>
public static class PartyMain
{
    private static JD Obj(object? o) => o as JD ?? throw new ArgumentException("config: object expected");

    private static int Num(object? o, string what)
    {
        if (o is not AtlasPca.Num n || !double.TryParse(n.Raw, NumberStyles.Float, CultureInfo.InvariantCulture, out double d)) throw new ArgumentException("config: " + what + " must be a number");
        if (d != Math.Round(d) || Math.Abs(d) > 1e9) throw new ArgumentException("config: " + what + " must be an integer");
        return (int)d;
    }

    private static string Str(object? o, string what) => o as string ?? throw new ArgumentException("config: " + what + " must be a string");

    private static BigInteger Big(object? o, string what) =>
        BigInteger.TryParse(Str(o, what), NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out BigInteger v) ? v : throw new ArgumentException("config: " + what + " must be a decimal integer");

    /// <summary>The endemic-LWE base OT lives in the separate AtlasPca.MpcLweOt assembly (it depends on this one); absent assembly or liblweot = refuse, never run as ec.</summary>
    private static OtNet.Result RunLwe(bool sender, Mesh mesh, int peer, int count, int id)
    {
        System.Reflection.MethodInfo? m = null;
        try { m = Type.GetType("AtlasPca.Mpc.LweOt.EndemicOtNet, AtlasPca.MpcLweOt")?.GetMethod(sender ? "RunOtSender" : "RunOtReceiver"); }
        catch (Exception e) when (e is IOException or BadImageFormatException or TypeLoadException) { }
        if (m == null) throw new NetWire.NetAbort("local", null, id, "ot kind 'lwe' is not available in this build (lwe-ot adapter not loaded)");
        try { return (OtNet.Result)m.Invoke(null, new object[] { mesh, peer, count })!; }
        catch (System.Reflection.TargetInvocationException e) when (e.InnerException != null)
        {
            System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(e.InnerException).Throw();
            throw;
        }
    }

    private static void Out(TextWriter w, JD m) => w.WriteLine(NetWire.Stringify(m));

    private static JD ResultJson(Protocol.PartyResult r) => new()
    {
        ["id"] = r.Id,
        ["n"] = r.N,
        ["Q"] = r.Q,
        ["composed"] = new JD { ["allow"] = r.Composed.Allow, ["t"] = r.Composed.T, ["rQuant"] = r.Composed.RQuant },
        ["transcriptDigest"] = r.TranscriptDigest,
        ["multiplications"] = r.Multiplications,
        ["opens"] = r.Opens,
        ["offlineMode"] = r.OfflineMode,
        ["macKeys"] = r.MacKeys,
        ["sacrificedTriples"] = r.SacrificedTriples,
        ["sacrificePartners"] = r.SacrificePartners,
        ["identifiableAbort"] = r.IdentifiableAbort,
    };

    private static List<object?> Links(Mesh mesh)
    {
        var l = new List<object?>();
        foreach (Mesh.LinkStats s in mesh.Stats())
            l.Add(new JD { ["peer"] = s.Peer, ["appBytesOut"] = s.AppBytesOut, ["appBytesIn"] = s.AppBytesIn, ["framesOut"] = s.FramesOut, ["framesIn"] = s.FramesIn });
        return l;
    }

    private static JD AbortJson(string role, int id, NetWire.NetAbort e) => new()
    {
        ["ok"] = false,
        ["role"] = role,
        ["id"] = id,
        ["error"] = new JD
        {
            ["kind"] = e.Kind,
            ["blamed"] = (object?)e.Blamed,
            ["reporter"] = e.Reporter,
            ["claimedKind"] = e.ClaimedKind,
            ["claimedBlame"] = (object?)e.ClaimedBlame,
            ["reason"] = e.Reason,
            ["evidence"] = e.Evidence,
            ["deadlineMs"] = (object?)e.DeadlineMs,
            ["message"] = e.Message,
        },
    };

    public static int Run(string[] argv) => Run(argv, Console.Out);

    /// <summary>Runs the node, writing its single JSON line to <paramref name="stdout"/>, and returns the process exit code (0 ok, 3 abort or refusal).</summary>
    public static int Run(string[] argv, TextWriter stdout)
    {
        if (argv.Length >= 3 && argv[0] == "keygen")
        {
            Certs.Identity ident = Certs.Generate(argv[2]);
            string dir = Directory.CreateDirectory(argv[1]).FullName;
            string keyPath = Path.Combine(dir, "key.pem");
            string certPath = Path.Combine(dir, "cert.pem");
            AtlasPca.OwnerOnly.WriteAllBytes(keyPath, new UTF8Encoding(false).GetBytes(ident.KeyPem + "\n"));
            File.WriteAllText(certPath, ident.CertPem + "\n", new UTF8Encoding(false));
            Out(stdout, new JD { ["keyPath"] = keyPath, ["certPath"] = certPath });
            return 0;
        }
        if (argv.Length != 1) throw new ArgumentException("usage: PartyMain <config.json> | keygen <dir> <cn>");
        JD cfg = Obj(Pca.ParseJson(File.ReadAllText(argv[0], Encoding.UTF8)));
        string role = Str(cfg.GetValueOrDefault("role"), "role");
        int id = Num(cfg.GetValueOrDefault("id"), "id");
        bool hooksRequested = cfg.ContainsKey("behavior") || cfg.ContainsKey("frameFault") || cfg.ContainsKey("dealerFault");
        if (hooksRequested && !(cfg.GetValueOrDefault("unsafeTestHooks") is true && Environment.GetEnvironmentVariable("PCA_MPC_UNSAFE_TEST_HOOKS") == "1"))
        {
            Out(stdout, AbortJson(role, id, new NetWire.NetAbort("local", null, id, "refusing to start: test hooks are not enabled in this environment")));
            return 3;
        }
        int n = Num(cfg.GetValueOrDefault("n"), "n");
        var nodes = new List<Mesh.NodeAddr>();
        if (cfg.GetValueOrDefault("nodes") is not List<object?> nodeList) throw new ArgumentException("config: nodes must be an array");
        foreach (object? o in nodeList)
        {
            JD x = Obj(o);
            nodes.Add(new Mesh.NodeAddr(Num(x.GetValueOrDefault("id"), "node id"), Str(x.GetValueOrDefault("host"), "host"), Num(x.GetValueOrDefault("port"), "port"),
                File.ReadAllText(Str(x.GetValueOrDefault("certPath"), "certPath"), Encoding.UTF8)));
        }
        var mc = new Mesh.Config { SelfId = id, Nodes = nodes };
        if (role == "dealer")
        {
            mc.LinkTo = new List<int>();
            foreach (Mesh.NodeAddr x in nodes) if (x.Id < n) mc.LinkTo.Add(x.Id);
        }
        mc.KeyPem = File.ReadAllText(Str(cfg.GetValueOrDefault("keyPath"), "keyPath"), Encoding.UTF8);
        mc.CertPem = File.ReadAllText(Str(cfg.GetValueOrDefault("certPath"), "certPath"), Encoding.UTF8);
        mc.SessionId = Str(cfg.GetValueOrDefault("sessionId"), "sessionId");
        if (cfg.GetValueOrDefault("listenHost") != null) mc.ListenHost = Str(cfg["listenHost"], "listenHost");
        if (cfg.GetValueOrDefault("recvTimeoutMs") != null) mc.RecvTimeoutMs = Num(cfg["recvTimeoutMs"], "recvTimeoutMs");
        if (cfg.GetValueOrDefault("connectTimeoutMs") != null) mc.ConnectTimeoutMs = Num(cfg["connectTimeoutMs"], "connectTimeoutMs");
        if (cfg.GetValueOrDefault("frameFault") != null)
        {
            JD ff = Obj(cfg["frameFault"]);
            mc.Tamper = FrameFaults.TamperFor(new FrameFaults.FrameFault(Str(ff.GetValueOrDefault("kind"), "frameFault.kind"), Str(ff.GetValueOrDefault("round"), "frameFault.round"),
                ff.GetValueOrDefault("to") == null ? null : Num(ff["to"], "frameFault.to"), ff.GetValueOrDefault("accuse") == null ? null : Num(ff["accuse"], "frameFault.accuse")));
        }
        mc.UnsafeTestHooks = hooksRequested;
        var mesh = new Mesh(mc);
        var t0 = System.Diagnostics.Stopwatch.StartNew();
        int? Q = cfg.GetValueOrDefault("Q") == null ? null : Num(cfg["Q"], "Q");
        try
        {
            mesh.Connect();
            var res = new JD { ["ok"] = true, ["role"] = role, ["id"] = id, ["connectMs"] = (int)t0.ElapsedMilliseconds };
            if (role == "dealer")
            {
                var d = new Protocol.DealerConfig
                {
                    N = n,
                    Q = Q,
                    Mesh = mesh,
                    InsecureTrustedDealer = cfg.GetValueOrDefault("insecureTrustedDealer") is true,
                };
                if (cfg.GetValueOrDefault("dealerSeed") != null) d.Seed = Big(cfg["dealerSeed"], "dealerSeed");
                if (cfg.GetValueOrDefault("dealerFault") != null)
                {
                    JD df = Obj(cfg["dealerFault"]);
                    BigInteger? keep = df.GetValueOrDefault("keepCDelta") == null ? null : Big(df["keepCDelta"], "keepCDelta");
                    List<BigInteger?>? partners = null;
                    if (df.GetValueOrDefault("partnerCDelta") != null)
                    {
                        partners = new List<BigInteger?>();
                        if (df["partnerCDelta"] is not List<object?> pl) throw new ArgumentException("config: partnerCDelta must be an array");
                        foreach (object? x in pl) partners.Add(x == null ? null : Big(x, "partnerCDelta"));
                    }
                    d.Fault = new Spdz.DealerFault(keep, partners);
                    if (df.GetValueOrDefault("macFaultAtInput") != null) d.MacFaultAtInput = Num(df["macFaultAtInput"], "macFaultAtInput");
                }
                Protocol.RunDealer(d);
            }
            else if (role == "ot-sender" || role == "ot-receiver")
            {
                JD otc = cfg.GetValueOrDefault("ot") == null ? new JD() : Obj(cfg["ot"]);
                string kind = otc.GetValueOrDefault("kind") == null ? "ec" : Str(otc["kind"], "ot.kind");
                int count = otc.GetValueOrDefault("count") == null ? 128 : Num(otc["count"], "ot.count");
                bool snd = role == "ot-sender";
                OtNet.Result r;
                if (kind == "ec") r = snd ? OtNet.RunOtSender(mesh, 1, count) : OtNet.RunOtReceiver(mesh, 0, count);
                else if (kind == "lwe") r = RunLwe(snd, mesh, snd ? 1 : 0, count, id);
                else throw new NetWire.NetAbort("local", null, id, "ot kind '" + kind + "' is not available in this build");
                res["result"] = new JD { ["kind"] = r.Kind, ["role"] = r.Role, ["count"] = r.Count, ["matched"] = r.Matched, ["padDigest"] = r.PadDigest };
            }
            else
            {
                JD input = Obj(cfg.GetValueOrDefault("input"));
                var c = new Protocol.PartyConfig
                {
                    Id = id,
                    N = n,
                    Q = Q,
                    Input = new Party.DecisionVector(Num(input.GetValueOrDefault("allow"), "allow"), Num(input.GetValueOrDefault("t"), "t"), Num(input.GetValueOrDefault("rQuant"), "rQuant")),
                    Mesh = mesh,
                    InsecureTrustedDealer = cfg.GetValueOrDefault("insecureTrustedDealer") is true,
                };
                if (cfg.GetValueOrDefault("offline") != null) c.Offline = Str(cfg["offline"], "offline");
                if (cfg.GetValueOrDefault("behavior") != null)
                {
                    JD b = Obj(cfg["behavior"]);
                    c.Behavior = new Protocol.Behavior(Str(b.GetValueOrDefault("kind"), "behavior.kind"), b.GetValueOrDefault("round") == null ? null : Str(b["round"], "behavior.round"));
                    c.UnsafeTestHooks = true;
                }
                c.SessionId = mc.SessionId;
                res["result"] = ResultJson(Protocol.RunParty(c));
            }
            res["links"] = Links(mesh);
            res["events"] = mesh.Events().Cast<object?>().ToList();
            Out(stdout, res);
            return 0;
        }
        catch (Protocol.CrashParty)
        {
            mesh.Kill(); // abrupt: no abort frames, no output (the reference exits 7)
            return 7;
        }
        catch (Protocol.SilentParty)
        {
            // stay connected, say nothing: the peers must time out; the launcher's kill ends this process (bounded here so it never hangs)
            Thread.Sleep((int)Math.Min(int.MaxValue, 4 * mc.RecvTimeoutMs));
            return 0;
        }
        catch (Exception e)
        {
            NetWire.NetAbort? f = mesh.Failed();
            NetWire.NetAbort ne = e as NetWire.NetAbort ?? f ?? new NetWire.NetAbort("local", null, id, e.Message);
            JD m = AbortJson(role, id, ne);
            m["links"] = Links(mesh);
            m["events"] = mesh.Events().Cast<object?>().ToList();
            Out(stdout, m);
            return 3;
        }
        finally
        {
            // give sockets a moment to flush abort frames
            Thread.Sleep(300);
            mesh.Kill();
        }
    }
}

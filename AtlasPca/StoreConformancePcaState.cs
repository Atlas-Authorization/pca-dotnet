// The pca-state conformance profile: run your replay store behind the REAL authorize path (Pca.Authorize, the guard's own call) with real signed
// PCActns, and check the replay-state invariant: one action id (grant, leaf holder, counter) goes from unconsumed to consumed at most once, however many
// copies arrive, on however many instances or processes, across crashes after the claim and retries after a timeout.
//
//     var report = StoreConformance.RunPcaState(new PcaStateConformance { Name = "postgres", Open = OpenStore, Shared = true, Durable = true });
//     Assert.True(report.Ok, report.ToString());
//
// Checks: claim-* (the store's claim on its own, as RunStateStore runs them), one-instance (N concurrent copies of one proof to one guard: exactly one
// admitted, every round), instances (the copies spread over K guards on separate handles, built multi-instance: a store only an in-process lock can
// serialise is refused there and fails), processes (the same race across K child processes), crash-after-claim (admitted, then the instance dies before its
// handler runs: the same proof is denied afterwards, the next counter admitted; with a worker the instance is a child process that kills itself right after
// the admission) and retry-after-timeout (the commit lands but its answer is lost: the guard fails closed and the retry is denied; and a retry on another
// instance while the first commit is still in flight: exactly one admitted). A check the store declares it cannot meet is skipped, never passed. The process
// checks need a worker: an executable of yours that calls StoreConformance.PcaStateWorkerMain with a way to open your store.
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using JD = System.Collections.Generic.Dictionary<string, object?>;
using JL = System.Collections.Generic.List<object?>;

namespace AtlasPca;

/// <summary>How to start one worker process: the executable, the arguments that come before the configuration text, and the options its open receives.</summary>
public sealed class PcaStateWorker
{
    public string Executable { get; set; } = "";
    public IReadOnlyList<string> Arguments { get; set; } = Array.Empty<string>();
    public IReadOnlyDictionary<string, string> Options { get; set; } = new Dictionary<string, string>();
}

/// <summary>Configures <see cref="StoreConformance.RunPcaState"/>.</summary>
public sealed class PcaStateConformance
{
    public string Name { get; set; } = "store";
    /// <summary>Returns a NEW handle onto the SAME backend each call (one handle = one verifier instance's connection).</summary>
    public Func<IStateStore>? Open { get; set; }
    /// <summary>Crashes and restarts the backend; it runs between closing the handles and reopening.</summary>
    public Action? Restart { get; set; }
    /// <summary>State survives closing every handle (and <see cref="Restart"/>). False skips the durability and crash checks.</summary>
    public bool Durable { get; set; }
    /// <summary>Several handles can share the backend. False skips the instance and process checks.</summary>
    public bool Shared { get; set; }
    /// <summary>The process checks and the process half of crash-after-claim; without it they are skipped.</summary>
    public PcaStateWorker? Worker { get; set; }
    public int Rounds { get; set; } = 10;
    public int Copies { get; set; } = 16;
    public int Instances { get; set; } = 4;
    public int Processes { get; set; } = 3;
}

public static partial class StoreConformance
{
    const string PcaStateAud = "pca-state-conformance";
    static readonly Operation PcaStateOperation = new("read", "doc:1", new JD());

    enum PcaOutcome { Admitted, Replay, Error }

    /// <summary>Pre-signed PCActns (counters 1..n) from one agent under one grant, each with the provenance bundle it is sent with.</summary>
    sealed class PcaStateFixture
    {
        public JD Grant = new();
        public JD Pin = new();
        public List<JD> Pcactns = new();
        public List<JD> Bundles = new();

        public static PcaStateFixture Make(int count)
        {
            var principal = SuiteKey.Ed25519(EdKey.Generate());
            var holder = SuiteKey.Ed25519(EdKey.Generate());
            var zero = new Num("0");
            var risk = new JD
            {
                ["weights"] = new JD { ["alpha"] = zero, ["beta"] = zero, ["gamma"] = zero, ["delta"] = zero, ["epsilon"] = zero, ["zeta"] = zero },
                ["theta1"] = new Num("0.5"), ["theta2"] = new Num("0.8"), ["kappa"] = new Num("1"), ["lambda"] = zero, ["rho"] = zero, ["bMax"] = new Num("1000"),
            };
            var envelope = new JD
            {
                ["predicates"] = new JL { new JD { ["verb"] = "read", ["resource"] = "doc:*" } }, ["caveats"] = new JL(), ["agent_binding"] = new JD(), ["risk_policy"] = risk,
            };
            var grant = Issue.MintGrant(principal, holder.Ed!.Id, null, envelope, "store conformance").Grant;
            var node = new JD
            {
                ["id"] = "n1", ["verb"] = "read", ["resource"] = "doc:1", ["params_digest"] = Pca.ParamsDigest(new JD()), ["reversibility_class"] = "irreversible",
            };
            var plan = Issue.CommitPlan(new[] { node });
            var recorder = new ProvenanceRecorder("pca-state-conformance", "k1");
            var now = AtlasPca.ReplayClock.NowMs();
            var fx = new PcaStateFixture { Grant = grant, Pin = recorder.Pin.ToJson() };
            for (var i = 1; i <= Math.Max(1, count); i++)
            {
                fx.Pcactns.Add(Issue.BuildPCActn(new ActSpec
                {
                    Grant = grant, Chain = new JL { grant }, Plan = plan, NodeId = "n1", Params = new JD(), Counter = i, Signer = holder, Aud = PcaStateAud, Iat = now,
                    Nonce = Pca.B64u(RandomNumberGenerator.GetBytes(16)), RiskClaim = new JD { ["r"] = zero, ["inputs"] = new JD() },
                }));
                fx.Bundles.Add(ArgProvenance.PrincipalDirect(recorder, "read", "doc:1", new JD()));
            }
            return fx;
        }

        public JD Json() => new()
        {
            ["grant"] = Grant, ["pin"] = Pin, ["pcactns"] = Pcactns.Select(p => (object?)p).ToList(), ["bundles"] = Bundles.Select(b => (object?)b).ToList(),
        };

        public static PcaStateFixture From(object? v)
        {
            var d = (JD)v!;
            return new PcaStateFixture
            {
                Grant = (JD)d["grant"]!, Pin = (JD)d["pin"]!, Pcactns = ((JL)d["pcactns"]!).Select(p => (JD)p!).ToList(), Bundles = ((JL)d["bundles"]!).Select(b => (JD)b!).ToList(),
            };
        }

        /// <summary>The guard under test: the real authorize path, the store as the replay store. Throws when the store cannot serve a multi-instance guard.</summary>
        public PcaGuard GuardFor(IStateStore store, bool multiInstance)
        {
            if (multiInstance && store.Scope == StoreScope.Process) throw new ArgumentException("multiInstance requires a shared state store (a process-scoped store lets one PCActn replay once per instance)");
            return new PcaGuard(this, store, multiInstance);
        }
    }

    sealed class PcaGuard
    {
        readonly PcaStateFixture _fx;
        readonly IStateStore _store;
        readonly bool _multi;

        public PcaGuard(PcaStateFixture fx, IStateStore store, bool multi) { _fx = fx; _store = store; _multi = multi; }

        /// <summary>Why the last presentation that was neither admitted nor a replay was refused (for the report).</summary>
        public volatile string? LastDeny;

        public PcaOutcome Handle(int counter)
        {
            try
            {
                var input = new AuthorizeInput
                {
                    Operation = PcaStateOperation, Audience = PcaStateAud, StateStore = _store, IsRevoked = (_, _) => false, Plan = "single-step", MultiInstance = _multi,
                    Now = AtlasPca.ReplayClock.NowMs(),
                    ResolveGrant = ref0 => Equals(ref0, _fx.Grant["id"]) ? _fx.Grant : null,
                    ProvenanceFlow = new ArgProvenanceOptions { Mediators = new[] { ProvMediatorPinFrom(_fx.Pin) } },
                    Provenance = _fx.Bundles[counter - 1],
                    ServerRisk = new Dictionary<string, double> { ["semanticDistance"] = 0, ["reversibility"] = 1, ["blastRadius"] = 0, ["taint"] = 0, ["confidence"] = 1, ["age"] = 0 },
                };
                var r = Pca.Authorize(_fx.Pcactns[counter - 1], input);
                if (r.Allow) return PcaOutcome.Admitted;
                // a store that raised is a guard error in the reference (no replay check); here it also marks the replay check, so tell it by its reason
                if (r.Checks.TryGetValue("replay", out var s) && s == "fail" && !r.Reasons.Any(x => x.Contains("the replay store failed", StringComparison.Ordinal))) return PcaOutcome.Replay;
                LastDeny = r.Reason ?? string.Join("; ", r.Reasons);
                return PcaOutcome.Error;
            }
            catch (Exception e) { LastDeny = e.GetType().Name + ": " + e.Message; return PcaOutcome.Error; }
        }
    }

    static ProvMediatorPin ProvMediatorPinFrom(JD pin) =>
        new((string)pin["mediator"]!, (string)pin["kid"]!, (string)pin["pk"]!, pin.TryGetValue("pq_pk", out var pq) ? pq as string : null);

    /// <summary>A store whose claim lands but whose answer is lost.</summary>
    sealed class LossyStateStore : IStateStore
    {
        readonly IStateStore _inner;
        public LossyStateStore(IStateStore inner) => _inner = inner;
        public StoreScope Scope => _inner.Scope;
        public ClaimResult? Claim(string key, long counter)
        {
            _inner.Claim(key, counter);
            throw new InvalidOperationException("the answer was lost (timeout)");
        }
    }

    /// <summary>A store whose claim blocks until released, to hold a commit in flight.</summary>
    sealed class GatedStateStore : IStateStore
    {
        readonly IStateStore _inner;
        public readonly SemaphoreSlim Entered = new(0), Gate = new(0);
        public GatedStateStore(IStateStore inner) => _inner = inner;
        public StoreScope Scope => _inner.Scope;
        public ClaimResult? Claim(string key, long counter)
        {
            Entered.Release();
            Gate.Wait();
            return _inner.Claim(key, counter);
        }
    }

    /// <summary>Runs every pca-state check.</summary>
    public static ConformanceReport RunPcaState(PcaStateConformance c)
    {
        var rep = new ConformanceReport(c.Name);
        if (c.Open == null) { rep.Add("configuration", "Open is required"); return rep; }
        int rounds = Math.Max(1, c.Rounds), copies = Math.Max(1, c.Copies);
        var claims = RunStateStore(new StateStoreConformance
        {
            Name = c.Name, Open = c.Open, Restart = c.Restart, Durable = c.Durable, Shared = c.Shared, Rounds = rounds, Copies = copies, Handles = Math.Max(1, c.Instances),
        });
        foreach (var k in claims.Checks) if (k.Name.StartsWith("claim-", StringComparison.Ordinal)) rep.Checks.Add(k);
        rep.Add("one-instance", PcaRaceCheck(c, 1, false, rounds, copies, out var one));
        if (one != null) rep.Admitted["one-instance"] = one;
        if (c.Shared)
        {
            rep.Add("instances", PcaRaceCheck(c, Math.Max(1, c.Instances), true, rounds, copies, out var many));
            if (many != null) rep.Admitted["instances"] = many;
        }
        else rep.Skip("instances", "Shared is false (one instance only)");
        if (!c.Shared) rep.Skip("processes", "Shared is false (one instance only)");
        else if (c.Worker == null) rep.Skip("processes", "needs a worker executable (the guards run in child processes)");
        else rep.Add("processes", PcaProcessRace(c.Worker, rounds, copies, Math.Max(1, c.Processes)));
        if (c.Durable) rep.Add("crash-after-claim", PcaCrashAfterClaim(c, rounds)); else rep.Skip("crash-after-claim", "Durable is false (state dies with the process)");
        rep.Add("retry-after-timeout", PcaRetryAfterTimeout(c, out var retried));
        if (retried != null) rep.Admitted["retry-after-timeout"] = retried;
        return rep;
    }

    static int PcaRace(List<PcaGuard> guards, int counter, int copies) => PcaPresentations(guards, counter, copies).Count(o => o == PcaOutcome.Admitted);

    static List<PcaOutcome> PcaPresentations(List<PcaGuard> guards, int counter, int copies)
    {
        var res = new PcaOutcome[Math.Max(1, copies)];
        Race(res.Length, i => res[i] = guards[i % guards.Count].Handle(counter));
        return res.ToList();
    }

    // admitted: per round, how many copies of that round's proof were admitted (null when the race never ran); every round runs, the first bad one is reported
    static string? PcaRaceCheck(PcaStateConformance c, int handles, bool multiInstance, int rounds, int copies, out List<int>? admitted)
    {
        admitted = null;
        var hs = new List<IStateStore>();
        try
        {
            for (var i = 0; i < handles; i++) hs.Add(c.Open!() ?? throw new InvalidOperationException("Open returned null"));
            var fx = PcaStateFixture.Make(rounds);
            var guards = new List<PcaGuard>();
            try { foreach (var s in hs) guards.Add(fx.GuardFor(s, multiInstance)); }
            catch (Exception e) { return "refused in multi-instance mode: " + e.Message; }
            var counts = new List<int>();
            string? bad = null;
            for (var r = 1; r <= rounds; r++)
            {
                var wins = PcaRace(guards, r, copies);
                counts.Add(wins);
                if (wins != 1) bad ??= $"round {r}: {wins} of {copies} copies of one proof were admitted (want exactly 1)" + (wins == 0 && guards.Select(g => g.LastDeny).FirstOrDefault(d => d != null) is { } why ? $"; refused: {why}" : "");
            }
            admitted = counts;
            return bad;
        }
        catch (Exception e) { return e.GetType().Name + ": " + e.Message; }
        finally { foreach (var s in hs) Close(s); }
    }

    static string? PcaCrashAfterClaim(PcaStateConformance c, int rounds)
    {
        var opened = new List<IStateStore>();
        try
        {
            var h1 = c.Open!();
            opened.Add(h1);
            var fx = PcaStateFixture.Make(Math.Max(4, rounds));
            // in process: admitted on handle 1, which is then abandoned (never closed); the backend restarts when it can
            var first = fx.GuardFor(h1, c.Shared).Handle(1);
            c.Restart?.Invoke();
            var h2 = c.Open!();
            opened.Add(h2);
            var g = fx.GuardFor(h2, c.Shared);
            var again = g.Handle(1);
            var next = g.Handle(2);
            if (first != PcaOutcome.Admitted || again != PcaOutcome.Replay || next != PcaOutcome.Admitted)
                return $"in process: admitted={first}, same proof after the instance died={again}, next counter={next}";
            return c.Worker != null ? PcaProcessCrash(c, c.Worker, fx) : null;
        }
        catch (Exception e) { return e.GetType().Name + ": " + e.Message; }
        finally { foreach (var s in opened) Close(s); }
    }

    // admitted: [1 when the lost-answer proof was admitted at all (it must not be), how many of the two in-flight presentations were admitted]
    static string? PcaRetryAfterTimeout(PcaStateConformance c, out List<int>? admitted)
    {
        admitted = null;
        var hs = new List<IStateStore>();
        try
        {
            for (var i = 0; i < (c.Shared ? 2 : 1); i++) hs.Add(c.Open!());
            var fx = PcaStateFixture.Make(4);
            var other = hs[^1];
            // 1. the commit lands, its answer is lost: the guard fails closed, the retry (another instance when shared) is a replay
            var first = fx.GuardFor(new LossyStateStore(hs[0]), c.Shared).Handle(1);
            var og = fx.GuardFor(other, c.Shared);
            var retry = og.Handle(1);
            var next = og.Handle(2);
            string? lost = first != PcaOutcome.Error || retry != PcaOutcome.Replay || next != PcaOutcome.Admitted ? $"lost answer: first={first}, retry={retry}, next counter={next}" : null;
            // 2. the first commit is still in flight when the caller retries elsewhere: exactly one of the two is admitted
            var slow = new GatedStateStore(hs[0]);
            var sg = fx.GuardFor(slow, c.Shared);
            var res = new PcaOutcome[2];
            var t1 = new Thread(() => res[0] = sg.Handle(3));
            t1.Start();
            while (!slow.Entered.Wait(10) && t1.IsAlive) { } // a guard that refuses before its commit never reaches the gate
            var t2 = new Thread(() => res[1] = og.Handle(3));
            t2.Start();
            slow.Gate.Release();
            t1.Join();
            t2.Join();
            var pair = res.Count(o => o == PcaOutcome.Admitted);
            admitted = new List<int> { first == PcaOutcome.Admitted || retry == PcaOutcome.Admitted ? 1 : 0, pair };
            return lost ?? (pair == 1 ? null : $"in-flight retry: {pair} admitted of 2 (want exactly 1)");
        }
        catch (Exception e) { return e.GetType().Name + ": " + e.Message; }
        finally { foreach (var s in hs) Close(s); }
    }

    // ---- child processes ----

    sealed record PcaWorkerRun(bool Killed, List<long[]> Lines)
    {
        public long Admitted => Lines.Sum(l => l[1]);
        public long Replays => Lines.Sum(l => l[2]);
    }

    static Process PcaStart(PcaStateWorker w, PcaStateFixture fx, JD cfg, string output)
    {
        var c = new JD(cfg) { ["fixture"] = fx.Json(), ["out"] = output, ["options"] = w.Options.ToDictionary(kv => kv.Key, kv => (object?)kv.Value) };
        var psi = new ProcessStartInfo(w.Executable) { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false };
        foreach (var a in w.Arguments) psi.ArgumentList.Add(a);
        psi.ArgumentList.Add(Pca.Canonicalize(c));
        var p = Process.Start(psi) ?? throw new InvalidOperationException("the worker did not start");
        p.OutputDataReceived += (_, _) => { };
        p.ErrorDataReceived += (_, _) => { };
        p.BeginOutputReadLine();
        p.BeginErrorReadLine();
        return p;
    }

    static PcaWorkerRun PcaFinish(Process p, string output)
    {
        p.WaitForExit();
        var lines = new List<long[]>();
        if (File.Exists(output))
        {
            foreach (var l in File.ReadAllLines(output, Encoding.UTF8))
            {
                if (string.IsNullOrWhiteSpace(l)) continue;
                var m = (JD)Pca.ParseJson(l)!;
                long N(string k) => m.GetValueOrDefault(k) is Num n && long.TryParse(n.Raw, out var v) ? v : 0;
                lines.Add(new[] { N("counter"), N("admitted"), N("replays"), N("errors") });
            }
        }
        return new PcaWorkerRun(p.ExitCode == 137, lines); // SIGKILL
    }

    static string PcaTempDir()
    {
        var d = Path.Combine(Path.GetTempPath(), "pcasc-pstate-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(d);
        return d;
    }

    static string? PcaProcessRace(PcaStateWorker w, int rounds, int copies, int processes)
    {
        string? dir = null;
        try
        {
            var fx = PcaStateFixture.Make(rounds);
            dir = PcaTempDir();
            var origin = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() + 3000; // time for every process to start and open its handles
            var ps = new List<(Process P, string Out)>();
            for (var i = 0; i < processes; i++)
            {
                var o = Path.Combine(dir, $"p{i}.jsonl");
                ps.Add((PcaStart(w, fx, new JD { ["mode"] = "race", ["rounds"] = new Num(rounds.ToString()), ["origin"] = new Num(origin.ToString()), ["roundMs"] = new Num("150"),
                    ["copies"] = new Num(copies.ToString()), ["instances"] = new Num("2") }, o), o));
            }
            var runs = ps.Select(p => PcaFinish(p.P, p.Out)).ToList();
            for (var r = 1; r <= rounds; r++)
            {
                var admitted = runs.Sum(run => run.Lines.Where(l => l[0] == r).Sum(l => l[1]));
                if (admitted != 1) return $"round {r}: {admitted} presentations admitted across {runs.Count} processes (want exactly 1)";
            }
            var bad = runs.FirstOrDefault(run => run.Killed || run.Lines.Count != rounds);
            return bad != null ? $"a worker did not finish ({bad.Lines.Count} of {rounds} rounds recorded)" : null;
        }
        catch (Exception e) { return e.GetType().Name + ": " + e.Message; }
        finally { if (dir != null) try { Directory.Delete(dir, true); } catch (IOException) { /* best effort */ } }
    }

    /// <summary>A child process admits counter 3 and kills itself before its handler; a new process retries it; the next counter is admitted.</summary>
    static string? PcaProcessCrash(PcaStateConformance c, PcaStateWorker w, PcaStateFixture fx)
    {
        string? dir = null;
        try
        {
            dir = PcaTempDir();
            PcaWorkerRun One(string mode, int counter, string file)
            {
                var o = Path.Combine(dir, file);
                return PcaFinish(PcaStart(w, fx, new JD { ["mode"] = mode, ["counter"] = new Num(counter.ToString()), ["copies"] = new Num("1"), ["instances"] = new Num("1"), ["rounds"] = new Num("1") }, o), o);
            }
            var killed = One("admit-then-die", 3, "a.jsonl");
            c.Restart?.Invoke();
            var retried = One("race", 3, "b.jsonl");
            var fresh = One("race", 4, "c.jsonl");
            if (!(killed.Killed && killed.Admitted == 1 && retried.Admitted == 0 && retried.Replays == 1 && fresh.Admitted == 1))
                return $"child process: killed after admission={killed.Killed && killed.Admitted == 1}, retry in a new process admitted {retried.Admitted}, next counter admitted {fresh.Admitted}";
            return null;
        }
        catch (Exception e) { return e.GetType().Name + ": " + e.Message; }
        finally { if (dir != null) try { Directory.Delete(dir, true); } catch (IOException) { /* best effort */ } }
    }

    // ---- the worker side ----

    static void PcaRecord(string output, long counter, List<PcaOutcome> rs)
    {
        var line = Pca.Canonicalize(new JD
        {
            ["counter"] = new Num(counter.ToString()), ["admitted"] = new Num(rs.Count(o => o == PcaOutcome.Admitted).ToString()),
            ["replays"] = new Num(rs.Count(o => o == PcaOutcome.Replay).ToString()), ["errors"] = new Num(rs.Count(o => o == PcaOutcome.Error).ToString()),
        }) + "\n";
        File.AppendAllText(output, line, new UTF8Encoding(false));
    }

    /// <summary>The entry of one worker process: <paramref name="configText"/> is the last argument the parent passed; <paramref name="open"/> opens a handle onto
    /// the shared backend from the parent's options. Returns the process exit status. Mode <c>admit-then-die</c> records the admission and kills the process
    /// (SIGKILL) before any handler.</summary>
    public static int PcaStateWorkerMain(string configText, Func<IReadOnlyDictionary<string, string>, IStateStore> open)
    {
        try
        {
            var cfg = (JD)Pca.ParseJson(configText)!;
            var fx = PcaStateFixture.From(cfg["fixture"]);
            var output = (string)cfg["out"]!;
            var options = ((JD)cfg["options"]!).ToDictionary(kv => kv.Key, kv => (string)kv.Value!);
            int Int(string k, int d) => cfg.GetValueOrDefault(k) is Num n ? int.Parse(n.Raw) : d;
            long Long(string k, long d) => cfg.GetValueOrDefault(k) is Num n ? long.Parse(n.Raw) : d;
            var guards = new List<PcaGuard>();
            for (var i = 0; i < Math.Max(1, Int("instances", 1)); i++) guards.Add(fx.GuardFor(open(options), true));
            var copies = Int("copies", 1);
            if ((cfg.GetValueOrDefault("mode") as string) == "admit-then-die")
            {
                var counter = Int("counter", 1);
                PcaRecord(output, counter, PcaPresentations(guards, counter, copies));
                Process.GetCurrentProcess().Kill();
                return 3;
            }
            var rounds = Int("rounds", 1);
            for (var r = 0; r < rounds; r++)
            {
                var counter = cfg.ContainsKey("counter") ? Int("counter", 1) : r + 1;
                var at = Long("origin", DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()) + r * Long("roundMs", 0);
                while (DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() < at) Thread.Sleep(2);
                PcaRecord(output, counter, PcaPresentations(guards, counter, copies));
            }
            return 0;
        }
        catch (Exception) { return 1; }
    }
}


public static partial class StoreConformance
{
    /// <summary>A store that declares itself shared whatever it wraps (the defective controls pass a process-local store off as shared).</summary>
    sealed class DeclaredShared(IStateStore inner) : IStateStore
    {
        public StoreScope Scope => StoreScope.Shared;
        public ClaimResult? Claim(string key, long counter) => inner.Claim(key, counter);
        public bool ConsumeOnce(string key, long retainUntilMs, long nowMs) => inner.ConsumeOnce(key, retainUntilMs, nowMs);
    }

    /// <summary>A claim that reads, yields, then writes: two instances both read "fresh" and both admit.</summary>
    sealed class ReadThenWriteStore(Dictionary<string, long> shared) : IStateStore
    {
        public StoreScope Scope => StoreScope.Shared;
        public ClaimResult? Claim(string key, long counter)
        {
            long? last;
            lock (shared) last = shared.TryGetValue(key, out var l) ? l : null;
            Thread.Sleep(1);
            if (last is long x && counter <= x) return new ClaimResult(false, x);
            lock (shared) shared[key] = counter;
            return new ClaimResult(true);
        }
    }

    /// <summary>A store that only reads and writes (no claim of its own): the claim is the read, then the write, serialised by <paramref name="gate"/>
    /// alone, as the guard drives a get / put store under whatever lock it has.</summary>
    sealed class GetPutStore(Dictionary<string, long> shared, object gate, StoreScope scope) : IStateStore
    {
        public StoreScope Scope => scope;
        public ClaimResult? Claim(string key, long counter)
        {
            lock (gate)
            {
                long? last;
                lock (shared) last = shared.TryGetValue(key, out var l) ? l : null;
                Thread.Sleep(1);
                if (last is long x && counter <= x) return new ClaimResult(false, x);
                lock (shared) shared[key] = counter;
                return new ClaimResult(true);
            }
        }
    }

    /// <summary>The reference adapters of the pca-state profile, by name; each takes the adapter options (<c>dir</c> for <c>durable-file</c>) and returns a
    /// configuration for <see cref="RunPcaState"/>. <c>in-memory</c> and <c>durable-file</c> are correct stores; the <c>bad-*</c> ones are defective controls a
    /// conformance run must catch: <c>bad-get-put</c> (read then write with no claim and no lock of its own: only the lock inside one process serialises it,
    /// so it is refused in multi-instance mode), <c>bad-read-then-write-claim</c> (a claim that is not atomic), <c>bad-local-lock</c> (declared shared, but its
    /// lock covers one handle only), <c>bad-volatile</c> (declared durable, forgets every claim on restart), <c>bad-unshared</c> (declared shared, every handle
    /// has its own state).</summary>
    public static readonly IReadOnlyDictionary<string, Func<IReadOnlyDictionary<string, string>, PcaStateConformance>> PcaStateReferenceAdapters =
        new Dictionary<string, Func<IReadOnlyDictionary<string, string>, PcaStateConformance>>(StringComparer.Ordinal)
        {
            ["in-memory"] = _ =>
            {
                var store = new MemoryStateStore();
                return new PcaStateConformance { Name = "in-memory atomic (MemoryStateStore)", Open = () => store, Durable = false, Shared = false };
            },
            ["durable-file"] = o =>
            {
                var dir = o.TryGetValue("dir", out var d) && d.Length > 0 ? d : Directory.CreateTempSubdirectory("pcasc-pstate-durable-").FullName;
                return new PcaStateConformance
                {
                    Name = $"durable-state file store, atomic claim ({dir})", Durable = true, Shared = true, Restart = () => { },
                    Open = () => new KvStateStore(Pca.OpenDurableState(new DurableStateOptions { Dir = dir })),
                };
            },
            ["bad-get-put"] = _ =>
            {
                var shared = new Dictionary<string, long>(StringComparer.Ordinal);
                var gate = new object(); // the one lock of this process
                return new PcaStateConformance
                {
                    Name = "BAD get/put without claim or lock", Open = () => new GetPutStore(shared, gate, StoreScope.Process), Durable = false, Shared = true,
                };
            },
            ["bad-read-then-write-claim"] = _ =>
            {
                var shared = new Dictionary<string, long>(StringComparer.Ordinal);
                return new PcaStateConformance { Name = "BAD claim as read, wait, write", Open = () => new ReadThenWriteStore(shared), Durable = false, Shared = true };
            },
            ["bad-local-lock"] = _ =>
            {
                var shared = new Dictionary<string, long>(StringComparer.Ordinal);
                return new PcaStateConformance
                {
                    Name = "BAD per-handle lock passed off as shared", Open = () => new GetPutStore(shared, new object(), StoreScope.Shared), Durable = false, Shared = true,
                };
            },
            ["bad-volatile"] = _ =>
            {
                var store = new MemoryStateStore();
                return new PcaStateConformance
                {
                    Name = "BAD volatile atomic store (claims lost on restart)", Durable = true, Shared = true,
                    Open = () => new DeclaredShared(store), Restart = () => store = new MemoryStateStore(),
                };
            },
            ["bad-unshared"] = _ => new PcaStateConformance
            {
                Name = "BAD per-handle state passed off as shared", Open = () => new DeclaredShared(new MemoryStateStore()), Durable = false, Shared = true,
            },
        };
}

// The command line of the store conformance kit: `pca-store-conformance --adapter <builtin:name> [options]`.
// Exit codes: 0 pass, 1 a contract violation was found, 3 unresolved, 2 usage or adapter error.
using AtlasPca.Js;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.StoreConformancePkg;

/// <summary>Argument parsing and the entry point of the store conformance command line.</summary>
public static class StoreConformanceCli
{
    /// <summary>States searched per key before a history is reported unresolved.</summary>
    public const double DefaultSearchBudget = LinearizabilitySearch.DefaultBudget;

    /// <summary>The tests of the linearizability profile.</summary>
    public static readonly IReadOnlyList<string> AllTests = new[] { "burst", "concurrent", "retention", "durability", "crash" };

    /// <summary>The tests of the pca-state profile (the store behind the real request guard).</summary>
    public static readonly IReadOnlyList<string> AllPcaStateTests = new[]
    {
        "claim-burst", "claim-concurrent", "claim-durability", "one-instance", "instances", "processes", "crash-after-claim", "retry-after-timeout",
    };

    public static readonly string Usage = "pca-store-conformance --adapter <module|builtin:name> [options]\n\n"
        + "  --adapter <path>        module exporting a store adapter (default export, 'adapter' or 'createAdapter(options)')\n"
        + "                          or builtin:in-memory | builtin:durable-file | builtin:bad-* (reference adapters)\n"
        + "  --option k=v            passed to the adapter factory (repeatable)\n"
        + "  --tests a,b             subset of: " + string.Join(", ", AllTests) + " (default all)\n"
        + "  --clients N             concurrent clients (default 16)\n"
        + "  --duration MS           concurrent run length (default 2000)\n"
        + "  --rounds N              same-key burst rounds (default 20)\n"
        + "  --revisit-keys N        retention run size (default 500)\n"
        + "  --processes N           crash test: client processes alive at once (default 3)\n"
        + "  --kill-every MS         crash test: SIGKILL one client process this often (default 400)\n"
        + "  --budget N              search states per key before it is UNRESOLVED (default 200000)\n"
        + "  --values N              advance tests: counter values are drawn from [0, N) (default 20)\n"
        + "  --seed N                workload PRNG seed, to reproduce a run (default random)\n"
        + "  --json                  print the report as JSON\n"
        + "  --profile pca-state     test the store behind requirePCA instead (a module exporting createPcaStateAdapter(options),\n"
        + "                          or builtin:in-memory | builtin:durable-file | builtin:bad-*); --tests then takes a subset of:\n"
        + "                          " + string.Join(", ", AllPcaStateTests) + "\n"
        + "                          (--rounds = race rounds, default 10; --clients = copies per round, default 16; --processes)\n\n"
        + "Exit: 0 pass, 1 violation found, 3 unresolved, 2 usage or adapter error.";

    // the value as the reference reads it: Number(text), so "1e2" is 100, " 5 " is 5 and "" is 0
    static double Number(string flag, string? v)
    {
        var n = v == null ? double.NaN : JsJson.ToJsNumber(v);
        if (!double.IsFinite(n) || n < 0) throw new ArgumentException(flag + " needs a non-negative number");
        return n;
    }

    static Num J(double n) => new(JsJson.NumberToString(n));

    /// <summary>The parsed command line as a JSON tree: <c>options</c>, <c>json</c>, <c>help</c>, <c>conf</c> (clients, durationMs, rounds, revisitKeys,
    /// budget, values, seed, tests) and, when given, <c>adapter</c>, <c>profile</c>, <c>pcaStateTests</c>, <c>processes</c>, <c>killEveryMs</c>.
    /// Throws <see cref="ArgumentException"/> on an unknown argument or a bad value.</summary>
    public static D ParseCli(IReadOnlyList<string> argv)
    {
        var options = new D();
        var conf = new D();
        var a = new D { ["options"] = options, ["json"] = false, ["help"] = false, ["conf"] = conf };
        List<string>? rawTests = null;
        for (int i = 0; i < argv.Count; i++)
        {
            var f = argv[i];
            var nx = i + 1 < argv.Count ? argv[i + 1] : null;
            switch (f)
            {
                case "--adapter": i++; if (nx != null) a["adapter"] = nx; break;
                case "--option":
                {
                    i++;
                    var kv = nx ?? "";
                    int eq = kv.IndexOf('=');
                    if (eq < 1) throw new ArgumentException("--option needs k=v");
                    options[kv[..eq]] = kv[(eq + 1)..];
                    break;
                }
                case "--tests": i++; rawTests = (nx ?? "").Split(',').Where(x => x.Length > 0).ToList(); break;
                case "--profile":
                    i++;
                    if (nx != "pca-state") throw new ArgumentException("--profile: unknown profile " + (nx ?? "undefined") + " (known: pca-state)");
                    a["profile"] = nx;
                    break;
                case "--clients": i++; conf["clients"] = J(Number(f, nx)); break;
                case "--duration": i++; conf["durationMs"] = J(Number(f, nx)); break;
                case "--rounds": i++; conf["rounds"] = J(Number(f, nx)); break;
                case "--revisit-keys": i++; conf["revisitKeys"] = J(Number(f, nx)); break;
                case "--processes": i++; a["processes"] = J(Number(f, nx)); break;
                case "--kill-every": i++; a["killEveryMs"] = J(Number(f, nx)); break;
                case "--budget": i++; conf["budget"] = J(Number(f, nx)); break;
                case "--values":
                {
                    i++;
                    var n = Number(f, nx);
                    if (n != Math.Floor(n) || n < 1) throw new ArgumentException("--values needs a positive integer");
                    conf["values"] = J(n);
                    break;
                }
                case "--seed":
                {
                    i++;
                    var n = Number(f, nx);
                    if (n != Math.Floor(n)) throw new ArgumentException("--seed needs a non-negative integer");
                    conf["seed"] = J(n);
                    break;
                }
                case "--json": a["json"] = true; break;
                case "-h" or "--help": a["help"] = true; break;
                default: throw new ArgumentException("unknown argument " + f);
            }
        }
        if (rawTests != null)
        {
            bool pcaState = a.GetValueOrDefault("profile") is "pca-state";
            var known = pcaState ? AllPcaStateTests : AllTests;
            var bad = rawTests.Where(x => !known.Contains(x)).ToList();
            if (bad.Count > 0 || rawTests.Count == 0) throw new ArgumentException("--tests: unknown test(s) " + (bad.Count > 0 ? string.Join(", ", bad) : "(none given)"));
            var list = rawTests.Cast<object?>().ToList();
            if (pcaState) a["pcaStateTests"] = list; else conf["tests"] = list;
        }
        return a;
    }

    static int? Int(object? n) => n == null ? null : (int)JsJson.ToJsNumber(n);

    /// <summary>Runs the command line and returns the exit code; output goes to <paramref name="print"/> and <paramref name="printErr"/>. The pca-state
    /// profile runs over the built-in reference adapters (<see cref="StoreConformance.PcaStateReferenceAdapters"/>); a store of your own is checked by
    /// calling <see cref="StoreConformance.RunPcaState"/> with a way to open it.</summary>
    public static int Main(IReadOnlyList<string> argv, Action<string> print, Action<string> printErr)
    {
        D args;
        try { args = ParseCli(argv); }
        catch (ArgumentException e)
        {
            printErr(e.Message + "\n\n" + Usage);
            return 2;
        }
        if (args["help"] is true) { print(Usage); return 0; }
        if (args.GetValueOrDefault("adapter") is not string spec) { printErr("--adapter is required\n\n" + Usage); return 2; }
        // shortcut: only the pca-state profile runs here (the store behind the real guard); the linearizability workloads over a
        // generic register adapter are not part of this package. Upgrade when a register-adapter runner is added.
        if (args.GetValueOrDefault("profile") is not "pca-state")
        {
            printErr("cannot load adapter: the linearizability workload profile is not available in this package; pass --profile pca-state");
            return 2;
        }
        PcaStateConformance c;
        try
        {
            const string builtin = "builtin:";
            var known = string.Join(", ", StoreConformance.PcaStateReferenceAdapters.Keys);
            if (!spec.StartsWith(builtin, StringComparison.Ordinal))
                throw new ArgumentException($"'{spec}' is not a built-in pca-state adapter (known: {known}); check your own store with StoreConformance.RunPcaState");
            if (!StoreConformance.PcaStateReferenceAdapters.TryGetValue(spec[builtin.Length..], out var make))
                throw new ArgumentException($"unknown built-in pca-state adapter '{spec[builtin.Length..]}' (known: {known})");
            c = make(((D)args["options"]!).ToDictionary(e => e.Key, e => (string)e.Value!));
        }
        catch (Exception e)
        {
            printErr("cannot load adapter: " + e.Message);
            return 2;
        }
        try
        {
            var conf = (D)args["conf"]!;
            if (Int(conf.GetValueOrDefault("rounds")) is int rounds) c.Rounds = rounds;
            if (Int(conf.GetValueOrDefault("clients")) is int copies) c.Copies = copies;
            if (Int(args.GetValueOrDefault("processes")) is int processes) c.Processes = processes;
            var r = StoreConformance.RunPcaState(c);
            if (args.GetValueOrDefault("pcaStateTests") is L keep) r.Checks.RemoveAll(t => !keep.Contains(t.Name));
            print(args["json"] is true
                ? Pca.Canonicalize(new D
                {
                    ["name"] = r.Name, ["ok"] = r.Ok,
                    ["results"] = r.Checks.Select(t => (object?)new D { ["test"] = t.Name, ["status"] = t.Status, ["note"] = t.Note }).ToList(),
                })
                : r.ToString());
            return r.Ok ? 0 : 1;
        }
        catch (Exception e)
        {
            printErr("conformance run failed: " + e.Message);
            return 2;
        }
    }
}
